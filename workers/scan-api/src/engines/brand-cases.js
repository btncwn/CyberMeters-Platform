// ── Managed Brand Protection cases ─────────────────────────────────────────
// Brand abuse takedown lifecycle on the shared managed-case platform. Human
// actions prepare and track takedowns; CyberMeters alone verifies removal.
import { deliverWorkspaceAlert } from "./alerts.js";
import { brandCandidateToApi, loadWorkspaceBrandProfile } from "./brand-protection.js";
import {
  applyCaseTransition,
  buildCaseQueue,
  createCaseMachine,
  newCaseEventId,
  newManagedCaseId,
  requireActor,
  requireField,
  requireReason,
} from "./case-workflow.js";
import { dnsQuery } from "./dns.js";
import { safeFetch } from "../lib/http.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";

export const BRAND_CASE_TYPE = "brand_abuse";
export const BRAND_CASE_STATES = [
  "detected", "triage", "confirmed_abuse", "customer_approval", "evidence_ready",
  "takedown_submitted", "provider_followup", "verification_pending", "resolved",
  "false_positive", "duplicate", "provider_no_response", "escalated", "reappeared", "closed",
];

export const BRAND_CASE_MACHINE = createCaseMachine({
  states: BRAND_CASE_STATES,
  transitions: {
    detected: ["triage"],
    triage: ["confirmed_abuse", "false_positive", "duplicate"],
    confirmed_abuse: ["customer_approval"],
    customer_approval: ["evidence_ready"],
    evidence_ready: ["takedown_submitted"],
    takedown_submitted: ["provider_followup"],
    provider_followup: ["verification_pending", "provider_no_response", "escalated"],
    verification_pending: ["resolved", "provider_no_response", "escalated"],
    resolved: ["reappeared", "closed"],
    reappeared: ["confirmed_abuse"],
    provider_no_response: ["provider_followup", "escalated", "closed"],
    escalated: ["provider_followup", "verification_pending", "closed"],
    false_positive: [],
    duplicate: [],
    closed: [],
  },
  terminals: ["false_positive", "duplicate", "closed"],
  guards: {
    confirmed_abuse: [requireReason],
    false_positive: [requireReason],
    duplicate: [requireReason],
    customer_approval: [requireReason],
    evidence_ready: [(_row, ctx) => requireActor(ctx)],
    takedown_submitted: [requireField("submission_reference")],
    provider_no_response: [requireReason],
  },
});

export const BRAND_SYSTEM_ONLY_STATES = new Set(["resolved", "reappeared", "provider_no_response"]);

function safeJson(value, fallback = null) {
  if (value == null) return fallback;
  try { return JSON.stringify(value); } catch { return fallback; }
}

function parseJson(raw, fallback = null) {
  if (!raw) return fallback;
  try { return typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return fallback; }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashEvidenceBundle(bundle) {
  const encoded = new TextEncoder().encode(stableJson(bundle));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoded);
  return `sha256:${hex(digest)}`;
}

function newBrandCampaignId() {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return "bac-" + (uuid || "").slice(0, 12).padEnd(12, "0");
}

function normalizeDomain(domain) {
  return String(domain || "").trim().toLowerCase();
}

function candidateKey(candidate) {
  return `${candidate.brand_profile_id || "profile"}:${normalizeDomain(candidate.candidate_domain)}`;
}

function candidateIsRegistered(candidate = {}, apiCandidate = null) {
  return candidate.dns_resolves === 1 || candidate.dns_resolves === true ||
    candidate.mx_present === 1 || candidate.mx_present === true ||
    candidate.https_available === 1 || candidate.https_available === true ||
    apiCandidate?.dns_active === true || apiCandidate?.mx_present === true || apiCandidate?.https_active === true;
}

function candidateCanOpenCase(candidate, profile) {
  const api = brandCandidateToApi(candidate, profile);
  if (["owned", "ignored", "false_positive"].includes(api.classification)) return { ok: false, candidate: api, reason: "dismissed" };
  if (!["critical", "high"].includes(api.risk_level)) return { ok: false, candidate: api, reason: "below_threshold" };
  if (!candidateIsRegistered(candidate, api)) return { ok: false, candidate: api, reason: "not_registered_watchlist" };
  if (api.risk_reasons?.includes("not_registered_watchlist")) return { ok: false, candidate: api, reason: "not_registered_watchlist" };
  return { ok: true, candidate: api };
}

export function brandCaseToApi(row = {}) {
  const evidence = evidenceToApi(parseJson(row.evidence_json, null));
  return {
    id: row.id,
    workspace_id: row.workspace_id,
    case_type: row.case_type,
    domain: row.domain,
    finding_id: row.finding_id,
    asset_ref: row.asset_ref,
    severity: row.severity,
    status: row.status,
    evidence,
    recommended_actions: parseJson(row.recommended_actions_json, []),
    reason: row.reason || null,
    due_at: row.due_at || null,
    last_verified_at: row.last_verified_at || null,
    resolved_at: row.resolved_at || null,
    reopened_count: Number(row.reopened_count || 0),
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    age_hours: row.age_hours,
  };
}

function evidenceToApi(evidence) {
  if (!evidence || typeof evidence !== "object") return evidence;
  const latest = latestEvidenceBundle(evidence);
  return latest ? { ...evidence, bundle: latest.bundle } : evidence;
}

async function writeBrandCaseEvent(env, caseRow, { actor_type = "system", actor_id = null, from_status = null, to_status = null, action, detail = null } = {}) {
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events
      (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newCaseEventId(), caseRow.id, caseRow.workspace_id, actor_type, actor_id, from_status, to_status, action, safeJson(detail))
    .run();
  await createAuditEvent(env, {
    workspace_id: caseRow.workspace_id,
    user_id: actor_id,
    actor_type,
    event_type: `brand_case_${action}`,
    entity_type: "managed_case",
    entity_id: caseRow.id,
    description: `Brand takedown case ${action.replace(/_/g, " ")} for ${caseRow.domain}`,
    metadata: { case_id: caseRow.id, domain: caseRow.domain, finding_id: caseRow.finding_id, from_status, to_status, detail },
  });
}

async function notifyBrandCase(env, caseRow, { type, title, message, severity = "info", metadata = {} } = {}) {
  await createNotificationEvent(env, caseRow.workspace_id, {
    type, severity, title, message,
    metadata: { case_id: caseRow.id, domain: caseRow.domain, finding_id: caseRow.finding_id, ...metadata },
  });
  try {
    await deliverWorkspaceAlert(env, caseRow.workspace_id, {
      kind: type, severity, title, summary: message, domain: caseRow.domain,
    });
  } catch { /* best-effort */ }
}

function mergeEvidence(row, patch) {
  const evidence = parseJson(row.evidence_json, {}) || {};
  return { ...evidence, ...patch };
}

function latestEvidenceBundle(evidence = {}) {
  const versions = Array.isArray(evidence.evidence_bundles) ? evidence.evidence_bundles : [];
  if (versions.length === 0) return evidence.bundle ? { version: 1, bundle: evidence.bundle, content_hash: null } : null;
  return versions
    .filter((entry) => entry && typeof entry === "object" && entry.bundle)
    .sort((a, b) => Number(b.version || 0) - Number(a.version || 0))[0] || null;
}

async function appendEvidenceBundle(caseRow, bundle) {
  const evidence = parseJson(caseRow.evidence_json, {}) || {};
  const existingVersions = Array.isArray(evidence.evidence_bundles) ? [...evidence.evidence_bundles] : [];
  if (existingVersions.length === 0 && evidence.bundle) {
    existingVersions.push({
      version: 1,
      content_hash: await hashEvidenceBundle(evidence.bundle),
      captured_at: evidence.bundle.evidence_captured_at || caseRow.updated_at || caseRow.created_at || null,
      bundle: evidence.bundle,
    });
  }
  const version = Math.max(0, ...existingVersions.map((entry) => Number(entry?.version || 0))) + 1;
  const contentHash = await hashEvidenceBundle(bundle);
  const capturedAt = bundle.evidence_captured_at || new Date().toISOString();
  const entry = { version, content_hash: contentHash, captured_at: capturedAt, bundle };
  const { bundle: _legacyBundle, ...rest } = evidence;
  return {
    ...rest,
    evidence_bundles: [...existingVersions, entry],
    current_evidence_bundle: { version, content_hash: contentHash, captured_at: capturedAt },
  };
}

async function updateCaseRow(env, next) {
  await env.cybermeters_db
    .prepare(`UPDATE managed_cases
      SET status = ?, reason = ?, evidence_json = ?, recommended_actions_json = ?,
          due_at = ?, last_verified_at = ?, resolved_at = ?, reopened_count = ?, updated_at = ?
      WHERE id = ? AND workspace_id = ?`)
    .bind(
      next.status,
      next.reason || null,
      next.evidence_json || null,
      next.recommended_actions_json || null,
      next.due_at || null,
      next.last_verified_at || null,
      next.resolved_at || null,
      Number(next.reopened_count || 0),
      next.updated_at || new Date().toISOString(),
      next.id,
      next.workspace_id,
    )
    .run();
}

async function applyBrandTransition(env, caseRow, to, ctx = {}) {
  if ((ctx.actor_type || "customer") !== "system" && BRAND_SYSTEM_ONLY_STATES.has(to)) {
    return { ok: false, error: "This state is set only after CyberMeters technical verification." };
  }
  const result = applyCaseTransition(BRAND_CASE_MACHINE, caseRow, to, ctx);
  if (!result.ok) return result;
  const next = {
    ...result.case,
    evidence_json: caseRow.evidence_json,
    recommended_actions_json: caseRow.recommended_actions_json,
    due_at: caseRow.due_at,
  };

  if (to === "evidence_ready") {
    const bundle = ctx.bundle || await buildBrandEvidenceBundle(env, caseRow);
    next.evidence_json = safeJson(await appendEvidenceBundle(caseRow, bundle));
    next.recommended_actions_json = safeJson(bundle.recommended_actions, "[]");
  }
  if (to === "takedown_submitted") {
    const evidence = mergeEvidence(caseRow, {});
    const latestBundle = latestEvidenceBundle(evidence);
    const submissions = Array.isArray(evidence.submissions) ? evidence.submissions : [];
    submissions.push({
      submitted_at: ctx.now || new Date().toISOString(),
      submitted_by: ctx.actor_id || null,
      reference: ctx.submission_reference,
      evidence_bundle_version: latestBundle?.version || null,
      evidence_bundle_hash: latestBundle?.content_hash || null,
      recipients: ctx.recipients || latestBundle?.bundle?.recipients || [],
      note: ctx.reason || null,
    });
    next.evidence_json = safeJson({ ...evidence, submissions });
    next.due_at = ctx.follow_up_at || new Date(Date.now() + 7 * 86400000).toISOString();
  }

  await updateCaseRow(env, next);
  await writeBrandCaseEvent(env, next, {
    actor_type: ctx.actor_type || "customer",
    actor_id: ctx.actor_id || null,
    from_status: caseRow.status,
    to_status: to,
    action: ctx.action || "transition",
    detail: ctx.detail || { reason: ctx.reason || null, submission_reference: ctx.submission_reference || null },
  });
  return { ok: true, case: next };
}

export async function transitionBrandCase(env, caseRow, to, ctx = {}) {
  return applyBrandTransition(env, caseRow, to, ctx);
}

export async function recaptureBrandEvidenceBundle(env, caseRow, { actor_id = null, bundle = null, reason = "Evidence bundle re-captured." } = {}) {
  if (!["customer_approval", "evidence_ready", "takedown_submitted", "provider_followup", "verification_pending", "provider_no_response", "escalated"].includes(caseRow.status)) {
    return { ok: false, error: "Evidence can only be re-captured after the case is approved." };
  }
  const nextBundle = bundle || await buildBrandEvidenceBundle(env, caseRow);
  const evidence = await appendEvidenceBundle(caseRow, nextBundle);
  const next = {
    ...caseRow,
    evidence_json: safeJson(evidence),
    recommended_actions_json: safeJson(nextBundle.recommended_actions, "[]"),
    updated_at: new Date().toISOString(),
  };
  await updateCaseRow(env, next);
  const latest = latestEvidenceBundle(evidence);
  await writeBrandCaseEvent(env, next, {
    actor_type: actor_id ? "customer" : "system",
    actor_id,
    from_status: caseRow.status,
    to_status: caseRow.status,
    action: "evidence_recaptured",
    detail: { reason, evidence_bundle_version: latest?.version || null, evidence_bundle_hash: latest?.content_hash || null },
  });
  return { ok: true, case: next, evidence_bundle: latest };
}

export async function getBrandCase(env, workspaceId, caseId) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ? AND case_type = ?`)
    .bind(caseId, workspaceId, BRAND_CASE_TYPE)
    .first();
}

export async function listBrandCases(env, workspaceId, { status = null, limit = 50 } = {}) {
  const where = ["workspace_id = ?", "case_type = ?"];
  const binds = [workspaceId, BRAND_CASE_TYPE];
  if (status) { where.push("status = ?"); binds.push(status); }
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE ${where.join(" AND ")} ORDER BY created_at ASC LIMIT ?`)
    .bind(...binds, Math.max(1, Math.min(200, Number(limit || 50))))
    .all();
  return buildCaseQueue(rows.results || []).map(brandCaseToApi);
}

export async function listBrandCaseEvents(env, workspaceId, caseId) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at
              FROM managed_case_events WHERE workspace_id = ? AND case_id = ? ORDER BY created_at ASC`)
    .bind(workspaceId, caseId)
    .all();
  return (rows.results || []).map((r) => ({ ...r, detail: parseJson(r.detail_json, null), detail_json: undefined }));
}

async function fetchRdap(domain) {
  const res = await safeFetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { accept: "application/rdap+json, application/json" },
  });
  if (!res || !res.ok) return { status: "unknown" };
  const data = await res.json().catch(() => null);
  const emails = [];
  for (const ent of data?.entities || []) {
    const roles = Array.isArray(ent.roles) ? ent.roles.join(",") : "";
    const vcard = Array.isArray(ent.vcardArray?.[1]) ? ent.vcardArray[1] : [];
    for (const item of vcard) {
      if (Array.isArray(item) && item[0] === "email" && typeof item[3] === "string") {
        emails.push({ role: roles || "abuse", contact: item[3] });
      }
    }
  }
  return {
    status: "ok",
    registrar: data?.registrar || data?.name || null,
    abuse_contacts: [...new Map(emails.map((e) => [e.contact, e])).values()].slice(0, 10),
  };
}

export async function resolveBrandProviderContacts(candidateDomain) {
  const rdap = await fetchRdap(candidateDomain).catch(() => ({ status: "unknown" }));
  const contacts = [];
  for (const contact of rdap.abuse_contacts || []) {
    contacts.push({ type: "registrar", contact: contact.contact, role: contact.role, source: "rdap" });
  }
  if (contacts.length === 0) contacts.push({ type: "registrar", contact: "unknown", role: "abuse", source: "rdap", status: "unknown" });
  return { rdap, recipients: contacts };
}

export async function buildBrandEvidenceBundle(env, caseRow, { now = new Date().toISOString() } = {}) {
  const evidence = parseJson(caseRow.evidence_json, {}) || {};
  const candidate = evidence.candidate || {};
  const domain = normalizeDomain(caseRow.domain);
  const dns = {};
  for (const type of ["A", "MX"]) {
    try {
      const r = await dnsQuery(domain, type);
      dns[type] = (r.Answer || []).map((a) => a.data).slice(0, 20);
    } catch {
      dns[type] = null;
    }
  }
  const contacts = await resolveBrandProviderContacts(domain);
  return {
    candidate_domain: domain,
    protected_brand: candidate.protected_domain || caseRow.asset_ref || null,
    evidence_captured_at: now,
    dns_snapshot: dns,
    rdap_snapshot: contacts.rdap,
    mx_present: Array.isArray(dns.MX) ? dns.MX.length > 0 : candidate.mx_present === true,
    tls_or_ct: { available: candidate.https_active ?? null, note: "Worker-native snapshot; screenshots require external render service." },
    similarity: { score: candidate.similarity_score ?? null, variant_type: candidate.variant_type ?? null },
    abuse_indicators: candidate.risk_reasons || [],
    recipients: contacts.recipients,
    recommended_actions: [
      { title: "Prepare takedown submission", action: "Send the evidence bundle to the registrar or abuse contact and record the submission reference." },
      { title: "Track follow-up", action: "Re-check the candidate domain until CyberMeters can verify it is no longer technically present." },
    ],
  };
}

async function candidateById(env, workspaceId, candidateId) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM workspace_brand_assets WHERE id = ? AND workspace_id = ? LIMIT 1`)
    .bind(candidateId, workspaceId)
    .first();
}

export async function createBrandCaseForCandidate(env, workspaceId, candidateRow, { actor_id = null } = {}) {
  const profile = await loadWorkspaceBrandProfile(env, workspaceId);
  const gate = candidateCanOpenCase(candidateRow, profile);
  if (!gate.ok) return { opened: false, reason: gate.reason, candidate: gate.candidate };
  const key = candidateKey(candidateRow);
  const existing = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases
              WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
                AND status NOT IN ('false_positive', 'closed', 'risk_accepted')
              LIMIT 1`)
    .bind(workspaceId, BRAND_CASE_TYPE, key)
    .first();
  if (existing) {
    if (existing.status === "resolved") {
      const linked = await linkBrandCampaign(env, workspaceId, candidateRow, existing);
      const linkedCase = await getBrandCase(env, workspaceId, existing.id) || existing;
      const reopened = await applyBrandTransition(env, linkedCase, "reappeared", {
        actor_type: "system",
        action: "reappeared",
        detail: { candidate_domain: candidateRow.candidate_domain, campaign_id: linked.campaign_id },
      });
      if (reopened.ok) {
        const confirmed = await applyBrandTransition(env, reopened.case, "confirmed_abuse", {
          actor_type: "system",
          reason: "Previously resolved brand abuse candidate reappeared.",
          action: "campaign_relinked",
          detail: { campaign_id: linked.campaign_id },
        });
        if (confirmed.ok) {
          await notifyBrandCase(env, confirmed.case, {
            type: "brand_case_reappeared",
            severity: "high",
            title: `Brand abuse case reappeared for ${confirmed.case.domain}`,
            message: "A previously resolved brand abuse candidate is technically present again and has been linked to its campaign.",
            metadata: { campaign_id: linked.campaign_id },
          });
          return { opened: false, case: confirmed.case, reappeared: true };
        }
      }
    }
    return { opened: false, case: existing };
  }

  const now = new Date().toISOString();
  const evidence = {
    candidate: gate.candidate,
    candidate_id: candidateRow.id,
    brand_profile_id: candidateRow.brand_profile_id || profile?.id || null,
    opened_at: now,
  };
  const id = newManagedCaseId();
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain, finding_id, asset_ref, severity, status,
       evidence_json, recommended_actions_json, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'detected', ?, ?, ?, datetime('now'), datetime('now'))`)
    .bind(
      id, workspaceId, BRAND_CASE_TYPE, normalizeDomain(candidateRow.candidate_domain),
      key, gate.candidate.protected_domain || profile?.primary_domain || null,
      gate.candidate.risk_level || "high",
      safeJson(evidence), safeJson([{ title: "Review brand abuse", action: "Confirm whether this candidate is abusive before preparing takedown material." }], "[]"),
      actor_id || "system",
    )
    .run();
  const row = await getBrandCase(env, workspaceId, id);
  await writeBrandCaseEvent(env, row, {
    actor_type: actor_id ? "customer" : "system",
    actor_id,
    from_status: null,
    to_status: "detected",
    action: "opened",
    detail: { candidate_id: candidateRow.id, candidate_domain: candidateRow.candidate_domain },
  });
  await notifyBrandCase(env, row, {
    type: "brand_case_opened",
    severity: row.severity,
    title: `Brand takedown case opened for ${row.domain}`,
    message: "A registered high-risk brand candidate needs review.",
  });
  return { opened: true, case: row, candidate: gate.candidate };
}

export async function createBrandCasesForWorkspace(env, workspaceId) {
  const profile = await loadWorkspaceBrandProfile(env, workspaceId);
  if (!profile?.id) return { opened: 0 };
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM workspace_brand_assets
              WHERE workspace_id = ?
                AND COALESCE(classification, 'unreviewed') NOT IN ('owned','ignored','false_positive')
              ORDER BY updated_at DESC LIMIT 200`)
    .bind(workspaceId)
    .all();
  let opened = 0;
  for (const row of rows.results || []) {
    const result = await createBrandCaseForCandidate(env, workspaceId, row).catch(() => null);
    if (result?.opened) opened++;
  }
  return { opened };
}

export async function createBrandCaseForCandidateId(env, workspaceId, candidateId, opts = {}) {
  const row = await candidateById(env, workspaceId, candidateId);
  if (!row) return { opened: false, reason: "candidate_not_found" };
  return createBrandCaseForCandidate(env, workspaceId, row, opts);
}

async function updateCandidateClassification(env, workspaceId, candidateId, classification) {
  await env.cybermeters_db
    .prepare(`UPDATE workspace_brand_assets SET classification = ?, updated_at = datetime('now') WHERE id = ? AND workspace_id = ?`)
    .bind(classification, candidateId, workspaceId)
    .run()
    .catch(() => {});
}

export async function reviewBrandCase(env, caseRow, { classification, reason, actor_id = null } = {}) {
  const evidence = parseJson(caseRow.evidence_json, {}) || {};
  const candidateId = evidence.candidate_id;
  if (classification === "confirmed_abuse") {
    await updateCandidateClassification(env, caseRow.workspace_id, candidateId, "confirmed_abuse");
    return transitionBrandCase(env, caseRow, "confirmed_abuse", {
      actor_type: "customer", actor_id, reason, action: "confirmed_abuse",
    });
  }
  if (classification === "false_positive") {
    await updateCandidateClassification(env, caseRow.workspace_id, candidateId, "false_positive");
    return transitionBrandCase(env, caseRow, "false_positive", {
      actor_type: "customer", actor_id, reason, action: "false_positive",
    });
  }
  if (classification === "duplicate") {
    return transitionBrandCase(env, caseRow, "duplicate", {
      actor_type: "customer", actor_id, reason, action: "duplicate",
    });
  }
  return { ok: false, error: "Invalid brand case classification." };
}

export async function approveBrandTakedown(env, caseRow, { actor_id = null, reason = "Customer approved takedown preparation.", bundle = null } = {}) {
  if (caseRow.status === "confirmed_abuse") {
    const approval = await transitionBrandCase(env, caseRow, "customer_approval", {
      actor_type: "customer", actor_id, reason, action: "customer_approval",
    });
    if (!approval.ok) return approval;
    caseRow = approval.case;
  }
  return transitionBrandCase(env, caseRow, "evidence_ready", {
    actor_type: "customer", actor_id, actor: actor_id, action: "evidence_ready", bundle,
  });
}

export async function recordBrandTakedownSubmission(env, caseRow, { actor_id = null, submission_reference, recipients = null, note = null } = {}) {
  const evidence = parseJson(caseRow.evidence_json, {}) || {};
  const bundleRecipients = latestEvidenceBundle(evidence)?.bundle?.recipients || [];
  return transitionBrandCase(env, caseRow, "takedown_submitted", {
    actor_type: "customer",
    actor_id,
    submission_reference,
    recipients: recipients || bundleRecipients,
    reason: note || null,
    action: "takedown_submitted",
  });
}

export async function advanceBrandCaseFollowup(env, caseRow, to, detail = {}) {
  return transitionBrandCase(env, caseRow, to, {
    actor_type: "system",
    reason: detail.reason || null,
    action: to,
    detail,
  });
}

export async function verifyBrandCandidateGone(candidateDomain, { verifier = null } = {}) {
  if (verifier) return verifier(candidateDomain);
  try {
    const [a, mx] = await Promise.all([dnsQuery(candidateDomain, "A"), dnsQuery(candidateDomain, "MX")]);
    const aCount = a?.Answer?.length || 0;
    const mxCount = mx?.Answer?.length || 0;
    return {
      complete: true,
      gone: aCount === 0 && mxCount === 0,
      observed: { a_records: aCount, mx_records: mxCount },
    };
  } catch (e) {
    return { complete: false, gone: false, observed: null, reason: "probe_failed" };
  }
}

export async function linkBrandCampaign(env, workspaceId, candidateRow, caseRow) {
  const evidence = parseJson(caseRow.evidence_json, {}) || {};
  if (evidence.campaign_id) return { campaign_id: evidence.campaign_id };
  const campaignId = newBrandCampaignId();
  const domain = normalizeDomain(candidateRow.candidate_domain || caseRow.domain);
  const ips = candidateRow.ip_address ? [candidateRow.ip_address] : [];
  await env.cybermeters_db
    .prepare(`INSERT INTO brand_abuse_campaigns
      (id, workspace_id, brand_profile_id, linked_domains, linked_ips, shared_certs,
       shared_favicon_hashes, first_seen_at, last_seen_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, '[]', '[]', datetime('now'), datetime('now'), datetime('now'), datetime('now'))`)
    .bind(campaignId, workspaceId, candidateRow.brand_profile_id || evidence.brand_profile_id || null, safeJson([domain], "[]"), safeJson(ips, "[]"))
    .run();
  const nextEvidence = { ...evidence, campaign_id: campaignId };
  await env.cybermeters_db
    .prepare(`UPDATE managed_cases SET evidence_json = ?, reopened_count = reopened_count + 1, updated_at = datetime('now')
              WHERE id = ? AND workspace_id = ?`)
    .bind(safeJson(nextEvidence), caseRow.id, workspaceId)
    .run();
  return { campaign_id: campaignId };
}

export async function runBrandTakedownFollowupSweep(env, { verifier = null, now = new Date().toISOString() } = {}) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases
              WHERE case_type = ?
                AND status IN ('takedown_submitted','provider_followup','verification_pending')
              ORDER BY updated_at ASC LIMIT 50`)
    .bind(BRAND_CASE_TYPE)
    .all()
    .catch(() => ({ results: [] }));
  let resolved = 0, pending = 0, noResponse = 0;
  for (const row of rows.results || []) {
    let current = row;
    if (current.status === "takedown_submitted") {
      const followup = await transitionBrandCase(env, current, "provider_followup", {
        actor_type: "system", action: "provider_followup", detail: { now },
      });
      if (followup.ok) current = followup.case;
    }
    if (current.status === "provider_followup") {
      const verification = await transitionBrandCase(env, current, "verification_pending", {
        actor_type: "system", action: "verification_pending", detail: { now },
      });
      if (verification.ok) current = verification.case;
    }
    const probe = await verifyBrandCandidateGone(current.domain, { verifier });
    if (!probe.complete) {
      pending++;
      await writeBrandCaseEvent(env, current, {
        actor_type: "system",
        from_status: current.status,
        to_status: current.status,
        action: "verification_deferred",
        detail: { reason: probe.reason || "probe_incomplete", observed: probe.observed || null },
      });
      continue;
    }
    if (probe.gone) {
      const done = await transitionBrandCase(env, current, "resolved", {
        actor_type: "system",
        action: "technically_verified_removed",
        detail: { observed: probe.observed },
      });
      if (done.ok) {
        resolved++;
        await notifyBrandCase(env, done.case, {
          type: "brand_case_resolved",
          severity: "info",
          title: `Brand case resolved for ${done.case.domain}`,
          message: "CyberMeters no longer observes the abusive domain as technically present.",
        });
      }
    } else {
      pending++;
      if (current.due_at && current.due_at <= now) {
        const nr = await transitionBrandCase(env, current, "provider_no_response", {
          actor_type: "system",
          reason: "The abusive domain is still technically present after the follow-up window.",
          action: "provider_no_response",
          detail: { observed: probe.observed },
        });
        if (nr.ok) noResponse++;
      }
    }
  }
  return { resolved, pending, noResponse };
}
