// ── Managed ASM remediation cases ──────────────────────────────────────────
// Case creation and verification loop for externally visible Attack Surface
// exposures. Reuses scan evidence; never performs a parallel probe.
// No direct outbound sender here: ASM alerts go through emitCaseLifecycleAlert,
// which persists the occurrence first and routes delivery through the canonical
// pipeline (entitlement, preference, dedupe, ledger). notifyCase and its Brand
// twin were near-identical hand-rolled senders that drifted apart.
import { emitCaseLifecycleAlert } from "./alert-consumers.js";
import {
  buildCaseQueue,
  newCaseEventId,
  newManagedCaseId,
} from "./case-workflow.js";
import { createAuditEvent } from "../lib/events.js";
import { normalizeDiscoveredHostname } from "./hostnames.js";
import { MANAGED_VERIFICATION_PROFILE, findingTypeOf, isSupportedVerification, runManagedVerificationProbe } from "./managed-verification.js";
import { findingRemediation } from "./remediation-registry.js";
import { ASM_CASE_TYPE, ASM_CASE_MACHINE, ASM_CASE_STATES, SYSTEM_ONLY_CASE_STATES } from "./asm-case-machine.js";
import { canTransitionCase } from "./managed-case-model.js";

// Re-exported from the neutral machine module so existing importers are unchanged.
export { ASM_CASE_TYPE, ASM_CASE_MACHINE, ASM_CASE_STATES, SYSTEM_ONLY_CASE_STATES };

const ASM_MODULES = new Set([
  "admin_surface_detection",
  "subdomain_takeover",
  "cloud_storage_discovery",
  "asset_exposure",
  "domain_security_enrichment",
]);

function safeJson(value, fallback = null) {
  if (value == null) return fallback;
  try { return JSON.stringify(value); } catch { return fallback; }
}

function parseJson(raw, fallback = null) {
  if (!raw) return fallback;
  try { return typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return fallback; }
}

function normaliseDomain(domain) {
  return String(domain || "").trim().toLowerCase();
}

// ── Affected hosts (the verification target) ─────────────────────────────────
// The hosts a finding actually concerns, as machine-readable hostnames scoped to the
// case's own domain. `affected_hosts` is emitted structurally by the ASM detectors from
// the real asset records — it is never parsed back out of customer-facing prose.
//
// Every candidate goes through normalizeDiscoveredHostname, which both validates the
// hostname shape and confirms it is the domain or a subdomain of it. Anything else
// (a sentence, a URL, a third-party bucket endpoint) is dropped rather than coerced.
//
// History: asset_ref previously fell back to the first evidence entry's `value`, which
// for every ASM finding is the finding's DESCRIPTION — so asset_ref held a prose sentence
// instead of a host, and verification could never pass its host-scope guard. The fallback
// is deliberately gone: a finding with no resolvable host now yields the domain itself,
// never free text.
function affectedHostsForFinding(finding = {}, domain) {
  const root = normaliseDomain(domain);
  const candidates = Array.isArray(finding.affected_hosts) ? finding.affected_hosts : [];
  const hosts = [];
  for (const candidate of candidates) {
    const host = normalizeDiscoveredHostname(candidate, root);
    if (host && !hosts.includes(host)) hosts.push(host);
  }
  if (hosts.length === 0) {
    const single = normalizeDiscoveredHostname(finding.hostname || finding.asset_ref, root);
    if (single) hosts.push(single);
  }
  return hosts;
}

function assetRefForFinding(finding = {}, domain) {
  const hosts = affectedHostsForFinding(finding, domain);
  return String(hosts[0] || normaliseDomain(domain) || "").slice(0, 255);
}

// Verification target for a stored case: the structured hosts captured on the finding at
// creation, each re-validated against the case's domain at read time (a stored value is
// never trusted as in-scope on the strength of having been stored). Cases created before
// affected_hosts existed carry no structured hosts; asset_ref is retried, and if it is
// legacy prose it fails validation and the case defers rather than probing the wrong host.
function verificationHostsForCase(caseRow, finding, evidence = null) {
  const domain = normaliseDomain(caseRow.domain);
  const hosts = affectedHostsForFinding(finding, domain);
  if (hosts.length > 0) return hosts;
  // Enrichment appended on a later observation of the same finding (see
  // enrichCaseAffectedHosts) — re-validated here, never trusted as stored.
  const enriched = affectedHostsForFinding({ affected_hosts: evidence?.affected_hosts }, domain);
  if (enriched.length > 0) return enriched;
  const legacy = normalizeDiscoveredHostname(caseRow.asset_ref, domain);
  return legacy ? [legacy] : [];
}

// ── Legacy-case enrichment ───────────────────────────────────────────────────
// Cases opened before affected_hosts existed stored the finding's DESCRIPTION in
// asset_ref, so they can never be verified (the host-scope guard correctly rejects
// prose). We do NOT parse that prose back into a host — it is customer-facing copy,
// not data. Instead, when the SAME finding is observed again by a later scan and that
// fresh observation carries structured hosts, we append them to the case.
//
// Append-only and non-destructive:
//   • the original evidence_json.finding snapshot is left byte-for-byte intact;
//   • hosts are added as a NEW top-level evidence key alongside it;
//   • asset_ref is only rewritten when what is stored is not a valid in-scope host
//     (i.e. legacy prose) — a case that already has a real host keeps it;
//   • the change is recorded as a case event, so the enrichment is auditable.
// The effect: the next verification of that case can proceed from real evidence.
async function enrichCaseAffectedHosts(env, existing, finding, scanId) {
  const domain = normaliseDomain(existing.domain);
  const freshHosts = affectedHostsForFinding(finding, domain);
  if (freshHosts.length === 0) return;

  const evidence = parseJson(existing.evidence_json, null);
  if (!evidence || typeof evidence !== "object") return;

  const storedHosts = affectedHostsForFinding(
    { affected_hosts: evidence.affected_hosts ?? evidence.finding?.affected_hosts },
    domain,
  );
  const assetRefUsable = Boolean(normalizeDiscoveredHostname(existing.asset_ref, domain));
  // Already verifiable and unchanged → nothing to do (idempotent on repeat scans).
  if (assetRefUsable && JSON.stringify(storedHosts) === JSON.stringify(freshHosts)) return;

  const nextEvidence = {
    ...evidence,
    affected_hosts: freshHosts,
    affected_hosts_observed_at: new Date().toISOString(),
    affected_hosts_scan_id: scanId,
  };
  const nextAssetRef = assetRefUsable ? existing.asset_ref : String(freshHosts[0]).slice(0, 255);

  await env.cybermeters_db
    .prepare(`UPDATE managed_cases SET evidence_json = ?, asset_ref = ?, updated_at = datetime('now')
              WHERE id = ? AND workspace_id = ?`)
    .bind(safeJson(nextEvidence), nextAssetRef, existing.id, existing.workspace_id)
    .run();

  await writeCaseEvent(env, existing, {
    actor_type: "system",
    from_status: existing.status,
    to_status: existing.status,
    action: "affected_hosts_enriched",
    detail: {
      scan_id: scanId,
      affected_hosts: freshHosts,
      asset_ref_replaced: !assetRefUsable,
      reason: assetRefUsable ? "affected_hosts_refreshed" : "legacy_asset_ref_not_a_host",
    },
  });
  existing.evidence_json = safeJson(nextEvidence);
  existing.asset_ref = nextAssetRef;
}

function isAsmManagedFinding(finding = {}) {
  if (!finding?.id) return false;
  if (ASM_MODULES.has(finding.module)) return true;
  const id = String(finding.id);
  return id.startsWith("admin_surface_") ||
    id.includes("takeover") ||
    id.includes("cloud_storage") ||
    id.includes("exposed_") ||
    id.includes("canonical_url") ||
    id.startsWith("dse_");
}

function recommendationSnapshot(finding = {}, recommendations = []) {
  const matches = recommendations.filter((r) => r.module && finding.module && r.module === finding.module).slice(0, 5);
  if (matches.length > 0) return matches;
  return [{
    title: finding.title || "Review exposure",
    action: finding.recommendation || finding.description || "Review and restrict this externally visible exposure.",
  }];
}

export function managedCaseToApi(row = {}) {
  return {
    id: row.id,
    workspace_id: row.workspace_id,
    case_type: row.case_type,
    domain: row.domain,
    finding_id: row.finding_id,
    asset_ref: row.asset_ref,
    severity: row.severity,
    status: row.status,
    owner_type: row.owner_type || null,
    owner_ref: row.owner_ref || null,
    assigned_by: row.assigned_by || null,
    evidence: parseJson(row.evidence_json, null),
    recommended_actions: parseJson(row.recommended_actions_json, []),
    reason: row.reason || null,
    risk_accepted_until: row.risk_accepted_until || null,
    due_at: row.due_at || null,
    last_verified_at: row.last_verified_at || null,
    resolved_at: row.resolved_at || null,
    reopened_count: Number(row.reopened_count || 0),
    created_by: row.created_by || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    age_hours: row.age_hours,
  };
}

async function writeCaseEvent(env, caseRow, { actor_type = "system", actor_id = null, from_status = null, to_status = null, action, detail = null } = {}) {
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
    event_type: `managed_case_${action}`,
    entity_type: "managed_case",
    entity_id: caseRow.id,
    description: `Managed case ${action.replace(/_/g, " ")} for ${caseRow.domain || caseRow.asset_ref || caseRow.id}`,
    metadata: { case_id: caseRow.id, domain: caseRow.domain, finding_id: caseRow.finding_id, from_status, to_status, detail },
  });
}

async function updateCaseStatus(env, caseRow, to, ctx = {}) {
  // Route ASM status changes through the UNIVERSAL validator (no bypass). It
  // dispatches to the same ASM machine + enforces the universal invariants
  // (system-only, verified-requires-structured-evidence). Verification evidence
  // for the resolve transition is supplied by the caller via ctx.evidence.
  const result = canTransitionCase({
    case: caseRow, target_status: to,
    actor: { actor_type: ctx.actor_type || "system", actor_id: ctx.actor_id || null },
    evidence: ctx.evidence ?? null, reason: ctx.reason ?? null,
    risk_accepted_until: ctx.risk_accepted_until ?? null, owner_ref: ctx.owner_ref ?? null,
    now: ctx.now,
  });
  if (!result.ok) return result;
  const next = result.case;
  await env.cybermeters_db
    .prepare(`UPDATE managed_cases
      SET status = ?, reason = ?, risk_accepted_until = ?, last_verified_at = ?,
          resolved_at = ?, reopened_count = ?, updated_at = ?,
          verified_at = ?, action_started_at = ?, awaiting_verification_at = ?,
          reopened_at = ?, accepted_at = ?, closed_at = ?
      WHERE id = ? AND workspace_id = ?`)
    .bind(
      next.status, next.reason || null, next.risk_accepted_until || null,
      next.last_verified_at || null, next.resolved_at || null,
      Number(next.reopened_count || 0), next.updated_at,
      next.verified_at || null, next.action_started_at || null, next.awaiting_verification_at || null,
      next.reopened_at || null, next.accepted_at || null, next.closed_at || null,
      next.id, next.workspace_id,
    )
    .run();
  await writeCaseEvent(env, next, {
    actor_type: ctx.actor_type || "system",
    actor_id: ctx.actor_id || null,
    from_status: caseRow.status,
    to_status: to,
    action: ctx.action || "transition",
    detail: ctx.detail || { reason: ctx.reason || null },
  });
  return { ok: true, case: next };
}

export async function assignManagedCaseOwner(env, caseRow, { owner_type, owner_ref, assigned_by = "customer", actor_id = null } = {}) {
  const type = ["person", "team", "vendor", "unknown"].includes(owner_type) ? owner_type : "unknown";
  const ref = String(owner_ref || "").trim().slice(0, 255) || "Unknown owner";
  const now = new Date().toISOString();
  await env.cybermeters_db
    .prepare(`UPDATE managed_cases
      SET owner_type = ?, owner_ref = ?, assigned_by = ?, updated_at = ?
      WHERE id = ? AND workspace_id = ?`)
    .bind(type, ref, assigned_by, now, caseRow.id, caseRow.workspace_id)
    .run();
  const updated = { ...caseRow, owner_type: type, owner_ref: ref, assigned_by, updated_at: now };
  await writeCaseEvent(env, updated, {
    actor_type: assigned_by === "system" ? "system" : "customer",
    actor_id,
    from_status: caseRow.status,
    to_status: caseRow.status,
    action: "owner_assigned",
    detail: { owner_type: type, owner_ref: ref, assigned_by },
  });
  if (caseRow.status === "triage") {
    return updateCaseStatus(env, updated, "owner_assigned", { actor_type: assigned_by === "system" ? "system" : "customer", actor_id, action: "transition" });
  }
  return { ok: true, case: updated };
}

// Verification-outcome states are reached ONLY by CyberMeters' own scan-driven
// verification (verifyManagedAsmCasesForScan → updateCaseStatus with
// actor_type "system"). A customer/analyst-initiated transition must never be
// able to self-drive them, or "independent fix verification" would be a lie and
// a case could be marked resolved without the exposure being observably absent.
export async function transitionManagedCase(env, caseRow, to, ctx = {}) {
  if ((ctx.actor_type || "customer") !== "system" && SYSTEM_ONLY_CASE_STATES.has(to)) {
    return { ok: false, error: "This step is verified by CyberMeters and cannot be set manually." };
  }
  return updateCaseStatus(env, caseRow, to, ctx);
}

export async function listManagedCases(env, workspaceId, { status = null, case_type = ASM_CASE_TYPE, limit = 50 } = {}) {
  await reassessExpiredRiskAcceptedCases(env, workspaceId);
  const where = ["workspace_id = ?", "case_type = ?"];
  const binds = [workspaceId, case_type];
  if (status) { where.push("status = ?"); binds.push(status); }
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE ${where.join(" AND ")} ORDER BY created_at ASC LIMIT ?`)
    .bind(...binds, Math.max(1, Math.min(200, Number(limit || 50))))
    .all();
  return buildCaseQueue(rows.results || []).map(managedCaseToApi);
}

export async function getManagedCase(env, workspaceId, caseId) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ?`)
    .bind(caseId, workspaceId)
    .first();
}

export async function listManagedCaseEvents(env, workspaceId, caseId) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at
              FROM managed_case_events WHERE workspace_id = ? AND case_id = ? ORDER BY created_at ASC`)
    .bind(workspaceId, caseId)
    .all();
  return (rows.results || []).map((r) => ({ ...r, detail: parseJson(r.detail_json, null), detail_json: undefined }));
}

async function isFindingWaived(env, workspaceId, domain, findingId) {
  const row = await env.cybermeters_db
    .prepare(`SELECT id FROM finding_waivers WHERE workspace_id = ? AND domain = ? AND finding_id = ? LIMIT 1`)
    .bind(workspaceId, domain, findingId)
    .first()
    .catch(() => null);
  return Boolean(row);
}

async function openCaseForFinding(env, { workspaceId, domainId, scanId, domain, finding, recommendations }) {
  const existing = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases
              WHERE workspace_id = ? AND domain = ? AND finding_id = ?
                AND status NOT IN ('false_positive', 'closed')
              LIMIT 1`)
    .bind(workspaceId, domain, finding.id)
    .first();

  if (existing) {
    // Same finding observed again → append any structured hosts this observation
    // carries, so a legacy prose-asset_ref case becomes verifiable from real evidence.
    await enrichCaseAffectedHosts(env, existing, finding, scanId).catch(() => {});
    if (existing.status === "resolved") {
      const reopened = await updateCaseStatus(env, existing, "reopened", {
        actor_type: "system",
        action: "reopened",
        detail: { scan_id: scanId, observed: "finding_present" },
      });
      if (reopened.ok) {
        await updateCaseStatus(env, reopened.case, "remediation_in_progress", {
          actor_type: "system",
          action: "transition",
          detail: { scan_id: scanId, observed: "finding_present" },
        });
        await emitCaseLifecycleAlert(env, reopened.case, {
          domain_key: "attack_surface",
          recurrence: "case_reopened",
          from_recurrence_type: "case_resolved",
          finding_type: finding.id,
          detail: { scan_id: scanId, observed: "finding_present" },
        });
      }
    }
    return { opened: false, case: existing };
  }

  // Universal-case linkage: attach the canonical domain_key, the source finding
  // type + scan, and the canonical remediation_id (null when no remediation).
  const remediationId = findingRemediation({ id: finding.id, finding_type: "finding" })?.remediation_id ?? null;
  const row = {
    id: newManagedCaseId(),
    workspace_id: workspaceId,
    case_type: ASM_CASE_TYPE,
    domain_key: "attack_surface",
    domain,
    finding_id: finding.id,
    source_finding_type: finding.id,
    source_scan_id: scanId,
    remediation_id: remediationId,
    asset_ref: assetRefForFinding(finding, domain),
    severity: finding.severity || "medium",
    status: "open",
    evidence_json: safeJson({ scan_id: scanId, domain_id: domainId, finding }),
    recommended_actions_json: safeJson(recommendationSnapshot(finding, recommendations), "[]"),
  };
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, source_finding_type,
       source_scan_id, remediation_id, asset_ref, severity, status,
       evidence_json, recommended_actions_json, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, 'system', datetime('now'), datetime('now'))`)
    .bind(row.id, row.workspace_id, row.case_type, row.domain_key, row.domain, row.finding_id,
      row.source_finding_type, row.source_scan_id, row.remediation_id, row.asset_ref, row.severity,
      row.evidence_json, row.recommended_actions_json)
    .run();
  await writeCaseEvent(env, row, {
    actor_type: "system",
    from_status: null,
    to_status: "open",
    action: "opened",
    detail: { scan_id: scanId, domain_id: domainId, finding_id: finding.id },
  });
  await emitCaseLifecycleAlert(env, row, {
    domain_key: "attack_surface",
    recurrence: "case_opened",
    finding_type: finding.id,
    detail: { scan_id: scanId, domain_id: domainId, finding_id: finding.id },
  });
  return { opened: true, case: row };
}

export async function createManagedAsmCasesForScan(scanId, domainId, domain, findings = [], recommendations = [], env) {
  try {
    const cleanDomain = normaliseDomain(domain);
    // Soft-deleted workspaces must NOT keep auto-opening cases during the 30-day
    // purge window — join workspaces and exclude deleted_at rows.
    const wsRows = await env.cybermeters_db
      .prepare(`SELECT wd.workspace_id FROM workspace_domains wd
                JOIN workspaces w ON w.id = wd.workspace_id
                WHERE wd.domain_id = ? AND w.deleted_at IS NULL`)
      .bind(domainId)
      .all();
    const workspaces = wsRows.results || [];
    if (workspaces.length === 0) return { opened: 0 };
    const managedFindings = findings.filter(isAsmManagedFinding);
    let opened = 0;
    for (const { workspace_id } of workspaces) {
      await reassessExpiredRiskAcceptedCases(env, workspace_id).catch(() => {});
      for (const finding of managedFindings) {
        if (await isFindingWaived(env, workspace_id, cleanDomain, finding.id)) continue;
        const result = await openCaseForFinding(env, {
          workspaceId: workspace_id, domainId, scanId, domain: cleanDomain, finding, recommendations,
        }).catch(() => null);
        if (result?.opened) opened++;
      }
    }
    return { opened };
  } catch {
    return { opened: 0 };
  }
}

// Verification completeness gate. A case must NEVER be resolved off an
// incomplete scan: if the exposure's own module explicitly failed / timed out /
// was skipped, or the whole scan came back "partial" (a core module broke),
// absence of the finding is NOT evidence the exposure is gone — it may just not
// have been looked for. Such cases are deferred (left awaiting verification,
// with an audit event) and retried on the next complete scan.
//
// FAIL-CLOSED. Absence-of-finding is only evidence of remediation when we can show
// the module that would have detected the exposure actually ran and completed. So
// the gate now refuses to verify whenever it cannot demonstrate that:
//   • no modules/scan-quality evidence at all → nothing verifies. Previously this
//     returned null and callers (`if (gate && !gate.canVerify(...))`) skipped gating
//     entirely, which is precisely "a completed scan verified the fix" — the thing
//     the platform's verification contract forbids.
//   • a case whose finding records no module → nothing to prove ran → no verification.
//   • an untracked module (present in neither `modules` nor the scan-quality report)
//     was previously trusted by omission; absence of telemetry is not evidence.
// The gate always returns an object now, so a caller can never silently opt out.
export function moduleCompletionGate(modules, scanQuality) {
  const haveEvidence = Boolean(modules || scanQuality);
  const incomplete = new Set(scanQuality?.modules_skipped || []);
  for (const [name, value] of Object.entries(modules || {})) {
    // A module that errored OR self-reported incomplete evidence (e.g. exposure
    // probes starved by the subrequest budget) did not truly re-check the exposure.
    if (value?.error || value?.incomplete === true) incomplete.add(name);
  }
  const scanPartial = scanQuality?.status === "partial";
  return {
    incomplete,
    scanPartial,
    haveEvidence,
    canVerify(relevantModule) {
      if (!haveEvidence) return false;              // no completeness evidence → never verify
      if (scanPartial) return false;
      if (!relevantModule) return false;            // unknown detecting module → cannot prove it ran
      if (incomplete.has(relevantModule)) return false;
      return Object.prototype.hasOwnProperty.call(modules || {}, relevantModule); // must have run
    },
  };
}

function relevantModuleForCase(caseRow) {
  return parseJson(caseRow.evidence_json)?.finding?.module || null;
}

export async function verifyManagedAsmCasesForScan(scanId, domainId, domain, findings = [], env, { modules = null, scanQuality = null } = {}) {
  try {
    const present = new Set(findings.filter(isAsmManagedFinding).map((f) => f.id));
    const cleanDomain = normaliseDomain(domain);
    const gate = moduleCompletionGate(modules, scanQuality);
    const rows = await env.cybermeters_db
      .prepare(`SELECT mc.*
                FROM managed_cases mc
                JOIN workspace_domains wd ON wd.workspace_id = mc.workspace_id
               WHERE wd.domain_id = ?
                 AND mc.case_type = ?
                 AND mc.domain = ?
                 AND mc.status IN ('verification_requested', 'verifying')`)
      .bind(domainId, ASM_CASE_TYPE, cleanDomain)
      .all();
    let resolved = 0, failed = 0, deferred = 0;
    for (const row of (rows.results || [])) {
      // Completeness guard (fail-closed): never resolve/fail off a scan that cannot be
      // shown to have actually re-checked this exposure's module. Defer and retry on
      // the next complete scan.
      const relevantModule = relevantModuleForCase(row);
      if (!gate.canVerify(relevantModule)) {
        await writeCaseEvent(env, row, {
          actor_type: "system",
          from_status: row.status,
          to_status: row.status,
          action: "verification_deferred",
          detail: {
            scan_id: scanId,
            module: relevantModule,
            reason: !gate.haveEvidence ? "no_completeness_evidence"
              : gate.scanPartial ? "scan_partial"
              : !relevantModule ? "unknown_detecting_module"
              : gate.incomplete.has(relevantModule) ? "module_incomplete"
              : "module_did_not_run",
          },
        });
        deferred++;
        continue;
      }
      let current = row;
      if (current.status === "verification_requested") {
        const verifying = await updateCaseStatus(env, current, "verifying", {
          actor_type: "system", action: "verification_started", detail: { scan_id: scanId },
        });
        if (!verifying.ok) continue;
        current = verifying.case;
      }
      const stillPresent = present.has(current.finding_id);
      if (stillPresent) {
        const failure = await updateCaseStatus(env, current, "verification_failed", {
          actor_type: "system",
          action: "verification_failed",
          reason: "CyberMeters still observed this exposure in the latest Cyber MOT.",
          detail: { scan_id: scanId, expected: "finding_absent", observed: "finding_present" },
        });
        if (failure.ok) {
          failed++;
          await emitCaseLifecycleAlert(env, failure.case, {
            domain_key: "attack_surface",
            recurrence: "case_verification_failed",
            detail: { observed: "still_present", source: "cyber_mot" },
          });
        }
      } else {
        const ok = await updateCaseStatus(env, current, "resolved", {
          actor_type: "system",
          action: "verified_resolved",
          detail: { scan_id: scanId, expected: "finding_absent", observed: "finding_absent" },
          // Structured verification evidence (module-completeness already gated
          // above, so this is a re-check of the specific exposure, not a bare scan).
          evidence: {
            verification_method: "rescan",
            verification_result: "fixed",
            evidence_type: "scan_absence",
            observed_at: new Date().toISOString(),
            observation: { scan_id: scanId, finding_id: current.finding_id, absent: true, module_complete: true },
          },
        });
        if (ok.ok) {
          resolved++;
          await emitCaseLifecycleAlert(env, ok.case, {
            domain_key: "attack_surface",
            recurrence: "case_resolved",
            detail: { observed: "absent", source: "cyber_mot" },
          });
        }
      }
    }
    return { resolved, failed, deferred };
  } catch {
    return { resolved: 0, failed: 0, deferred: 0 };
  }
}

// ── Managed-verification profile (single-case, lean re-check) ─────────────────
// Verifies ONE case's affected host via the managed_verification profile — it does not
// run a full scan. All scope is derived from the STORED case (never the client).
//
// Concurrency model (Commit 4 scope): compare-and-set on managed_cases.status —
// single-invocation dedup, so duplicate concurrent requests cause exactly one probe.
// This is NOT durable cross-window idempotency (no idempotency-key table); the
// correlation key is recorded in the audit trail only. A deferred probe RELEASES the
// claim (verifying → verification_requested) so it stays retryable.
export const VERIFICATION_ELIGIBLE_STATES = new Set(["verification_requested", "verifying", "resolved"]);

// Stable short version of a finding (case + finding version → idempotency key).
function findingVersionHash(text) {
  let h = 5381;
  for (const ch of String(text || "")) h = ((h << 5) + h + ch.charCodeAt(0)) & 0xffffffff;
  return (h >>> 0).toString(36);
}

// Atomic compare-and-set on case status. Returns true iff THIS caller moved it (so
// duplicate concurrent verification runs cannot both proceed).
async function casCaseStatus(env, caseRow, from, to, extraSet = "") {
  // Validate the edge through the universal validator BEFORE the atomic write —
  // the CAS provides concurrency safety, canTransitionCase provides legality (no
  // status mutation bypasses the validator). System actor: these claim/release/
  // reappearance edges are all CyberMeters-driven.
  const decision = canTransitionCase({
    case: { ...caseRow, status: from }, target_status: to,
    actor: { actor_type: "system", actor_id: null },
    // Reappearance (resolved → reopened) is not a verified target, so no evidence
    // is required; the release and claim edges are non-verified too.
  });
  if (!decision.ok) return false;
  const res = await env.cybermeters_db
    .prepare(`UPDATE managed_cases SET status = ?, updated_at = datetime('now')${extraSet} WHERE id = ? AND workspace_id = ? AND status = ?`)
    .bind(to, caseRow.id, caseRow.workspace_id, from)
    .run();
  return (res?.meta?.changes || 0) === 1;
}

export async function verifyManagedCaseById(env, { workspaceId, caseId, actorId = null, correlationId = null } = {}) {
  // 1. Load case (workspace-scoped) — foreign workspace/case → not found (non-enumerating).
  const caseRow = await getManagedCase(env, workspaceId, caseId).catch(() => null);
  if (!caseRow) return { ok: false, code: "not_found" };

  // 2. Eligible state
  if (!VERIFICATION_ELIGIBLE_STATES.has(caseRow.status)) return { ok: false, code: "ineligible_state", status: caseRow.status };

  // 3. Finding + allowlisted, supported type (unsupported fails closed → deferred).
  const caseEvidence = parseJson(caseRow.evidence_json, null);
  const finding = caseEvidence?.finding || {};
  if (!isSupportedVerification(finding)) {
    await writeCaseEvent(env, caseRow, { actor_type: "system", from_status: caseRow.status, to_status: caseRow.status, action: "verification_deferred", detail: { profile: MANAGED_VERIFICATION_PROFILE, reason: "unsupported_finding_type", finding_type: findingTypeOf(finding) } });
    return { ok: false, code: "unsupported_finding_type" };
  }

  // 4. Affected host(s) derived from the STORED case; each must belong to the case's
  //    domain. A finding may cover several hosts, so this is a validated list — the
  //    probe concludes "fixed" only when EVERY one of them is observed clear.
  const domain = normaliseDomain(caseRow.domain);
  const hosts = verificationHostsForCase(caseRow, finding, caseEvidence);
  if (hosts.length === 0) {
    await writeCaseEvent(env, caseRow, {
      actor_type: "system", from_status: caseRow.status, to_status: caseRow.status,
      action: "verification_deferred",
      detail: { profile: MANAGED_VERIFICATION_PROFILE, reason: "no_affected_host_in_scope", finding_type: findingTypeOf(finding) },
    });
    return { ok: false, code: "host_scope_mismatch" };
  }

  // 5. Domain still linked to this workspace (removed/archived → ineligible).
  const link = await env.cybermeters_db
    .prepare(`SELECT d.id FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ? AND d.domain = ? LIMIT 1`)
    .bind(workspaceId, domain).first().catch(() => null);
  if (!link) return { ok: false, code: "domain_ineligible" };

  // 6. Correlation key for the audit trail. NOTE: this is NOT durable cross-window
  //    idempotency enforcement — concurrency is enforced by the compare-and-set claim
  //    in step 7 (single-invocation dedup). Commit 4 is scoped to CAS-based concurrency.
  const correlationKey = correlationId || `${caseId}:${findingVersionHash(caseRow.evidence_json)}:${caseRow.status}`;

  // 7. Concurrency claim via compare-and-set. verification_requested → verifying (winner
  //    only); an in-flight 'verifying' means another run holds it → no-op. 'resolved'
  //    probes for reappearance and claims resolved→reopened below.
  let workingStatus = caseRow.status;
  if (caseRow.status === "verification_requested") {
    const won = await casCaseStatus(env, caseRow, "verification_requested", "verifying");
    if (!won) return { ok: true, code: "in_progress", idempotent: true };
    workingStatus = "verifying";
    await writeCaseEvent(env, { ...caseRow, status: "verifying" }, { actor_type: "system", from_status: "verification_requested", to_status: "verifying", action: "verification_started", detail: { profile: MANAGED_VERIFICATION_PROFILE, correlation_key: correlationKey } });
  } else if (caseRow.status === "verifying") {
    return { ok: true, code: "in_progress", idempotent: true };
  }

  // 8. Lean probe of ONLY the affected host(s), metered.
  let outbound = 0;
  const startedAt = new Date().toISOString();
  const probe = await runManagedVerificationProbe(finding, hosts, { onOutbound: () => { outbound++; } });
  const audit = { profile: MANAGED_VERIFICATION_PROFILE, case_id: caseId, finding_id: caseRow.finding_id, finding_type: findingTypeOf(finding), host: hosts[0], hosts, correlation_key: correlationKey, started_at: startedAt, completed_at: new Date().toISOString(), outbound_calls: outbound, completeness: probe.completeness, decision: probe.decision, evidence: probe.evidence || null };
  const working = { ...caseRow, status: workingStatus };

  // 9. Decision → lifecycle (system actor only).
  if (probe.decision === "deferred") {
    // Release the claim so the case is never permanently locked in 'verifying': a
    // timeout / SSRF refusal / DNS-indeterminate / budget result must stay retryable.
    // Atomic verifying → verification_requested (preserves ownership).
    if (working.status === "verifying") {
      await casCaseStatus(env, caseRow, "verifying", "verification_requested");
      await writeCaseEvent(env, { ...caseRow, status: "verification_requested" }, { actor_type: "system", from_status: "verifying", to_status: "verification_requested", action: "verification_deferred", detail: audit });
    } else {
      await writeCaseEvent(env, working, { actor_type: "system", from_status: working.status, to_status: working.status, action: "verification_deferred", detail: audit });
    }
    return { ok: true, code: "deferred", decision: "deferred", completeness: probe.completeness, outbound_calls: outbound };
  }

  if (probe.decision === "still_present") {
    if (working.status === "verifying") {
      const r = await updateCaseStatus(env, working, "verification_failed", { actor_type: "system", action: "verification_failed", reason: "CyberMeters still observed this exposure.", detail: audit });
      if (r.ok) await emitCaseLifecycleAlert(env, r.case, { domain_key: "attack_surface", recurrence: "case_verification_failed", detail: audit });
    } else if (working.status === "resolved") {
      // Reappearance: claim resolved → reopened exactly once (CAS), then remediation.
      const won = await casCaseStatus(env, caseRow, "resolved", "reopened", ", reopened_count = COALESCE(reopened_count, 0) + 1");
      if (won) {
        await writeCaseEvent(env, { ...caseRow, status: "reopened" }, { actor_type: "system", from_status: "resolved", to_status: "reopened", action: "reopened", detail: audit });
        const fresh = await getManagedCase(env, workspaceId, caseId);
        if (fresh) {
          await updateCaseStatus(env, fresh, "remediation_in_progress", { actor_type: "system", action: "transition", detail: audit });
          await emitCaseLifecycleAlert(env, fresh, { domain_key: "attack_surface", recurrence: "case_reopened", from_recurrence_type: "case_resolved", finding_type: caseRow.finding_id, detail: audit });
        }
      }
    }
    return { ok: true, code: "still_present", decision: "still_present", outbound_calls: outbound };
  }

  if (probe.decision === "fixed") {
    if (working.status === "verifying") {
      const r = await updateCaseStatus(env, working, "resolved", { actor_type: "system", action: "verified_resolved", detail: audit,
        evidence: {
          verification_method: "automated_probe",
          verification_result: "fixed",
          evidence_type: "http_probe",
          observed_at: audit.completed_at,
          observation: audit.evidence || { host: audit.host, decision: audit.decision, completeness: audit.completeness },
        } });
      if (r.ok) await emitCaseLifecycleAlert(env, r.case, { domain_key: "attack_surface", recurrence: "case_resolved", detail: audit });
    }
    // A 'resolved' case that is still fixed → no-op (idempotent).
    return { ok: true, code: "fixed", decision: "fixed", outbound_calls: outbound };
  }

  return { ok: true, code: "no_change", outbound_calls: outbound };
}

export async function reassessExpiredRiskAcceptedCases(env, workspaceId = null, now = new Date().toISOString()) {
  const where = ["status = 'risk_accepted'", "risk_accepted_until IS NOT NULL", "risk_accepted_until <= ?"];
  const binds = [now];
  if (workspaceId) { where.push("workspace_id = ?"); binds.push(workspaceId); }
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE ${where.join(" AND ")} LIMIT 100`)
    .bind(...binds)
    .all()
    .catch(() => ({ results: [] }));
  let reassessed = 0;
  for (const row of rows.results || []) {
    const result = await updateCaseStatus(env, row, "triage", {
      actor_type: "system",
      action: "risk_acceptance_expired",
      detail: { risk_accepted_until: row.risk_accepted_until },
    }).catch(() => null);
    if (result?.ok) reassessed++;
  }
  return { reassessed };
}
