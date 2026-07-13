// ── Managed ASM remediation cases ──────────────────────────────────────────
// Case creation and verification loop for externally visible Attack Surface
// exposures. Reuses scan evidence; never performs a parallel probe.
import { deliverWorkspaceAlert } from "./alerts.js";
import {
  applyCaseTransition,
  buildCaseQueue,
  createCaseMachine,
  newCaseEventId,
  newManagedCaseId,
  requireExpiry,
  requireField,
  requireReason,
} from "./case-workflow.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";

export const ASM_CASE_TYPE = "asm_exposure";
export const ASM_CASE_STATES = [
  "open", "triage", "owner_assigned", "remediation_in_progress",
  "verification_requested", "verifying", "resolved",
  "risk_acceptance_requested", "risk_accepted", "false_positive",
  "verification_failed", "reopened", "closed",
];

export const ASM_CASE_MACHINE = createCaseMachine({
  states: ASM_CASE_STATES,
  transitions: {
    open: ["triage"],
    triage: ["owner_assigned", "false_positive"],
    owner_assigned: ["remediation_in_progress", "risk_acceptance_requested", "false_positive"],
    remediation_in_progress: ["verification_requested", "risk_acceptance_requested", "false_positive", "closed"],
    verification_requested: ["verifying"],
    verifying: ["resolved", "verification_failed"],
    verification_failed: ["remediation_in_progress", "verification_requested", "risk_acceptance_requested"],
    resolved: ["reopened", "closed"],
    reopened: ["remediation_in_progress"],
    risk_acceptance_requested: ["risk_accepted", "remediation_in_progress"],
    risk_accepted: ["triage"],
    false_positive: [],
    closed: [],
  },
  terminals: ["false_positive", "closed"],
  guards: {
    owner_assigned: [requireField("owner_ref")],
    remediation_in_progress: [requireField("owner_ref")],
    risk_acceptance_requested: [requireReason],
    risk_accepted: [requireReason, requireExpiry],
    false_positive: [requireReason],
    verification_failed: [requireReason],
  },
});

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

function assetRefForFinding(finding = {}, domain) {
  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  const fromEvidence = evidence.find((e) => e?.hostname || e?.host || e?.asset || e?.value);
  return String(finding.hostname || finding.asset_ref || fromEvidence?.hostname || fromEvidence?.host || fromEvidence?.asset || fromEvidence?.value || domain || "").slice(0, 255);
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

async function notifyCase(env, caseRow, { type, title, message, severity = "info", metadata = {} } = {}) {
  await createNotificationEvent(env, caseRow.workspace_id, {
    type,
    severity,
    title,
    message,
    metadata: { case_id: caseRow.id, domain: caseRow.domain, finding_id: caseRow.finding_id, ...metadata },
  });
  try {
    await deliverWorkspaceAlert(env, caseRow.workspace_id, {
      kind: type,
      severity,
      title,
      summary: message,
      domain: caseRow.domain,
    });
  } catch { /* best-effort */ }
}

async function updateCaseStatus(env, caseRow, to, ctx = {}) {
  const result = applyCaseTransition(ASM_CASE_MACHINE, caseRow, to, ctx);
  if (!result.ok) return result;
  const next = result.case;
  await env.cybermeters_db
    .prepare(`UPDATE managed_cases
      SET status = ?, reason = ?, risk_accepted_until = ?, last_verified_at = ?,
          resolved_at = ?, reopened_count = ?, updated_at = ?
      WHERE id = ? AND workspace_id = ?`)
    .bind(
      next.status, next.reason || null, next.risk_accepted_until || null,
      next.last_verified_at || null, next.resolved_at || null,
      Number(next.reopened_count || 0), next.updated_at, next.id, next.workspace_id,
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
export const SYSTEM_ONLY_CASE_STATES = new Set([
  "verifying", "resolved", "verification_failed", "reopened",
]);

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
        await notifyCase(env, reopened.case, {
          type: "managed_case_reopened",
          severity: finding.severity || "high",
          title: `Managed case reopened for ${domain}`,
          message: `${finding.title || finding.id} was detected again and needs review.`,
        });
      }
    }
    return { opened: false, case: existing };
  }

  const row = {
    id: newManagedCaseId(),
    workspace_id: workspaceId,
    case_type: ASM_CASE_TYPE,
    domain,
    finding_id: finding.id,
    asset_ref: assetRefForFinding(finding, domain),
    severity: finding.severity || "medium",
    status: "open",
    evidence_json: safeJson({ scan_id: scanId, domain_id: domainId, finding }),
    recommended_actions_json: safeJson(recommendationSnapshot(finding, recommendations), "[]"),
  };
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain, finding_id, asset_ref, severity, status,
       evidence_json, recommended_actions_json, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, 'system', datetime('now'), datetime('now'))`)
    .bind(row.id, row.workspace_id, row.case_type, row.domain, row.finding_id, row.asset_ref, row.severity, row.evidence_json, row.recommended_actions_json)
    .run();
  await writeCaseEvent(env, row, {
    actor_type: "system",
    from_status: null,
    to_status: "open",
    action: "opened",
    detail: { scan_id: scanId, domain_id: domainId, finding_id: finding.id },
  });
  await notifyCase(env, row, {
    type: "managed_case_opened",
    severity: row.severity,
    title: `Managed case opened for ${domain}`,
    message: `${finding.title || finding.id} needs an owner and remediation.`,
  });
  return { opened: true, case: row };
}

export async function createManagedAsmCasesForScan(scanId, domainId, domain, findings = [], recommendations = [], env) {
  try {
    const cleanDomain = normaliseDomain(domain);
    const wsRows = await env.cybermeters_db
      .prepare(`SELECT workspace_id FROM workspace_domains WHERE domain_id = ?`)
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

export async function verifyManagedAsmCasesForScan(scanId, domainId, domain, findings = [], env) {
  try {
    const present = new Set(findings.filter(isAsmManagedFinding).map((f) => f.id));
    const cleanDomain = normaliseDomain(domain);
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
    let resolved = 0, failed = 0;
    for (const row of (rows.results || [])) {
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
          await notifyCase(env, failure.case, {
            type: "managed_case_verification_failed",
            severity: failure.case.severity || "high",
            title: `Fix not verified for ${cleanDomain}`,
            message: "CyberMeters still observed the exposure in the latest Cyber MOT.",
          });
        }
      } else {
        const ok = await updateCaseStatus(env, current, "resolved", {
          actor_type: "system",
          action: "verified_resolved",
          detail: { scan_id: scanId, expected: "finding_absent", observed: "finding_absent" },
        });
        if (ok.ok) {
          resolved++;
          await notifyCase(env, ok.case, {
            type: "managed_case_resolved",
            severity: "info",
            title: `Managed case resolved for ${cleanDomain}`,
            message: "CyberMeters no longer observed the exposure in the latest Cyber MOT.",
          });
        }
      }
    }
    return { resolved, failed };
  } catch {
    return { resolved: 0, failed: 0 };
  }
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
