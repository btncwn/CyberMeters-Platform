// ── Cyber Essentials Readiness managed cases ────────────────────────────────
// The third and final M5.a vertical. Mig 090 reserved
// `cyber_essentials_control_records.linked_case_id` and a `case_linked` event type and both
// have been dead since; this makes them mean something.
//
// Canonical systems only: `createManagedCase` is the factory, `canTransitionCase` is the
// only validator, `managed_case_events` is the history, and the verification method comes
// from the Canonical Remediation Registry via PR #129's contract.
//
// ── WHAT CE CAN AND CANNOT SEE — the whole design turns on this ──
// Of the five canonical CE controls, the repo's own honesty metadata declares only THREE
// externally assessable, and only ever PARTIALLY:
//
//   boundary_protection         external_coverage "partial"  → assessable
//   secure_configuration        external_coverage "partial"  → assessable
//   patch_management_readiness  external_coverage "partial"  → assessable
//   access_control              external_coverage "none"     → questionnaire-only
//   malware_protection          external_coverage "none"     → questionnaire-only
//
// The two `none` controls are scored from email-auth proxies that measure anti-spoofing,
// not user access control or endpoint AV. gradeCeControl returns
// `not_externally_assessable` for them, which is never `actionable`, so they can never
// carry a recurrence — and therefore can never open a case here at all. That is the honest
// answer, not an omission: there is no external observation to base a case on, and no
// verifier could ever close one. A control CyberMeters cannot see must never be presented
// as externally verified.
//
// ── THE PARTIAL CEILING ──
// The three assessable controls are `partial`, NOT full. CyberMeters observes a slice of
// each control, never the whole thing, so a case here must never imply the CONTROL is
// compliant. The lifecycle already scopes its own vocabulary this way
// (`externally_observed_control_not_ready`), and the case title/summary below keep that
// scope verbatim: what is opened, and what may later be verified, is the EXTERNALLY
// OBSERVABLE EVIDENCE for the control — never the control itself, and never the customer's
// questionnaire answer. This is the `v2026.07.16-6` "fully validated" defect class: a
// partial check must not be reported as a complete one.
//
// Both CE recurrences resolve to `ce.readiness.control_review` → `rescan` → automated, so
// every cyber_essentials_case is verifiable ONLY by CyberMeters re-observing. A customer
// attestation can never conclude one. That falls out of the registry, not a special case
// here, and the CI guard asserts the registry keeps saying it.
import {
  createManagedCase, canTransitionCase, canonicalPhaseFor, verificationSupportForCase,
} from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";
import { getRemediationById } from "./remediation-registry.js";

// Imports NOTHING from ce-lifecycle.js, deliberately — the lifecycle calls into here, so
// importing back would make a cycle. The caller passes its own record identity, control key
// and finding type, and owns its own append-only event log.
export const CE_CASE_TYPE = "cyber_essentials_case";
export const CE_CASE_DOMAIN_KEY = "cyber_essentials_readiness";

// The two alertable recurrences. Both are the EXTERNALLY OBSERVED evidence moving, and both
// are re-observable, so both open a case and both are verifiable.
export const CE_CASE_RECURRENCES = Object.freeze(new Set([
  "externally_observed_control_not_ready",  // ce_control_not_ready → rescan → automated
  "externally_observed_control_worsened",   // ce_control_worsened  → rescan → automated
]));

// The ONE system-observed verifier for this domain. `control_recovered` is Cyber Essentials'
// recovery event (mig 090) — NOT `condition_resolved`, which belongs to Website Security.
export const CE_RECOVERY_EVENT = "control_recovered";

// Scoped to the evidence, never to the control. "Boundary protection is verified" is a claim
// the product cannot make; "the externally observable evidence for boundary protection is
// clear" is one it can.
const caseTitle = (label, key) =>
  `Cyber Essentials: externally observable evidence for ${label || key} shows gaps`;
const caseSummary = (label, key) =>
  `CyberMeters observed gaps in the externally visible evidence for ${label || key}. `
  + `This is a PARTIAL view of the control — it is not a Cyber Essentials assessment, `
  + `certification, or a statement about the parts of this control CyberMeters cannot see.`;

const TERMINAL = "('rejected','false_positive','closed_no_action','superseded')";

/**
 * Open — or reopen — the canonical case for one CE control record, and write the linkage
 * mig 090 reserved.
 *
 * Idempotent by construction: createManagedCase dedupes on finding_id across non-terminal
 * cases, so an unchanged pass returns the existing case and writes no second one.
 */
export async function openOrReopenCeCase(env, {
  workspace_id, record_id, control_key, control_label = null, recurrence,
  finding_type = null, severity = "medium", now = new Date().toISOString(),
} = {}) {
  if (!env?.cybermeters_db || !workspace_id || !record_id || !recurrence) return { ok: false, code: "incomplete" };
  if (!CE_CASE_RECURRENCES.has(recurrence)) return { ok: false, code: "recurrence_does_not_open_a_case" };

  const existing = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases
              WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
                AND status NOT IN ${TERMINAL}
              LIMIT 1`)
    .bind(workspace_id, CE_CASE_TYPE, record_id).first().catch(() => null);

  if (!existing) {
    const result = await createManagedCase(env, {
      workspace_id,
      domain_key: CE_CASE_DOMAIN_KEY,
      case_type: CE_CASE_TYPE,
      source_finding_type: finding_type,
      source_finding_id: record_id,   // THE linkage — createManagedCase dedupes on this
      // NO domain: CE readiness is assessed per WORKSPACE, not per domain (mig 090 has no
      // domain_id). Passing one would be inventing an attribution the evidence does not
      // carry — and createManagedCase would validate it against workspace_domains anyway.
      domain: null,
      asset_ref: control_key || record_id,
      title: caseTitle(control_label, control_key),
      summary: caseSummary(control_label, control_key),
      severity,
      actor: { actor_type: "system", actor_id: null },
    });
    if (!result?.ok) return { ok: false, code: result?.code || "create_failed" };
    if (result.case?.id) await linkControlToCase(env, workspace_id, record_id, result.case.id);
    return { ok: true, created: Boolean(result.created), case: result.case };
  }

  // The evidence deteriorated AGAIN after we saw it clear: a recurrence, not a duplicate.
  const phase = canonicalPhaseFor(existing.case_type, existing.status);
  if (phase === "verified" || phase === "monitoring") {
    const decision = canTransitionCase({
      case: existing, target_status: "reopened",
      actor: { actor_type: "system", actor_id: null }, reason: recurrence, now,
    });
    if (decision.ok) {
      const n = decision.case;
      await env.cybermeters_db
        .prepare(`UPDATE managed_cases SET status = ?, reopened_at = ?, reopened_count = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
        .bind(n.status, n.reopened_at || now, Number(n.reopened_count || 0), n.updated_at, existing.id, workspace_id).run();
      await env.cybermeters_db
        .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                  VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
        .bind(newCaseEventId(), existing.id, workspace_id, existing.status, n.status, decision.event.action,
          JSON.stringify({ recurrence, control_key, record: record_id })).run();
      await linkControlToCase(env, workspace_id, record_id, existing.id);
      return { ok: true, reopened: true, case: { ...existing, status: n.status } };
    }
  }

  // An already-open case whose evidence moved (a NEW gap on an already-not-ready control):
  // history ON the case, and NOT a second case.
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, 'ce_recurrence', ?, datetime('now'))`)
    .bind(newCaseEventId(), existing.id, workspace_id, existing.status, existing.status,
      JSON.stringify({ recurrence, control_key, record: record_id })).run().catch(() => {});
  await linkControlToCase(env, workspace_id, record_id, existing.id);
  return { ok: true, updated: true, case: existing };
}

/**
 * Write the pointer mig 090 reserved. Tenant-scoped, and only ever called with a case id
 * that exists — the column's whole meaning is "there is a case to open".
 */
async function linkControlToCase(env, workspaceId, recordId, caseId) {
  if (!caseId) return;
  await env.cybermeters_db
    .prepare(`UPDATE cyber_essentials_control_records SET linked_case_id = ?, updated_at = datetime('now')
              WHERE id = ? AND workspace_id = ?`)
    .bind(caseId, recordId, workspaceId).run().catch(() => {});
}

/** Which case belongs to this control record. */
export async function findCeCaseForRecord(env, workspaceId, recordId, { includeTerminal = false } = {}) {
  const sql = includeTerminal
    ? `SELECT * FROM managed_cases WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT 1`
    : `SELECT * FROM managed_cases WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
         AND status NOT IN ${TERMINAL}
       ORDER BY created_at DESC, rowid DESC LIMIT 1`;
  return await env.cybermeters_db.prepare(sql).bind(workspaceId, CE_CASE_TYPE, recordId).first().catch(() => null);
}

/**
 * CyberMeters observed the external evidence support readiness again. Verify the case — if,
 * and only if, the evidence actually supports it.
 *
 * FOUR independent stops, each load-bearing:
 *
 *  1. the event must be CE's own `control_recovered`. `condition_resolved` is Website
 *     Security's vocabulary and concludes nothing here.
 *  2. `evidence_complete` — every signal the grade depends on was actually collected.
 *     gradeCeControl already refuses to call a control `ready` while anything is unknown,
 *     so the caller's recovery branch has this fact. It is re-checked HERE anyway and
 *     defaults to REFUSING, because "the caller was in the right branch" is not a contract
 *     — the next caller of this function inherits nothing. This is the #105 class.
 *  3. the registry, per finding — a finding the product cannot observe is not ours to
 *     conclude.
 *  4. the case machine — only a case the customer has driven to awaiting_verification can
 *     be verified.
 *
 * What is verified is the EXTERNALLY OBSERVABLE EVIDENCE, never the control: CE coverage is
 * `partial` by declaration, and a partial check reported as a complete one is exactly the
 * defect class the evidence-honesty corrective closed.
 */
export async function verifyCeCaseFromRecovery(env, {
  workspace_id, record_id, recovery_event_type = CE_RECOVERY_EVENT,
  evidence_complete = false, control_key = null, scan_id = null,
  observed_at = new Date().toISOString(),
} = {}) {
  if (recovery_event_type !== CE_RECOVERY_EVENT) return { skipped: "not_a_recovery_observation" };

  const kase = await findCeCaseForRecord(env, workspace_id, record_id);
  if (!kase) return { skipped: "no_open_case" };

  // STOP 2 — a grade built on signals we never collected cannot verify anything.
  if (evidence_complete !== true) {
    await noteOnCase(env, kase, workspace_id, "recovery_observed_not_verifying", {
      recovery_event_type, control_key, scan_id,
      reason: "external_evidence_incomplete",
      verification_state: "deferred",
    });
    return { skipped: "evidence_incomplete_verification_deferred" };
  }

  // STOP 3 — the registry decides, per finding.
  const support = verificationSupportForCase(kase);
  if (support !== "automated") {
    await noteOnCase(env, kase, workspace_id, "recovery_observed_not_verifying", {
      recovery_event_type, support,
      reason: "registry_method_is_not_externally_observable",
      verification_state: "unknown",
    });
    return { skipped: "verification_not_automated_for_this_finding", support };
  }

  // STOP 4 — the machine governs the path.
  const phase = canonicalPhaseFor(kase.case_type, kase.status);
  if (phase !== "awaiting_verification") {
    await noteOnCase(env, kase, workspace_id, "recovery_observed", {
      recovery_event_type, phase, reason: "case_not_awaiting_verification",
    });
    return { skipped: "case_not_awaiting_verification", phase };
  }

  // getRemediationById, NOT resolveRemediation: the latter resolves by FINDING TYPE and
  // returns an unknown-resolution (verification_method: null) for anything else.
  const rem = kase.remediation_id ? getRemediationById(kase.remediation_id) : null;
  const evidence = {
    verification_method: rem?.verification_method ?? null,
    verification_result: "fixed",
    evidence_type: recovery_event_type,
    observed_at,
    // The scope travels WITH the evidence: whatever reads this back must be able to see
    // that a partial view is what was re-observed.
    verification_scope: "externally_observable_evidence_only",
    external_coverage: "partial",
    observation: { recovery_event_type, record_id, control_key, scan_id },
  };
  const decision = canTransitionCase({
    case: kase, target_status: "verified",
    actor: { actor_type: "system", actor_id: null }, evidence, now: observed_at,
  });
  if (!decision.ok) return { skipped: "transition_refused", code: decision.code, reason: decision.reason };

  const n = decision.case;
  await env.cybermeters_db
    .prepare(`UPDATE managed_cases SET status = ?, verified_at = ?, last_verified_at = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
    .bind(n.status, n.verified_at || observed_at, observed_at, n.updated_at, kase.id, workspace_id).run();
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
    .bind(newCaseEventId(), kase.id, workspace_id, kase.status, n.status, decision.event.action, JSON.stringify(evidence)).run();
  return { ok: true, verified: true, case_id: kase.id };
}

async function noteOnCase(env, kase, workspaceId, action, detail) {
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
    .bind(newCaseEventId(), kase.id, workspaceId, kase.status, kase.status, action, JSON.stringify(detail))
    .run().catch(() => {});
}
