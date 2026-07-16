// ── Email Protection managed cases ──────────────────────────────────────────
// The case layer mig 088 never had. Its lifecycle recorded conditions and alerted on them
// for months with nothing to own, action or close: an alert with no case is a notification,
// not a managed service.
//
// Everything here goes through the canonical systems. `createManagedCase` is the factory,
// `canTransitionCase` is the only validator, `managed_case_events` is the history, and the
// verification method comes from the Canonical Remediation Registry via the contract
// shipped in PR #129. There is no Email case model — there is the universal one, used.
//
// ── LINKAGE, AND WHY THERE IS NO MIGRATION ──
// Migration 088 created NO state table: the events ARE the history and the current state
// lives on the parent rows (`hosted_dns_entries`, `email_sender_sources`), which have no
// linked_case_id column. The forward pointer already exists — `managed_cases.finding_id`
// holds the lifecycle record id — and `createManagedCase` already dedupes on
// (workspace_id, case_type, finding_id) across non-terminal cases. So the reverse lookup is
// a QUERY, not a new column, and an unchanged evaluation pass creates nothing. Adding a
// column would be a migration to duplicate a pointer the schema already has.
//
// ── ONE CASE PER RECORD, NOT PER CONDITION ──
// finding_id is the RECORD id, so a sender carrying both `sender_unrecognised` and
// `sender_classification_worsened` gets ONE case (they share a finding_type too), and a
// hosted record gets one. That matches identity/shadow_it and is what a customer means by
// "this sender needs looking at".
import {
  createManagedCase, canTransitionCase, canonicalPhaseFor, verificationSupportForCase,
} from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";
import { getRemediationById } from "./remediation-registry.js";

// This module imports NOTHING from email-protection-lifecycle.js, deliberately: the
// lifecycle calls into here, so importing back would make a cycle. ES modules tolerate a
// cycle whose bindings are only touched at call time, and every use here would qualify
// today — which is exactly why it is worth refusing now, while the invariant is cheap. The
// caller already knows its own finding_type and record identity and passes them in; the
// caller also owns its append-only event log and writes the linkage event itself.
export const EMAIL_CASE_TYPE = "email_case";
export const EMAIL_PROTECTION_DOMAIN_KEY = "email_protection";

// ── Which recurrences open a case ───────────────────────────────────────────
// Five of the six. `hosted_impact_regression` is deliberately ABSENT, and the reason is the
// point rather than an oversight:
//
//   its registry method is `receiver_reports` — the product CAN observe it — but the engine
//   emits the regression and NEVER an "impact recovered" signal, so no system verifier
//   exists or can exist without new detection work.
//
// A case there could never honestly reach `verified`. Declaring it `unsupported` would
// contradict the registry, which says it is observable; opening it anyway would leave a
// case that cannot be closed honestly — the "cases but no honest verifier" state the
// vertical ship rule forbids. It continues to ALERT exactly as before. When an
// impact-recovery observation exists, it joins this map and nothing else changes.
export const EMAIL_CASE_RECURRENCES = Object.freeze(new Set([
  "hosted_record_disconnected",          // dns_recheck        → automated  ← hosted_record_reconnected
  "hosted_rolled_back_auto",             // manual_attestation → manual     (registry: cannot observe)
  "sender_unrecognised",                 // manual_attestation → manual
  "sender_classification_worsened",      // manual_attestation → manual
  "sender_unauthorised_failures_active", // receiver_reports   → automated  ← sender_failures_recovered
]));

// ── Which recovery observation verifies which condition ─────────────────────
// The two system-observed verifiers, and ONLY these. Both are CyberMeters re-observing the
// world, with no customer input: a DNS lookup of the hosted record, and zero
// receiver-reported failures across a COMPLETE window (a cumulative counter could never
// come back down — the window can, which is why recovery is expressible at all).
export const EMAIL_RECOVERY_VERIFIES = Object.freeze({
  hosted_record_reconnected: "hosted_record_disconnected",
  sender_failures_recovered: "sender_unauthorised_failures_active",
});

const caseTitle = (recurrence, entity) =>
  `Email Protection: ${String(recurrence).replace(/_/g, " ")} (${entity})`;

/**
 * Open — or reopen — the canonical case for one Email lifecycle record.
 *
 * Idempotent by construction: createManagedCase dedupes on finding_id across non-terminal
 * cases, so an unchanged pass returns the existing case and writes no second one.
 */
export async function openOrReopenEmailCase(env, {
  workspace_id, record_id, entity, domain = null, recurrence, finding_type = null,
  severity = "medium", now = new Date().toISOString(),
} = {}) {
  if (!env?.cybermeters_db || !workspace_id || !record_id || !recurrence) return { ok: false, code: "incomplete" };
  if (!EMAIL_CASE_RECURRENCES.has(recurrence)) return { ok: false, code: "recurrence_does_not_open_a_case" };

  // An existing non-terminal case for this record?
  const existing = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases
              WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
                AND status NOT IN ('rejected','false_positive','closed_no_action','superseded')
              LIMIT 1`)
    .bind(workspace_id, EMAIL_CASE_TYPE, record_id).first().catch(() => null);

  if (!existing) {
    const result = await createManagedCase(env, {
      workspace_id,
      domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
      case_type: EMAIL_CASE_TYPE,
      source_finding_type: finding_type,
      source_finding_id: record_id,   // THE linkage — the reverse lookup reads this
      // `domain` is passed only for the hosted family. createManagedCase validates it
      // against workspace_domains, and a sender's entity is an IP, not a domain the
      // workspace owns — passing one would fail the eligibility check for a legitimate case.
      domain,
      asset_ref: entity || record_id,
      title: caseTitle(recurrence, entity || record_id),
      summary: `Externally observed Email Protection condition needs review: ${String(recurrence).replace(/_/g, " ")}.`,
      severity,
      actor: { actor_type: "system", actor_id: null },
    });
    if (!result?.ok) return { ok: false, code: result?.code || "create_failed" };
    return { ok: true, created: Boolean(result.created), case: result.case };
  }

  // A verified/monitoring case whose condition RETURNED is a recurrence, not a duplicate:
  // reopen it through the canonical validator rather than minting a second case.
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
          JSON.stringify({ recurrence, record: record_id })).run();
      return { ok: true, reopened: true, case: { ...existing, status: n.status } };
    }
  }

  // An already-open case, same condition: history on the case, and NOT a second case.
  // Typed `case_recurrence_noted` for the same reason the other domains type it that way —
  // it records that the case was touched again, not that anything about the monitoring
  // state changed, and it must never enter the occurrence resolver's namespace.
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, 'email_recurrence', ?, datetime('now'))`)
    .bind(newCaseEventId(), existing.id, workspace_id, existing.status, existing.status,
      JSON.stringify({ recurrence, record: record_id })).run().catch(() => {});
  return { ok: true, updated: true, case: existing };
}

/**
 * The reverse lookup mig 088 has no column for: which case belongs to this record.
 * A query, not a duplicated pointer.
 */
export async function findEmailCaseForRecord(env, workspaceId, recordId, { includeTerminal = false } = {}) {
  const sql = includeTerminal
    ? `SELECT * FROM managed_cases WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT 1`
    : `SELECT * FROM managed_cases WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
         AND status NOT IN ('rejected','false_positive','closed_no_action','superseded')
       ORDER BY created_at DESC, rowid DESC LIMIT 1`;
  return await env.cybermeters_db.prepare(sql).bind(workspaceId, EMAIL_CASE_TYPE, recordId).first().catch(() => null);
}

/**
 * CyberMeters observed the condition clear. Verify the case — if, and only if, the
 * registry says this finding is ours to observe.
 *
 * This is the whole point of the increment: the customer drives the case up to
 * `awaiting_verification`, and the last step is an observation, never an assertion. A
 * recovery event for a `manual_attestation` finding is NOT a verification — the registry
 * says we cannot see that fix, so seeing "no failures" is not evidence the customer did
 * anything. It is recorded as history and the case waits for the attestation the registry
 * does endorse.
 */
export async function verifyEmailCaseFromRecovery(env, {
  workspace_id, record_id, recovery_event_type, observed_at = new Date().toISOString(),
} = {}) {
  const recurrence = EMAIL_RECOVERY_VERIFIES[recovery_event_type];
  if (!recurrence) return { skipped: "not_a_recovery_observation" };

  const kase = await findEmailCaseForRecord(env, workspace_id, record_id);
  if (!kase) return { skipped: "no_open_case" };

  // The registry decides, per finding — not this function, and not the domain.
  const support = verificationSupportForCase(kase);
  if (support !== "automated") {
    await env.cybermeters_db
      .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                VALUES (?, ?, ?, 'system', NULL, ?, ?, 'recovery_observed_not_verifying', ?, datetime('now'))`)
      .bind(newCaseEventId(), kase.id, workspace_id, kase.status, kase.status,
        JSON.stringify({ recovery_event_type, support, reason: "registry_method_is_not_externally_observable" })).run().catch(() => {});
    return { skipped: "verification_not_automated_for_this_finding", support };
  }

  // The machine still governs the path: only a case the customer has driven to
  // awaiting_verification can be verified. Observing a recovery for a case nobody has
  // acted on is real, and it is history — it is not a completed remediation.
  const phase = canonicalPhaseFor(kase.case_type, kase.status);
  if (phase !== "awaiting_verification") {
    await env.cybermeters_db
      .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                VALUES (?, ?, ?, 'system', NULL, ?, ?, 'recovery_observed', ?, datetime('now'))`)
      .bind(newCaseEventId(), kase.id, workspace_id, kase.status, kase.status,
        JSON.stringify({ recovery_event_type, phase, reason: "case_not_awaiting_verification" })).run().catch(() => {});
    return { skipped: "case_not_awaiting_verification", phase };
  }

  // getRemediationById, NOT resolveRemediation: the latter resolves by FINDING TYPE and
  // returns an unknown-resolution for anything else, which silently produced
  // `verification_method: undefined` — evidence the contract then refused. The case already
  // holds the resolved remediation id; this reads that entry directly.
  const rem = kase.remediation_id ? getRemediationById(kase.remediation_id) : null;
  const evidence = {
    verification_method: rem?.verification_method ?? null,
    verification_result: "fixed",
    evidence_type: recovery_event_type,
    observed_at,
    observation: { recovery_event_type, record_id, recurrence },
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
