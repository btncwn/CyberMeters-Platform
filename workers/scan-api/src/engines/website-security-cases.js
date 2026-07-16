// ── Website Security managed cases ──────────────────────────────────────────
// The case layer mig 089 declared but never had. The migration reserved
// `website_security_conditions.linked_case_id` and a `case_linked` event type, and both
// have been dead since: the column was always null and the route's linked_case lookup
// could never return anything. This is the increment that makes them mean something.
//
// Everything goes through the canonical systems: `createManagedCase` is the factory,
// `canTransitionCase` is the only validator, `managed_case_events` is the history, and the
// verification method comes from the Canonical Remediation Registry via PR #129's contract.
// There is no Website Security case model — there is the universal one, used.
//
// ── LINKAGE — the column exists here, unlike Email ──
// Mig 088 created no state table, so Email's reverse lookup had to be a query. Mig 089 DID
// create a state table WITH `linked_case_id`, so the pointer is written where the schema
// already reserved it. `managed_cases.finding_id` still holds the condition id as the
// forward pointer, so the two directions agree and `createManagedCase`'s dedupe on
// (workspace_id, case_type, finding_id) still makes an unchanged pass create nothing.
// The column is populated ONLY once a real case exists — a non-null linked_case_id is a
// promise that the case is there to open.
//
// ── WHY EVERY RECURRENCE OPENS A CASE (contrast Email) ──
// Email had to exclude `hosted_impact_regression`: the registry called it observable but no
// recovery signal existed, so a case could never honestly close. Website Security has no
// such hole. All four recurrences resolve to `https_recheck`, and ONE recovery event —
// `condition_resolved` — covers every one of them, because the same evaluator that observes
// a condition observes its absence. So there is no condition here that can be opened but
// never honestly verified.
//
// ── VERIFICATION IS AN OBSERVATION, NEVER AN ASSERTION ──
// All 14 Website Security condition keys (2 ssl_* + 6 headers × missing/malformed) resolve
// to `https_recheck` in the registry, so verificationSupportForCase returns "automated" for
// every website_case and a customer attestation can never conclude one. That is not enforced
// by a special case here — it falls out of the registry, and the CI guard asserts the
// registry keeps saying it.
import {
  createManagedCase, canTransitionCase, canonicalPhaseFor, verificationSupportForCase,
} from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";
import { getRemediationById } from "./remediation-registry.js";

// Imports NOTHING from website-security-lifecycle.js, deliberately — the lifecycle calls
// into here, so importing back would make a cycle. The caller knows its own condition key
// and record identity and passes them in, and owns its own append-only event log.
export const WEBSITE_CASE_TYPE = "website_case";
export const WEBSITE_SECURITY_DOMAIN_KEY = "website_security";

// The four alertable recurrence classes the lifecycle can emit. Every one opens a case and
// every one is verifiable by re-observation.
export const WEBSITE_CASE_RECURRENCES = Object.freeze(new Set([
  "transport_not_available",       // ssl_not_available          → https_recheck → automated
  "insecure_redirect",             // ssl_no_http_redirect       → https_recheck → automated
  "browser_protection_missing",    // header_missing_*           → https_recheck → automated
  "browser_protection_malformed",  // header_malformed_*         → https_recheck → automated
]));

// The ONE system-observed verifier for this domain. `condition_resolved` is the Website
// Security recovery event (mig 089) — NOT `control_recovered`, which belongs to Cyber
// Essentials and names a different table's vocabulary entirely.
export const WEBSITE_RECOVERY_EVENT = "condition_resolved";

const caseTitle = (conditionKey, entity) =>
  `Website Security: ${String(conditionKey).replace(/_/g, " ")} (${entity})`;

const TERMINAL = "('rejected','false_positive','closed_no_action','superseded')";

/**
 * Open — or reopen — the canonical case for one Website Security condition, and write the
 * linkage the migration reserved.
 *
 * Idempotent by construction: createManagedCase dedupes on finding_id across non-terminal
 * cases, so an unchanged pass returns the existing case and writes no second one.
 *
 * Returns { ok, created?, reopened?, updated?, case } — the caller writes its own
 * `case_linked` lifecycle event, because the caller owns that log.
 */
export async function openOrReopenWebsiteCase(env, {
  workspace_id, record_id, entity, domain = null, recurrence, condition_key = null,
  severity = "medium", now = new Date().toISOString(),
} = {}) {
  if (!env?.cybermeters_db || !workspace_id || !record_id || !recurrence) return { ok: false, code: "incomplete" };
  if (!WEBSITE_CASE_RECURRENCES.has(recurrence)) return { ok: false, code: "recurrence_does_not_open_a_case" };

  const existing = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases
              WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
                AND status NOT IN ${TERMINAL}
              LIMIT 1`)
    .bind(workspace_id, WEBSITE_CASE_TYPE, record_id).first().catch(() => null);

  if (!existing) {
    const result = await createManagedCase(env, {
      workspace_id,
      domain_key: WEBSITE_SECURITY_DOMAIN_KEY,
      case_type: WEBSITE_CASE_TYPE,
      // The condition_key IS the canonical finding id, so the registry resolves the
      // remediation (web.header.hsts, web.https.redirect, cert.tls.install) with no second
      // mapping to drift.
      source_finding_type: condition_key,
      source_finding_id: record_id,
      // Unlike an Email sender (whose entity is an IP), a Website Security condition is
      // domain-scoped by construction (mig 089), so the domain is always a real
      // workspace_domains entry and passes createManagedCase's eligibility check.
      domain,
      asset_ref: entity || record_id,
      title: caseTitle(condition_key || recurrence, entity || record_id),
      summary: `Externally observed Website Security condition needs remediation: ${String(recurrence).replace(/_/g, " ")}.`,
      severity,
      actor: { actor_type: "system", actor_id: null },
    });
    if (!result?.ok) return { ok: false, code: result?.code || "create_failed" };
    if (result.case?.id) await linkConditionToCase(env, workspace_id, record_id, result.case.id);
    return { ok: true, created: Boolean(result.created), case: result.case };
  }

  // The condition RETURNED after we saw it clear: a recurrence, not a duplicate. Reopen
  // through the canonical validator rather than minting a second case.
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
          JSON.stringify({ recurrence, condition_key, record: record_id })).run();
      // Re-assert the linkage: the case is live again and the column must still point at it.
      await linkConditionToCase(env, workspace_id, record_id, existing.id);
      return { ok: true, reopened: true, case: { ...existing, status: n.status } };
    }
  }

  // An already-open case, same condition (e.g. the grade worsened): history ON the case, and
  // NOT a second case. Never `monitoring_changed` — that action name belongs to the
  // occurrence resolver's namespace and this is not a monitoring transition.
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, 'website_recurrence', ?, datetime('now'))`)
    .bind(newCaseEventId(), existing.id, workspace_id, existing.status, existing.status,
      JSON.stringify({ recurrence, condition_key, record: record_id })).run().catch(() => {});
  await linkConditionToCase(env, workspace_id, record_id, existing.id);
  return { ok: true, updated: true, case: existing };
}

/**
 * Write the pointer mig 089 reserved. Tenant-scoped, and only ever called with a case id
 * that exists — the column's whole meaning is "there is a case to open".
 */
async function linkConditionToCase(env, workspaceId, recordId, caseId) {
  if (!caseId) return;
  await env.cybermeters_db
    .prepare(`UPDATE website_security_conditions SET linked_case_id = ?, updated_at = datetime('now')
              WHERE id = ? AND workspace_id = ?`)
    .bind(caseId, recordId, workspaceId).run().catch(() => {});
}

/**
 * Which case belongs to this condition. Reads the column mig 089 reserved, and falls back to
 * the finding_id query so a row whose pointer was never written (every row created before
 * this increment) still resolves.
 */
export async function findWebsiteCaseForRecord(env, workspaceId, recordId, { includeTerminal = false } = {}) {
  const sql = includeTerminal
    ? `SELECT * FROM managed_cases WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT 1`
    : `SELECT * FROM managed_cases WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
         AND status NOT IN ${TERMINAL}
       ORDER BY created_at DESC, rowid DESC LIMIT 1`;
  return await env.cybermeters_db.prepare(sql).bind(workspaceId, WEBSITE_CASE_TYPE, recordId).first().catch(() => null);
}

/**
 * CyberMeters observed the condition clear. Verify the case — if, and only if, the evidence
 * actually supports it.
 *
 * THREE independent stops, and each one is load-bearing:
 *
 *  1. `module_assessed` — the detecting module provably ran to completion. The caller's
 *     `condition_resolved` branch is already gated on moduleCompletionGate.canVerify(), so
 *     this argument re-states a fact the caller has. It is re-checked here ANYWAY and
 *     defaults to REFUSING, because "the caller was in the right branch" is not a contract:
 *     the next caller of this function inherits nothing. Incomplete, partial or
 *     never-executed evidence produces a deferred history row, never a verification. This
 *     is the #105 defect class — an unexecuted probe reading as a clean result — and the
 *     guard belongs where the conclusion is drawn, not only where it happens to be called.
 *  2. the registry, per finding — a `manual_attestation` finding is not ours to conclude.
 *  3. the case machine — only a case the customer has driven to awaiting_verification can
 *     be verified. Observing a fix on a case nobody has acted on is real, and it is
 *     history; it is not a completed remediation.
 */
export async function verifyWebsiteCaseFromResolution(env, {
  workspace_id, record_id, recovery_event_type = WEBSITE_RECOVERY_EVENT,
  module_assessed = false, detecting_module = null, scan_id = null,
  observed_at = new Date().toISOString(),
} = {}) {
  // Only THE Website Security recovery event verifies. `control_recovered` is Cyber
  // Essentials' vocabulary and must never conclude anything here.
  if (recovery_event_type !== WEBSITE_RECOVERY_EVENT) return { skipped: "not_a_recovery_observation" };

  const kase = await findWebsiteCaseForRecord(env, workspace_id, record_id);
  if (!kase) return { skipped: "no_open_case" };

  // STOP 1 — absence is only evidence of a fix when the module that detects it provably ran.
  if (module_assessed !== true) {
    await noteOnCase(env, kase, workspace_id, "resolution_observed_not_verifying", {
      recovery_event_type, detecting_module, scan_id,
      reason: "detecting_module_not_proven_complete",
      verification_state: "deferred",
    });
    return { skipped: "evidence_incomplete_verification_deferred" };
  }

  // STOP 2 — the registry decides, per finding. Every Website Security condition is
  // https_recheck today, so this never fires for a resolved condition — it is here because
  // the registry is the authority and this function must not assume its current answer.
  const support = verificationSupportForCase(kase);
  if (support !== "automated") {
    await noteOnCase(env, kase, workspace_id, "resolution_observed_not_verifying", {
      recovery_event_type, support,
      reason: "registry_method_is_not_externally_observable",
      verification_state: "unknown",
    });
    return { skipped: "verification_not_automated_for_this_finding", support };
  }

  // STOP 3 — the machine still governs the path.
  const phase = canonicalPhaseFor(kase.case_type, kase.status);
  if (phase !== "awaiting_verification") {
    await noteOnCase(env, kase, workspace_id, "resolution_observed", {
      recovery_event_type, phase, reason: "case_not_awaiting_verification",
    });
    return { skipped: "case_not_awaiting_verification", phase };
  }

  // getRemediationById, NOT resolveRemediation: the latter resolves by FINDING TYPE and
  // returns an unknown-resolution (verification_method: null) for anything else — evidence
  // the contract then refuses. The case already holds the resolved remediation id.
  const rem = kase.remediation_id ? getRemediationById(kase.remediation_id) : null;
  const evidence = {
    verification_method: rem?.verification_method ?? null,
    verification_result: "fixed",
    evidence_type: recovery_event_type,
    observed_at,
    observation: { recovery_event_type, record_id, detecting_module, scan_id },
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
