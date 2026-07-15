// ── Managed-lifecycle alert consumer (shared by all managed domains) ─────────
// ONE consumer, not one per domain. Certificates, Identity Exposure and Shadow IT
// differ only in their event table, entity identifier and recurrence vocabulary —
// all of which are data. Copying this three times is how notifyCase and
// notifyBrandCase became near-identical twins that drifted.
//
// It does NOT detect anything. Detection stays in each evaluator, which already
// computes recurrence_type + required_case_action and opens the managed case. This
// only answers: given a condition the evaluator ALREADY decided is case-worthy,
// when did it begin, and should the customer be told?
//
// Contract:
//   • the condition-start and occurrence identity come from the append-only
//     lifecycle event (findConditionOccurrence) — never evaluated_at/last_seen_at/
//     updated_at/now();
//   • no occurrence => pre-existing => baseline only, and NO timestamp is invented;
//   • customer-facing meaning comes from the Canonical Remediation Registry;
//   • delivery decisions belong to emitManagedAlert. Nothing here sends.
import { createId } from "../lib/util.js";
import { buildMonitoringTransitionDetail, findConditionOccurrence, MONITORING_CHANGED } from "./alert-occurrence.js";
import { emitManagedAlert, buildAlertDedupeKey } from "./managed-alerts.js";
import { resolveRemediation } from "./remediation-registry.js";

// Declares that this recurrence takes the RECORD's own assigned severity rather
// than a fixed grade. Not a loophole in the "never invent a severity" rule — the
// opposite. A managed case carries the severity the scoring engine already assigned
// to its finding; a static grade would OVERWRITE that decision, flattening a
// critical takeover risk and a low-severity observation into the same alert. With
// PR-A's `critical_only` preference live, that would mean a customer who asked for
// critical alerts would never be told about a critical case.
//
// The caller must then supply record_severity. If it does not, emitLifecycleAlert
// fails closed exactly as it does for an unmapped recurrence — inheriting from
// nothing is still inventing.
//
// Declared before RECURRENCE_SEVERITY because the map references it at module
// evaluation time (a `const` below would be in the temporal dead zone).
export const INHERIT_SEVERITY = "__inherit_record_severity__";

// Severity is a property of the CONDITION, not of the copy. Kept here so every
// domain grades comparably and a reader can audit the whole ladder at once.
//
// NAMESPACED BY DOMAIN (founder mandate, 15 July 2026). This was a flat map, which
// silently made every recurrence key global: `expired` meant "certificate expired,
// critical" for anyone who used the word. Adding managed cases exposed it —
// `case_opened` is a real recurrence in BOTH Brand Protection and Attack Surface,
// and a flat map would have forced them to share one grade, or worse, let a new
// domain inherit an unrelated domain's severity by name collision alone. The alert
// KIND was already namespaced (`alertKindFor` → `<domain>.<recurrence>`); only the
// severity lookup was not.
const RECURRENCE_SEVERITY = Object.freeze({
  certificates_trust: Object.freeze({
    expired: "critical",
    // INHERIT (PR-B2): a renewal-overdue certificate gets louder as it approaches
    // expiry — 30-8 days is `high`, 7-1 days is `critical` (renewalAlertBand in
    // certificate-policy.js). A static grade would have meant a customer on
    // `critical_only` never hearing that a certificate expires in three days,
    // which is the alert that matters most. The evaluator supplies the band as
    // record_severity; absent or unrecognised fails closed like any unmapped
    // recurrence, so an unbanded certificate cannot alert at an invented grade.
    renewal_overdue: INHERIT_SEVERITY,
    replacement_contradicted: "high",
    verification_failed: "high",
    replacement_unverified: "medium",
    coverage_regression: "medium",
    unexpected_san: "medium",
    exception_expired: "medium",
    owner_missing: "low",
    evidence_stale: "low",
  }),
  // `verification_failed` and `exception_expired` are declared here explicitly.
  // Under the old FLAT map they existed only in the Certificates block, and
  // identity-lifecycle.js was silently borrowing the certificate grades by name
  // collision alone — nobody had decided what an identity verification failure is
  // worth. Namespacing surfaced it. The grades below are this domain's own.
  identity_exposure: Object.freeze({
    public_admin_surface: "high",
    removal_contradicted: "high",
    verification_failed: "high",
    unexpected_surface: "medium",
    retired_reappeared: "medium",
    investigate_unresolved: "medium",
    exception_expired: "medium",
    provider_change: "low",
    owner_missing: "low",
    evidence_stale: "low",
  }),
  // Shadow IT — every recurrence the evaluator can emit is listed explicitly.
  // (Verified against shadow-it-inventory.js: approved_disappeared, evidence_stale,
  // exception_expired, material_change, owner_missing, rejected_reappeared,
  // removal_contradicted, removal_incomplete, retired_reappeared.)
  shadow_it_unmanaged_technology: Object.freeze({
    removal_incomplete: "medium",
    rejected_reappeared: "medium",
    removal_contradicted: "high",
    retired_reappeared: "medium",
    exception_expired: "medium",
    approved_disappeared: "low",   // disappearance is an observation, never verified removal
    material_change: "low",
    owner_missing: "low",
    evidence_stale: "low",
  }),
  // ── Managed-case domains (PR-B1) ──────────────────────────────────────────
  // These carry the severity their own case row was assigned by scoring, so the
  // grades that describe a specific finding INHERIT rather than flatten. The two
  // fixed grades are properties of the transition itself, not of the finding:
  // a reappearance is serious regardless of the original grade, and a resolution
  // is good news at any grade.
  brand_protection: Object.freeze({
    case_opened: INHERIT_SEVERITY,
    case_reappeared: "high",      // it came back after we called it resolved
    case_resolved: "info",
  }),
  attack_surface: Object.freeze({
    case_opened: INHERIT_SEVERITY,
    case_reopened: INHERIT_SEVERITY,
    case_verification_failed: INHERIT_SEVERITY,
    case_resolved: "info",
  }),
});

// Severity for a recurrence, or null when the recurrence is not mapped.
//
// Deliberately NOT defaulted. A silent "medium" for an unmapped recurrence would
// invent a risk grade the platform never assigned — the alert would look authored
// when nobody had decided what it means. Unknown => the consumer skips and logs, so
// a newly added recurrence shows up as a missing mapping rather than as a
// confidently-worded alert of arbitrary severity. CI asserts full coverage.
export function severityForRecurrence(domain_key, recurrence) {
  const domain = RECURRENCE_SEVERITY[String(domain_key || "")];
  if (!domain) return null;
  return domain[String(recurrence || "")] ?? null;
}

export function isMappedRecurrence(domain_key, recurrence) {
  return severityForRecurrence(domain_key, recurrence) !== null;
}

// The severities the platform grades with. An inherited value outside this set is
// not a severity we recognise, and is refused rather than passed through.
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
export const isValidSeverity = (s) => VALID_SEVERITIES.has(String(s || ""));

// Deterministic alert kind: <domain>.<recurrence>. Stable, machine-readable, and
// derived — never free text, so a reworded title can never mint a "new" alert.
export function alertKindFor(domain_key, recurrence) {
  return `${domain_key}.${recurrence}`;
}

// ── Managed-case bridge (PR-B1) ──────────────────────────────────────────────
// The ONE way a managed-case domain (Brand Protection, Attack Surface) alerts.
// It replaces the hand-rolled notifyCase/notifyBrandCase twins — near-identical
// functions that each wrote notification_events directly and fanned out to
// channels, with no occurrence, no dedupe key, no baseline guard and no delivery
// ledger. Two copies of "tell the customer" is how they drifted apart.
//
// Two steps, in this order and never reversed:
//
//   1. PERSIST the transition as an append-only managed_case_events row
//      (action='monitoring_changed'), whose created_at becomes the occurrence
//      timestamp. This is what makes a "new" claim provable: without it there is
//      no evidence the condition began when we say it did.
//   2. EMIT through emitLifecycleAlert, which re-reads that event to resolve the
//      occurrence. It deliberately re-reads rather than trusting the id we just
//      wrote — the same rule the verification incident taught: a write is not proof
//      until it has been read back.
//
// If the event write fails we do NOT alert. A customer-visible "new" claim with no
// persisted event behind it is exactly what this episode exists to prevent.
//
// ── The transition guard ─────────────────────────────────────────────────────
// An UNGUARDED append would mint a new occurrence on every evaluation, hence a new
// dedupe key, hence re-alert forever. The three lifecycle domains guard with
// isMonitoringTransition (a monitoring_status/recurrence_type diff). Managed cases
// have no monitoring_status column — their equivalent guard is the CASE STATE
// MACHINE itself: every caller reaches this function only after a transition it
// actually won (`updateCaseStatus(...).ok`, a `casCaseStatus` CAS win, or a case
// being created). canTransitionCase rejects a repeat of the same transition, so a
// re-run of the hourly sweep cannot append a second event for a condition that has
// not moved. The guard is upstream, and validate-alert-b1-canonical-cases.js
// asserts it by driving the real sweep twice.
export async function emitCaseLifecycleAlert(env, caseRow, {
  domain_key, recurrence, from_recurrence_type = null,
  finding_type = null, link = null, detail = null, actor_type = "system", actor_id = null,
} = {}) {
  try {
    if (!caseRow?.id || !caseRow?.workspace_id || !domain_key || !recurrence) {
      return { skipped: "incomplete_condition" };
    }

    // Canonical detail shape — the resolver matches on to_recurrence_type, so it is
    // built by the shared helper rather than hand-rolled here.
    const transitionDetail = buildMonitoringTransitionDetail({
      from_recurrence_type,
      to_recurrence_type: recurrence,
      entity: caseRow.domain || caseRow.asset_ref || caseRow.id,
      reason: detail?.reason ?? null,
    });

    await env.cybermeters_db
      .prepare(`INSERT INTO managed_case_events
          (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
      .bind(
        createId("mce"), caseRow.id, caseRow.workspace_id, actor_type, actor_id,
        null, null, MONITORING_CHANGED,
        JSON.stringify({ ...transitionDetail, ...(detail || {}) }),
      )
      .run();

    return await emitLifecycleAlert(env, {
      workspace_id: caseRow.workspace_id,
      domain_key,
      record_id: caseRow.id,              // the occurrence fk for managed_case_events
      entity: caseRow.domain || caseRow.asset_ref || caseRow.id,
      recurrence,
      record_severity: caseRow.severity,  // the grade scoring already assigned
      finding_type: finding_type || caseRow.finding_type || null,
      case_id: caseRow.id,
      link,
      hostname: caseRow.domain || null,
    });
  } catch (err) {
    // No persisted event => no alert. Never throws: alerting must not break the
    // evaluator that raised the case.
    console.error("[alert-consumer] case monitoring event failed", JSON.stringify({
      workspace_id: caseRow?.workspace_id, case_id: caseRow?.id, domain_key, recurrence, reason: err?.message,
    }));
    return { skipped: "monitoring_event_not_persisted" };
  }
}

// Emit one managed-lifecycle alert for a condition the evaluator has already decided
// is case-worthy. Returns {skipped} | the emitManagedAlert result. Never throws:
// alerting must not break the evaluator that raised it.
export async function emitLifecycleAlert(env, {
  workspace_id, domain_key, record_id, entity,
  recurrence, finding_type = null, case_id = null, link = null,
  hostname = null, cooldownActive = null, record_severity = null,
} = {}) {
  try {
    if (!workspace_id || !domain_key || !record_id || !recurrence) return { skipped: "incomplete_condition" };

    // An unmapped recurrence has no agreed severity or meaning. Fail closed and say
    // so, rather than grade it arbitrarily and tell the customer something we never
    // decided. CI keeps every evaluator's recurrence set mapped.
    //
    // The lookup is namespaced by domain: `case_opened` exists in two domains and
    // `expired` must never mean "certificate expired, critical" merely because
    // another domain reused the word.
    const declared = severityForRecurrence(domain_key, recurrence);
    if (declared === null) {
      console.error("[alert-consumer] unmapped recurrence", JSON.stringify({ workspace_id, domain_key, recurrence }));
      return { skipped: "unmapped_recurrence" };
    }

    // A recurrence declared INHERIT takes the record's own assigned grade. Absent or
    // unrecognised => fail closed: inheriting from nothing is still inventing, and a
    // wrong grade is worse than a missed alert now that severity gates delivery.
    const severity = declared === INHERIT_SEVERITY ? record_severity : declared;
    if (!isValidSeverity(severity)) {
      console.error("[alert-consumer] unresolved severity", JSON.stringify({ workspace_id, domain_key, recurrence, declared, record_severity }));
      return { skipped: "unmapped_recurrence" };
    }

    // 1. When did this condition begin, and which occurrence is it? Only the
    //    append-only event knows. No event => it predates alerting => baseline only.
    const occurrence = await findConditionOccurrence(env, {
      workspace_id, domain_key, record_id, recurrence_type: recurrence,
    });
    if (!occurrence) return { skipped: "baseline_only" };

    // 2. Customer-facing meaning from the canonical registry — never hand-written
    //    here, or alerts become a second source of remediation truth.
    const remediation = finding_type ? resolveRemediation({ finding_type }) : null;
    const resolved = remediation?.status === "resolved" ? remediation : null;

    // 3. Occurrence identity is the event id, so repeated hourly evaluation of the
    //    same occurrence yields the same key (=> deduplicated), while a genuine
    //    later recurrence appends a new event => new key => a new eligible alert.
    const dedupe_key = buildAlertDedupeKey({
      domain_key, kind: alertKindFor(domain_key, recurrence),
      subject: entity || record_id, period: occurrence.occurrence_id,
    });

    return await emitManagedAlert(env, {
      workspace_id, domain_key,
      kind: alertKindFor(domain_key, recurrence),
      severity,
      title: resolved?.customer_title || `${entity || record_id}: review required`,
      message: resolved?.recommended_action || "Review this item in CyberMeters.",
      dedupe_key,
      link,
      case_id,
      remediation_id: resolved?.remediation_id || null,
      observed_at: occurrence.observed_at,   // the event's OWN timestamp
      cooldown_entity: entity || record_id,
      cooldownActive,
      metadata: {
        hostname: hostname || entity || null,
        recurrence_type: recurrence,
        occurrence_id: occurrence.occurrence_id,
        required_case_action: occurrence.detail?.required_case_action || null,
        recommended_action: resolved?.recommended_action || null,
      },
    });
  } catch (err) {
    console.error("[alert-consumer] emit failed", JSON.stringify({ workspace_id, domain_key, recurrence, reason: err?.message }));
    return { skipped: "consumer_error" };
  }
}
