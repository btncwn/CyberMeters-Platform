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
import { findConditionOccurrence } from "./alert-occurrence.js";
import { emitManagedAlert, buildAlertDedupeKey } from "./managed-alerts.js";
import { resolveRemediation } from "./remediation-registry.js";

// Severity is a property of the CONDITION, not of the copy. Kept here so all three
// domains grade comparably and a reader can audit the whole ladder at once.
const RECURRENCE_SEVERITY = Object.freeze({
  // Certificates
  expired: "critical",
  renewal_overdue: "high",
  replacement_contradicted: "high",
  verification_failed: "high",
  replacement_unverified: "medium",
  coverage_regression: "medium",
  unexpected_san: "medium",
  exception_expired: "medium",
  // Identity Exposure
  public_admin_surface: "high",
  removal_contradicted: "high",
  unexpected_surface: "medium",
  retired_reappeared: "medium",
  investigate_unresolved: "medium",
  provider_change: "low",
  // Shadow IT — every recurrence the evaluator can emit is listed explicitly.
  // (Verified against shadow-it-inventory.js: approved_disappeared, evidence_stale,
  // exception_expired, material_change, owner_missing, rejected_reappeared,
  // removal_contradicted, removal_incomplete, retired_reappeared.)
  removal_incomplete: "medium",
  rejected_reappeared: "medium",
  approved_disappeared: "low",   // disappearance is an observation, never verified removal
  material_change: "low",
  // Cross-domain
  owner_missing: "low",
  evidence_stale: "low",
});

// Severity for a recurrence, or null when the recurrence is not mapped.
//
// Deliberately NOT defaulted. A silent "medium" for an unmapped recurrence would
// invent a risk grade the platform never assigned — the alert would look authored
// when nobody had decided what it means. Unknown => the consumer skips and logs, so
// a newly added recurrence shows up as a missing mapping rather than as a
// confidently-worded alert of arbitrary severity. CI asserts full coverage.
export function severityForRecurrence(recurrence) {
  return RECURRENCE_SEVERITY[String(recurrence || "")] ?? null;
}

export function isMappedRecurrence(recurrence) {
  return severityForRecurrence(recurrence) !== null;
}

// Deterministic alert kind: <domain>.<recurrence>. Stable, machine-readable, and
// derived — never free text, so a reworded title can never mint a "new" alert.
export function alertKindFor(domain_key, recurrence) {
  return `${domain_key}.${recurrence}`;
}

// Emit one managed-lifecycle alert for a condition the evaluator has already decided
// is case-worthy. Returns {skipped} | the emitManagedAlert result. Never throws:
// alerting must not break the evaluator that raised it.
export async function emitLifecycleAlert(env, {
  workspace_id, domain_key, record_id, entity,
  recurrence, finding_type = null, case_id = null, link = null,
  hostname = null, cooldownActive = null,
} = {}) {
  try {
    if (!workspace_id || !domain_key || !record_id || !recurrence) return { skipped: "incomplete_condition" };

    // An unmapped recurrence has no agreed severity or meaning. Fail closed and say
    // so, rather than grade it arbitrarily and tell the customer something we never
    // decided. CI keeps every evaluator's recurrence set mapped.
    const severity = severityForRecurrence(recurrence);
    if (severity === null) {
      console.error("[alert-consumer] unmapped recurrence", JSON.stringify({ workspace_id, domain_key, recurrence }));
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
