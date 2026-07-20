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
import { getEmailFrontendOrigin } from "../lib/lifecycle-email.js";
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
  // ── Email Protection (PR-B3) ──────────────────────────────────────────────
  // Every grade below is CARRIED from behaviour already shipped on the legacy
  // paths this episode deletes — none is invented, and no customer-visible grade
  // changes.
  //
  // Only ACTIONABLE conditions appear here (founder decision, 15 July 2026).
  // Confirmations — reconnected, policy_changed, manual rollback, sender recovery
  // — are deliberately ABSENT. They append lifecycle events for history and are
  // structurally unable to alert: their event_type is not `monitoring_changed`,
  // so findConditionOccurrence cannot match them. Absence here is a second,
  // independent stop: even a future caller that hand-rolled a monitoring_changed
  // row for one of them would be refused as an unmapped recurrence.
  //
  // NOT PRESENT, and must never be: SPF/DKIM/DMARC/BIMI/MTA-STS posture. It has
  // no persisted identity — per-scan `findings` rows take a fresh random id every
  // scan — so no occurrence can be attributed to it. See email-protection-lifecycle.js.
  email_protection: Object.freeze({
    // INHERIT: the band comes from senderAlertBand(classification) — the B2
    // pattern. An `unauthorised` sender is `high` and a `suspicious`/`unknown`
    // one is `medium`, exactly as the legacy sweep graded them
    // (dmarc-alerts.js:101). A static grade would flatten those into one, and
    // with `critical_only` live, flattening is how a customer stops hearing the
    // thing that mattered.
    sender_unrecognised: INHERIT_SEVERITY,
    // Same ladder: worsening exists to ESCALATE medium→high, so its severity must
    // follow the new band rather than a fixed grade.
    sender_classification_worsened: INHERIT_SEVERITY,
    // Fixed: an unauthorised source failing authentication at volume is `high`
    // regardless of anything else about it (legacy dmarc-alerts.js:86).
    sender_unauthorised_failures_active: "high",
    // Fixed: our hosted link is gone (legacy hosted-dmarc.js:529).
    hosted_record_disconnected: "high",
    // INHERIT: the grade is already decided by assessImpactRollback and supplied
    // as record_severity (legacy hosted-dmarc.js:569 used the same value).
    hosted_impact_regression: INHERIT_SEVERITY,
    // Fixed, and deliberately split from the manual rollback. The legacy path
    // computed `source === "auto" ? "high" : "medium"` inline; splitting the
    // recurrence keeps severity an ASSERTED lookup instead of a computed one,
    // with no change to the grade a customer sees. The manual half is not here at
    // all — a customer's own rollback is not a risk alert.
    hosted_rolled_back_auto: "high",
  }),
  // ── Website Security (corrective phase) ───────────────────────────────────
  // Every grade INHERITS, and that is the honest choice rather than a shortcut.
  // Severity for this domain is already decided by scoring.js and is a property of
  // the CONDITION, not of the transition: `ssl_not_available` is critical,
  // `header_missing_strict_transport_security` is high, `header_malformed_*` and the
  // validated `ssl_no_http_redirect` are medium. A fixed grade here would OVERWRITE
  // the platform's own decision and flatten a critical transport failure into the
  // same alert as a malformed header — and with `critical_only` live, flattening is
  // how a customer stops hearing the thing that mattered.
  //
  // The evaluator supplies the scan's own severity as record_severity and as the
  // recurrence_band, so a condition that WORSENS (medium → high on the same
  // recurrence_type) is a transition in its own right and escalates — the PR-B2
  // pattern. Absent or unrecognised fails closed like any unmapped recurrence, so an
  // ungraded condition cannot alert at an invented grade.
  //
  // ONLY actionable conditions appear here. Recovery, baseline and unknown are
  // deliberately ABSENT: they append lifecycle events for history and are
  // structurally unable to alert (their event_type is not `monitoring_changed`, so
  // findConditionOccurrence cannot match them). Absence here is the second,
  // independent stop.
  //
  // NOT PRESENT, and must never be: the info/low grades this domain also emits —
  // `security_headers_not_observed`, `header_weak_hsts`, `canonical_url_uncertain`,
  // `tech_*`. They are evidence-quality signals, not customer events, and a
  // downgrade to one of them means our evidence got weaker, not that anything
  // was fixed. website-security-lifecycle.js records that as `unknown`.
  website_security: Object.freeze({
    transport_not_available:       INHERIT_SEVERITY,
    insecure_redirect:             INHERIT_SEVERITY,
    browser_protection_missing:    INHERIT_SEVERITY,
    browser_protection_malformed:  INHERIT_SEVERITY,
  }),
  // ── Cyber Essentials Readiness (corrective phase) ─────────────────────────
  // FIXED at medium, and deliberately NOT inherited — the opposite reasoning to
  // every other domain here, for a reason worth stating.
  //
  // CE detects nothing of its own. Each control theme re-interprets evidence another
  // domain already owns AND ALREADY ALERTS ON at that evidence's own grade: a missing
  // DMARC record is Email Protection's alert, an expired certificate is Certificates
  // & Trust's. If CE inherited those grades it would re-raise the same urgency a
  // second time under a different name — the duplicate-detection this domain's
  // ownership decision exists to prevent.
  //
  // What CE adds is a different, quieter question: "are you still on track for
  // certification?" That is a review item, not an incident, so it is graded as one.
  // The technical domain keeps the urgent grade; CE keeps the readiness framing. A
  // customer on `critical_only` therefore hears the technical alert and is not
  // interrupted twice.
  //
  // Only the two externally evidenced transitions appear. Recovery and unknown are
  // absent: they append history and are structurally unable to alert (their
  // event_type is not `monitoring_changed`), and absence here is the second stop.
  // access_control and malware_protection can never reach this map at all — the
  // evaluator refuses them upstream on external_coverage: "none".
  cyber_essentials_readiness: Object.freeze({
    externally_observed_control_not_ready: "medium",
    externally_observed_control_worsened:  "medium",
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
// ── Where a lifecycle alert points ──────────────────────────────────────────
// THE DEFECT THIS EXISTS TO FIX (traced 2026-07-16): not one of the lifecycle emit sites
// passed a `link`. managed-alerts.js fell back to `${origin}/notifications`, so a customer
// told their DMARC record had disconnected — at `high` — landed on a generic alert list
// with no way to reach the record. An alert is not actionable if the customer cannot open
// what it references.
//
// ONE mapping, here, rather than a URL built at each of the six emit sites: the deep link
// is part of the alert contract, and six copies of it is six chances to point somewhere
// that does not exist. Every target below is a route that exists in App.jsx — a link to a
// route that does not is a different broken promise, not a fix.
//
// The identifiers are the records' own stable ids (`wsc-`, `cec-`, `hd-`/`snd-`), which
// are opaque per-tenant surrogates, not enumerable integers, and the page they land on is
// workspace-scoped and auth-gated: a customer without access gets the same nothing they
// would get by typing the URL.
const LIFECYCLE_LINK_BUILDERS = Object.freeze({
  website_security: (origin, recordId) =>
    `${origin}/ws/website-security?condition=${encodeURIComponent(recordId)}`,
  cyber_essentials_readiness: (origin, recordId) =>
    `${origin}/ws/cyber-essentials?control=${encodeURIComponent(recordId)}`,
  email_protection: (origin, recordId) =>
    `${origin}/ws/email-protection?lifecycle=${encodeURIComponent(recordId)}`,
  // Shadow IT alerts used to dead-end at the generic notifications list. The
  // inventory page is the canonical read surface (App.jsx: /ws/shadow-it); the
  // record id is the item's own opaque `sii-` surrogate, and the page is
  // workspace-scoped + auth-gated, so the link is tenant-safe by the same rule as
  // every other builder here.
  shadow_it_unmanaged_technology: (origin, recordId) =>
    `${origin}/ws/shadow-it?item=${encodeURIComponent(recordId)}`,
});

/**
 * The customer-facing URL for a lifecycle record, or null when this domain has no read
 * surface yet. Null is honest: managed-alerts falls back to the notifications list, which
 * is where the customer would otherwise have been sent anyway.
 */
export function lifecycleRecordLink(env, domain_key, record_id) {
  const build = LIFECYCLE_LINK_BUILDERS[domain_key];
  if (!build || !record_id) return null;
  const origin = getEmailFrontendOrigin(env);
  return origin ? build(origin, record_id) : null;
}

export function alertKindFor(domain_key, recurrence) {
  return `${domain_key}.${recurrence}`;
}

// ── What changed vs. what to do (alert-truth episode, July 2026) ─────────────
// `message` (the email's "What Changed") and `metadata.recommended_action` were
// BOTH sourced from the registry's recommended_action — the customer read the
// same sentence twice, and neither described the event. The registry stays the
// one source of remediation meaning (the ACTION); the EVENT description comes
// from the recurrence transition itself, which the registry cannot know.
//
// Per-recurrence copy is bounded and namespaced by domain, exactly like
// RECURRENCE_SEVERITY. Where a recurrence has no specific copy, the fallback is a
// truthful generic transition statement — never the recommendation again, so the
// two can never collapse back into one sentence.
//
// owner_missing carries its own copy because the registry action for the finding
// ("confirm it is sanctioned") is WRONG for this transition: the service is
// already approved — implying it needs sanction review would misdescribe the
// customer's own classification. The truthful meaning is "approved, but nobody
// owns it".
const RECURRENCE_COPY = Object.freeze({
  shadow_it_unmanaged_technology: Object.freeze({
    owner_missing: Object.freeze({
      what_changed: () => "An approved service does not have an assigned owner.",
      action: (entity) => `Assign a business or technical owner for ${entity} and record the responsible team.`,
    }),
  }),
});

export function humanizeRecurrence(recurrence) {
  return String(recurrence || "").replace(/_/g, " ").trim();
}

// The generic event description: names the entity and the observed transition,
// asserts nothing beyond them. Deliberately NOT the recommendation.
export function describeRecurrenceEvent(domain_key, recurrence, entityDisplay) {
  const copy = RECURRENCE_COPY[String(domain_key || "")]?.[String(recurrence || "")];
  if (copy?.what_changed) return copy.what_changed(entityDisplay);
  const subject = String(entityDisplay || "").trim() || "A monitored item";
  return `${subject}: condition "${humanizeRecurrence(recurrence)}" was observed.`;
}

// The recommendation: recurrence-specific override first (a transition can make
// the finding-level action wrong — see owner_missing), then the canonical
// registry action, then the bounded fallback.
export function recommendationForRecurrence(domain_key, recurrence, entityDisplay, registryAction) {
  const copy = RECURRENCE_COPY[String(domain_key || "")]?.[String(recurrence || "")];
  if (copy?.action) return copy.action(String(entityDisplay || "").trim() || "this item");
  return registryAction || "Review this item in CyberMeters.";
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
  // Semantic entity typing (alert-truth episode). Optional and additive: a caller
  // that knows its entity is a service/vendor/certificate says so, with a
  // customer-facing display name; monitored_domain is the workspace domain the
  // observation belongs to (shown separately from the entity — a service is not a
  // domain); evidence_source is a structured { label, detail, last_seen_at }
  // summary of HOW it was observed. Callers that pass none of these keep the
  // legacy behaviour exactly.
  entity_type = null, entity_display = null, monitored_domain = null, evidence_source = null,
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

    // 4. Where the customer can open this. An explicit `link` from the caller still wins
    //    — a domain that knows a better destination than "its own record" should say so —
    //    but no caller passing one is why every lifecycle alert dead-ended at the generic
    //    notifications list until now. Falls back to null (and thence to that same list)
    //    for domains with no read surface: pointing at a page that does not exist would
    //    be worse than pointing at a general one.
    const record_link = link || lifecycleRecordLink(env, domain_key, record_id);

    // What changed ≠ what to do. The event description comes from the recurrence
    // transition; the recommendation from the recurrence override or the registry.
    // They are built by separate functions so they can never collapse back into
    // the same registry string (the defect this episode fixes).
    const displayName = String(entity_display || "").trim() || entity || record_id;
    const whatChanged = describeRecurrenceEvent(domain_key, recurrence, displayName);
    const recommendation = recommendationForRecurrence(domain_key, recurrence, displayName, resolved?.recommended_action || null);

    return await emitManagedAlert(env, {
      workspace_id, domain_key,
      kind: alertKindFor(domain_key, recurrence),
      severity,
      title: resolved?.customer_title || `${entity || record_id}: review required`,
      message: whatChanged,
      dedupe_key,
      link: record_link,
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
        recommended_action: recommendation,
        // Typed entity + bounded evidence for the email field mapping
        // (managed-alerts.js buildAlertEmailFields). Absent for legacy callers.
        entity_type: entity_type || null,
        entity_display: entity_type ? displayName : null,
        monitored_domain: monitored_domain || null,
        evidence_source: evidence_source || null,
        // The in-app card reads its destination from metadata, not from the row's `link`
        // column (NotificationsPage.jsx). Without this the email would deep-link and the
        // card next to it would not — the same alert, two different answers to "where do
        // I go".
        link: record_link,
      },
    });
  } catch (err) {
    console.error("[alert-consumer] emit failed", JSON.stringify({ workspace_id, domain_key, recurrence, reason: err?.message }));
    return { skipped: "consumer_error" };
  }
}
