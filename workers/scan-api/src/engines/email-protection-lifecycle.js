// ── Email Protection managed lifecycle (PR-B3) ──────────────────────────────
// The ONE canonical owner of Email Protection alerting. Two record families, one
// domain_key, one append-only event source:
//   hosted_dns_entries    (mig 071) → our managed DMARC/TLS-RPT/MTA-STS records
//   email_sender_sources  (mig 054) → who receivers report is sending as you
//
// ── Why one engine and one table ────────────────────────────────────────────
// LIFECYCLE_EVENT_SOURCES maps one domain_key to exactly one {table, fk,
// type_column}. Both families are `email_protection`, so a second table is not
// expressible: one family would silently resolve no occurrence forever — the
// exact production defect PR-B1 found in Brand Protection and Attack Surface.
// record_id is generic and the two id namespaces ('hd-' / 'esender_') are
// disjoint, which is a CI-asserted invariant because the database cannot hold it.
//
// ── Why Email Protection was harder than B1/B2 ──────────────────────────────
// B1 and B2 wired alerts onto lifecycles that already existed. Email had NONE.
// So this engine creates the transition semantics — and that is precisely why it
// may only grade conditions the platform can already evidence:
//
//   • Posture (SPF/DKIM/DMARC/BIMI/MTA-STS) is NOT alertable here and must never
//     be. It is recomputed per scan into the R2 blob (scan-engine.js) plus
//     `findings` rows that get a FRESH RANDOM ID every scan and carry no
//     workspace_id and no state. There is nothing to attribute an occurrence to.
//     Worse, email-scan.js probes phase-2 DKIM selectors ONLY if SPF resolution
//     succeeded — so a flaky SPF lookup silently narrows the DKIM probe set and
//     can flip DKIM to "not detected" with nothing having changed at the
//     customer. A blob diff cannot tell that apart from a real regression.
//
//   • Sender thresholds NEVER read email_sender_sources.failed_messages /
//     total_messages. Those columns are CUMULATIVE LIFETIME counters
//     (dmarc-ingest.js: `existing.total_messages + agg.total`) and never
//     decrease, so a threshold on them LATCHES TRUE FOREVER and recovery is
//     mathematically inexpressible. The legacy sweep this engine replaces did
//     exactly that, and only the 24h dedupe stopped it re-alerting daily,
//     forever. Volumes here are WINDOWED over dmarc_aggregate_records — the
//     append-only, receiver-reported evidence, which drops out of the window and
//     therefore CAN recover.
//
// ── Honesty (permanent) ─────────────────────────────────────────────────────
// DMARC aggregate reports are what RECEIVING mail providers tell us they saw.
// They do not prove an attack, a spike, an increase, or that any message was
// delivered or read. We report an ABSOLUTE COUNT INSIDE A FIXED WINDOW, because
// that is the only thing the evidence supports: we hold no prior-period baseline
// to compare against, so "spike"/"increase" would be a claim we cannot make.
// A disconnected hosted record means OUR link is absent — never that the domain
// is unprotected, because the customer may publish their own DMARC TXT directly.
//
// ── Non-alertable transitions are enforced by construction ──────────────────
// Founder decision (15 July 2026): confirmations and customer actions append
// history but must never alert. That is not implemented by remembering to skip a
// call — it is structural. Those events use their own event_type (never
// `monitoring_changed`) and carry to_recurrence_type = null, so
// findConditionOccurrence cannot match them and no alert path exists at all.
import { emitLifecycleAlert } from "./alert-consumers.js";
import { dmarcAuthoritySourceSql } from "../lib/dmarc-authority.js";
import {
  aggregateReportCompleteSql,
  sha256Hex,
} from "../lib/aggregate-report-ingest.js";
import {
  assertedClassification, isCustomerDisposition, isObservedClassification,
  resolveEffectiveClassification,
} from "./sender-classification.js";
import {
  MONITORING_CHANGED, buildMonitoringTransitionDetail, isMonitoringTransition, parseUtcMs,
} from "./alert-occurrence.js";
import { ensureAlertActivation } from "./managed-alerts.js";
// One direction only: this module calls INTO the case layer. email-protection-cases.js
// imports nothing back, so there is no cycle to reason about at init time.
import {
  EMAIL_CASE_RECURRENCES, EMAIL_RECOVERY_VERIFIES,
  openOrReopenEmailCase, verifyEmailCaseFromRecovery,
} from "./email-protection-cases.js";

export const EMAIL_PROTECTION_DOMAIN_KEY = "email_protection";

// The two record families sharing the event source.
export const HOSTED_RECORD_TYPE = "hosted_dns_entry";
export const SENDER_RECORD_TYPE = "email_sender_source";
export const DMARC_POLICY_CONDITION_RECORD_TYPE = "dmarc_policy_condition";

// Non-alertable event types. Each is a real fact worth keeping, and none may
// ever alert. They are deliberately NOT `monitoring_changed`: the resolver only
// looks at that value, so these are unreachable by the alert path by design.
export const EMAIL_EVENT_BASELINE               = "baseline_established";
export const EMAIL_EVENT_DMARC_DOMAIN_BASELINE  = "dmarc_domain_baseline_established";
export const EMAIL_EVENT_HOSTED_RECONNECTED     = "hosted_record_reconnected";
export const EMAIL_EVENT_HOSTED_POLICY_CHANGED  = "hosted_policy_changed";
export const EMAIL_EVENT_HOSTED_ROLLED_BACK_MANUAL = "hosted_rolled_back_manual";
export const EMAIL_EVENT_SENDER_RECOVERED       = "sender_failures_recovered";
export const EMAIL_EVENT_SENDER_MANUAL_CLASS    = "sender_manual_classification";
// Case linkage. History only — never `monitoring_changed`, so the occurrence resolver
// cannot see them and they can never become an alert.
export const EMAIL_EVENT_CASE_LINKED           = "case_linked";
export const EMAIL_EVENT_CASE_REOPENED         = "case_reopened";

export const NON_ALERTABLE_EVENT_TYPES = Object.freeze([
  EMAIL_EVENT_BASELINE,
  EMAIL_EVENT_DMARC_DOMAIN_BASELINE,
  EMAIL_EVENT_HOSTED_RECONNECTED,
  EMAIL_EVENT_HOSTED_POLICY_CHANGED,
  EMAIL_EVENT_HOSTED_ROLLED_BACK_MANUAL,
  EMAIL_EVENT_SENDER_RECOVERED,
  EMAIL_EVENT_SENDER_MANUAL_CLASS,
  EMAIL_EVENT_CASE_LINKED,
  EMAIL_EVENT_CASE_REOPENED,
]);

// The six actionable recurrences. Their severities live in RECURRENCE_SEVERITY
// (alert-consumers.js) — never here, so there is one ladder to audit.
export const EMAIL_RECURRENCES = Object.freeze([
  "hosted_record_disconnected",
  "hosted_impact_regression",
  "hosted_rolled_back_auto",
  "sender_unrecognised",
  "sender_classification_worsened",
  "sender_unauthorised_failures_active",
]);

// finding_type → the Canonical Remediation Registry. Prefixed `email_` so they
// match the email_protection domain matcher in cyber-mot-domains.js, which tests
// /^(email_|dmarc_|spf_|dkim_|mta_|bimi_|tlsrpt_)/ — a `hosted_dmarc_*` slug
// would NOT match and would land the finding in no domain at all.
export const EMAIL_RECURRENCE_FINDING_TYPE = Object.freeze({
  hosted_record_disconnected:          "email_hosted_dmarc_disconnected",
  hosted_impact_regression:            "email_hosted_dmarc_impact_regression",
  hosted_rolled_back_auto:             "email_hosted_dmarc_auto_rollback",
  sender_unrecognised:                 "email_sender_unrecognised",
  sender_classification_worsened:      "email_sender_unrecognised",
  sender_unauthorised_failures_active: "email_sender_unauthorised_failures",
});

// ── Sender evidence policy (founder-approved, 15 July 2026) ──────────────────
// W = 7 days rolling. Trigger at >= 50 receiver-reported failures IN THE WINDOW.
// Recover ONLY at exactly 0 in a complete window.
//
// The hysteresis is deliberately ASYMMETRIC. Symmetric thresholds would flap a
// sender across the boundary and mint an occurrence each way, alerting on noise.
// Recovery demands zero — "fewer failures than last week" is not evidence the
// condition ended, and we have no prior-period baseline to say it improved.
export const SENDER_WINDOW_DAYS = 7;
export const SENDER_FAILURE_TRIGGER = 50;
export const SENDER_RECOVERY_FAILURES = 0;
export const SENDER_NEW_MIN_VOLUME = 50;
export const SENDER_SWEEP_MAX_ROWS = 500;

// The eight-value auto vocabulary from sender-classification.js, ranked worst-last.
// Ranked so "worsening" is a comparison rather than a per-pair opinion.
const CLASSIFICATION_RANK = Object.freeze({
  authorised: 0,
  likely_authorised: 1,
  mailing_list: 1,
  forwarder: 1,
  unknown: 2,
  misconfigured: 2,
  suspicious: 3,
  unauthorised: 4,
});

export function classificationRank(classification) {
  const r = CLASSIFICATION_RANK[String(classification || "").toLowerCase()];
  return r === undefined ? null : r;
}

// Severity band from classification. ONE pure function, exactly the B2
// `renewalAlertBand` pattern: the band doubles as the severity (both values are
// already valid severities), so there is no second mapping to drift.
//
// This reproduces the shipped legacy grade — dmarc-alerts.js:101 graded
// `unauthorised ? "high" : "medium"` — as an ASSERTED lookup rather than an
// inline ternary. No customer-visible grade changes.
//
// It is also isMonitoringTransition's THIRD dimension: suspicious→unauthorised
// keeps recurrence_type but must escalate medium→high, and without the band no
// transition is seen and the customer is never told it got worse.
export function senderAlertBand(classification) {
  const c = String(classification || "").toLowerCase();
  if (c === "unauthorised") return "high";
  if (c === "suspicious" || c === "unknown" || c === "misconfigured") return "medium";
  return null;   // authorised / likely_authorised / mailing_list / forwarder
}

// The effective classification, ALWAYS in the observed vocabulary. Delegates to the
// single canonical resolver so this engine, dmarc-impact and rua-routing cannot drift
// apart again.
//
// It used to return the customer's word verbatim — `trusted` / `threat` / `ignored`
// went straight to senderAlertBand(), which speaks only the observed vocabulary, so all
// three banded null. Marking a sender a THREAT turned its own high alert off.
// See sender-classification.js for the vocabulary and why there is only one now.
export function effectiveClassification(row) {
  return resolveEffectiveClassification(row || {});
}

// ── The canonical customer-classification policy ────────────────────────────
// ONE documented rule for what a customer decision may do to severity. The whole
// policy is here, in the module that owns the bands and the failure trigger.
//
//   1. The floor is the EVIDENCE. observedBand is computed from what we actually
//      saw and is never lowered by anything the customer says.
//   2. The customer may ESCALATE. `threat` claims `unauthorised` (band high), so it
//      can only ever raise the band. It can never reduce or nullify one — that was
//      the defect.
//   3. The customer may SUPPRESS — `trusted` / `ignored` — but ONLY when the evidence
//      does not contradict them.
//   4. When a suppressing decision meets contradicting evidence, the result is an
//      explicit CONFLICT, not silence: the alert stands at the observed band and the
//      disagreement is named. A customer calling a sender trusted does not stop it
//      failing authentication 80 times, and we do not pretend otherwise.
//   5. Anything unrecognised FAILS CLOSED to medium with a conflict, never to null.
//      An unknown word must not be a silent all-clear.
//
// Contradiction is deliberately evidence-side only: either the observed verdict is
// itself high, or receiver-reported failures crossed the same trigger the alerting
// rule uses. It is not an opinion about the customer.
export const SENDER_BAND_RANK = Object.freeze({ low: 1, medium: 2, high: 3 });
const bandRank = (b) => (b == null ? 0 : (SENDER_BAND_RANK[String(b).toLowerCase()] ?? 0));
const higherBand = (a, b) => (bandRank(a) >= bandRank(b) ? a : b);

// Dispositions that ask to be left alone. `ignored` claims nothing about the sender;
// `trusted` claims it is authorised. Both request suppression, and both lose to
// contradicting evidence.
const SUPPRESSING_DISPOSITIONS = new Set(["trusted", "ignored"]);

/**
 * resolveSenderPolicy — pure and total, so CI can drive every branch directly.
 * @returns {{band: string|null, suppressed: boolean, conflict: string|null,
 *            observed_band: string|null, asserted_band: string|null}}
 */
export function resolveSenderPolicy({
  observed = null, disposition = null, has_customer_decision = false, window_failed = 0,
} = {}) {
  const obs = String(observed || "").toLowerCase();
  const observedKnown = isObservedClassification(obs);
  const observed_band = observedKnown ? senderAlertBand(obs) : "medium"; // unknown evidence fails closed
  const observedConflict = observedKnown ? null : "unsupported_observed_classification";

  if (!has_customer_decision) {
    return { band: observed_band, suppressed: false, conflict: observedConflict, observed_band, asserted_band: null };
  }

  const disp = String(disposition || "").toLowerCase();
  if (!isCustomerDisposition(disp)) {
    // Fail closed. The route rejects these, so reaching here means a value was written
    // by something that bypassed it — which is exactly when we must not go quiet.
    return {
      band: higherBand(observed_band, "medium"), suppressed: false,
      conflict: "unsupported_customer_disposition", observed_band, asserted_band: null,
    };
  }

  const claim = assertedClassification(disp);           // null for `ignored`
  const asserted_band = claim ? senderAlertBand(claim) : null;

  // The evidence contradicts a suppression when it is independently serious.
  const contradicted = bandRank(observed_band) >= bandRank("high")
    || Number(window_failed || 0) >= SENDER_FAILURE_TRIGGER;

  if (SUPPRESSING_DISPOSITIONS.has(disp)) {
    if (contradicted) {
      return {
        band: observed_band, suppressed: false,
        conflict: `customer_${disp}_but_observed_${observedKnown ? obs : "unsupported"}`,
        observed_band, asserted_band,
      };
    }
    return { band: null, suppressed: true, conflict: observedConflict, observed_band, asserted_band };
  }

  // Escalation-only: the customer's claim can raise the band, never lower it.
  return {
    band: higherBand(observed_band, asserted_band), suppressed: false,
    conflict: observedConflict, observed_band, asserted_band,
  };
}

function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 12).padEnd(12, "0")}`;
}
function safeJson(v, fallback = null) { try { return v == null ? fallback : JSON.stringify(v); } catch { return fallback; } }
function parseJson(v, fallback = null) { try { return v ? JSON.parse(v) : fallback; } catch { return fallback; } }

// ── The append-only event source ─────────────────────────────────────────────
// Never updated, never deleted outside workspace purge. The row id IS the
// occurrence identity and created_at IS when the condition began.
export async function appendEmailProtectionEvent(env, {
  workspace_id, record_id, record_type, event_type,
  actor_type = "system", actor_id = null, detail = null,
}) {
  if (!env?.cybermeters_db || !workspace_id || !record_id || !record_type || !event_type) return null;
  const id = newId("epe");
  await env.cybermeters_db
    .prepare(`INSERT INTO email_protection_events
        (id, record_id, record_type, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(id, record_id, record_type, workspace_id, actor_type, actor_id, event_type, safeJson(detail))
    .run();
  return id;
}

const DMARC_CONDITION_TYPES = new Set([
  "missing",
  "malformed",
  "multiple",
  "weak",
  "unauthorised_rua",
]);

function canonicalDmarcConditionSubject(subject) {
  return String(subject || "").trim().replace(/\.$/, "").toLowerCase();
}

export async function dmarcPolicyConditionRecordId({
  domain_id,
  condition_type,
  subject_key,
} = {}) {
  const type = String(condition_type || "");
  const subject = canonicalDmarcConditionSubject(subject_key);
  if (!domain_id || !DMARC_CONDITION_TYPES.has(type) || !subject) return null;
  const digest = await sha256Hex(subject);
  return `dmarc:${domain_id}:${type}:${digest}`;
}

function primaryPolicyWalkEntries(policyEvidence) {
  return (Array.isArray(policyEvidence?.lookup_path)
    ? policyEvidence.lookup_path
    : [])
    .filter((entry) =>
      entry?.question?.resolver === "primary" &&
      entry?.question?.purpose === "policy_tree_walk");
}

// P2 establishes only non-alertable lifecycle baselines. P4 owns transition
// events and P5 owns alert/case eligibility. Every subject is derived from the
// complete canonical resolver output; no raw RRset is copied to D1.
export function deriveDmarcPolicyConditions(policyEvidence) {
  if (policyEvidence?.core_completeness !== "complete") return [];
  const conditions = [];
  const seen = new Set();
  const add = (condition_type, subject_key, detail = {}) => {
    const subject = canonicalDmarcConditionSubject(subject_key);
    const key = `${condition_type}|${subject}`;
    if (!DMARC_CONDITION_TYPES.has(condition_type) || !subject || seen.has(key)) return;
    seen.add(key);
    conditions.push({ condition_type, subject_key: subject, ...detail });
  };

  for (const entry of primaryPolicyWalkEntries(policyEvidence)) {
    const rawState = entry?.record_set?.raw_state;
    const qname = entry?.question?.name;
    if (["multiple", "multiple_mixed", "multiple_invalid"].includes(rawState)) {
      add("multiple", qname, { record_state: rawState });
    } else if ([
      "single_invalid",
      "single_invalid_duplicate_tag",
    ].includes(rawState)) {
      add("malformed", qname, { record_state: rawState });
    }
  }

  const hasRecordDefect = conditions.some((condition) =>
    condition.condition_type === "malformed" ||
    condition.condition_type === "multiple");
  if (!policyEvidence.policy_source_domain && !hasRecordDefect) {
    add("missing", policyEvidence.author_domain, {
      record_state: policyEvidence.observation_state,
    });
  } else if (policyEvidence.effective_requested_policy === "none") {
    add("weak", policyEvidence.author_domain, {
      policy_source_domain: policyEvidence.policy_source_domain,
      effective_policy_tag: policyEvidence.effective_policy_tag,
      inheritance_reason: policyEvidence.inheritance_reason,
    });
  }

  if (policyEvidence.rua_authorisation_completeness === "complete") {
    const destinations =
      policyEvidence.external_rua_authorisation?.destinations || [];
    for (const destination of destinations) {
      if (destination?.authorization_status !== "unauthorized") continue;
      add(
        "unauthorised_rua",
        destination.authorization_query_name,
        {
          destination_uri: destination.normalized_uri || null,
          authorization_status: destination.authorization_status,
        },
      );
    }
  }
  return conditions;
}

async function deterministicDmarcEventId(workspaceId, recordId, eventType) {
  return `epe-${(await sha256Hex(
    `${workspaceId}|${recordId}|${eventType}`,
  )).slice(0, 24)}`;
}

// Reuses migration 088 exactly: one active workspace/domain membership read,
// one bounded existing-event read, then one batch. INSERT OR IGNORE plus
// deterministic baseline IDs makes concurrent scan retries idempotent.
export async function establishDmarcPolicyBaseline(env, {
  workspace_id,
  domain_id,
  domain,
  scan_id,
  policy_evidence,
} = {}) {
  if (!env?.cybermeters_db || !workspace_id || !domain_id || !domain || !scan_id) {
    return { skipped: "incomplete_context" };
  }
  if (policy_evidence?.core_completeness !== "complete") {
    return { skipped: "core_incomplete" };
  }

  const live = await env.cybermeters_db
    .prepare(`SELECT wd.domain_id
              FROM workspace_domains wd
              JOIN workspaces w ON w.id = wd.workspace_id
              JOIN domains d ON d.id = wd.domain_id
              WHERE wd.workspace_id = ? AND wd.domain_id = ?
                AND w.deleted_at IS NULL AND lower(d.domain) = lower(?)
              LIMIT 1`)
    .bind(workspace_id, domain_id, domain)
    .first()
    .catch(() => null);
  if (!live) return { skipped: "workspace_or_domain_inactive" };

  const authorDomain =
    canonicalDmarcConditionSubject(policy_evidence.author_domain || domain);
  const domainMarkerSubject = await sha256Hex(authorDomain);
  const domainMarkerId =
    `dmarc:${domain_id}:domain_baseline:${domainMarkerSubject}`;
  const conditions = deriveDmarcPolicyConditions(policy_evidence);
  const conditionRows = [];
  for (const condition of conditions) {
    const recordId = await dmarcPolicyConditionRecordId({
      domain_id,
      condition_type: condition.condition_type,
      subject_key: condition.subject_key,
    });
    if (recordId) conditionRows.push({ ...condition, record_id: recordId });
  }

  // Hash the exact bounded R2 protocol object. Only the digest is copied to
  // D1; raw DNS remains single-source in the immutable scan report.
  // P3 seals the immutable protocol object before the report write. Reuse that
  // exact fingerprint so D1 lifecycle references reconcile with both R2
  // artifacts. P2 reports without a seal retain the original fallback.
  const evidenceFingerprint =
    typeof policy_evidence.evidence_fingerprint === "string"
      ? policy_evidence.evidence_fingerprint
      : await sha256Hex(JSON.stringify(policy_evidence));
  const possibleCandidates = [
    {
      record_id: domainMarkerId,
      event_type: EMAIL_EVENT_DMARC_DOMAIN_BASELINE,
      detail: {
        entity: authorDomain,
        domain_id,
        author_domain: authorDomain,
        scan_id,
        methodology_version: policy_evidence.methodology_version ?? null,
        core_completeness: "complete",
        evidence_fingerprint: evidenceFingerprint,
        to_recurrence_type: null,
      },
    },
    ...conditionRows.map((condition) => ({
      record_id: condition.record_id,
      event_type: EMAIL_EVENT_BASELINE,
      detail: {
        entity: condition.subject_key,
        domain_id,
        author_domain: authorDomain,
        condition_type: condition.condition_type,
        subject_key: condition.subject_key,
        scan_id,
        methodology_version: policy_evidence.methodology_version ?? null,
        core_completeness: "complete",
        rua_authorisation_completeness:
          policy_evidence.rua_authorisation_completeness ?? null,
        evidence_fingerprint: evidenceFingerprint,
        policy_source_domain: condition.policy_source_domain ?? null,
        effective_policy_tag: condition.effective_policy_tag ?? null,
        inheritance_reason: condition.inheritance_reason ?? null,
        destination_uri: condition.destination_uri ?? null,
        authorization_status: condition.authorization_status ?? null,
        record_state: condition.record_state ?? null,
        to_recurrence_type: null,
      },
    })),
  ];
  const placeholders = possibleCandidates.map(() => "?").join(", ");
  const prior = await env.cybermeters_db
    .prepare(`SELECT record_id, event_type
              FROM email_protection_events
              WHERE workspace_id = ? AND record_type = ?
                AND record_id IN (${placeholders})`)
    .bind(
      workspace_id,
      DMARC_POLICY_CONDITION_RECORD_TYPE,
      ...possibleCandidates.map((candidate) => candidate.record_id),
    )
    .all()
    .catch(() => ({ results: [] }));
  const existing = new Set(
    (prior.results || []).map((row) => `${row.record_id}|${row.event_type}`),
  );
  const candidates = possibleCandidates.filter((candidate) =>
    !existing.has(`${candidate.record_id}|${candidate.event_type}`));

  if (candidates.length === 0) {
    return { established: true, inserted: 0, conditions: conditionRows.length };
  }
  const statements = [];
  for (const candidate of candidates) {
    const id = await deterministicDmarcEventId(
      workspace_id,
      candidate.record_id,
      candidate.event_type,
    );
    statements.push(env.cybermeters_db
      .prepare(`INSERT OR IGNORE INTO email_protection_events
          (id, record_id, record_type, workspace_id, actor_type, actor_id,
           event_type, detail_json, created_at)
        VALUES (?, ?, ?, ?, 'system', NULL, ?, ?, datetime('now'))`)
      .bind(
        id,
        candidate.record_id,
        DMARC_POLICY_CONDITION_RECORD_TYPE,
        workspace_id,
        candidate.event_type,
        safeJson(candidate.detail),
      ));
  }
  await env.cybermeters_db.batch(statements);
  return {
    established: true,
    inserted: statements.length,
    conditions: conditionRows.length,
  };
}

// ── Read accessors — the customer-facing shape ──────────────────────────────
// Mig 088 had NO read helper of any kind: `email_protection_events` was read only by the
// alert pipeline (findConditionOccurrence) and the private lastGradedCondition, and the
// four lifecycle-state columns it added to `email_sender_sources` are stripped by
// emailSenderToApi before they leave the API. So a customer could be told a hosted DMARC
// record had disconnected and had no way to see when, how often, or whether it came back.
//
// `record_type` (hosted_dns_entry | email_sender_source) is what makes this readable: it
// is deliberately NOT part of the occurrence lookup (mig 088:63-67) but it is exactly the
// filter a customer-facing history needs.
//
// `detail_json` is NOT passed through raw. It carries the evaluator's internal grading
// vocabulary (from/to monitoring status, recurrence bands, reasons); a customer-facing
// history exposes the transition it describes, not the machinery. `evaluated_at` never
// appears at all — mig 088:126 calls it diagnostic.
export function emailProtectionEventToApi(row = {}) {
  let detail = null;
  try { detail = row.detail_json ? JSON.parse(row.detail_json) : null; } catch { detail = null; }
  return {
    id: row.id,
    record_id: row.record_id,
    record_type: row.record_type,
    event_type: row.event_type,
    actor_type: row.actor_type ?? null,
    created_at: row.created_at,
    // The transition, in the terms the customer was alerted in.
    entity: detail?.entity ?? null,
    recurrence_type: detail?.to_recurrence_type ?? null,
    reason: detail?.reason ?? null,
  };
}

// Tenant-scoped, BOUNDED and deterministic. `created_at` is second-precision so it ties
// routinely (the hosted sweep can append twice inside one second); `rowid` is the
// insertion order the table already maintains and is the same tie-break the occurrence
// resolver uses, so a page of history cannot reorder under the customer.
export async function listEmailProtectionEvents(env, workspaceId, {
  record_id = null, record_type = null, limit = 50, offset = 0,
} = {}) {
  // P2 persists DMARC baselines for future continuity but does not activate a
  // customer timeline surface. P4 removes this read boundary when immutable
  // before/after transition events and their wording are ready together.
  if (record_type === DMARC_POLICY_CONDITION_RECORD_TYPE) return [];
  const where = ["workspace_id = ?", "record_type <> ?"];
  const binds = [workspaceId, DMARC_POLICY_CONDITION_RECORD_TYPE];
  if (record_id) { where.push("record_id = ?"); binds.push(String(record_id)); }
  if (record_type) { where.push("record_type = ?"); binds.push(String(record_type)); }
  const rows = await env.cybermeters_db
    .prepare(`SELECT id, record_id, record_type, actor_type, event_type, detail_json, created_at
              FROM email_protection_events
              WHERE ${where.join(" AND ")}
              ORDER BY created_at DESC, rowid DESC
              LIMIT ? OFFSET ?`)
    .bind(...binds, Number(limit), Number(offset)).all().catch(() => ({ results: [] }));
  return (rows.results || []).map(emailProtectionEventToApi);
}

// This history is the one in scope that grows without bound — an hourly evaluator across
// every sender and hosted record — so `total` is worth the second query: a customer
// paging back through months of it needs to know there IS a back, and the has_more
// heuristic (count >= limit) guesses wrong on an exact-multiple final page.
export async function countEmailProtectionEvents(env, workspaceId, { record_id = null, record_type = null } = {}) {
  if (record_type === DMARC_POLICY_CONDITION_RECORD_TYPE) return 0;
  const where = ["workspace_id = ?", "record_type <> ?"];
  const binds = [workspaceId, DMARC_POLICY_CONDITION_RECORD_TYPE];
  if (record_id) { where.push("record_id = ?"); binds.push(String(record_id)); }
  if (record_type) { where.push("record_type = ?"); binds.push(String(record_type)); }
  const row = await env.cybermeters_db
    .prepare(`SELECT COUNT(*) AS n FROM email_protection_events WHERE ${where.join(" AND ")}`)
    .bind(...binds).first().catch(() => null);
  return Number(row?.n ?? 0);
}

// ── Recovery closure: which events CLOSE a graded condition ─────────────────
// THE DEFECT THIS EXISTS TO PREVENT (reproduced live, 2026-07-16):
//   disconnect → alert → reconnect → disconnect again → **SILENCE, FOREVER**.
// Recovery is appended as `hosted_record_reconnected`, a different event_type, and
// this reader only looked at `monitoring_changed`. So the last graded condition
// stayed `hosted_record_disconnected` across the recovery; the second disconnect
// compared equal to it, isMonitoringTransition said "unchanged", no event was
// appended, no occurrence was minted, and the customer was never told their DMARC
// record had dropped out a second time. A hosted record could alert on
// disconnection exactly ONCE in its lifetime.
//
// The sender family never had this bug because its condition lives on the row and
// is nulled on recovery. The hosted family's state IS the event log, so the log has
// to be read for closure too — that asymmetry is the whole defect.
//
// Fixed by correcting the READER, deliberately not by appending a clearing
// `monitoring_changed` on recovery.
//
// (When this was written the reason was that findConditionOccurrence read a bounded
// `LIMIT 25` page of monitoring_changed rows and filtered them in JS, so every extra row
// narrowed the window a real transition could still be found in. That resolver has since
// been fixed to ask SQL for the exact row it needs, so extra rows no longer threaten
// correctness — the original rationale no longer holds and is recorded here as history,
// not as a live reason.) The decision stands on its own merits: the reader was the thing
// that was wrong, and a recovery is already recorded once, honestly, under its own event
// type. Writing a second row to make a broken read work is how a log stops meaning
// anything.
//
// The list is EXPLICIT, and short, for a reason. Every non-alertable hosted event
// carries `to_recurrence_type: null` (buildMonitoringTransitionDetail always sets
// the key), so "any event that carries the key" would let `hosted_policy_changed` or
// `hosted_rolled_back_manual` close a LIVE disconnection — and the next sweep would
// re-alert an outage that never went away. Only a genuine return to a healthy state
// is recovery. A policy change is not recovery; a rollback is not recovery.
const CONDITION_CLOSING_EVENT_TYPES = Object.freeze([EMAIL_EVENT_HOSTED_RECONNECTED]);

// The record's current graded condition, read from the append-only history.
//
// The events table IS the state for the hosted family, which is why B3 needs no
// new column on hosted_dns_entries: the last monitoring_changed row already says
// what condition we last graded this record with — or, since the recovery fix
// above, the last reconnection says the condition closed.
// Ordering is `created_at DESC, rowid DESC`, and the rowid tie-break is
// load-bearing rather than cosmetic. created_at comes from SQLite `datetime('now')`,
// which is SECOND-precision, and the hosted sweep assesses impact and then
// auto-rolls-back INSIDE ONE ITERATION — so two events for the same record land in
// the same second routinely. Falling back to `id DESC` would tie-break on random
// hex and could return the OLDER event as "the last condition", making an unchanged
// regression look like a transition and firing a spurious alert. rowid is the
// insertion order the table already maintains, so it is the only tie-break that
// answers the question actually being asked: what did we grade this record with
// most recently?
async function lastGradedCondition(env, workspaceId, recordId) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT detail_json FROM email_protection_events
                WHERE workspace_id = ? AND record_id = ? AND event_type IN (?, ?)
                ORDER BY created_at DESC, rowid DESC LIMIT 1`)
      .bind(workspaceId, recordId, MONITORING_CHANGED, ...CONDITION_CLOSING_EVENT_TYPES)
      .first();
    const detail = parseJson(row?.detail_json, {}) || {};
    return {
      recurrence_type: detail.to_recurrence_type ?? null,
      recurrence_band: detail.recurrence_band ?? null,
    };
  } catch {
    // Fail CLOSED: unable to establish the prior condition => we cannot show this
    // one is a transition => treat it as unchanged and stay silent. A missed
    // alert is recoverable next pass; a fabricated one is not.
    return null;
  }
}

// ── The activation watermark, and the per-record baseline guard ──────────────
//
// THIS IS THE FLOOD GUARD, and it is mandatory even though both families ship
// together. alert_activation alone is NOT sufficient here, unlike B1/B2:
//
// Those domains were safe because their event tables already held weeks of
// history, so countPriorOccurrences > 0 and the backlog suppressed itself.
// email_protection_events is BRAND NEW — every workspace's baseline_count is 0,
// which trips emitManagedAlert's `firstEverCondition` escape hatch and makes the
// entire pre-existing backlog look "genuinely new by construction".
//
// So the guard is here, on the record's OWN persisted birth: anything born at or
// before the watermark is history and can never alert, whatever the pipeline
// thinks. Founder decision D, 15 July 2026.
export async function emailProtectionWatermark(env, workspaceId) {
  try {
    const activation = await ensureAlertActivation(env, workspaceId, EMAIL_PROTECTION_DOMAIN_KEY);
    return activation?.activated_at || null;
  } catch {
    return null;
  }
}

// Born at or before the watermark => pre-existing => baseline only, forever.
// An unknown watermark or an unparseable birth FAILS CLOSED (pre-existing): we
// cannot show the record is new, so we must not announce it as news.
export function isPreExistingRecord(bornAt, activatedAt) {
  const born = parseUtcMs(bornAt);
  const activated = parseUtcMs(activatedAt);
  if (born === null || activated === null) return true;
  return born <= activated;
}

// ── Hosted DMARC family ─────────────────────────────────────────────────────
//
// The transition guard is the SHIPPED state machine, not a new one:
// runHostedDnsVerificationSweep only reaches a transition when
// `next !== row.status`, and applyHostedDmarcChange / rollbackHostedDmarc only
// run on a genuine write (rollback nulls previous_value, so it cannot repeat).
// hosted-dmarc.js therefore calls this only on a real edge — exactly the
// managed-case shape, where the state machine upstream is the guard.
export async function recordHostedTransition(env, row, {
  recurrence = null, event_type = null, from_status = null, to_status = null,
  band = null, record_severity = null, reason = null,
  actor_type = "system", actor_id = null, detail = null,
} = {}) {
  if (!row?.id || !row?.workspace_id) return { skipped: "incomplete_record" };

  // Non-alertable: history only. Structurally incapable of alerting — the
  // event_type is not `monitoring_changed`, so the resolver cannot see it.
  if (!recurrence) {
    if (!event_type) return { skipped: "incomplete_record" };
    // A RECOVERY observation is history AND, for a case the customer has already driven to
    // awaiting_verification, the evidence that closes it. `hosted_record_reconnected` is a
    // real DNS re-observation of the record — CyberMeters seeing the fix, not being told
    // about it. The case layer re-checks the registry itself and refuses to verify a
    // finding the registry says we cannot observe, so this call cannot launder an
    // attestation-only condition into a verification.
    if (EMAIL_RECOVERY_VERIFIES[event_type]) {
      await verifyEmailCaseFromRecovery(env, {
        workspace_id: row.workspace_id, record_id: row.id, recovery_event_type: event_type,
      }).catch(() => {});
    }
    await appendEmailProtectionEvent(env, {
      workspace_id: row.workspace_id, record_id: row.id, record_type: HOSTED_RECORD_TYPE,
      event_type, actor_type, actor_id,
      detail: {
        ...buildMonitoringTransitionDetail({
          from_monitoring_status: from_status, to_monitoring_status: to_status,
          to_recurrence_type: null, reason, entity: row.domain,
        }),
        ...(detail || {}),
      },
    }).catch(() => {});
    return { emitted: false, reason: "non_alertable" };
  }

  const activatedAt = await emailProtectionWatermark(env, row.workspace_id);
  if (isPreExistingRecord(row.created_at, activatedAt)) {
    await appendEmailProtectionEvent(env, {
      workspace_id: row.workspace_id, record_id: row.id, record_type: HOSTED_RECORD_TYPE,
      event_type: EMAIL_EVENT_BASELINE, actor_type,
      detail: { reason: "pre_existing_at_activation", recurrence, entity: row.domain },
    }).catch(() => {});
    return { emitted: false, reason: "baseline_only" };
  }

  const prev = await lastGradedCondition(env, row.workspace_id, row.id);
  if (prev === null) return { skipped: "condition_lookup_failed" };
  // Compare the CONDITION only — recurrence_type + band — never from_status vs
  // to_status. Those two differ by definition on every transition call, so
  // including them would make the guard always report "changed" and re-append the
  // same condition on every sweep. The record's status machine upstream is
  // already the edge guard (we only get called when next !== row.status, or on a
  // genuine write); this guard exists for the second question: is the CONDITION
  // we are about to alert on the same one we last graded?
  const prevCondition = { monitoring_status: null, recurrence_type: prev.recurrence_type, recurrence_band: prev.recurrence_band };
  const next = { monitoring_status: null, recurrence_type: recurrence, recurrence_band: band ?? null };
  if (!isMonitoringTransition(prevCondition, next)) {
    // Same condition as last time: no event, so the occurrence id is unchanged,
    // so the dedupe key is unchanged, so the database silences the repeat. This
    // is what ends hosted_impact_regression's daily re-alert.
    return { emitted: false, reason: "unchanged" };
  }

  const occurrenceId = await appendEmailProtectionEvent(env, {
    workspace_id: row.workspace_id, record_id: row.id, record_type: HOSTED_RECORD_TYPE,
    event_type: MONITORING_CHANGED, actor_type, actor_id,
    detail: {
      ...buildMonitoringTransitionDetail({
        from_monitoring_status: from_status, to_monitoring_status: to_status,
        from_recurrence_type: prev.recurrence_type, to_recurrence_type: recurrence,
        reason, entity: row.domain,
      }),
      recurrence_band: band ?? null,
      ...(detail || {}),
    },
  }).catch(() => null);
  // A write is not proof until it is read back: emitLifecycleAlert re-reads the
  // event rather than trusting this id (the PR-B1 bridge rule).
  if (!occurrenceId) return { skipped: "monitoring_event_not_persisted" };

  // The case, BEFORE the alert: an alert that references a case is only honest once the
  // case exists. Idempotent — createManagedCase dedupes on finding_id, so an unchanged
  // condition re-graded later reuses the same case rather than minting a second.
  const findingType = EMAIL_RECURRENCE_FINDING_TYPE[recurrence] || null;
  let caseId = null;
  if (EMAIL_CASE_RECURRENCES.has(recurrence)) {
    const linked = await openOrReopenEmailCase(env, {
      workspace_id: row.workspace_id,
      record_id: row.id,
      entity: row.domain,
      domain: row.domain,          // hosted records ARE a workspace domain; senders are not
      recurrence,
      finding_type: findingType,
      severity: record_severity || band || "medium",
    }).catch(() => null);
    if (linked?.ok && linked.case?.id) {
      caseId = linked.case.id;
      if (linked.created || linked.reopened) {
        await appendEmailProtectionEvent(env, {
          workspace_id: row.workspace_id, record_id: row.id, record_type: HOSTED_RECORD_TYPE,
          event_type: linked.reopened ? EMAIL_EVENT_CASE_REOPENED : EMAIL_EVENT_CASE_LINKED,
          detail: { case_id: caseId, recurrence, remediation_id: linked.case.remediation_id ?? null },
        }).catch(() => {});
      }
    }
  }

  return await emitLifecycleAlert(env, {
    workspace_id: row.workspace_id,
    domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
    record_id: row.id,
    entity: row.domain,
    hostname: row.domain,
    recurrence,
    record_severity,
    case_id: caseId,
    finding_type: findingType,
  });
}

// ── Sender family ───────────────────────────────────────────────────────────

// Receiver-reported failures for every source of one (workspace, domain) inside
// the rolling window. ONE grouped query — never per-row, and never the cumulative
// columns.
//
// Alignment is copied EXACTLY from dmarc-ingest.js: aligned iff
// spf_aligned_result='pass' OR dkim_aligned_result='pass'; everything else
// failed. Two definitions of "failed" would eventually disagree and the alert
// would contradict the sender inventory the customer is looking at.
//
// date_range_end is INTEGER epoch seconds (mig 054).
export async function senderWindowVolumes(env, workspaceId, domain, { now = new Date() } = {}) {
  const windowStart = Math.floor((now.getTime() - SENDER_WINDOW_DAYS * 86400000) / 1000);
  const out = new Map();
  try {
    const rows = await env.cybermeters_db
      .prepare(`SELECT r.source_ip AS source_ip,
                       SUM(r.message_count) AS window_total,
                       SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                                THEN 0 ELSE r.message_count END) AS window_failed
                FROM dmarc_aggregate_records r
                JOIN dmarc_aggregate_reports rep
                  ON rep.id = r.report_id
                 AND rep.workspace_id = r.workspace_id
                 AND rep.domain = r.domain
                WHERE r.workspace_id = ? AND r.domain = ? AND rep.date_range_end >= ?
                  AND ${aggregateReportCompleteSql("rep", "dmarc")}
                  AND ${dmarcAuthoritySourceSql("rep")}
                GROUP BY r.source_ip`)
      .bind(workspaceId, domain, windowStart)
      .all();
    for (const r of rows.results || []) {
      out.set(String(r.source_ip || ""), {
        window_total: Number(r.window_total || 0),
        window_failed: Number(r.window_failed || 0),
      });
    }
  } catch {
    // Fail closed: no windowed evidence => no condition => no alert.
    return new Map();
  }
  return out;
}

// The condition a sender is in, from windowed evidence + the canonical policy.
// Pure and total, so CI can drive it directly.
//
// `observed` is the EVIDENCE (auto_classification) and is what the conditions below
// are graded on. `disposition` is the customer's decision and reaches the band only
// through resolveSenderPolicy, which may escalate it but never silently lower it.
//
// The legacy single-`classification` form is still accepted: with no customer
// decision it means "observed", which is exactly what it meant before.
export function gradeSenderCondition({
  observed, disposition = null, has_customer_decision = false,
  window_total, window_failed, is_new, classification,
}) {
  const obs = String(observed ?? classification ?? "").toLowerCase();
  const policy = resolveSenderPolicy({
    observed: obs, disposition, has_customer_decision, window_failed,
  });
  const band = policy.band;
  const failed = Number(window_failed || 0);
  const total = Number(window_total || 0);

  // Active unauthorised authentication failures. NOT a spike and never described
  // as one: we hold no prior-period baseline, so we can only state an absolute
  // count inside the window.
  //
  // Graded on the OBSERVED verdict, never on what the customer called it. This used
  // to read the customer's word, so `trusted` or `threat` erased the condition
  // outright — 80 receiver-reported failures stopped existing because someone
  // clicked a label. The customer's decision is expressed in `band` (policy), not by
  // deleting the evidence. `suppressed` can silence a sender, but resolveSenderPolicy
  // refuses to suppress once the failures cross this very trigger, so this condition
  // cannot be clicked away.
  if (obs === "unauthorised" && failed >= SENDER_FAILURE_TRIGGER) {
    return {
      recurrence: "sender_unauthorised_failures_active",
      band: band ?? "high",
      conflict: policy.conflict,
    };
  }
  // A new, high-volume, not-yet-recognised source.
  if (is_new && band !== null && total >= SENDER_NEW_MIN_VOLUME) {
    return { recurrence: "sender_unrecognised", band, conflict: policy.conflict };
  }
  return { recurrence: null, band, conflict: policy.conflict };
}

// Disappearance-confirmation gate for sender recovery / email case closure.
// The active-failures case closes ONLY when the receivers' own reports in the window
// PROVE the sender now passes. A sender absent from the window defaults to
// { window_total: 0, window_failed: 0 } (senderWindowVolumes returns an empty Map on
// a RUA outage), so window_failed === 0 is ALSO the no-evidence-at-all case — a
// receiver that stopped reporting, or the ingest feed going down, is indistinguishable
// from "now passing". Require window_total > 0 (the window demonstrably contains
// receiver reports) so an evidence outage can never manufacture a false recovery and
// close the case. Pure and total, so CI can drive it directly.
export function senderRecoveryConfirmed({ prev_recurrence_type, graded_recurrence, window_total, window_failed }) {
  return prev_recurrence_type === "sender_unauthorised_failures_active"
    && graded_recurrence === null
    && Number(window_total || 0) > 0
    && Number(window_failed || 0) === SENDER_RECOVERY_FAILURES;
}

/**
 * evaluateEmailSenderMonitoring — the sender lifecycle pass for one
 * (workspace, domain). Called after a NEW report is ingested, because that is
 * the only moment the evidence can have changed.
 *
 * observe → grade from windowed evidence → guard the transition → append →
 * alert → monitor → recover → re-enter.
 */
export async function evaluateEmailSenderMonitoring(env, workspaceId, domain, { now = new Date() } = {}) {
  if (!env?.cybermeters_db || !workspaceId || !domain) return { checked: 0, alerts: 0 };

  const activatedAt = await emailProtectionWatermark(env, workspaceId);
  const volumes = await senderWindowVolumes(env, workspaceId, domain, { now });

  let rows = [];
  try {
    const r = await env.cybermeters_db
      .prepare(`SELECT id, workspace_id, domain, source_ip, first_seen, last_seen,
                       classification, auto_classification, classified_at,
                       monitoring_status, recurrence_type, recurrence_band
                FROM email_sender_sources
                WHERE workspace_id = ? AND domain = ?
                ORDER BY id ASC LIMIT ?`)
      .bind(workspaceId, domain, SENDER_SWEEP_MAX_ROWS)
      .all();
    rows = r.results || [];
  } catch {
    return { checked: 0, alerts: 0 };
  }

  let checked = 0, alerts = 0;
  for (const row of rows) {
    checked += 1;
    try {
      const vol = volumes.get(String(row.source_ip || "")) || { window_total: 0, window_failed: 0 };
      // The two axes stay SEPARATE all the way to the policy. Collapsing them into one
      // value here — which is what effectiveClassification used to do for grading — is
      // what let a customer's word overwrite the evidence.
      const cls = effectiveClassification(row);          // observed vocabulary, for history/detail
      const preExisting = isPreExistingRecord(row.first_seen, activatedAt);
      const graded = gradeSenderCondition({
        observed: row.auto_classification ?? row.classification,
        disposition: row.classified_at ? row.classification : null,
        has_customer_decision: Boolean(row.classified_at),
        window_total: vol.window_total,
        window_failed: vol.window_failed,
        is_new: !preExisting,
      });

      const prev = {
        monitoring_status: row.monitoring_status ?? null,
        recurrence_type: row.recurrence_type ?? null,
        recurrence_band: row.recurrence_band ?? null,
      };

      // ── The activating pass: baseline, never news ──────────────────────────
      // Every sender whose evidence predates the watermark is history. It gets
      // state and a non-alertable baseline event, and can never alert on this
      // pass or any later one for the condition it was already in.
      if (!row.monitoring_status) {
        const status = preExisting ? "baseline" : "observed";
        await persistSenderState(env, row, { status, graded, now });
        await appendEmailProtectionEvent(env, {
          workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
          event_type: EMAIL_EVENT_BASELINE,
          detail: {
            reason: preExisting ? "pre_existing_at_activation" : "first_evaluation",
            recurrence: graded.recurrence, entity: row.source_ip,
            window_total: vol.window_total, window_failed: vol.window_failed,
          },
        }).catch(() => {});
        // A record born after the watermark is genuinely new and must still be
        // able to raise its FIRST condition — baselining it would swallow the
        // very alert this family exists for. Fall through only in that case.
        if (preExisting || !graded.recurrence) continue;
      }

      // ── The customer's own action is never a risk alert ───────────────────
      // A manual reclassification is recorded as history and stops there.
      // Alerting someone about their own click is noise, and a customer
      // assertion is not a CyberMeters observation.
      //
      // This branch can no longer erase a live condition. It only runs when the
      // customer's decision actually MOVED the band, and resolveSenderPolicy refuses to
      // move it down past contradicting evidence — so a sender failing authentication
      // above the trigger keeps its band, this test is false, and the condition falls
      // through to the normal path untouched. Previously the band collapsed to null
      // here (the customer's word went straight to senderAlertBand) and the live
      // `sender_unauthorised_failures_active` condition was wiped by a click.
      //
      // The event records the disposition and any conflict, so history says what the
      // customer claimed AND what we still observe — never just the claim. `conflict`
      // is recomputable from the persisted row + window at any time, so it needs no
      // column of its own.
      if (row.classified_at && prev.recurrence_band !== graded.band && row.monitoring_status) {
        await appendEmailProtectionEvent(env, {
          workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
          event_type: EMAIL_EVENT_SENDER_MANUAL_CLASS, actor_type: "customer",
          detail: {
            to_recurrence_type: null,
            reason: graded.conflict ? "customer_classified_conflicts_with_evidence" : "customer_classified",
            entity: row.source_ip,
            classification: cls,                       // observed vocabulary
            disposition: row.classification ?? null,   // the customer's own word
            observed_classification: row.auto_classification ?? null,
            conflict: graded.conflict ?? null,
          },
        }).catch(() => {});
        await persistSenderState(env, row, { status: row.monitoring_status || "observed", graded, now });
        continue;
      }

      // ── Recovery: zero receiver-reported failures in a window that HAS reports ─
      // Expressible ONLY because the window drops old reports out. A cumulative
      // counter could never come back down, which is why the legacy sweep had no
      // recovery at all. Non-alertable by founder decision. senderRecoveryConfirmed
      // additionally requires window_total > 0, so an empty window (RUA outage /
      // receiver stopped reporting) can never be read as recovery.
      if (senderRecoveryConfirmed({
            prev_recurrence_type: prev.recurrence_type,
            graded_recurrence: graded.recurrence,
            window_total: vol.window_total,
            window_failed: vol.window_failed,
          })) {
        await appendEmailProtectionEvent(env, {
          workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
          event_type: EMAIL_EVENT_SENDER_RECOVERED,
          detail: {
            to_recurrence_type: null, reason: "no_failures_in_window",
            entity: row.source_ip, window_days: SENDER_WINDOW_DAYS,
          },
        }).catch(() => {});
        // The same observation that clears the condition closes the case — zero
        // receiver-reported failures across a COMPLETE window is CyberMeters reading the
        // receivers' own reports, not the customer telling us they fixed it. The case layer
        // re-checks the registry and refuses to verify anything it says we cannot observe.
        await verifyEmailCaseFromRecovery(env, {
          workspace_id: workspaceId, record_id: row.id,
          recovery_event_type: EMAIL_EVENT_SENDER_RECOVERED,
        }).catch(() => {});
        await persistSenderState(env, row, { status: "recovered", graded, now });
        continue;
      }

      // monitoring_status is DERIVED from whether the condition moved — never
      // computed independently. It previously flipped baseline→observed on the
      // second pass while the condition was identical, which isMonitoringTransition
      // correctly read as a transition: the entire pre-existing backlog re-alerted
      // on pass two, defeating the flood guard that pass one had just applied.
      // A baselined record stays `baseline` until its CONDITION actually changes.
      const conditionChanged =
        String(prev.recurrence_type ?? "") !== String(graded.recurrence ?? "")
        || String(prev.recurrence_band ?? "") !== String(graded.band ?? "");
      const next = {
        monitoring_status: conditionChanged ? "observed" : (row.monitoring_status || "observed"),
        recurrence_type: graded.recurrence,
        recurrence_band: graded.band,
      };

      // Unchanged: no event. The occurrence id stays, the dedupe key stays, the
      // database silences the repeat. No per-ingest re-alerting.
      if (!isMonitoringTransition(prev, next)) {
        await persistSenderState(env, row, { status: next.monitoring_status, graded, now });
        continue;
      }

      // Worsening keeps the recurrence but raises the band; a distinct recurrence
      // names it so the customer is told what changed rather than just re-told.
      let recurrence = graded.recurrence;
      if (recurrence === "sender_unrecognised"
          && prev.recurrence_type === "sender_unrecognised"
          && rankOf(prev.recurrence_band) < rankOf(graded.band)) {
        recurrence = "sender_classification_worsened";
      }

      await persistSenderState(env, row, { status: next.monitoring_status, graded, now });

      if (!recurrence) {
        // Fell out of a graded condition without meeting the recovery bar.
        // History only — we cannot claim it recovered on evidence we lack.
        await appendEmailProtectionEvent(env, {
          workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
          event_type: EMAIL_EVENT_BASELINE,
          detail: { to_recurrence_type: null, reason: "condition_cleared", entity: row.source_ip },
        }).catch(() => {});
        continue;
      }

      // Re-entry after recovery needs no counter: this appends a NEW row, so a
      // NEW occurrence id, so a NEW dedupe key, so a new eligible alert.
      const occurrenceId = await appendEmailProtectionEvent(env, {
        workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
        event_type: MONITORING_CHANGED,
        detail: {
          ...buildMonitoringTransitionDetail({
            from_monitoring_status: prev.monitoring_status, to_monitoring_status: next.monitoring_status,
            from_recurrence_type: prev.recurrence_type, to_recurrence_type: recurrence,
            reason: "windowed_receiver_evidence", entity: row.source_ip,
          }),
          recurrence_band: graded.band,
          window_days: SENDER_WINDOW_DAYS,
          window_total: vol.window_total,
          window_failed: vol.window_failed,
          classification: cls,
        },
      }).catch(() => null);
      if (!occurrenceId) continue;

      // The case, BEFORE the alert. `domain` is deliberately NOT passed: a sender's entity
      // is a source IP, and createManagedCase validates any domain it is given against
      // workspace_domains — handing it the header-from domain would be asserting the
      // sender IS that domain's asset, which is the opposite of what an unrecognised
      // sender means.
      const senderFindingType = EMAIL_RECURRENCE_FINDING_TYPE[recurrence] || null;
      let senderCaseId = null;
      if (EMAIL_CASE_RECURRENCES.has(recurrence)) {
        const linked = await openOrReopenEmailCase(env, {
          workspace_id: workspaceId,
          record_id: row.id,
          entity: row.source_ip,
          recurrence,
          finding_type: senderFindingType,
          severity: graded.band || "medium",
        }).catch(() => null);
        if (linked?.ok && linked.case?.id) {
          senderCaseId = linked.case.id;
          if (linked.created || linked.reopened) {
            await appendEmailProtectionEvent(env, {
              workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
              event_type: linked.reopened ? EMAIL_EVENT_CASE_REOPENED : EMAIL_EVENT_CASE_LINKED,
              detail: { case_id: senderCaseId, recurrence, remediation_id: linked.case.remediation_id ?? null },
            }).catch(() => {});
          }
        }
      }

      const res = await emitLifecycleAlert(env, {
        workspace_id: workspaceId,
        domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
        record_id: row.id,
        entity: row.source_ip,
        hostname: row.domain,
        recurrence,
        record_severity: graded.band,
        case_id: senderCaseId,
        finding_type: senderFindingType,
      });
      if (res?.emitted) alerts += 1;
    } catch {
      // Per-row isolation: one bad row never aborts the pass.
    }
  }
  return { checked, alerts };
}

// The band ladder, from the ONE definition. This was a second, private ladder
// (high=2/medium=1/else=0) sitting beside the policy's — two ranked scales over the same
// three values, which is the drift this episode exists to remove. Only the ORDER is ever
// used (worsening is `prev < next`), so both agreed by luck; a `low` band would have
// exposed them, since this one ranked it equal to "no band at all".
const rankOf = (band) => bandRank(band);

// recurrence_type/band/status are the guard's memory. evaluated_at is diagnostic
// ONLY and is never read back as a condition-start.
async function persistSenderState(env, row, { status, graded, now }) {
  try {
    await env.cybermeters_db
      .prepare(`UPDATE email_sender_sources
                SET monitoring_status = ?, recurrence_type = ?, recurrence_band = ?,
                    evaluated_at = ?, updated_at = datetime('now')
                WHERE id = ? AND workspace_id = ?`)
      .bind(status, graded.recurrence, graded.band, now.toISOString(), row.id, row.workspace_id)
      .run();
  } catch { /* the next pass re-evaluates from persisted truth */ }
}
