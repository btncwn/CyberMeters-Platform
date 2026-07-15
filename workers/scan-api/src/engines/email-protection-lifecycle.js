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
import {
  MONITORING_CHANGED, buildMonitoringTransitionDetail, isMonitoringTransition, parseUtcMs,
} from "./alert-occurrence.js";
import { ensureAlertActivation } from "./managed-alerts.js";

export const EMAIL_PROTECTION_DOMAIN_KEY = "email_protection";

// The two record families sharing the event source.
export const HOSTED_RECORD_TYPE = "hosted_dns_entry";
export const SENDER_RECORD_TYPE = "email_sender_source";

// Non-alertable event types. Each is a real fact worth keeping, and none may
// ever alert. They are deliberately NOT `monitoring_changed`: the resolver only
// looks at that value, so these are unreachable by the alert path by design.
export const EMAIL_EVENT_BASELINE               = "baseline_established";
export const EMAIL_EVENT_HOSTED_RECONNECTED     = "hosted_record_reconnected";
export const EMAIL_EVENT_HOSTED_POLICY_CHANGED  = "hosted_policy_changed";
export const EMAIL_EVENT_HOSTED_ROLLED_BACK_MANUAL = "hosted_rolled_back_manual";
export const EMAIL_EVENT_SENDER_RECOVERED       = "sender_failures_recovered";
export const EMAIL_EVENT_SENDER_MANUAL_CLASS    = "sender_manual_classification";

export const NON_ALERTABLE_EVENT_TYPES = Object.freeze([
  EMAIL_EVENT_BASELINE,
  EMAIL_EVENT_HOSTED_RECONNECTED,
  EMAIL_EVENT_HOSTED_POLICY_CHANGED,
  EMAIL_EVENT_HOSTED_ROLLED_BACK_MANUAL,
  EMAIL_EVENT_SENDER_RECOVERED,
  EMAIL_EVENT_SENDER_MANUAL_CLASS,
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

// Manual customer classification WINS over auto, preserved verbatim from
// dmarc-alerts.js:28-31. `classified_at` is the marker the customer decided.
export function effectiveClassification(row) {
  if (row?.classified_at) return row.classification || "unknown";
  return row?.auto_classification || row?.classification || "unknown";
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

// The record's current graded condition, read from the append-only history.
//
// The events table IS the state for the hosted family, which is why B3 needs no
// new column on hosted_dns_entries: the last monitoring_changed row already says
// what condition we last graded this record with.
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
                WHERE workspace_id = ? AND record_id = ? AND event_type = ?
                ORDER BY created_at DESC, rowid DESC LIMIT 1`)
      .bind(workspaceId, recordId, MONITORING_CHANGED)
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

  return await emitLifecycleAlert(env, {
    workspace_id: row.workspace_id,
    domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
    record_id: row.id,
    entity: row.domain,
    hostname: row.domain,
    recurrence,
    record_severity,
    finding_type: EMAIL_RECURRENCE_FINDING_TYPE[recurrence] || null,
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
                JOIN dmarc_aggregate_reports rep ON rep.id = r.report_id
                WHERE r.workspace_id = ? AND r.domain = ? AND rep.date_range_end >= ?
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

// The condition a sender is in, from windowed evidence + classification ONLY.
// Pure and total, so CI can drive it directly.
export function gradeSenderCondition({ classification, window_total, window_failed, is_new }) {
  const band = senderAlertBand(classification);
  const failed = Number(window_failed || 0);
  const total = Number(window_total || 0);

  // Active unauthorised authentication failures. NOT a spike and never described
  // as one: we hold no prior-period baseline, so we can only state an absolute
  // count inside the window.
  if (String(classification || "").toLowerCase() === "unauthorised" && failed >= SENDER_FAILURE_TRIGGER) {
    return { recurrence: "sender_unauthorised_failures_active", band: "high" };
  }
  // A new, high-volume, not-yet-recognised source.
  if (is_new && band !== null && total >= SENDER_NEW_MIN_VOLUME) {
    return { recurrence: "sender_unrecognised", band };
  }
  return { recurrence: null, band };
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
      const cls = effectiveClassification(row);
      const preExisting = isPreExistingRecord(row.first_seen, activatedAt);
      const graded = gradeSenderCondition({
        classification: cls,
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
      if (row.classified_at && prev.recurrence_band !== graded.band && row.monitoring_status) {
        await appendEmailProtectionEvent(env, {
          workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
          event_type: EMAIL_EVENT_SENDER_MANUAL_CLASS, actor_type: "customer",
          detail: {
            to_recurrence_type: null, reason: "customer_classified",
            entity: row.source_ip, classification: cls,
          },
        }).catch(() => {});
        await persistSenderState(env, row, { status: row.monitoring_status || "observed", graded, now });
        continue;
      }

      // ── Recovery: zero receiver-reported failures in a complete window ─────
      // Expressible ONLY because the window drops old reports out. A cumulative
      // counter could never come back down, which is why the legacy sweep had no
      // recovery at all. Non-alertable by founder decision.
      if (prev.recurrence_type === "sender_unauthorised_failures_active"
          && graded.recurrence === null
          && vol.window_failed === SENDER_RECOVERY_FAILURES) {
        await appendEmailProtectionEvent(env, {
          workspace_id: workspaceId, record_id: row.id, record_type: SENDER_RECORD_TYPE,
          event_type: EMAIL_EVENT_SENDER_RECOVERED,
          detail: {
            to_recurrence_type: null, reason: "no_failures_in_window",
            entity: row.source_ip, window_days: SENDER_WINDOW_DAYS,
          },
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

      const res = await emitLifecycleAlert(env, {
        workspace_id: workspaceId,
        domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
        record_id: row.id,
        entity: row.source_ip,
        hostname: row.domain,
        recurrence,
        record_severity: graded.band,
        finding_type: EMAIL_RECURRENCE_FINDING_TYPE[recurrence] || null,
      });
      if (res?.emitted) alerts += 1;
    } catch {
      // Per-row isolation: one bad row never aborts the pass.
    }
  }
  return { checked, alerts };
}

function rankOf(band) {
  if (band === "high") return 2;
  if (band === "medium") return 1;
  return 0;
}

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
