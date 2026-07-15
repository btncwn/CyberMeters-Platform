// ── Canonical managed-alert pipeline (all eight domains) ─────────────────────
// ONE emitter. Every domain calls emitManagedAlert; nothing else decides whether a
// customer is told something. It exists because alerting had grown eight parallel
// emitters over three storage models, each with its own dedupe, its own recipient
// rules and its own silence — so a rule fixed in one place stayed broken in seven.
//
// This module OWNS the decision. It does not own the transport: channel fan-out is
// still deliverWorkspaceAlert (alerts.js), email is still sendTenantAlertEmail →
// lifecycle-email.js, the bell is still notification_events, cases are still the
// universal model, and customer-facing meaning is still the Canonical Remediation
// Registry. Nothing here is a second copy of any of those.
//
// ── The pipeline, in order ───────────────────────────────────────────────────
//   1. workspace live?          → workspace_deleted          (terminal)
//   2. activation watermark     → alert_baseline_established  (terminal)
//   3. dedupe (UNIQUE key)      → deduplicated               (terminal)
//   4. WRITE THE CANONICAL EVENT — always, from here on
//   5. cooldown                 → cooldown_active            (terminal, outbound only)
//   6. entitlement              → feature_not_entitled       (terminal, outbound only)
//   7. per-channel preference   → channel_disabled           (terminal, per channel)
//   8. verified recipients      → no_verified_recipient      (terminal)
//   9. send                     → delivered | retryable failure
//
// Step 2 sits ABOVE event creation and dedupe deliberately: pre-existing lifecycle
// state must not become a bell notification at all, so it must never reach the
// INSERT. Gating later would still write the event and merely suppress the email.
//
// Step 3 sits ABOVE the outbound gates on purpose: an unentitled or
// channel-disabled workspace still accrues its canonical in-app history. What the
// customer is not sold is the PUSH, never the truth about their own posture.
//
// ── Two rules that are easy to break and must not be ─────────────────────────
//   • SEVERITY NEVER OVERRIDES A DISABLED CHANNEL. There is deliberately no
//     `if (severity === "critical")` escape hatch in this file. A customer who
//     turned a channel off has turned it off. Mandatory account/security service
//     messages are a SEPARATE system (lib/lifecycle-email.js) and are not routed
//     through here, precisely so this rule can hold without stranding them.
//   • NO PLAN NAMES. Entitlement resolves through the canonical helper chain
//     (getWorkspaceBillingUserId → getEffectivePlan → hasFeatureEntitlement) so
//     Pricing Lockstep can rename or re-tier plans without touching alert logic.
import { createId } from "../lib/util.js";
import { deliverWorkspaceAlert, formatAlertEmail, sendTenantAlertEmail } from "./alerts.js";
import { getEmailFrontendOrigin } from "../lib/lifecycle-email.js";
import { isInCooldown, normalizeProviderOutcome, PROVIDER_OUTCOMES } from "./alert-outcomes.js";
import { ALERTS_FEATURE_KEY, channelEnabledForWorkspace, GATED_CHANNELS, workspaceAlertsEntitled } from "./alert-gate.js";

// The entitlement and preference decisions now live in alert-gate.js so the legacy
// senders in alerts.js can share them without a circular import (managed-alerts.js
// already imports alerts.js). Re-exported here so existing importers and the
// validators keep working against the same single definition.
export { ALERTS_FEATURE_KEY, channelEnabledForWorkspace, workspaceAlertsEntitled };

// Outbound channels this pipeline governs. `in_app` is deliberately absent: the
// bell is the canonical record, not an outbound channel, and is never suppressed
// by a preference or an entitlement.
export const MONITORING_CHANNELS = GATED_CHANNELS;

// Reasons the email chokepoint returns that are a DECISION, not a transport
// failure: recorded as `suppressed` + terminal, never retried. Anything else that
// comes back unsent is a real failure and goes through provider normalisation.
const EMAIL_SUPPRESSION_REASONS = new Set([
  "feature_not_entitled",
  "channel_disabled",
  "preference_filtered",
  "no_verified_recipient",
]);

// Terminal: a decision, not a transient error. Retrying any of these would either
// waste budget or override a deliberate rule (entitlement/preference).
export const TERMINAL_REASONS = Object.freeze(new Set([
  "feature_not_entitled",
  "channel_disabled",
  // The alert was real and the customer is entitled, but its severity is below the
  // threshold they chose (`critical_only`). Distinct from channel_disabled — they
  // did not silence the channel, they narrowed it — and terminal, because retrying
  // would override a deliberate choice. `reason` is TEXT with no CHECK constraint,
  // so adding it needed no migration; the vocabulary is enforced in code.
  "preference_filtered",
  "no_verified_recipient",
  "workspace_deleted",
  "deduplicated",
  "cooldown_active",
  "recipient_undeliverable",
  "alert_baseline_established",
  // Configuration failures. Retrying cannot succeed until a deploy changes the
  // config, so a bounded retry would just burn attempts and bury real failures.
  // Terminal + visible in the ledger is the honest outcome.
  "invalid_sender",
  "missing_api_key",
  "invalid_content",
  "no_valid_recipients",
  // Permanent provider outcomes, from the same canonical vocabulary.
  ...Object.entries(PROVIDER_OUTCOMES).filter(([, v]) => v.terminal).map(([k]) => k),
]));

// Retryable: we tried (or could not determine) and it may yet succeed. A hard
// bounce is NOT here — it belongs to recipient_undeliverable above, so an
// permanently invalid address terminates instead of retrying forever.
// Retryable: transient. provider_rejected covers the provider's non-2xx responses,
// which include 429 and 5xx — the cases the founder explicitly allows to retry. It is
// still bounded by RETRY_MAX_ATTEMPTS + RETRY_MAX_AGE_HOURS, so even a permanent 4xx
// hiding in this bucket stops quickly and visibly rather than retrying forever.
export const RETRYABLE_REASONS = Object.freeze(new Set([
  // Derived from the canonical provider vocabulary so the two can never disagree.
  ...Object.entries(PROVIDER_OUTCOMES).filter(([, v]) => !v.terminal).map(([k]) => k),
  "recipient_lookup_failed",
  // We could not establish the plan (a D1 error), which is NOT the same fact as
  // "this workspace is not entitled". Recording the latter would assert something
  // about the customer's billing we never checked, and would terminate an alert
  // that deserves a retry. Retryable and distinct on purpose.
  "entitlement_lookup_failed",
  "send_failed",
]));

export function isTerminalReason(reason) {
  return TERMINAL_REASONS.has(String(reason || ""));
}

// Default: anything we do not recognise is treated as terminal. Fail closed —
// an unknown reason retried hourly forever is worse than one that stops and is
// visible in the ledger.
export function reasonIsRetryable(reason) {
  return RETRYABLE_REASONS.has(String(reason || ""));
}

// ── Deterministic alert identity ─────────────────────────────────────────────
// Same real-world event => same key => at most one alert (enforced by the partial
// UNIQUE index from migration 087, not by a read-then-write race).
//
// Built ONLY from stable, server-side inputs. Never from title/message — those are
// display copy that can be reworded, which would silently mint a "new" alert and
// re-notify the customer about something they already know.
export function buildAlertDedupeKey({ domain_key, kind, subject, period = null }) {
  return [
    String(domain_key || "unknown"),
    String(kind || "unknown"),
    String(subject || "").trim().toLowerCase(),
    period ? String(period) : "",
  ].filter((p) => p !== "").join("|");
}

// ── Append-only delivery ledger ──────────────────────────────────────────────
// One row per (alert, channel) attempt. Never updated — a retry appends a new row,
// so the full history stays reconstructable. Best-effort: a ledger write must
// never break the alert itself, but it IS logged when it fails, because a silent
// ledger is the thing this module exists to end.
async function recordDelivery(env, {
  workspace_id, notification_id = null, domain_key = null, alert_kind, dedupe_key = null,
  severity = null, channel, channel_id = null, outcome, reason = null,
  provider_id = null, recipient_count = 0, attempt = 1,
  provider_status_code = null, provider_error_class = null, provider_message_code = null,
}) {
  const terminal = outcome === "suppressed" || isTerminalReason(reason) ? 1 : 0;
  try {
    await env.cybermeters_db
      .prepare(`INSERT INTO alert_deliveries
          (id, workspace_id, notification_id, domain_key, alert_kind, dedupe_key, severity,
           channel, channel_id, outcome, reason, terminal, provider_id, recipient_count, attempt,
           provider_status_code, provider_error_class, provider_message_code, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
      .bind(`ad_${createId()}`, workspace_id, notification_id, domain_key, alert_kind, dedupe_key,
        severity, channel, channel_id, outcome, reason, terminal, provider_id, recipient_count, attempt,
        provider_status_code, provider_error_class, provider_message_code)
      .run();
  } catch (err) {
    console.error("[managed-alert] ledger write failed", JSON.stringify({ workspace_id, alert_kind, channel, reason: err?.message }));
  }
  return { channel, outcome, reason, terminal: Boolean(terminal) };
}

// ── Gates ────────────────────────────────────────────────────────────────────

// ── Activation watermark (first-run flood guard) ─────────────────────────────
// Each (workspace, domain) is activated exactly once. The activating pass
// establishes the baseline and alerts on NOTHING; only changes observed strictly
// after activated_at may alert.
//
// This exists because the shipped evaluators (certificate/identity/shadow-IT)
// recompute recurrence_type on every run over rows that already exist in
// production. Without this, switching alerting on would announce the entire
// backlog at once — true statements, but not news, and an inbox flood is how a
// monitoring product teaches customers to ignore it.
//
// Idempotent + tenant-scoped by construction: INSERT OR IGNORE against
// UNIQUE (workspace_id, domain_key). A concurrent or repeated pass cannot
// re-baseline, cannot double-activate, and cannot un-suppress history.
//
// Returns { activated_at, established_now }. On any DB error it fails CLOSED
// (treated as just-established), because alerting a backlog is worse than a
// delayed alert.
export async function ensureAlertActivation(env, workspaceId, domainKey, { now = new Date().toISOString() } = {}) {
  try {
    const insert = await env.cybermeters_db
      .prepare(`INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, created_at)
                VALUES (?, ?, ?, ?, datetime('now'))`)
      .bind(`aa_${createId()}`, workspaceId, domainKey, now)
      .run();
    if ((insert.meta?.changes ?? 0) === 1) return { activated_at: now, established_now: true };

    const row = await env.cybermeters_db
      .prepare(`SELECT activated_at FROM alert_activation WHERE workspace_id = ? AND domain_key = ?`)
      .bind(workspaceId, domainKey).first();
    return { activated_at: row?.activated_at || now, established_now: false };
  } catch (err) {
    console.error("[managed-alert] activation check failed", JSON.stringify({ workspace_id: workspaceId, domain_key: domainKey, reason: err?.message }));
    return { activated_at: now, established_now: true, error: true };
  }
}

// Is this observation new enough to alert on?
//   • the activating pass itself  → never (it IS the baseline)
//   • observed at/before the mark → never (pre-existing state, not news)
//   • no observed_at supplied     → allowed: the caller is asserting "this just
//     happened". Consumers of pre-existing state MUST pass observed_at.
export function observationIsAfterWatermark(observedAt, activatedAt) {
  if (!observedAt) return true;
  const o = Date.parse(observedAt), a = Date.parse(activatedAt);
  if (!Number.isFinite(o) || !Number.isFinite(a)) return false; // unparseable → fail closed
  return o > a;
}


// A soft-deleted workspace is nonexistent: no event, no email, no channel.
async function workspaceIsLive(env, workspaceId) {
  const row = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(workspaceId).first().catch(() => null);
  return Boolean(row);
}

// Entitlement and channel-preference decisions live in alert-gate.js (imported and
// re-exported above). They used to be defined here, which meant the legacy senders
// in alerts.js could not reach them without a circular import — and so they simply
// did not check, and free workspaces received paid alerts. One definition, shared.
//
// The channel-preference read in particular was subtly broken here: it looked for
// `event_type IN (<domain_key>.<recurrence>, 'all')`, a vocabulary nothing ever
// wrote, so it always missed and defaulted ON — silently overriding an explicit
// customer opt-out stored under the Settings vocabulary. See alert-gate.js.

// ── The emitter ──────────────────────────────────────────────────────────────
//
// Returns { emitted, notification_id, deliveries[] } — deliveries is the per-channel
// outcome list, so a caller (and a test) can see exactly what was suppressed and why.
// Never throws: an alerting failure must not break the scan or lifecycle that raised it.
export async function emitManagedAlert(env, {
  workspace_id, domain_key, kind, severity = "info",
  title, message, dedupe_key = null, link = null,
  case_id = null, remediation_id = null, metadata = {},
  // Canonical cooldown is resolved INSIDE the pipeline (see alert-outcomes.js).
  // Kept only as a test/override seam; callers do not decide cooldown policy.
  cooldownActive = null,
  cooldown_entity = null,
  // When the underlying CONDITION was observed — not when it was evaluated.
  //
  // This distinction is the whole flood guard. The lifecycle evaluators refresh
  // `evaluated_at` on EVERY pass, so a consumer passing evaluated_at (or now())
  // would clear the watermark on the second run and release the entire backlog —
  // the activation baseline would only have delayed the flood by one hour.
  //
  // Consumers MUST pass a timestamp that is stable across evaluations and belongs
  // to the condition itself: replacement_detected_at, last_changed_at,
  // first_seen_at. Then a pre-existing condition stays pre-existing no matter how
  // many times it is re-evaluated, and only a genuinely new observation alerts.
  observed_at = null,
} = {}) {
  const deliveries = [];
  const base = { workspace_id, domain_key, alert_kind: kind, dedupe_key, severity };
  try {
    // 1. Soft-deleted workspaces receive nothing at all.
    if (!(await workspaceIsLive(env, workspace_id))) {
      deliveries.push(await recordDelivery(env, { ...base, channel: "in_app", outcome: "suppressed", reason: "workspace_deleted" }));
      return { emitted: false, notification_id: null, reason: "workspace_deleted", deliveries };
    }

    // 2. Activation watermark — BEFORE event creation and dedupe, so pre-existing
    //    state never becomes a bell notification and is never enqueued for retry.
    const activation = await ensureAlertActivation(env, workspace_id, domain_key);
    if (activation.established_now || !observationIsAfterWatermark(observed_at, activation.activated_at)) {
      deliveries.push(await recordDelivery(env, {
        ...base, channel: "in_app", outcome: "suppressed", reason: "alert_baseline_established",
      }));
      return { emitted: false, notification_id: null, reason: "alert_baseline_established", deliveries };
    }

    // 3 + 4. Dedupe and write the canonical event in ONE statement. INSERT OR
    // IGNORE against the partial UNIQUE index makes duplicate suppression a
    // database guarantee — two concurrent scans cannot both win.
    const notifId = `notif_${createId()}`;
    // cooldown_entity is persisted on the event so the cooldown window can be
    // resolved per (kind, entity) from the ledger join without a second table.
    const cooldownEntity = String(cooldown_entity || metadata.hostname || dedupe_key || "").trim().toLowerCase();
    const meta = { ...metadata, domain_key, kind, case_id, remediation_id, link, cooldown_entity: cooldownEntity };
    const insert = await env.cybermeters_db
      .prepare(`INSERT OR IGNORE INTO notification_events
          (id, workspace_id, type, severity, title, message, metadata_json, status, created_at, domain_key, dedupe_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'unread', datetime('now'), ?, ?)`)
      .bind(notifId, workspace_id, kind, severity, title, message, JSON.stringify(meta), domain_key, dedupe_key)
      .run();

    if ((insert.meta?.changes ?? 0) === 0) {
      // Same event, already recorded. Terminal — never retried, never re-sent.
      deliveries.push(await recordDelivery(env, { ...base, channel: "in_app", outcome: "suppressed", reason: "deduplicated" }));
      return { emitted: false, notification_id: null, reason: "deduplicated", deliveries };
    }
    deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "in_app", outcome: "delivered" }));

    // 4. Cooldown — ONE canonical policy (alert-outcomes.js), resolved here rather
    //    than trusted from the caller. Outbound only: the canonical event above is
    //    already recorded, so the bell and history stay complete.
    const inCooldown = cooldownActive === null
      ? await isInCooldown(env, { workspace_id, domain_key, kind, entity: cooldownEntity, severity })
      : Boolean(cooldownActive);
    if (inCooldown) {
      for (const channel of MONITORING_CHANNELS) {
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel, outcome: "suppressed", reason: "cooldown_active" }));
      }
      return { emitted: true, notification_id: notifId, reason: "cooldown_active", deliveries };
    }

    // 5. Entitlement. Proactive DELIVERY is the paid feature; the finding itself
    //    is not. Recorded as an entitlement outcome — never as a preference.
    if (!(await workspaceAlertsEntitled(env, workspace_id))) {
      for (const channel of MONITORING_CHANNELS) {
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel, outcome: "suppressed", reason: "feature_not_entitled" }));
      }
      return { emitted: true, notification_id: notifId, reason: "feature_not_entitled", deliveries };
    }

    // 6 + 7 + 8. Email.
    //
    // Audience, per-user preference and severity are ALL decided inside
    // sendTenantAlertEmail — it is the one chokepoint, so this branch no longer
    // pre-resolves recipients or second-guesses the preference. It maps the
    // chokepoint's honest reason onto the ledger's closed vocabulary.
    {
      // Reuse the canonical escaped template — one alert-email body for every
      // domain — and carry the monitoring-preference-centre link (a product
      // setting, NOT a marketing unsubscribe).
      const origin = getEmailFrontendOrigin(env);
      const { text, html } = formatAlertEmail({
        workspaceName: workspace_id,
        domain: metadata.hostname || null,
        whatChanged: message,
        recommendation: metadata.recommended_action || "Review this alert in CyberMeters.",
        link: link || (origin ? `${origin}/notifications` : null),
        preferencesLink: origin ? `${origin}/settings` : null,
      });
      const sent = await sendTenantAlertEmail(env, workspace_id, {
        subject: title, text, html, fromKey: "ALERT_EMAIL_FROM", severity,
      });
      if (!sent.sent && EMAIL_SUPPRESSION_REASONS.has(sent.reason)) {
        // A deliberate rule decided this, not a transport failure. Terminal.
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "email", outcome: "suppressed", reason: sent.reason }));
      } else if (!sent.sent && sent.reason === "recipient_lookup_failed") {
        // Could not determine the audience — retryable, and explicitly NOT
        // "this workspace has nobody".
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "email", outcome: "failed", reason: "recipient_lookup_failed" }));
      } else {
        // Normalize the transport's coarse outcome into the closed vocabulary so
        // the retry sweep can tell a 429 from a 403. Unknown => terminal.
        const norm = sent.sent ? null : normalizeProviderOutcome({ reason: sent.reason, status: sent.status, provider_code: sent.provider_code });
        deliveries.push(await recordDelivery(env, {
          ...base, notification_id: notifId, channel: "email",
          outcome: sent.sent ? "delivered" : "failed",
          reason: sent.sent ? null : norm.reason,
          provider_id: sent.provider_id || null,
          recipient_count: (sent.recipients || []).length,
          provider_status_code: norm?.provider_status_code ?? null,
          provider_error_class: norm?.provider_error_class ?? null,
          provider_message_code: norm?.provider_message_code ?? null,
        }));
      }
    }

    // Channel fan-out (Slack/Teams/webhook) — one preference gate for the family,
    // then the existing signed/SSRF-validated sender. Best-effort by contract:
    // notification_events is the source of truth, channels are a convenience.
    //
    // The gate is read here to record the ledger reason, and enforced AGAIN inside
    // deliverWorkspaceAlert (which every legacy path also goes through). The double
    // check is deliberate: this one exists to explain the suppression, that one
    // exists so no caller can skip it.
    if (!(await channelEnabledForWorkspace(env, workspace_id, { channel: "webhook" }))) {
      deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "webhook", outcome: "suppressed", reason: "channel_disabled" }));
    } else {
      try {
        await deliverWorkspaceAlert(env, workspace_id, { kind, severity, title, message, link, domain_key });
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "webhook", outcome: "delivered" }));
      } catch (err) {
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "webhook", outcome: "failed", reason: "provider_unavailable" }));
      }
    }

    return { emitted: true, notification_id: notifId, reason: null, deliveries };
  } catch (err) {
    // Never break the caller. But do NOT swallow silently — a silent alert
    // pipeline is exactly the failure mode this module replaces.
    console.error("[managed-alert] emit failed", JSON.stringify({ workspace_id, kind, domain_key, reason: err?.message }));
    return { emitted: false, notification_id: null, reason: "emit_failed", deliveries };
  }
}

// ── Bounded retry sweep ──────────────────────────────────────────────────────
// Re-attempts deliveries that failed for a TRANSIENT reason. Everything about this
// is bounded, because an unbounded retry loop against a provider is how a
// monitoring product turns one outage into a sending-reputation incident.
//
//   • only outcome='failed' AND terminal=0 — a terminal row is a decision, not a
//     failure, and must never be revisited;
//   • deterministic ordering + LIMIT — one bounded slice per tick;
//   • max attempts / max age — a permanently broken target stops, visibly;
//   • deterministic backoff — attempt N waits 2^N hours, so a struggling provider
//     is not hammered;
//   • append-only — every attempt INSERTs a new ledger row; nothing is overwritten,
//     so the full attempt history stays reconstructable;
//   • re-checks workspace live state, entitlement, preferences and recipients
//     BEFORE resending — a customer who disabled the channel, lost entitlement or
//     deleted the workspace between the failure and the retry must not receive it;
//   • never resends after a success for the same alert.
export const RETRY_MAX_ATTEMPTS = 4;
export const RETRY_MAX_AGE_HOURS = 72;
export const RETRY_BATCH_LIMIT = 10;

// Deterministic backoff: attempt 1 → 2h, 2 → 4h, 3 → 8h. Not random: a fixed
// schedule is reproducible in tests and predictable in an incident.
export function retryBackoffHours(attempt) {
  return Math.pow(2, Math.max(1, Number(attempt) || 1));
}

export function retryDue(row, { now = new Date().toISOString() } = {}) {
  const last = Date.parse(row.created_at);
  const t = Date.parse(now);
  if (!Number.isFinite(last) || !Number.isFinite(t)) return false;   // unparseable → fail closed
  return (t - last) >= retryBackoffHours(row.attempt) * 3_600_000;
}

// Should this failure ever be retried again?
// Fails CLOSED: an unrecognised reason is treated as permanent. A wrong "stop" is
// visible in the ledger; a wrong "retry forever" is a silent outbound loop.
export function retryEligible(row, { now = new Date().toISOString() } = {}) {
  if (row.outcome !== "failed" || Number(row.terminal) === 1) return { ok: false, reason: "terminal" };
  if (!reasonIsRetryable(row.reason)) return { ok: false, reason: "permanent_reason" };
  if (Number(row.attempt) >= RETRY_MAX_ATTEMPTS) return { ok: false, reason: "max_attempts" };
  const age = Date.parse(now) - Date.parse(row.created_at);
  if (!Number.isFinite(age) || age > RETRY_MAX_AGE_HOURS * 3_600_000) return { ok: false, reason: "max_age" };
  if (!retryDue(row, { now })) return { ok: false, reason: "backoff" };
  return { ok: true, reason: null };
}

// Has this alert already been delivered on this channel? Success is final — a retry
// after a success would double-send the same alert.
async function alreadyDelivered(env, notificationId, channel) {
  const row = await env.cybermeters_db
    .prepare(`SELECT id FROM alert_deliveries
              WHERE notification_id = ? AND channel = ? AND outcome = 'delivered' LIMIT 1`)
    .bind(notificationId, channel).first().catch(() => null);
  return Boolean(row);
}

export async function retryFailedAlertDeliveries(env, { now = new Date().toISOString(), limit = RETRY_BATCH_LIMIT } = {}) {
  const stats = { examined: 0, retried: 0, delivered: 0, skipped: 0, terminated: 0 };
  try {
    const rows = await env.cybermeters_db
      .prepare(`SELECT * FROM alert_deliveries
                WHERE outcome = 'failed' AND terminal = 0 AND channel = 'email'
                  AND created_at > datetime(?, '-${RETRY_MAX_AGE_HOURS} hours')
                ORDER BY created_at ASC, id ASC
                LIMIT ?`)
      .bind(now, Math.max(1, Math.min(50, limit)))
      .all().catch(() => null);

    for (const row of (rows?.results || [])) {
      stats.examined++;

      const eligible = retryEligible(row, { now });
      if (!eligible.ok) {
        if (eligible.reason === "backoff") { stats.skipped++; continue; }   // not yet due — leave it
        // Out of attempts / too old / permanent: stop, and say so in the ledger.
        await recordDelivery(env, { ...row, notification_id: row.notification_id, alert_kind: row.alert_kind,
          outcome: "suppressed", reason: eligible.reason === "permanent_reason" ? row.reason : eligible.reason,
          attempt: Number(row.attempt) + 1 });
        stats.terminated++;
        continue;
      }

      // Never resend after a success.
      if (row.notification_id && await alreadyDelivered(env, row.notification_id, row.channel)) {
        stats.skipped++;
        continue;
      }

      // Re-check the decision gates: the world may have changed since the failure.
      if (!(await workspaceIsLive(env, row.workspace_id))) {
        await recordDelivery(env, { ...row, outcome: "suppressed", reason: "workspace_deleted", attempt: Number(row.attempt) + 1 });
        stats.terminated++; continue;
      }
      if (!(await workspaceAlertsEntitled(env, row.workspace_id))) {
        await recordDelivery(env, { ...row, outcome: "suppressed", reason: "feature_not_entitled", attempt: Number(row.attempt) + 1 });
        stats.terminated++; continue;
      }
      // Channel-family preference. Email is NOT gated here: it is per-recipient,
      // and sendTenantAlertEmail below re-applies the preference and severity for
      // every address at send time — re-checking a workspace-wide row for it would
      // be the wrong grain and could contradict the chokepoint.
      if (row.channel !== "email"
          && !(await channelEnabledForWorkspace(env, row.workspace_id, { channel: row.channel }))) {
        await recordDelivery(env, { ...row, outcome: "suppressed", reason: "channel_disabled", attempt: Number(row.attempt) + 1 });
        stats.terminated++; continue;
      }

      // Rebuild from the canonical event — never from a cached copy of the copy.
      const notif = row.notification_id ? await env.cybermeters_db
        .prepare(`SELECT title, message FROM notification_events WHERE id = ? AND workspace_id = ?`)
        .bind(row.notification_id, row.workspace_id).first().catch(() => null) : null;
      if (!notif) {
        await recordDelivery(env, { ...row, outcome: "suppressed", reason: "recipient_undeliverable", attempt: Number(row.attempt) + 1 });
        stats.terminated++; continue;
      }

      const sent = await sendTenantAlertEmail(env, row.workspace_id, {
        subject: notif.title, text: notif.message, html: `<p>${String(notif.message || "")}</p>`,
        fromKey: "ALERT_EMAIL_FROM",
        // From the ledger row, so a retry is filtered by the same severity rule
        // the original send was. Omitting it would make every retry look
        // unlabelled and silently drop `critical_only` recipients.
        severity: row.severity,
      });
      // A suppression from the chokepoint is a DECISION (not entitled / opted out /
      // below their severity threshold / no verified audience). It must settle as
      // terminal `suppressed`, never `failed` — a failed row is what this very
      // sweep re-picks up, so recording a deliberate rule as a failure would retry
      // it hourly until the attempt cap, burning budget and burying real failures.
      if (!sent.sent && EMAIL_SUPPRESSION_REASONS.has(sent.reason)) {
        await recordDelivery(env, {
          ...row, outcome: "suppressed", reason: sent.reason, attempt: Number(row.attempt) + 1,
        });
        stats.terminated++;
        continue;
      }
      const rnorm = sent.sent ? null : normalizeProviderOutcome({ reason: sent.reason, status: sent.status, provider_code: sent.provider_code });
      await recordDelivery(env, {
        ...row, outcome: sent.sent ? "delivered" : "failed",
        reason: sent.sent ? null : rnorm.reason,
        provider_id: sent.provider_id || null,
        recipient_count: (sent.recipients || []).length,
        attempt: Number(row.attempt) + 1,
        provider_status_code: rnorm?.provider_status_code ?? null,
        provider_error_class: rnorm?.provider_error_class ?? null,
        provider_message_code: rnorm?.provider_message_code ?? null,
      });
      stats.retried++;
      if (sent.sent) stats.delivered++;
    }
    return stats;
  } catch (err) {
    console.error("[managed-alert] retry sweep failed", JSON.stringify({ reason: err?.message }));
    return stats;
  }
}
