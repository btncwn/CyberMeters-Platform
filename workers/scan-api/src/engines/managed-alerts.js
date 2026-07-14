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
import { deliverWorkspaceAlert, formatAlertEmail, resolveWorkspaceAlertRecipients, sendTenantAlertEmail } from "./alerts.js";
import { getEmailFrontendOrigin } from "../lib/lifecycle-email.js";
import { getEffectivePlan, hasFeatureEntitlement } from "./entitlements.js";
import { getWorkspaceBillingUserId } from "./plan-usage.js";

// The entitlement key is canonical and already declared in PLAN_FEATURES. Never
// inline a plan name here.
export const ALERTS_FEATURE_KEY = "alerts";

// Outbound channels this pipeline governs. `in_app` is deliberately absent: the
// bell is the canonical record, not an outbound channel, and is never suppressed
// by a preference or an entitlement.
export const MONITORING_CHANNELS = Object.freeze(["email", "webhook", "slack", "teams"]);

// Terminal: a decision, not a transient error. Retrying any of these would either
// waste budget or override a deliberate rule (entitlement/preference).
export const TERMINAL_REASONS = Object.freeze(new Set([
  "feature_not_entitled",
  "channel_disabled",
  "no_verified_recipient",
  "workspace_deleted",
  "deduplicated",
  "cooldown_active",
  "recipient_undeliverable",
  "alert_baseline_established",
]));

// Retryable: we tried (or could not determine) and it may yet succeed. A hard
// bounce is NOT here — it belongs to recipient_undeliverable above, so an
// permanently invalid address terminates instead of retrying forever.
export const RETRYABLE_REASONS = Object.freeze(new Set([
  "provider_rejected",
  "provider_unavailable",
  "recipient_lookup_failed",
  "missing_api_key",
  "invalid_sender",
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
}) {
  const terminal = outcome === "suppressed" || isTerminalReason(reason) ? 1 : 0;
  try {
    await env.cybermeters_db
      .prepare(`INSERT INTO alert_deliveries
          (id, workspace_id, notification_id, domain_key, alert_kind, dedupe_key, severity,
           channel, channel_id, outcome, reason, terminal, provider_id, recipient_count, attempt, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
      .bind(`ad_${createId()}`, workspace_id, notification_id, domain_key, alert_kind, dedupe_key,
        severity, channel, channel_id, outcome, reason, terminal, provider_id, recipient_count, attempt)
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

// Entitlement via the canonical chain — no plan names in this module.
export async function workspaceAlertsEntitled(env, workspaceId) {
  try {
    const billingUserId = await getWorkspaceBillingUserId(workspaceId, null, env);
    if (!billingUserId) return false;
    const plan = await getEffectivePlan(billingUserId, env);
    return hasFeatureEntitlement(plan, ALERTS_FEATURE_KEY);
  } catch (err) {
    // Fail CLOSED: if entitlement cannot be established we do not push. The
    // canonical in-app event is already recorded, so the customer still sees the
    // finding — they simply are not emailed off an unverified entitlement.
    console.error("[managed-alert] entitlement check failed", JSON.stringify({ workspace_id: workspaceId, reason: err?.message }));
    return false;
  }
}

// Is this outbound channel enabled for this workspace?
//
// notification_preferences (mig 014) already has the right grain
// (workspace_id, user_id, event_type, channel) and was fully built, routed and
// surfaced in Settings — but no engine ever read it, so the UI's "Disabled" was a
// lie. This is the read that makes it real.
//
// Default ON when no row exists: absence of a preference is not a preference, and
// silently defaulting monitoring off would be its own dishonesty. A workspace-wide
// row (user_id IS NULL) is the workspace default; a per-user row overrides it.
export async function channelEnabledForWorkspace(env, workspaceId, { channel, event_type }) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT enabled FROM notification_preferences
                WHERE workspace_id = ? AND channel = ? AND user_id IS NULL
                  AND event_type IN (?, 'all')
                ORDER BY CASE WHEN event_type = ? THEN 0 ELSE 1 END
                LIMIT 1`)
      .bind(workspaceId, channel, event_type, event_type)
      .first().catch(() => null);
    if (!row) return true;
    return Number(row.enabled) === 1;
  } catch {
    // A preference lookup failure must not silently push to a channel the
    // customer may have disabled. Fail closed.
    return false;
  }
}

// ── The emitter ──────────────────────────────────────────────────────────────
//
// Returns { emitted, notification_id, deliveries[] } — deliveries is the per-channel
// outcome list, so a caller (and a test) can see exactly what was suppressed and why.
// Never throws: an alerting failure must not break the scan or lifecycle that raised it.
export async function emitManagedAlert(env, {
  workspace_id, domain_key, kind, severity = "info",
  title, message, dedupe_key = null, link = null,
  case_id = null, remediation_id = null, metadata = {},
  cooldownActive = false,
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
    const meta = { ...metadata, domain_key, kind, case_id, remediation_id, link };
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

    // 4. Cooldown — damps the intrusive channels; the canonical event above is
    //    already recorded, so history stays complete.
    if (cooldownActive) {
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
    if (!(await channelEnabledForWorkspace(env, workspace_id, { channel: "email", event_type: kind }))) {
      deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "email", outcome: "suppressed", reason: "channel_disabled" }));
    } else {
      const recipients = await resolveWorkspaceAlertRecipients(env, workspace_id);
      if (!recipients.ok) {
        // Could not determine the audience — retryable, and explicitly NOT
        // "this workspace has nobody".
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "email", outcome: "failed", reason: "recipient_lookup_failed" }));
      } else if (recipients.emails.length === 0) {
        deliveries.push(await recordDelivery(env, { ...base, notification_id: notifId, channel: "email", outcome: "suppressed", reason: "no_verified_recipient" }));
      } else {
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
          subject: title, text, html, fromKey: "ALERT_EMAIL_FROM",
        });
        deliveries.push(await recordDelivery(env, {
          ...base, notification_id: notifId, channel: "email",
          outcome: sent.sent ? "delivered" : "failed",
          reason: sent.sent ? null : (sent.reason || "send_failed"),
          provider_id: sent.provider_id || null,
          recipient_count: (sent.recipients || []).length,
        }));
      }
    }

    // Channel fan-out (Slack/Teams/webhook) — one preference gate for the family,
    // then the existing signed/SSRF-validated sender. Best-effort by contract:
    // notification_events is the source of truth, channels are a convenience.
    if (!(await channelEnabledForWorkspace(env, workspace_id, { channel: "webhook", event_type: kind }))) {
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
