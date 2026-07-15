// ── The alert trust gate ─────────────────────────────────────────────────────
// Two questions, one place: is this workspace ENTITLED to outbound alerts, and
// has this customer asked not to receive them? Every outbound alert path must
// pass through here — email, Slack, Teams, webhook, canonical or legacy.
//
// Why this module exists at all (rather than living in managed-alerts.js):
// managed-alerts.js already imports alerts.js, and the legacy senders live in
// alerts.js. Putting the gate in managed-alerts.js and calling it from alerts.js
// would be a circular import. This module imports only entitlements/plan-usage,
// so both can depend on it. It is an extraction, not a second alert system —
// there is still exactly one definition of each rule.
//
// ── Defect 1 this closes: the free-plan entitlement bypass ───────────────────
// `emitManagedAlert` checked entitlement; NOTHING else did. The legacy scan-alert
// path (processAlertsForWorkspace → triggerAlert) sent real email AND fanned out
// to Slack/Teams/webhook on every scan with no check at all, while the `free` plan
// grants no "alerts" feature. Free workspaces received paid alerts. The gate now
// lives INSIDE the two chokepoints (sendTenantAlertEmail, deliverWorkspaceAlert)
// rather than at call sites, so a new caller cannot forget it — the same pattern
// PR #86 used to stop the operator-inbox fallback.
//
// ── Defect 2 this closes: the preference control that did nothing ────────────
// The Settings page wrote per-USER rows under the vocabulary
// {critical_finding, high_finding, daily_digest, email_alerts}. The pipeline read
// WORKSPACE-wide rows under `event_type IN (<domain_key>.<recurrence>, 'all')`.
// The two never intersected — neither the user scope nor the vocabulary — and
// nothing ever wrote 'all'. So the lookup always missed and defaulted to ON,
// silently overriding an explicit customer opt-out. Write and read now share ONE
// vocabulary, defined here, so they cannot drift apart again.

import { getEffectivePlan, hasFeatureEntitlement } from "./entitlements.js";
import { getWorkspaceBillingUserId } from "./plan-usage.js";

// The entitlement key is canonical and already declared in PLAN_FEATURES. Never
// inline a plan name. One global key by founder decision (14 July 2026) — there
// are deliberately NO per-domain entitlement keys.
export const ALERTS_FEATURE_KEY = "alerts";

// ── The canonical preference vocabulary ──────────────────────────────────────
// ONE event_type family for every managed alert, every domain. Per founder
// decision this is deliberately NOT per-domain: a customer sets how they want to
// be told, not which of the eight domains may tell them.
//
// Two rows encode three states, because notification_preferences (migration 014)
// stores a boolean `enabled` and no value column — and this episode ships no
// migration:
//
//   managed_alert.enabled = 0                → "disabled"
//   managed_alert_critical_only.enabled = 1  → "critical_only"
//   neither                                  → "all_alerts"  (the default)
export const ALERT_PREF_EVENT         = "managed_alert";
export const ALERT_PREF_CRITICAL_ONLY = "managed_alert_critical_only";

// The supported immediate-alert preferences. `daily_digest` is deliberately ABSENT:
// the Settings page offered "One summary email per day. No immediate alerts." and
// no daily digest sender has ever existed anywhere in the backend — the value
// appeared in exactly one file, the route that stored it. While preferences were
// ignored the option was merely inert; wiring them would have made it load-bearing,
// and then every mapping is a lie (suppress → the customer gets silence; send → the
// label lies). Removed at source rather than aliased. Zero production rows carried
// it, so nothing was migrated. Do not re-add it without a real digest sender.
export const ALERT_EMAIL_FREQUENCIES = Object.freeze(["all_alerts", "critical_only", "disabled"]);

// Outbound channels this gate governs. `in_app` is deliberately absent: the bell is
// the canonical evidence record, not an outbound channel, and is never suppressed
// by a preference or an entitlement. A customer who silenced their email still has
// the history.
export const GATED_CHANNELS = Object.freeze(["email", "webhook", "slack", "teams"]);

// ── Entitlement ──────────────────────────────────────────────────────────────
// Proactive DELIVERY is the paid feature; the finding itself is not. A free
// workspace still sees its scan results, findings and in-app state — it just is
// not told proactively. Fails CLOSED: an unresolvable plan never sends.
// Tri-state on purpose. "We checked, and they are not entitled" and "we could not
// check" are different facts, and collapsing them is the same mistake this episode
// keeps finding: a transient D1 error recorded forever as `feature_not_entitled`
// asserts something about the customer's plan that we never established, and
// terminates an alert that should have been retried.
//
//   { ok: true,  entitled: true  } → send
//   { ok: true,  entitled: false } → feature_not_entitled  (terminal, honest)
//   { ok: false, entitled: false } → could not determine    (retryable)
export async function resolveAlertEntitlement(env, workspaceId) {
  try {
    // Signature is positional: (workspaceId, fallbackUserId, env). No fallback
    // user — an alert belongs to the workspace's billing owner or to nobody.
    const billingUserId = await getWorkspaceBillingUserId(workspaceId, null, env);
    // A workspace with no owner is definitively unentitled, not unknown.
    if (!billingUserId) return { ok: true, entitled: false };
    const plan = await getEffectivePlan(billingUserId, env);
    return { ok: true, entitled: hasFeatureEntitlement(plan, ALERTS_FEATURE_KEY) };
  } catch (err) {
    console.error("[alert-gate] entitlement check failed", JSON.stringify({ workspace_id: workspaceId, reason: err?.message }));
    return { ok: false, entitled: false };
  }
}

// Fail-CLOSED boolean for callers that only need "may we send?". An unresolvable
// entitlement never sends: the canonical in-app event is already recorded, so the
// customer still sees the finding — they simply are not emailed off an unverified
// entitlement. Callers that must explain WHY should use resolveAlertEntitlement.
export async function workspaceAlertsEntitled(env, workspaceId) {
  const r = await resolveAlertEntitlement(env, workspaceId);
  return r.ok && r.entitled;
}

// ── Severity filter ──────────────────────────────────────────────────────────
// `critical_only` means EXACTLY severity === "critical". It is not "high or above":
// the customer chose the narrowest setting and widening it for them would be us
// deciding they did not mean it. High/medium/low are suppressed and recorded.
//
// Unknown frequency → false. An unrecognised preference must never resolve to
// outbound ON; that is the exact shape of the bug this module exists to kill.
export function severityAllowedByFrequency(frequency, severity) {
  if (frequency === "all_alerts")    return true;
  if (frequency === "critical_only") return String(severity) === "critical";
  return false; // "disabled" and anything unrecognised
}

// ── Per-user email preference ────────────────────────────────────────────────
// Resolution order: the recipient's own row wins over the workspace-wide default,
// which wins over the built-in default (all_alerts). Scoped to (workspace, user):
// one member silencing their email cannot silence a colleague's, and no row from
// another workspace is visible to this query.
//
// Returns { ok, frequency }. ok:false means we could not determine the preference
// (a D1 error) — deliberately distinct from "they chose all_alerts". The caller
// must fail closed on it: pushing to someone who may have opted out is worse than
// a missed alert that the in-app record still carries.
export async function alertEmailFrequencyForUser(env, workspaceId, userId) {
  try {
    const rows = await env.cybermeters_db
      .prepare(
        `SELECT user_id, event_type, enabled
           FROM notification_preferences
          WHERE workspace_id = ?
            AND channel = 'email'
            AND (user_id = ? OR user_id IS NULL)
            AND event_type IN (?, ?)`
      )
      .bind(workspaceId, userId ?? null, ALERT_PREF_EVENT, ALERT_PREF_CRITICAL_ONLY)
      .all();

    const results = rows?.results || [];
    // The user's own row wins over the workspace-wide (user_id IS NULL) default.
    const pick = (eventType) => {
      const forType = results.filter((r) => r.event_type === eventType);
      const own = forType.find((r) => r.user_id != null && r.user_id === userId);
      const wide = forType.find((r) => r.user_id == null);
      const row = own ?? wide;
      return row ? Number(row.enabled) : null;
    };

    if (pick(ALERT_PREF_EVENT) === 0) return { ok: true, frequency: "disabled" };
    if (pick(ALERT_PREF_CRITICAL_ONLY) === 1) return { ok: true, frequency: "critical_only" };
    return { ok: true, frequency: "all_alerts" };
  } catch {
    return { ok: false, frequency: null };
  }
}

// ── Workspace channel preference ─────────────────────────────────────────────
// Slack/Teams/webhook endpoints are workspace-owned, not user-owned: the webhook
// fires once for the workspace, so a per-user toggle on it would be meaningless.
// These read the workspace-wide row only. Default ON; fails CLOSED on error.
export async function channelEnabledForWorkspace(env, workspaceId, { channel } = {}) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT enabled FROM notification_preferences
          WHERE workspace_id = ? AND channel = ? AND user_id IS NULL AND event_type = ?
          LIMIT 1`
      )
      .bind(workspaceId, channel, ALERT_PREF_EVENT)
      .first();
    if (!row) return true;             // no preference stored → default ON
    return Number(row.enabled) === 1;
  } catch {
    // A preference lookup failure must not silently push to a channel the
    // customer may have disabled. Fail closed.
    return false;
  }
}
