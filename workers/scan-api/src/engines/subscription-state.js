// ── Subscription / trial state engine ──
// Trial plan constants, trial/subscription state checks, workspace
// subscription resolution (with trial auto-provisioning), checkout plan
// parsing, public billing-plan metadata and the API-token session-route
// denial audit helper. Extracted verbatim from index.js (router split,
// Phase 2 PR #12).
import { BILLING_PLAN_METADATA, getPlanFeatures } from "./entitlements.js";
import { getPlanLimits } from "./plan-usage.js";
import { createAuditEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";

// ── Trial engine ──────────────────────────────────────────────────────────────

export const TRIAL_PLAN          = "professional"; // plan granted during trial
export const TRIAL_DURATION_DAYS = 14;

/**
 * isTrialActive(sub)
 *
 * Returns true if the subscription row represents an active trial.
 * A trial is active when:
 *   - subscription_status is 'trialing'
 *   - trial_end has not passed
 *
 * Handles null/missing gracefully (returns false).
 */
export function isTrialActive(sub) {
  if (!sub) return false;
  const status = String(sub.subscription_status || sub.status || "").trim().toLowerCase();
  if (status !== "trialing") return false;
  if (!sub.trial_end) return false;
  const end = new Date(sub.trial_end);
  if (Number.isNaN(end.getTime())) return false;
  return end.getTime() > Date.now();
}

/**
 * isSubscriptionActive(sub)
 *
 * Returns true if the subscription represents a live paid subscription.
 * Excludes trialing status — use isTrialActive() for that case.
 * An active paid subscription requires:
 *   - subscription_status is 'active' (not trialing, past_due, cancelled, etc.)
 *   - current_period_end (or expires_at) has not passed, OR is null (no expiry set yet)
 */
export function isSubscriptionActive(sub) {
  if (!sub) return false;
  const status = String(sub.subscription_status || sub.status || "").trim().toLowerCase();
  if (status !== "active") return false;
  // If no period end set, assume active (manual subscription with no expiry)
  const periodEnd = sub.current_period_end || sub.expires_at;
  if (!periodEnd) return true;
  const end = new Date(periodEnd);
  if (Number.isNaN(end.getTime())) return true; // unparseable — assume active
  return end.getTime() > Date.now();
}

/**
 * getTrialRemainingDays(sub)
 *
 * Returns integer days remaining in the trial (0 if not trialing or expired).
 * Rounds up: a trial ending in 30 minutes returns 1 day.
 */
export function getTrialRemainingDays(sub) {
  if (!isTrialActive(sub)) return 0;
  const now = Date.now();
  const end = new Date(sub.trial_end).getTime();
  const diffMs = end - now;
  if (diffMs <= 0) return 0;
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * getWorkspaceSubscription(workspaceId, env)
 *
 * Fetches the full subscription row for a workspace.
 * Resolves via workspace.owner_user_id → subscriptions.owner_user_id.
 * Returns null if no subscription row exists.
 *
 * Used by:
 *   - GET /api/workspaces/:id/subscription
 *   - SubscriptionPage.jsx (via the above endpoint)
 */
export async function getWorkspaceSubscription(workspaceId, env) {
  if (!workspaceId) return null;
  try {
    const ws = await env.cybermeters_db
      .prepare(`SELECT owner_user_id FROM workspaces WHERE id = ?`)
      .bind(workspaceId)
      .first();
    if (!ws?.owner_user_id) return null;

    const sub = await env.cybermeters_db
      .prepare(
        `SELECT id, owner_user_id, workspace_id, plan, status,
                subscription_status, billing_interval,
                trial_start, trial_end, current_period_start, current_period_end,
                expires_at, stripe_customer_id, stripe_subscription_id,
                cancel_at_period_end, cancelled_at,
                payment_failed_at, payment_retry_count,
                created_at, updated_at
         FROM subscriptions
         WHERE owner_user_id = ?
         ORDER BY COALESCE(updated_at, created_at) DESC
         LIMIT 1`
      )
      .bind(ws.owner_user_id)
      .first();
    return sub ?? null;
  } catch {
    return null;
  }
}

/**
 * createWorkspaceTrialSubscription(workspaceId, ownerUserId, env)
 *
 * Inserts a 14-day Professional trial subscription row when a workspace is created.
 * Also inserts a trial_started event in subscription_events.
 *
 * Called from the POST /api/workspaces route after workspace row is inserted.
 * Fails silently — workspace creation should not be blocked by billing errors.
 */
export async function createWorkspaceTrialSubscription(workspaceId, ownerUserId, env) {
  if (!workspaceId || !ownerUserId) return;
  try {
    const now     = new Date();
    const trialEnd = new Date(now.getTime() + TRIAL_DURATION_DAYS * 24 * 60 * 60 * 1000);
    const subId   = createId("sub");

    await env.cybermeters_db
      .prepare(
        `INSERT OR IGNORE INTO subscriptions
           (id, owner_user_id, workspace_id, plan, status, subscription_status,
            trial_start, trial_end, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'trialing', 'trialing', ?, ?, datetime('now'), datetime('now'))`
      )
      .bind(
        subId,
        ownerUserId,
        workspaceId,
        TRIAL_PLAN,
        now.toISOString(),
        trialEnd.toISOString()
      )
      .run();

    // Record trial_started event
    try {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO subscription_events
             (id, subscription_id, event_type, payload_json, created_at)
           VALUES (?, ?, 'trial_started', ?, datetime('now'))`
        )
        .bind(
          createId("sev"),
          subId,
          JSON.stringify({
            workspace_id: workspaceId,
            owner_user_id: ownerUserId,
            plan: TRIAL_PLAN,
            trial_start: now.toISOString(),
            trial_end: trialEnd.toISOString(),
            trial_duration_days: TRIAL_DURATION_DAYS,
          })
        )
        .run();
    } catch { /* event log failure is non-fatal */ }
  } catch { /* billing failure must not block workspace creation */ }
}

export function parseCheckoutPlan(plan) {
  const value = String(plan || "").trim().toLowerCase();
  if (!value || !Object.prototype.hasOwnProperty.call(BILLING_PLAN_METADATA, value)) {
    return { ok: false, plan: null };
  }
  return { ok: true, plan: value };
}

export function getPublicBillingPlans() {
  return ["free", "starter", "professional", "business", "enterprise"].map((plan) => ({
    key: plan,
    ...BILLING_PLAN_METADATA[plan],
    limits: getPlanLimits(plan),
    features: getPlanFeatures(plan),
  }));
}

export async function auditApiTokenSessionRouteDenied(env, user, request) {
  if (!user?.api_token_id) return;
  await createAuditEvent(env, {
    user_id:     user.id,
    event_type:  "api_token_denied_session_required",
    entity_type: "api_token",
    entity_id:   user.api_token_id,
    description: "API token denied for session-only route",
    metadata:    { method: request.method, path: new URL(request.url).pathname },
  });
}


