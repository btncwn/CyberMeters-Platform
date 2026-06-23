# SUBSCRIPTION_LIFECYCLE_AUDIT.md

Sprint 10D — Phase 5
Date: 2026-06-23
Auditor: Code inspection (no assumptions)

---

## Scope

Files inspected:
- `workers/scan-api/src/index.js`:
  - `getUserPlan()` / `getEffectivePlan()`
  - `createWorkspaceTrialSubscription()`
  - `handleStripeSubscriptionCreated/Updated/Deleted()`
  - `handleStripeInvoicePaymentFailed/Succeeded()`
  - `POST /api/workspaces/:id/billing/checkout`
  - `POST /api/workspaces/:id/billing/portal`
  - Stripe webhook handler

---

## Lifecycle Summary

```
Workspace created:
  createWorkspaceTrialSubscription()
    → INSERT subscriptions (plan='professional', subscription_status='trialing', trial_end=+14 days)

Trial expires:
  getUserPlan() sees trial_end < now() → returns 'free'
  (no Stripe event — trial is local-only, not a Stripe trial)

User upgrades:
  POST /api/workspaces/:id/billing/checkout → Stripe Checkout Session
  → User completes payment on Stripe
  → Stripe fires checkout.session.completed → upsertSubscription()
  → Stripe fires customer.subscription.created → updates status='active', plan, period_end

Payment fails:
  Stripe fires invoice.payment_failed
  → handleStripeInvoicePaymentFailed() sets subscription_status='past_due'
  → getUserPlan() sees status='past_due' → returns 'free' immediately

Payment recovered:
  Stripe fires invoice.payment_succeeded
  → handleStripeInvoicePaymentSucceeded() sets status back to 'active' IF was 'past_due'

Subscription cancelled:
  Stripe fires customer.subscription.deleted
  → handleStripeSubscriptionDeleted() sets status='canceled'
  → getUserPlan() returns 'free' immediately
```

---

## Findings

### ISSUE-25 — CRITICAL — Trial is local-only, not synced with Stripe — checkout metadata collision risk

**File:** `workers/scan-api/src/index.js`
**Function:** `createWorkspaceTrialSubscription()`
**Root cause:** The 14-day trial is created as a D1 subscription row with no Stripe customer or subscription ID:

```js
// createWorkspaceTrialSubscription — no stripe IDs
await env.cybermeters_db.prepare(
  `INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status,
    trial_start, trial_end, ...)`
).bind(subscriptionId, ownerUserId, workspaceId, TRIAL_PLAN, "trialing", "trialing", ...)
```

When the user later upgrades via Stripe Checkout, `handleStripeCheckoutSessionCompleted()` calls `upsertSubscription()`. This function first tries to find an existing row by `stripe_subscription_id`. The trial row has no `stripe_subscription_id`, so the upsert may create a second row instead of updating the trial row. The user ends up with two subscription rows: the orphaned trial row (status=trialing) and a new active row.

`getUserPlan()` resolves via `ORDER BY COALESCE(updated_at, created_at) DESC LIMIT 1` — this should return the newer active row correctly, but the orphaned trialing row remains indefinitely and could cause confusion in billing audit logs.

**Remediation:** In `upsertSubscription()`, before inserting a new row, also check `WHERE workspace_id = ? AND stripe_subscription_id IS NULL AND subscription_status = 'trialing'` and UPDATE that row rather than INSERT. This converts the trial row into the active subscription row cleanly.

---

### ISSUE-26 — HIGH — Past-due users lose access immediately on first payment failure

**File:** `workers/scan-api/src/index.js`
**Function:** `getUserPlan()` (line ~16897)
**Root cause:** `getUserPlan()` only returns a non-free plan if `subscription_status IN ('active', 'trialing')`. On the first `invoice.payment_failed`, the status is set to `past_due` and `getUserPlan()` immediately returns `free`. Stripe's default retry schedule retries payment 3–4 times over 7 days before cancelling.

```js
// getUserPlan()
const status = String(sub.subscription_status || "").trim().toLowerCase();
if (status && !["active", "trialing"].includes(status)) return "free";  // past_due → free immediately
```

**Impact for beta:** A customer with an expired card gets locked out of their paid features on the first declined charge, before Stripe has had a chance to retry. This will generate support tickets and churn.

**Remediation:** Add `"past_due"` to the allowed status list with a grace period. Either:
1. Allow `past_due` access for 7 days from `payment_failed_at` (store in D1, already done), OR
2. Check `payment_failed_at` and allow access while `payment_failed_at > datetime('now', '-7 days')`.

```js
if (status === "past_due") {
  const failedAt = sub.payment_failed_at ? new Date(sub.payment_failed_at) : null;
  if (failedAt && (Date.now() - failedAt.getTime()) < 7 * 24 * 60 * 60 * 1000) {
    return normalizePlan(sub.plan);  // 7-day grace period
  }
  return "free";
}
```

---

### ISSUE-27 — HIGH — No subscription cancellation notification to user

**File:** `workers/scan-api/src/index.js`
**Function:** `handleStripeSubscriptionDeleted()` (line ~17537)
**Root cause:** When Stripe fires `customer.subscription.deleted`, the Worker sets `subscription_status='canceled'` and updates D1. No email is sent to the user, no in-app notification is created, no alert is generated. The next time the user logs in, they will silently be on the free plan with no explanation.

```js
async function handleStripeSubscriptionDeleted(env, subscription) {
  // Sets status to 'canceled', updates period_end — no notification
  await env.cybermeters_db.prepare(
    `UPDATE subscriptions SET subscription_status = 'canceled', ...`
  ).bind(...).run();
  return rowId;
}
```

**Impact for beta:** Customers who are downgraded after cancellation will be confused. Features will stop working with no warning.

**Remediation:** After setting status to `'canceled'`, call `sendCustomerEmail()` to the workspace owner's email notifying them that their subscription has ended and linking to `/billing` to resubscribe.

---

### ISSUE-28 — HIGH — Subscription lookup is per owner_user_id — breaks on workspace ownership transfer

**File:** `workers/scan-api/src/index.js`
**Function:** `getUserPlan()` (line ~16897), `getWorkspaceSubscription()` (line ~17014)
**Root cause:** `getUserPlan(userId, env)` queries `subscriptions WHERE owner_user_id = ?`. `getWorkspaceSubscription(workspaceId, env)` resolves via `workspace.owner_user_id → subscriptions.owner_user_id`.

There is no workspace ownership transfer mechanism (correct — `PERMISSION_MAP["workspace:transfer"]` exists but no endpoint implements it). However, if ownership is ever transferred via direct D1 update or a future transfer endpoint, the subscription lookup chain will break: the new owner has no subscription row, and the old owner's subscription will be orphaned.

**Impact for beta:** Low immediate risk. High future risk if ownership transfer is added without updating subscription resolution.

**Remediation:** Add `workspace_id` as a direct foreign key on subscriptions for primary lookup. Fall back to `owner_user_id` only for backwards compatibility. Already partially in place (`workspace_id` column exists on subscriptions table).

---

### ISSUE-29 — MEDIUM — checkout.session.completed does not verify workspace_id matches authenticated user

**File:** `workers/scan-api/src/index.js`
**Route:** Stripe webhook handler (line ~18700+)
**Root cause:** The `checkout.session.completed` event resolves `workspace_id` from the Stripe session's `metadata.workspace_id`. This metadata is set by the checkout endpoint from the authenticated request. If a webhook is replayed or metadata is tampered, the workspace_id in the webhook may not match any real workspace or may reference another user's workspace.

The `upsertSubscription()` function does not verify that the `owner_user_id` in the metadata matches the workspace's actual `owner_user_id`.

**Remediation:** In `handleStripeCheckoutSessionCompleted()`, after resolving `workspace_id` from metadata, validate: `SELECT owner_user_id FROM workspaces WHERE id = ? AND owner_user_id = ?` using both the metadata workspace_id and metadata user_id. Reject if they don't match.

---

### ISSUE-30 — LOW — Stripe webhook endpoint has no idempotency guard for duplicate events

**File:** `workers/scan-api/src/index.js`
**Webhook handler:** all event types
**Root cause:** Stripe guarantees at-least-once delivery and will retry webhooks on 5xx responses. The Worker returns 500 on D1 errors (correct — triggers retry). However, there is no deduplication by `stripe_event_id`. A temporarily unavailable D1 could cause the same event to be processed twice, resulting in duplicate subscription_events rows and potentially incorrect payment_retry_count.

**Remediation:** Store processed Stripe event IDs in a `stripe_events_processed` table (id, stripe_event_id, processed_at) and check before processing. Alternatively, use D1 transactions to make each handler idempotent (upsert rather than insert for all writes).

---

## Verified Correct ✓

- Trial auto-created on workspace creation (14-day Professional) ✓
- `getUserPlan()` correctly falls back to `free` on missing/expired subscription ✓
- `invoice.payment_succeeded` restores `active` from `past_due` ✓
- Stripe signature verification is implemented in the webhook handler ✓
- Billing portal endpoint correctly resolves `stripe_customer_id` before calling Stripe ✓

---

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 25 | CRITICAL | Trial row and upgrade row may create duplicate subscriptions — resolution by recency is fragile |
| 26 | HIGH | Past-due users lose access immediately — no grace period |
| 27 | HIGH | No notification to user when subscription is cancelled |
| 28 | HIGH | Subscription lookup tied to owner_user_id — breaks on ownership transfer |
| 29 | MEDIUM | Webhook workspace_id not validated against workspace owner |
| 30 | LOW | Stripe webhook has no idempotency guard for duplicate events |
