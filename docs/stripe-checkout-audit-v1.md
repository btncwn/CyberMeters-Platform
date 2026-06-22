# CyberMeters — Stripe Checkout Audit v1

**Sprint 14B — Phase 1**
**Date:** June 2026
**Status:** Audit complete — implementation follows

---

## What Already Exists

### Stripe Helper Functions (Worker, lines ~16930–17320)

All core Stripe primitives are already implemented and production-ready:

| Function | Purpose | Status |
|----------|---------|--------|
| `parseStripePriceMap(env)` | Reads `STRIPE_PRICE_MAP` JSON env var | ✅ Exists |
| `validateStripeBillingConfig(env)` | Checks `STRIPE_SECRET_KEY` + `STRIPE_PRICE_MAP` | ✅ Exists |
| `validateStripeSecretConfig(env)` | Checks `STRIPE_SECRET_KEY` only | ✅ Exists |
| `validateStripeWebhookConfig(env)` | Checks `STRIPE_WEBHOOK_SECRET` | ✅ Exists |
| `getStripePriceIdForPlan(env, plan, interval)` | Looks up price ID by `{plan}_{interval}` key | ✅ Exists |
| `parseStripeSignatureHeader(header)` | Parses `Stripe-Signature` header format | ✅ Exists |
| `verifyStripeWebhookSignature(rawBody, sigHeader, secret)` | Full HMAC-SHA256 with timing-safe compare + 5min tolerance | ✅ Exists |
| `stripeUnixToIso(value)` | Converts Unix timestamps to ISO-8601 | ✅ Exists |
| `getStripeObjectId(value)` | Extracts Stripe ID from string or object | ✅ Exists |
| `getStripeSubscriptionPrice(subscription)` | Gets price from subscription items array | ✅ Exists |
| `getPlanFromStripePriceId(env, priceId, fallback)` | Reverse lookup: price → plan | ✅ Exists |
| `getBillingIntervalFromStripeSubscription(sub)` | Extracts monthly/annual from price data | ✅ Exists |
| `normalizeStripeSubscriptionStatus(status)` | Normalises Stripe status string | ✅ Exists |
| `findSubscriptionRowId(env, { ownerUserId, stripeSubscriptionId, stripeCustomerId })` | Finds subscription row by any of 3 keys | ✅ Exists |
| `upsertStripeSubscriptionState(env, state)` | UPDATE or INSERT subscription row | ✅ Exists — missing `current_period_start` |
| `handleCheckoutSessionCompleted(env, session)` | Handles `checkout.session.completed` | ✅ Exists |
| `handleStripeSubscriptionUpsert(env, sub)` | Handles subscription created/updated | ✅ Exists — missing `current_period_start` |
| `handleStripeSubscriptionDeleted(env, sub)` | Handles subscription.deleted → canceled | ✅ Exists |
| `handleStripeInvoicePaymentFailed(env, invoice)` | Handles payment_failed → past_due | ✅ Exists |

### Existing API Endpoints

| Endpoint | Auth | Status |
|----------|------|--------|
| `POST /api/billing/checkout` | User session, any authenticated user | ✅ Full implementation |
| `POST /api/billing/portal` | User session, requires stripe_customer_id | ✅ Full implementation |
| `POST /api/billing/webhook` | Stripe signature (no user auth) | ✅ Full implementation |
| `GET /api/billing/plans` | Any (public metadata) | ✅ Full implementation |
| `GET /api/billing/subscription` | User session | ✅ Full implementation |
| `GET /api/workspaces/:id/subscription` | Workspace member (Sprint 14A) | ✅ Full implementation |

### Webhook Event Coverage (existing `/api/billing/webhook`)

| Event | Handler | Status |
|-------|---------|--------|
| `checkout.session.completed` | `handleCheckoutSessionCompleted()` | ✅ Handled |
| `customer.subscription.created` | `handleStripeSubscriptionUpsert()` | ✅ Handled |
| `customer.subscription.updated` | `handleStripeSubscriptionUpsert()` | ✅ Handled |
| `customer.subscription.deleted` | `handleStripeSubscriptionDeleted()` | ✅ Handled |
| `invoice.payment_failed` | `handleStripeInvoicePaymentFailed()` | ✅ Handled |
| `invoice.payment_succeeded` | — | ❌ Missing |

### Environment Variables (existing references in code)

| Variable | Used by | Format | Status |
|----------|---------|--------|--------|
| `STRIPE_SECRET_KEY` | Checkout, portal, all Stripe API calls | `sk_live_...` or `sk_test_...` | Referenced, must be set as secret |
| `STRIPE_WEBHOOK_SECRET` | Webhook signature verification | `whsec_...` | Referenced, must be set as secret |
| `STRIPE_PRICE_MAP` | `getStripePriceIdForPlan()` | JSON string `{"starter_monthly":"price_xxx",...}` | Referenced |

---

## What Is Missing (Sprint 14B deliverables)

### 1. Workspace-scoped checkout endpoint

**Missing:** `POST /api/workspaces/:id/billing/checkout`

The existing `POST /api/billing/checkout` is account-scoped. The sprint requires a workspace-scoped version that:
- Enforces workspace **owner** role (not just any authenticated user)
- Passes `workspace_id` in checkout session metadata
- Derives the billing user from `getWorkspaceBillingUserId()`
- Hardcodes success/cancel URLs to the billing page (no client-provided redirect)
- Accepts `{ plan }` only (no `interval` field initially — defaults monthly)

### 2. Workspace-scoped portal endpoint

**Missing:** `POST /api/workspaces/:id/billing/portal`

Same pattern — workspace owner only, derives `stripe_customer_id` from the workspace billing owner.

### 3. Canonical webhook path

**Missing:** `POST /api/stripe/webhook`

The existing webhook lives at `/api/billing/webhook`. The sprint wants `/api/stripe/webhook` as the canonical Stripe-configured endpoint. Both can coexist; the new path delegates to the same handler logic.

### 4. `invoice.payment_succeeded` handler

**Missing:** No handler for this event. When a payment succeeds (renewal), the subscription status should be confirmed as `active` and `current_period_end` extended. Currently Stripe fires `customer.subscription.updated` on renewal which covers this, but the explicit `invoice.payment_succeeded` event allows clearing `payment_failed_at` and resetting `payment_retry_count`.

### 5. `current_period_start` sync

**Missing:** `upsertStripeSubscriptionState()` does not write `current_period_start`. The column was added in migration 050. The webhook payload includes `current_period_start` on subscription objects. This needs to be added to the upsert.

### 6. `subscription_events` table writes from webhook

**Missing:** The `subscription_events` table (migration 050) is only written by `createWorkspaceTrialSubscription()`. The webhook handlers create audit events via `createAuditEvent()` (workspace audit log) but do not write to `subscription_events`. Sprint 14B should add `subscription_events` writes for each webhook event type for the dedicated billing event log.

### 7. Individual price ID env vars

**Gap:** `STRIPE_PRICE_MAP` is a JSON string which is hard to manage per-environment. The sprint specifies individual vars (`STRIPE_STARTER_MONTHLY_PRICE_ID` etc.). Sprint 14B adds a `buildStripePriceMapFromIndividualVars(env)` helper that composes the JSON map from individual vars, so both formats work.

### 8. Frontend billing flow

**Missing:** `SubscriptionPage.jsx` currently has stub upgrade buttons (`window.location.href = /pricing?plan=...`) and no Manage Billing button. Sprint 14B wires these to the real checkout and portal APIs.

---

## Price ID Key Format

The existing `STRIPE_PRICE_MAP` uses composite keys:
```json
{
  "starter_monthly": "price_xxx",
  "starter_annual":  "price_yyy",
  "professional_monthly": "price_zzz",
  "professional_annual":  "price_aaa",
  "business_monthly": "price_bbb",
  "business_annual":  "price_ccc"
}
```

Individual env var equivalents (Sprint 14B addition):
```
STRIPE_STARTER_MONTHLY_PRICE_ID   → starter_monthly
STRIPE_STARTER_ANNUAL_PRICE_ID    → starter_annual
STRIPE_PRO_MONTHLY_PRICE_ID       → professional_monthly
STRIPE_PRO_ANNUAL_PRICE_ID        → professional_annual
STRIPE_BUSINESS_MONTHLY_PRICE_ID  → business_monthly
STRIPE_BUSINESS_ANNUAL_PRICE_ID   → business_annual
```

---

## Subscription Table State

Current columns relevant to Stripe sync:

| Column | Synced from Stripe | Notes |
|--------|-------------------|-------|
| `plan` | Derived from price ID + STRIPE_PRICE_MAP | ✅ Synced |
| `subscription_status` | `subscription.status` | ✅ Synced |
| `stripe_customer_id` | `subscription.customer` | ✅ Synced |
| `stripe_subscription_id` | `subscription.id` | ✅ Synced |
| `stripe_price_id` | `subscription.items.data[0].price.id` | ✅ Synced |
| `billing_interval` | Derived from `price.recurring.interval` | ✅ Synced |
| `current_period_end` | `subscription.current_period_end` (Unix → ISO) | ✅ Synced |
| `current_period_start` | `subscription.current_period_start` (Unix → ISO) | ❌ Not synced — Sprint 14B fix |
| `cancel_at_period_end` | `subscription.cancel_at_period_end` | ❌ Not synced — Sprint 14B fix |
| `payment_failed_at` | Set on `invoice.payment_failed` | ✅ Synced |
| `payment_retry_count` | Incremented on `invoice.payment_failed` | ✅ Synced |
| `trial_start` | Set by trial engine on workspace creation | Not a Stripe field |
| `trial_end` | Set by trial engine on workspace creation | Not a Stripe field |

---

## BillingPage / SubscriptionPage State

| Page | Route | API used | Status |
|------|-------|---------|--------|
| `BillingPage.jsx` | `/billing` (no longer routed) | `getSubscription()`, `getSubscriptionLimits()` | Exists but deactivated — route now points to SubscriptionPage |
| `SubscriptionPage.jsx` | `/billing` | `getWorkspaceSubscription(wsId)` | Active — upgrade buttons are stubs |

`SubscriptionPage.jsx` currently:
- Calls `api.getWorkspaceSubscription(workspaceId)` ✅
- Shows trial countdown ✅
- Shows plan limits and feature checklist ✅
- Upgrade buttons: `window.location.href = /pricing?plan=xxx` ← **stub, Sprint 14B replaces**
- No "Manage Billing" button ← **missing, Sprint 14B adds**
- No success/canceled URL param handling ← **missing, Sprint 14B adds**

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Initial audit — Sprint 14B pre-implementation |
