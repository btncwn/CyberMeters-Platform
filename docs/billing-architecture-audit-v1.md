# Billing Architecture Audit v1

**Date:** June 2026
**Scope:** Stripe billing source-of-truth cleanup
**Decision:** Option A - `subscriptions` only

## Runtime Billing Flow

Current actual flow:

```text
User
-> Checkout
-> Stripe
-> Webhook
-> D1 subscriptions
-> getEffectivePlan()
-> PLAN_LIMITS / PLAN_FEATURES
-> application behavior
```

Stripe is the external billing source of truth. The CyberMeters runtime source
of truth is D1, specifically the `subscriptions` table. Runtime API requests do
not call Stripe for authorization or plan decisions.

## Table Ownership

### Authoritative Table: `subscriptions`

`subscriptions` is authoritative because:

- Remote D1 has `subscriptions` as the deployed billing table.
- Migration `028-stripe-billing.sql` extends `subscriptions` with Stripe fields.
- `getEffectivePlan(userId, env)` reads `subscriptions`.
- `POST /api/billing/checkout` reads `subscriptions` for existing
  `stripe_customer_id` reuse.
- `POST /api/billing/webhook` writes Stripe lifecycle state into
  `subscriptions`.
- Account and admin subscription endpoints now read `subscriptions`.

### Non-Authoritative Table: `subscription_accounts`

`subscription_accounts` was introduced by the Customer Portal foundation as a
manual subscription/account profile table. It is no longer the runtime billing
source of truth.

Runtime Worker code no longer reads `subscription_accounts`.

Historical docs and migration `016-customer-portal.sql` may still mention
`subscription_accounts`. Those references describe earlier architecture and
should not drive Stripe billing implementation.

## Dependency Map

### Runtime Functions / Routes Reading `subscriptions`

Evidence from `workers/scan-api/src/index.js`:

| Code path | Purpose |
| --- | --- |
| `getEffectivePlan(userId, env)` | Canonical runtime plan resolver. Reads `plan`, `subscription_status`, and `current_period_end`. |
| `findSubscriptionRowId(...)` | Looks up subscription rows by `owner_user_id`, `stripe_subscription_id`, or `stripe_customer_id`. |
| `POST /api/billing/checkout` | Reads existing `stripe_customer_id` so Checkout can reuse an existing Stripe Customer. |
| `GET /api/account/profile` | Returns account profile plus subscription summary from `subscriptions`. |
| `GET /api/account/subscription` | Returns subscription summary from `subscriptions`. |
| `GET /api/admin/subscriptions` | Admin subscription listing joins users to `subscriptions`. |

### Runtime Functions / Routes Writing `subscriptions`

Evidence from `workers/scan-api/src/index.js`:

| Code path | Purpose |
| --- | --- |
| `upsertStripeSubscriptionState(env, state)` | Inserts or updates Stripe subscription state. |
| `handleCheckoutSessionCompleted(env, session)` | Creates/updates the row using Checkout metadata and Stripe IDs. |
| `handleStripeSubscriptionUpsert(env, subscription)` | Handles `customer.subscription.created` and `customer.subscription.updated`. |
| `handleStripeSubscriptionDeleted(env, subscription)` | Sets `subscription_status = 'canceled'`. |
| `POST /api/billing/webhook` | Verifies Stripe events and calls the lifecycle handlers above. |

### Runtime Code Paths Reading `subscription_accounts`

None in `workers/scan-api/src/index.js`.

### Runtime Code Paths Writing `subscription_accounts`

None in `workers/scan-api/src/index.js`.

## Finding 1 - Table Source Of Truth

Resolved: `subscriptions` is required and authoritative.

`subscription_accounts` is not required for billing runtime behavior because no
active plan enforcement, account usage, checkout, webhook, or subscription API
path depends on it.

## Finding 2 - `syncSubscriptionAccountsPlan()`

Resolved: `syncSubscriptionAccountsPlan()` is not required.

No runtime consumer depends on `subscription_accounts` for effective plan
resolution. `getEffectivePlan()` reads `subscriptions`, and all plan/limit
checks call `getEffectivePlan()`.

Therefore, syncing Stripe events into `subscription_accounts` would create a
dual-write model with no runtime benefit and higher drift risk.

## Finding 3 - Webhook Retry Strategy

Stripe treats non-2xx webhook responses as failed deliveries and retries them.
It treats 2xx responses as acknowledged.

Correct behavior:

- Invalid signatures: return HTTP `400`.
- Unsupported but valid events: return HTTP `200`.
- Valid supported events with successful D1 synchronization: return HTTP `200`.
- Valid supported events where D1 synchronization fails: return HTTP `500`.

Justification:

Returning HTTP `200` after a D1 write failure would cause Stripe to stop
retrying, leaving CyberMeters with stale or missing subscription state. Returning
HTTP `500` preserves Stripe's retry behavior and is the safest default for a
Stripe -> D1 synchronization pipeline.

## Recommendation

### Chosen Option: Option A - `subscriptions` only

Technical justification:

- It matches the actual deployed remote table.
- It avoids dual writes.
- It keeps `getEffectivePlan()` as the single application resolver.
- It aligns Checkout, Webhook, Account, Admin, and enforcement paths.
- It prevents divergence between `subscriptions` and `subscription_accounts`.

Rejected options:

- **Option B - `subscription_accounts` only:** rejected because remote D1 and
  migration `028-stripe-billing.sql` use `subscriptions`.
- **Option C - both tables:** rejected because it creates avoidable dual-write
  drift and no current runtime consumer requires `subscription_accounts`.

## Operational Notes

- Do not add an entitlement table yet.
- Do not query Stripe at runtime for plan decisions.
- Stripe webhooks should update `subscriptions`.
- Application behavior should continue to flow through `getEffectivePlan()`.
- Feature gating should be added only after Checkout, Webhooks, and D1 sync are
  stable in production.
