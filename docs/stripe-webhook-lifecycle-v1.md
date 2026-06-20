# Stripe Webhook Lifecycle v1

**Sprint:** Stripe Webhook Lifecycle Synchronization
**Status:** Implemented

## Overview

`POST /api/billing/webhook` receives Stripe lifecycle events, verifies the
request signature with HMAC-SHA256, and synchronizes subscription state into
D1.

Stripe is the billing source of truth. CyberMeters runtime authorization does
not call Stripe. Runtime plan decisions read from D1 through
`getEffectivePlan()`.

```text
Stripe
-> POST /api/billing/webhook
-> subscriptions
-> getEffectivePlan()
-> PLAN_LIMITS / PLAN_FEATURES
-> application behavior
```

## Endpoint

Configure Stripe to send events to:

```text
POST https://<worker-host>/api/billing/webhook
```

The Worker reads the raw request body and verifies the `Stripe-Signature`
header with `STRIPE_WEBHOOK_SECRET` before parsing JSON.

Invalid signatures return HTTP `400`.

Webhook handler persistence failures return HTTP `500` so Stripe can retry
delivery according to Stripe's webhook retry policy.

## Required Environment

Set these Worker secrets/variables before enabling live webhooks:

```bash
wrangler secret put STRIPE_WEBHOOK_SECRET
wrangler secret put STRIPE_SECRET_KEY
wrangler secret put STRIPE_PRICE_MAP
```

`STRIPE_PRICE_MAP` uses composite keys:

```json
{
  "starter_monthly": "price_xxx",
  "starter_annual": "price_yyy",
  "professional_monthly": "price_xxx",
  "professional_annual": "price_yyy",
  "business_monthly": "price_xxx",
  "business_annual": "price_yyy"
}
```

Checkout resolves `plan + interval` to a Stripe Price ID. Webhooks reverse-map
the received Stripe Price ID back to a CyberMeters plan.

## Supported Events

Only these events are handled:

| Stripe event | Behavior |
| --- | --- |
| `checkout.session.completed` | Uses Checkout metadata (`user_id`, `plan`, `interval`) to create or update the user's `subscriptions` row with Stripe customer/subscription IDs. |
| `customer.subscription.created` | Inserts or updates subscription state from the Stripe subscription object. |
| `customer.subscription.updated` | Updates plan, billing interval, status, current period end, and Stripe identifiers. |
| `customer.subscription.deleted` | Sets `subscription_status = 'canceled'`. Rows are not deleted. |

All other events are acknowledged and ignored.

## D1 Synchronization

The webhook updates only the existing `subscriptions` table:

- `stripe_customer_id`
- `stripe_subscription_id`
- `stripe_price_id`
- `plan`
- `billing_interval`
- `subscription_status`
- `current_period_end`
- `updated_at`

`subscription_accounts` is legacy customer portal/account metadata. It is not
the runtime billing source of truth.

## Stripe Dashboard Setup

1. Open Stripe Dashboard > Developers > Webhooks.
2. Add endpoint: `https://<worker-host>/api/billing/webhook`.
3. Select only:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
4. Copy the signing secret and store it as `STRIPE_WEBHOOK_SECRET`.
5. Ensure Checkout sends metadata:
   - `user_id`
   - `plan`
   - `interval`

## Stripe CLI Testing

Forward local Stripe events to the Worker URL:

```bash
stripe listen --forward-to https://<worker-host>/api/billing/webhook
```

Trigger a subscription lifecycle event:

```bash
stripe trigger checkout.session.completed
stripe trigger customer.subscription.created
stripe trigger customer.subscription.updated
stripe trigger customer.subscription.deleted
```

For realistic tests, complete a test-mode Checkout Session created by:

```bash
curl -s -X POST https://<worker-host>/api/billing/checkout \
  -H "Authorization: Bearer <session-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "starter",
    "interval": "monthly",
    "success_url": "https://app.cybermeters.com/billing/success",
    "cancel_url": "https://app.cybermeters.com/billing/cancel"
  }'
```

## Explicit Non-Goals

- No Stripe SDK.
- No Customer Portal.
- No trial lifecycle.
- No feature enforcement.
- No frontend billing UI.
- No runtime Stripe API lookups for plan decisions.
