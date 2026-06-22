# CyberMeters — Stripe Integration Design v1

**Sprint 14 — Phase 8**
**Date:** June 2026
**Status:** Design document only — no implementation in this sprint

---

## Overview

This document describes the planned Stripe integration for CyberMeters billing.
Sprint 14 establishes the subscription foundation (trial engine, subscription table,
feature gates). Stripe checkout and webhook handling are implemented in a future sprint.

The existing Worker already contains partial Stripe infrastructure from earlier sprints:
- `upsertStripeSubscriptionState()` — subscription row upsert on webhook events
- `handleCheckoutSessionCompleted()` — handles `checkout.session.completed`
- `handleStripeSubscriptionUpsert()` — handles `customer.subscription.updated`
- Stripe signature verification via `STRIPE_WEBHOOK_SECRET` env var
- `STRIPE_PRICE_MAP` env var for price ID → plan mapping

This document completes the design so the next sprint can implement without ambiguity.

---

## Environment Variables Required

| Variable             | Description                                             |
|----------------------|---------------------------------------------------------|
| `STRIPE_SECRET_KEY`  | Stripe secret key (`sk_live_...` or `sk_test_...`)      |
| `STRIPE_WEBHOOK_SECRET` | Webhook signing secret from Stripe dashboard         |
| `STRIPE_PRICE_MAP`   | JSON map of Stripe price IDs to CyberMeters plan names  |

### STRIPE_PRICE_MAP format

```json
{
  "price_abc123": "starter",
  "price_def456": "starter",
  "price_ghi789": "professional",
  "price_jkl012": "professional",
  "price_mno345": "business",
  "price_pqr678": "business"
}
```

Monthly and annual price IDs for each plan. Enterprise has no Stripe price (custom invoiced).

---

## Checkout Session Flow

### Trigger

User clicks "Upgrade" on `/billing` → `SubscriptionPage.jsx`.

### Step 1 — Frontend initiates checkout

```js
// SubscriptionPage.jsx (Sprint 15 implementation)
const res = await api.startCheckout(
  targetPlan,           // 'starter' | 'professional' | 'business'
  billingInterval,      // 'monthly' | 'annual'
  `${origin}/checkout/success`,
  `${origin}/checkout/cancel`,
)
window.location.href = res.checkout_url
```

### Step 2 — Worker creates Checkout Session

```
POST /api/billing/checkout
Auth: required (session token)
Body: { plan, interval, success_url, cancel_url }
```

Worker logic:
1. Validate plan is one of `starter | professional | business`
2. Look up price ID from `STRIPE_PRICE_MAP` for plan + interval combination
3. Create Stripe Checkout Session via `https://api.stripe.com/v1/checkout/sessions`
4. Pass `client_reference_id: user.id` and `metadata: { user_id, plan, interval }`
5. Return `{ checkout_url, session_id }`

```js
// Stripe API call (simplified)
const session = await stripe.checkout.sessions.create({
  mode: 'subscription',
  line_items: [{ price: priceId, quantity: 1 }],
  client_reference_id: user.id,
  metadata: { user_id: user.id, plan, interval },
  success_url: successUrl + '?session_id={CHECKOUT_SESSION_ID}',
  cancel_url: cancelUrl,
  allow_promotion_codes: true,
})
```

### Step 3 — Stripe redirects to /checkout/success

`CheckoutSuccessPage.jsx` shows a confirmation message.
It does NOT re-fetch plan state immediately — the webhook updates the DB asynchronously.
A brief polling mechanism (3 attempts, 2s interval) on `/api/account/subscription` confirms
the upgrade before showing the confirmation.

---

## Webhook Flow

### Endpoint

```
POST /api/stripe/webhook
No auth — validated by Stripe signature
```

### Signature verification

```js
const sig   = request.headers.get('stripe-signature')
const body  = await request.text()
const event = stripe.webhooks.constructEvent(body, sig, env.STRIPE_WEBHOOK_SECRET)
```

If signature is invalid → return `400 Bad Request` immediately.

### Events handled

| Stripe event                        | Handler function                     | Action                                       |
|-------------------------------------|--------------------------------------|----------------------------------------------|
| `checkout.session.completed`        | `handleCheckoutSessionCompleted()`   | Create/update subscription row; set active   |
| `customer.subscription.created`     | `handleStripeSubscriptionUpsert()`   | Sync subscription state                      |
| `customer.subscription.updated`     | `handleStripeSubscriptionUpsert()`   | Sync plan, status, period end                |
| `customer.subscription.deleted`     | `handleStripeSubscriptionDeleted()`  | Mark canceled, set cancel date               |
| `invoice.payment_succeeded`         | `handleInvoicePaymentSucceeded()`    | Extend current_period_end, clear past_due    |
| `invoice.payment_failed`            | `handleInvoicePaymentFailed()`       | Set payment_failed_at, increment retry count |

### Idempotency

All handlers call `upsertStripeSubscriptionState()` which uses `UPDATE … WHERE` + `INSERT OR IGNORE`.
Re-delivering the same webhook is safe.

---

## Subscription Sync

The `subscriptions` table is the source of truth for plan state at runtime.
Stripe is the source of truth for billing events. The sync direction is:

```
Stripe webhook → Worker handler → subscriptions table → getUserPlan() → API responses
```

### Fields synced from Stripe

| subscriptions column    | Stripe source                                       |
|-------------------------|-----------------------------------------------------|
| `plan`                  | Derived from `stripe_price_id` via `STRIPE_PRICE_MAP` + webhook metadata |
| `subscription_status`   | `subscription.status` (active, trialing, past_due, canceled) |
| `current_period_end`    | `subscription.current_period_end` (Unix timestamp → ISO-8601) |
| `current_period_start`  | `subscription.current_period_start`                 |
| `stripe_customer_id`    | `subscription.customer`                             |
| `stripe_subscription_id`| `subscription.id`                                   |
| `stripe_price_id`       | `subscription.items.data[0].price.id`               |
| `billing_interval`      | Derived from `price.recurring.interval`             |
| `cancel_at_period_end`  | `subscription.cancel_at_period_end`                 |
| `cancelled_at`          | Set when subscription.deleted event received        |
| `payment_failed_at`     | Set on invoice.payment_failed                       |
| `payment_retry_count`   | Incremented on invoice.payment_failed               |

### Fields NOT overwritten by Stripe

| subscriptions column   | Reason                                                    |
|------------------------|-----------------------------------------------------------|
| `trial_start`          | Set by CyberMeters on workspace creation; Stripe does not manage CyberMeters trials |
| `trial_end`            | Same as above                                             |
| `owner_user_id`        | Set at checkout via client_reference_id / metadata        |
| `workspace_id`         | Set at workspace creation                                 |

---

## Cancellation Flow

### Self-serve cancellation (Sprint 15+)

```
User clicks "Cancel subscription" → /billing
    ↓
POST /api/billing/cancel
    ↓
Worker calls stripe.subscriptions.update({ cancel_at_period_end: true })
    ↓
customer.subscription.updated webhook fires
    ↓
upsertStripeSubscriptionState() sets cancel_at_period_end = 1
    ↓
/api/workspaces/:id/subscription returns cancel_at_period_end: true
    ↓
SubscriptionPage shows "Cancels on [date]" banner
    ↓
On period end: customer.subscription.deleted fires
    ↓
handleStripeSubscriptionDeleted() sets status = 'canceled', cancelled_at = now
    ↓
getUserPlan() returns 'free'
```

### After cancellation

- Workspace reverts to Free plan limits
- Historical data, reports, and scans are retained (Rule 5: Historical Data Is Sacred)
- Workspace is NOT deleted
- User can re-subscribe at any time

---

## Trial → Paid Conversion

CyberMeters trials are managed internally (trial_start, trial_end in subscriptions table).
They are independent of Stripe trials. When a trialing user upgrades:

1. They complete Stripe checkout (full plan price, no Stripe trial)
2. `checkout.session.completed` fires
3. `handleCheckoutSessionCompleted()` updates subscription row:
   - `plan` → paid plan
   - `subscription_status` → 'active'
   - `current_period_end` → Stripe billing period end
4. `isTrialActive()` returns false (subscription_status is no longer 'trialing')
5. `isSubscriptionActive()` returns true
6. Feature gates immediately reflect paid plan

The `trial_start` and `trial_end` columns are preserved for audit purposes.

---

## Plan Upgrade / Downgrade

Handled via Stripe's subscription update API (proration).

```js
// Upgrade (immediate proration)
await stripe.subscriptions.update(subscriptionId, {
  items: [{ id: currentItemId, price: newPriceId }],
  proration_behavior: 'create_prorations',
})

// Downgrade (effective at period end)
await stripe.subscriptions.update(subscriptionId, {
  items: [{ id: currentItemId, price: newPriceId }],
  proration_behavior: 'none',
  billing_cycle_anchor: 'unchanged',
})
```

The `customer.subscription.updated` webhook fires and `handleStripeSubscriptionUpsert()`
syncs the new plan to the subscriptions table.

---

## Security Considerations

1. **Webhook signature always verified.** Requests without a valid `stripe-signature` header → 400.
2. **No plan state stored in frontend.** All plan checks go through the Worker.
3. **Checkout metadata user_id** is verified against the authenticated session on webhook receipt.
4. **Price IDs are server-side only.** The frontend sends plan names; the Worker resolves price IDs from `STRIPE_PRICE_MAP`.
5. **No Stripe keys in frontend.** The publishable key is not needed (hosted checkout).

---

## Error Handling

| Scenario                              | Response                                             |
|---------------------------------------|------------------------------------------------------|
| STRIPE_SECRET_KEY missing             | `503 Service Unavailable` with `billing_not_configured` |
| Checkout: invalid plan requested      | `400 Bad Request`                                    |
| Checkout: Stripe API error            | `502 Bad Gateway` with Stripe error message          |
| Webhook: invalid signature            | `400 Bad Request` (do not log payload)               |
| Webhook: unknown event type           | `200 OK` (acknowledge; ignore)                       |
| Webhook: DB error on upsert           | `500 Internal Server Error` (Stripe retries)         |

---

## Testing

### Test environment

Use Stripe test mode keys (`sk_test_...`, `whsec_...`).
Use Stripe CLI for local webhook forwarding:

```bash
stripe listen --forward-to localhost:8787/api/stripe/webhook
```

### Test cards

| Card number          | Scenario                      |
|----------------------|-------------------------------|
| 4242 4242 4242 4242  | Successful payment            |
| 4000 0000 0000 0341  | Payment failure (card declined)|
| 4000 0025 0000 3155  | 3D Secure authentication      |

### Key scenarios to test

1. Free → Starter upgrade (checkout flow)
2. Trial → Professional upgrade (replaces trial status with active)
3. Invoice payment failure → past_due status
4. Subscription cancellation → cancel_at_period_end
5. Subscription period end → status = canceled → plan = free
6. Duplicate webhook delivery (idempotency check)

---

## What Is NOT in Scope (Sprint 14)

- Stripe checkout implementation
- Invoice display in UI
- Refund handling
- VAT / tax handling (Stripe Tax)
- Usage-based billing
- Per-seat pricing
- Coupon / promotion code UI

---

## Version History

| Version | Date      | Notes                                              |
|---------|-----------|----------------------------------------------------|
| v1      | June 2026 | Initial design — checkout, webhooks, sync, cancellation |
