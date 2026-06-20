# Stripe Checkout Flow v1

**Sprint:** Stripe Checkout Session Creation  
**Date:** June 2026  
**Status:** Implemented — pending webhook sprint for plan activation

---

## Overview

`POST /api/billing/checkout` creates a Stripe Checkout Session and returns a redirect URL. The customer completes payment on Stripe's hosted checkout page. **Plan activation in D1 is not performed here** — it happens in the webhook sprint when Stripe fires `checkout.session.completed`.

---

## Environment Variables Required

| Variable | Required | Description |
|---|---|---|
| `STRIPE_SECRET_KEY` | Yes | Stripe secret key (`sk_live_...` or `sk_test_...`). Set as a Wrangler secret. |
| `STRIPE_PRICE_MAP` | Yes | JSON string mapping Stripe Price IDs to plan names. See format below. |

### STRIPE_PRICE_MAP format

`STRIPE_PRICE_MAP` is a JSON object where keys are Stripe Price IDs and values are plan names (`starter`, `professional`, `business`). Interval is resolved by matching `monthly` or `annual` as a substring of the Price ID — use Stripe's recommended price ID naming or add interval hints.

```json
{
  "price_1ABC_monthly_starter":      "starter",
  "price_1ABC_annual_starter":       "starter",
  "price_1DEF_monthly_professional": "professional",
  "price_1DEF_annual_professional":  "professional",
  "price_1GHI_monthly_business":     "business",
  "price_1GHI_annual_business":      "business"
}
```

Set via Wrangler:

```bash
echo '{"price_1ABC_monthly_starter":"starter","price_1ABC_annual_starter":"starter","price_1DEF_monthly_professional":"professional","price_1DEF_annual_professional":"professional","price_1GHI_monthly_business":"business","price_1GHI_annual_business":"business"}' \
  | wrangler secret put STRIPE_PRICE_MAP

wrangler secret put STRIPE_SECRET_KEY
# enter: sk_test_...
```

---

## Endpoint

### `POST /api/billing/checkout`

**Auth:** Required (Bearer token)

**Request body:**

```json
{
  "plan":        "professional",
  "interval":    "monthly",
  "success_url": "https://app.cybermeters.com/checkout/success?session_id={CHECKOUT_SESSION_ID}",
  "cancel_url":  "https://app.cybermeters.com/pricing"
}
```

| Field | Type | Required | Values |
|---|---|---|---|
| `plan` | string | Yes | `starter`, `professional`, `business` |
| `interval` | string | No | `monthly` (default), `annual` |
| `success_url` | string | Yes | URL Stripe redirects to on payment success. Use `{CHECKOUT_SESSION_ID}` placeholder to capture the session ID. |
| `cancel_url` | string | Yes | URL Stripe redirects to if the customer cancels. |

**Success response `200`:**

```json
{
  "checkout_url": "https://checkout.stripe.com/pay/cs_test_a1b2c3...",
  "session_id":   "cs_test_a1b2c3..."
}
```

Redirect the customer to `checkout_url` immediately after receiving this response.

---

## Stripe Checkout Session Parameters

The endpoint creates a Stripe Checkout Session with the following parameters:

| Stripe param | Value |
|---|---|
| `mode` | `subscription` |
| `line_items[0][price]` | Resolved from `STRIPE_PRICE_MAP` by plan + interval |
| `line_items[0][quantity]` | `1` |
| `customer` | `stripe_customer_id` from `subscriptions` table (if exists) |
| `customer_email` | `user.email` (if no Stripe customer exists yet) |
| `metadata[user_id]` | Authenticated user's ID |
| `metadata[plan]` | Requested plan (`starter`, `professional`, `business`) |
| `metadata[interval]` | `monthly` or `annual` |
| `subscription_data[metadata][user_id]` | Authenticated user's ID for webhook subscription correlation |
| `subscription_data[metadata][plan]` | Requested plan for webhook subscription correlation |
| `subscription_data[metadata][interval]` | Requested billing interval for webhook subscription correlation |
| `allow_promotion_codes` | `true` |
| `success_url` | From request body |
| `cancel_url` | From request body |

### Stripe Customer resolution

- If the `subscriptions` table has a `stripe_customer_id` for the authenticated user, it is passed as `customer`. Stripe will pre-fill the checkout form and associate the subscription with the existing customer.
- If no `stripe_customer_id` exists, `customer_email` is passed instead. Stripe auto-creates a Customer record on checkout completion. The webhook sprint writes this Customer ID back to `subscriptions`.

---

## Error Responses

| HTTP | `error` key | Cause |
|---|---|---|
| `400` | `invalid_plan` | Missing or unknown plan. Valid checkout plans are `starter`, `professional`, `business` |
| `400` | `plan_not_checkout_eligible` | Plan is `free` or `enterprise` — not available via self-service |
| `400` | `missing_success_url` | `success_url` not provided or not a string |
| `400` | `missing_cancel_url` | `cancel_url` not provided or not a string |
| `401` | `Unauthorized` | Missing or invalid Bearer token |
| `503` | `missing_stripe_config` | `STRIPE_SECRET_KEY` or `STRIPE_PRICE_MAP` not set in env |
| `503` | `missing_stripe_price` | No price in `STRIPE_PRICE_MAP` matches the requested plan + interval |
| `503` | `invalid_stripe_price_map` | `STRIPE_PRICE_MAP` is not valid JSON or not an object |
| `502` | `stripe_api_error` | Stripe returned a non-2xx response (invalid key, invalid price ID, etc.) |
| `502` | `stripe_request_failed` | Network error reaching Stripe |
| `500` | `Database error` | D1 query failed when looking up existing subscription |

### Error response shape

```json
{
  "error":             "stripe_api_error",
  "message":           "No such price: 'price_invalid'",
  "stripe_error_type": "invalid_request_error",
  "stripe_error_code": "resource_missing"
}
```

---

## Test curl Examples

Replace `TOKEN`, `WORKER_URL`, and price IDs with real values.

### Successful checkout — Professional monthly

```bash
curl -s -X POST https://WORKER_URL/api/billing/checkout \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan":        "professional",
    "interval":    "monthly",
    "success_url": "https://app.cybermeters.com/checkout/success?session_id={CHECKOUT_SESSION_ID}",
    "cancel_url":  "https://app.cybermeters.com/pricing"
  }' | jq .
```

Expected:

```json
{
  "checkout_url": "https://checkout.stripe.com/pay/cs_test_...",
  "session_id":   "cs_test_..."
}
```

---

### Successful checkout — Starter annual

```bash
curl -s -X POST https://WORKER_URL/api/billing/checkout \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan":        "starter",
    "interval":    "annual",
    "success_url": "https://app.cybermeters.com/checkout/success?session_id={CHECKOUT_SESSION_ID}",
    "cancel_url":  "https://app.cybermeters.com/pricing"
  }' | jq .
```

---

### Attempt Free plan — expect 400

```bash
curl -s -X POST https://WORKER_URL/api/billing/checkout \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan":        "free",
    "interval":    "monthly",
    "success_url": "https://app.cybermeters.com/checkout/success",
    "cancel_url":  "https://app.cybermeters.com/pricing"
  }' | jq .
```

Expected:

```json
{
  "error":   "plan_not_checkout_eligible",
  "plan":    "free",
  "message": "This plan is not available through self-service checkout."
}
```

---

### Missing STRIPE_SECRET_KEY — expect 503

```bash
# (with STRIPE_SECRET_KEY unset in wrangler.toml / secrets)
curl -s -X POST https://WORKER_URL/api/billing/checkout \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan":        "professional",
    "interval":    "monthly",
    "success_url": "https://app.cybermeters.com/checkout/success",
    "cancel_url":  "https://app.cybermeters.com/pricing"
  }' | jq .
```

Expected:

```json
{
  "error":   "missing_stripe_config",
  "missing": ["STRIPE_SECRET_KEY"],
  "message": "Stripe billing configuration is not ready for checkout."
}
```

---

### Missing success_url — expect 400

```bash
curl -s -X POST https://WORKER_URL/api/billing/checkout \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan":       "professional",
    "interval":   "monthly",
    "cancel_url": "https://app.cybermeters.com/pricing"
  }' | jq .
```

Expected:

```json
{
  "error":   "missing_success_url",
  "message": "success_url is required."
}
```

---

### Unauthenticated — expect 401

```bash
curl -s -X POST https://WORKER_URL/api/billing/checkout \
  -H "Content-Type: application/json" \
  -d '{
    "plan":        "professional",
    "interval":    "monthly",
    "success_url": "https://app.cybermeters.com/checkout/success",
    "cancel_url":  "https://app.cybermeters.com/pricing"
  }' | jq .
```

Expected:

```json
{ "error": "Unauthorized" }
```

---

## What Is NOT Done Here (By Design)

| Action | Sprint |
|---|---|
| Write plan to `subscriptions` or `subscription_accounts` | Webhook sprint |
| Create or update Stripe Customer record in D1 | Webhook sprint |
| Verify Stripe session after redirect | Webhook sprint (via `checkout.session.completed`) |
| Customer Portal (manage subscription, cancel) | Customer Portal sprint |
| Feature entitlement gating | Entitlement sprint (after webhook sprint) |

The checkout flow is intentionally stateless on the CyberMeters side. Until the webhook is implemented, a completed Stripe payment does **not** activate a plan in D1. Do not add D1 writes here.

---

## Implementation Notes

- The Stripe API call uses `fetch` directly — no Stripe SDK. This is required for Cloudflare Workers compatibility.
- Stripe's Checkout Sessions API requires `application/x-www-form-urlencoded` — not JSON. `URLSearchParams` is used to encode the body.
- Auth is `Bearer STRIPE_SECRET_KEY` (Authorization header). Basic auth with empty password is also valid but Bearer is simpler in Workers.
- The `subscriptions` table is queried read-only to check for an existing `stripe_customer_id`. Migration 028 added this column.
- Price ID resolution: `getStripePriceIdForPlan` matches entries in `STRIPE_PRICE_MAP` by plan name, then prefers an entry whose Price ID contains the interval string (`monthly` or `annual`). If no interval match, the first matching entry is used.

---

## Validation Results

```
node --input-type=module --check < workers/scan-api/src/index.js
# (no output — syntax valid)

node scripts/validate-regression-fixtures.js
# Regression pass rate: 15/15 (100%)
# accuracy validation passed

cd frontend && npm run build
# Known arm64 sandbox limitation (rollup native binary).
# No frontend changes were made in this sprint — build is unaffected.
```

---

## Suggested Commit

```
feat(billing): implement Stripe checkout session creation

POST /api/billing/checkout now creates a real Stripe Checkout Session
via fetch (no SDK). Returns checkout_url and session_id. Handles
existing stripe_customer_id from subscriptions table or falls back
to customer_email. Validates success_url, cancel_url, plan eligibility,
and Stripe config. Error codes: 400 invalid plan/missing URL, 503
missing config, 502 Stripe API failure.

D1 is not updated on checkout — plan activation is deferred to the
webhook sprint (checkout.session.completed).

Docs: docs/stripe-checkout-flow-v1.md
```

---

*CyberMeters Platform — Stripe Checkout Flow v1 — June 2026*
