# CyberMeters — Stripe Environment Setup v1

> **Status: Current for the live (legacy) prices — not the adopted pricing
> (16 July 2026).** This runbook is **accurate**: the £29 / £276 · £149 / £1,428 ·
> £399 / £3,828 products it configures are the prices Stripe carries today, and the
> `STRIPE_*_PRICE_ID` variable names it sets match the implemented resolver in
> `workers/scan-api/src/engines/stripe.js`. Keep using it for the current setup.
>
> It is **not** the adopted pricing. The canonical policy `docs/PRICING-POLICY.md`
> (DECIDED 2026-07-09) adopts different tiers, to be cut over **once**, in lockstep
> (Stripe prices + `BILLING_PLAN_METADATA` + pricing cards together), at public-beta
> launch and on founder approval. That cutover — including the test→live mode
> change — is specified in `docs/PRICING-POLICY.md` §6, not here. Do not change
> live prices from this document.

**Sprint 14B — Phase 2**
**Date:** June 2026

---

## Overview

CyberMeters uses Stripe for subscription billing. This document covers the exact steps
to configure Stripe secrets and price IDs for both test and production environments.

All Stripe secrets are set via `wrangler secret` — they are never committed to the
repository or added to `wrangler.toml`.

---

## Prerequisites

1. A Stripe account at https://dashboard.stripe.com
2. `wrangler` CLI installed and authenticated
3. Products and prices created in Stripe Dashboard (see below)

---

## Step 1 — Create Stripe Products and Prices

In the Stripe Dashboard → Products, create the following:

### Products

| Product name | Stripe metadata |
|---|---|
| CyberMeters Starter | `plan: starter` |
| CyberMeters Professional | `plan: professional` |
| CyberMeters Business | `plan: business` |

### Prices (per product)

For each product, create two recurring prices:

| Price | Interval | Amount (GBP) |
|---|---|---|
| Starter Monthly | Monthly | £29.00 |
| Starter Annual | Yearly | £276.00 |
| Professional Monthly | Monthly | £149.00 |
| Professional Annual | Yearly | £1,428.00 |
| Business Monthly | Monthly | £399.00 |
| Business Annual | Yearly | £3,828.00 |

Note each price's **Price ID** (format: `price_xxxxxxxxxxxxxxxxxx`).

---

## Step 2 — Set Stripe Secrets

Run these commands from the `workers/scan-api/` directory.

### Test mode (use during development)

```bash
cd workers/scan-api

# Stripe test secret key (starts with sk_test_)
wrangler secret put STRIPE_SECRET_KEY
# Paste: sk_test_...

# Stripe webhook signing secret (starts with whsec_)
wrangler secret put STRIPE_WEBHOOK_SECRET
# Paste: whsec_...
```

### Production mode

```bash
# Stripe live secret key (starts with sk_live_)
wrangler secret put STRIPE_SECRET_KEY
# Paste: sk_live_...

# Stripe live webhook signing secret
wrangler secret put STRIPE_WEBHOOK_SECRET
# Paste: whsec_...
```

---

## Step 3 — Configure Price IDs

CyberMeters supports two formats. Use whichever is more convenient for your workflow.

---

### Option A — Individual env vars (recommended, easiest to manage)

Set each price as a separate secret:

```bash
# Starter
wrangler secret put STRIPE_STARTER_MONTHLY_PRICE_ID
# Paste: price_xxx

wrangler secret put STRIPE_STARTER_ANNUAL_PRICE_ID
# Paste: price_xxx

# Professional
wrangler secret put STRIPE_PRO_MONTHLY_PRICE_ID
# Paste: price_xxx

wrangler secret put STRIPE_PRO_ANNUAL_PRICE_ID
# Paste: price_xxx

# Business
wrangler secret put STRIPE_BUSINESS_MONTHLY_PRICE_ID
# Paste: price_xxx

wrangler secret put STRIPE_BUSINESS_ANNUAL_PRICE_ID
# Paste: price_xxx
```

The Worker automatically composes these into the internal price map at runtime.

---

### Option B — JSON price map (alternative, for scripted deployments)

Build a single JSON string with all price IDs and set it as one secret:

```bash
wrangler secret put STRIPE_PRICE_MAP
```

Paste the following JSON (replace price IDs with your actual Stripe price IDs):

```json
{
  "starter_monthly": "price_xxxxxxxxxx",
  "starter_annual": "price_xxxxxxxxxx",
  "professional_monthly": "price_xxxxxxxxxx",
  "professional_annual": "price_xxxxxxxxxx",
  "business_monthly": "price_xxxxxxxxxx",
  "business_annual": "price_xxxxxxxxxx"
}
```

**Key format:** `{plan}_{interval}` where plan is one of `starter | professional | business`
and interval is one of `monthly | annual`.

---

## Step 4 — Configure Stripe Webhook

In the Stripe Dashboard → Developers → Webhooks:

1. Click **Add endpoint**
2. Set endpoint URL to:
   ```
   https://cybermeters-platform.ttrnn47.workers.dev/api/stripe/webhook
   ```
3. Select these events to listen for:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Click **Add endpoint**
5. Copy the **Signing secret** (starts with `whsec_`)
6. Set it as `STRIPE_WEBHOOK_SECRET` (Step 2 above)

### Legacy webhook path

The legacy path `/api/billing/webhook` also accepts Stripe events and uses the
same signature verification. Both paths coexist; configure only `/api/stripe/webhook`
in the Stripe Dashboard for new deployments.

---

## Step 5 — Local Development with Stripe CLI

For local testing, forward Stripe events to your local Worker dev server:

```bash
# Install Stripe CLI (https://stripe.com/docs/stripe-cli)
brew install stripe/stripe-cli/stripe

# Log in
stripe login

# Forward events to local worker
stripe listen --forward-to http://localhost:8787/api/stripe/webhook

# The CLI prints a webhook signing secret — use it for local testing:
# wrangler secret put STRIPE_WEBHOOK_SECRET  (paste the CLI secret)
```

---

## Step 6 — Verify Configuration

After setting all secrets, verify with:

```bash
# Test checkout endpoint (replace with a real workspace ID)
curl -s -X POST https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces/WORKSPACE_ID/billing/checkout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SESSION_TOKEN" \
  -d '{"plan":"starter"}' | jq .

# Expected: { "url": "https://checkout.stripe.com/..." }
# If STRIPE_SECRET_KEY missing: { "error": "missing_stripe_config", "missing": ["STRIPE_SECRET_KEY"] }
# If price IDs missing: { "error": "missing_stripe_price", "missing": ["starter_monthly"] }
```

---

## Environment Variable Reference

| Variable | Format | Required | Set via |
|----------|--------|:--------:|---------|
| `STRIPE_SECRET_KEY` | `sk_test_...` or `sk_live_...` | ✅ | `wrangler secret put` |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...` | ✅ | `wrangler secret put` |
| `STRIPE_STARTER_MONTHLY_PRICE_ID` | `price_...` | Option A | `wrangler secret put` |
| `STRIPE_STARTER_ANNUAL_PRICE_ID` | `price_...` | Option A | `wrangler secret put` |
| `STRIPE_PRO_MONTHLY_PRICE_ID` | `price_...` | Option A | `wrangler secret put` |
| `STRIPE_PRO_ANNUAL_PRICE_ID` | `price_...` | Option A | `wrangler secret put` |
| `STRIPE_BUSINESS_MONTHLY_PRICE_ID` | `price_...` | Option A | `wrangler secret put` |
| `STRIPE_BUSINESS_ANNUAL_PRICE_ID` | `price_...` | Option A | `wrangler secret put` |
| `STRIPE_PRICE_MAP` | JSON string | Option B | `wrangler secret put` |

Option A (individual vars) and Option B (JSON map) are mutually exclusive.
If both are set, individual vars take precedence.

---

## Test Cards

Use these card numbers in Stripe test mode:

| Card number | Scenario |
|---|---|
| `4242 4242 4242 4242` | Successful payment |
| `4000 0000 0000 0341` | Card declined |
| `4000 0025 0000 3155` | 3D Secure authentication required |
| `4000 0000 0000 9995` | Insufficient funds |

Expiry: any future date. CVC: any 3 digits. Postcode: any value.

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Initial setup guide — individual vars + JSON map, webhook config |
