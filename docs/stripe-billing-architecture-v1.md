# CyberMeters — Stripe Billing Foundation Architecture

> **Status: Historical / Superseded (16 July 2026).** Retained for historical
> context; no longer a source of truth for prices, products or price IDs.
> Canonical pricing and the go-live cutover sequence: `docs/PRICING-POLICY.md`
> (DECIDED 2026-07-09) · the Stripe products/prices as configured today:
> `docs/stripe-env-setup-v1.md` · implemented behaviour: `BILLING_PLAN_METADATA`
> in `workers/scan-api/src/engines/entitlements.js` and
> `workers/scan-api/src/engines/stripe.js`.
>
> **Why superseded.** Its price table is a **third, never-live set** — Starter
> **£49**, annuals £470 / £1,430 / £3,830. That set was never charged, never
> deployed and never approved: it is neither the legacy live prices (£29 / £149 /
> £399) nor the adopted policy. Its `price_starter_monthly`-style identifiers and
> its `prod_msp` six-product catalogue do not match the implemented resolver,
> which reads price IDs from `STRIPE_*_PRICE_ID` environment variables or
> `STRIPE_PRICE_MAP` and hardcodes none. Do not implement anything in this
> document; the architecture narrative is historical background only.

**Version:** 1.0 | **Date:** June 2026 | **Status:** Superseded (was: Draft — Pending Engineering Review)

**Scope:** Stripe Checkout, Webhooks, Subscription Lifecycle  
**Next Migration:** 028 (`subscription_accounts` extension)  
**Stripe Mode:** Test mode first; production gate after Phase 2 QA

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Billing Readiness Audit](#2-billing-readiness-audit)
3. [Stripe Product Architecture](#3-stripe-product-architecture)
4. [Price Structure](#4-price-structure)
5. [Database Migrations](#5-database-migrations)
6. [Worker Endpoints](#6-worker-endpoints)
7. [Frontend Pages](#7-frontend-pages)
8. [Webhook Matrix](#8-webhook-matrix)
9. [Subscription Lifecycle](#9-subscription-lifecycle)
10. [Upgrade / Downgrade Rules](#10-upgrade--downgrade-rules)
11. [Dunning Flow](#11-dunning-flow)
12. [Entitlement Model](#12-entitlement-model)
13. [Commercial Readiness](#13-commercial-readiness)
14. [Launch Blockers](#14-launch-blockers)
15. [Risk Assessment](#15-risk-assessment)
16. [Implementation Roadmap](#16-implementation-roadmap)

---

## 1. Executive Summary

CyberMeters is in the Productization Phase. Authentication, RBAC, workspaces, quota enforcement, and the `subscription_accounts` table are all in production. The billing infrastructure stops at the database boundary: plan values are written manually, no payment processor is connected, and no customer self-service purchase flow exists.

This document specifies the complete Stripe integration required to convert CyberMeters from a manually-provisioned SaaS into a commercially self-service product. It is specific to the existing codebase, existing schema, and existing enforcement layer — it does not propose generic billing theory.

### What Is Already Built

- `subscription_accounts` D1 table with `plan`, `status`, `trial_ends_at`, `current_period_end`
- `getEffectivePlan()` — reads plan from D1, handles trial/expiry, fail-safe to `'free'`
- `PLAN_LIMITS` constant — 5 tiers: `free`, `starter`, `professional`, `business`, `enterprise`
- `checkScanLimit` / `checkReportLimit` / `checkScheduledScanLimit` — quota enforcement on all write paths
- `AccountPage` — subscription display panel (read-only, shows plan badge and status)
- `GET /api/account/subscription` — returns subscription row to frontend
- `GET /api/account/subscription/limits` — returns plan limits and current usage
- `customer_profiles` — company name, industry, contact for CRM/billing

### What Is Missing

- No Stripe customer ID, subscription ID, or price ID stored in D1
- No Stripe Checkout session creation endpoint
- No Stripe Customer Portal session creation endpoint
- No webhook handler — no `POST /api/webhooks/stripe`
- No invoice history table or endpoint
- No failed payment grace period or dunning flow
- No upgrade/downgrade via self-service
- No annual billing interval support
- No pricing page or upgrade CTA flow in the frontend
- No trial-to-paid conversion logic

### Commercial Impact

Without this integration, CyberMeters cannot accept payment. Customers cannot self-service upgrade. Revenue requires manual Stripe invoicing by the founding team. This blocks the transition from beta to commercial launch.

---

## 2. Billing Readiness Audit

### 2.1 Schema Audit

The `subscription_accounts` table (migration 016) current state:

| Column | Type | Current Use | Gap |
|---|---|---|---|
| `id` | TEXT PK | CUID row identifier | — |
| `owner_user_id` | TEXT FK | Links to `users.id` (billing owner) | — |
| `plan` | TEXT | `free / starter / professional / business / enterprise` | — |
| `status` | TEXT | `active / trial / cancelled` | — |
| `billing_provider` | TEXT | Always `'manual'` | Must become `'stripe'` after checkout |
| `billing_email` | TEXT | Set from `user.email` on signup | — |
| `trial_ends_at` | TEXT ISO | Checked by `getEffectivePlan()` | — |
| `current_period_end` | TEXT ISO | Checked by `getEffectivePlan()` | Must be set from Stripe webhook |
| `created_at` | TEXT | Record creation | — |
| `updated_at` | TEXT | Record update | Must be updated by webhook handler |
| `stripe_customer_id` | **MISSING** | — | Required for Checkout and Portal |
| `stripe_subscription_id` | **MISSING** | — | Required for webhook correlation |
| `stripe_price_id` | **MISSING** | — | Required for plan mapping |
| `billing_interval` | **MISSING** | — | `monthly / annual` |
| `cancel_at_period_end` | **MISSING** | — | Graceful cancel flag from Stripe |
| `cancelled_at` | **MISSING** | — | Timestamp of cancellation |

### 2.2 Endpoint Audit

| Endpoint | Method | Status | Gap |
|---|---|---|---|
| `GET /api/account/subscription` | GET | Live | Does not expose `stripe_customer_id` |
| `GET /api/account/subscription/limits` | GET | Live | — |
| `GET /api/account/profile` | GET | Live | `billing_provider` always `'manual'` |
| `GET /api/account/usage` | GET | Live | — |
| `GET /api/admin/subscriptions` | GET | Live | No Stripe metadata |
| `POST /api/billing/checkout` | POST | **MISSING** | Stripe Checkout session creation |
| `POST /api/billing/portal` | POST | **MISSING** | Stripe Customer Portal session |
| `POST /api/webhooks/stripe` | POST | **MISSING** | Webhook receiver and dispatcher |
| `GET /api/account/invoices` | GET | **MISSING** | Invoice history list |
| `GET /api/billing/plans` | GET | **MISSING** | Public pricing/plan metadata |

### 2.3 Frontend Audit

| Component | Status | Gap |
|---|---|---|
| AccountPage — subscription section | Live (read-only) | No Checkout CTA, no manage billing button |
| AccountPage — plan badge | Live | — |
| AccountPage — usage bars | Live | — |
| PricingPage | **MISSING** | Required for inbound conversion |
| BillingPage / BillingManagePage | **MISSING** | Upgrade, downgrade, cancel, portal |
| UpgradeBanner / UpgradeCTA | **MISSING** | Contextual upgrade prompts on limit hit |
| CheckoutSuccessPage | **MISSING** | Post-checkout confirmation / plan activation |
| InvoiceHistorySection | **MISSING** | Invoice list in AccountPage |

### 2.4 Readiness Summary

| Area | Readiness | Blocker |
|---|---|---|
| D1 schema — core fields | 70% | Missing 6 Stripe columns (migration 028 required) |
| Plan enforcement layer | 100% | — |
| Backend subscription routes | 40% | Missing checkout, portal, webhook, invoice endpoints |
| Frontend subscription UI | 25% | Missing pricing, billing management, upgrade CTAs |
| Stripe configuration | 0% | No products, prices, or webhooks configured in Stripe |
| Webhook security | 0% | No `STRIPE_WEBHOOK_SECRET`, no signature verification |
| Trial flow | 50% | `trial_ends_at` exists; Stripe trial must set this via webhook |
| Invoice history | 0% | No table, no endpoint, no UI |

---

## 3. Stripe Product Architecture

### 3.1 Products

One Stripe Product is created per paid plan. Free is not a Stripe product — it is the default state when no active subscription exists. Enterprise is handled via Stripe invoicing (custom quote), not Checkout.

| Stripe Product | Product Name | Description | Plan Key |
|---|---|---|---|
| `prod_starter` | CyberMeters Starter | Up to 5 workspaces, 25 domains, 5 users | `starter` |
| `prod_professional` | CyberMeters Professional | Up to 25 workspaces, 250 domains, 25 users | `professional` |
| `prod_business` | CyberMeters Business | Up to 25 workspaces, 250 domains, compliance reports | `business` |
| `prod_enterprise` | CyberMeters Enterprise | Custom — Stripe invoice only, not Checkout | `enterprise` |

### 3.2 Worker Environment Variables

| Variable | Value | Notes |
|---|---|---|
| `STRIPE_SECRET_KEY` | `sk_live_...` / `sk_test_...` | Server-side only. Never expose to frontend. |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...` | From Stripe dashboard > Webhooks endpoint. |
| `STRIPE_PRICE_MAP` | JSON string | Maps Stripe `price_id` to plan name. |
| `STRIPE_PUBLISHABLE_KEY` | `pk_live_...` / `pk_test_...` | Safe for frontend. Used in pricing page. |

### 3.3 Plan → Stripe Price ID Mapping

The `STRIPE_PRICE_MAP` variable maps Stripe price IDs to plan names. This is the authoritative source for webhook-driven plan changes.

```json
{
  "price_starter_monthly":      "starter",
  "price_starter_annual":       "starter",
  "price_professional_monthly": "professional",
  "price_professional_annual":  "professional",
  "price_business_monthly":     "business",
  "price_business_annual":      "business"
}
```

> **Note:** Price IDs are placeholders. Replace with actual Stripe price IDs after creating products in the Stripe dashboard. Store as a JSON string in the Cloudflare Worker environment.

---

## 4. Price Structure

Each paid product has two prices: monthly (default) and annual (20% discount). Enterprise is handled via custom Stripe invoicing only.

| Plan | Monthly Price | Annual Price | Annual equiv/mo | Stripe Price ID (monthly) | Stripe Price ID (annual) |
|---|---|---|---|---|---|
| Free | £0 | — | — | — | — |
| Starter | £49 | £470 | £39 | `price_starter_monthly` | `price_starter_annual` |
| Professional | £149 | £1,430 | £119 | `price_professional_monthly` | `price_professional_annual` |
| Business | £399 | £3,830 | £319 | `price_business_monthly` | `price_business_annual` |
| Enterprise | Custom | Custom | Custom | Custom Stripe Invoice | Custom Stripe Invoice |

---

## 5. Database Migrations

### Migration 028 — Stripe Fields on `subscription_accounts`

Extends the existing `subscription_accounts` table (migration 016) with all Stripe-specific fields. All new columns are nullable to preserve backward compatibility with existing manual subscription rows.

```sql
-- 028-stripe-billing.sql
-- Apply: wrangler d1 execute cybermeters-db --remote \
--          --file=database/migrations/028-stripe-billing.sql

ALTER TABLE subscription_accounts ADD COLUMN stripe_customer_id    TEXT;
ALTER TABLE subscription_accounts ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE subscription_accounts ADD COLUMN stripe_price_id        TEXT;
ALTER TABLE subscription_accounts ADD COLUMN billing_interval       TEXT DEFAULT 'monthly';
ALTER TABLE subscription_accounts ADD COLUMN cancel_at_period_end   INTEGER DEFAULT 0;
ALTER TABLE subscription_accounts ADD COLUMN cancelled_at           TEXT;
ALTER TABLE subscription_accounts ADD COLUMN payment_failed_at      TEXT;
ALTER TABLE subscription_accounts ADD COLUMN payment_retry_count    INTEGER DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_stripe_customer
  ON subscription_accounts (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_stripe_subscription
  ON subscription_accounts (stripe_subscription_id)
  WHERE stripe_subscription_id IS NOT NULL;
```

> **Design:** `stripe_customer_id` must be UNIQUE — one Stripe Customer per CyberMeters account owner. These columns are populated by the `customer.created` webhook and on Checkout session completion.

### Migration 029 — Invoice Records

Stores Stripe invoice metadata in D1 for display in the AccountPage invoice history section. This is a cache of Stripe data — Stripe is the source of truth. Records are created or updated on `invoice.payment_succeeded` and `invoice.payment_failed` webhooks.

```sql
-- 029-invoice-records.sql
CREATE TABLE IF NOT EXISTS invoice_records (
    id                 TEXT PRIMARY KEY,
    owner_user_id      TEXT NOT NULL,
    stripe_invoice_id  TEXT NOT NULL UNIQUE,
    amount_due         INTEGER NOT NULL,
    amount_paid        INTEGER NOT NULL,
    currency           TEXT NOT NULL DEFAULT 'gbp',
    status             TEXT NOT NULL,
    description        TEXT,
    period_start       TEXT,
    period_end         TEXT,
    invoice_pdf_url    TEXT,
    hosted_invoice_url TEXT,
    created_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_invoices_owner
  ON invoice_records (owner_user_id, created_at DESC);
```

> **Note:** Amounts are in minor units (pence). £49.00 = 4900. `invoice_pdf_url` and `hosted_invoice_url` come directly from the Stripe Invoice object and are safe to expose to the customer.

### Migration 030 — Webhook Idempotency Log

Prevents duplicate processing of Stripe webhook events, which are delivered at-least-once. The worker checks this table before processing any event and writes a record after successful processing.

```sql
-- 030-stripe-webhook-events.sql
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    stripe_event_id TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    processed_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status          TEXT NOT NULL DEFAULT 'processed'
);

CREATE INDEX IF NOT EXISTS idx_stripe_events_processed_at
  ON stripe_webhook_events (processed_at);
```

> **Maintenance:** Prune events older than 30 days via the existing Cloudflare `scheduled()` handler to prevent unbounded growth. One `DELETE` per scheduled run is sufficient.

---

## 6. Worker Endpoints

### 6.1 `POST /api/billing/checkout`

Creates a Stripe Checkout Session and returns the URL for redirect. Called when a customer clicks 'Upgrade' on the pricing or billing page.

| Attribute | Detail |
|---|---|
| Auth | `requireAuth` — returns 401 if unauthenticated |
| Mode | `subscription` |
| Body params | `price_id` (required), `success_url`, `cancel_url` |
| `success_url` | `{FRONTEND_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}` |
| `cancel_url` | `{FRONTEND_URL}/account` |
| `customer` | If `stripe_customer_id` exists on `subscription_accounts`, reuse it. Otherwise create new. |
| `metadata` | `user_id: user.id` — used by webhook to correlate with D1 row |
| Trial | If account is trial-eligible, add `trial_period_days: 14` |
| `allow_promotion_codes` | `true` |
| Response | `{ checkout_url: 'https://checkout.stripe.com/...' }` |

> **Critical:** Do NOT activate the plan in D1 at this point. Wait for the `checkout.session.completed` webhook. The checkout session may be abandoned.

### 6.2 `POST /api/billing/portal`

Creates a Stripe Customer Portal session for subscription management (upgrade, downgrade, cancel, update payment method, download invoices).

| Attribute | Detail |
|---|---|
| Auth | `requireAuth` — returns 401 if unauthenticated |
| Pre-condition | `stripe_customer_id` must exist on `subscription_accounts` |
| `return_url` | `{FRONTEND_URL}/account` |
| Response | `{ portal_url: 'https://billing.stripe.com/...' }` |
| Error — no customer | `{ error: 'no_stripe_customer', message: 'No billing account found. Please subscribe first.' }` |

> **Design:** The Stripe Customer Portal handles ALL subscription changes. CyberMeters does NOT need to build its own cancel or change-plan UI.

### 6.3 `POST /api/webhooks/stripe`

Receives all Stripe webhook events. Must: (1) verify the `Stripe-Signature` header, (2) check idempotency, (3) dispatch to the appropriate handler, (4) return 200 immediately even on non-fatal errors.

| Attribute | Detail |
|---|---|
| Auth | No Bearer token — authenticated by `Stripe-Signature` HMAC verification |
| Signature check | `stripe.webhooks.constructEvent(body, sig, STRIPE_WEBHOOK_SECRET)` |
| Idempotency | `SELECT stripe_event_id FROM stripe_webhook_events` before processing |
| Dispatch | `switch` on `event.type` — see [Section 8](#8-webhook-matrix) |
| Failure handling | Catch all handler errors; log but return 200 to avoid retry storm |
| Idempotency write | `INSERT INTO stripe_webhook_events` after successful processing |
| Response | Always `{ received: true }` with status 200 |

### 6.4 `GET /api/account/invoices`

| Attribute | Detail |
|---|---|
| Auth | `requireAuth` |
| Query | `SELECT * FROM invoice_records WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT 24` |
| Response | `{ invoices: [{ stripe_invoice_id, amount_paid, currency, status, period_start, period_end, invoice_pdf_url, hosted_invoice_url, created_at }] }` |

### 6.5 `GET /api/billing/plans` (Public)

Returns plan metadata and current pricing for the pricing page. No authentication required. Sourced from `PLAN_LIMITS` + price constants in the worker.

> **Security:** Stripe price IDs are NOT returned to the frontend — the frontend passes the plan name to `POST /api/billing/checkout` and the backend resolves the price ID server-side.

### 6.6 `GET /api/billing/success`

Called by the frontend after Stripe Checkout redirects to `success_url`. Accepts `session_id` query param. Fetches the Checkout Session from Stripe to confirm payment and returns the active plan for immediate UI update. Belt-and-suspenders only — the webhook is the authoritative activator.

---

## 7. Frontend Pages

### 7.1 PricingPage (`/pricing`)

Public page (no auth required). Displays plan comparison table with monthly/annual toggle.

| Component | Detail |
|---|---|
| Monthly/Annual toggle | Local state toggle. Annual prices show 20% savings badge. |
| Plan cards (3) | Starter, Professional, Business. Free shown as 'Current Plan' if applicable. |
| Feature comparison rows | Map from `PLAN_LIMITS`: workspaces, domains, users, scheduled scans, history, report retention. |
| CTA button | Authenticated: calls `POST /api/billing/checkout`. Unauthenticated: links to `/signup`. |
| Current plan highlight | Highlight the active plan card if user is authenticated. |
| Enterprise card | Static: 'Contact Sales'. Links to mailto or contact form. No Checkout. |
| API call | `GET /api/billing/plans` |

### 7.2 BillingPage (`/account` — extended)

Extend the existing AccountPage subscription section. Add the following:

| Component | Detail |
|---|---|
| Manage billing button | `POST /api/billing/portal` → redirect to Stripe Customer Portal. Shows if `billing_provider='stripe'`. |
| Upgrade button | Links to `/pricing`. Shows if plan is `free` or lower tier. |
| Trial banner | If `status='trial'`: 'Your trial ends on [date]. Add a payment method to continue.' |
| Past due warning banner | If `status='past_due'`: 'Payment failed. Update your card to avoid losing access.' |
| Cancel at period end note | If `cancel_at_period_end=1`: 'Your subscription cancels on [date]. You have full access until then.' |
| Invoice history table | `GET /api/account/invoices`. Columns: date, amount, status, PDF download link. |
| Billing interval badge | Shows 'Monthly' or 'Annual' next to plan name. |

### 7.3 CheckoutSuccessPage (`/billing/success`)

Shown after Stripe Checkout redirect. Polls `GET /api/billing/success?session_id=X` to confirm plan is active. Redirects to `/account` after 3 seconds.

### 7.4 UpgradeBanner Component

Contextual inline upgrade prompt shown when a plan limit is hit. Triggered by the existing `plan_limit_exceeded` CustomEvent dispatched by `api.js`. Renders in a portal, links to `/pricing`, and can be dismissed.

### 7.5 Navigation Changes

- Add 'Plans & Billing' link in the UserMenu dropdown (top-right).
- Add upgrade CTA in sidebar footer for free-plan users.
- Add persistent `past_due` warning banner in `Layout.jsx`.

---

## 8. Webhook Matrix

Register exactly these events in the Stripe webhook endpoint. Do not use 'all events'.

| Stripe Event | D1 Action | Notification | Priority |
|---|---|---|---|
| `checkout.session.completed` | Set `stripe_customer_id`, `stripe_subscription_id`, `stripe_price_id`, `plan`, `status='active'`, `billing_provider='stripe'`, `current_period_end`. If trial, set `trial_ends_at`. | Welcome email | P0 |
| `customer.subscription.created` | Upsert `subscription_accounts`: set `stripe_subscription_id`, plan from price map, `status`, `current_period_end`, `billing_interval` | None (covered by `checkout.session.completed`) | P0 |
| `customer.subscription.updated` | Update plan (from new `price_id` via `STRIPE_PRICE_MAP`), `status`, `current_period_end`, `cancel_at_period_end`, `billing_interval` | Plan changed email if plan differs | P0 |
| `customer.subscription.deleted` | Set `status='cancelled'`, `cancelled_at=now()`, `plan='free'` | Cancellation confirmation | P0 |
| `customer.subscription.trial_will_end` | No D1 change — `trial_ends_at` already set | Trial ending in 3 days email | P1 |
| `invoice.payment_succeeded` | Upsert `invoice_records`. Update `current_period_end`. Reset `payment_failed_at=null`, `payment_retry_count=0` | Receipt email (Stripe sends automatically if configured) | P0 |
| `invoice.payment_failed` | Set `payment_failed_at=now()`, increment `payment_retry_count`. If `retry_count >= 3`, set `status='past_due'` | Payment failed email with update link | P0 |
| `invoice.upcoming` | No D1 change | Upcoming renewal reminder (optional) | P2 |
| `customer.created` | Store `stripe_customer_id` on `subscription_accounts` if missing | None | P1 |
| `customer.updated` | Sync `billing_email` if changed | None | P2 |
| `payment_method.attached` | No D1 change | None | P2 |
| `payment_intent.payment_failed` | Log; do not duplicate `invoice.payment_failed` handling | None | P2 |

---

## 9. Subscription Lifecycle

### 9.1 New Subscription Flow (Happy Path)

1. Customer visits `/pricing` and selects a plan + billing interval.
2. Frontend calls `POST /api/billing/checkout` with plan name.
3. Worker creates (or reuses) a Stripe Customer, creates a Checkout Session, returns `checkout_url`.
4. Customer completes payment in Stripe Checkout (Stripe-hosted page).
5. Stripe fires `checkout.session.completed` webhook.
6. Worker verifies signature, checks idempotency, extracts subscription data.
7. Worker updates D1 `subscription_accounts`: `plan`, `status='active'`, `stripe_customer_id`, `stripe_subscription_id`, `current_period_end`, `billing_provider='stripe'`.
8. Worker inserts `stripe_webhook_events` idempotency row.
9. Customer is redirected to `/billing/success?session_id=...` — frontend shows confirmation.
10. `GET /api/account/subscription` now returns the activated plan.

### 9.2 Trial Flow

A 14-day trial is offered on Starter, Professional, and Business plans for new accounts that have never had an active paid subscription. Implemented via Stripe's `trial_period_days` parameter on the Checkout Session.

**Trial eligibility rule:** owner's `subscription_accounts` row has never had `billing_provider='stripe'` AND `status='active'`.

| Step | Action | D1 State |
|---|---|---|
| Checkout created | Pass `trial_period_days: 14` if eligible | `status='active'`, `trial_ends_at=+14d` (set by `subscription.created` webhook) |
| During trial | `getEffectivePlan()` returns paid plan, limits apply | `plan=starter/pro/biz`, `status='active'` |
| 3 days before end | `customer.subscription.trial_will_end` fires | Send 'trial ending soon' notification |
| Trial converts | Stripe charges card; `invoice.payment_succeeded` fires | `payment_failed_at=null`, `status='active'` (no change) |
| Trial — card declined | `invoice.payment_failed` fires; Stripe retries per dunning config | `status='past_due'` after 3 failures |
| Trial ends, no card | `customer.subscription.deleted` fires | `status='cancelled'`, `plan='free'` |

### 9.3 Subscription Status State Machine

| Status Value | Meaning | `getEffectivePlan()` Returns | Access |
|---|---|---|---|
| `active` | Paid and current | Paid plan | Full |
| `trial` | In trial period | Paid plan | Full |
| `past_due` | Payment failed; retrying | Paid plan | Full (grace period) |
| `cancelled` | Cancelled; awaiting period end | Paid plan (until `period_end`) | Full until `period_end` |
| `expired` | Period ended or lapsed | `free` | Free tier only |
| — | No row in `subscription_accounts` | `free` | Free tier only |

### 9.4 Cancellation Flow

1. Customer opens Stripe Customer Portal and cancels.
2. Stripe sets `cancel_at_period_end=true` on the subscription.
3. `customer.subscription.updated` fires. Worker sets `cancel_at_period_end=1` in D1.
4. AccountPage shows 'Cancels on [date]' banner. Access continues until `current_period_end`.
5. On period end: `customer.subscription.deleted` fires.
6. Worker sets `status='cancelled'`, `plan='free'`, `cancelled_at=now()`.
7. `getEffectivePlan()` returns `'free'`. Enforcement kicks in on next action.

---

## 10. Upgrade / Downgrade Rules

### 10.1 Upgrade (Higher Plan)

All upgrades are immediate. Stripe applies proration automatically.

| Rule | Detail |
|---|---|
| Timing | Effective immediately on Stripe subscription update |
| Proration | Stripe prorates by default — no custom logic required |
| D1 update | `customer.subscription.updated` webhook fires; worker updates plan from new `price_id` |
| Entitlements | `getEffectivePlan()` returns new plan immediately after D1 update |
| Notification | Send 'Plan upgraded to X' via existing notification helper |
| Annual option | Customer can switch to annual during upgrade — handled in Customer Portal |

### 10.2 Downgrade (Lower Plan)

Downgrades take effect at the end of the current billing period.

| Rule | Detail |
|---|---|
| Timing | Takes effect at `current_period_end` — never immediately |
| Stripe config | Set `proration_behavior='none'` for downgrades |
| D1 update | Update plan and `current_period_end` from `customer.subscription.updated` webhook |
| Entitlements | Access continues at current plan level until `current_period_end` |
| Notification | Send 'Plan changing to X on [date]' notification |
| Data retention | Excess workspaces/domains are not deleted — they become read-only. Rule 5 — Historical data is sacred. |

### 10.3 Over-Limit State After Downgrade

Existing data is preserved. Enforcement applies on the next write action only: `POST /api/workspaces/:id/domains` returns `402 plan_limit_exceeded` if over the new limit. Existing data remains fully readable.

---

## 11. Dunning Flow

### 11.1 Stripe Smart Retries

Configure in Stripe Dashboard > Billing > Subscriptions > Retry schedule. **Recommended: 3 retries over 7 days.**

### 11.2 CyberMeters Dunning Flow

| Event | Day | D1 Action | Customer Notification |
|---|---|---|---|
| First payment failure | 0 | `payment_failed_at=now()`, `retry_count=1`, `status='past_due'` | 'Payment failed — update your card' |
| Stripe retry 1 | 2 | `retry_count=2` if fails again | 'We tried again — update card to avoid losing access' |
| Stripe retry 2 | 5 | `retry_count=3` if fails again | 'Final warning — access suspended in 2 days' |
| Stripe retry 3 / final | 7 | If failed: `status='cancelled'`, `plan='free'` | 'Access suspended — resubscribe to restore' |
| Payment recovers | — | Reset `payment_failed_at=null`, `retry_count=0`, `status='active'` | 'Payment successful — access restored' |

### 11.3 Access During `past_due` Status

The customer retains full plan access during the grace period (days 0–7). `getEffectivePlan()` returns the paid plan because `current_period_end` has not yet passed. A persistent warning banner is shown in the AccountPage and dashboard header.

---

## 12. Entitlement Model

### 12.1 PLAN_LIMITS — No Changes Required

`PLAN_LIMITS` is already complete with all 5 tiers and all enforcement dimensions. No changes required for Stripe integration.

| Limit | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| Workspaces | 1 | 5 | 25 | 25 | Unlimited |
| Domains | 3 | 25 | 250 | 250 | Unlimited |
| Users | 1 | 5 | 25 | 100 | Unlimited |
| History days | 30 | 90 | 365 | 730 | Unlimited |
| Report retention | 30d | 90d | 1yr | 7yr | Unlimited |
| API tokens | 1 | 5 | 20 | 50 | Unlimited |
| Scans/month | 10 | 100 | 1,000 | 5,000 | Unlimited |
| Scheduled scans | 0 | 5 | 25 | 100 | Unlimited |

### 12.2 `getEffectivePlan()` — No Changes Required

The existing `getEffectivePlan()` function already handles all required states: `active`, `trial` (via `trial_ends_at`), and expired/cancelled (via `current_period_end` and `status`). The webhook handler writes to the same columns that `getEffectivePlan()` already reads.

### 12.3 Enforcement Behaviour After Plan Change

- Existing data is preserved (no deletions)
- Write actions beyond the new limit return `402 plan_limit_exceeded`
- Read actions on existing data are unrestricted

---

## 13. Commercial Readiness

### 13.1 Invoice History

Invoice records are retained indefinitely in D1. This supports the Business plan's 7-year compliance retention requirement.

Data displayed per invoice:

- Date
- Description (e.g. 'CyberMeters Professional — November 2026')
- Amount paid (formatted as £49.00)
- Status badge: Paid / Failed / Voided
- PDF download link (`invoice_pdf_url` from Stripe)
- View invoice link (`hosted_invoice_url` from Stripe)

### 13.2 Invoice Lifecycle

| Stripe Event | `invoice_records` Action |
|---|---|
| `invoice.payment_succeeded` | `INSERT OR REPLACE` with `status='paid'`, `amount_paid`, period dates, PDF URL |
| `invoice.payment_failed` | `INSERT OR REPLACE` with `status='payment_failed'` |
| `invoice.voided` | `UPDATE invoice_records SET status='voided'` |

### 13.3 Stripe Test Cards

| Scenario | Test Card Number | Result |
|---|---|---|
| Payment success | `4242 4242 4242 4242` | Payment succeeds; subscription activates |
| Payment declined | `4000 0000 0000 0002` | Card declined; `invoice.payment_failed` fires |
| 3D Secure required | `4000 0025 0000 3155` | Requires authentication in Checkout |
| Insufficient funds | `4000 0000 0000 9995` | Fails; triggers dunning flow |

Use any future MM/YY and any 3-digit CVV.

### 13.4 Stripe CLI — Local Development

```bash
# Forward Stripe events to local Worker during Phase 2 testing:
stripe listen --forward-to http://localhost:8787/api/webhooks/stripe

# Trigger specific events manually:
stripe trigger checkout.session.completed
stripe trigger invoice.payment_failed
stripe trigger customer.subscription.deleted
```

### 13.5 wrangler.toml Additions

```toml
[vars]
STRIPE_PUBLISHABLE_KEY = "pk_test_..."

# Secrets — set via: wrangler secret put STRIPE_SECRET_KEY
# STRIPE_SECRET_KEY
# STRIPE_WEBHOOK_SECRET

# STRIPE_PRICE_MAP — store as JSON string in Cloudflare Dashboard > Settings > Variables
# { "price_starter_monthly": "starter", ... }
```

---

## 14. Launch Blockers

The following items must be resolved before CyberMeters can accept customer payment.

| Blocker | Severity | Resolution |
|---|---|---|
| No `POST /api/webhooks/stripe` — plan cannot be activated after payment | P0 | Phase 2 — implement webhook handler with `Stripe-Signature` verification |
| No `POST /api/billing/checkout` — customers cannot initiate payment | P0 | Phase 2 — implement Checkout session endpoint |
| `stripe_customer_id` missing from `subscription_accounts` | P0 | Migration 028 |
| No `STRIPE_WEBHOOK_SECRET` in Worker — webhooks unauthenticated | P0 | Phase 1 — `wrangler secret put STRIPE_WEBHOOK_SECRET` |
| No pricing page — no conversion path | P0 | Phase 3 — build PricingPage |
| No manage billing UI — customers cannot update payment method or cancel | P1 | Phase 3 — add Stripe Customer Portal button to AccountPage |
| No invoice history — customers cannot download receipts | P1 | Phase 2 (backend) + Phase 3 (frontend) |
| No trial-to-paid conversion flow | P1 | Phase 2 — wire `trial_period_days` in Checkout; webhook sets `trial_ends_at` |
| No failed payment notification | P1 | Phase 2 — `invoice.payment_failed` webhook fires existing notification helper |
| No Terms of Service or Privacy Policy linked at checkout | P1 | Legal — add `consent_collection` or `terms_of_service_acceptance` to Checkout Session |

---

## 15. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Webhook arrives before Checkout redirect — customer sees 'plan not active' | High | Low | CheckoutSuccessPage polls `/api/billing/success` with retry. Plan activates within seconds via webhook. |
| Duplicate webhook delivery processes subscription twice | Medium | High | Migration 030 — `stripe_webhook_events` idempotency table prevents double-processing. |
| `STRIPE_WEBHOOK_SECRET` not set in production — malicious webhook accepted | Low | Critical | Worker must hard-fail (not soft-fail) if `env.STRIPE_WEBHOOK_SECRET` is absent. |
| `getEffectivePlan()` called before D1 updated by webhook — stale plan returned | Medium | Low | Existing fail-safe defaults to `'free'` on error. Webhook latency is typically <1s. |
| Customer downgrades; excess data causes confusion | Medium | Medium | Rule 5 — no data deletion. Excess items are read-only. Clear UI messaging in AccountPage. |
| Stripe price IDs misconfigured in `STRIPE_PRICE_MAP` — wrong plan activated | Medium | High | Worker must throw and return 500 if `price_id` not found in map. Test in test mode first. |
| Annual billing customer on monthly price — wrong tier activated | Low | Medium | `STRIPE_PRICE_MAP` maps both monthly and annual price IDs to the same plan name. |
| `customer.subscription.deleted` fires immediately on cancel | Low | High | Stripe only fires `deleted` after period end when `cancel_at_period_end=true`. Verify during Phase 1. |
| D1 write failure during webhook — subscription lost but Stripe charged | Low | Critical | On D1 failure: log error, return 500 (Stripe retries). Do NOT return 200 on failed D1 write. |
| Cloudflare Worker CPU time limit hit during webhook | Very Low | Medium | Webhook handlers are lightweight D1 writes. Not a concern for this workload. |

---

## 16. Implementation Roadmap

### Phase 1 — Stripe Configuration + Schema

**Estimated effort: 1 day.** Pre-requisite for all subsequent phases. No code deployed to production.

| Task | Owner | Deliverable |
|---|---|---|
| Create Stripe account (test mode) | Founder | Stripe test account active |
| Create 3 Products in Stripe (Starter, Pro, Business) | Founder | `prod_*` IDs noted |
| Create 6 Prices (monthly + annual for each plan) | Founder | `price_*` IDs noted |
| Create Stripe webhook endpoint pointing to Worker URL | Founder | `whsec_*` secret noted |
| Add `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` to Worker | Engineer | `wrangler secret put` commands run |
| Add `STRIPE_PRICE_MAP` JSON to Worker environment | Engineer | Price ID → plan name map deployed |
| Run migration 028 | Engineer | D1 schema updated |
| Run migration 029 | Engineer | D1 schema updated |
| Run migration 030 | Engineer | D1 schema updated |

### Phase 2 — Backend Endpoints (Test Mode)

**Estimated effort: 2–3 days.**

| Task | Deliverable |
|---|---|
| Implement `POST /api/billing/checkout` | Checkout session created; redirect URL returned |
| Implement `POST /api/billing/portal` | Portal session created; redirect URL returned |
| Implement `POST /api/webhooks/stripe` (all P0 events) | Webhook verified, dispatched, D1 updated |
| Implement `GET /api/account/invoices` | Invoice list from D1 returned |
| Implement `GET /api/billing/plans` | Plan metadata returned (no auth required) |
| Implement `GET /api/billing/success` | Checkout session confirmed; plan verified |
| `node --check` syntax validation | No syntax errors |
| Manual webhook testing with Stripe CLI | `stripe listen --forward-to localhost` confirms all P0 events |

### Phase 3 — Frontend Integration (Test Mode)

**Estimated effort: 3–4 days.**

| Task | Deliverable |
|---|---|
| Create PricingPage with monthly/annual toggle | Public `/pricing` route live |
| Add `STRIPE_PUBLISHABLE_KEY` to frontend `.env` | Frontend can reference plan metadata |
| Extend AccountPage — manage billing button, invoice history | Stripe portal accessible from account |
| Build CheckoutSuccessPage | Post-checkout confirmation works |
| Build UpgradeBanner wired to `plan_limit_exceeded` | Limit hits show upgrade prompt |
| Add billing nav items to UserMenu and sidebar | Navigation updated |
| End-to-end test: free → starter upgrade via Checkout | Plan activates in test mode |
| End-to-end test: downgrade via Customer Portal | Plan changes at period end |
| End-to-end test: failed payment via Stripe test card | `past_due` state and banner shown |
| `npm run build` | Frontend builds without errors |

### Phase 4 — Production Cutover

**Estimated effort: 1 day.** Requires Phase 2 and 3 QA sign-off.

| Task | Deliverable |
|---|---|
| Create live Stripe products and prices (identical to test) | Live price IDs noted |
| Rotate `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` to live keys | Worker redeployed with live secrets |
| Update `STRIPE_PRICE_MAP` with live price IDs | Worker redeployed |
| Test one live Checkout with a real card | Payment confirmed in Stripe live dashboard |
| Enable Stripe email receipts in Stripe Dashboard | Customers receive receipts automatically |
| Set Stripe Smart Retry schedule: 3 retries over 7 days | Dunning configured |
| Monitor webhook delivery in Stripe dashboard for 24h | All events delivering 200 |
| Announce billing to beta users | Commercial launch email sent |

---

*CyberMeters Platform — Stripe Billing Foundation Architecture v1 — Confidential — June 2026*
