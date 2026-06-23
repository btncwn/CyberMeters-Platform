# CyberMeters — Pricing Audit: Current State

**Date:** June 2026  
**Type:** Read-only audit — no code, Stripe, or documentation was modified  
**Sources read:** `workers/scan-api/src/index.js` (PLAN_LIMITS, PLAN_FEATURES, BILLING_PLAN_METADATA), `frontend/src/pages/SubscriptionPage.jsx`, `frontend/src/pages/PricingPage.jsx`, `docs/pricing-strategy-v1.md`, `docs/commercial-packaging-strategy-v1.md`, `docs/final-commercial-packaging-v1.md`, `docs/feature-entitlements-v1.md`, `docs/billing-implementation-map.md`, `docs/stripe-billing-architecture-v1.md`, `docs/stripe-checkout-audit-v1.md`, `docs/stripe-env-setup-v1.md`, `docs/pricing-page-copy-v1.md`

---

## 1. Plans Currently Implemented in Code

Exactly five plan keys exist. They are used in `PLAN_LIMITS`, `PLAN_FEATURES`, `BILLING_PLAN_METADATA`, `normalizePlan()`, `parseCheckoutPlan()`, and `getPublicBillingPlans()`.

```
free
starter
professional
business
enterprise
```

`msp` does **not** exist as a plan key anywhere in code. It is neither validated, normalised, nor referenced as a billing tier.

---

## 2. Limits per Plan — Exact Values from PLAN_LIMITS

| Limit | free | starter | professional | business | enterprise |
|---|---|---|---|---|---|
| workspaces | 1 | 3 | 10 | 50 | unlimited |
| domains | 3 | 10 | 100 | 1,000 | unlimited |
| users | 1 | 3 | 10 | 50 | unlimited |
| history_days | 30 | 90 | 365 | 730 | unlimited |
| report_retention | 90_days | 90_days | 2_years | 7_years | forever |
| api_tokens | 1 | 5 | 25 | 100 | unlimited |
| scans_per_month | 5 | 100 | 1,000 | 5,000 | unlimited |
| scan_starts_per_hour | 5 | 20 | 100 | 300 | unlimited |
| reports_per_month | 3 | 50 | 500 | 2,000 | unlimited |
| scheduled_scans | 0 | 5 | 20 | 100 | unlimited |
| scheduled_reports_per_workspace | 1 | 3 | 10 | 50 | unlimited |
| pending_invitations | 10 | 25 | 50 | 250 | unlimited |

---

## 3. Features per Plan — Exact Values from PLAN_FEATURES

| Feature key | free | starter | professional | business | enterprise |
|---|---|---|---|---|---|
| scheduled_scans | ✗ | ✓ | ✓ | ✓ | ✓ |
| alerts | ✗ | ✓ | ✓ | ✓ | ✓ |
| pdf_reports | ✗ | ✓ | ✓ | ✓ | ✓ |
| multi_workspace | ✗ | ✓ | ✓ | ✓ | ✓ |
| team_members | ✗ | ✓ | ✓ | ✓ | ✓ |
| business_risk_score | ✗ | ✓ | ✓ | ✓ | ✓ |
| cyber_essentials | ✗ | ✗ | ✓ | ✓ | ✓ |
| vendor_risk | ✗ | ✗ | ✓ | ✓ | ✓ |
| executive_dashboard | ✗ | ✗ | ✓ | ✓ | ✓ |
| audit_logs | ✗ | ✗ | ✓ | ✓ | ✓ |
| portfolio_monitoring | ✗ | ✗ | ✗ | ✓ | ✓ |
| white_label | ✗ | ✗ | ✗ | ✓ | ✓ |
| msp_dashboard | ✗ | ✗ | ✗ | ✗ | ✓ |

---

## 4. Pricing — Exact Values from BILLING_PLAN_METADATA and Frontend

Both the Worker (`BILLING_PLAN_METADATA`) and frontend (`SubscriptionPage.jsx`, `PricingPage.jsx`) agree on the following:

| Plan | Monthly (GBP) | Annual equiv/mo | Annual total | checkout_enabled |
|---|---|---|---|---|
| free | £0 | £0 | £0 | false |
| starter | £29 | £23 | £276 | true |
| professional | £149 | £119 | £1,428 | true |
| business | £399 | £319 | £3,828 | true |
| enterprise | custom | custom | custom | false |

Annual pricing represents exactly a 20–21% discount on monthly. No discrepancy between Worker and frontend.

---

## 5. Does Code Assume MSP as a Billing Plan?

**No.** Code assumes exactly: `free`, `starter`, `professional`, `business`, `enterprise`.

`msp` appears in the codebase only in these forms:
- `msp_dashboard` — a feature key in `PLAN_FEATURES.enterprise`
- Prose references in documentation describing the MSP customer persona
- One stale doc (`stripe-billing-architecture-v1.md`) mentions a `prod_msp` Stripe product — this document is pre-Sprint 14 and contradicts all subsequent implementation

MSP is a **customer persona and use case**, not a billing plan. The MSP Dashboard feature unlocks at Enterprise for qualifying MSP customers.

---

## 6. Is Enterprise Self-Service or Contact Sales?

**Contact sales only.** This is enforced in three places:

1. `BILLING_PLAN_METADATA.enterprise.checkout_enabled = false`
2. `parseCheckoutPlan()` returns `{ ok: false }` for enterprise because `checkout_enabled` is checked before creating a Stripe session
3. `POST /api/workspaces/:id/billing/checkout` explicitly returns `{ error: "contact_sales" }` when `plan === "enterprise"`

Enterprise is never routed to Stripe Checkout. It is sales-assisted.

---

## 7. Conflicts Found

### Conflict 1: PLAN_LIMITS vs. final-commercial-packaging-v1.md

The most significant conflict is between the limits currently coded and the quota table in `docs/final-commercial-packaging-v1.md`, which was produced as the "Approved Commercial Direction" document.

| Quota | Code (current) | final-commercial-packaging-v1.md |
|---|---|---|
| Free — domains | 3 | 1 |
| Free — history_days | 30 | 7 days |
| Starter — domains | 10 | 5 |
| Starter — scans/month | 100 | 50 |
| Professional — domains | 100 | 25 |
| Professional — scans/month | 1,000 | 500 |
| Professional — scheduled scans | 20 | 25 |
| Business — workspaces | 50 | 25 |
| Business — domains | 1,000 | 250 |
| Business — scans/month | 5,000 | 2,500 |

The code aligns with `docs/pricing-strategy-v1.md` (Sprint 14 working doc). The `final-commercial-packaging-v1.md` recommends tighter limits — particularly fewer domains per tier and a shorter Free history window (7 days vs 30 days). Neither document has been formally reconciled into the code.

**Verdict:** Two competing authoritative documents. Code matches Sprint 14 doc. Commercial doc recommends tighter limits. Must be resolved before Stripe products are created, because limit changes post-launch require customer communications.

---

### Conflict 2: Starter report_retention

| Source | Starter report_retention |
|---|---|
| Code (PLAN_LIMITS) | 90_days |
| pricing-strategy-v1.md | 90 days |
| final-commercial-packaging-v1.md | 90 days |

No conflict. All three agree.

---

### Conflict 3: Free plan report_retention

| Source | Free report_retention |
|---|---|
| Code (PLAN_LIMITS) | 90_days |
| pricing-strategy-v1.md | "90 days report retention" |
| final-commercial-packaging-v1.md | "7 days" (data retention row) |

Minor conflict. Code and Sprint 14 doc say 90 days for Free. The commercial packaging doc says 7 days for Free retention. The commercial doc's intent was to use retention limits as an upgrade driver. The code is more generous.

---

### Conflict 4: Stale stripe-billing-architecture-v1.md

`docs/stripe-billing-architecture-v1.md` (pre-Sprint 14) describes a Stripe product called `prod_msp` and a 6-product Stripe catalog including MSP as a separate purchasable product. This is incompatible with all subsequent implementation. The current code has no `msp` plan key, no `msp` entry in `BILLING_PLAN_METADATA`, and no checkout path for an MSP plan.

**This document is stale and should not be used as a reference for Stripe catalog setup.**

---

### Conflict 5: STRIPE_PRICE_MAP key format evolution

Two key formats appear across docs:

**Format A** (stripe-checkout-flow-v1.md — older):
```json
{
  "price_1ABC_monthly_starter": "starter",
  "price_1ABC_annual_starter":  "starter"
}
```
Keys are Stripe price IDs; values are plan names. Interval derived from substring matching.

**Format B** (stripe-checkout-audit-v1.md — Sprint 14B, current):
```json
{
  "starter_monthly":       "price_xxx",
  "professional_monthly":  "price_xxx"
}
```
Keys are composite `{plan}_{interval}`; values are Stripe price IDs. Direct lookup.

**Code implements Format B.** Format A is a stale design from a pre-Sprint 14 doc. `getStripePriceIdForPlan()` uses Format B exclusively. Format A must not be used when setting `STRIPE_PRICE_MAP`.

---

### Conflict 6: commercial-packaging-strategy-v1.md pricing vs. code

The `commercial-packaging-strategy-v1.md` document initially proposed a different (lower) price point for Starter (£9.90, later revised to £49) before the final commercial direction settled at £29. The current code and `final-commercial-packaging-v1.md` both agree on the final pricing (£29/£149/£399), but the intermediate document contains the old prices. The intermediate doc should be treated as analysis only, not as an authoritative pricing reference.

---

## 8. Recommended Final Pricing Structure

Based on what is implemented and what the approved commercial documents agree on:

### Plan Structure (no change required)

```
free → starter → professional → business → enterprise
```

Five plans. No MSP plan. Enterprise is contact sales. This is correct.

### Pricing (no change required)

| Plan | Monthly | Annual total | Annual equiv/mo |
|---|---|---|---|
| Starter | £29 | £276 | £23 |
| Professional | £149 | £1,428 | £119 |
| Business | £399 | £3,828 | £319 |
| Enterprise | Custom | Custom | Custom |

This matches both the code and the final commercial doc. No change needed.

### Feature Placement (no change required)

The current `PLAN_FEATURES` in code matches the final commercial direction:

- Business Risk Score → Starter ✓
- Cyber Essentials → Professional ✓
- Portfolio Monitoring → Business ✓
- White Label → Business ✓
- MSP Dashboard → Enterprise ✓

### Limits — One decision required

The only open question before creating Stripe products is which limit set to use. The two options are:

**Option A — Current code (generous limits, matches pricing-strategy-v1.md):**
- Starter: 10 domains, 100 scans/month
- Professional: 100 domains, 1,000 scans/month
- Business: 1,000 domains, 5,000 scans/month

**Option B — Tighter limits (matches final-commercial-packaging-v1.md):**
- Starter: 5 domains, 50 scans/month
- Professional: 25 domains, 500 scans/month
- Business: 250 domains, 2,500 scans/month

Limits do not affect the Stripe catalog. Stripe products and prices are plan/interval/price only. Limits are enforced in the Worker at runtime. This decision can be made independently of Stripe setup and changed without touching Stripe.

**Recommendation: Decide limits separately from Stripe catalog. Create Stripe products now using the pricing above — limits can be adjusted in PLAN_LIMITS without any Stripe changes.**

---

## 9. Stripe Catalog Corrections Required

### What should exist in Stripe

Three products, six prices:

| Stripe Product | Display Name | Plan key |
|---|---|---|
| CyberMeters Starter | CyberMeters Starter | starter |
| CyberMeters Professional | CyberMeters Professional | professional |
| CyberMeters Business | CyberMeters Business | business |

For each product, two prices:

| Price label | Amount | Interval | Key for STRIPE_PRICE_MAP |
|---|---|---|---|
| Starter Monthly | £29.00 GBP | monthly | starter_monthly |
| Starter Annual | £276.00 GBP | yearly | starter_annual |
| Professional Monthly | £149.00 GBP | monthly | professional_monthly |
| Professional Annual | £1,428.00 GBP | yearly | professional_annual |
| Business Monthly | £399.00 GBP | monthly | business_monthly |
| Business Annual | £3,828.00 GBP | yearly | business_annual |

**Total: 3 products, 6 prices.**

**Do not create:**
- A Free product (Free is the default state, not a Stripe product)
- An MSP product (MSP is not a plan)
- An Enterprise product for Checkout (Enterprise is contact sales / custom invoice only)

### STRIPE_PRICE_MAP format to use

After creating the prices above, set `STRIPE_PRICE_MAP` using Format B (composite key → price ID):

```json
{
  "starter_monthly":      "price_xxxxxxxxxx",
  "starter_annual":       "price_xxxxxxxxxx",
  "professional_monthly": "price_xxxxxxxxxx",
  "professional_annual":  "price_xxxxxxxxxx",
  "business_monthly":     "price_xxxxxxxxxx",
  "business_annual":      "price_xxxxxxxxxx"
}
```

Or use individual env vars (Sprint 14B Option A — takes precedence over STRIPE_PRICE_MAP):

```bash
STRIPE_STARTER_MONTHLY_PRICE_ID
STRIPE_STARTER_ANNUAL_PRICE_ID
STRIPE_PRO_MONTHLY_PRICE_ID
STRIPE_PRO_ANNUAL_PRICE_ID
STRIPE_BUSINESS_MONTHLY_PRICE_ID
STRIPE_BUSINESS_ANNUAL_PRICE_ID
```

### Stale Stripe products to ignore or archive

If any of the following Stripe products were previously created, they should be archived (not deleted — Stripe does not allow deleting products with existing prices):

- Any product named or keyed as `msp` or `prod_msp`
- Any price using Format A key structure (price ID as the map key)
- Any Starter product priced at £9.90 or £49 (not the approved £29)
- Any Professional product priced at £29.90 (not the approved £149)
- Any Business product priced at £99.90 (not the approved £399)

---

## 10. No-Code Action Items

These items require decisions or actions outside the codebase:

1. **Decide on PLAN_LIMITS** — Choose Option A (current code) or Option B (commercial doc). Update `PLAN_LIMITS` in Worker only after the decision is made. No Stripe changes needed.

2. **Create Stripe products and prices** — Three products, six prices, as specified in Section 9 above. Use GBP currency. Set as recurring subscriptions.

3. **Archive any stale Stripe products** — If `prod_msp` or any incorrectly-priced products exist in the Stripe Dashboard, archive them before going live.

4. **Set Wrangler secrets** — After creating Stripe prices, set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and either `STRIPE_PRICE_MAP` (JSON) or the six individual price ID vars. See `docs/stripe-env-setup-v1.md` for exact commands.

5. **Configure Stripe webhook endpoint** — Register `https://cybermeters-platform.ttrnn47.workers.dev/api/stripe/webhook` in Stripe Dashboard → Developers → Webhooks. Select the six events documented in `docs/stripe-env-setup-v1.md`.

6. **Reconcile stale docs** — Mark `docs/stripe-billing-architecture-v1.md` and `docs/stripe-checkout-flow-v1.md` (STRIPE_PRICE_MAP Format A section) as superseded. They predate Sprint 14 and contain incorrect plan structures.

---

## Summary

| Question | Answer |
|---|---|
| Plans in code | free, starter, professional, business, enterprise |
| MSP as a billing plan | No — MSP is a customer persona; `msp_dashboard` is a feature within Enterprise |
| Enterprise self-service | No — contact sales only, enforced in code |
| Pricing agreed across code and docs | Yes — £29 / £149 / £399 / custom |
| Feature placement agreed | Yes — BRS at Starter, CE at Professional, Portfolio at Business, MSP Dashboard at Enterprise |
| Limits agreed | No — code (generous) vs. commercial doc (tighter); needs a decision |
| STRIPE_PRICE_MAP format | Format B: `{plan}_{interval}` → `price_id` |
| Stripe products to create | 3 products (Starter, Professional, Business), 6 prices |
| Stale documents to watch out for | stripe-billing-architecture-v1.md (mentions prod_msp), stripe-checkout-flow-v1.md (Format A keys) |

---

## Version History

| Version | Date | Notes |
|---|---|---|
| v1 | June 2026 | Initial pricing audit — read-only, no changes made |
