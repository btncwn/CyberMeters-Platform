# M7 — Founder Stripe Configuration Action Sheet

Status: **PENDING FOUNDER ACTION** · Prepared 20 July 2026 (M7 Pricing & Billing Lockstep)
Authority: `docs/PRICING-POLICY.md` (CANONICAL · FOUNDER-FINAL · LOCKED 2026-07-19)

The M7 code lockstep is engineering-complete: the runtime plan registry, plan API, pricing
cards, entitlements, webhook mapping and checkout guard all state the locked ladder, and
**checkout refuses any Stripe price that does not charge exactly the policy amount**
(`verifyStripePriceMatchesPolicy` — GBP, interval, unit amount to the penny, active).
That means nothing sells until the Stripe objects below exist and match. Engineering never
sees live secret values (policy §8); every step here is founder-run.

## 1. Current Stripe state (as inventoried, read-only)

- Worker secrets present: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_MAP`,
  `STRIPE_STARTER_MONTHLY_PRICE_ID`, `STRIPE_STARTER_YEARLY_PRICE_ID`,
  `STRIPE_PROFESSIONAL_MONTHLY_PRICE_ID`, `STRIPE_PROFESSIONAL_YEARLY_PRICE_ID`,
  `STRIPE_BUSINESS_MONTHLY_PRICE_ID`, `STRIPE_BUSINESS_YEARLY_PRICE_ID` (values not readable
  by engineering; presumed test-mode and legacy-priced).
- Production D1 holds two Stripe-bound test subscriptions (`sub_1Tl…`), both `starter`.
- The webhook now hard-fails-closed on any price ID not present in the configured maps.

## 2. Prices to create (test mode first, live mode at public-beta cutover)

All prices GBP, recurring. Create one product per plan (or reuse existing products), then:

| # | Product | Interval | Unit amount | Lookup key (recommended) | Maps to secret |
| - | --- | --- | --- | --- | --- |
| 1 | CyberMeters Starter | monthly | **£9.99** (999p) | `starter_monthly` | `STRIPE_STARTER_MONTHLY_PRICE_ID` |
| 2 | CyberMeters Starter | yearly | **£99.90** (9990p) | `starter_annual` | `STRIPE_STARTER_YEARLY_PRICE_ID` |
| 3 | CyberMeters Professional | monthly | **£19.99** (1999p) | `professional_monthly` | `STRIPE_PROFESSIONAL_MONTHLY_PRICE_ID` |
| 4 | CyberMeters Professional | yearly | **£199.90** (19990p) | `professional_annual` | `STRIPE_PROFESSIONAL_YEARLY_PRICE_ID` |
| 5 | CyberMeters Business | monthly | **£49.99** (4999p) | `business_monthly` | `STRIPE_BUSINESS_MONTHLY_PRICE_ID` |
| 6 | CyberMeters Business | yearly | **£499.90** (49990p) | `business_annual` | `STRIPE_BUSINESS_YEARLY_PRICE_ID` |

Annual figures are the policy's **exact** ×10 numbers — do not let Stripe compute a
percentage discount.

Deferred (create only when per-domain overage billing ships — see §6):

| Product | Interval | Unit amount | Purpose |
| --- | --- | --- | --- |
| CyberMeters Additional Domain | monthly | £3.00 (300p) | Business domains 11–25; MSP metered domains |
| CyberMeters Additional Domain | yearly | £30.00 (3000p) | Annual equivalent |
| CyberMeters MSP Base | monthly | £99.99 (9999p) | MSP base fee (sales-led) |
| CyberMeters MSP Base | yearly | £999.90 (99990p) | MSP annual base |

## 3. Secrets to set after creating prices

From `workers/scan-api/`:

```bash
npx wrangler secret put STRIPE_STARTER_MONTHLY_PRICE_ID       # price_…
npx wrangler secret put STRIPE_STARTER_YEARLY_PRICE_ID
npx wrangler secret put STRIPE_PROFESSIONAL_MONTHLY_PRICE_ID
npx wrangler secret put STRIPE_PROFESSIONAL_YEARLY_PRICE_ID
npx wrangler secret put STRIPE_BUSINESS_MONTHLY_PRICE_ID
npx wrangler secret put STRIPE_BUSINESS_YEARLY_PRICE_ID
```

`STRIPE_PRICE_MAP` (JSON) is optional once the six individual secrets are set — individual
secrets take precedence in BOTH checkout and webhook directions. If kept, update it to the
same six price IDs or delete it; a stale map entry no longer wins but should not linger.

## 4. Old object disposition

- **Archive (do not delete)** the legacy £29/£149/£399 prices in Stripe (set inactive).
  The checkout guard refuses inactive prices, so an accidentally lingering secret fails
  closed instead of charging the legacy amount.
- The two existing test subscriptions (`starter`) keep working: their price IDs remain in
  history; if their price is archived, renewal events still map by ID. If you cancel and
  re-checkout them on the new prices, entitlements follow automatically.

## 5. Safe order of operations (test mode)

1. Create the six prices (test mode) with the exact amounts above.
2. Set the six secrets (test values).
3. Run a test checkout for each of Starter/Professional/Business, monthly + annual:
   the checkout must open, and Stripe must show the policy amount.
   A wrong amount will be refused server-side with `stripe_price_policy_mismatch` (503) —
   that is the guard working, not a bug.
4. Complete one test checkout; verify the webhook activated the right plan:
   `GET /api/billing/subscription` shows the purchased plan, and the workspace subscription
   endpoint shows the correct domain limit (Starter 1 / Professional 3 / Business 10).
5. Verification query (read-only):
   `SELECT plan, subscription_status, stripe_price_id FROM subscriptions WHERE stripe_subscription_id = '<new sub id>';`

At **public-beta go-live** repeat 1–4 in live mode with live keys + live webhook
(`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` live values) — the one-time test → live
cutover of policy §8. Production runtime must never mix live keys with test price IDs;
the webhook's environment guard drops cross-mode events.

## 6. Known deferred item (founder-visible)

**Per-domain overage billing (Business 11–25, MSP metered domains) is not yet implemented
in code.** Entitlement fails closed at the included count (Business = 10) with the honest
message that per-domain expansion is not yet self-service. Before the first Business
customer needs domain 11 — and before any MSP onboarding — a follow-up episode must add
Stripe subscription-item quantity sync against the Additional Domain price. Until then, do
not sell a >10-domain Business arrangement or a self-serve MSP plan.

## 7. Rollback

- Secrets are versioned by `wrangler secret put` — re-putting the previous value restores it.
- Archiving a price is reversible (set active again).
- The Worker rollback ID for the M7 runtime release is recorded in `CHANGELOG.md`.
