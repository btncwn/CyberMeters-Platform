# CyberMeters — Pricing Policy (canonical)

> **Status: CANONICAL · FOUNDER-FINAL · LOCKED 2026-07-19.**
> This file is the **single canonical pricing and packaging authority** — the one source of truth for
> all CyberMeters pricing, packaging and entitlement limits. (This founder-final 2026-07-19 lock
> supersedes the earlier 2026-07-09 pricing decision.)
> Any change to prices, tiers, limits or plan mapping MUST update **this document first**, then
> propagate to Stripe prices + backend entitlements/billing metadata + pricing cards in **one
> lockstep**. Cards, Stripe and limits must always match this document. No partial live-price change.
>
> **Owner:** Turhan (founder). Pricing is founder authority — engineering recommends, the founder decides.
>
> This file supersedes every earlier pricing, packaging and commercial-direction document. The prices
> actually charged in production remain the OLD legacy set until the founder performs the one-time
> Stripe **test → live cutover** at public-beta launch (see [§8](#8-stripe-testlive-boundary)); this
> document does not itself change live billing.

**Superseded / historical (must not be implemented or quoted):**
`docs/final-commercial-packaging-v1.md` · `docs/cyber-essentials-commercial-strategy-v1.md` ·
`docs/pricing-strategy-v1.md` · `docs/pricing-page-copy-v1.md` ·
`docs/commercial-packaging-strategy-v1.md` · `docs/stripe-billing-architecture-v1.md` ·
`docs/pricing-audit-current-state-v1.md` · `docs/entitlement-audit-v1.md` · earlier point-in-time
audits/reviews. Any £-figure in those files, in the previous £9/£29/£69 or £29/£149/£399 sets, in
`docs/competitive-battlecard-v2.md`, or in prior notes is stale relative to this document. The earlier
"~£0.10–0.20/domain all-in" cost claim is **discredited and withdrawn** — see [§9](#9-cost-floor--planning-assumptions).
Canonical competitive positioning reference (non-price): `docs/competitive-battlecard-v2.md`.

---

## 1. Product & value metric

- **One product: the Cyber MOT.** Eight canonical customer-facing categories, and **every paid plan
  includes all eight**:
  1. Email Protection
  2. Brand Protection
  3. Attack Surface
  4. Certificates & Trust
  5. Cyber Essentials Readiness
  6. Website Security
  7. Identity Exposure
  8. Shadow IT & Unmanaged Technology
- **Primary commercial metric: monitored domains.** Billing is **per primary (organisation) domain**;
  each primary domain includes its discovered footprint — subdomains, certificates, lookalikes and
  related externally observed evidence — across all eight categories at no extra charge.
- **Do not price by** users, workspaces, scans or reports, and do not surface those on pricing cards.
- **Self-service is the operating model.** No routine founder intervention; no managed-service
  positioning; no feature expansion beyond the existing product boundary.

**Bundle claim (positioning).** CyberMeters is the cheapest per-domain option for the
**full external-security posture** — the eight canonical domains:
Email Protection · Brand Protection · Attack Surface · Certificates & Trust · Cyber Essentials Readiness · Website Security · Identity Exposure · Shadow IT & Unmanaged Technology
— i.e. **bundle economics**, not undercutting any single single-purpose tool on its one job.
"Cyber MOT" is the product name, not a ninth domain.

---

## 2. Plans (locked · monthly · GBP)

| Plan | Monthly | Monitored domains | Notes |
| --- | --- | --- | --- |
| **14-Day Full Trial** | £0 | 1 | Full product — all 8 categories + alerts + cases + reports + remediation. No card required. |
| **Starter** | £9.99 | 1 | Full Cyber MOT |
| **Professional** | £19.99 | 3 | Full Cyber MOT |
| **Business** | £49.99 | 10 included | +£3/mo per additional domain, hard cap 25 |
| **MSP** | £99.99 base + £3/domain | Minimum billed quantity 10 | Monthly floor **£129.99**; distinct customer type |

**Business overage** — base £49.99/mo **includes 10 domains**; domains 11–25 are billed at **+£3/month
each**; **hard cap 25**. Worked points: 15 domains = £64.99 · 20 = £79.99 · 25 = £94.99. A customer
needing more than 25 domains moves to **MSP**.

**MSP billing** — base £99.99/mo **does not include domains**; **every** monitored domain is £3/month
with a **minimum billed quantity of 10** → MSP minimum monthly charge is **£129.99** (£99.99 + 10 × £3).
Worked points: 10 domains = £129.99 · 25 = £174.99. MSP is a distinct customer type (multi-client
portfolio, bulk onboarding, client reporting, white-label, MSP billing/usage), **not** merely a
high-domain Business plan.

---

## 3. Annual billing (locked · exact)

Annual billing = **pay for 10 months, receive 12** (2 months free ≈ 16.7%). Stripe must use these
**exact** annual figures — never a re-computed percentage — so cards, Stripe and this document cannot
drift on rounding:

| Plan | Annual base | Annual per-domain |
| --- | --- | --- |
| Starter | £99.90/year | — |
| Professional | £199.90/year | — |
| Business | £499.90/year | £30/domain/year (domains 11–25) |
| MSP | £999.90/year | £30/domain/year (min billed quantity 10) |

**MSP annual minimum = £1,299.90/year** (£999.90 + 10 × £30).

---

## 4. 14-Day Full Trial rules

- Full product for **14 days**, **1 monitored domain**, all 8 categories, alerts/cases/reports/
  remediation — **no card required**.
- **No automatic charge.** Conversion to a paid plan requires **explicit customer consent**.
- **Monitoring stops at expiry (fail-closed).** Read-only access to prior evidence may remain only if
  the existing lifecycle already supports it safely.
- Abuse controls in place of a card: verified business email (where existing controls allow);
  domain-ownership verification; **one trial per user/workspace**; **no repeat trial for the same
  domain**; rate limiting.

---

## 5. Internal plan-key mapping (naming only — subscriptions are NOT auto-migrated)

Internal keys may remain `free / starter / professional / business / enterprise`. Relabelling is a
**naming** operation; subscription behaviour, entitlements and Stripe mappings are **not** silently
remapped.

- `free` → **14-Day Full Trial** (time-limited; monitoring stops at expiry)
- `starter` → **Starter**
- `professional` → **Professional**
- `business` → **Business** (base includes 10; 11–25 per-domain overage)
- `enterprise` → **MSP** — **only** after proving zero live enterprise subscriptions, zero live
  enterprise customers, zero active Stripe enterprise mappings and zero contractual/entitlement
  divergence from the MSP model. `enterprise → MSP` is a **billing-model and commercial-contract
  change, not a safe relabel**; if any of that proof is missing, stop and report migration/cutover
  options rather than remap.

---

## 6. Entitlement limits (PLAN_LIMITS — monitored domains)

- `free` (trial): 1, expires after 14 days (fail-closed)
- `starter`: 1
- `professional`: 3
- `business`: 10 included, per-domain overage to a **hard cap of 25** (domain 26 rejected → routed to MSP)
- `enterprise` (MSP): **minimum billed quantity 10**, metered per-domain

The frontend must never derive or override entitlements; domain-cap enforcement is backend-owned and
tenant-scoped.

---

## 7. Lockstep rule (permanent)

Any price / tier / limit change = **this document + Stripe prices + backend PLAN_LIMITS /
BILLING_PLAN_METADATA + pricing cards**, in one founder-approved lockstep. No partial live-price change.
Pricing cards must always match what Stripe charges and what this document states, for both monthly and
annual.

---

## 8. Stripe test/live boundary

- Until public-beta go-live, only Stripe **sandbox/test** keys are used, and **production runtime is
  never bound to test price IDs**. Test price IDs live only in test-only fixtures/config, clearly
  separated from production metadata.
- **Go-live is a one-time founder-run test → live cutover:** the founder activates live Stripe, creates
  live prices + webhook, and sets the secrets himself. Engineering never sees live secret values and
  then updates metadata/limits/cards to reference the live price IDs.
- If the repository lacks a safe test/live configuration separation, stop and present the minimum safe
  design — never improvise a production binding to test price IDs.

---

## 9. Cost floor — planning assumptions

Subject to accountant verification + actual Stripe/Cloudflare telemetry. Solo-founder, AI-augmented,
self-service operating model — no employee hiring:

- Founder gross salary ~£40,000/year (company-paid); employer NIC ~£5,250 (2026/27: (£40,000 − £5,000)
  × 15%; single-director → no Employment Allowance; no mandatory pension).
- Annual operating costs ~£10,000 (Cloudflare, AI/software tooling, accounting/legal, insurance, other).
- Stripe processing modelled at low 2% / base 2.5% / high 3.5% of revenue (not a single locked %).
- **Breakeven ≈ £57k ARR;** ~£90k revenue ≈ ~£26k retained post-tax company profit; Corporation Tax
  19% ≤£50k profit, marginal relief £50k–£250k.
- Cloudflare-native infrastructure is marginal per domain. The real constraint is **founder time per
  customer** → MSP-heavy mix + self-service SMB.

These are **founder-approved planning assumptions, not audited figures**. Retained company profit is
**not** the founder's net personal income; personal income tax and employee NIC on the salary sit
outside this unit-economics model. (The earlier "~£0.10–0.20/domain all-in / 85% margin" claim is
withdrawn.)

---

## 10. Competitor guardrails (positioning, not anchors)

SMB/MSP audit set (positioning reference only): Red Sift, CyberSmart, Intruder, CYRISMA, Guardz,
ConnectSecure, ThreatMate, EasyDMARC, PowerDMARC, Sendmarc. Price anchors: the per-domain email floor
(EasyDMARC / PowerDMARC / Red Sift) and CyberSmart (UK/channel, ~65% MSP margin). Position on
eight-category scope at an accessible entry price, **not** on a competitor median. £9.99 removes the
price-excuse to choose a single-wedge email tool while delivering eight-category scope; growth comes
from upgrades (2nd/3rd domain → Professional, wider portfolio → Business, multi-client → MSP), not from
the entry tier.
