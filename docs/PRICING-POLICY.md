# CyberMeters — Pricing Policy (canonical)

> **Owner:** Turhan. **Status: DECIDED 2026-07-09 — adopted, NOT yet live.**
> The live cutover happens at **public-beta launch** (see [Go-live](#go-live--the-one-lockstep-cutover-at-launch)), not before.
> **Competitor research is CLOSED.** Act from this file — do not re-run pricing analysis.
> The prices actually charged today are still the OLD ones (see [Currently live](#currently-live-until-the-launch-cutover)).

> **This file is the single canonical pricing and packaging authority (recorded
> 16 July 2026).** It supersedes every earlier pricing, packaging and commercial
> direction document. The following are Historical / Superseded and must not be
> implemented or quoted:
>
> - `docs/final-commercial-packaging-v1.md` — was "Approved — Active Commercial
>   Direction"; legacy £29 / £149 / £399, Business as multi-workspace.
> - `docs/cyber-essentials-commercial-strategy-v1.md` — was "Active Commercial
>   Direction"; legacy prices and CE claims that exceed external evidence.
> - `docs/pricing-strategy-v1.md` — was "Current strategy"; legacy prices and
>   workspace/domain limits that were never enforced.
> - `docs/pricing-page-copy-v1.md` — was "Ready for implementation"; legacy prices,
>   banned "Save 20%" annual copy, workspaces shown on cards.
> - `docs/commercial-packaging-strategy-v1.md` — analysis only; rejected £9.90/£49.
> - `docs/stripe-billing-architecture-v1.md` — a third, never-live £49 price set.
> - `docs/pricing-audit-current-state-v1.md`, `docs/entitlement-audit-v1.md`,
>   `docs/PHASE-0-AUDIT.md`, `docs/strategic-review-board-level-june2026.md` —
>   point-in-time audits/reviews; historical only.
>
> `docs/stripe-env-setup-v1.md` remains accurate **for the currently-live legacy
> prices** and is the runbook for today's Stripe setup — not for the adopted
> tiers, which cut over per §6. Canonical competitive positioning:
> `docs/competitive-battlecard-v2.md`.

---

## 1. The thesis — why we can be genuinely "unbeatable"

Every competitor is either on traditional/AWS infra or single-purpose (DMARC-only,
or ASM-only, or ratings-only). Our **Cloudflare-native cost is ~£0.10–0.20/domain/mo
all-in** (incl. Stripe fees; compute alone ≈ £0.002–0.01). So we keep **85 %+ margin
even at these prices.** No competitor's cost base can follow us down.

**Honest definition of "unbeatable" (never overclaim):** cheapest per-domain for the
**full external-security posture** — the eight canonical domains: Email Protection ·
Brand Protection · Attack Surface · Certificates & Trust · Cyber Essentials
Readiness · Website Security · Identity Exposure · Shadow IT & Unmanaged
Technology — i.e. **bundle economics**, NOT "cheaper than every single-purpose tool
on its one job." A UK SMB otherwise stacks OnDMARC + an ASM tool (£89) + a cert
monitor = £150–250/mo; we give all of it for a fraction.

**The real moat is the Free tier competitors can't match** (their cost base forbids a
free continuously-monitored domain), not undercutting any single price.

---

## 2. Permanent rules

1. **Public value metric = monitored domains.** NEVER on pricing cards: workspaces,
   users, scans/month, reports/month (internal enforcement concepts only).
2. **SMB = simple bundled domain tiers · MSP = platform fee + per-domain.** Fixed MSP
   bands ("20–100+ from £X") are banned — 21 and 99 domains must not cost the same.
3. **Any price change = Stripe prices + backend `BILLING_PLAN_METADATA` + pricing
   cards in ONE lockstep change, Turhan-approved.** Cards must ALWAYS match what
   Stripe charges — a £9 card charging £29 is a trust catastrophe.
4. **Keep internal plan keys** (`free/starter/professional/business/enterprise`) —
   relabel only (`professional`→"Growth", `enterprise`→"MSP / Partner"). No key
   migration, existing subscriptions never break.
5. Positioning: simpler + cheaper + UK SMB/MSP + domain-first + Cyber MOT language.
   Don't out-feature Red Sift / Hardenize; make them irrelevant to the UK SMB.
6. No customer-facing "DAST / scanner / pen test / certification / guaranteed secure".

---

## 3. Adopted tiers (MAX-aggressive — Turhan, 2026-07-09)

### SMB — domain bundles (all include the full platform)

| Plan | Monthly | Annual (pay 9, get 12) | Monitored domains | Internal key |
|---|---|---|---|---|
| **Free forever** | £0 | — | 1 (continuous weekly monitoring) | `free` |
| **Starter** | **£9** | £81 | 3 | `starter` |
| **Growth** | **£29** | £261 | 10 | `professional` |
| **Business** | **£69** | £621 | 25 (single workspace) | `business` |

- Extra domains on any SMB plan: **£3/domain/mo**.
- Free tier is the land-grab weapon: continuous (weekly passive) monitoring of 1
  domain + all four services + Cyber MOT + CE Readiness preview. On-demand re-scan
  limited (cost control). Upgrade triggers: 2nd domain, full history, alerts,
  scheduled reports, brand depth, CE dashboard.

### MSP / Partner — platform fee + per-domain (white-label, multi-workspace)

**£29/mo platform + £1/domain**, **£0.75 over 100**, **£0.50 over 500**. Min 25 domains.
Internal key `enterprise`.

| Client domains | Monthly | Effective £/domain |
|---|---|---|
| 25 | £54 | £2.16 |
| 50 | £79 | £1.58 |
| 100 | £129 | £1.29 |
| 250 | £241 | £0.97 |
| 500 | £429 | £0.86 |
| 1,000 | £679 | £0.68 |

### Business vs MSP boundary (resolves the old `ws=50` question)

- **Business = single-org** (1 workspace, ≤25 monitored domains) → set `PLAN_LIMITS`
  `business.workspaces = 1`.
- **MSP / Partner = multi-client** (a workspace per client, white-label) → keeps
  multi-workspace. This is the ONLY tier that shows "client workspaces".

### Annual

**Pay 9, get 12** (3 months free). Card copy may state this plainly *because the
Stripe annual prices are set to exactly 9× monthly* — unlike the old ~20 % annuals,
where only "Save with annual billing." was allowed.

---

## 4. Phasing (don't block launch on the complex part)

- **Phase 1 (launch):** Free + Starter/Growth/Business as **fixed Stripe prices**
  (the proven checkout machinery handles these). MSP = **"Talk to us"** (manual
  invoicing).
- **Phase 2 (fast-follow, Stripe usage-based):** per-domain add-on (£3) + **MSP
  metered** (£29 + £1/domain automated) + free-tier continuous-monitoring cron
  (cost-controlled weekly eligibility).

---

## 5. Currently live (until the launch cutover)

Deployed prices are still the OLD set — **Starter £29 / Professional £149 /
Business £399**, annuals ~20 % off (£276 / £1,428 / £3,828), MSP "Talk to us",
annual copy "Save with annual billing." Cards render monitored-domains only
(`PricingPage.jsx`, commits `0e7d1ff` + `bb20865`). Enforcement `v2026.07.09-1`
(worker `2d17cf49`): SMB single-workspace, domains per-workspace, creation-only.

**These stay live until the launch cutover below.**

---

## 6. Go-live — the ONE lockstep cutover (at launch)

**Important:** the platform has only ever run on **Stripe sandbox/test keys** — no
real payment has ever been taken (the "6/6 checkouts" were test-mode). Going live is
a real **test → live cutover**, done ONCE at public-beta launch. No real
subscriptions exist → clean slate, zero migration.

Order (checkout must never break mid-cutover; cards never go live before Stripe):

1. **Turhan — Stripe (LIVE mode):** activate account (business verify + bank — do
   this early, verification takes time; UK sole-trader is fine to start), create the
   3 products with the new live prices (Starter £9/£81 · Professional £29/£261 ·
   Business £69/£621), create the LIVE webhook (same `/api/billing/webhook` endpoint,
   live signing secret).
2. **Turhan — worker secrets** (he sets these himself; Claude never sees values):
   `wrangler secret put STRIPE_SECRET_KEY` (`sk_live_…`),
   `STRIPE_WEBHOOK_SECRET` (`whsec_…` live), and the 6 live price IDs
   (`STRIPE_*_PRICE_ID` or `STRIPE_PRICE_MAP`).
3. **Claude — code:** `BILLING_PLAN_METADATA` (new prices/names), `PLAN_LIMITS`
   (domains 1/3/10/25, `business.workspaces=1`), display names (Growth / MSP),
   pricing cards. Deploy on Turhan's approval.
4. **Verify:** Turhan runs ONE real **£9 Starter** checkout with his card → confirm
   charge + subscription activates (webhook fired) → refund from Stripe.

Until then, the new pricing can be **built and tested in sandbox** (test cards, zero
risk) so the machinery is proven against the new tiers before launch.

---

## 7. Honest risk

At these prices the **£100k-Y1 target is volume-bound**: ~50 MSPs (avg £150/mo) *or*
~120 Business (£69) + the free→paid funnel. It's a deliberate **land-grab bet** that
the free-funnel virality + MSP channel convert more customers than higher prices
would. Cloudflare cost advantage + Cyber MOT hook + UK SMB TAM make the bet
reasonable, but **distribution (funnel + MSP outreach) must actually work** —
engineering isn't the constraint, go-to-market is.

Month-3 checkpoint: if MRR is weak and no MSP design partner is engaged, revisit the
aggression dial (a "smart-aggressive" fallback exists: £12/£39/£89 · MSP £1.50/domain).

---

## 8. Competitor benchmarks (settled 2026-07 — cite, DO NOT re-research)

| Competitor | Model | Signal |
|---|---|---|
| **Red Sift / OnDMARC** | DMARC, tiered | Express $9/mo (4 domains); Essentials 25 sender domains; upper tiers sales-led. Enterprise-ish + complex. |
| **Intruder** | Ext. vuln mgmt / ASM | Base fee + per-target; Enterprise = quote. |
| **HostedScan** | Ext. scanning | $39 / $109 / $189 mo, 5 targets each. |
| **Pentest-Tools** | Ext. assessment | $95 / $140 / $190 mo, from 5 assets. |
| **Detectify** | Surface + app scanning | Platform fee + per-domain (surface) + per-target (app); PCI ASV €500/yr. |
| **Attack Surface Center** (UK) | ASM | Free · £89/10 assets · £179/30 · £499/100. Closest UK ASM analog. |
| **Hardenize / Red Sift** | Asset/DNS/TLS/cert monitoring | Monitored-host tiers (250 / 500+), +hosts $2/mo. Business = demo/quote. |
| **UpGuard** | Ratings / vendor risk | $1,750/mo (50 vendors), +vendors $79 each. Enterprise. |
| **Censys ASM** | Internet visibility | Credit-based, packages from $100. |
| **DMARC Report** | DMARC / MSP | Core 1 / Guard 5 / Shield 10 / Defender 25 / Ultimate ∞ ($3,900/mo). MSP 50 % off + volume. |
| **DMARC Digests** | DMARC-only | **Flat $14/mo per domain**, 60-day history — the cheapest per-domain DMARC benchmark. |
| **Mailhardener MSP** (model to emulate) | DMARC MSP | **€149 base + €1/domain**, nothing else metered; 50 domains ≈ €199/mo. |
| **URIports** | DMARC/TLS/DNS packs | €5/5 · €25/25 · €100/100 · €400/400 domains. Domain bundles are market-normal. |

**Four market models** exist (domain-count / host-asset / volume / MSP fee+per-domain).
Ours: **SMB = domain bundles, MSP = platform fee + per-domain, metric = monitored
domains** — cheaper than all of them for the full posture, on a cost base they can't
match. Related: [GROWTH-ROADMAP.md](GROWTH-ROADMAP.md).
