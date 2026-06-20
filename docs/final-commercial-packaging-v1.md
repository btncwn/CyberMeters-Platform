# CyberMeters — Final Commercial Packaging v1

**Version:** 1.0 | **Date:** June 2026 | **Status:** Approved — Active Commercial Direction  
**Scope:** Plan structure, feature placement, upgrade paths, revenue rationale, commercial milestones  
**Market:** UK SMBs, MSPs, vCISOs, security consultants

> This document records approved commercial decisions. The plan structure, feature placement, pricing, and upgrade path defined here are the authoritative reference for all product, engineering, and marketing work until a subsequent commercial review is completed and approved.

---

## Table of Contents

1. [Approved Plan Structure](#1-approved-plan-structure)
2. [Approved Feature Placement](#2-approved-feature-placement)
3. [Final Plan Matrix](#3-final-plan-matrix)
4. [Upgrade Path Analysis](#4-upgrade-path-analysis)
5. [Commercial Packaging Audit](#5-commercial-packaging-audit)
6. [Revenue Rationale](#6-revenue-rationale)
7. [Feature Entitlement Map](#7-feature-entitlement-map)
8. [Rejected Proposals — Do Not Revisit](#8-rejected-proposals--do-not-revisit)
9. [Recommended Next Commercial Milestones](#9-recommended-next-commercial-milestones)

---

## 1. Approved Plan Structure

### Free — Platform Evaluation

**Purpose:** Allow prospective customers to experience the platform before committing. Provide genuine value while creating clear, felt limitations that drive Starter conversion.

**Primary conversion goal:** Free → Starter via Business Risk Score visibility.

| Included | Detail |
|---|---|
| Basic domain scans | Manual trigger only |
| Basic scan reports | On-screen results, no PDF |
| ASM technical score | Raw score without BRS narrative |
| Basic asset inventory | Core findings visible |

**What Free deliberately withholds:**
- Business Risk Score (the primary upgrade driver to Starter)
- Scheduled scans (automation withheld to create friction)
- Scheduled reports (no automated delivery)
- PDF/downloadable reports (no shareable deliverable)
- Historical trend data (no improvement tracking)
- Executive Dashboard

---

### Starter — £29/month

**Primary upgrade driver: Business Risk Score**

**Commercial message:** *"Understand your business risk, not just technical findings."*

**Purpose:** Convert the IT Manager who runs manual scans and wants to show something meaningful to their management. Starter is where the platform becomes a continuous monitoring tool rather than a point-in-time scanner.

| Included | Detail |
|---|---|
| Business Risk Score | Grade (A–F), narrative, category summary |
| Scheduled scans | Automated scan execution on a schedule |
| Scheduled reports | Automated report delivery |
| Executive Dashboard | Workspace-level overview |
| Historical Tracking | Score and finding history |
| Basic Executive Reporting | PDF executive summary, CyberMeters branded |

**Starter is the right home for Business Risk Score because:**
- It translates technical scan output into a business-level narrative — the core value proposition for any non-technical stakeholder
- It creates a board-reportable output without requiring the full compliance depth of Professional
- It makes Starter sticky: once a customer's CEO sees a BRS grade in a meeting, they will not stop monitoring

---

### Professional — £149/month

**Primary upgrade driver: Cyber Essentials Readiness**

**Commercial message:** *"Stay continuously prepared for Cyber Essentials and client audits."*

**Purpose:** Serve the compliance-driven SMB, the IT Manager facing a government contract or insurance renewal, and the solo vCISO who needs a complete intelligence picture for their client engagements.

| Included | Detail |
|---|---|
| Cyber Essentials Readiness | Continuous gap assessment against UK CE framework |
| Vendor Risk | Third-party vendor detection and risk categorisation |
| SaaS Exposure | Detected SaaS tool footprint and risk surface |
| Third-Party Risk | Asset-level third-party dependency intelligence |
| Advanced Reporting | Full executive report with BRS breakdown, trend charts, recommendations |
| Extended Retention | Longer data retention for compliance evidence |

**Professional is the right home for Cyber Essentials Readiness because:**
- Cyber Essentials is a UK government-backed certification. It is required for UK government contracts over £25,000 and increasingly required by cyber insurers and supply chain partners
- A UK SMB with a hard compliance deadline has a budget-unlocking event, not a discretionary spend decision
- At £149/month, CyberMeters replaces a £500–£2,000 one-time consultant gap assessment with continuous automated monitoring
- Professional thus has a clear, externally-referenced value anchor that Starter deliberately lacks

---

### Business — £399/month

**Primary upgrade drivers: White-Label Reports + Portfolio Monitoring**

**Commercial message:** *"Manage and report on multiple clients from one platform."*

**Purpose:** Serve the MSP adding security services, the vCISO managing multiple client engagements, and the security consultant who delivers branded work product to clients. Business is where CyberMeters becomes a professional service delivery platform, not just an internal monitoring tool.

| Included | Detail |
|---|---|
| Portfolio Monitoring | Cross-workspace portfolio dashboard and alerts |
| White-Label Reports | All report types rendered under the customer's brand |
| Multi-Workspace Management | Manage all client workspaces from one account |
| Consultant / vCISO Workflows | Portfolio-level risk views, bulk scheduled reports |
| Extended Retention | 7-year data retention for compliance and client audit trails |

**Business is the right home for White-Label Reports because:**
- A vCISO or MSP cannot send a CyberMeters-branded report to their client — it exposes their tooling and undermines their professional positioning
- White-label is not a luxury feature; it is a buying requirement for any customer delivering work product to third parties
- Placing white-label at Enterprise would exclude the most commercially motivated early adopters — vCISOs and MSPs — who are likely to be among the first 50 paying customers

**Business is the right home for Portfolio Monitoring because:**
- An MSP or vCISO managing 10 clients cannot use a tool that only shows one client at a time
- Portfolio Monitoring is what transforms CyberMeters from a single-tenant tool into a managed service platform
- The moment a consultant adds their second client, they need Business

---

### Enterprise — Custom Pricing

**Primary upgrade driver: MSP Dashboard**

**Commercial message:** *"Operate CyberMeters as a managed security platform."*

**Purpose:** Serve large MSPs, enterprise security teams, and organisations requiring contractual guarantees, SSO integration, and unlimited scale.

| Included | Detail |
|---|---|
| MSP Dashboard | Purpose-built multi-tenant MSP operational view |
| Custom Limits | Workspace, domain, and user limits negotiated per contract |
| SSO / SAML | Identity provider integration |
| Priority Support | Named support contact and SLA |
| Dedicated Onboarding | Guided setup and configuration assistance |

Enterprise is sales-assisted. It is not available via self-service Stripe Checkout.

---

## 2. Approved Feature Placement

This table is the canonical reference. All engineering, product, and marketing decisions must align to these placements.

| Feature | Approved Tier | Notes |
|---|---|---|
| Basic domain scans | Free | Hook feature — available without payment |
| Basic scan reports (on-screen) | Free | No PDF, no download |
| ASM technical score | Free | Raw score only, no BRS narrative |
| Business Risk Score | **Starter** | Primary Free → Starter driver |
| Scheduled scans | Starter | Automation unlock |
| Scheduled reports | Starter | Automated delivery unlock |
| Executive Dashboard | Starter | Workspace-level overview |
| Historical Tracking | Starter | Score and finding history |
| Basic Executive Report (PDF) | Starter | CyberMeters branded |
| Cyber Essentials Readiness | **Professional** | Primary Starter → Professional driver |
| Vendor Risk | Professional | Third-party intelligence |
| SaaS Exposure | Professional | Detected SaaS footprint |
| Third-Party Risk | Professional | Asset-level dependency intelligence |
| Advanced Executive Reports | Professional | Full BRS breakdown, trend charts |
| Extended Retention (compliance) | Professional + Business | Professional: 1yr. Business: 7yr. |
| Portfolio Monitoring | **Business** | Primary Professional → Business driver |
| White-Label Reports | **Business** | Primary Professional → Business driver |
| Multi-Workspace Management | Business | Multi-client operational capability |
| Consultant / vCISO Workflows | Business | Portfolio views, bulk reporting |
| MSP Dashboard | **Enterprise** | Primary Business → Enterprise driver |
| Custom Limits | Enterprise | Negotiated per contract |
| SSO / SAML | Enterprise | Identity provider integration |
| Priority Support | Enterprise | Named contact + SLA |
| Dedicated Onboarding | Enterprise | Guided setup |

---

## 3. Final Plan Matrix

### Pricing

| Plan | Monthly | Annual (per month) | Annual (billed upfront) |
|---|---|---|---|
| Free | £0 | £0 | £0 |
| Starter | £29 | £23 | £276 |
| Professional | £149 | £119 | £1,428 |
| Business | £399 | £319 | £3,828 |
| Enterprise | Custom | Custom | Custom |

Annual pricing applies a 20% discount. Annual billing is the recommended default on the pricing page.

### Feature Matrix

| Feature | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| **Core Scanning** | | | | | |
| Domain scanning (manual) | ✓ | ✓ | ✓ | ✓ | ✓ |
| DNS analysis | ✓ | ✓ | ✓ | ✓ | ✓ |
| SSL/TLS analysis | ✓ | ✓ | ✓ | ✓ | ✓ |
| Security headers | ✓ | ✓ | ✓ | ✓ | ✓ |
| Email security (SPF/DKIM/DMARC) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Subdomain discovery | ✓ | ✓ | ✓ | ✓ | ✓ |
| Asset inventory | Basic | Full | Full | Full | Full |
| Scheduled scans | ✗ | ✓ | ✓ | ✓ | ✓ |
| **Risk Intelligence** | | | | | |
| ASM technical score | ✓ | ✓ | ✓ | ✓ | ✓ |
| Business Risk Score (BRS) | ✗ | ✓ | ✓ | ✓ | ✓ |
| BRS category breakdown | ✗ | Summary | Full | Full | Full |
| BRS historical trend | ✗ | ✗ | ✓ | ✓ | ✓ |
| Vendor Risk | ✗ | ✗ | ✓ | ✓ | ✓ |
| SaaS Exposure | ✗ | ✗ | ✓ | ✓ | ✓ |
| Third-Party Risk | ✗ | ✗ | ✓ | ✓ | ✓ |
| **Compliance** | | | | | |
| Cyber Essentials Readiness | ✗ | ✗ | ✓ | ✓ | ✓ |
| Cyber Essentials gap report | ✗ | ✗ | ✓ | ✓ | ✓ |
| **Reporting** | | | | | |
| On-screen scan results | ✓ | ✓ | ✓ | ✓ | ✓ |
| Basic executive summary (PDF) | ✗ | ✓ | ✓ | ✓ | ✓ |
| Full executive report (PDF) | ✗ | ✗ | ✓ | ✓ | ✓ |
| Scheduled reports | ✗ | ✓ | ✓ | ✓ | ✓ |
| White-label reports | ✗ | ✗ | ✗ | ✓ | ✓ |
| **Monitoring & History** | | | | | |
| Historical tracking | ✗ | ✓ | ✓ | ✓ | ✓ |
| Data retention | 7 days | 90 days | 1 year | 7 years | Unlimited |
| Executive Dashboard | ✗ | ✓ | ✓ | ✓ | ✓ |
| Asset change events | ✗ | ✓ | ✓ | ✓ | ✓ |
| Notifications / alerts | ✗ | ✓ | ✓ | ✓ | ✓ |
| **Portfolio / Multi-tenant** | | | | | |
| Multi-workspace management | ✗ | ✗ | ✗ | ✓ | ✓ |
| Portfolio dashboard | ✗ | ✗ | ✗ | ✓ | ✓ |
| Portfolio alerts | ✗ | ✗ | ✗ | ✓ | ✓ |
| Portfolio trend reports | ✗ | ✗ | ✗ | ✓ | ✓ |
| Consultant / vCISO workflows | ✗ | ✗ | ✗ | ✓ | ✓ |
| MSP Dashboard | ✗ | ✗ | ✗ | ✗ | ✓ |
| **Platform** | | | | | |
| Team members / RBAC | ✗ | Basic | Full | Full | Full |
| Audit trail | ✗ | ✗ | ✓ | ✓ | ✓ |
| SSO / SAML | ✗ | ✗ | ✗ | ✗ | ✓ |
| Custom limits | ✗ | ✗ | ✗ | ✗ | ✓ |
| Priority support | ✗ | ✗ | ✗ | ✗ | ✓ |
| Dedicated onboarding | ✗ | ✗ | ✗ | ✗ | ✓ |

### Quota Limits

| Quota | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| Workspaces | 1 | 3 | 10 | 25 | Unlimited |
| Domains | 1 | 5 | 25 | 250 | Unlimited |
| Users | 1 | 3 | 10 | 25 | Unlimited |
| Scans / month | 5 | 50 | 500 | 2,500 | Unlimited |
| Scheduled scans | 0 | 5 | 25 | 100 | Unlimited |
| Scheduled reports | 0 | 5 | 25 | 100 | Unlimited |
| Report retention | 7 days | 90 days | 1 year | 7 years | Unlimited |
| History days | 7 | 90 | 365 | 730 | Unlimited |
| API tokens | 0 | 0 | 5 | 20 | Unlimited |

---

## 4. Upgrade Path Analysis

The approved upgrade path is a single-driver model: each tier transition has one primary feature that pulls the customer forward. This is intentional — a single clear reason to upgrade is more effective than a bundle of reasons. Bundles create comparison paralysis.

### Free → Starter

**Primary driver: Business Risk Score**

| Signal | Mechanic |
|---|---|
| Customer has run scans but has no board-reportable output | BRS preview is visible but locked in Free — shows the grade, blurs the detail |
| Customer wants to automate monitoring | Scheduled scan prompt after third manual scan |
| Customer wants a downloadable deliverable | PDF report is locked behind Starter |

The conversion moment: the customer sees their BRS grade — A, B, C, D, or F — and immediately understands what it means. They do not need to read a findings list. They need to show this to someone. That is the Starter upgrade.

**Conversion message:** *"Your Business Risk Score is ready. Upgrade to Starter to unlock it and share it with your team."*

---

### Starter → Professional

**Primary driver: Cyber Essentials Readiness**

| Signal | Mechanic |
|---|---|
| Customer has a government contract application in progress | Cyber Essentials Readiness tab is visible but locked in Starter |
| Customer has a cyber insurance renewal approaching | In-app: "Is your renewal coming up? Check your Cyber Essentials readiness →" |
| Customer is a vCISO who needs a compliance deliverable for a client | Cyber Essentials gap report preview visible but locked |
| Customer wants BRS trend history and full category breakdown | BRS trend is Professional-only |

The conversion moment: the customer knows they need Cyber Essentials and realises CyberMeters replaces a consultant engagement. The locked Cyber Essentials tab should be the most visible upsell surface in the Starter product.

**Conversion message:** *"Find out if you'd pass Cyber Essentials — continuously, not just once."*

---

### Professional → Business

**Primary drivers: White-Label Reports + Portfolio Monitoring**

| Signal | Mechanic |
|---|---|
| Customer is managing a second client and needs separate workspaces | "Add workspace" is locked behind Business |
| Customer wants to remove CyberMeters branding from client reports | White-label option is locked in report settings |
| Customer wants a portfolio view across all clients | Portfolio dashboard is locked behind Business |
| vCISO wants bulk scheduled reports to all clients in one action | Bulk reporting is a Business workflow |

The conversion moment: the customer has a second client, opens report settings to white-label a PDF, and sees the upgrade prompt. Or they try to add a new workspace and hit the Professional limit.

**Conversion message:** *"Manage all your clients from one portfolio view and send reports under your brand."*

---

### Business → Enterprise

**Primary driver: MSP Dashboard**

| Signal | Mechanic |
|---|---|
| MSP is approaching the 25-workspace Business limit | Limit warning in portfolio dashboard |
| MSP needs SSO for team access management | SSO is Enterprise-only |
| MSP needs a contractual SLA for their clients | SLA only available at Enterprise |
| MSP needs custom limits negotiated per contract | Custom limits unlock at Enterprise |

Enterprise conversion is sales-assisted. Business customers approaching limits should trigger an outbound conversation, not just a self-service upgrade wall.

**Conversion message:** *"You're operating at scale. Enterprise gives you custom limits, SSO, and a dedicated support contact."*

---

## 5. Commercial Packaging Audit

### Alignment with the Billing Implementation Map

The `billing-implementation-map.md` defines the feature entitlement architecture. The approved commercial packaging aligns to it as follows:

| Entitlement Key | Approved Tier | Alignment |
|---|---|---|
| `business_risk_score` | Starter | Previously mapped to Professional in `billing-implementation-map.md` — **updated to Starter per approved decision** |
| `scheduled_scans` | Starter | Consistent |
| `basic_executive_reports` | Starter | Consistent |
| `cyber_essentials_readiness` | Professional | Consistent |
| `vendor_risk` | Professional | Consistent |
| `advanced_reports` | Professional | Consistent |
| `portfolio_monitoring` | Business | Consistent |
| `white_label_reports` | Business | Consistent |
| `extended_retention` | Business | Consistent (7yr at Business) |
| `msp_dashboard` | Enterprise | Consistent |

**Action required for engineering:** The `PLAN_FEATURES` map in `billing-implementation-map.md` must be updated to move `business_risk_score` from Professional to Starter before feature gating is implemented. The `hasFeatureEntitlement(plan, featureKey)` helper should reflect the approved placement above.

### Alignment with the Stripe Billing Architecture

The `stripe-billing-architecture-v1.md` defines 3 Stripe Products (Starter, Professional, Business). The approved pricing differs from the earlier recommended pricing in one respect:

| Plan | stripe-billing-architecture-v1.md | Approved |
|---|---|---|
| Starter | £49/month | **£29/month** |
| Professional | £149/month | £149/month |
| Business | £399/month | £399/month |

Stripe price IDs for Starter must be updated when Stripe products are created to reflect £29/month (monthly) and £23/month (annual equivalent / £276 billed annually). All other Stripe architecture decisions in `stripe-billing-architecture-v1.md` remain valid.

### Alignment with commercial-packaging-strategy-v1.md

The commercial packaging strategy document recommended £49/month for Starter. The approved decision is £29/month. This is a considered choice: positioning Starter closer to an impulse-purchase price point to maximise early adoption volume, with Professional at £149 as the primary revenue tier. This document supersedes the £49 Starter recommendation from the strategy document.

---

## 6. Revenue Rationale

### Why £29 for Starter

At £29/month, Starter sits at the threshold where a UK IT Manager can put it on a company card without a purchase order. It is budget-invisible — which is the right property for an entry-level plan designed to maximise adoption and build an install base.

The risk of £29 Starter is low revenue per customer, but this is offset by:
1. The Professional tier at £149 being the real revenue driver
2. Starter's purpose being install-base growth and trial conversion, not ARR
3. The upgrade path from Starter to Professional being the primary commercial conversion event

At £29/month, a customer who upgrades to Professional within 3 months contributes £87 in Starter revenue and then £149/month ongoing — the Starter price is essentially a trial fee paid at a low-friction level.

### Why £149 for Professional

Professional carries Cyber Essentials Readiness — the most commercially valuable feature in the product for the UK market. At £149/month, the annual cost is £1,428–£1,788. A single Cyber Essentials gap assessment from a consultant costs £500–£2,000 as a one-time engagement. Professional pays for itself against one avoided consultant engagement within 1–3 months.

Professional is where the majority of ARR will be generated in year one. The target Professional-to-total ratio should be at least 50% of paying customers.

### Why £399 for Business

Business is the MSP and vCISO tier. The MSP pricing logic: 25 client workspaces at £399/month = £16/client/month. MSPs bill security services to clients at £50–£200/client/month. The margin on CyberMeters Business for an MSP is 3–12x. At this margin, £399/month is not a cost conversation — it is an investment conversation.

### Revenue Scenarios

**Conservative Year 1 (75 paying customers):**

| Plan | Customers | Monthly | ARR |
|---|---|---|---|
| Starter | 40 | £1,160 | £13,920 |
| Professional | 25 | £3,725 | £44,700 |
| Business | 8 | £3,192 | £38,304 |
| Enterprise | 2 | £1,500 est. | £18,000 |
| **Total** | **75** | **£9,577** | **£114,924** |

**Target Year 1 mix:** Professional should be the modal plan. Free trials converting at 20% to Starter, Starter converting at 30% to Professional within 90 days, defines the target funnel shape.

---

## 7. Feature Entitlement Map

This is the canonical `PLAN_FEATURES` mapping for the `hasFeatureEntitlement(plan, featureKey)` helper. Engineering must align to this when implementing feature gating.

```
PLAN_FEATURES = {
  free: [],

  starter: [
    'business_risk_score',
    'scheduled_scans',
    'scheduled_reports',
    'executive_dashboard',
    'historical_tracking',
    'basic_executive_reports',
    'asset_change_events',
    'notifications',
  ],

  professional: [
    ...starter features...,
    'cyber_essentials_readiness',
    'vendor_risk',
    'saas_exposure',
    'third_party_risk',
    'advanced_executive_reports',
    'brs_trend_history',
    'brs_category_detail',
    'audit_trail',
    'extended_retention_1yr',
  ],

  business: [
    ...professional features...,
    'portfolio_monitoring',
    'white_label_reports',
    'multi_workspace_management',
    'vciso_workflows',
    'extended_retention_7yr',
    'api_access',
  ],

  enterprise: [
    ...business features...,
    'msp_dashboard',
    'custom_limits',
    'sso_saml',
    'priority_support',
    'dedicated_onboarding',
  ],
}
```

**Implementation note:** Do not gate Business Risk Score or Cyber Essentials Readiness until the Stripe billing lifecycle (Checkout → Webhooks → `subscription_accounts` sync → `getEffectivePlan()`) is stable in production. Add feature gates after billing is live, not before.

**Backend behaviour when a plan lacks a feature:**

```json
{
  "error": "feature_not_available",
  "feature": "cyber_essentials_readiness",
  "required_plan": "professional",
  "upgrade_message": "Upgrade to Professional to access Cyber Essentials Readiness."
}
```

Return with HTTP `403`. Frontend prompt must never be the only gate.

---

## 8. Rejected Proposals — Do Not Revisit

The following proposals were explicitly reviewed and rejected. They must not be re-introduced without a new commercial review cycle.

| Proposal | Decision | Reason |
|---|---|---|
| Starter at £9.90/month | **Rejected** | Consumer-grade pricing that kills B2B credibility and yields unsustainable ARR per customer |
| Starter at £49/month | **Rejected** | Replaced by £29/month to lower the impulse-purchase barrier for early adoption |
| Business Risk Score at Professional | **Rejected** | BRS is the primary Free→Starter driver; placing it at Professional removes the Starter value proposition |
| White-Label Reports at Enterprise | **Rejected** | Excludes the core MSP and vCISO segment from a feature they require; they will not buy Enterprise at this stage |
| Cyber Essentials Readiness at Starter | **Not proposed but excluded** | CE Readiness is the Professional anchor; moving it to Starter removes the primary Starter→Professional conversion driver |

---

## 9. Recommended Next Commercial Milestones

### Milestone 1 — Stripe Billing Foundation (Engineering, Next Sprint)

Implement the Stripe billing lifecycle so that the approved plan prices and feature entitlements can be enforced. Specifically:

- Migration 028: Add `stripe_customer_id`, `stripe_subscription_id`, `stripe_price_id`, `billing_interval`, `cancel_at_period_end` to `subscription_accounts`
- Migration 029: `invoice_records` table
- Migration 030: `stripe_webhook_events` idempotency table
- `POST /api/billing/checkout` — Stripe Checkout session at approved price points
- `POST /api/billing/portal` — Stripe Customer Portal for plan management
- `POST /api/webhooks/stripe` — webhook handler for subscription lifecycle
- Pricing page at `/pricing` with monthly/annual toggle
- Starter price: £29/month (£23/month annual). Professional: £149. Business: £399.

Reference: `docs/stripe-billing-architecture-v1.md` for full implementation specification. Update Stripe price guidance in that document to reflect £29 Starter.

---

### Milestone 2 — Feature Entitlement Gating (Engineering, After Billing is Live)

Implement `hasFeatureEntitlement(plan, featureKey)` based on the `PLAN_FEATURES` map in Section 7. Apply backend `403` gates to:

- `GET /api/workspaces/:id/business-risk` — require `business_risk_score` (Starter+)
- `GET /api/workspaces/:id/cyber-essentials-readiness` — require `cyber_essentials_readiness` (Professional+)
- `GET /api/workspaces/:id/vendors` — require `vendor_risk` (Professional+)
- `GET /api/portfolio/*` — require `portfolio_monitoring` (Business+)
- White-label report generation — require `white_label_reports` (Business+)

Do not implement feature gates before billing is live. Gating features that customers cannot yet pay to unlock creates friction with no commercial benefit.

---

### Milestone 3 — Pricing Page and Upgrade CTAs (Product + Engineering, Concurrent with Billing)

- Public `/pricing` page with the approved plan matrix, monthly/annual toggle, and feature comparison table
- Locked feature states in the UI (grayed-out BRS for Free, locked Cyber Essentials tab for Starter)
- In-app upgrade prompts at plan limits and locked feature surfaces
- UpgradeBanner component wired to `plan_limit_exceeded` and `feature_not_available` events

---

### Milestone 4 — Cyber Essentials as a Marketing Anchor (Marketing)

Cyber Essentials Readiness is the strongest UK-specific commercial differentiator in the product. Before Professional launches publicly:

- Landing page content: *"Find out if you'd pass Cyber Essentials — continuously, not just once."*
- Comparison page: CyberMeters Professional vs. one-time consultant gap assessment (cost and continuity)
- Target channels: UK government supplier communities, cyber insurance broker networks, IT trade press

This is the most effective route to first Professional conversions without paid acquisition.

---

### Milestone 5 — MSP / vCISO Partner Programme (Commercial, Q3 Target)

Before Business tier launches publicly:

- Dedicated `/business` or `/for-msps` landing page targeting the Portfolio Monitoring + White-Label value proposition
- vCISO and MSP messaging that speaks to the client delivery workflow, not the technical features
- Early partner programme: 5–10 MSPs and vCISOs onboarded at Business before public launch, used for case studies and product feedback
- Define the Enterprise criteria: when does a Business customer need to talk to sales?

---

### Milestone 6 — Annual Billing Default (Commercial, At Launch)

Default the pricing page to annual billing. Monthly should be the visible choice, not the default. Annual billing:

- Improves cash flow
- Reduces churn (annual customers do not cancel at card change)
- Increases ACV by 0% in price but creates upfront commitment

At the approved pricing: Starter annual = £276 upfront. Professional annual = £1,428 upfront. Business annual = £3,828 upfront.

---

*CyberMeters Platform — Final Commercial Packaging v1 — Approved — June 2026*  
*This document supersedes all previous packaging proposals. Do not reference prior pricing recommendations without noting this document as the current approved baseline.*
