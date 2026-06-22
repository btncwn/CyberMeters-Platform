# CyberMeters — Pricing Strategy v1

**Sprint 14 — Phase 1**
**Date:** June 2026
**Status:** Current strategy — based on features already implemented

---

## Positioning

CyberMeters is an external Attack Surface Management and Security Posture Management platform.
Target buyers: SMBs (direct), IT Managers, Security-conscious business owners, and MSPs (portfolio accounts).

Pricing is denominated in **GBP** and billed monthly or annually.
Annual billing provides approximately 20–22% savings.

---

## Plan Structure

| Plan         | Price (monthly) | Price (annual/mo equiv) | Target                             |
|--------------|----------------:|------------------------:|------------------------------------|
| Free         | £0              | £0                      | Evaluation / free-scan lead-gen    |
| Starter      | £29/mo          | £23/mo (£276/yr)        | SMBs, sole traders, small teams    |
| Professional | £149/mo         | £119/mo (£1,428/yr)     | Growing companies, IT managers     |
| Business     | £399/mo         | £319/mo (£3,828/yr)     | Large teams, portfolio operators   |
| Enterprise   | Custom          | Custom                  | MSPs, large enterprises            |

---

## Feature Map — Implemented Features Only

All features listed below exist in the current platform. No future features are referenced.

### Free

| Feature                      | Included |
|------------------------------|:--------:|
| External domain scan         | ✅        |
| DNS / SSL / Headers / Email analysis | ✅ |
| On-screen security score     | ✅        |
| Academy (all articles)       | ✅        |
| 1 workspace                  | ✅        |
| 3 domains per workspace      | ✅        |
| 1 user                       | ✅        |
| 5 scans per month            | ✅        |
| 30 days scan history         | ✅        |
| 90 days report retention     | ✅        |
| 1 API token                  | ✅        |
| Free scan page (/free-scan)  | ✅        |
| Scheduled scans              | ❌        |
| PDF reports                  | ❌        |
| Email alerts                 | ❌        |
| Team members                 | ❌        |
| Business Risk Score          | ❌        |

### Starter — £29/mo

Includes everything in Free, plus:

| Feature                              | Included |
|--------------------------------------|:--------:|
| 3 workspaces                         | ✅        |
| 10 domains per workspace             | ✅        |
| 3 users                              | ✅        |
| 100 scans per month                  | ✅        |
| 90 days scan history                 | ✅        |
| 5 scheduled scans per workspace      | ✅        |
| 3 scheduled reports per workspace    | ✅        |
| 50 reports per month                 | ✅        |
| PDF report export                    | ✅        |
| Email alert notifications            | ✅        |
| Business Risk Score                  | ✅        |
| 5 API tokens                         | ✅        |

### Professional — £149/mo

Includes everything in Starter, plus:

| Feature                                   | Included |
|-------------------------------------------|:--------:|
| 10 workspaces                             | ✅        |
| 100 domains per workspace                 | ✅        |
| 10 users                                  | ✅        |
| 1,000 scans per month                     | ✅        |
| 365 days scan history                     | ✅        |
| 2 years report retention                  | ✅        |
| 20 scheduled scans per workspace          | ✅        |
| 10 scheduled reports per workspace        | ✅        |
| 500 reports per month                     | ✅        |
| Cyber Essentials Readiness module         | ✅        |
| Vendor Risk Intelligence                  | ✅        |
| Executive Risk Dashboard                  | ✅        |
| Workspace Audit Logs                      | ✅        |
| 25 API tokens                             | ✅        |

### Business — £399/mo

Includes everything in Professional, plus:

| Feature                              | Included |
|--------------------------------------|:--------:|
| 50 workspaces                        | ✅        |
| 1,000 domains per workspace          | ✅        |
| 50 users                             | ✅        |
| 5,000 scans per month                | ✅        |
| 730 days (2 years) scan history      | ✅        |
| 7 years report retention             | ✅        |
| 100 scheduled scans per workspace    | ✅        |
| Portfolio Monitoring                 | ✅        |
| White Label PDF reports              | ✅        |
| 100 API tokens                       | ✅        |

### Enterprise — Custom

Includes everything in Business, plus:

| Feature                         | Included |
|---------------------------------|:--------:|
| Unlimited workspaces            | ✅        |
| Unlimited domains               | ✅        |
| Unlimited users                 | ✅        |
| Unlimited scans                 | ✅        |
| Unlimited history               | ✅        |
| Forever report retention        | ✅        |
| MSP Dashboard                   | ✅        |
| Priority support                | Planned  |
| Dedicated onboarding            | Planned  |
| Custom limits negotiated        | ✅        |

---

## Trial Strategy

**14-day free trial** on every new workspace.

- Trial plan: Professional (full feature access during trial)
- No credit card required to start trial
- Trial starts on workspace creation
- Trial end = trial_start + 14 days
- After trial: workspace reverts to Free plan limits
- Conversion CTA shown from day 1, escalated after day 10

**Trial conversion sequence:**
- Day 1: Welcome + trial start banner
- Day 10: "4 days left" warning banner
- Day 13: "Trial ends tomorrow" urgent banner
- Day 14: Trial end → Free plan limits enforced

---

## Conversion Funnel

```
/free-scan (anonymous)
    ↓ scan results
Create free account → /signup
    ↓ workspace auto-created
14-day Professional trial begins
    ↓ user sees full platform
Trial expires → Free plan
    ↓ hits a limit
Upgrade CTA → /billing → Stripe checkout
    ↓
Paid subscriber
```

---

## Pricing Rationale

**Free plan** exists purely for lead generation. The free scan + free account drives email capture and lets users verify CyberMeters works before committing. It is not designed to be a long-term destination.

**Starter** targets the price-sensitive SMB that needs scheduled monitoring and PDF reports for compliance evidence. £29/mo is designed to be an easy yes for any business with a website.

**Professional** is the primary revenue target. Cyber Essentials, Vendor Risk, and Executive Dashboards make this the right product for IT managers presenting to boards. The 10× price jump from Starter is justified by the compliance-readiness positioning.

**Business** serves portfolio operators managing multiple clients or domains. The portfolio monitoring feature is the key differentiator.

**Enterprise** is MSP-only. Custom pricing negotiated per account. MSP Dashboard is the differentiating feature.

---

## Key Decisions

1. **GBP pricing** — UK-centric initial market. Stripe handles FX for international customers.
2. **5 plans** rather than 3 — provides upsell staircase. Reduces price jump anxiety between free and paid.
3. **Annual discount** — 20–22% off. Standard SaaS. Creates 12-month commitment and improves LTV.
4. **Trial on Professional** — not Starter. Users experience the full platform during trial, making the post-trial downgrade to Free feel like a loss. This increases Starter/Professional conversion.
5. **No feature-locked landing page** — trial gives full access. Gates appear on expiry. This matches the product-led growth approach.

---

## What Is NOT in This Document

- Future features (SIEM, API integrations, remediation workflows)
- Per-domain pricing models
- Reseller / channel pricing
- Multi-region pricing tiers
- Volume discounts beyond annual

---

## Version History

| Version | Date      | Notes                                             |
|---------|-----------|---------------------------------------------------|
| v1      | June 2026 | Initial pricing strategy — implemented features only |
