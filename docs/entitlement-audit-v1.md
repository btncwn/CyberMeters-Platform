# CyberMeters — Entitlement & Plan Enforcement Audit v1

**Sprint:** Entitlement & Plan Enforcement Audit  
**Date:** June 2026  
**Type:** Audit only — no code changes  
**Scope:** Free, Starter, Professional, Business, Enterprise

---

## 1. Complete Entitlement Matrix

### 1.1 Quota Limits (PLAN_LIMITS — index.js ~16547)

| Resource | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| Workspaces | 1 | 3 | 10 | 50 | Unlimited |
| Domains (per workspace) | 3 | 10 | 100 | 1,000 | Unlimited |
| Users (per workspace) | 1 | 3 | 10 | 50 | Unlimited |
| Scans / month | 5 | 100 | 1,000 | 5,000 | Unlimited |
| Scan starts / hour | 5 | 20 | 100 | 300 | Unlimited |
| Reports / month | 3 | 50 | 500 | 2,000 | Unlimited |
| Scheduled scans | 0 | 5 | 20 | 100 | Unlimited |
| History (days) | 30 | 90 | 365 | 730 | Unlimited |
| API tokens | 1 | 5 | 25 | 100 | Unlimited |

### 1.2 Feature Gates (PLAN_FEATURES — index.js ~16620)

| Feature | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| Scheduled scans | ❌ | ✅ | ✅ | ✅ | ✅ |
| Alerts (email / in-app) | ❌ | ✅ | ✅ | ✅ | ✅ |
| PDF report export | ❌ | ✅ | ✅ | ✅ | ✅ |
| Multiple workspaces | ❌ | ✅ | ✅ | ✅ | ✅ |
| Team member invitations | ❌ | ✅ | ✅ | ✅ | ✅ |
| Business Risk Score | ❌ | ✅ | ✅ | ✅ | ✅ |
| Cyber Essentials Readiness | ❌ | ❌ | ✅ | ✅ | ✅ |
| Vendor Risk Intelligence | ❌ | ❌ | ✅ | ✅ | ✅ |
| Executive Risk Dashboard | ❌ | ❌ | ✅ | ✅ | ✅ |
| Workspace Audit Logs | ❌ | ❌ | ✅ | ✅ | ✅ |
| Portfolio Monitoring | ❌ | ❌ | ❌ | ✅ | ✅ |
| White Label Reports | ❌ | ❌ | ❌ | ✅ | ✅ |
| MSP Dashboard | ❌ | ❌ | ❌ | ❌ | ✅ |

### 1.3 Pricing

| Plan | Monthly | Annual (total) | Annual (per-month equivalent) |
|---|---|---|---|
| Free | £0 | £0 | £0 |
| Starter | £29 | £276 | £23 |
| Professional | £149 | £1,428 | £119 |
| Business | £399 | £3,828 | £319 |
| Enterprise | Custom | Custom | Custom |

Stripe products: Starter, Professional, Business. Each has monthly and annual prices. Enterprise and Free have no Stripe products.

---

## 2. Backend Enforcement Map

### 2.1 Quota Enforcement

| Resource | Enforcement Route | Status | Notes |
|---|---|---|---|
| Scans / month | `POST /api/workspaces/:id/scans` via `checkScanLimit()` | ✅ Enforced | |
| Scan starts / hour | Same route via `consumeApiRateLimit()` | ✅ Enforced | |
| Reports / month | PDF report generation route via `checkReportLimit()` | ✅ Enforced | |
| Scheduled scans | `POST /api/workspaces/:id/scheduled-scans` via `checkScheduledScanLimit()` | ✅ Enforced | |
| Workspaces | `POST /api/workspaces` via `planLimitExceeded("workspaces")` | ✅ Enforced | |
| Domains (explicit add) | `POST /api/workspaces/:id/domains` | ✅ Enforced | Uses `domains_per_workspace` alias |
| Domains (bulk import) | `POST /api/workspaces/:id/domains/import` | ✅ Enforced | Trims list to remaining capacity |
| **Domains (via scan)** | `POST /api/workspaces/:id/scans` | ❌ **NOT ENFORCED** | Domain auto-created on scan — bypasses domain limit |
| Users / members (direct invite) | `POST /api/workspaces/:id/members` | ✅ Enforced | |
| Users / members (invite accept) | `POST /api/workspaces/:id/invitations/accept` | ✅ Enforced | |
| API tokens | `POST /api/account/api-tokens` | ✅ Enforced | |
| Report retention | Cleanup job via `getReportRetentionPolicyForWorkspace()` | ✅ Enforced | Purges R2 objects and soft-deletes DB rows |
| Scan history | No enforcement found | ❓ Unknown | History days limit defined but no cleanup job confirmed for scans |

### 2.2 Feature Gate Enforcement

| Feature Key | Enforced At | Status |
|---|---|---|
| `business_risk_score` | 3 Worker routes (BRS compute, BRS API, report export) | ✅ Enforced |
| `cyber_essentials` | 1 Worker route (Cyber Essentials report route) | ✅ Enforced |
| `vendor_risk` | 2 Worker routes (vendor risk analysis) | ✅ Enforced |
| `executive_dashboard` | 1 Worker route (executive dashboard API) | ✅ Enforced |
| `audit_logs` | 1 Worker route (audit log API) | ✅ Enforced |
| `portfolio_monitoring` | 1 Worker route (portfolio API) | ✅ Enforced |
| `scheduled_scans` | Not enforced at route level | ❌ **NOT ENFORCED** | Gate defined but only the numeric quota (0 for free) blocks creation |
| `alerts` | Not enforced at any route | ❌ **NOT ENFORCED** | Free users can configure alerts |
| `pdf_reports` | Not enforced at route level | ❌ **NOT ENFORCED** | Only monthly quota enforced, not the feature gate |
| `multi_workspace` | Not enforced at route level | ❌ **NOT ENFORCED** | Only the workspaces quota (1 for free) blocks creation |
| `team_members` | Not enforced at route level | ❌ **NOT ENFORCED** | Only the users quota (1 for free) blocks creation |
| `white_label` | Not enforced at any route | ❌ **NOT ENFORCED** | No route found that checks this gate |
| `msp_dashboard` | Not enforced at any route | ❌ **NOT ENFORCED** | No route found that checks this gate |

---

## 3. Pricing Page vs. Backend Mismatch Report

### 3.1 Fallback Copy Mismatches (PricingPage.jsx `FALLBACK_PLANS`)

The fallback plan copy is shown when the `/api/plans` endpoint is unavailable. It contains limits that do not match the backend.

| Plan | Fallback Copy | Backend Enforcement | Verdict |
|---|---|---|---|
| Starter | "5 workspaces" | `PLAN_LIMITS.starter.workspaces = 3` | ❌ **MISMATCH — overpromises by 2 workspaces** |
| Starter | "25 domains" | `PLAN_LIMITS.starter.domains = 10` | ❌ **MISMATCH — overpromises by 15 domains** |
| Professional | "Business Risk Score, Cyber Essentials Readiness, Vendor Risk" | Matches PLAN_FEATURES | ✅ |
| Business | "Portfolio Monitoring, White-label reports, Extended retention" | Matches PLAN_FEATURES | ✅ |

**Risk:** When `/api/plans` is unreachable (network error, cold start, Stripe misconfiguration), customers see incorrect limits on the pricing page. A customer purchasing Starter based on "5 workspaces / 25 domains" would immediately hit enforcement at 3 workspaces / 10 domains. This is a commercial dispute risk and a trust violation.

### 3.2 Live Pricing Response (when API is healthy)

When the API responds, `PricingPage.jsx` renders from `plan.limits` keys via `planFeatures()`. This path correctly derives feature bullets from backend limit values, so no mismatch exists on this path.

### 3.3 Annual Pricing Representation

`SubscriptionPage.jsx` (`PLAN_META`) shows per-month equivalents for annual pricing (e.g., £23/mo for Starter annual). `PricingPage.jsx` shows annual totals (e.g., £276/yr for Starter annual). Both figures are mathematically correct (£23 × 12 = £276) but the representations differ across two customer-facing pages. A customer comparing the billing page to the pricing page could perceive a discrepancy.

---

## 4. Frontend Display Issues

### 4.1 Billing Page Feature Checklist (`SubscriptionPage.jsx`)

`GATE_DISPLAY` renders 11 feature keys. Two keys from `PLAN_FEATURES` are missing:

| Missing Key | Plan that includes it | Impact |
|---|---|---|
| `white_label` | Business, Enterprise | Business customers cannot see "White Label Reports" on their billing page |
| `msp_dashboard` | Enterprise | Enterprise customers cannot see "MSP Dashboard" on their billing page |

**Effect:** Business customers paying £399/mo do not see confirmation of the white label feature they purchased. This reduces perceived value and may generate support queries.

### 4.2 Billing Page Limits Grid

`LimitsGrid` renders: Workspaces, Domains, Users, Scans/month, Scheduled scans, History (days). Not shown: Reports/month, Scan starts/hour, API tokens. These omissions are acceptable — the grid shows the most customer-visible limits.

---

## 5. Trial Behavior

- **Duration:** 14 days (defined as `TRIAL_DURATION_DAYS = 14`)
- **Plan:** Professional (`TRIAL_PLAN = "professional"`)
- **Trigger:** Auto-created when workspace is created
- **Limits during trial:** Full Professional limits apply
- **Expiry:** Plan falls back to free; no grace period documented
- **Downgrade enforcement:** Not immediate — existing resources created during trial are not removed. Domain count, workspace count, member count are only checked at creation time.

**Example:** A user on trial creates 3 workspaces (Professional limit: 10). After trial, they are on Free (limit: 1). All 3 workspaces remain accessible. Future workspace creation is blocked at 1, but the 3 existing ones are not locked. This is the correct behavior per Rule 5 (Historical Data Is Sacred).

---

## 6. Downgrade & Upgrade Edge Cases

### Downgrade
- No enforcement of existing resource counts on plan downgrade
- Correct per Rule 5 — resources are preserved, creation is blocked going forward
- No warning shown to the customer about what will be restricted after downgrade

### Upgrade
- Limits increase immediately when subscription is activated via Stripe webhook → `subscriptions` table update → `getEffectivePlan()` reads new plan on next request
- Feature gates become available immediately post-webhook

### Over-Limit on Downgrade (not enforced — by design)
The following scenarios produce a state where existing resources exceed new plan limits. No enforcement applies to existing data:
- Starter customer (10 domains) downgrades to Free (3 domains): existing domains remain
- Professional customer (5 workspaces) downgrades to Starter (3 workspaces): existing workspaces remain
- These are acceptable per platform rules but should be communicated to the customer

---

## 7. Revenue Leakage Risks

| Risk | Severity | Description |
|---|---|---|
| Domain bypass via scan | **HIGH** | Scanning a new domain auto-creates a domain row without checking the domain quota. A Free user is limited to 3 domains but can scan unlimited distinct domains. Each scan creates a new domain record. This is the primary quota bypass path. |
| Fallback pricing copy | **HIGH** | Customers are shown 5 workspaces / 25 domains for Starter when the API is down, but enforcement allows only 3 / 10. Creates refund risk and support burden. |
| alerts gate unenforced | **MEDIUM** | Free users can configure notification preferences. The feature is defined as Starter+ but no route blocks it. |
| scheduled_scans gate unenforced | **LOW** | Free users are blocked by the `scheduled_scans = 0` quota, making the gate redundant. However, if a bug temporarily sets quota to a non-zero value, free users would gain the feature. |
| white_label gate unenforced | **LOW** | No route enforces the white label gate. However, the white label UI is not built out yet, so there is no functional exposure currently. |
| msp_dashboard gate unenforced | **LOW** | Same as white_label — no enforcement, but feature is not yet accessible in practice. |
| History days unenforced for scans | **LOW** | Report retention is enforced by cleanup job. Scan retention has no confirmed cleanup job. Free users may accumulate scan history beyond 30 days. |

---

## 8. Beta Blockers

These issues must be resolved before commercial launch:

| # | Issue | Blocking Reason |
|---|---|---|
| BB-1 | **Fallback pricing copy mismatches backend limits** | Customer could purchase Starter based on "5 workspaces / 25 domains" and immediately be limited to 3 / 10. Commercial dispute risk. |
| BB-2 | **Domain bypass via scan creation** | Primary quota bypass. Domain limit enforcement is the commercial boundary for plan upsell, yet it can be circumvented by scanning new domains rather than explicitly adding them. |
| BB-3 | **white_label missing from billing page** | Business customers (£399/mo) cannot see their purchased feature on the billing confirmation page. Trust and value-perception issue. |

---

## 9. Prioritized Remediation Plan

### Priority 1 — Fix before beta (blocking)

**P1-A: Fix fallback pricing copy in PricingPage.jsx**
- Update `FALLBACK_PLANS` Starter to: `"3 workspaces, 10 domains, Scheduled scans"`
- This is a copy change only. No backend change required.
- Risk: None. Corrects false advertising.

**P1-B: Enforce domain limit on scan creation**
- In `POST /api/workspaces/:id/scans`, after line 21529 (`resolvedDomainId` is determined), add a domain limit check only when `!existingDomain`.
- Pattern already exists at lines 27944–27951 (`POST /api/workspaces/:id/domains`).
- Risk: Low. Only blocks new domain creation — rescanning existing domains is unaffected.

### Priority 2 — Fix before public launch (high value)

**P2-A: Add `white_label` to SubscriptionPage GATE_DISPLAY**
- Add `{ key: 'white_label', icon: FileText, label: 'White-label reports' }` to `GATE_DISPLAY`.
- This makes Business customers see the feature they purchased.
- Risk: None. Display-only change.

**P2-B: Reconcile annual pricing representation**
- Standardize both pages to show annual totals (e.g., £276/yr) or both show monthly equivalents (£23/mo).
- Recommended: SubscriptionPage shows the annual total to match what Stripe charges.

### Priority 3 — Post-launch improvements

**P3-A: Enforce `alerts` feature gate**
- Add `canUseFeature(user, 'alerts')` check on the notification preferences routes.
- Free users cannot configure alerts.

**P3-B: Confirm or implement scan history retention**
- Verify whether a cleanup job exists for scan rows older than `history_days`.
- If not, implement one similar to the report retention cleanup job.

**P3-C: Add `msp_dashboard` to SubscriptionPage GATE_DISPLAY**
- When the MSP dashboard is built, add display entry so Enterprise customers can see it.

**P3-D: Surface downgrade impact to customer**
- Before downgrade checkout, show customer which limits will apply.
- Does not require blocking existing resources — just communication.

---

## 10. Summary

| Category | Count | Detail |
|---|---|---|
| Quotas confirmed enforced | 10 | Scans/month, scans/hour, reports/month, scheduled scans, workspaces, domains (2 explicit routes), members (2 routes), API tokens |
| Quota enforcement gaps | 2 | Domains via scan (bypass), scan history retention (unconfirmed) |
| Feature gates enforced | 6 | business_risk_score, cyber_essentials, vendor_risk, executive_dashboard, audit_logs, portfolio_monitoring |
| Feature gates not enforced | 7 | scheduled_scans (quota blocks), alerts, pdf_reports (quota blocks), multi_workspace (quota blocks), team_members (quota blocks), white_label, msp_dashboard |
| Pricing copy mismatches | 2 | Starter workspaces (5 vs 3), Starter domains (25 vs 10) |
| Billing page display gaps | 2 | white_label, msp_dashboard not shown |
| Beta blockers | 3 | BB-1 fallback copy, BB-2 domain bypass, BB-3 white_label display |
| Revenue leakage risks | 2 HIGH | Domain bypass via scan, fallback copy mismatch |

The platform enforcement posture is strong for the commercially sensitive quotas (scans, reports, workspaces). The two highest-risk gaps are the domain bypass path and the fallback pricing copy. Both are simple, targeted fixes with no architectural impact.

---

*Audit conducted against index.js, PricingPage.jsx, SubscriptionPage.jsx, and docs/stripe-env-setup-v1.md. No code changes made.*
