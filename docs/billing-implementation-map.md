# Billing Implementation Map

This document maps the existing manual subscription foundation to the future
Stripe Billing Foundation sprint. It intentionally does not add Stripe code,
checkout sessions, webhooks, prices, or schema changes.

## Current Billing Tables

| Table | Source | Purpose |
| --- | --- | --- |
| `customer_profiles` | `database/migrations/016-customer-portal.sql` | Account-owned company/customer profile. |
| `subscription_accounts` | `database/migrations/016-customer-portal.sql` | Manual subscription foundation: owner, plan, status, billing provider, billing email, trial/current period dates. |
| `api_rate_limits` | `database/migrations/026-api-rate-limits.sql` | D1-backed burst rate limiting for scan starts. |
| `scheduled_reports` | `database/migrations/019-scheduled-reporting.sql` | Scheduled report configuration, limited by plan. |
| `scheduled_scans` | `database/schema.sql`, `database/migrations/006-scheduled-scans-workspace.sql` | Scheduled scan configuration, limited by plan. |
| `workspace_reports` | `database/migrations/010-workspace-reports.sql`, retention migrations | Report usage source for monthly report quota and retention. |
| `workspaces` | `database/migrations/003-workspaces.sql`, auth migrations | Account-owned workspace count for workspace quota. |
| `workspace_domains` | `database/migrations/003-workspaces.sql` | Domain count per workspace for domain quota. |
| `workspace_members` | `database/migrations/015-rbac.sql` | User/member count per workspace for member quota. |
| `scans` | base schema plus workspace attribution migration | Monthly scan usage source. |
| `api_tokens` | `database/migrations/018-api-tokens.sql` | API token count enforcement. |

## Existing Plan Helpers

All current plan enforcement is centralized in `workers/scan-api/src/index.js`.

| Helper | Purpose |
| --- | --- |
| `PLAN_LIMITS` | Defines limits for `free`, `starter`, `professional`, `business`, and `enterprise`. |
| `normalizePlan(plan)` | Normalizes unknown or missing plans to `free`. |
| `getEffectivePlan(userId, env)` | Resolves active manual subscription; cancelled, expired, or period-ended accounts fall back to `free`. |
| `getPlanLimits(plan)` | Returns limit object and backward-compatible aliases. |
| `getPlanContext(user, env)` | Returns `{ plan, limits, usage }` for account UI/API. |
| `getAccountUsage(userId, env)` | Counts owned workspaces, domains, and members. |
| `getEntitlementUsage(user, env, workspaceId)` | Counts account and workspace-scoped usage, including API tokens, scheduled reports, scheduled scans, reports, and scans. |
| `planLimitExceeded(resource, limit, usage)` | Structured quota error payload. |
| `checkScanLimit(user, workspaceId, env)` | Monthly scan quota by billing owner. |
| `consumeApiRateLimit(env, scopes, action, limit)` | Burst scan-start rate limiting by user, workspace, and billing account. |
| `checkReportLimit(user, workspaceId, env)` | Monthly report quota. |
| `checkScheduledScanLimit(user, workspaceId, env)` | Enabled scheduled scan quota. |
| `getReportRetentionPolicyForWorkspace(workspaceId, env)` | Maps account plan to report retention policy. |

## Existing Billing Endpoints

| Endpoint | Current State |
| --- | --- |
| `GET /api/account/profile` | Returns account, company, and manual subscription. |
| `PATCH /api/account/profile` | Updates name only. |
| `GET /api/account/company` | Reads customer profile. |
| `PUT /api/account/company` | Creates/updates customer profile. |
| `GET /api/account/subscription` | Returns manual subscription foundation. |
| `GET /api/account/usage` | Returns `{ plan, limits, usage }`. |
| `GET /api/account/subscription/limits` | Backward-compatible usage/limits alias. |
| `GET /api/admin/subscriptions` | Admin-only subscription/customer list. |

## Current Quota Enforcement

| Resource | Status | Enforcement Point |
| --- | --- | --- |
| Workspaces | Enforced | `POST /api/workspaces` checks `workspaces` limit. |
| Domains | Enforced | `POST /api/workspaces/:id/domains` and `POST /api/workspaces/:id/domains/import` check per-workspace domain limit. |
| Users | Enforced | Direct member add, invitation create, and invitation accept check per-workspace user limit. |
| Scans | Enforced | `POST /api/scan` checks monthly scan quota before scan creation. |
| Scan burst rate | Enforced | `POST /api/scan` uses `api_rate_limits` by user, workspace, and billing account. |
| Reports | Enforced | `POST /api/workspaces/:id/reports/generate` checks monthly report quota. |
| Scheduled scans | Enforced | `POST /api/schedules` checks enabled scheduled scan count. |
| Scheduled reports | Enforced | `POST /api/workspaces/:id/scheduled-reports` checks enabled scheduled report count per workspace. |
| API tokens | Enforced | `POST /api/account/api-tokens` checks active API token count. |
| Report retention | Enforced | Report generation/cleanup uses plan-derived retention policy. |
| History days | Defined only | `history_days` exists in plan limits and UI, but no audited query-level enforcement was found in this pass. |

## Feature Entitlement Model

CyberMeters currently handles numeric usage limits well. Future paid-plan
features need a separate feature entitlement model so the product can distinguish
between "how many" and "whether this capability is available."

Usage limits are numeric quotas:

- `5` domains
- `100` scans per month
- `25` users
- `3` reports per month

Feature entitlements are boolean capabilities:

- Business Risk Score enabled or disabled
- Cyber Essentials Readiness enabled or disabled
- White-label reports enabled or disabled

Recommended future helper:

```js
hasFeatureEntitlement(plan, featureKey)
```

For v1, feature entitlements should be represented in code as a static
plan-feature map:

```js
const PLAN_FEATURES = {
  free: [],
  starter: [],
  professional: [],
  business: [],
  enterprise: [],
}
```

Do not create an entitlements table yet. A D1 entitlement table would be
premature before Stripe checkout, customer portal, webhook lifecycle, and
`subscription_accounts` sync are stable in production.

Recommended feature keys:

- `business_risk_score`
- `cyber_essentials_readiness`
- `executive_reports`
- `portfolio_monitoring`
- `vendor_risk`
- `white_label_reports`
- `msp_dashboard`

Recommended plan mapping:

| Plan | Feature Entitlements |
| --- | --- |
| Free | Basic scans and basic reports. |
| Starter | `scheduled_scans`, `basic_executive_reports` |
| Professional | `business_risk_score`, `cyber_essentials_readiness`, `vendor_risk`, `advanced_reports` |
| Business | `portfolio_monitoring`, `white_label_reports`, `extended_retention` |
| Enterprise | `msp_dashboard`, `custom_limits`, `priority_support` |

Business Risk Score and Cyber Essentials Readiness are key product
differentiators. They should remain visible until:

- Stripe Checkout is live.
- Customer Portal is live.
- Webhooks are syncing `subscription_accounts` reliably.
- `getEffectivePlan()` is proven stable in production.

Only then should Professional gating be added.

Recommended API behavior when a user lacks a feature:

```json
{
  "error": "feature_not_available",
  "feature": "business_risk_score",
  "required_plan": "professional",
  "upgrade_message": "Upgrade to Professional to access Business Risk Score."
}
```

Return this with HTTP `403`.

Frontend hiding is not sufficient. When feature gates are later implemented,
backend endpoints such as `GET /api/workspaces/:id/business-risk` and
`GET /api/workspaces/:id/cyber-essentials-readiness` must return structured
HTTP `403` responses if the effective plan lacks access.

Implementation guidance:

- `getEffectivePlan()` must remain the canonical plan resolver.
- Stripe webhooks should only update `subscription_accounts`.
- Application logic should never depend directly on Stripe objects.
- Feature entitlement checks should be added after Stripe checkout/webhook lifecycle is stable.
- Do not gate Business Risk Score or Cyber Essentials until billing is live.

Stripe must never be the runtime source of truth for application behavior.
Correct flow:

```text
Stripe
-> subscription_accounts
-> getEffectivePlan()
-> PLAN_LIMITS / PLAN_FEATURES
-> application behavior
```

Avoid this pattern:

```text
API request
-> Stripe API lookup
-> runtime plan decision
```

Recommended implementation order:

1. Stripe Billing Foundation
2. Checkout + Customer Portal
3. Webhook lifecycle
4. `subscription_accounts` sync
5. `PLAN_FEATURES` helper
6. `hasFeatureEntitlement(plan, featureKey)`
7. Backend feature gates
8. Frontend upgrade prompts

## Frontend Billing Surface

Existing:

- `frontend/src/pages/AccountPage.jsx`: account profile, company, subscription, plan usage, API tokens.
- `frontend/src/pages/SettingsPage.jsx`: account/company/subscription details and plan usage.
- `frontend/src/components/Layout.jsx`: global plan-limit modal via `cybermeters:plan-limit`.
- `frontend/src/api.js`: account, subscription, usage, and admin subscription methods.

Missing for Stripe foundation:

- Dedicated billing route, for example `/billing` or `/account/billing`.
- Billing page for plan comparison, current subscription, invoices placeholder, and checkout/customer portal actions.
- Upgrade CTA destinations wired from account/settings/plan-limit modal.
- Admin subscription detail page or plan override UI.
- Frontend API methods for future checkout session, customer portal session, and webhook-visible subscription state refresh.

## Professional Gating Candidates

Business Risk Score and Cyber Essentials Readiness should be Professional-gated
later, but not in this audit sprint.

Recommended entitlement keys:

- `business_risk_score`
- `cyber_essentials_readiness`

Recommended behavior:

- Backend remains source of truth.
- Free/Starter should return structured `plan_limit_exceeded` or
  `feature_not_available` style responses once a feature-entitlement helper
  exists.
- Frontend should show an upgrade prompt instead of raw API errors.

## Stripe Implementation File Map

Backend:

- `workers/scan-api/src/index.js`
  - Add Stripe customer/session/webhook helpers.
  - Add checkout session route.
  - Add customer portal session route.
  - Add webhook route before auth-only API routes.
  - Map Stripe subscription status into `subscription_accounts`.
  - Keep `getEffectivePlan()` as the canonical plan resolver.

Database:

- Future migration only when approved.
  - Add Stripe customer/subscription identifiers to `subscription_accounts`.
  - Add webhook event dedupe table if needed.
  - Do not replace the manual foundation table.

Frontend:

- `frontend/src/api.js`
  - Add checkout/customer portal methods.
- `frontend/src/App.jsx`
  - Add billing route.
- `frontend/src/components/Layout.jsx`
  - Wire upgrade CTA to billing route.
- `frontend/src/pages/AccountPage.jsx`
  - Link existing upgrade card to billing route.
- New `frontend/src/pages/BillingPage.jsx`
  - Plan comparison, current plan, checkout button, customer portal button.

Configuration:

- Worker environment bindings/secrets:
  - `STRIPE_SECRET_KEY`
  - `STRIPE_WEBHOOK_SECRET`
  - Stripe price IDs per plan.
- Frontend environment:
  - No Stripe secret values.
  - Public price copy only if needed.

Validation:

- `node --check workers/scan-api/src/index.js`
- `node scripts/validate-regression-fixtures.js`
- `cd frontend && npm ci && npm run build`

## Recommended Next Sprint

Implement Stripe Billing Foundation v1:

1. Add approved migration for Stripe identifiers and webhook event dedupe.
2. Add Stripe config validation and price ID mapping.
3. Add authenticated checkout session route.
4. Add authenticated customer portal session route.
5. Add webhook route for subscription created, updated, deleted, and invoice payment state.
6. Keep `subscription_accounts` as the source table consumed by `getEffectivePlan()`.
7. Add Billing page and wire upgrade CTAs.
8. After Stripe lifecycle is stable, add Feature Entitlements v1.
9. Add Professional gating for Business Risk Score and Cyber Essentials only after checkout/webhook lifecycle is stable and upgrade prompts are ready.
