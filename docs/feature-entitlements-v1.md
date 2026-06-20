# Feature Entitlements v1

Feature Entitlements v1 is the internal foundation for future paid-plan feature
gating. It does not add Stripe, checkout, webhooks, migrations, frontend billing
pages, or runtime feature gates.

## Purpose

CyberMeters already has numeric usage limits for resources such as workspaces,
domains, scans, reports, scheduled scans, scheduled reports, users, and API
tokens.

Feature entitlements model boolean product capabilities, for example whether a
plan includes Business Risk Score or Cyber Essentials Readiness.

## PLAN_FEATURES

For v1, feature entitlements are represented in code as a static map:

```js
const PLAN_FEATURES = {
  free: [],
  starter: [
    "business_risk_score",
  ],
  professional: [
    "business_risk_score",
    "cyber_essentials",
    "vendor_risk",
  ],
  business: [
    "business_risk_score",
    "cyber_essentials",
    "vendor_risk",
    "portfolio_monitoring",
    "white_label",
  ],
  enterprise: [
    "business_risk_score",
    "cyber_essentials",
    "vendor_risk",
    "portfolio_monitoring",
    "white_label",
    "msp_dashboard",
  ],
}
```

There is no D1 entitlement table in v1. A database-backed entitlement model would
be premature before Stripe checkout, customer portal, webhook lifecycle, and
`subscription_accounts` sync are stable.

Current implementation table is `subscriptions`. Earlier architecture docs may
refer to `subscription_accounts` as the conceptual billing account table.

## Helper Functions

`getPlanFeatures(plan)`

- Pure function.
- Normalizes unknown plans to `free`.
- Returns a copy of the feature array for the plan.
- Does not read D1.
- Does not call Stripe.

`hasFeatureEntitlement(plan, featureKey)`

- Pure function.
- Returns `true` when the normalized plan includes the feature key.
- Returns `false` for missing, invalid, or unknown feature keys.
- Does not read D1.
- Does not call Stripe.

`getEffectivePlan(userId, env)` remains the canonical plan resolver. Application
logic should resolve the effective plan first, then pass that plan into the
feature helpers.

## Read-Only Metadata Endpoint

`GET /api/account/subscription/features`

Returns:

```json
{
  "plan": "starter",
  "features": [
    "business_risk_score"
  ]
}
```

This endpoint is informational only. It does not enforce gates and does not
change subscription behavior.

## Future Gating Strategy

Feature gates should be added only after:

1. Stripe Checkout is live.
2. Customer Portal is live.
3. Stripe webhooks reliably sync `subscription_accounts`.
4. `getEffectivePlan()` is proven stable in production.
5. Upgrade prompts are ready in the frontend.

Business Risk Score and Cyber Essentials Readiness must not be gated before the
billing lifecycle is stable.

## Backend Enforcement Requirements

Frontend hiding is not sufficient. When feature gates are implemented, backend
routes must enforce entitlements using the effective plan.

Example future response:

```json
{
  "error": "feature_not_available",
  "feature": "business_risk_score",
  "required_plan": "starter",
  "upgrade_message": "Upgrade to Starter to access Business Risk Score."
}
```

Return this with HTTP `403`.

Candidate future route gates:

- `GET /api/workspaces/:id/business-risk` -> `business_risk_score`
- `GET /api/workspaces/:id/cyber-essentials-readiness` -> `cyber_essentials`
- `GET /api/workspaces/:id/vendors` -> `vendor_risk`
- Portfolio routes -> `portfolio_monitoring`
- White-label report rendering -> `white_label`

## Stripe Source of Truth Boundary

Stripe must not be the runtime source of truth for application behavior.

Correct flow:

```text
Stripe
-> subscription_accounts
-> getEffectivePlan()
-> PLAN_LIMITS / PLAN_FEATURES
-> application behavior
```

Avoid:

```text
API request
-> Stripe API lookup
-> runtime plan decision
```

## Upgrade Path

Commercial placement:

- Free: no paid feature entitlements.
- Starter: Business Risk Score.
- Professional: Cyber Essentials Readiness and Vendor Risk.
- Business: Portfolio Monitoring and White Label.
- Enterprise: MSP Dashboard.

Recommended implementation order:

1. Stripe Billing Foundation.
2. Checkout + Customer Portal.
3. Webhook lifecycle.
4. `subscription_accounts` sync.
5. `PLAN_FEATURES` helper.
6. `hasFeatureEntitlement(plan, featureKey)`.
7. Backend feature gates.
8. Frontend upgrade prompts.
