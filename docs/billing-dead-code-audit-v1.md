# Billing Dead Code Audit v1

**Scope:** `workers/scan-api/src/index.js`
**Mode:** Read-only audit summary

## Summary

No duplicate billing routes were found.

The billing route set is singular:

- `GET /api/billing/plans`
- `POST /api/billing/webhook`
- `POST /api/billing/checkout`
- `POST /api/billing/portal`

No duplicate or shadowed billing route blocks were identified.

## `subscription_accounts` Runtime References

No runtime references to `subscription_accounts` were found in
`workers/scan-api/src/index.js`.

Runtime billing code uses `subscriptions` as the billing source of truth.

## Webhook Reachability

No unreachable webhook route was found.

There is a single active `POST /api/billing/webhook` route. It verifies the
Stripe signature, handles supported lifecycle events, and returns `5xx` on D1
synchronization failure so Stripe can retry.

## Retained Helper

`hasFeatureEntitlement(plan, featureKey)` is currently not used by runtime
feature gates.

It is intentionally retained for future Feature Enforcement v1. Removing it now
would create churn and provide little benefit because it is small, pure, and
aligned with the documented entitlement model.

## Plan Mapping Drift Risk

Plan metadata is currently represented across multiple structures:

- `PLAN_LIMITS`
- `PLAN_FEATURES`
- `BILLING_PLAN_METADATA`
- hard-coded plan ordering in public billing metadata

This is functional today, but future plan changes could drift if one map is
updated without the others.

Recommended future cleanup:

- Introduce a single shared `PLAN_KEYS` ordering constant.
- Add a lightweight consistency check or test to verify every plan key exists
  across `PLAN_LIMITS`, `PLAN_FEATURES`, and `BILLING_PLAN_METADATA`.

No cleanup was performed in this audit.
