# Worker Modularization Plan

This is a planning document only. It does not authorize a large refactor of `workers/scan-api/src/index.js` in the current sprint.

## Current Function Groups

The Worker currently combines several major ownership areas in one file:

- Utilities and crypto helpers: IDs, token hashing, password hashing, safe fetch, JSON/CORS helpers.
- Authentication and sessions: login, logout, `requireAuth`, API token helper.
- RBAC and tenant isolation: workspace membership, role ranking, route permission checks.
- Scan modules: DNS, SSL, headers, email security, subdomains, exposure, CVE/KEV, enrichment, inventory updates.
- Scoring and recommendations: `computeScore`, risk intelligence, remediation prioritization.
- Reporting: PDF/report generation, report archive, scheduled reports, retention cleanup.
- Workspace intelligence APIs: scorecard, assets, vendors, certificates, SaaS exposure, admin surfaces, brand monitoring.
- Portfolio APIs: overview, workspace risk table, alerts, trends.
- Billing and entitlements: plan resolution, plan limits, quota checks, usage APIs.
- Accuracy and validation: evidence quality, regression fixture evaluation, platform accuracy metrics.
- Route dispatcher: all HTTP route matching and response handling.

## Recommended Future Module Boundaries

- `src/modules/auth.js`: password/session/token helpers, auth routes, API token auth.
- `src/modules/rbac.js`: role hierarchy, permission mapping, membership helpers.
- `src/modules/scan-engine.js`: `runScanEngine`, scan module orchestration, scan quality.
- `src/modules/scoring.js`: `computeScore`, evidence validation, risk level calculation.
- `src/modules/reporting.js`: report generation, report CRUD, retention cleanup, scheduled report generation.
- `src/modules/portfolio.js`: portfolio overview/workspaces/alerts/trends.
- `src/modules/workspace-intelligence.js`: workspace scorecard, assets, vendors, certificates, SaaS, admin surfaces, brand monitoring.
- `src/modules/billing-entitlements.js`: plan resolver, plan limits, usage counters, quota and rate-limit helpers.
- `src/modules/accuracy.js`: regression fixtures, accuracy metrics, evidence quality helpers.
- `src/modules/utils.js`: `createId`, `safeFetch`, DNS helpers, CORS/JSON helpers.

## Dependency Risks

- `computeScore` depends on module output shapes from many scan modules. Moving it before contracts are documented can cause subtle scoring drift.
- `runScanEngine` mutates `modules` across many phases and writes to R2/D1. It should be moved only after small pure helpers are extracted.
- Route handlers rely on shared auth/RBAC/entitlement helpers and often assume local function scope.
- Reporting and scorecard share report JSON structure. Extraction must preserve R2 report compatibility.
- D1 bindings are currently passed as `env`; extracted modules should receive `env` explicitly to avoid hidden globals.

## Suggested Extraction Order

1. `utils.js`: pure helpers with no route dependencies.
2. `accuracy.js`: evidence quality and regression fixture helpers.
3. `billing-entitlements.js`: plan limits, usage counters, quota/rate-limit helpers.
4. `rbac.js`: role and membership helpers.
5. `auth.js`: auth helpers after RBAC dependencies are explicit.
6. `scoring.js`: `computeScore` after scan module output fixtures are stable.
7. Route groups: portfolio, reporting, workspace intelligence.
8. `scan-engine.js`: last, after module contracts and persistence boundaries are documented.

## First Safe Extraction Candidate

`accuracy.js` is the safest first candidate because the new evidence-quality and regression helpers are mostly pure, have a narrow API, and can be covered by `scripts/validate-regression-fixtures.js`.

## Recommended First Three Extraction Candidates

1. `accuracy.js`
2. `billing-entitlements.js`
3. `rbac.js`

Do not extract `scan-engine.js` first. The scan engine is the highest-risk dependency area because it coordinates live network probes, scoring inputs, R2 report persistence, D1 scan status updates, asset inventory writes, notifications, and historical snapshots.

## What Must Not Be Moved Yet

- Do not move `runScanEngine` until scan module output contracts are documented.
- Do not split `computeScore` until regression fixtures directly cover all scored findings.
- Do not move report generation while report retention/delete behavior is still being hardened.
- Do not move auth/RBAC route enforcement without route-level authorization tests.
- Do not change D1 write ordering during extraction.
