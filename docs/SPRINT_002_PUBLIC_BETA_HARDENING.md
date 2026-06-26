# Sprint 002 Public Beta Hardening Notes

Date: 2026-06-26

## Billing Canonical Path

Runtime billing source of truth:

- Plans and limits: `PLAN_LIMITS` in `workers/scan-api/src/index.js`
- Feature entitlements: `PLAN_FEATURES` in `workers/scan-api/src/index.js`
- Public plan metadata: `BILLING_PLAN_METADATA` and `GET /api/billing/plans`
- Checkout: `POST /api/billing/checkout` and workspace-scoped `POST /api/workspaces/:id/billing/checkout`
- Subscription status: `subscriptions` table via `GET /api/billing/subscription` and `GET /api/workspaces/:id/subscription`
- Stripe lifecycle: `POST /api/stripe/webhook` and legacy-compatible `POST /api/billing/webhook`

`subscriptions` is the runtime billing model. `subscription_accounts` is not used by the Worker runtime.

No Stripe webhook behavior was removed in Sprint 002.

## Report Scheduling Canonical Path

Canonical Public Beta report scheduling:

- Table: `scheduled_reports`
- Frontend: `WorkspaceReportsPage.jsx`
- Routes: `/api/workspaces/:id/scheduled-reports`
- Cron processor: `processScheduledReports()`

Newer but currently unreferenced frontend path:

- Table: `report_schedules`
- Run history: `report_schedule_runs`
- Routes: `/api/workspaces/:id/report-schedules`
- Processor: `executeDueReportSchedules()`

Sprint 002 keeps `scheduled_reports` active because it is the path used by the current customer UI. The `report_schedules` processor is not invoked by cron, preventing the two systems from generating overlapping reports. Its routes and tables remain available for migration work.

Migration plan for Sprint 003:

1. Export active `scheduled_reports` rows.
2. Decide whether recipient management and run history justify adopting `report_schedules`.
3. Map `report_type` and `frequency` into `report_schedules`.
4. Choose default recipients from workspace owner/member emails.
5. Insert with duplicate checks and validate generated report counts.
6. Soft-disable migrated `scheduled_reports` rows.
7. Switch the frontend and cron only after validating no active legacy rows remain.

## Business Email Exposure Score v1 Prep

Existing email logic is sufficient for a lightweight Sprint 003 score without a new engine.

Relevant files/locations:

- `workers/scan-api/src/index.js` module 4: `runEmailModule()` for SPF, DKIM, DMARC, provider inference.
- `workers/scan-api/src/index.js` email intelligence section: SPF/DMARC/DKIM enrichment, MTA-STS, TLS-RPT, MX posture placeholders, weighted score.
- `workers/scan-api/src/index.js` vendor/email provider helpers reuse SPF/MX data.
- `workers/scan-api/src/index.js` brand/lookalike indicators exist in brand monitoring helpers and workspace routes.

Recommended v1 inputs:

- SPF status and strictness.
- DKIM detected or not verified.
- DMARC policy strength and percentage.
- MTA-STS policy presence/enforcement.
- TLS-RPT record presence.
- MX presence and mail provider detection.
- Brand/lookalike signals where already available from existing scan/workspace data.

Sprint 003 implementation should reuse existing module output and expose a small derived score. It should not introduce Microsoft 365, Google Workspace, mailbox access, or BEC protection claims.
