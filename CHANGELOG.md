# Changelog

Internal release notes for CyberMeters. Newest first. `APP_VERSION` in
`workers/scan-api/wrangler.toml` tracks the human version; each production
release is git-tagged `vYYYY.MM.DD-n` and the deployment id is visible at
`GET /health`.

## 2026.07.08 (v2026.07.08-5 — asset-alert retry + manual release model)

### Production verification (release closure)
First cron on deployment `2a6e2baa` — the first run with `asset_alert_retry`
in the registry (captured via `wrangler tail`, window 14:58–15:04 UTC):
- **Run time:** 2026-07-08 **15:00:12 UTC** (`"0 * * * *" — Ok`).
- **Errors:** zero `[cron-error]` / exception lines in the window. A mis-wired
  registry entry would have surfaced as an `is not a function` cron error; the
  task-name set is additionally CI-locked (pipeline suite).
- **`[asset-alert-retry]` log lines:** none — expected: the sweep logs only
  when it retries something, and the failed-set is empty (the pre-067 lost
  alert reads `'sent'` by design and is never retro-retried).
- **Metric reference:** AE `cybermeters_metrics` `cron_task` rows at
  2026-07-08T15:00Z include `asset_alert_retry` (query in OPERATIONS.md).

### Changed
- **Release model:** Cloudflare Workers Builds disconnected from the worker
  (probe-verified before and after — a docs push created a version while
  connected, none after). The worker now deploys manually only; Pages keeps
  auto-deploying the frontend. Flow: feature branch → PR/CI → merge → manual
  `wrangler deploy` → tag → CHANGELOG.

### Fixed
- Asset-change alert emails are enrolled in the hourly retry cron
  (`asset_alert_retry`): previously the dedupe row was written before the
  send, so a failed delivery was permanently lost (observed 2026-07-08).
  Migration 067 adds delivery-outcome tracking (safe to re-run, NOT strictly
  idempotent — duplicate-column error = already applied). Delivery semantics
  are documented at-least-once. Deployment `2a6e2baa`.

### Added
- Standalone `cybermeters-email` worker deployed dark (Stage B; 56 KiB bundle;
  Email Routing still points at the main worker until cutover).
- Pipeline suite → 31 assertions: billing lifecycle arc (payment-failed →
  grace holds → cancellation closes the gate → re-subscribe restores) and
  cron assertions upgraded to exact task-name-set + all-ok outcomes.

## 2026.07.08 (v2026.07.08-4 — worker decomposition phase 1)

### Production verification (Sprint 9 closure evidence)
First production cron of the modular worker — captured via `wrangler tail`
(window 10:58–11:04 UTC):
- **Run time:** 2026-07-08 **11:00:28 UTC** (`"0 * * * *" — Ok`).
- **Deployment:** `575d361a-0b91-4f35-bc98-4ac865342ab8` (`v2026.07.08-4`).
- **Tasks:** `triggerScheduledScan` ran visibly — real scheduled scan on
  blackbullbarbers.co.uk (`scan_06b0c7ee`, inventory 2 assets found, change
  detection 14 → +2, two workspaces updated). The six wrapped tasks
  (scheduled_reports, user_scheduled_reports, hosted_dns_sweep,
  deletion_purge, lifecycle_email_retry, domain_verify_retry) completed with
  **zero `[cron-error]` lines** (success is metrics-only by design; per-task
  duration datapoints in AE `cybermeters_metrics`, query in OPERATIONS.md).
  `report_retention` correctly skipped (only 02:00 UTC).
- **Unexpected exceptions:** 0. Handled external-dependency errors inside the
  scan: 1× certspotter CT-log timeout (scan completed past it), 2× alert-email
  `network_error` (pre-existing failure class — the documented motivation for
  the lifecycle-retry cron; follow-up: confirm asset-alert emails have a retry
  path).
- **API plane served traffic throughout** the cron (notification polls Ok at
  11:59–12:04 local, uninterrupted).
- **Reference:** tail capture preserved in session scratchpad; AE `cron_task`
  rows at 2026-07-08T11:00Z.

### Changed
- The worker is now a multi-module ES build (behaviour-identical, single
  deployment): inbound RUA email handling lives in `src/email/inbound.js`,
  cron orchestration in `src/cron/scheduled.js` (task-registry injection),
  and metrics in `src/lib/metrics.js`. Deployment `575d361a`.
- The four validation suites load the worker as a real ES module (vm-free);
  the request-pipeline suite gained a cron-orchestration section and now
  proves login, webhook→entitlement, feature-gate, pagination, rate-limiting
  and cron wiring end to end (24 assertions).
- Frontend: Vitest + Testing Library layer (24 tests) and an incremental
  TypeScript foundation (typed API client, CI type gate) — Sprints 7-8.

## 2026.07.08

### Added
- Release traceability: `GET /health` now returns `version` (APP_VERSION) and
  `deployment_id` (Cloudflare version-metadata binding); `[request-error]` logs
  carry the version.
- `docs/PUBLIC-BETA-SPRINTS.md` — the 10-sprint public-beta ladder.
- `OPERATIONS.md` — production runbook (deploy / rollback / secrets / incident).
- `scripts/validate-security-contracts.js` — 36 auth / MFA / RBAC / billing
  contract tests, wired into CI (blocking).
- CI: dependency-free secret scan + `npm audit --audit-level=high`.
- Reports: four-service Ocean & Ice colour-coding across the scan and executive
  PDFs (data reads in its owning service's colour).

### Changed
- Notifications are clickable again — the UI now reads the parsed `metadata`
  object (the API had stopped returning `metadata_json`), restoring
  click-through to the related scan.
- Domain verification auto-retries the DNS TXT check hourly for 48h so slow
  registrar propagation completes without manual re-clicks; verification audit
  events record the DNS record hash + resolver used.
- Cloudflare API calls retry transient 429/503 with a short bounded backoff.
- Colour-coded, persistent workspace sidebar; wider logo bracket spacing.

### Fixed
- Stale-chunk "reload" screen no longer dead-ends: the auto-reload budget is
  restored after a healthy boot, so an independent later deploy self-heals.
- Inbound DMARC report drops now raise a calm in-app notification instead of
  failing silently.

### Security
- Stopped returning internal R2 object paths (`report_key`) in client report
  responses.
- Masked recipient email local-parts in delivery logs.
- Auth/RBAC/billing crypto now covered by CI contract tests.

### Ops / hygiene
- `.gitignore` fixed (lockfiles no longer ignored; de-duplicated); strategy
  docs + a sample report PDF untracked from the code repo.
