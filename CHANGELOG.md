# Changelog

Internal release notes for CyberMeters. Newest first. `APP_VERSION` in
`workers/scan-api/wrangler.toml` tracks the human version; each production
release is git-tagged `vYYYY.MM.DD-n` and the deployment id is visible at
`GET /health`.

## 2026.07.10 (v2026.07.10-2 — asset alert trust fixes)

### Fixed
- **Inventory diff survives domain delete/re-add** (`145974e`): existing assets are
  matched by hostname (root or `*.root`) as well as `domain_id`. Previously a re-added
  domain got a new `domain_id`, making rows written under the old id invisible to the
  diff — every later scan re-announced known assets as `new_asset_discovered` while
  `UNIQUE(workspace_id, hostname)` silently blocked the re-insert and froze `last_seen`
  (observed live: `cybermeters.com` + `app.cybermeters.com` stuck at 2026-06-19 while
  alerted as "new" by scan `scan_2d7183d1` on 2026-07-10). Matched rows are re-linked
  to the current `domain_id`, so orphaned inventory self-heals on the next scan.
- **Asset change alert scoped to the scan's own workspace** (`8ccf344`): one scan
  produced three alert emails — HIGH "new assets" to the owning workspace plus two
  identical MEDIUM "reappeared" mails to the other workspaces linked to the same
  domain, each exposing the owning workspace's scan id. Alert email + channel fan-out
  now target only the scan's workspace; asset events remain written for every linked
  workspace (in-app feeds unchanged). Scans without a workspace keep the old fan-out.
- Validation: accuracy 227/227, security-contracts 45/45, integration 18/18,
  email-worker equivalence 9/9, `wrangler deploy --dry-run` clean. Post-deploy smoke:
  `GET /health` → 200, `deployment_id 4003937f-100f-41e3-ab2d-b838a14fbe39`.
  Rollback: previous version `b35a8990-00fd-46f6-968f-11837db07747`.

## 2026.07.10 (v2026.07.10-1 — monolith decomposition Phase 1)

### Changed
- **Worker modularisation** (worker `780d3120`, decomposition commits `61b63a3`…`d95f242`):
  the 36,321-line `workers/scan-api/src/index.js` monolith was split into **66 focused
  modules** (53 `src/engines/` + 13 `src/lib/`); index.js is now ~15,637 lines. Every
  extraction is a **verbatim, behaviour-preserving move** — no logic, scoring, copy,
  pricing, schema, or API change. Extracted: all scan/discovery modules, the scoring
  engine (`computeScore`), the email wedge (analysis/scan/intel/BEC), brand protection,
  the DMARC/hosted/RUA subsystem (incl. the hosted DMARC records engine), PDF generation,
  billing (entitlements + Stripe), alerts, risk-scoring (BRS/vendor/supply-chain/portfolio/
  CE), and the scan pipeline orchestrator (`runScanEngine` → `engines/scan-engine.js`,
  which now composes 56 symbols from 37 modules). Remaining index.js = worker entry/auth
  glue + operational plumbing + the HTTP router.
- **Latent bug fixed in passing:** the dangling-reference audit caught `computeScanBudget`'s
  fallback referencing `BRUTEFORCE_MAX_NAMES` (a `subdomains-scan` module-internal) — a
  `ReferenceError` on the non-numeric branch that the test suites never exercised. Now
  exported + imported. This branch existed pre-decomposition too; the refactor surfaced it.
- Verified at every step and at release: all 5 regression suites green (accuracy 227/227,
  pipeline real-fetch, security-contracts, integration authz, email-worker golden
  equivalence 9/9), `wrangler deploy --dry-run` clean (bundle 1399 KiB, identical to the
  deployed bundle), `git diff --check` clean. Post-deploy smoke: `GET /health` → 200 with
  `deployment_id 780d3120`. Structural refactor done pre-revenue at zero customer stakes.

## 2026.07.09 (v2026.07.09-3 — Cyber MOT welcome-email copy)

### Changed
- **Welcome email wording** (worker `d8a1bd45`, PR #7 `a79e6f3`): the signup
  welcome email now leads with Cyber MOT / Website Security / Certificates & Trust
  instead of "external attack surface" + "run your first scan". Copy-only, part of
  the ChatGPT-led Cyber MOT wording pass (docs/COPY-CLEANUP-BACKLOG.md); the
  matching frontend copy (dashboard, onboarding, pricing hero, scans, workspaces)
  shipped on Pages via the same PR. No logic, pricing, or template-structure change;
  email-worker golden equivalence 9/9.

## 2026.07.09 (v2026.07.09-2 — trust-copy corrections)

### Fixed
- **Mis-selling plan copy** (worker `38a9291b`, commit `0c6518a`): the upgrade
  wall advertised "Up to 25 domains" (Starter, sells 1) and "Up to 250 domains"
  (Professional, sells 5) — now matches the frozen tiers (1 / up to 5 / up to
  20 monitored domains). Billing plan-limits grid is domain-first (internal
  workspace/scan quotas no longer rendered). Free Cyber MOT 429 no longer
  promises "unlimited scanning" (free plan has monthly caps). Source: external
  audit P1s, each verified against source before fixing.
- Also shipped on Pages this cycle: Cyber MOT domain handoff through signup →
  onboarding (+ regression tests via PR #6), CE Preview/Dashboard naming, and
  the in-app entry for the paid CE dashboard (previously an orphan route).

## 2026.07.09 (v2026.07.09-1 — pricing coherence + single-workspace SMB)

### Fixed
- **SMB plans are single-workspace** (worker version `2d17cf49`): Starter and
  Professional allowed multi-workspace (ws=3 / ws=10) while domains are enforced
  per-workspace, so a Professional user could reach 10×5=50 domains vs the
  advertised 5. Set starter/professional `workspaces` to 1 (free already 1);
  Business (50) and Enterprise (unlimited) keep multi-workspace for per-client
  tenant isolation. Enforcement is creation-only — existing workspaces are never
  touched (verified against prod D1: the only >1-workspace account is the
  founder's own and stays intact).
- **Pricing cards are tier-aware** (frontend / Pages, commit `b629fc0`): SMB
  tiers lead with domains (the value metric); MSP tiers show client workspaces +
  domains-per-workspace. Removed internal scans/reports quotas from the cards,
  added a "Most popular" badge on Professional, and persisted the billing-cycle
  choice so it survives the signup/checkout round-trip.
- **Self-serve checkout** (worker deploy `bd43876d`): checkout was disabled by
  three of our own bugs (hardcoded `checkout_enabled:false`, env-var name
  mismatch, yearly→monthly interval collapse) — not the Stripe configuration.
  Verified live: 6/6 checkout sessions created, zero missing-price errors.

## 2026.07.08 (v2026.07.08-6 — Cyber Essentials Readiness)

### Added
- **Cyber Essentials Readiness endpoint** (deployment `22fe448e`): GET/PUT
  `/api/workspaces/:id/cyber-essentials/answers` (auth + professional plan gate +
  server-side key validation + upsert on migration 068). The readiness endpoint
  now additively returns `self_assessment` — measured categories merged with
  self-attestation, with an HONEST per-control evidence label
  (self_attested_only for internal controls — never "verified";
  contradicted_by_scan where an optimistic answer conflicts with observed
  evidence). Partial verification, transparently labelled.
- **CE Readiness free-hook page** (frontend, Codex + Claude review): public
  `/cyber-essentials-readiness` lead-gen questionnaire (local state), distinct
  from the paid in-app `ws/cyber-essentials` service. Not yet wired to data.

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
