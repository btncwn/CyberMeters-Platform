# Changelog

Internal release notes for CyberMeters. Newest first. `APP_VERSION` in
`workers/scan-api/wrangler.toml` tracks the human version; each production
release is git-tagged `vYYYY.MM.DD-n` and the deployment id is visible at
`GET /health`.

## 2026.07.13 (v2026.07.13-1 — Auth rate-limit hardening) — deployed 2026-07-13

### Security (P0 pre-public-beta hardening — see docs/P0-PUBLIC-BETA-BLOCKERS.md)
- **Per-account login lockout** (PR #38 #1): login was throttled per-IP only, so a
  DISTRIBUTED attack (many IPs, one account) had no per-account ceiling. Added a
  per-account consume (20 / 15 min, keyed on the normalised email, fail-closed)
  before any credential check. Generous threshold so real users never trip it;
  the short window bounds the account-lockout DoS inherent to any per-account
  throttle. `validate-pipeline.js` proves it (22 attempts from unique IPs → 21st
  is 429 while no single IP is over its own limit).
- **Fail-closed `scan_start`** (PR #38 #2): the scan-start burst limiter failed
  OPEN on D1 error, so under the exact D1 stress an attack causes an account could
  start unmetered (expensive, many-subrequest) scans. Now fail-closed — a brief
  503 + retry is safer than an unthrottled burst. (The coarse global read/write
  guard is deliberately left fail-open — defense-in-depth behind the fail-closed
  primary limiters; hard-closing it would 503 the whole API on any D1 blip.)
- No migration. pipeline 42/42, security-contracts, regression, integration green.
- Live version **a6ff57eb-f8f4-48fb-a760-61d83b9359a5** (health reports
  2026.07.13); login path verified (bogus creds → 401, no 5xx). Rollback:
  **c9a46eed-b9e0-46c0-8c5a-50c83d6f7960**.

## 2026.07.12 (v2026.07.12-9 — Guided-hybrid MTA-STS) — deployed 2026-07-12

### Product (Phase C — email wedge, on the hosted DNS v2 foundation)
- **Guided-hybrid MTA-STS** (PR #36): CyberMeters hosts + manages the
  `_mta-sts.<domain>` DNS TXT (policy id) via `record_kind='mtasts'` on
  `hosted_dns_entries`; generates a standards-compliant policy from the domain's
  **live MX**, pinned at creation. Deliberately **guided-hybrid, not full-hosted**
  — the customer/their web provider serves the HTTPS policy file at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt` (full hosting via Cloudflare
  for SaaS custom hostnames is a separate post-beta packet).
  - Two **independent** verified states: DNS TXT (CNAME delegation, existing saga)
    and HTTPS policy (reachable + matches pinned content). UI says "MTA-STS active
    in testing mode" only when **both** are green — never "protected/hosted".
  - Strictly `mode: testing`; never auto-`enforce`. MX drift is surfaced ("review
    and republish"), never silently applied, and the DNS policy id is not bumped
    before the policy verifies. Explicit product boundary shown in the UI.
  - Migration **073** additive (`hosted_dns_entries.policy_content`). DMARC +
    TLS-RPT parity preserved. `validate-hosted-mta-sts.js` (36) covers every
    guardrail; regression 227/227 green.
- Live version **c9a46eed-b9e0-46c0-8c5a-50c83d6f7960**; new route 401 unauth,
  existing hosted-dmarc/tls-rpt routes intact. Rollback:
  **8fa4b19d-c681-4876-892a-e6bbc8873633**.

## 2026.07.12 (v2026.07.12-8 — Hosted DNS v2 + TLS-RPT hosting & ingestion) — deployed 2026-07-12

### Architecture (pre-revenue refactor + Phase C)
- **Hosted DNS v2 bounded context** (PR #34): `hosted_dns_records` was pinned by
  `CHECK (record_type IN ('dmarc'))` — Codex's audit caught it; widening a CHECK
  needs a `DROP TABLE` rebuild the additive-only guard rightly forbids. So the
  layer was redesigned additively as `hosted_dns_entries` — one table for
  DMARC/TLS-RPT/MTA-STS/SPF, **no CHECK** (enums in code → new kinds never need a
  migration). Migration **071** created it + **idempotent 1:1 backfill** of the
  live hosted DMARC row (verified: `_dmarc.cybermeters.com`, connected, mapped
  1:1). Engine + routes repointed via an aliased projection → **DMARC behaviour
  identical** (the 3 hosted-DMARC lifecycle contracts + regression 227/227 green).
  Old table retired-in-place (kept + still purged; no `DROP TABLE`).
- **TLS-RPT hosting** — new `record_kind='tlsrpt'`, no migration: `/hosted-tls-rpt`
  create/verify/delete via CNAME delegation (`_smtp._tls.<domain>`), reusing the
  domain's reporting mailbox. `validate-hosted-tls-rpt.js` (20).
- **TLS-RPT report ingestion** — migration **072** (`tlsrpt_aggregate_reports` +
  `tlsrpt_failure_details`, both purged); a **separate JSON parser**
  (`lib/tlsrpt-ingest.js`) — never the DMARC XML path; the inbound handler now
  **routes by attachment type** (TLS-RPT JSON → new path; DMARC XML unchanged).
  `GET /tls-rpt/reports` + a SMTP-TLS-delivery-health card. `validate-tlsrpt-ingest.js`
  (21, incl. real inbound routing end-to-end + no-regression).
- Migrations 071 + 072 applied to remote D1 (071 first — backfill). Live version
  **8fa4b19d-c681-4876-892a-e6bbc8873633**; health/ready 200, new + repointed
  routes 401 unauth. Rollback: **36f77bb0-3082-4854-9bab-72f3750d2741**.

## 2026.07.12 (v2026.07.12-7 — White-label report branding) — deployed 2026-07-12

### Product (Faz 1 — MSP wedge)
- **White-label report branding** (PR #29): MSPs on Business+ can put their own
  company name, logo, and accent colour on the reports they share with clients —
  the answer to "can I send the report with my own logo?" is now yes, **including
  a real logo image on the PDF**. Branding is account-level (`customer_profiles`,
  keyed by owner_user_id) so it applies to every customer workspace the MSP owns;
  OFF by default → existing reports unchanged.
  - `GET/PUT /api/account/report-branding` — Business `white_label` entitlement
    gate on switch-ON, requires a company profile (409), rejects api-token
    sessions, audited.
  - PDF logo image (`engines/pdf-image.js` + `assemblePdfWithImage`): JPEG via
    `/DCTDecode`; PNG inflated/de-filtered/alpha-flattened over the accent band
    and re-deflated as an 8-bit DeviceRGB XObject; SVG/WebP/CMYK → text-wordmark
    fallback (never throws). Header wordmark → logo/name, accent band, footer
    "Prepared by <MSP> | Powered by CyberMeters". Logo also rides the HTML exec
    report brand bar.
  - CI-blocking `validate-report-branding.js` (42) incl. PNG decode round-trip,
    JPEG passthrough, plan gating, company-profile requirement, cross-account
    isolation. Verified end-to-end with pypdf (valid PDF, `/Im0` Image XObject).
- **Migration 070** (`customer_profiles.brand_logo/brand_accent/report_white_label`,
  additive) applied to remote D1 before deploy; columns verified present.
- Also fixed a pre-existing time-of-day flake in `validate-pipeline.js` (cron
  task-set assertion now mirrors the 08:00-UTC ops-health + Monday weekly-digest
  tasks, not just 02:00 retention).
- Live version **36f77bb0-3082-4854-9bab-72f3750d2741**; report-branding endpoint
  401 unauth (sanitized). Rollback: previous version
  **99acf2bf-ae61-4d16-9947-76b96b60cddb**.

## 2026.07.12 (v2026.07.12-6 — Identity Exposure) — deployed 2026-07-12

### Product (Faz 0 — final bet)
- **Identity Exposure** (`7a1c594`,`104c6da`): consolidates three REAL, free,
  outside-in signals under "how can an attacker impersonate/steal/abuse your
  identity?" — exposed login surfaces (identity_assets), active impersonation
  infrastructure (resolving lookalikes that can send mail / host a login), and
  email spoofing (SPF/DMARC weakness = the #1 BEC threat, from the latest scan
  report). Overall Low/Medium/High level + plain-English summary. New
  GET /api/workspaces/:id/identity-exposure + an explanation-first card on the
  identity page. NO fake HIBP placeholder — HIBP breached-credentials is a
  genuine Faz 1 add. CI-blocking validate-identity-exposure.js (14) incl. tenant
  isolation. No migration.
- Live version **99acf2bf-ae61-4d16-9947-76b96b60cddb**; endpoint 401 unauth,
  /ready healthy, free-scan verified. Rollback: **77bd47ac-facb-46db-9b6c-47ef15e8657e**.

## 2026.07.12 (v2026.07.12-5 — MSP Portfolio: change-counts + exec summary) — deployed 2026-07-12

### Product (Faz 0 — MSP wedge)
- **MSP Portfolio sharpening** (`86067ca`): the "which customer needs attention
  today?" view now shows THIS WEEK'S Exposure-Timeline change counts per customer
  and factors new high/critical changes into the attention ranking (connecting the
  two Faz 0 bets). New `GET /api/portfolio/executive-summary` — portfolio-level
  posture spread + this week's movement + top-3 attention list + plain-English
  narrative the MSP can share. Per-customer logic extracted to a shared,
  unit-tested engine. New CI-blocking `validate-portfolio.js` (21) closes the
  previously-untested CROSS-MSP ISOLATION invariant (MSP A never sees MSP B's
  customers). No migration.
- Live version **77bd47ac-facb-46db-9b6c-47ef15e8657e**; new endpoints 401 unauth.
  Rollback: previous version **22ab9763-9d90-48f2-a7f0-4f87cb0935d6**.

## 2026.07.12 (v2026.07.12-4 — SSRF gate hardening) — deployed 2026-07-12

### Security (internal pentest, code-side)
- **SSRF domain-gate hardening** (`7a64a28`): `isValidDomain` (enforced before
  every scan AND the public free-scan) now also rejects reserved / private-use
  TLDs (internal/local/localhost/corp/lan/…). Closes a finding from the internal
  pentest: `metadata.google.internal` previously passed the alpha-TLD rule.
  Verified live — metadata + IP-literal targets rejected, legitimate domains
  unaffected. Locked by `validate-ssrf-domain-guard.js` (37) +
  `validate-dmarc-xml-safety.js` (18, XXE/DoS), both CI-blocking.
- Live version **22ab9763-9d90-48f2-a7f0-4f87cb0935d6**. Rollback: previous
  version **8e243e0b-5264-42c5-84d2-8e50ec9038d2**.

## 2026.07.12 (v2026.07.12-3 — weekly Exposure Timeline digest) — deployed 2026-07-12

### Product (Faz 0 — retention hook)
- **Weekly digest** (`4377c6e`): a Monday 08:00 UTC "what changed this week" email
  to active workspaces (verified owner + >=1 monitored domain), deduped once per
  ISO week, aggregating the last 7 days of exposure events (severity + category
  breakdown + top 5). Quiet weeks send a short "all quiet — posture stable"
  reassurance; dormant/unverified owners get nothing (protects deliverability).
  Completes the Exposure Timeline (change detection -> feed API -> UI -> digest) —
  the one-time-scan -> subscription hinge. No migration (reuses lifecycle_email_events).
- Live version **8e243e0b-5264-42c5-84d2-8e50ec9038d2**; /health 200, /ready d1+r2
  healthy, free-scan verified. Rollback: previous version **52281cb0-aadf-41ea-80b7-0eb2830b2954**.

## 2026.07.12 (v2026.07.12-2 — Exposure Timeline backend) — deployed 2026-07-12

### Product (Faz 0 — the subscription hinge)
- **Exposure Timeline change detection + feed** (`#26`,`#27`,`#28`): the platform
  now records what changed between scans — turning a one-time scan tool into a
  subscription product. New `asset_events` on top of the existing subdomain/cert
  diffs: DNS changes (IP / CNAME / redirect target, external redirect = high),
  email-auth changes (SPF record, DMARC policy weakened/strengthened, DKIM), and
  new/resolved internet-exposed services. Surfaced by a new enriched, filterable,
  paginated feed API `GET /api/workspaces/:id/exposure/feed` (category + severity
  + hostname + date filters), consumed by the upcoming Timeline UI + weekly digest.
  Fully test-covered (validate-exposure-events / -posture-events / -exposure-feed,
  all CI-blocking) and documented in OpenAPI (ExposureEvent schema). New events
  accrue on future scans, so deploying now starts building change history.
- Live version **52281cb0-aadf-41ea-80b7-0eb2830b2954**; `/health` 200,
  `/exposure/feed` 401 (auth enforced). Rollback: previous version
  **4d9898d4-d0e2-45c0-b77f-59842dff7a29**.

## 2026.07.12 (v2026.07.12-1 — planned maintenance mode) — deployed 2026-07-12

### Operations
- **Planned maintenance mode** (`17dc938`): `MAINTENANCE_MODE` var (off by
  default, fail-safe). When on, every API route returns the uniform
  `503 { code: "maintenance", message }` + `Retry-After: 300` — placed right
  after `/health` and `/ready` so monitoring stays reachable; `/health` reports a
  `maintenance` flag. `MAINTENANCE_BYPASS_TOKEN` + `X-Maintenance-Bypass` header
  lets the founder smoke-test a deploy mid-window. Frontend detects the contract
  and shows a full-screen "back shortly" overlay (covers login too) that polls
  `/health` and auto-reloads when the window lifts. Guarded by
  `validate-maintenance-mode.js` (29 assertions, CI-blocking); enable/verify/lift
  runbook in `docs/07-RELEASE-CHECKLIST.md`. Capability shipped with the flag OFF
  (behaviourally inert until toggled).
- Live version **4d9898d4-d0e2-45c0-b77f-59842dff7a29**; `/health` 200
  (version 2026.07.12, maintenance:false). Rollback: previous stable
  **60d557a2-9467-4e3f-b28a-11b18d4637a8**.

## 2026.07.11 (v2026.07.11-3 — daily ops-health heartbeat) — deployed 2026-07-11

### Operations
- **Daily ops-health heartbeat** (`4850c91`): a cron self-check (08:00 UTC) runs
  read-only signal queries — scans stuck `running` >15min, undelivered
  lifecycle-email backlog, undelivered asset-alert backlog, deletion purges
  overdue >35d — and emails ops (`ALERT_EMAIL_TO`) ONLY when a threshold is
  breached, so a healthy system stays silent (≤1 alert/day). If every query is
  skipped the DB is treated as unreachable and the alert says so. Per-run
  `ops_health` metric for trends. Fully isolated via `runCronTask` (never affects
  existing cron tasks). New `src/lib/ops-health.js` (pure, tunable
  `OPS_THRESHOLDS`) + CI-blocking `validate-ops-health.js` (29 assertions).
  `docs/MONITORING.md` documents all three layers (/health+/ready probes,
  Cloudflare 5xx/log notifications, this heartbeat) + response runbook.
- Live version **16212a24-1b94-4892-87ef-28a04e52ed6d**; `/health` 200, `/ready`
  d1+r2 healthy. Rollback: previous version **60d557a2-9467-4e3f-b28a-11b18d4637a8**.

## 2026.07.11 (v2026.07.11-2 — uniform API error contract) — deployed 2026-07-11

### API / trust
- **Uniform error contract** (`c33aff9`): every error response (HTTP ≥ 400) now
  carries `{ error, code, message }` — a snake_case machine `code` the UI can
  switch on and a customer-safe human `message` a user can read verbatim —
  enforced centrally in `normalizeApiResponseData` (the choke point behind
  `json()`), so all 568+ error sites conform with no route churn. Completed the
  status→code map (405/410/422/502/503) and guaranteed `message` (added only
  when a route didn't set its own). `detail`/`stack` are still stripped.
  Backward-compatible: `error` unchanged (existing machine-code switches keep
  working); `message` is additive. OpenAPI Error schema updated. New CI-blocking
  harness `validate-error-contract.js` (116 assertions). Live 401 now returns a
  clean sentence instead of a bare "Unauthorized".
- Live version **60d557a2-9467-4e3f-b28a-11b18d4637a8**; `/health` 200. Rollback:
  previous version **9e0949d6-123b-4526-b863-a635f7236928**.

## 2026.07.11 (v2026.07.11-1 — secure-SDLC batch: log redaction, Stripe replay guard, purge + migration CI gates) — deployed 2026-07-11

### Security / reliability (every finding paired with an automated regression)
- **P0#7 — central log redaction** (`a168bd4`): new `src/lib/redact.js` (recursive,
  cycle-safe, depth-capped) strips secret-named keys (password/token/secret/
  authorization/cookie/api-key/mfa/totp/session/…) and secret-shaped values
  (JWT, Stripe sk/rk/pk, whsec_, cm_/cmrua_, Bearer, long hex). The `serverError`
  request-error logger now routes through `redactedJson()` — defense-in-depth so
  no log site can ever leak a credential. Test: `validate-log-redaction.js` (17/17).
- **P0#5 — idempotent Stripe webhooks** (`c18defb`): a replayed/retried event
  (same id) could re-run entitlement side effects. Every handled event id is now
  persisted in `stripe_processed_events` (migration 069, additive) and an
  `INSERT OR IGNORE` before the switch short-circuits a replay to
  `{received, deduped}` without reprocessing; signature verification unchanged and
  still first. Test: `validate-pipeline.js` posts the webhook twice and asserts
  the replay is deduped (38/38). Migration 069 applied to remote D1 before deploy.
- **P1#10 — purge-completeness regression** (`adc9e0f`): `validate-purge-completeness.js`
  seeds every purge table + reports + a scan (+children) for two workspaces, runs
  the real `purgeWorkspaceData` to completion, and asserts zero orphaned rows/R2
  objects for the purged workspace with the other fully intact (10/10). Guards the
  forgotten-table orphan class.
- **P1#3 — CI security gates expanded** (`33222a8`): new `validate-migrations.js`
  enforces additive-only migrations (destructive-statement scan) + fresh-apply
  convergence (79/79); worker `npm audit --audit-level=high` (0 vulns) and the
  three new harnesses are now CI-blocking.

### UX
- **New Scan re-click resets the form** (`ea84ff0`): clicking the header New Scan
  button while already on /scans/new now clears + scrolls the form. Feedback
  widget simplified to a single **Contact support** action (bug/feature options
  removed).

- Live version **9e0949d6-123b-4526-b863-a635f7236928**; `/health` 200 (version
  2026.07.11), anon endpoints 401. Rollback: previous version
  **5dc30474-f8df-4e4d-a198-fbe7484a4c50**.

## 2026.07.10 (v2026.07.10-11 — authenticated red-team fixes) — deployed 2026-07-11

### Security (Codex authenticated logic-layer red-team — all findings verified vs HEAD)
- **P1 — Free trial is now once-per-owner** (`5b57af3`): trials were minted per
  workspace with no lifetime check, and workspace usage ignores soft-deleted
  workspaces, so an owner could farm unlimited 14-day Professional trials via
  create → soft-delete → create. Trial creation now skips if the owner already
  has any subscription with a trial_start (survives soft-delete). First workspace
  still trials; recycled ones do not.
- **P1 — Workspace notifications scoped per user** (`68d056b`): notification_events
  has a user_id column (NULL = global) but list/count/mark-read filtered only by
  workspace_id, so any member could see and clear another member's user-specific
  notifications. All four queries now scope by (user_id IS NULL OR user_id =
  caller). Backward-compatible — today all rows are global.
- **P2 — MFA recovery-code endpoint throttle** (`a7ea6e5`): added the fail-closed
  IP limiter the other MFA proof endpoints already had.
- **P2 — Worker lockfiles committed** (`6068eb3`): npm audit now reproducible on
  both workers, 0 vulnerabilities.
- Live version **5dc30474-f8df-4e4d-a198-fbe7484a4c50**; `/health` 200, anon
  endpoints 401. Rollback: previous version `fa3c49d1-c111-4785-bbdf-a2d136d282e0`.

## 2026.07.10 (v2026.07.10-10 — red-team hardening) — deployed 2026-07-11

### Security
- **Signup user-enumeration removed** (`429f2e0`): signup returned a distinct
  409 for a registered email, letting an attacker probe which emails have
  accounts (found in the authorized black-box red-team pass). Signup with an
  existing email now returns the exact same generic 201 as a fresh signup — no
  account is created, and a security-notice email goes to the genuine owner
  instead. The HTTP response is now indistinguishable between registered and
  unregistered emails; signup stays rate-limited (5/hour/IP). Verified live:
  existing vs non-existing email now return identical responses.
- **Dev-dependency CVEs cleared** (`eb2562a`, no deploy needed): wrangler
  bumped v3 → ^4.24.4, clearing 5 advisories (esbuild dev-server SSRF, undici
  ×9, miniflare) — all devDependency-only, never in the production runtime.
  `npm audit` now 0 across frontend + both workers.
- Authorized black-box red-team pass (16 checks) otherwise clean: HSTS/CSP/
  X-Frame/nosniff, auth-required 401s, error sanitisation, login rate-limit
  fires at the 10th attempt, CORS not reflected, body 413 / URL 414, webhook
  400 unsigned, no file leaks, security.txt present, no cookies.
- Live version **fa3c49d1-c111-4785-bbdf-a2d136d282e0**; `/health` 200.
  Rollback: previous version `fd583e3d-525b-4a35-8561-80ab91deda3f`.

## 2026.07.10 (v2026.07.10-9 — pre-beta security hardening)

### Fixed (independent Codex audit at 0bf010e, all verified against HEAD)
- **Cross-tenant domain existence oracle** (`4783ef6`): the domain verification
  init + check routes returned 403 for a domain owned by another tenant but 404
  for a nonexistent id — an authenticated user could distinguish foreign-existing
  from nonexistent domain ids. Both now return an identical 404 (ids are opaque
  UUIDs so enumeration was already impractical; the response oracle is closed).
- **Invitation-send rate limiting now fail-closed** (`4af86f7`): invite_send
  hourly/daily limits fell open on a rate_limit table outage; each invite sends
  an email from our domain, so an outage was an open spam/reputation window. Now
  fail-closed (503) — a brief inability to invite beats unbounded outbound mail.
- **Fail-closed throttles on MFA proof endpoints** (`27d597f`): verify-setup /
  disable (per user, 10/15min) and login challenge (per IP, 20/15min) had no
  endpoint-specific limit — the TOTP/password proofs relied only on the fail-open
  global guard. Defense-in-depth atop the existing per-challenge single-use guard.

### CI
- **Worker bundle dry-run added to CI** (`a762bec`): CI ran all 5 harnesses +
  frontend build but not the Cloudflare bundling step — the exact class that
  produced the v-3 PLAN_LIMITS runtime break would now be caught pre-merge.

### Deploy note
- Live version **7c7c7a05-449e-42cd-9d28-6dbcc362365c** (100% traffic, confirmed
  via `wrangler deployments list` + `/health`). The `wrangler deploy` client
  reported "fetch failed" on its final confirmation fetch due to flaky local
  network, but the Cloudflare-side activation succeeded — verified independently.
  Post-deploy smoke: `/health` 200, `/api/billing/plans` 200, anon `/api/auth/me`
  401. Rollback: previous version `fd583e3d-525b-4a35-8561-80ab91deda3f`.

## 2026.07.10 (v2026.07.10-8 — RUA external report authorization auto-provisioning)

### Added
- **RFC 7489 §7.1 authorization auto-provisioning** (`24ff2a7`): configuring a
  DMARC ingest endpoint's Cloudflare route now also upserts the
  `<domain>._report._dmarc.<rua-domain>` TXT (`v=DMARC1;`) on our zone, so
  cross-org receivers (Google, Microsoft) actually send aggregate reports for
  external customer domains — previously a manual, silently-gating step (the
  first pilot's stall). Same-org domains (apex + sibling subdomains of the
  inbound domain's org) exempt per the RFC; idempotent (adopts existing
  records); a failure never blocks route setup and self-heals on the next
  configure pass. Unit-tested against a mocked CF API (6/6); 5/5 harnesses.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id fd583e3d-525b-4a35-8561-80ab91deda3f`; plans 200, anon
  auth/me 401. Rollback: previous version
  `f0528ca1-cefa-4123-9b96-4d33e4432730`.
- Same day: **first real external DMARC aggregate ingested** — google.com →
  blackbullbarbers.co.uk (3 records: SPF aligned pass ×3, DKIM aligned fail ×3
  from Microsoft 365 IPs — confirming the known M365-DKIM-disabled gap),
  stored in the correct workspace end-to-end.

## 2026.07.10 (v2026.07.10-7 — router split COMPLETE, PRs #14–#20)

### Changed
- **Router split PRs #14–#20 — Phase 2 COMPLETE** (behaviour-preserving, solo):
  scans (start/report/PDF + scheduled scans), portfolio + workspace list,
  **attack-surface** (assets/alerts/posture/vendors, 1,493 lines — largest
  band), workspace-insights (validation/usage/summary/health), account
  (profile/tokens/sessions/GDPR export + platform QA), global-billing (plans,
  DMARC signed-upload ingest, **Stripe webhook**, checkout/portal) and finally
  **auth** (signup/login/MFA/SSO/password lifecycle, 1,499 lines, zero
  routeCtx changes). **index.js 15,637 → 2,242 lines (−86%) across 20 PRs**;
  every route group now lives in `src/routes/` (16 modules) behind the
  per-request routeCtx dispatcher; engines grew by plan-usage +
  subscription-state. Every PR: byte-equality vs main, index-def leak scan +
  cross-module missing-import scan, all 5 harnesses, CI green.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id f0528ca1-cefa-4123-9b96-4d33e4432730`; auth paths verified
  live (bad login → 401 not 500, anon `/api/auth/me` → 401,
  `/api/billing/plans` → 200). Rollback: previous version
  `892f8ee6-7d90-43be-91d3-52f72eb855ee`.

## 2026.07.10 (v2026.07.10-6 — router split PRs #11–#13)

### Changed
- **Router split PRs #11–#13** (behaviour-preserving, solo): workspaces-core
  (detail/rename/domain-link CRUD + delete-request/restore; routeCtx gains
  DELETION_PURGE_WINDOW_DAYS), the **subscription/trial-state engine**
  (`engines/subscription-state.js`: TRIAL_PLAN constants, trial/subscription
  state checks, workspace subscription resolution, checkout plan parsing,
  public billing plans), and billing + free-scan routes (last group before the
  404 fallback; routeCtx gains rateLimitScopeId). index.js 9,579 → 8,916
  (running total 15,637 → 8,916 across 13 PRs). Byte-equality + double leak
  scans + all 5 harnesses per PR; CI green throughout.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id 892f8ee6-7d90-43be-91d3-52f72eb855ee`; `/api/billing/plans`
  → 200. Rollback: previous version `e95c982d-fd2f-4f6a-8f95-11f6394bb01c`.

## 2026.07.10 (v2026.07.10-5 — router split PRs #7–#10)

### Changed
- **Router split PRs #7–#10** (behaviour-preserving, solo): workspace-members
  (invitations + members, routeCtx gains consumeApiRateLimit + ROLE_RANK),
  executive-dashboard (KPI + activity feed), **email-protection** (the whole
  email-wedge route band — DMARC report import/list/summary, sender inventory,
  BEC exposure, hosted DMARC/DNS management, RUA routing, alert channels;
  1,040 lines, 54 symbols from 9 modules), and domains (import + verification
  lifecycle; /domains/import precedence over :domainId preserved; routeCtx
  gains requireDomainRole). index.js 11,928 → 10,037 lines. Every PR:
  byte-equality vs main, index-def leak scan + cross-module missing-import
  scan, all 5 harnesses (incl. validate-pipeline — mandatory since the v-4
  incident), CI green.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id e95c982d-fd2f-4f6a-8f95-11f6394bb01c`; `/api/billing/plans`
  → 200. Rollback: previous version `414ec706-13f6-4682-8f46-6d322737a1cd`.

## 2026.07.10 (v2026.07.10-4 — hotfix: PLAN_LIMITS import)

### Fixed
- **`/api/billing/plans` 500 introduced by v2026.07.10-3**: PR #4 moved
  `getPlanLimits` into `engines/plan-usage.js` without carrying the
  `PLAN_LIMITS` import (bracket access evaded the call-based dependency scan;
  the symbol was satisfied by index.js's own import — for the old scope).
  Caught by CI `validate-pipeline` (local runs had skipped that harness — all
  5 are now mandatory for every change, no exceptions). A cross-module
  missing-import scan (refs to another module's exports without importing
  them) now runs over every extracted module: all 7 clean. Post-deploy:
  endpoint 200, `deployment_id 414ec706-13f6-4682-8f46-6d322737a1cd`.
  Broken window: ~70 min on a public no-auth metadata endpoint; quota checks
  were unaffected (fail-open by design).

## 2026.07.10 (v2026.07.10-3 — router split, low-risk batch)

### Changed
- **Router split PRs #1–#6** (behaviour-preserving; PRs #21/#22/#23 via Codex +
  3 solo): route groups extracted from the monolithic `fetch()` router into
  `src/routes/` modules dispatched through a per-request `routeCtx` —
  workspace-analytics (scorecard/CE/BRS), workspace-intel (identity/vendor-rel/
  supply-chain), brand (intelligence v1 + monitoring), workspace-reports
  (reports + scheduled-reports), workspace-activity (audit events +
  notifications); plus the 31-function plan-usage/report-lifecycle engine
  (`engines/plan-usage.js`: plan limits, usage metering, retention, quota
  checkers, report cadence, generateWorkspaceExecutiveReport). index.js
  15,637 → 12,558 lines. Every move byte-equality-verified against main with a
  full bare-identifier leak scan; all 4 harnesses green per PR.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id 42e170a8-21e7-4b8c-a9fc-b4f7373fb7ae`.
  Rollback: previous version `4003937f-100f-41e3-ab2d-b838a14fbe39`.

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
