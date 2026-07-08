# Changelog

Internal release notes for CyberMeters. Newest first. `APP_VERSION` in
`workers/scan-api/wrangler.toml` tracks the human version; each production
release is git-tagged `vYYYY.MM.DD-n` and the deployment id is visible at
`GET /health`.

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
