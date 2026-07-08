# CyberMeters — Operations Runbook

Operational runbook for running CyberMeters in production. Complements `README.md`
(which covers day-to-day dev commands) — this file is deploy / rollback / secrets /
incident / observability. Every command and value below is taken from the repo
(`workers/scan-api/wrangler.toml`, the source, and `database/`).

## Architecture at a glance

| Piece | What | Where |
|---|---|---|
| **API + engine** | One Cloudflare Worker `cybermeters-platform` — REST API, cron, inbound email (RUA), scan engine, scoring, PDF gen | `workers/scan-api/src/index.js` |
| **Frontend** | React/Vite SPA on Cloudflare Pages, git-integrated (auto-build on push to `main`) | `frontend/` |
| **Database** | Cloudflare D1 (SQLite) `cybermeters-db` (`fd6792cb-441a-44a7-8ca2-9a0b411ec706`) | binding `cybermeters_db` |
| **Object store** | R2 bucket `cybermeters-reports` — scan report JSON + PDFs | binding `cybermeters_reports` |
| **Scheduled work** | Cron `0 * * * *` (hourly) | Worker `scheduled()` |
| **Inbound email** | Cloudflare Email Routing on `reports.cybermeters.com` → Worker `email()` (DMARC RUA ingestion) | — |

## Deploy

**Always run the validation gate before deploying the Worker** (see also `CLAUDE.md`):

```bash
node --input-type=module --check < workers/scan-api/src/index.js   # syntax
node scripts/validate-regression-fixtures.js                        # 218 accuracy contracts
cd workers/scan-api && npx wrangler deploy --dry-run                # bundle + config check
```

**Worker** (manual):

```bash
cd workers/scan-api && npx wrangler deploy
```

The deploy prints a `Current Version ID` — record it (needed for rollback).

**Frontend** — no manual step: pushing to `main` triggers the Cloudflare Pages
git build (`npm run build` in `frontend/`). `frontend/.env` supplies the public
`VITE_API_BASE_URL` at build time (intentionally committed — it is not a secret).

CI (`.github/workflows/ci.yml`) runs on every PR + push to `main`: secret scan →
worker syntax → regression fixtures → `npm ci` → `npm audit --audit-level=high` →
frontend build. CI does **not** deploy.

## Rollback

**Worker:**

```bash
cd workers/scan-api
npx wrangler deployments list          # find the last-good Version ID
npx wrangler rollback <version-id>     # revert to it
```

**Frontend:** Cloudflare dashboard → Pages → the project → Deployments →
"Rollback to this deployment" on the last-good build (or revert the offending
commit on `main` to trigger a fresh build).

**Database:** migrations are **forward-only** (D1/SQLite; documented in `CLAUDE.md`).
There are no down-migrations — a bad migration is corrected by writing a new
corrective migration, never by an automatic rollback. Take extra care.

## Secrets & configuration

**Non-secret vars** live in `workers/scan-api/wrangler.toml` `[vars]` and deploy
with the Worker: `ALERT_EMAIL_TO/FROM`, `SAFE_EMAIL_FROM`, `HELLO_EMAIL_FROM`,
`ALLOWED_ORIGIN`, `RUA_INBOUND_DOMAIN`, `FRONTEND_URL`, `MICROSOFT_REDIRECT_URI`.

**Secrets** are set with Wrangler (never committed):

```bash
cd workers/scan-api
npx wrangler secret list                # what is currently set
npx wrangler secret put <NAME>          # set/rotate one
```

Required secrets (referenced in the source):

| Secret | Used for | Rotation note |
|---|---|---|
| `STRIPE_SECRET_KEY` | Stripe API | Rotate in Stripe → `secret put` |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signature verify | Rotate the endpoint secret in Stripe, then `secret put` |
| `RESEND_API_KEY` | Outbound email (Resend) | Rotate in Resend → `secret put` |
| `MFA_ENCRYPTION_KEY` | AES-GCM encryption of stored TOTP secrets | **DANGER:** rotating this makes existing TOTP secrets undecryptable — every MFA user must re-enrol. Do not rotate without a migration plan |
| `CLOUDFLARE_API_TOKEN` | Hosted Records Engine — DNS:Edit + Email Routing on `cybermeters.com` | Rotate in CF dashboard → `secret put` |
| `CLOUDFLARE_ZONE_ID` | `cybermeters.com` zone for hosted DMARC | Stable; only changes if the zone changes |
| `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` | Microsoft (Entra) SSO | Rotate the client secret in Entra → `secret put` |
| `ADMIN_EMAILS` | Admin allow-list | Config value |
| `APP_URL` | Absolute-URL building | Config value |

## Database

D1 `cybermeters-db`. Schema in `database/schema.sql`; numbered migrations in
`database/migrations/NNN-*.sql` (apply in numeric order):

```bash
npx wrangler d1 execute cybermeters-db --remote --file=database/migrations/<NNN-name>.sql
# read-only inspection:
npx wrangler d1 execute cybermeters-db --remote --command "SELECT ... ;"
```

Rules (from `CLAUDE.md`): every schema change needs a migration file; idempotent
where D1/SQLite allows; no inline production DDL; no destructive migration without
explicit approval.

## Scheduled work (hourly cron)

The `scheduled()` handler runs each hour and dispatches (all bounded, fail-safe):
scheduled scans (`LIMIT 20`), scheduled + user reports, Hosted DNS verification
sweep (retries/reconciles hosted DMARC intents), report retention cleanup
(daily at 02:00 UTC), deletion purge (soft-delete → 30-day → hard delete),
lifecycle-email retry, and domain-verification auto-retry.

## Observability

```bash
cd workers/scan-api && npx wrangler tail          # live structured logs
```

Logs are tagged (`[inventory]`, `[email-delivery]`, `[scheduled-monitoring]`,
`[request-error]`, `[cron-error]`, …). Recipient email local-parts are masked in
logs. Also: Cloudflare dashboard → Workers analytics (requests, errors, CPU,
subrequests); the D1 `audit_events` table (business audit trail).

**Probes:** `GET /health` (liveness — returns version + deployment_id).
`GET /ready` (readiness — checks D1 + R2 reachability; 200 ready / 503 degraded).
Point uptime monitors at `/ready`.

**Metrics (Analytics Engine, dataset `cybermeters_metrics`, binding `METRICS`):**
`recordMetric()` writes fail-open data points — `http_5xx` (blob = route scope)
and `cron_task` (blobs = task name + ok/error, double = duration ms). Query via
the Analytics Engine SQL API, e.g. cron failures in the last day:

```sql
SELECT blob1 AS task, blob2 AS outcome, count() AS n, avg(double1) AS avg_ms
FROM cybermeters_metrics WHERE blob1 != '' AND timestamp > NOW() - INTERVAL '1' DAY
GROUP BY task, outcome
```

**Alerting hooks:** a failing cron task emits both a `cron_task`/`error` metric
and a distinct `[cron-error]` log line; a 5xx emits `http_5xx`. Wire real
notifications in the Cloudflare dashboard: Notifications → on Workers error-rate,
or a Logpush job filtered to `[cron-error]` → your channel (email/Slack/PagerDuty).

## Incident response — first checks

1. `wrangler tail` — look for `[request-error]` and recent exceptions.
2. Cloudflare status + Workers/D1/R2 dashboards — platform-level issues.
3. `audit_events` (D1) — what the system recorded around the incident window.
4. Scans stuck in `running`? A stuck-scan reconciler exists; check the scans table
   + R2 placeholder. Hosted DMARC diverged? The write-ahead intent + sweep
   reconciler self-heal on the next hourly cron.

## Quota / scale watch (before and during public beta)

- **D1:** free 100k reads/day, paid 10M/day. Each scan ≈ 50 queries.
- **Worker:** 30s CPU + 1000 subrequests **per invocation**; each `waitUntil` scan
  is its own invocation (scales horizontally). Cron batch is bounded (`LIMIT 20`).
- **R2:** storage cost grows with retained reports; the retention cron prunes them.
- **Rate limits:** a coarse per-IP global guard (reads 300 / writes 60 per 5 min)
  plus stricter per-route limits (login, signup, free-scan, invites, scans).
