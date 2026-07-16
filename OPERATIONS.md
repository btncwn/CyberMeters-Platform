# CyberMeters — Operations Runbook

Version: July 2026

Last updated: 14 July 2026

Operational runbook for deploying, operating, observing, recovering and securing CyberMeters in production.

This document complements:

- `README.md` — local development and common developer commands;
- `AGENTS.md` — permanent engineering rules and canonical roadmap;
- `CLAUDE.md` — product ownership, implementation authority and release behaviour;
- `CHANGELOG.md` — deployed release history.

CyberMeters is currently in **pre-public-beta managed-platform completion**.

---

# 1. Architecture at a Glance

| Piece | Purpose | Location / Binding |
|---|---|---|
| **Primary API and engine** | REST API, scan orchestration, cron work, scoring, reports, managed cases and lifecycle engines | Worker `cybermeters-platform`, entry point `workers/scan-api/src/index.js` |
| **Frontend** | React/Vite/Tailwind SPA | `frontend/`, deployed through Cloudflare Pages |
| **Database** | Multi-tenant relational state | D1 `cybermeters-db`, binding `cybermeters_db` |
| **Object storage** | Scan reports, generated report objects and PDFs | R2 bucket `cybermeters-reports`, binding `cybermeters_reports` |
| **Scheduled work** | Bounded scheduled scans, reports, retries, reconciliation and retention | Worker `scheduled()` handler |
| **Inbound DMARC email** | Aggregate-report ingestion through Cloudflare Email Routing | Worker `email()` handler |
| **Metrics** | Fail-open operational events | Analytics Engine dataset `cybermeters_metrics`, binding `METRICS` |
| **Audit trail** | Customer and system business events | D1 `audit_events` and domain-specific append-only event tables |

Current D1 database:

```text
cybermeters-db
fd6792cb-441a-44a7-8ca2-9a0b411ec706
```

Do not hardcode Cloudflare resource IDs in application logic.

---

# 2. Current Infrastructure Plan

CyberMeters currently operates on the **Cloudflare Workers Paid plan**.

Do not describe production infrastructure as remaining on Workers Free.

Paid capacity provides additional headroom, but it does not remove:

- CPU constraints;
- memory constraints;
- cost exposure;
- D1 row-processing costs;
- R2 growth;
- retry amplification;
- the need for bounded scheduled work;
- the need for indexing and query optimisation.

---

# 3. Release Model

## Branch protection — solo-founder policy (canonical)

`main` is protected. The policy below is DELIBERATE and is not a temporary exception.

| Setting | Value |
| --- | --- |
| `required_status_checks` | **`validate`, `sast`** (strict: false) |
| `required_approving_review_count` | **0** |
| `dismiss_stale_reviews` | true |
| `required_conversation_resolution` | true |
| `enforce_admins` | true |
| `allow_force_pushes` | false |
| `allow_deletions` | false |

**Why approvals are 0.** This repository has exactly ONE human GitHub account, and GitHub
refuses self-approval ("Can not approve your own pull request"). A required approval count of
1 therefore made every PR unmergeable and forced repeated temporary protection windows —
weakening the branch on a schedule is worse governance than a policy that tells the truth
about who is here.

> **Raise `required_approving_review_count` to 1 the moment a genuine independent
> collaborator or reviewer joins the repository.** It is 0 because there is nobody to review,
> not because review is unwanted. This is the one line to change.

**What actually gates a merge now: CI, not a rubber stamp.** `validate` and `sast` are
REQUIRED contexts, so a PR with failing or missing mandatory CI cannot merge — including for
admins (`enforce_admins: true`). `--admin` is not needed in normal operation and must not be
used to bypass a red check.

**Why only `validate` and `sast` are required** — read from the actual check contexts of the
last seven PRs, not invented:

- `validate` — 7/7 PRs. Runs the repository validators, frontend type-check, Vitest coverage
  and `npm run build`. The build IS covered here.
- `sast` — 7/7 PRs. Security analysis.
- `playwright` — 2/7. It lives in `frontend-e2e.yml`, which is path-filtered to `frontend/**`,
  so it does not run for backend- or docs-only PRs. A required context that never reports
  stays pending forever, so requiring it would permanently block every non-frontend PR — the
  exact deadlock this policy exists to remove. It still runs and still blocks frontend PRs
  through the PR UI; it is simply not a merge gate for changes it never examines.
- `Cloudflare Pages` — 7/7, but it is a third-party deployment preview, not a correctness
  gate, and `validate` already builds the frontend. Requiring it would make every merge
  depend on Cloudflare's availability and would reintroduce the need for `--admin` during an
  incident, contradicting the requirement that no bypass is needed in normal operation.

If a new mandatory job is added to `ci.yml`, add its job name to the required contexts. The
context name IS the job key in the workflow.

## Primary Worker

The primary Worker deploys manually only.

Canonical flow:

```text
feature branch
→ focused validation
→ PR
→ CI green
→ merge to main
→ apply additive migration if required
→ manual Worker deploy
→ verify live deployment
→ verify Pages deployment
→ release tag
→ CHANGELOG
→ production proof
```

Pushing to `main` does not deploy the Worker.

## Frontend

Cloudflare Pages remains connected to Git and auto-deploys after merge to `main`.

Public `VITE_*` values are build-time frontend configuration and must never contain secrets.

## Email Worker

Deploy the separate email-ingest Worker only with its dedicated configuration:

```bash
cd workers/scan-api
npx wrangler deploy --config ../email-ingest/wrangler.toml
```

---

# 4. Pre-Deployment Gate

Deployment is not validation.

## Repository sanity

```bash
git status --short
git diff --check
git log --oneline -5
```

Do not deploy with unrelated modified files.

## Worker validation

```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-regression-fixtures.js

cd workers/scan-api
npx wrangler deploy --dry-run
cd ../..
```

Also run every focused validator relevant to the change.

Do not hardcode expected assertion counts in this runbook. Compare against CI and the most recent release.

## Frontend validation

```bash
cd frontend
npm ci
npm run test
npm run test:coverage
npm run build
cd ..
```

## Full gate required for shared systems

Run the full CI-equivalent gate when changing:

- authentication;
- authorisation;
- tenant isolation;
- managed-case state machines;
- verification;
- canonical remediation;
- scan orchestration;
- scoring;
- reports or PDFs;
- database lifecycle;
- billing;
- scheduled work;
- alerts or notifications;
- RUA ingestion;
- workspace deletion or purge.

---

# 5. Deploy

## Confirm current live version

```bash
cd workers/scan-api
npx wrangler deployments list
```

Record the current known-good Version ID.

Verify liveness:

```bash
curl -sS https://api.cybermeters.com/health
```

Use the actual production API hostname if different.

## Apply migration

From the repository root:

```bash
npx wrangler d1 execute cybermeters-db   --remote   --file=database/migrations/<NNN-name>.sql
```

Immediately verify the expected schema or rows:

```bash
npx wrangler d1 execute cybermeters-db   --remote   --command "SELECT ...;"
```

Never apply `database/schema.sql` directly to production as a normal migration.

## Deploy Worker

```bash
cd workers/scan-api
npx wrangler deploy
```

Record the printed Version ID.

Then verify:

```bash
curl -sS https://api.cybermeters.com/health
curl -i -sS https://api.cybermeters.com/ready
```

A protected route returning `401` proves only that the route exists and authentication is enforced.

It does not prove the customer workflow.

## Verify Pages

Confirm in Cloudflare Pages:

- intended commit;
- successful production build;
- correct production alias;
- correct API base URL;
- no runtime errors on affected pages.

## Tag and changelog

```bash
git tag vYYYY.MM.DD-n
git push origin vYYYY.MM.DD-n
```

Record:

- feature PR;
- merge commit;
- migration;
- validation summary;
- live Worker Version ID;
- rollback Worker Version ID;
- Pages status;
- known limitations.

---

# 6. Rollback

## Worker rollback

```bash
cd workers/scan-api
npx wrangler deployments list
npx wrangler versions list
npx wrangler rollback --version-id <version-id>
```

After rollback:

```bash
curl -sS https://api.cybermeters.com/health
curl -i -sS https://api.cybermeters.com/ready
npx wrangler tail
```

## Frontend rollback

Use one of:

1. Cloudflare Pages deployment rollback;
2. revert the offending commit on `main`.

Verify API compatibility after rollback.

## Database recovery

Repository migrations are forward-only.

For a bad migration:

1. roll back code if safe;
2. inspect D1 Time Travel availability;
3. create a corrective migration or approved restore;
4. never improvise destructive SQL under incident pressure;
5. record every repair action.

An additive migration may remain after code rollback when old code safely ignores the new schema.

---

# 7. Secrets and Configuration

## Non-secret configuration

Non-secret values live in:

```text
workers/scan-api/wrangler.toml
```

Examples may include:

- `ALERT_EMAIL_TO`;
- `ALERT_EMAIL_FROM`;
- `SAFE_EMAIL_FROM`;
- `HELLO_EMAIL_FROM`;
- `ALLOWED_ORIGIN`;
- `RUA_INBOUND_DOMAIN`;
- `FRONTEND_URL`;
- `MICROSOFT_REDIRECT_URI`.

The code and current Wrangler configuration are authoritative.

## Secret management

```bash
cd workers/scan-api
npx wrangler secret list
npx wrangler secret put <NAME>
```

Never commit or log secret values.

## Sensitive secrets and bindings

| Secret / binding | Purpose | Rotation rule |
|---|---|---|
| `STRIPE_SECRET_KEY` | Stripe server API | Rotate in Stripe, update Worker secret, run billing smoke |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook verification | Rotate endpoint and Worker secret together |
| `RESEND_API_KEY` | Outbound email | Rotate in Resend, update secret, run founder-controlled test |
| `MFA_ENCRYPTION_KEY` | Encrypt stored TOTP secrets | Do not rotate without migration and re-enrolment plan |
| `CLOUDFLARE_API_TOKEN` | Approved hosted DNS / email-routing operations | Least privilege |
| `CLOUDFLARE_ZONE_ID` | Hosted-DMARC zone context | Sensitive configuration |
| `AZURE_CLIENT_ID` | Microsoft SSO application | Coordinate with Entra |
| `AZURE_CLIENT_SECRET` | Microsoft SSO secret | Rotate before expiry and run SSO smoke |
| `AZURE_TENANT_ID` | Microsoft tenant configuration | Confirm tenant model before changing |
| `ADMIN_EMAILS` | Admin allow-list | Restrict and audit |
| `APP_URL` | Absolute URL generation | Must match production origin |

Search actual usage before adding or removing configuration:

```bash
rg "env\.[A-Z0-9_]+" workers/scan-api/src
```

---

# 8. Database Operations

## Schema sources

- baseline schema: `database/schema.sql`;
- production changes: `database/migrations/NNN-*.sql`.

## Read-only inspection

```bash
npx wrangler d1 execute cybermeters-db   --remote   --command "SELECT ... LIMIT 100;"
```

Avoid broad production dumps containing customer data.

## Data safety

Every production query must consider:

- workspace scope;
- soft-delete state;
- tenant isolation;
- append-only history;
- retention;
- purge order.

Never perform destructive SQL without explicit founder approval.

---

# 9. Scheduled Work

The primary cron schedule is configured in `workers/scan-api/wrangler.toml`.

Expected schedule:

```cron
0 * * * *
```

The source code is authoritative for the current task list.

Scheduled work may include:

- scheduled scans;
- scheduled and user reports;
- hosted-DNS verification and reconciliation;
- report retention;
- soft-delete purge;
- lifecycle-email retry;
- asset-alert retry;
- domain-verification retry;
- lifecycle evaluators.

Each task must:

- be bounded;
- fail independently;
- be idempotent or safely retryable;
- respect soft-deleted workspaces;
- avoid duplicate notifications;
- emit useful metrics and logs.

---

# 10. Observability

## Live logs

```bash
cd workers/scan-api
npx wrangler tail
```

Never log:

- access tokens;
- reset tokens;
- invitation tokens;
- secret values;
- plaintext MFA material;
- unnecessary full customer email addresses;
- complete inbound DMARC XML unless explicitly protected.

## Health and readiness

```text
GET /health
GET /ready
```

Use:

- `/health` for liveness and deployment ID;
- `/ready` for D1/R2 dependency readiness.

## Analytics Engine

Dataset:

```text
cybermeters_metrics
```

Binding:

```text
METRICS
```

Example:

```sql
SELECT
  blob1 AS task,
  blob2 AS outcome,
  count() AS n,
  avg(double1) AS avg_ms
FROM cybermeters_metrics
WHERE blob1 != ''
  AND timestamp > NOW() - INTERVAL '1' DAY
GROUP BY task, outcome
ORDER BY n DESC;
```

Metrics writes must remain fail-open.

---

# 11. Incident Response

## SEV-1

Examples:

- cross-tenant exposure;
- authentication bypass;
- destructive data loss;
- secret compromise;
- broad Stripe entitlement failure;
- complete production outage.

Actions:

1. contain;
2. preserve evidence;
3. roll back if safe;
4. rotate compromised secrets;
5. identify affected workspaces;
6. preserve audit history;
7. escalate to founder;
8. record UTC timeline.

## First checks

1. `/health`;
2. `/ready`;
3. `wrangler tail`;
4. Cloudflare status;
5. Workers/D1/R2/Pages dashboards;
6. Analytics Engine;
7. `audit_events`;
8. latest deploy;
9. latest migration;
10. customer side effects.

## Tenant-isolation incident

Treat as SEV-1.

Check both:

- route-level access control;
- SQL workspace scoping.

Add a regression test before restoring service.

## Billing incident

Check:

- Stripe event ID;
- signature verification;
- idempotency;
- subscription row;
- entitlements;
- grace period;
- cancellation date;
- audit events.

## DMARC ingestion incident

Check:

- Email Routing;
- recipient mapping;
- token-to-domain/workspace mapping;
- XML parse;
- dedupe;
- D1 aggregate rows;
- sender-source rows;
- hosted-DNS intent and reconciliation.

---

# 12. Capacity, Quota and Cost Watch

Cloudflare limits and pricing change.

The Cloudflare dashboard and current official documentation are authoritative.

## 12.1 D1 — Workers Paid

Do not use:

```text
each scan ≈ 50 queries
```

as a capacity or cost assumption.

A query count does not show how many rows D1 processed.

The current D1 Paid allowance documented by Cloudflare is:

- first 25 billion rows read per month included;
- first 50 million rows written per month included;
- first 5 GB storage included;
- usage above included allowances is billed.

Operational capacity must be measured using:

- rows read per scan;
- rows written per scan;
- rows read and written per scheduled cycle;
- query latency;
- database size;
- index use;
- full-table scans;
- workspaces and monitored domains;
- scan frequency;
- report and lifecycle write amplification.

D1 returns `rows_read` and `rows_written` metadata for executed queries.

Use that metadata plus Cloudflare D1 analytics to establish real profiles for:

- small domain scan;
- medium domain scan;
- large domain scan;
- scheduled monitoring cycle;
- report generation;
- managed-case update;
- DMARC ingestion.

Do not publish a fixed per-scan number until it is produced by a repeatable benchmark.

## 12.2 Workers — Paid

The old assumptions:

```text
30 seconds CPU
1,000 subrequests per invocation
```

are no longer valid as universal limits.

Current Workers Paid defaults and ceilings include:

- default CPU limit: 30,000 ms per invocation;
- configurable CPU limit: up to 300,000 ms where supported;
- default subrequest limit: 10,000 per invocation;
- configurable paid-plan subrequest limit: up to 10,000,000.

The effective CyberMeters values are those configured in:

```text
workers/scan-api/wrangler.toml
```

or the Cloudflare dashboard.

Do not increase limits merely because the Paid plan allows it.

Before changing `cpu_ms` or `subrequests`:

1. measure actual usage;
2. identify the exact workload;
3. check for N+1 or unbounded loops;
4. confirm scheduled work remains bounded;
5. estimate cost and failure impact;
6. add resource-budget tests;
7. document the approved limit.

Track:

- CPU milliseconds by route/task;
- duration;
- request count;
- exceeded-resource outcomes;
- outbound fetches;
- D1 rows processed;
- R2 operations;
- memory pressure;
- scheduled backlog;
- retry amplification.

Paid capacity is headroom, not permission for unbounded scans.

## 12.3 R2

Track:

- object count;
- retained report size;
- PDF size;
- failed writes;
- missing objects;
- retention cleanup;
- report-access patterns.

## 12.4 Rate limits

The source code is authoritative for exact thresholds.

Security-sensitive write paths should generally fail closed.

---

# 13. Production Smoke

Use only founder-controlled workspaces and domains.

Common checks:

- login;
- workspace selection;
- affected API route;
- tenant boundary;
- scan start and completion;
- report retrieval;
- managed-case transition;
- canonical remediation;
- frontend rendering;
- audit event;
- no unexpected email.

For lifecycle features, prove actual behaviour.

A `401` is not workflow proof.

---

# 14. Public-Beta Operations Gate

Before the first two controlled invitations:

- complete the canonical roadmap;
- complete debugging;
- complete pentesting and security review;
- complete founder-controlled acceptance;
- confirm quota and budget headroom;
- confirm observability;
- confirm auth, billing, reports, alerts and deletion;
- rerun tenant isolation;
- close P0/P1 blockers.

First cohort:

- one real small business;
- one small MSP or IT-support provider.

---

# 15. Operational Change Record

For every production change, record:

```text
Change:
Owner:
UTC start:
Feature PR:
Merge commit:
Migration:
Previous Worker Version:
New Worker Version:
Pages deployment:
Release tag:
Validation:
Production proof:
Known limitations:
Rollback command:
UTC completion:
```

For incidents, also record:

```text
Severity:
Customer impact:
Affected workspaces:
Detection source:
Containment:
Root cause:
Corrective action:
Regression test:
Follow-up owner:
```

---

# 16. Final Operating Principles

- Prefer evidence over assumptions.
- Prefer rollback readiness over deployment speed.
- Prefer measured rows over query-count guesses.
- Prefer bounded work over larger resource limits.
- Prefer tenant isolation over convenience.
- Prefer structured logs and metrics over ad hoc debugging.
- Prefer founder-controlled smoke over customer-data testing.
- Prefer current Cloudflare documentation over stale limits.
- Never describe route existence as complete workflow proof.
