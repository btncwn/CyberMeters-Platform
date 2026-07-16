# CyberMeters Platform

CyberMeters is a multi-tenant, evidence-led **Cyber MOT platform** for small businesses, IT support providers and MSPs.

It helps organisations understand, prioritise, manage and verify their externally observable security posture across eight canonical domains:

1. Email Protection
2. Brand Protection
3. Attack Surface
4. Certificates & Trust
5. Cyber Essentials Readiness
6. Website Security
7. Identity Exposure
8. Shadow IT & Unmanaged Technology

CyberMeters is not a generic vulnerability scanner, penetration-testing platform, DAST product, EDR, SIEM or internal asset-discovery system.

The product focuses on turning external evidence into an operational lifecycle:

```text
Observe
→ assess evidence
→ explain risk
→ prioritise
→ resolve canonical remediation
→ open or link a managed case
→ assign ownership
→ track action
→ verify outcome
→ monitor recurrence
→ reopen when required
```

---

## Current Product Phase

CyberMeters is in:

> **Pre-public-beta managed-platform completion**

The platform foundations are live, and the current focus is completing the managed lifecycle across all eight domains before controlled external invitations.

Current roadmap state:

| Platform Area | Status |
| --- | --- |
| Eight-Domain Coverage-State Honesty | Live |
| Canonical Remediation Registry | Live |
| Universal Managed-Case Model (incl. enforced invariants) | Live |
| Shadow IT Approved Inventory + Correlation Depth | Live |
| Certificates Managed Lifecycle | Live |
| Identity Exposure Managed Workflow | Live |
| Complete ASM Verification | Live |
| Alerts Across All Eight Domains | Live — 8 of 8 domains alert canonically. Engineering closed; genuine live-event acceptance outstanding. |
| MSP Portfolio Per-Domain State and Trend | Live — built, NOT customer-accepted. Engineering closed; authenticated customer acceptance outstanding. |
| M5 Completion Across All Eight Domains | In progress — evidence-honesty corrective closed (`v2026.07.16-6`); remaining increments planned. |
| Debugging and Reliability Hardening | Planned after managed lifecycle completion |
| Pentesting and Security Assurance | Planned after managed lifecycle completion |
| Founder-Controlled Acceptance Testing | Planned |
| Final Public-Beta Gate | Planned |

---

# Product Capabilities

## Email Protection

Externally observable email-security posture and managed email-authentication readiness, including:

- SPF
- DKIM
- DMARC
- DMARC aggregate-report ingestion
- sender intelligence
- policy readiness
- MTA-STS
- TLS-RPT
- BIMI where applicable
- BEC exposure interpretation
- remediation guidance

CyberMeters distinguishes between:

- DNS configuration;
- report ingestion;
- sender alignment;
- enforcement readiness;
- externally verifiable state.

Reports arriving do not automatically mean DNS is fully connected or correctly configured.

---

## Brand Protection

Externally observable brand-abuse and impersonation signals, including:

- lookalike domains
- typosquatting
- homoglyphs
- certificate-related brand observations
- candidate review
- classification
- evidence bundles
- prepare-and-track takedown workflows
- recurrence monitoring

CyberMeters does not claim to independently perform or guarantee takedown.

---

## Attack Surface

Externally visible assets and exposure signals, including:

- subdomains
- DNS
- takeover risk
- public admin interfaces
- development and staging exposure
- public management surfaces
- cloud-storage observations
- externally visible technologies
- selected vulnerability intelligence
- historical asset tracking

The platform prioritises evidence quality, false-positive reduction and managed remediation over raw finding volume.

---

## Certificates & Trust

Externally observable certificate and HTTPS posture, including:

- expiry
- issuer observations
- subject and SAN observations
- wildcard use
- replacement detection
- Certificate Transparency signals
- hostname coverage
- renewal readiness
- trust-related anomalies

Unsupported trust claims remain explicit.

Unless verified by a supported source, values such as complete chain validity, trusted-root status, OCSP and revocation remain `unknown`.

---

## Cyber Essentials Readiness

Indicative readiness based on:

- externally observable controls
- scan evidence
- customer-provided answers
- gap mapping
- canonical remediation
- managed follow-up

CyberMeters does not issue Cyber Essentials certification.

Certification is completed through an appropriate accredited assessment body.

---

## Website Security

Externally observable website posture, including:

- HTTPS availability
- HTTP-to-HTTPS redirect
- security headers
- cookie flags
- exposed technologies
- public configuration weaknesses
- externally visible website-risk indicators

---

## Identity Exposure

Externally observable identity-facing exposure, including:

- public login surfaces
- identity-provider observations
- Microsoft 365-related external signals
- legacy-authentication indicators where supported
- externally visible identity entry points

CyberMeters does not claim leaked-password, breached-credential, stealer-log or dark-web coverage unless a real approved evidence source is implemented.

---

## Shadow IT & Unmanaged Technology

Managed inventory for externally observed technology and SaaS signals, including:

- SaaS portals
- vendors
- third-party scripts
- provider relationships
- cloud services
- identity providers
- email-service providers
- customer classification
- approved inventory
- business and technical ownership
- onboarding and removal tracking
- monitoring and recurrence
- managed-case linkage

CyberMeters observation and customer classification are separate concepts.

```text
externally observed
≠
customer approved
```

---

# Core Platform Features

Implemented platform foundations include:

- multi-tenant workspaces
- workspace domains
- domain ownership verification
- email/password authentication
- Microsoft SSO
- MFA/TOTP
- email verification
- password reset
- session metadata
- login history
- audit logs
- Stripe billing
- subscription and entitlement handling
- scheduled scans
- historical monitoring
- asset inventory and asset events
- reports
- Executive Reports
- Executive PDF
- eight-domain coverage-state model
- Canonical Remediation Registry
- Universal Managed-Case Model
- ASM managed cases
- Brand managed cases
- Shadow IT Approved Inventory
- DMARC sender intelligence
- Cyber Essentials Readiness
- certificate intelligence
- notification infrastructure
- portfolio and MSP foundations

---

# Architecture

CyberMeters is designed to remain Cloudflare-native.

## Frontend

- React
- Vite
- Tailwind CSS
- Cloudflare Pages

## Backend

- Cloudflare Workers
- modular route handlers
- shared engine modules
- cron-triggered scheduled work
- inbound email handling

## Data

- Cloudflare D1 for relational state
- Cloudflare R2 for report objects and PDFs
- Analytics Engine for selected operational metrics

## External Services

- Stripe for billing
- Resend for outbound email
- Microsoft Entra ID for SSO
- Cloudflare Email Routing for DMARC aggregate reports
- Cloudflare DNS APIs for approved hosted-DMARC workflows

Do not introduce traditional Node servers, Express.js, dedicated VPS infrastructure or a second authoritative relational database without an approved architecture decision.

---

# Repository Layout

```text
CyberMeters-Platform/

frontend/
  src/
    api.js
    components/
    data/
    lib/
    pages/

workers/
  scan-api/
    src/
      engines/
      lib/
      routes/
      index.js

  email-ingest/
    wrangler.toml

database/
  schema.sql
  migrations/

scripts/

docs/

.github/
  workflows/

README.md
AGENTS.md
CLAUDE.md
OPERATIONS.md
CHANGELOG.md
```

Important paths:

| Path | Purpose |
| --- | --- |
| `frontend/src/pages/` | application pages |
| `frontend/src/components/` | shared UI components |
| `frontend/src/lib/` | frontend helpers and canonical presentation logic |
| `workers/scan-api/src/engines/` | domain engines, state machines, correlation, scoring and verification |
| `workers/scan-api/src/routes/` | workspace-scoped API routes |
| `database/migrations/` | additive production schema changes |
| `scripts/` | validators, regression harnesses and operational checks |
| `docs/` | ADRs, runbooks, product rules and release documentation |

---

# Requirements

Recommended local environment:

- Node.js 20 or later
- npm
- Wrangler 4.x
- Git
- Cloudflare account access
- access to the required D1, R2 and Worker bindings for deployment work

Check versions:

```bash
node --version
npm --version
npx wrangler --version
git --version
```

---

# Local Development

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Build:

```bash
npm run build
```

Preview:

```bash
npm run preview
```

Tests:

```bash
npm run test
npm run test:coverage
```

---

## Worker

```bash
cd workers/scan-api
npm install
npm run dev
```

Syntax check:

```bash
node --input-type=module --check < src/index.js
```

Dry-run bundle validation:

```bash
npx wrangler deploy --dry-run
```

---

# Environment and Configuration

## Frontend

Frontend build-time variables use the Vite `VITE_*` convention. The committed
template is `frontend/.env.example`; copy it to `frontend/.env` and set the value.

The frontend reads exactly one variable, and it is required:

```text
VITE_API_BASE_URL=https://api.cybermeters.com/api
```

The trailing `/api` segment is part of the value. Requests are built as
`${BASE}${path}` with a bare path (e.g. `/auth/login`), so the API resolves to
`https://api.cybermeters.com/api/auth/login`. Omitting `/api` here — or adding it to
the request paths as well — breaks every call.

In production the value comes from the Cloudflare Pages build-environment settings,
not from a file in the repository.

Do not place secrets in frontend environment files.

Any `VITE_*` value becomes part of the client bundle.

---

## Worker non-secret configuration

Non-secret production configuration belongs in:

```text
workers/scan-api/wrangler.toml
```

Examples may include:

- `ALLOWED_ORIGIN`
- `FRONTEND_URL`
- `RUA_INBOUND_DOMAIN`
- `MICROSOFT_REDIRECT_URI`
- sender addresses

The current source and Wrangler configuration are authoritative.

---

## Worker secrets

Manage secrets with Wrangler:

```bash
cd workers/scan-api
npx wrangler secret list
npx wrangler secret put <NAME>
```

Common secrets include:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `RESEND_API_KEY`
- `MFA_ENCRYPTION_KEY`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_TENANT_ID`
- `ADMIN_EMAILS`
- `APP_URL`

Never commit secret values.

---

# Database

The baseline schema is stored in:

```text
database/schema.sql
```

Production changes use numbered migrations:

```text
database/migrations/NNN-description.sql
```

## Apply a migration

From the repository root:

```bash
npx wrangler d1 execute cybermeters-db \
  --remote \
  --file=database/migrations/<NNN-name>.sql
```

## Read-only inspection

```bash
npx wrangler d1 execute cybermeters-db \
  --remote \
  --command "SELECT ... LIMIT 100;"
```

## Database rules

- every production schema change requires a migration;
- prefer additive migrations;
- do not apply hidden inline production DDL;
- do not routinely apply `database/schema.sql` to production;
- do not perform destructive migrations without explicit approval;
- preserve historical data;
- review tenant isolation and purge order.

---

# Validation

Deployment is not validation.

## Repository checks

```bash
git status --short
git diff --check
git log --oneline -5
```

## Backend checks

```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-regression-fixtures.js

cd workers/scan-api
npx wrangler deploy --dry-run
cd ../..
```

Run all focused validators relevant to the change.

## Frontend checks

```bash
cd frontend
npm ci
npm run test
npm run test:coverage
npm run build
cd ..
```

## Full validation gate

Run the full CI-equivalent gate when changing:

- authentication
- authorisation
- tenant isolation
- managed cases
- verification
- canonical remediation
- scan orchestration
- scoring
- reports or PDFs
- billing
- scheduled work
- alerts
- RUA ingestion
- deletion or purge
- core database behaviour

Do not weaken validators merely to make a change pass.

---

# Release and Deployment

## Primary Worker

The primary Worker deploys manually.

Pushing to `main` does not deploy the Worker.

Canonical release flow:

```text
feature branch
→ implementation
→ focused validation
→ full gate where required
→ PR
→ CI green
→ merge
→ additive migration if required
→ manual Worker deploy
→ Pages verification
→ release tag
→ CHANGELOG
→ production proof
```

Deploy:

```bash
cd workers/scan-api
npx wrangler deploy
```

Record the live Version ID printed by Wrangler.

## Frontend

Cloudflare Pages auto-deploys from `main`.

After merge, verify:

- expected commit
- build success
- production alias
- API base URL
- affected pages
- browser-console errors

## Email-ingest Worker

```bash
cd workers/scan-api
npx wrangler deploy --config ../email-ingest/wrangler.toml
```

## Release tag

```bash
git tag vYYYY.MM.DD-n
git push origin vYYYY.MM.DD-n
```

See `OPERATIONS.md` for the full production procedure.

---

# Rollback

## Worker

```bash
cd workers/scan-api
npx wrangler deployments list
npx wrangler versions list
npx wrangler rollback --version-id <version-id>
```

## Frontend

Use Cloudflare Pages deployment rollback or revert the offending commit on `main`.

## Database

Migrations are forward-only.

For a bad migration:

- roll back code if safe;
- inspect D1 Time Travel;
- create a corrective migration or approved restore;
- do not improvise destructive SQL under incident pressure.

See `OPERATIONS.md`.

---

# Health and Observability

## Health endpoints

```text
GET /health
GET /ready
```

- `/health` provides liveness and deployment information.
- `/ready` checks required dependencies such as D1 and R2.

## Live logs

```bash
cd workers/scan-api
npx wrangler tail
```

## Operational metrics

CyberMeters uses the Analytics Engine dataset:

```text
cybermeters_metrics
```

Operational metrics must remain fail-open and must not block customer workflows.

## Audit events

Business and security-relevant actions are recorded in D1 audit and domain-specific event tables.

Never log:

- access tokens
- reset tokens
- invitation tokens
- secrets
- plaintext MFA material
- unnecessary customer data
- raw internal exceptions to customers

---

# Scheduled Work

Scheduled execution is configured in Wrangler and currently runs hourly.

Scheduled tasks may include:

- scheduled scans
- scheduled reports
- user-report processing
- hosted-DNS verification
- reconciliation
- report retention
- deletion purge
- lifecycle-email retry
- alert retry
- domain-verification retry
- lifecycle monitoring evaluators

Every scheduled task must be:

- bounded
- idempotent or safely retryable
- independently failure-isolated
- tenant-safe
- soft-delete aware
- duplicate-notification safe
- observable

---

# Multi-Tenant Security

CyberMeters is already multi-tenant.

Every workspace-scoped read and write must be:

- workspace-scoped
- permission-checked
- tenant-isolated
- non-enumerating where appropriate
- auditable

Foreign and nonexistent resources should return the same safe response when resource enumeration is a risk.

Soft-deleted workspaces must not receive:

- new scans
- observations
- inventory records
- managed cases
- reports
- scheduled work
- alerts
- notifications

New workspace-scoped surfaces require tenant-isolation tests.

---

# Evidence and Product Honesty

## Coverage-state honesty

Missing, incomplete or unsupported evidence must not appear healthy.

The frontend must not independently derive security verdicts.

## Remediation

Customer-facing remediation meaning must come from the Canonical Remediation Registry.

## Managed cases

All case transitions use the Universal Managed-Case Model.

Base case creation uses:

```text
createManagedCase(...)
```

Transitions use:

```text
canTransitionCase(...)
```

## Verification

A completed scan, customer note or bare boolean cannot verify a fix.

Verification requires structured, method-appropriate evidence.

Customer assertion and CyberMeters verification are different states.

## Historical integrity

Do not overwrite or erase:

- observations
- reports
- case events
- evidence
- remediation identities
- verification history
- inventory history
- certificate history
- replacement relationships
- recurrence history
- audit events

---

# Capacity and Paid Infrastructure

CyberMeters currently operates on the Cloudflare Workers Paid plan.

Do not use the old estimate:

```text
each scan ≈ 50 queries
```

as a cost or capacity model.

D1 usage should be measured through:

- rows read
- rows written
- query latency
- index use
- database size
- scheduled-cycle amplification
- report and lifecycle writes

Worker usage should be measured through:

- CPU milliseconds
- duration
- subrequests
- outbound fetches
- D1 operations
- R2 operations
- exceptions
- retries
- scheduled backlog

Paid limits provide headroom, not permission for unbounded processing.

See `OPERATIONS.md` for current operational assumptions and monitoring rules.

---

# Contributing and Engineering Workflow

Before implementation:

1. identify the active canonical roadmap episode;
2. inspect repository status;
3. inspect the active branch;
4. review recent commits and PRs;
5. review recent migrations;
6. inspect the existing architecture;
7. search for duplicate functionality;
8. define scope and compatibility risk;
9. extend canonical systems instead of creating parallel ones.

After implementation:

1. run focused validators;
2. run the full gate where required;
3. review the diff;
4. open a focused PR;
5. require CI green;
6. merge;
7. apply migration if needed;
8. deploy manually;
9. verify Pages;
10. record live and rollback IDs;
11. update release documentation;
12. perform production proof;
13. stop after the assigned episode.

Read:

- `AGENTS.md` for permanent engineering rules;
- `CLAUDE.md` for AI engineering authority and product ownership;
- `OPERATIONS.md` for production operations;
- `CHANGELOG.md` for releases.

---

# Public-Beta Gate

Before the first two controlled external invitations:

- complete the remaining canonical roadmap;
- complete debugging and reliability hardening;
- complete security testing and pentesting;
- complete founder-controlled acceptance testing;
- confirm billing and entitlements;
- confirm all eight domain states;
- confirm reports and PDFs;
- confirm managed cases and alerts;
- rerun tenant-isolation testing;
- verify rollback;
- close all P0 and P1 blockers.

The first cohort should remain controlled:

- one real small business;
- one small MSP or IT-support provider.

This is not an unrestricted public launch.

---

# Documentation Map

| Document | Purpose |
| --- | --- |
| `README.md` | product, architecture, setup and development |
| `AGENTS.md` | permanent engineering constitution and roadmap discipline |
| `CLAUDE.md` | AI product ownership, implementation and release authority |
| `OPERATIONS.md` | production deploy, rollback, secrets, observability and incident response |
| `CHANGELOG.md` | release history |
| `docs/` | ADRs, runbooks, product rules and release gates |

---

# Licence and Commercial Status

CyberMeters is a proprietary commercial SaaS platform.

Do not assume the repository is open source unless an explicit licence file states otherwise.

---

# Final Principle

CyberMeters is not measured by the number of scanners, findings or dashboards it contains.

It is measured by whether a real organisation can:

- understand its external exposure;
- know what matters;
- assign ownership;
- act on clear remediation;
- verify outcomes;
- monitor recurrence;
- trust the platform.
