# AGENTS.md

# CyberMeters Platform — AI Engineering Context

Version: July 2026

Last updated: 16 July 2026 (release v2026.07.16-9; active canonical episode: M5 Completion Across All Eight Domains — in progress)

---

# 1. Project Overview

CyberMeters is a multi-tenant, evidence-led, managed Cyber MOT platform for small businesses and MSPs.

It helps organisations understand, prioritise, manage and verify their externally observable security posture.

CyberMeters is not a generic vulnerability scanner, penetration-testing platform, DAST product, EDR, SIEM or internal asset-discovery system.

CyberMeters provides an operational lifecycle across eight canonical customer-facing security domains:

1. Email Protection
2. Brand Protection
3. Attack Surface
4. Certificates & Trust
5. Cyber Essentials Readiness
6. Website Security
7. Identity Exposure
8. Shadow IT & Unmanaged Technology

These eight domains are canonical.

Do not describe the platform as four, six or seven domains.

Customer-facing security domains and internal scan modules are different concepts and must not be treated as interchangeable.

---

# 2. Current Product Phase

CyberMeters is in pre-public-beta managed-platform completion.

The objective is not to add more scanner breadth.

The objective is to complete an honest, evidence-led and operational lifecycle across all eight Cyber MOT domains while preserving:

- multi-tenant security;
- evidence honesty;
- backward compatibility;
- operational reliability;
- historical continuity;
- customer-facing consistency;
- commercial readiness.

CyberMeters is no longer in the Scanner Development Phase.

---

# 3. Primary Objective

Complete the eight-domain managed Cyber MOT lifecycle before public beta.

The target lifecycle is:

```text
Observe
→ Assess evidence
→ Explain risk
→ Prioritise
→ Resolve canonical remediation
→ Open managed case
→ Assign ownership
→ Track action
→ Verify outcome
→ Monitor recurrence
→ Reopen when required
```

CyberMeters must not claim to perform actions it cannot perform.

Customer, provider or external-party execution may still be required for:

- DNS changes;
- email configuration;
- website fixes;
- certificate renewal;
- identity hardening;
- brand takedown;
- SaaS removal;
- Cyber Essentials certification.

CyberMeters manages and verifies the lifecycle where externally observable evidence supports verification.

---

# 4. Current Strategic Status

| Platform Area | Status |
| --- | --- |
| Eight-Domain Coverage-State Honesty | Live |
| Canonical Remediation Registry | Live |
| Universal Managed-Case Model (incl. enforced invariants) | Live |
| Shadow IT Approved Inventory + Correlation Depth | Live |
| Certificates Managed Lifecycle | Live |
| Identity Exposure Managed Workflow | Live |
| Complete ASM Verification | Live |
| Alerts Across All Eight Domains | Live — 8 of 8 domains alert canonically (`docs/alerts-eight-domain-coverage.md`). Engineering closed; genuine live-event acceptance outstanding. |
| MSP Portfolio Per-Domain State and Trend | Live — built, NOT customer-accepted. Persisted per-domain state + honest trend across all 8 domains (mig 091). Engineering closed; authenticated customer acceptance outstanding (no entitled account exists in production), so it is not sellable and must not be demoed. |
| M5 Completion Across All Eight Domains | In progress — evidence-honesty corrective (`v2026.07.16-6`) and alerting repair (`v2026.07.16-7`) closed; remaining increments planned. |
| Final Public-Beta Gate | Planned after managed-platform completion |

Current release facts (as of 16 July 2026):

- latest release tag: `v2026.07.16-9` (M5 read surfaces for mig 088/089/090 — deployed);
- live Worker Version ID: `3ad513ee-bec5-4634-963f-eb08c57d7a43` (built from `62b7272`);
- rollback Worker Version ID: `db190243-5f44-4f70-ab4f-ecfe0427b8b7` (v2026.07.16-8);
- latest migration applied to production: `091-cyber-mot-domain-states.sql` (unchanged — none of `v2026.07.16-6` through `-9` carried a migration);
- active canonical episode: M5 Completion Across All Eight Domains (in progress).

**All eight canonical domains alert through the canonical pipeline.** The earlier
six-of-eight closure (`v2026.07.15-2`) was premature and is superseded — it deferred
Website Security and Cyber Essentials on reasoning that turned out to be wrong (CE's
readiness never read the questionnaire; Website Security's findings were persisted all
along). Both were buildable. `docs/alerts-eight-domain-coverage.md` is the
authoritative matrix and records why the original audit was wrong.

Two live P1s had to ship first, neither about alerting: a probe that never executed
reported `scan_quality: complete` and rendered Website Security **assessed_healthy**
for a site nobody could reach (#105), and `cyber_essentials_answers` survived every
workspace purge while the deletion email said "permanently removed" (#106).

Genuine live occurrence proof is outstanding for **every** domain: alerting is proven
by CI and no-op deployment only. Controlled, founder-led acceptance with real events
remains a release-gate activity.

The founder-approved commercial roadmap from product completion to the first paying customer is `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md`. It is the single authoritative copy of that plan.

Do not use speculative percentage-completion figures unless they come from an approved, current release-readiness assessment.

Use milestone status instead:

- Live
- Foundation live — completion planned
- In progress
- Next canonical episode
- Planned
- Blocked
- Deprecated

---

# 5. Current Canonical Roadmap

Priority order:

1. Certificates Managed Lifecycle (complete — Live)
2. Identity Exposure Managed Workflow (complete — Live)
3. Complete ASM Verification (complete — Live)
4. Alerts Across All Eight Domains (complete — Live, 8 of 8; genuine live-event acceptance outstanding)
5. MSP Portfolio Per-Domain State and Trend (Live — built, NOT customer-accepted; acceptance outstanding)
6. M5 Completion Across All Eight Domains (ACTIVE — in progress; evidence-honesty corrective closed, remaining increments planned)
7. Systematic debugging and reliability hardening
8. Security testing and pentesting
9. Founder-controlled acceptance testing
10. Final public-beta gate
11. First controlled customer invitations
12. Gradual cohort expansion

Do not begin a later phase before the active canonical episode is closed unless an immediate security or production incident requires intervention.

Cosmetic redesigns, homepage work, dashboard wording changes and service-label cleanup must not displace the active canonical roadmap.

New scanner development is not currently a priority.

New detection work is allowed only when it is required to:

- complete an existing managed lifecycle;
- close a confirmed coverage gap;
- support verification;
- prevent a material false positive or false negative;
- meet a defined public-beta gate.

---

# 6. Repository Layout

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

database/
  schema.sql
  migrations/

scripts/

docs/

.github/
  workflows/
```

Important areas:

- `workers/scan-api/src/engines/`
- `workers/scan-api/src/routes/`
- `frontend/src/pages/`
- `frontend/src/components/`
- `database/migrations/`
- `scripts/`

---

# 7. Core Commands

## Frontend

Run from `frontend/` where applicable:

```bash
npm run dev
npm run build
npm run preview
npm run test
npm run test:coverage
```

## Worker

Run from `workers/scan-api/` where applicable:

```bash
npm run dev
npm run deploy
```

Worker syntax check:

```bash
node --input-type=module --check < src/index.js
```

Worker dry run:

```bash
npx wrangler deploy --dry-run
```

## Validation

Typical validation sequence:

```bash
git diff --check
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/<relevant-validator>.js
npm run build
npm run test:coverage
npx wrangler deploy --dry-run
```

Run focused validators first.

Run the full regression and CI-equivalent gate when shared infrastructure, state machines, tenant isolation, scoring, reporting, cases or core API contracts change.

## Database

Production changes must use a migration file:

```bash
npx wrangler d1 execute cybermeters-db \
  --remote \
  --file=../../database/migrations/<migration-file>.sql
```

Never apply `database/schema.sql` directly to production unless explicitly authorised for:

- disaster recovery;
- a controlled rebuild;
- a verified empty-environment bootstrap.

Do not silently alter production tables.

---

# 8. Current Architecture

## Frontend

- React
- Vite
- Tailwind CSS
- Cloudflare Pages

## Backend

- Cloudflare Workers
- Modular route handlers
- Shared engine modules
- Cron-triggered scheduled processing

## Storage

- Cloudflare D1 for relational state
- Cloudflare R2 for reports and report-related objects

## Authentication and Account Security

- Email/password authentication
- Microsoft SSO
- MFA/TOTP
- Email verification
- Password reset hardening
- Session metadata
- Login history
- Audit events

## Billing

- Stripe Checkout
- Stripe webhooks
- Subscription and entitlement handling
- Plan and usage enforcement

## Operational Capabilities

- Scheduled monitoring
- Scan history
- Historical trends
- Report generation
- Executive reporting
- PDF reporting
- Notification infrastructure
- Managed cases
- Canonical remediation
- Workspace and tenant management

## Architecture Goal

Remain Cloudflare-native.

Do not introduce the following unless explicitly approved through an architecture decision:

- Express.js;
- traditional Node application servers;
- dedicated VPS infrastructure;
- a second relational database;
- a parallel job-processing platform;
- duplicated case or remediation systems.

---

# 9. Canonical Customer-Facing Security Domains

## 9.1 Email Protection

Externally observable email-security posture, including:

- SPF;
- DKIM;
- DMARC;
- MTA-STS;
- TLS-RPT;
- BIMI where applicable;
- sender intelligence;
- policy readiness;
- externally observable email-provider signals.

## 9.2 Brand Protection

Externally observable brand-abuse signals, including:

- lookalike domains;
- typosquatting;
- homoglyphs;
- certificate-related brand signals;
- candidate review;
- evidence bundles;
- prepare-and-track takedown workflows;
- recurrence monitoring.

Do not claim CyberMeters independently performs or guarantees takedown.

## 9.3 Attack Surface

Externally visible assets and exposure signals, including:

- subdomains;
- DNS;
- takeover risk;
- public admin interfaces;
- development or staging exposure;
- public management tools;
- cloud-storage observations;
- selected externally visible vulnerability intelligence.

## 9.4 Certificates & Trust

Externally observable certificate and HTTPS posture, including:

- expiry;
- replacement;
- coverage;
- issuer observations;
- Certificate Transparency signals;
- anomalies;
- renewal readiness.

When chain validity, root trust, OCSP or revocation status is not verified, the value must remain `unknown`.

## 9.5 Cyber Essentials Readiness

Indicative readiness based on:

- externally observable controls;
- scan evidence;
- customer-provided answers;
- control-gap mapping;
- canonical remediation.

CyberMeters does not issue Cyber Essentials certification.

Certification is performed externally through an appropriate accredited assessment body.

## 9.6 Website Security

Externally observable website posture, including:

- HTTPS availability;
- HTTP-to-HTTPS redirect;
- security headers;
- cookie flags;
- exposed technologies;
- externally visible configuration weaknesses.

## 9.7 Identity Exposure

Externally observable identity-facing exposure, including:

- public login surfaces;
- identity-provider exposure;
- Microsoft 365-related external signals;
- legacy-authentication indicators where supported;
- externally visible identity entry points.

Do not claim:

- leaked-password discovery;
- breached credential coverage;
- stealer-log coverage;
- dark-web monitoring;
- confirmed account compromise;

unless a real approved evidence source is implemented.

## 9.8 Shadow IT & Unmanaged Technology

Externally observed technology and SaaS signals, including:

- SaaS portals;
- vendors;
- third-party scripts;
- provider relationships;
- cloud-service observations;
- externally visible technology signals;
- customer classification;
- approved inventory;
- ownership;
- onboarding and removal tracking.

Do not claim:

- internal network discovery;
- endpoint software inventory;
- full SaaS licence visibility;
- employee browser history;
- internal CASB coverage;
- confirmed unauthorised use without customer classification.

---

# 10. Internal Detection and Analysis Modules

Internal modules may include:

- DNS analysis;
- SSL and HTTPS analysis;
- security headers;
- email authentication;
- subdomain discovery;
- subdomain takeover;
- asset exposure;
- admin-surface detection;
- brand-candidate detection;
- certificate intelligence;
- identity discovery;
- SaaS and vendor observation;
- cloud-asset observation;
- sender provenance;
- historical tracking;
- scoring;
- business-risk interpretation;
- reporting.

Internal module names must not be presented as customer-facing domain names unless explicitly mapped.

A customer-facing domain may use evidence from multiple internal modules.

An internal module may support more than one customer-facing domain.

---

# 11. Current Platform Capabilities

Implemented platform foundations include:

- multi-tenant workspaces;
- workspace domains;
- domain ownership verification;
- email/password authentication;
- Microsoft SSO;
- MFA/TOTP;
- audit logs;
- session history;
- Stripe billing;
- plan limits;
- scheduled scans;
- historical monitoring;
- assets and asset events;
- reports;
- Executive Report;
- Executive PDF;
- eight-domain coverage-state model;
- Canonical Remediation Registry;
- Universal Managed-Case Model;
- ASM managed cases;
- Brand managed cases;
- managed verification foundations;
- Shadow IT Approved Inventory;
- Shadow IT multi-source correlation, ownership and monitoring evaluation;
- DMARC sender intelligence;
- Cyber Essentials Readiness;
- certificate intelligence;
- certificate managed lifecycle (ownership, renewal planning, verification, monitoring);
- notification infrastructure;
- portfolio and MSP foundations.

Do not infer that every foundation is already complete at full managed-lifecycle depth.

Use the current roadmap status table.

---

# 12. Core Architectural Invariants

## 12.1 Coverage-State Honesty

Missing, incomplete, unsupported or unavailable evidence must never be presented as healthy.

The frontend must not independently derive security verdicts.

Coverage-state semantics belong to the backend canonical resolver.

## 12.2 Canonical Remediation

All customer-facing remediation meaning must resolve through the Canonical Remediation Registry.

The frontend may own presentation-only detail, but it must not become a second remediation source of truth.

Unknown findings must fail honestly.

Do not invent generic remediation for an unmapped finding.

## 12.3 Universal Managed Cases

All case-status transitions must use:

```text
canTransitionCase(...)
```

Base-domain case creation must use:

```text
createManagedCase(...)
```

Do not create a parallel case system for each domain.

Existing ASM and Brand state machines must remain backward compatible.

## 12.4 Verification Honesty

A completed scan alone cannot verify a fix.

A customer note alone cannot verify a fix.

A bare boolean flag cannot verify a fix.

Verification requires structured, method-appropriate evidence.

Failed, inconclusive or still-present results cannot become verified.

Customer assertion and CyberMeters verification are different concepts.

## 12.5 External-Scope Honesty

CyberMeters is primarily an externally observable posture platform.

Do not claim unsupported visibility into internal networks, endpoints, leaked credentials, dark-web data, EDR, SIEM, internal CASB or unsupported certificate trust.

## 12.6 Historical Integrity

Where auditability matters, use append-only records.

Do not overwrite or erase:

- case history;
- case evidence;
- remediation identity;
- verification history;
- inventory history;
- classification history;
- evidence bundles;
- recurrence history;
- audit events.

## 12.7 Customer Classification Is Not Observation

For Shadow IT and similar managed inventory:

```text
CyberMeters observation
≠
customer classification
```

`Approved` does not mean secure.

`Rejected` does not mean removed.

`Removed` asserted by a customer does not automatically mean externally verified removal.

Disappearance does not automatically prove remediation.

---

# 13. Engineering Constitution

## Rule 1 — Never Rewrite Working Systems

If an existing system works:

- do not replace it;
- do not redesign it without need;
- extend it;
- preserve compatibility.

## Rule 2 — Backward Compatibility Is Mandatory

Do not break existing scans, historical reports, report JSON, Executive Reports, PDFs, portfolio APIs, frontend pages, scheduled scans, billing, authentication, audit logs, ASM cases, Brand cases or historical remediation items.

Prefer additive changes and compatibility adapters.

## Rule 3 — Reuse Before Creating

Before adding functions, engines, routes, tables, migrations, components, pages, registries or state machines, search for equivalent existing functionality.

Never create duplicate authoritative systems.

## Rule 4 — Complete the Canonical Roadmap First

Prefer completion of the active managed-platform episode over unrelated scanner modules, cosmetic redesign, dashboard wording changes, homepage changes, duplicated subsystems or speculative architecture.

## Rule 5 — Historical Data Is Sacred

Never destructively remove historical scans, findings, observations, assets, reports, events, case events, classifications, remediation identities, inventory history, verification attempts, evidence bundles or recurrence records.

Use append-only history where audit integrity matters.

## Rule 6 — Multi-Tenant Isolation Is Mandatory

CyberMeters is already multi-tenant.

Every read and write must be workspace-scoped, tenant-isolated, permission-checked and non-enumerating where appropriate.

Soft-deleted workspaces must not receive new scans, observations, inventory items, cases, notifications or scheduled work.

Tenant-isolation tests are mandatory for new workspace-scoped surfaces.

## Rule 7 — Security First

Every feature must consider authentication, authorisation, tenant isolation, auditability, rate limiting, fail-open versus fail-closed behaviour, data exposure, report access, soft-delete behaviour and production error handling.

## Rule 8 — Cloudflare Native

Implementations must remain compatible with Cloudflare Workers, D1, R2, Pages and Cron Triggers.

## Rule 9 — Database Safety

Every schema change requires a numbered migration, validation, compatibility review, rollback strategy, purge-order review and tenant-isolation review.

Prefer additive migrations.

Never run the full schema file against production as a routine migration.

## Rule 10 — Avoid N+1 Queries

Prefer joins, grouping, aggregation, batched reads, batched writes and bounded processing.

## Rule 11 — Validation Is Required

Before merge, run as applicable:

- focused validators;
- regression tests;
- tenant-isolation tests;
- migration validation;
- frontend tests;
- frontend coverage;
- frontend build;
- Worker syntax check;
- Wrangler dry run;
- `git diff --check`;
- CI.

Deployment is not validation.

## Rule 12 — No Placeholder Implementations

Do not ship TODO-only paths, fake logic, mock findings, hardcoded customer scores, fake verification evidence, invented remediation, optimistic healthy states or unsupported automation claims.

Do not treat customer assertion as product verification.

Do not mark missing evidence as healthy.

## Rule 13 — Domain Ownership Verification Is Mandatory

Domain ownership verification is implemented and is a strategic security boundary.

Do not weaken or bypass verification.

Protected monitoring and sensitive domain operations must respect the canonical verification state.

## Rule 14 — Portfolio-Level Thinking

Where relevant, consider domain state, workspace state, customer state and MSP portfolio state.

Do not prematurely turn Business workspaces into mini-MSP accounts.

## Rule 15 — Commercial Readiness

Prefer implementations that improve onboarding, customer trust, operational reliability, evidence clarity, remediation completion, verification, MSP usability, controlled public-beta readiness and revenue readiness.

Do not optimise for feature count.

## Rule 16 — Duplicate Feature Detection

Before implementing, inspect existing APIs, tables, migrations, pages, components, engines, registries, state machines and recent pull requests.

## Rule 17 — Sprint and Release Awareness

Before proposing work, review the active branch, recent commits, latest merged PRs, recent migrations, current release tag, live deployment ID and active canonical episode.

Do not re-propose completed work.

Do not reopen a closed episode without direct regression evidence.

## Rule 18 — Historical and Trendable Data First

Prefer structures supporting first_seen_at, last_seen_at, last_changed_at, created_at, updated_at, resolved_at, reopened_at, verified_at and monitoring_started_at.

## Rule 19 — API Stability

Existing APIs are contracts.

Do not rename response fields, remove fields, change field meaning, alter status semantics or change response shapes without a compatibility plan.

Prefer additive response fields and compatibility adapters.

Introduce explicit versioning only through an approved architecture decision.

## Rule 20 — Canonical Implementation Format

Before implementation, provide:

- Goal
- Exact Pre-Change Map
- Design Decision
- Scope Boundaries
- Risks and Compatibility

After implementation, provide:

- Files Changed
- Schema and Migrations
- Behavioural Changes
- Tests and Regression
- PR and Merge
- Deployment IDs
- Production Proof
- Rollback
- Residual Risks
- Confirmation Later Phases Were Not Started

## Rule 21 — Eight-Domain Canonical Model

Always use the eight canonical customer-facing domains.

Do not collapse them into four modules or describe the product as seven domains.

## Rule 22 — Canonical Coverage State

All eight domains must remain visible where the product contract requires them.

Missing, partial or unavailable data must not remove a domain or mark it healthy.

## Rule 23 — Canonical Remediation Registry

All customer-facing remediation semantics must come from the shared registry.

Unknown mappings must remain explicit.

## Rule 24 — Universal Case Model

All case types must use the shared managed-case substrate.

All status mutations must pass through the canonical transition validator.

All base-domain creation must use the shared case factory.

## Rule 25 — Verification Evidence

A case may reach `verified` only through a supported verification contract.

Verification must be evidence-based, method-specific, auditable, attributable and time-stamped.

## Rule 26 — No Roadmap Drift

Complete the active canonical episode before starting a later phase, homepage work, dashboard redesign, service-label changes, cosmetic cleanup or speculative architecture.

Exceptions are production incidents, critical security/data issues or direct founder instruction.

---

# 14. Development Workflow

Before implementing any feature:

1. Identify the active canonical roadmap episode.
2. Review the current branch.
3. Review recent commits and merged pull requests.
4. Review the latest release tag.
5. Review the current live deployment ID where relevant.
6. Review existing engines, routes, APIs and components.
7. Review the database schema and recent migrations.
8. Search for duplicate functionality.
9. Build an exact pre-change map.
10. Define compatibility and tenant-isolation requirements.
11. Define the minimum safe scope.
12. Implement by extending existing systems.
13. Run focused validators.
14. Run the full gate when shared infrastructure changes.
15. Open a focused pull request.
16. Merge only when CI is green.
17. Apply migrations through the approved process.
18. Deploy Worker and Pages changes as required.
19. Record live and rollback deployment IDs.
20. Perform production proof on founder-controlled workspaces.
21. Do not send unrelated customer notifications, reports or email during testing.
22. Stop after the requested episode.

Parallel discovery agents may inspect different areas.

Do not allow parallel implementation agents to edit overlapping files without an explicit coordination plan.

---

# 15. Production Proof Rules

Production testing must use founder-controlled workspaces, founder-controlled domains, controlled test records and side-effect-safe actions.

Do not modify unrelated customer cases, trigger unrelated email, send reports to unrelated recipients, change third-party production DNS without explicit approval or mark customer issues resolved for test purposes.

A `401` response proves a route is live and auth-gated, but it does not by itself prove the customer workflow.

---

# 16. Public-Beta Gate

Do not send the first controlled external invitations until:

- the required managed-platform roadmap is complete;
- debugging and hardening are complete;
- security review and pentesting are complete;
- the final release-candidate gate is green;
- signup works;
- email verification works;
- login and logout work;
- Microsoft SSO works;
- MFA works;
- onboarding works;
- domain verification works;
- first scan works;
- eight-domain state rendering works;
- report generation works;
- Executive PDF works;
- managed cases work;
- alerts work;
- billing and entitlements work;
- tenant isolation is revalidated;
- production smoke is completed.

The first external cohort should be controlled and small:

- one real small business;
- one small MSP or IT-support provider.

Do not treat the first two invitations as an unrestricted public launch.

---

# 17. Post-Roadmap Engineering Work

After the managed-platform phases are complete, CyberMeters will enter dedicated hardening and assurance work.

## Debugging and Reliability Engineering

Planned work includes:

- systematic frontend and backend debugging;
- lifecycle edge-case testing;
- race-condition analysis;
- retry and idempotency review;
- scheduled-job failure testing;
- production observability;
- performance profiling;
- Worker and D1 limit testing;
- R2 failure testing;
- quota and resource-headroom testing;
- rollback exercises.

## Security Testing and Pentesting

Planned work includes:

- authenticated application testing;
- horizontal and vertical privilege escalation;
- tenant-isolation testing;
- authentication, session, Microsoft SSO and MFA testing;
- API authorisation;
- business-logic abuse testing;
- Stripe and entitlement testing;
- rate-limit testing;
- injection testing;
- XSS testing;
- CSRF review;
- SSRF and unsafe-fetch review;
- R2/report access testing;
- D1 isolation testing;
- Worker route and binding review;
- dependency and secret scanning;
- static analysis;
- controlled Nuclei checks;
- controlled API fuzzing.

Automated tools support engineering judgement and are not proof that the platform is secure.

---

# 18. Final Directive

CyberMeters is in pre-public-beta managed-platform completion.

The mission is not to maximise the number of scanners or findings.

The mission is to deliver an honest, consistent and managed Cyber MOT lifecycle across all eight domains.

When uncertain:

- prefer evidence honesty over optimistic presentation;
- prefer canonical shared systems over duplicated domain logic;
- prefer verified outcomes over customer assertions;
- prefer backward-compatible extension over rewrites;
- prefer tenant isolation over convenience;
- prefer historical integrity over destructive cleanup;
- prefer completion of the active roadmap phase over cosmetic work;
- prefer operational customer value over technical novelty.

Act as a senior software engineer maintaining a production multi-tenant SaaS platform.
