# CyberMeters Official Roadmap
## From Final Product Completion to the First Paying Customer

Version: July 2026 (r2 — founder-approved revision)

Canonical location: `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md`. This file is the single authoritative copy. Do not maintain parallel copies outside the repository.

Current canonical episode: **Posture Timeline Trust & Actionability** (the founder-approved **RESCOPE of M6** — see the Pre-Public-Beta Gate Sequence below). **M5 Completion Across All Eight Domains is engineering-complete: M5.a–M5.g all CLOSED.**

- **M5.a–M5.g** — managed-case verticals, CE honesty/hygiene, Certificates verify-by-observation + reconciliation, Unified Reporting snapshot + renderer migration, eight-domain parity, maturity ledger, and the final CI closure — **ALL CLOSED**.
- **M6** — gated by **M6.0**. **M6.0-A** (competitive differentiation hypothesis) **PASSED**. **M6.0-B** (sensor sufficiency + real-data empirical proof) **RAN 2026-07-18 (read-only, no code) and the founder ruled RESCOPE**: the GO criteria were not met (only one of the needed ≥2 correlation use cases is sensor-sufficient — UC1 Brand weaponisation needs four prohibited new sensors/stores, and UC2 Email's core transition is already shipped by `posture-events.js`). M6 "External Behaviour Intelligence Engine" is therefore **rescoped to the episode "Posture Timeline Trust & Actionability"** (plan: `docs/EPISODE-PLAN-posture-timeline-trust.md`), which is the **CURRENT ACTIVE PHASE**.
- **Behaviour Intelligence (cross-domain correlation as a category)** is **explicitly DEFERRED as a sensor-dependent, founder-gated programme** — it is *not* promised roadmap functionality and its delivery depends on future approved sensors that do not exist today.
- **M7** — Pricing + Billing Alignment — remains the following gate (after the rescoped episode).

Earlier canonical episodes — Alerts Across All Eight Domains and MSP Portfolio Per-Domain State and Trend — are Live. Engineering is closed on the shipped M5 items, but genuine authenticated live-event acceptance remains outstanding for every managed vertical (gate 10 below). This roadmap uses milestone language; for exact release tags, migrations, and deployment IDs see `CHANGELOG.md` and `CLAUDE.md` — they are the source of truth for fast-aging release facts, which are deliberately not duplicated here.

## Mission

Complete the managed Cyber MOT platform, prove reliability and security, convert controlled users into customer evidence, and acquire the first paying customer without allowing marketing, funding applications, or feature expansion to distract from product trust.

## North-star outcome

The roadmap is complete when CyberMeters has:

1. completed the remaining canonical product phases;
2. passed systematic debugging and reliability hardening;
3. passed internal security review and focused pentesting;
4. completed founder-controlled end-to-end acceptance;
5. passed a formal release-candidate gate;
6. onboarded controlled real users;
7. demonstrated measurable customer value;
8. converted at least one external organisation into a paying customer;
9. established a repeatable acquisition and onboarding process;
10. prepared an evidence-backed funding and growth application pack.

## First paying customer definition

A first paying customer is a real external organisation that has completed onboarding, accepted commercial terms, paid through production billing, and is actively monitoring at least one real domain.

It is not a free user, test workspace, complimentary pilot, Stripe test payment, verbal promise, or permanent free account.

The first paying customer must be acquired on the adopted pricing (see Phase F0), not the legacy pricing.

Record:

- organisation type;
- acquisition source;
- plan and contract value;
- monitored domains;
- onboarding time;
- time to first value;
- support required;
- conversion reason and objections;
- renewal date.

---

# Master sequence

```text
Complete final canonical phases
→ Systematic debugging and reliability hardening (timeboxed)
→ Internal security review and pentesting (timeboxed)
→ Founder-controlled end-to-end acceptance
→ Release Candidate gate
→ Pricing lockstep + commercial foundation and launch assets
→ Founder-led sales (SEO already running as a parallel lane)
→ First controlled real users
→ Trust and friction fixes
→ First paid conversion
→ Repeatable acquisition system
→ Funding and grant applications
→ Gradual cohort expansion (full external security review before wide expansion)
→ Wider public beta
```

---

# Pre-Public-Beta Gate Sequence

Founder-approved (16 July 2026; **re-sequenced 18 July 2026 to insert M6 before pricing**). This is the canonical, ordered spine from the current position to public beta. **The order must not be reordered, collapsed, or skipped.** It is the operational expression of the phases below; where a gate and a phase overlap, the phase text is the detail and this list is the sequence.

| # | Gate | Status |
| --- | --- | --- |
| 1 | M5.b Certificates & Trust | CLOSED |
| 2 | M5.c Unified Reporting Snapshot | CLOSED — deployed `v2026.07.17-1` (migration `093`) |
| 3 | M5.d Online/PDF Unified Reporting | CLOSED — deployed `v2026.07.17-2` |
| 4 | M5.e Eight-domain Parity | CLOSED — deployed `v2026.07.17-4` (migration `094`) |
| 5 | M5.f Maturity Ledger | CLOSED — deployed `v2026.07.17-5` (migration `095`); founder-controlled complete-scan acceptance passed |
| 6 | M5.g Final CI Closure | CLOSED — `validate-m5-closure.js` locks the full M5 gate + append-only idempotency (CI-only, no deploy); CE double-build cost is a tracked deploy-gated residual |
| 7 | **M6.0 Viability Gate → RESCOPE: Posture Timeline Trust & Actionability** | **CURRENT ACTIVE PHASE** — M6.0-A PASSED; M6.0-B ran 2026-07-18 (read-only) and the founder **ruled RESCOPE** (GO criteria unmet). M6 is rescoped to **"Posture Timeline Trust & Actionability"** (plan: `docs/EPISODE-PLAN-posture-timeline-trust.md`): Phase A timeline-trust (eligibility/producer-version guards + flip-flop dedupe on `asset_events`), then Phase B the single sensor-sufficient host-level correlation (one canonical managed case + canonical owner-or-explicitly-unassigned). Behaviour Intelligence deferred (sensor-dependent, founder-gated) |
| 8 | M7 Pricing + Billing Alignment | Planned |
| 9 | Final Beta Hardening | Planned |
| 10 | Controlled Authenticated / Live Acceptance | Planned |
| 11 | Independent Pentest + Remediation Retest | Planned |
| 12 | Legal & Data-Protection Foundation | Planned |
| 13 | Formal Release-Candidate Gate (`-rc1`) | Planned |
| 14 | Final Website Design & Conversion | Planned |
| 15 | Invitations / Controlled Private Beta | Planned |
| 16 | Private-Beta Acceptance & Fix Cycle | Planned |
| 17 | Public Beta Gate & Launch | Planned |

(M5.a is CLOSED and precedes gate 1; M5 as a whole — gates 1–6 plus M5.a — is engineering-complete.)

**Gate specifics that are not obvious from the phase text:**

- **7 — M6.0 Viability Gate → RESCOPE: Posture Timeline Trust & Actionability.** Honest re-diagnosis: the app ALREADY does change-over-time (`posture-events.js` is a posture-diff engine feeding the Exposure Timeline + weekly digest). So **M6 was NOT "change over time"** — its only defensible new value would have been **cross-domain correlation + bounded DETERMINISTIC significance** the existing diff timeline cannot produce. Significance is composed deterministically (`change type + security direction + persistence + recurrence + inventory mismatch + corroborating signals`; historical rarity is one enriching factor, not the base) — **not** statistical anomaly; customer-facing wording avoids "anomalous/suspicious/attacker/statistically unusual" in favour of "material / correlated / requires verification / higher-confidence progression". Correlation is kept small (**≤3 signal families** per use case). Deterministic decides, AI explains; change ≠ compromise; honest-by-default; emits through the canonical alert/case/remediation systems (no parallel platform).
  - **M6.0-A — Competitive differentiation hypothesis: PASSED** (structurally verified: provider audit logs — Cloudflare, GoDaddy — are control-plane-only / own-account / external-blind; the external, cross-provider and attacker-side blind spots are real).
  - **M6.0-B — Sensor sufficiency + real-data empirical proof: RAN 2026-07-18 (read-only, no code).** Candidate use cases ranked (1) Brand weaponisation progression, (2) Email posture transition, (3) New public surface correlation, each tested against the three counterfactuals (provider / existing-timeline / analyst-at-scale-or-SME-continuity). **Result — GO criteria not met:** only **one** of the needed ≥2 correlation use cases is sensor-sufficient. UC1 Brand needs **four prohibited** new sensors/stores (CT monitor, content fetch, MX-over-time persistence, per-lookalike baseline store — real data confirmed `mx_present`/`https_available` dead across 880 lookalikes, `brand_abuse_campaigns` empty). UC2 Email's core transition is **already shipped** by `posture-events.js`. Only UC3 host-level correlation is buildable from existing sensors, and it carries the weakest provider counterfactual. Founder-domain honesty was proven live (silent-on-stable; the existing eligibility gate correctly returned `not_comparable` on a would-be fake regression).
  - **Outcome — founder ruled RESCOPE (18 Jul 2026):** the episode is **"Posture Timeline Trust & Actionability"** (plan: `docs/EPISODE-PLAN-posture-timeline-trust.md`) — Phase A ports the eligibility/producer-version guards that already exist on migrations `091`/`093`/`095` onto `asset_events` (mig `004`) + flip-flop dedupe; Phase B builds the single sensor-sufficient UC3 host-level correlation (one canonical managed case + canonical owner or explicitly unassigned). It must **NOT** carry a "behaviour intelligence" claim. Six founder constraints govern: (1) `not_comparable`/`unavailable`/`insufficient_history` are comparison-STATUS outcomes, not customer security events — fail closed, diagnostic transparency separate; (2) canonical ownership only, never fabricated; (3) controlled detection fixtures (positive/negative/stable/unavailable-source/cross-version/recurrence/dedupe) mandatory before UC3 is production-enabled; (4) no pre-committed migration; (5) `asset_events` never mutated or deleted; (6) remediation must map to the registry or stay explicit-unknown.
  - **Behaviour Intelligence (cross-domain correlation as a category) is explicitly DEFERRED** as a sensor-dependent, founder-gated programme — not promised roadmap functionality; its delivery depends on future approved sensors that do not exist today.
  - **Scanner boundary (canonical):** CyberMeters will not embed or depend on open-source vulnerability scanner engines or community scanning-template ecosystems in its production scanning pipeline. External checks must be proprietary CyberMeters probes or separately founder-approved commercial integrations. Public vulnerability data such as KEV, NVD and CVE metadata may be used only for enrichment and prioritisation; it must not independently create or verify a finding. No new scanner dependency may be introduced implicitly. The rescoped episode consumes selected existing, inventoried and approved sensor outputs; developing a new vulnerability detection framework requires a separate founder-gated programme.
  - Founder decision (18 Jul 2026): the rescoped episode precedes pricing (M7).
- **8 — M7 Pricing + Billing Alignment.** Design may be two tasks, but the production deploy is **one lockstep release** (Stripe products/prices + backend entitlements + pricing cards together); founder deploy approval is mandatory; the first customer is acquired on the adopted pricing, never the legacy pricing. Design the pricing architecture with a "Behaviour / Change Intelligence" tier.
- **9 — Final Beta Hardening.** Auth/session/tenant isolation; rate limits and failure honesty; per-pass row growth and operational scale. Recovery must be **demonstrated, not described**: a tested D1 restore, an R2 object-loss recovery, and a Worker/Pages rollback drill, each with evidence and timings recorded. Includes verifying that CyberMeters' own alert/verification/report email lands in the inbox (our outbound SPF/DKIM/DMARC posture) — ironic to fail this as an email-security product.
- **10 — Controlled Authenticated / Live Acceptance.** A real production session exercising the full lifecycle across Email, Website Security, Cyber Essentials, Certificates, and every eight-domain path. This clears the accumulated M5.a/M5.b acceptance debt. CI green and a `401` route check do **not** substitute for it.
- **12 — Legal & Data-Protection Foundation.** A distinct pre-invitations blocker, not website copy. Complete the ICO data-protection-fee self-assessment and pay the applicable fee unless a valid exemption applies — for CyberMeters' business model a fee is **likely**, but this must be confirmed via the self-assessment rather than assumed. Publish a Privacy Notice (controller identity, data types, purpose and lawful basis, retention, sharing and subprocessors, data-subject rights, complaint and contact route), Terms, a DPA, a processor/subprocessor record, a retention/deletion statement, a DSAR process, a responsible-disclosure/security contact, and cookie/analytics control.
- **13 — Formal Release-Candidate Gate.** `-rc1` is tagged only when every prior gate is green: M5 complete, M6 engine validated, pricing/billing deployed, hardening complete, live acceptance complete, pentest/retest complete, legal foundation complete, recovery drills complete. If private beta surfaces a blocker: `rc1 → fix → rc2`; public beta opens from the last accepted RC.
- **15–17.** An invitation is not a public launch. Gate 16 (private-beta acceptance and fix cycle) sits deliberately between invitations and the public beta gate.

**SEO parallel lane** (low-intensity through M5; never displaces the active canonical episode — see Phase G). Do now: honest eight-domain Academy content, glossary and educational pages, canonical/meta/schema checks, internal linking, crawl/index hygiene, and removal of stale Vendor Risk / Supply Chain claims. Do not yet: fixed pricing pages, any pentest or certification implication, presenting incomplete workflows as live features, or unproven ransomware-prevention rates.

---

# Timeboxes and gate discipline

The largest internal risk to this roadmap is not external; it is unbounded hardening. Phases B and C will expand to fill all available time unless bounded.

- Phase B (debugging and reliability hardening): timebox **2 weeks**.
- Phase C internal work (C1–C3): timebox **2 weeks**.
- When a timebox ends, remaining findings are triaged: P0 and P1 block the gate; P2 and below are documented and scheduled — they do not silently extend the phase.
- Every gate decision is made on P0/P1 status, never on "no findings remain".
- A timebox may be extended only by explicit founder decision, recorded with a reason.

---

# Phase A — Complete the final canonical product phases

## A1. Complete ASM Verification — **complete (Live)**

Closed in two releases:

- Part 1 — `v2026.07.14-19` (PR #83): affected-host truth, deterministic verifiers for six exposure finding types, fail-closed rescan-absence gating.
- Part 2 — `v2026.07.14-20` (PR #84): honest DNS/header verification for `subdomain_takeover` and `dse_*` findings; the `ASM_VERIFICATION_SUPPORT` matrix (14 automated, 2 intentionally unsupported, 3 observation-only) is asserted in CI.

Exit gate satisfied: focused validators and managed-case/tenant-isolation tests green; deployment and rollback Worker version ids recorded in the CHANGELOG; founder authenticated UI smoke remains queued as a final release-gate action (Phase D3); no Alerts, MSP, or M5 work was started inside the episode.

## A2. Alerts Across All Eight Domains — **closed (Live)**

### Objective

Create one canonical, reliable, deduplicated alert lifecycle across all eight domains.

### Required capabilities

- all eight domains emit through one shared event model;
- customer preferences;
- severity and entitlement rules;
- cooldown and deduplication;
- retry and failure handling;
- append-only delivery history;
- customer-safe wording;
- correct links to the related domain, case, or remediation;
- soft-deleted workspaces receive no alerts;
- no duplicate delivery for the same event.

### Minimum alert families

- new high or critical issue;
- material deterioration;
- verified issue recurrence;
- approaching certificate expiry;
- email-authentication deterioration;
- brand-abuse recurrence;
- unexpected identity exposure;
- Shadow IT removal contradiction;
- website-security regression;
- Cyber Essentials readiness deterioration;
- ownership or verification failure where appropriate.

### Exit gate

- all eight domains use the shared infrastructure;
- preference, dedupe, cooldown, and retry tests green;
- founder-controlled email-delivery proof completed;
- no customer receives a test alert;
- alert copy reviewed for evidence honesty.

### PR sequence (founder-approved 15 July 2026)

- **PR-A — Alert Trust Foundation.** Shipped: PR #97, merged `24dfc85`, Worker `fce2a66f-d1c4-4690-839f-079fe0ce1374`. No migration.
- **PR-B — canonicalise the existing six domains** onto `emitManagedAlert`.
- **PR-C — minimum upstream for CE Readiness and Website Security** (they have no case creation or occurrence source today). Minimum for alerts only; NOT the full M5 lifecycle.
- **PR-D — production acceptance and cleanup**, including the authenticated acceptance deferred from PR-A.

### PR-B1 production safety result — PASS (15 July 2026, controlled scan)

One founder-authorised scan of `cybermeters.com` in Turhan Workspace, on Worker `49c973a1-61a7-4039-acc8-51ae8cebbe8e`.

**PR #98 production safety: PASS. No rollback.**

Two alert emails were received (`new_vendor`, `supply_chain_risk_increase`). **Both were emitted by the legacy `processAlertsForWorkspace` path in `alerts.js`, NOT by the canonical managed-alert pipeline.** Evidence:

- `domain_key` **NULL** on both (the canonical pipeline always sets it);
- `dedupe_key` **NULL** on both (canonical dedupe is a DB guarantee);
- `alert_activation` unchanged at **0**;
- `alert_deliveries` unchanged at **0** (no ledger row = the canonical emitter never ran);
- no `managed_case_events` `monitoring_changed` occurrence;
- no canonical notification emitted.

Findings recorded:

1. **PR #98 caused no backlog flood and no unintended canonical alert.**
2. **Email entitlement, recipient resolution and provider delivery worked end to end** — both emails `email_delivery: accepted` to the founder's verified address for an entitled workspace. This is PR-A's gate chain proven in production.
3. **Canonical first-new-alert production acceptance remains OPEN**: the scan returned Attack Surface / Certificates / Brand all *Healthy*, so no case opened or transitioned, so no qualifying occurrence was minted and the canonical pipeline correctly stayed silent.
4. **`new_vendor` and `supply_chain_risk_increase` remain legacy alert paths** and must be migrated to: append-only occurrence → stable occurrence id → activation/watermark → canonical ledger → delivery.
5. **Raw current-state SQL must not invent canonical alerts.** `supply_chain_risk_increase` ("resilience score dropped from 32 to 20") is a score diff with no persisted occurrence — the exact shape this rule forbids.

**A second scan was deliberately NOT run**: an unchanged re-scan exercises only the legacy 24-hour `isAlertDuplicate` window and would not prove canonical occurrence idempotency. Canonical acceptance closes only on a genuine Brand/ASM case open/reopen.

### PR-B4a follow-up design items (required before either email may return)

PR-B4a suppressed the outbound email for `new_vendor` and `supply_chain_risk_increase` because neither can evidence its claim. **Removing a type from `EMAIL_SUPPRESSED_LEGACY_TYPES` requires the matching model below to exist first.** Neither is a wire-up; both are design work.

**A. Vendor occurrence model** (blocks `new_vendor`)

- **Stable vendor identity** — not the free-text `vendor_name`. Today a rename or a normalisation change mints a fresh `workspace_vendors` row with a fresh `first_seen`, which reads as "new".
- **Source/domain attribution** — the alert claims "on your attack surface", but `workspace_vendors` is shared and has no `domain_key`. A *certificate* observation (`cert-events.js:332`) inserts CA vendor rows; that is Certificates & Trust evidence, not Attack Surface.
- **First-ever vs reactivation/rename** — `first_seen` is stable (writers use `INSERT OR IGNORE`), but `asset-persistence.js` flips `status` back to `'active'`, and nothing distinguishes rediscovery, reactivation, rename or transient scan/provider variance from a genuinely new vendor.
- **Append-only evidence** — an observation log, not a mutable inventory row.
- **Recurrence vocabulary** — namespaced under its true domain, with severities the platform has actually decided.

**B. Supply-chain evidence-change model** (blocks `supply_chain_risk_increase`)

- **Persisted underlying dependency/vendor changes** — `workspace_supply_chain_history` stores the score, never which evidence moved.
- **Attributable score explanation** — a delta alone cannot say *why*; the alert must cite the change, not the number.
- **Formula-version awareness** — a scoring-model change currently produces an identical delta to a real risk increase, and the customer is told "risk increased" either way.
- **No alert directly from an unexplained score delta.** A derived score is not an occurrence.

### PR-D authenticated production acceptance (deferred from PR-A)

PR-A's contract is covered by 108 CI-blocking, mutation-tested assertions against the real engine, and its deploy was verified not to silence any live workspace. The authenticated checks below were **deferred, not skipped**: production has **no free-plan workspace, no enabled alert channel, no preference row and no alert_deliveries row**, and the canonical pipeline has never emitted in production — so there was nothing to observe, and manufacturing it would have meant fabricating production data. Founder decision, 15 July 2026.

Run these at PR-D, once all eight domains are connected, founder-controlled occurrences exist, a controlled delivery workspace/channel is available, and the two-pass baseline proof can be performed:

1. Founder-controlled **free-plan entitlement suppression** proof — no email, Slack, Teams or webhook.
2. Founder-controlled **paid delivery** proof.
3. **Per-user `disabled`** preference proof (suppresses only that user, in that workspace).
4. **`critical_only`** proof — `critical` delivered; `high`/`medium`/`low` suppressed.
5. **Slack/Teams/webhook workspace-level gate** proof, including that the channel test endpoint cannot bypass entitlement or preferences.
6. **Terminal `alert_deliveries` outcome** proof for every suppression reason.
7. **No retry loop** for a terminal suppression.
8. **No alert reaches another customer or workspace.**

## A3. MSP Portfolio Per-Domain State and Trend

### Objective

Give MSPs and IT-support providers a portfolio-level view without turning normal Business workspaces into mini-MSP accounts.

### Required capabilities

- customer, workspace, and domain hierarchy;
- per-domain eight-domain state;
- per-domain trend;
- highest-priority action;
- stale and unavailable evidence states;
- alert and case summary;
- material-change visibility;
- sorting and filtering;
- delegated tenant-safe access;
- no cross-customer leakage;
- bounded aggregate queries;
- clear MSP/customer permission boundaries.

### Exit gate

- one realistic MSP test portfolio;
- no N+1 query pattern;
- portfolio state matches domain source of truth;
- usability proven at 5, 10, and 25 domains;
- tenant isolation green.

## A4. M5 Completion Across All Eight Domains

### Objective

Bring every canonical domain to the required managed maturity level.

M5 means each domain can:

```text
observe
→ explain
→ remediate
→ assign ownership
→ manage a case
→ verify where supported
→ monitor recurrence
→ alert
→ report honestly
```

### Required parity matrix

For each domain verify:

- coverage state;
- evidence source;
- remediation mapping;
- managed-case support;
- ownership;
- verification contract;
- recurrence;
- alert event;
- report and PDF meaning;
- frontend state;
- limitation wording;
- tenant isolation;
- historical integrity.

### Exit gate

A domain-by-domain parity matrix is complete with no hidden “healthy by absence” states. Unsupported verification remains explicitly unsupported.

### Relationship to Phase D

A4 **produces and closes** the parity matrix. Phase D does not repeat A4's work: it re-validates the same matrix end-to-end in one founder-controlled pass through the real UI. Any gap found in Phase D is a defect against A4, not a second parity exercise.

---

# Phase B — Systematic debugging and reliability hardening

Timebox: 2 weeks (see Timeboxes and gate discipline).

## Objective

Prove that every major lifecycle works during success, failure, timeout, retry, duplicate, race, and recovery conditions.

## B1. Authentication and account lifecycle

Test:

- registration and duplicate registration;
- email verification and expiry;
- login, invalid login, logout, and session expiry;
- password reset and expired reset;
- MFA enrolment, challenge, and recovery;
- Microsoft SSO success and failure;
- rate limits and lock behaviour;
- login history and audit events.

## B2. Workspace and domain lifecycle

Test:

- workspace create and switch;
- invitations, expiry, and permissions;
- domain add, duplicate, verify, fail, and remove;
- workspace soft-delete;
- purge behaviour;
- scheduled-work suppression after deletion.

## B3. Scan lifecycle

Test:

- manual and scheduled scans;
- duplicate start;
- partial scan;
- module timeout;
- Worker, D1, and R2 failure;
- stuck-running reconciliation;
- retries and idempotency;
- result persistence;
- report generation;
- historical trend;
- verification gate.

## B4. Managed lifecycle reliability

For all eight domains test:

- case creation and deduplication;
- assignment and transitions;
- invalid transition rejection;
- remediation resolution;
- customer assertion;
- verification pending, success, and failure;
- recurrence and reopen;
- append-only history.

## B5. Alerts and email

Test normal delivery, provider failure, retry, dedupe, cooldown, preferences, invalid recipient, soft-delete suppression, link destination, and safe copy.

## B6. Billing and entitlements

Test checkout, signatures, duplicate webhooks, upgrade, downgrade, cancellation, failed payment, grace period, entitlements, plan limits, billing portal, and audit history.

## B7. Performance and capacity

Measure:

- Worker CPU and subrequests;
- D1 rows read and written;
- D1 query latency;
- R2 operations;
- scan duration;
- report generation;
- cron duration;
- retry amplification;
- 1, 5, 10, and 25-domain workloads.

## Exit gate

- no open P0 reliability defect;
- no open P1 lifecycle defect;
- known P2 issues documented;
- retry/idempotency contracts tested;
- monitoring and capacity baseline recorded.

---

# Phase C — Security review and pentest

Timebox for C1–C3: 2 weeks (see Timeboxes and gate discipline).

## Objective

Prove that CyberMeters protects customer data, enforces tenant boundaries, and resists common technical and business-logic attacks.

## C1. Internal security review

Review:

- authentication and sessions;
- MFA and Microsoft SSO;
- password reset and email verification;
- API authorisation;
- tenant isolation;
- report and R2 access;
- D1 scoping;
- managed-case transitions;
- verification forgery;
- billing entitlement bypass;
- invitation abuse;
- rate-limit fail-open behaviour;
- webhook replay;
- scheduled-job and email-ingest abuse;
- secret and binding exposure.

## C2. Application testing

Test:

- horizontal and vertical privilege escalation;
- IDOR;
- SQL injection;
- stored, reflected, and DOM XSS;
- SSRF and unsafe external fetches;
- unsafe redirects;
- XML parser abuse;
- header injection;
- path/object-key manipulation;
- oversized input;
- mass assignment;
- race conditions;
- duplicate-request abuse.

## C3. Automated assurance

Use dependency audit, secret scanning, static analysis, controlled Nuclei, and controlled API fuzzing. Automated tools support judgement; they do not prove security.

## C4. External independent review — scheduled after first paid evidence

A full independent authenticated SaaS review is deliberately positioned **after the first paying customer and before cohort expansion beyond the first controlled cohorts** (see Phase N). Reasons: pre-revenue budget, calendar risk, and the fact that C1–C3 plus the security regression suite gate the first controlled users.

Before the first paying customer the external requirement is narrow:

- if budget permits, commission a tightly scoped external verification of tenant isolation, authentication, and billing entitlement only;
- if budget does not permit, document the absence of independent review as a known limitation in the beta terms.

The full-scope independent review (tenant isolation, auth, billing, API, business logic, cloud storage, with retesting) remains mandatory before expansion beyond the 5-user cohort.

## Exit gate (for first controlled users)

- all P0 security issues closed;
- all P1 issues closed or release-blocked;
- retests green;
- security regression tests added;
- incident response and disclosure process ready;
- narrow external verification completed, or its absence documented in the beta terms.

---

# Phase D — Founder-controlled end-to-end acceptance

Phase D re-validates the A4 parity matrix end-to-end in one founder-controlled pass (see A4); it does not repeat the matrix exercise.

## D1. Small-business journey

```text
register
→ verify email
→ log in
→ create workspace
→ add and verify domain
→ run Cyber MOT
→ review all eight domains
→ open remediation
→ assign owner
→ manage case
→ record action
→ verify supported fix
→ receive alert
→ generate report/PDF
→ upgrade
→ manage billing
→ cancel
→ request deletion
```

## D2. MSP journey

```text
create partner context
→ add customer and domains
→ view per-domain state and trend
→ sort by priority
→ open customer case
→ receive portfolio alert
→ generate customer report
→ prove tenant isolation
```

## D3. Deferred authenticated smoke

Close remaining smoke for Shadow IT, Certificates, Identity Exposure, ASM verification, Alerts, MSP portfolio, reports/PDF, and billing.

## Exit gate

- every step recorded pass/fail;
- screenshots and evidence retained;
- no real customer data used;
- no unresolved P0/P1 acceptance defect;
- onboarding time and first-value time measured.

---

# Phase E — Final Release Candidate gate

## E1. Technical gate

Confirm migrations, Worker/Pages versions, rollback, health/readiness, tenant isolation, auth, billing, all-eight-domain rendering, managed cases, alerts, reports/PDF, scheduled jobs, and capacity baseline.

## E2. Product gate

Confirm onboarding, customer wording, unsupported-claim removal, pricing/Stripe alignment (see F0), one primary CTA, visible limitations, support path, cancellation, and deletion.

## E3. Legal and trust gate

Producing the legal foundation is a task, not only a review:

- register with the ICO as a data controller (a legal requirement for UK personal-data processing; low cost);
- draft Terms of Service, Privacy Policy, and DPA (template-based drafts are acceptable at this stage; flag them for professional review as revenue grows);
- cookie and consent policy, and subprocessor list;
- data-retention statement;
- security contact and responsible-disclosure page;
- refund and cancellation policy;
- beta terms, including documented evidence limitations and, where applicable, the external-review limitation from C4;
- VAT position confirmed and Stripe Tax configured where applicable; invoice format carries the required company details.

Legal text requires separate careful review. Do not publish generated legal text without that review.

## E4. Operational gate

Confirm error-rate, cron-failure, and budget alerts; D1/R2/Worker monitoring; incident runbook; support mailbox; recovery plan; release and rollback owners; customer communication templates.

Recovery must be demonstrated, not described:

- one tested D1 restore (export or Time Travel) into a non-production database, with the restore time recorded;
- one R2 missing-object scenario exercised end to end;
- one Worker rollback drill executed against a recorded previous version id.

Create:

```text
v2026.xx.xx-rc1
```

Use later RCs only when fixes require another candidate.

## Exit gate

The RC checklist is fully green and founder-approved.

---

# Phase F — Commercial foundation before advertising

## F0. Pricing lockstep (precondition for every commercial asset)

The adopted pricing (Free forever + £9/£29/£69 SMB tiers + MSP £29 + £1/domain; metric = monitored domains) is **not yet live**; production Stripe still carries the legacy £29/£149/£399 plans.

Before any commercial asset, page, or conversation quotes a price:

- deploy Stripe products/prices, backend entitlements, and the pricing page together, in lockstep;
- verify upgrade and downgrade paths and plan limits against the new plans;
- confirm no existing workspace loses entitlements it currently holds;
- founder deploy approval is required.

**Precondition — resolve duplicate subscription rows** (found 15 July 2026 while proving PR-A's entitlement gate against production; **not** an Alerts blocker):

`getUserPlan` (`engines/entitlements.js:205`) selects `ORDER BY COALESCE(updated_at, created_at) DESC LIMIT 1` — the effective plan is simply the newest row. Three live owners hold **two** subscription rows each (`professional`/`trialing` **and** `starter`/`active`); every live workspace also has `current_period_end = NULL`, which `isExpiredDate` correctly treats as "not expired". Today both rows grant `alerts`, so entitlement is identical either way and nothing is broken — which is exactly why it is invisible. Under the new tiers the two rows would grant **different** entitlements, and which one wins would depend on row ordering rather than on a decision.

Before pricing lockstep:

- define the canonical active subscription row per owner (and what supersedes what);
- remove or supersede duplicate historical rows safely — append-only/superseded, never destructive (historical billing evidence is not disposable);
- ensure `getUserPlan` cannot depend on ambiguous newest-row ordering — resolve by an explicit canonical marker, not `ORDER BY ... LIMIT 1`;
- decide the meaning of a NULL `current_period_end` on a `trialing` row explicitly, rather than inheriting it from `isExpiredDate`'s null-check.

The first paying customer must be acquired on the adopted pricing. Do not change pricing mid-pilot for an active prospect.

## F1. Initial customer profile

### Small business

- UK-based;
- 5–100 employees;
- owns business domains;
- uses Microsoft 365 or Google Workspace;
- no dedicated security team;
- relies on an IT provider or generalist;
- values a plain-English action plan.

### MSP / IT-support provider

- UK-based;
- manages multiple small-business customers;
- needs portfolio visibility and recurring reports;
- wants a repeatable security review;
- does not want enterprise vulnerability tooling.

## F2. Initial offer

> A managed Cyber MOT for your business domain, with an eight-domain report, prioritised actions, ongoing monitoring, alerts, and clear follow-up.

State clearly what is included, monitored-domain limits, monitoring frequency, reports, alerts, managed cases, support, price, cancellation, and evidence limitations.

Do not sell “complete security,” “pentest,” “certification,” or “guaranteed protection.”

## F3. Sales assets

Prepare:

- one-page product overview;
- eight-domain overview;
- redacted sample Cyber MOT report;
- sample Executive PDF;
- “what CyberMeters can and cannot see” page;
- pricing page;
- FAQ;
- security/privacy page;
- MSP overview;
- onboarding guide;
- controlled demo;
- three-minute founder demo;
- discovery-call script;
- objection sheet;
- pilot agreement;
- onboarding checklist.

## F4. Measurement foundation

Configure Search Console, analytics, conversion events, consent, CRM/lead tracker, source/medium, free Cyber MOT start/completion, booked call, qualified lead, pilot, and paid conversion.

Primary metric:

```text
qualified opportunity
→ completed onboarding
→ paid customer
```

---

# Phase G — SEO programme (parallel lane)

SEO runs as a **low-intensity parallel lane from Phase B onward**: indexing takes months, and content work does not touch the product trust path. It must never displace the active canonical episode; the weekly cadence (Thursday) is its time budget. The phase letter marks when SEO becomes a primary focus, not when it starts.

## G1. Technical SEO

Confirm crawlability, canonical URLs, sitemap, robots rules, titles, meta descriptions, internal links, mobile speed, headings, status codes, Search Console, JavaScript rendering, and valid structured data.

## G2. Commercial pages

Create focused pages for:

- Cyber MOT for small businesses;
- website security monitoring UK;
- DMARC monitoring UK;
- external attack surface monitoring for SMEs;
- certificate expiry monitoring;
- brand impersonation monitoring;
- Cyber Essentials readiness;
- identity exposure monitoring;
- Shadow IT monitoring;
- MSP cyber-security monitoring;
- Cyber MOT Scotland;
- Cyber MOT UK.

Avoid thin, duplicated location pages.

## G3. Evidence-led content

Publish useful content such as:

- what a Cyber MOT checks;
- what external posture can and cannot see;
- DMARC reports explained;
- certificate expiry and business interruption;
- public admin surfaces;
- lookalike domains and invoice fraud;
- readiness versus certification;
- Shadow IT for small businesses;
- questions to ask an MSP;
- monthly UK small-business cyber posture briefing.

## G4. Content standard

Every page answers a real question, uses plain language, includes examples/evidence, explains limitations, has one CTA, and avoids generic AI filler.

## SEO KPIs

Track indexed pages, non-brand impressions, qualified organic visits, free Cyber MOT starts, booked calls, and paid conversions. Do not celebrate impressions without qualified action.

---

# Phase H — Founder-led sales before broad advertising

## H1. Prospect list

Create a controlled list of 50–100 UK prospects such as professional services, accountancy, legal, dental/medical where suitable, retailers, trades, charities, manufacturers, IT-support companies, and MSPs.

Do not scrape or mass-spam.

Track organisation, domain, contact, role, likely need, lawful-basis notes, outreach date, response, and next step.

## H2. Warm outreach

Start with existing business relationships, local networks, accountants, web developers, IT providers, chambers, Scottish business networks, LinkedIn connections, and cyber-professional contacts.

Message structure:

1. specific observation;
2. business relevance;
3. simple Cyber MOT explanation;
4. no fear-based language;
5. one low-friction next action.

## H3. Discovery call

Ask about domains, email/DNS ownership, Microsoft 365/Google Workspace, sender visibility, certificate ownership, public services, recurring reporting, buying authority, desired outcome, budget, and timeline.

## H4. Controlled pilot

Use a time-bounded 14- or 30-day pilot, one real domain, one review call, agreed success criteria, explicit end date, and conversion decision.

Success means the customer understands the report, identifies useful action, sees monitoring value, and agrees the recurring value exceeds the price.

---

# Phase I — Paid advertising

Paid acquisition begins only after landing pages, conversion tracking, real discovery-call language, clear pricing, and fast follow-up exist.

## I1. Google Search Ads

Start with high-intent search only.

Keyword families:

- cyber security check for small business;
- website security monitoring UK;
- DMARC monitoring UK;
- certificate expiry monitoring;
- external attack surface monitoring small business;
- Cyber Essentials readiness support;
- MSP security monitoring platform.

Use exact/phrase match initially, negative keywords, UK targeting, intent-specific landing pages, and qualified-lead/paid-customer conversion tracking.

Do not optimise only for form submissions.

## I2. LinkedIn

Start with founder-led content and tightly scoped outreach. Paid tests focus on MSP owners, IT-support founders, IT directors, and relevant operations leaders. Avoid broad awareness campaigns.

Microsoft Ads and retargeting are deliberately deferred to Phase O: they add measurement surface without adding first-customer probability.

## Advertising guardrails

Pause when tracking is broken, leads are irrelevant, follow-up is slow, CAC cannot be measured, landing-page intent is mismatched, or fear-based claims attract the wrong audience.

Start with a controlled test budget. Define maximum monthly spend, cost per qualified lead, cost per meeting, target CAC, and stop-loss threshold. Scale only after repeatable qualified demand.

---

# Phase J — First controlled real users

Entry gate: clean exit of the founder-controlled private beta on the two controlled domains (`cybermeters.com` and `blackbullbarbers.co.uk`) — no open P0/P1 arising from private-beta usage. Cohorts 1 and 2 below are the first two controlled external invitations defined by the canonical sequence.

## Cohort 1: one real small business

Observe at least 48 hours after meaningful use. Track signup, verification, domain addition, first scan, first useful finding, report comprehension, support questions, alerts, and willingness to continue.

## Cohort 2: one MSP or IT-support provider

Observe 48–72 hours. Track customer/domain setup, portfolio comprehension, report value, case ownership, commercial value, and willingness to introduce a customer.

## Exit gate

At least one controlled user reaches first value without founder intervention that would not scale.

---

# Phase K — Convert the first paying customer

## K1. Value review

At pilot midpoint/end, show what was observed, what changed, what action was completed, what remains, what monitoring will continue, and what is lost if monitoring stops.

## K2. Ask directly

> CyberMeters has shown the external issues, ownership, and monitoring value for your domain. Shall we keep this active on the appropriate paid plan from the pilot end date?

## K3. Objection handling

- Antivirus: CyberMeters covers externally observable posture, not endpoint antivirus.
- IT provider: CyberMeters complements the provider with evidence, prioritisation, and monitoring.
- Cyber Essentials: certification and continuous external monitoring are different.
- One-off check: historical change, alerts, certificate monitoring, sender intelligence, and recurrence create ongoing value.
- Price: return to domains, interruption risk, staff time, reporting, and visibility before discounting.

## K4. Payment proof

Confirm production Stripe checkout, plan, entitlement, invoice/receipt (VAT-correct, see E3), onboarding continuity, support contact, renewal date, and cancellation path.

## Exit gate

- payment received;
- subscription active;
- real domain monitored;
- customer reached first value;
- no unresolved P0/P1 issue;
- acquisition source and conversion reason documented.

---

# Phase L — Case study and repeatable sales system

After the first payment, request permission for an anonymised or named case study.

Capture customer profile, initial concern, findings, actions, time to value, monitoring outcome, quote, measurable improvement, and limitations.

Build repeatable pipeline stages, response-time targets, discovery/pilot/proposal/onboarding templates, monthly review, and churn-risk checklist.

---

# Phase M — UK and Scotland funding after first paid evidence

Funding begins after the first paying customer unless an unusually strong time-limited opportunity appears. Funding accelerates proven growth; it does not replace customer discovery.

- Maintain a funding evidence pack: company profile, founder CV, product and architecture summary, innovation narrative, customer evidence, revenue and pipeline, pricing, forecast, use of funds, Scottish/UK impact, R&D work packages, milestones, risks, security/privacy posture, and IP position.
- Review monthly: GOV.UK Find a Grant, the UK business finance and support finder, Innovate UK competitions, Scottish Enterprise funding calls, Find Business Support Scotland, Business Gateway, HIE or South of Scotland Enterprise where geographically relevant, Horizon Europe, and Scottish EDGE where entity-age and eligibility rules fit.
- Gate every application on eligibility, strategic fit, customer evidence, match funding, distraction cost, reporting burden, deadline, and outcome value. Reject weak-fit funding.
- Guardrails: do not invent a project, exaggerate AI, overstate readiness, misrepresent traction, depend on grants for core survival, delay sales, or assume a programme remains open without checking the official source.

Full application detail lives in a dedicated funding document produced when this phase starts; this roadmap holds only the gate.

---

# Phase N — Gradual cohort expansion

```text
2 controlled users
→ 5
→ 10
→ 25
→ wider public beta
```

Before each expansion review error rate, support load, onboarding completion, time to value, false positives, alert reliability, scan duration, D1/Worker/R2 usage, email deliverability, billing failures, churn signals, CAC, and conversion.

The full-scope external independent security review (C4) must be complete, with retests green, before expansion beyond the 5-user cohort.

---

# Phase O — Wider public beta and commercial scaling

After stability:

- open controlled public signup;
- maintain capacity gates;
- publish customer evidence;
- refine pricing and entitlements;
- improve MSP onboarding;
- establish support SLAs/SLOs;
- run recovery exercises;
- repeat external security review;
- build product analytics;
- optimise conversion funnel;
- expand commercial website;
- start Microsoft Ads and consent-compliant retargeting once meaningful traffic and conversion evidence exist;
- build partner/referral programme;
- prepare compliance roadmap.

---

# Weekly founder cadence

## Monday — Product and reliability

Review incidents, P0/P1 issues, roadmap gate, and technical scope.

## Tuesday — Customer discovery and sales

Prospect research, outreach, discovery calls, and pilot follow-up.

## Wednesday — Product evidence

Review findings, false positives, reports, demos, and case-study evidence.

## Thursday — Marketing and content

Publish one high-quality page/article or founder-led post; improve landing pages; review ads when active. This is the SEO parallel lane's time budget (see Phase G).

## Friday — Metrics and commercial review

Review active users, leads, calls, pilots, customers, MRR, onboarding, time to value, support load, infrastructure usage, and roadmap status.

## Monthly after first payment

Review official funding finders, funding pack, cash runway, acquisition economics, and next cohort size.

---

# Executive scorecard

## Product

Canonical phases, P0/P1, parity, cases, alerts, verification, reports.

## Reliability

Error rate, scan completion, cron success, delivery, duplicates, incidents, rollback readiness.

## Security

Open findings, tenant isolation, auth testing, pentest/retest.

## Acquisition

Qualified organic visits, Cyber MOT starts, leads, calls, pilots, paid conversions, source.

## Commercial

MRR, ARR, ARPC, CPL, CAC, pilot-to-paid conversion, churn, expansion.

## Funding

Eligible calls, applications, requested amount, match, status, funded milestones.

---

# Non-negotiable principles

1. Product trust before acquisition volume.
2. No paid advertising before conversion tracking and clear landing pages.
3. No grant application without strategic fit.
4. No unsupported security claim.
5. No customer assertion presented as CyberMeters verification.
6. No public beta before the RC gate.
7. No wider cohort before the previous cohort is stable.
8. No feature expansion that delays first paid evidence.
9. No grant dependency replacing sales.
10. Every production defect gets a regression test where practical.
11. Every customer-facing state is evidence-led.
12. Measure channels through paid conversion, not vanity metrics.
13. Hardening phases are timeboxed; gates are decided on P0/P1 status, never on zero findings.
14. No commercial asset quotes legacy pricing; the pricing lockstep (F0) precedes every priced conversation.

---

# Official next actions

The canonical order is the Pre-Public-Beta Gate Sequence above. **M5 (a–g) is engineering-complete; the active phase is the rescoped episode "Posture Timeline Trust & Actionability" (the founder-approved RESCOPE of M6, following M6.0-B).** The immediate sequence:

1. Deliver **"Posture Timeline Trust & Actionability"** (plan: `docs/EPISODE-PLAN-posture-timeline-trust.md`) — **Phase A** first: port the eligibility/producer-version guards already on migrations `091`/`093`/`095` onto `asset_events` (mig `004`) + flip-flop dedupe (fail-closed comparison statuses, `asset_events` never mutated/deleted); **Phase B** after Phase A ships and the controlled detection fixtures pass: the single sensor-sufficient UC3 host-level correlation (one canonical managed case + canonical owner or explicitly unassigned; remediation mapped to the registry or explicit-unknown; no pre-committed migration). Behaviour Intelligence stays explicitly deferred (sensor-dependent, founder-gated). *(M6.0-B ran 2026-07-18; the founder ruled RESCOPE because GO criteria were unmet — see gate 7.)*
2. Complete **M7 Pricing + Billing** lockstep (Stripe + entitlements + pricing cards, one release, founder-approved); architecture may provision a Behaviour / Change Intelligence tier as headroom, but that tier depends on the deferred, sensor-dependent programme and must not be sold as shipped functionality.
3. Run Final Beta Hardening, with demonstrated restore/recovery/rollback drills and outbound email-deliverability verification.
4. Complete Controlled Authenticated / Live Acceptance across every managed vertical.
5. Complete Independent Pentest + Remediation Retest.
6. Complete the Legal & Data-Protection Foundation (ICO fee self-assessment, Privacy Notice, Terms, DPA, retention/DSAR).
7. Produce and approve `-rc1` once every prior gate is green.
10. Complete Final Website Design & Conversion.
11. Send controlled private-beta invitations, then run the private-beta acceptance and fix cycle.
12. Open the Public Beta Gate only from the last accepted RC.
13. Convert the first paying customer; document the case study.
14. Submit strong-fit UK/Scotland funding applications after first paid evidence.
15. Expand cohorts gradually; commission the full external security review before expanding beyond five users.

# Final directive

The first paying customer comes from:

```text
credible product
+ verified reliability
+ security assurance
+ clear commercial offer
+ founder-led sales
+ measurable marketing
+ disciplined follow-up
```

Do not wait for grants before selling.
Do not wait for perfect brand awareness before contacting customers.
Do not buy traffic before measuring conversion.
Complete the product, prove trust, speak to real organisations, demonstrate value, ask for the sale, and use first revenue as evidence for growth and funding.
