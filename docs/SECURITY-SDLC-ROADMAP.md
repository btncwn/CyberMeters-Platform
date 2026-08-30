# CyberMeters — Security & Hardening Roadmap (Secure SDLC)

> **Status: TECHNICAL CONTROL-STATUS REFERENCE — not role, governance or current
> queue authority.** Schedule controls through the canonical execution order and
> apply the R0/R1/R2 assurance model. The dated owner/status text below is
> historical unless refreshed by measured evidence.

> **Core principle (non-negotiable):** a pentest does not make a SaaS "safe". It
> finds what was visible on one date, in one scope. Real safety comes from a
> **Secure SDLC**: close each finding at its root, then make the same mistake
> impossible to silently reintroduce. **Every security finding must become an
> automated regression test — not just a code fix.** So the next engineer,
> refactor, or AI agent cannot quietly bring it back.

```
Pentest + Retest + ASVS verification + Tenant-isolation regression tests
+ Secure CI/CD gates + Threat modelling + Monitoring + Backup/restore
+ Incident response + Controlled releases  =  Production-grade SaaS
```

**Status legend:** ✅ done · 🟡 partial / in progress · ⬜ not started
**Historical owner/status:** Lead Engineer (Turhan + Claude). Last updated:
2026-07-11.

This document is **living** — update statuses in place, never fork it. When a
finding is closed, link its fix commit AND its regression test here.

---

## Where we are today (honest snapshot, 2026-07-11)

Two independent adversarial passes plus two internal ones ran this cycle; **9
security findings surfaced, all 9 fixed and deployed**, each verified against the
current HEAD before merge (refute-first, zero false-positives shipped):

| Source | Findings | Outcome |
|---|---|---|
| Pre-beta code audit (DeepSeek + internal) | 3 P1 | fixed + deployed `v2026.07.10-9` |
| Black-box red-team (internal, 16 probes) | 1 (signup enum) + 1 dep-CVE | fixed + deployed `v2026.07.10-10` |
| Authenticated logic red-team (Codex) | 2 P1 + 2 P2 | fixed + deployed `v2026.07.10-11` |

Live security posture is strong: HSTS/CSP/X-Frame/nosniff, all protected
endpoints 401, error sanitisation (no SQL/stack/secret leak), CORS not
reflected, login rate-limit fires, body-413 / URL-414, webhook 400-unsigned,
no file leaks, `security.txt` present, no cookies. What remains is **process**:
turning this from "we passed the tests" into "the tests can't regress".

---

## Prioritised programme

### P0 — required before public self-serve

| # | Item | Status | Evidence / gap |
|---|---|---|---|
| 1 | Close pentest critical/high findings at root | ✅ | 9/9 fixed; roots addressed (e.g. palette drift → single source; PLAN_LIMITS import class) |
| 2 | Independent retest | 🟡 | Every fix independently re-verified vs HEAD + live smoke by a second reviewer. Full internal pentest run against the 459-control checklist by a qualified team — Turhan (CompTIA Security+) with Claude/Codex/ChatGPT — see `docs/PENTEST-CHECKLIST-INTERNAL.md` (coverage map: ~14 areas CI-proven, focused manual queue for SSO/XSS/SSRF/business-logic). An independent external review remains on the roadmap for commercial scale (P2-1); the Trust Center reflects this honestly. |
| 3 | Cross-tenant test pack (per resource) | ✅ | `validate-tenant-isolation.js` (57 assertions) drives the real fetch() router with four actors (admin/viewer/foreign/non-member) over 13 resource endpoints, asserting all 7 invariants incl. the existence oracle; runs in CI. Plus `validate-integration.js` (18) at the auth-helper level. |
| 4 | Auth/session/MFA/SSO regression tests | 🟡 | `validate-security-contracts.js` (45) covers auth/MFA/RBAC/billing; MFA proof endpoints now fail-closed (`27d597f`,`a7ea6e5`); full SSO/session-fixation regression suite = partial |
| 5 | Stripe webhook idempotency + signature tests | ✅ | Signature verified before parse ✅; upsert-not-insert prevents duplicate state; strict processed-event-id replay guard now persists every handled event in `stripe_processed_events` (migration 069) and `INSERT OR IGNORE` short-circuits a replay to `{received, deduped}` before the switch (`global-billing.js`). `validate-pipeline.js` posts the same webhook twice and asserts the replay is deduped, not reprocessed (38/38). |
| 6 | Rate limits fail-closed on cost/abuse paths | ✅ | Invitation send (`4af86f7`), all MFA proof endpoints (`27d597f`,`a7ea6e5`) now fail-closed. Global read guard is intentionally fail-open. Scan-start quota fail-open is documented/accepted. |
| 7 | Secret + log redaction | ✅ | CI secret-scan ✅; audit-metadata redaction ✅ (`sanitizeAuditMetadata`); customer error sanitisation ✅; central `src/lib/redact.js` now strips secret-named keys and secret-shaped values (JWT/Stripe/whsec_/Bearer/long-hex) and the `serverError` logger routes through `redactedJson()` — defense-in-depth so no log site can leak a credential. `validate-log-redaction.js` (17/17). |
| 8 | Backup + real restore test | ✅ | Proven restore drill in `docs/BACKUP-RESTORE-DRILL.md` — prod D1 exported (2.7 MB), restored into a fresh DB (**RTO 1.57 s**, 59 tables), `integrity_check` ok, no FK violations, real rows verified. Runbook + RPO/RTO + Option A/B procedures recorded, plus guarded ops scripts (`scripts/ops/backup-production-data.sh`, `scripts/ops/restore-production-backup-to-staging.sh`) proven by `validate-f004-recovery-instrumentation.js`. R2 has no object versioning, so recovery is a separately copied object set plus manifest. Follow-ups: automate daily export + manifest copy (Turhan-gated). |
| 9 | Production monitoring + alerting | 🟡→✅ | Three layers documented in `docs/MONITORING.md`: (1) `/health` + `/ready` (D1+R2) probes; (2) real-time signals — `http_5xx` metric, redacted `[request-error]`/`[cron-error]` logs; (3) **daily ops-health heartbeat** (`opsHealthHeartbeat`, self-alerting email on stuck scans / undelivered-email backlog / overdue purges, `validate-ops-health.js` 29 assertions, CI-blocking). Only outstanding piece is **Turhan/dashboard**: Cloudflare Notification policy + an uptime monitor pointed at `/ready`. |
| 10 | Incident-response base plan | ✅ | `docs/INCIDENT-RESPONSE-PLAN.md` — roles, SEV1/2/3, lifecycle, break-glass command reference (rollback / secret rotation / session + token revoke / account freeze), 12 per-incident playbooks, ICO 72h notification path, RPO/RTO, post-incident review template |

### P1 — before public beta

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | OWASP ASVS 5.0 Level 2 gap assessment | ✅ | `docs/ASVS-GAP-ASSESSMENT.md` — 16 chapters mapped to implementation + evidence; at/near L2, 7 tracked gaps |
| 2 | Threat model per critical flow | ✅ | `docs/THREAT-MODEL.md` — STRIDE across 16 flows with control + evidence + residual risk |
| 3 | CI security gates (expand) | ✅ | secret-scan, 8 harnesses (now incl. log-redaction, purge-completeness, migrations), dry-run, OpenAPI, frontend audit, typecheck, vitest, build. SAST ✅ (Semgrep). Worker `npm audit --audit-level=high` ✅ (0 vulns), migration validation ✅, SBOM generation ✅, all Actions pinned to commit SHAs ✅, and a **license-policy gate** ✅ (`validate-licenses.js` — permissive allowlist + documented exceptions, reads the SBOMs, 344 deps clean) — all CI-blocking. No remaining polish. |
| 4 | Business-logic abuse tests | 🟡 | Trial recycle closed (`5b57af3`) + notification scoping (`68d056b`); formalise the abuse matrix below as tests |
| 5 | Load / resilience / idempotency tests | ⬜ | Concurrent scans, large DMARC XML, slow DNS, provider timeouts, cron double-run |
| 6 | Migration test system | 🟡 | All migrations additive — now **enforced** by `validate-migrations.js` (destructive-statement scan + fresh-apply convergence, CI-blocking); **staging apply + rollback/corrective plan per migration = remaining gap** |
| 7 | Staging parity with production | ⬜ | Same runtime/bindings, separate D1/R2/Stripe-test/secrets; anonymised data only |
| 8 | Dependency + SBOM process | ✅ | Lockfiles committed (`6068eb3`), `npm audit --audit-level=high` 0 across both workspaces (CI-blocking); **CycloneDX SBOMs** generated per workspace (`sbom/*.cdx.json`, regenerated + uploaded as a CI artifact each run); **all CI GitHub Actions pinned to full commit SHAs** (checkout/setup-node/setup-python/upload-artifact) so a mutated tag can't inject code. |
| 9 | Secure release checklist | ✅ | `docs/07-RELEASE-CHECKLIST.md` v2.0 — executable runbook: risk-tier deploy gate, full local validation gate (12 harnesses + audit + dry-run), migration apply+verify with pre-snapshot, deploy + Version-ID recording, live smoke test (`/health`+`/ready`+401), tag/CHANGELOG, and a fast rollback path. Cross-links incident-response/monitoring/backup rather than duplicating. |
| 10 | Data retention + deletion verification | ✅ | Soft-delete + 30-day purge verified (beta checklist); `validate-purge-completeness.js` now seeds every purge table + reports + scan (+children) for two workspaces, runs the real `purgeWorkspaceData` to completion, and asserts zero orphaned rows/R2 objects for the purged workspace with the other fully intact (10/10, CI-blocking) — guards the `workspace_assets` orphan class. |

### P2 — before commercial growth

Regular independent pentest · vulnerability-disclosure policy · public trust/security
page · disaster-recovery exercise · privileged-access review · OWASP SAMM maturity
assessment · secure-development training · recurring threat-model refresh · security KPIs.

---

## Tenant isolation matrix ✅ (`scripts/validate-tenant-isolation.js`, in CI)

For CyberMeters, cross-tenant data access outranks even classic XSS. Every API
resource gets the same seven assertions — now enforced by a real-fetch harness
(four seeded actors × 13 resource endpoints, 57 assertions, CI-blocking):

```
A cannot READ B's resource
A cannot MODIFY B's resource
A cannot DELETE B's resource
A cannot tell whether B's resource EXISTS (404 == 403)   ← the domain-oracle class (4783ef6)
A low-privilege member cannot perform an admin action
A soft-deleted workspace cannot be reused / re-trialed    ← trial recycle (5b57af3)
An invite token cannot be used for another workspace
```

Apply across: **Domains · Scans · Reports · Assets · Brand monitoring · DMARC
reports · Email sender inventory · API tokens · Audit logs · Invitations ·
Billing · Workspace settings · R2 report objects · Notifications.**

Preferred data-access shape everywhere (scope in the query, not after the fetch):

```sql
SELECT * FROM scans WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL;
```

Fetching by `id` first and checking ownership afterwards is the exact pattern
that produced the domain existence oracle — avoid it.

---

## Business-logic abuse checklist (turn each into a test)

- Free user exceeds plan limits? · Deleted domain re-added to bypass entitlement?
- Same scan re-triggered to run up cost? · Scheduled scan runs as another workspace?
- **Trial re-started repeatedly?** ✅ closed (`5b57af3`) · Stripe webhook replayed?
- Stale/forged webhook flips subscription state? · Invitation reused?
- Email endpoint used for spam? · **Signup used to enumerate accounts?** ✅ closed (`429f2e0`)
- DMARC XML import → storage/parser DoS? (size + XML-bomb guards present — add a test)
- R2 object key guessed to reach a report? · Soft-deleted workspace still API-readable?

---

## Error handling & fail-safe (verified ✅, keep as a gate)

Never returned to the user: SQL error, stack trace, internal object key, worker
binding, third-party response body, user/workspace existence, secret/config
names. Internal log keeps a correlation ID for diagnosis:

```json
{ "request_id": "...", "workspace_id": "...", "route": "...", "error_code": "...", "timestamp": "..." }
```

Current `serverError()` already does exactly this — the gate is: no new route may
bypass it.

## Rate limiting (fail-closed on cost/abuse paths)

Priority endpoints — login · registration · email verification · password reset ·
invitation · scan trigger · domain verification · report generation · DMARC import ·
support forms · email sending · API-token creation. Key on the right combination,
not just IP: `IP · user_id · workspace_id · email · domain · endpoint`.

## Secrets & keys

Secrets out of the repo (CI secret-scan ✅) · prod/staging split · rotation
procedure ⬜ · revocation process ⬜ · least privilege · unused-key cleanup ·
**scan git HISTORY, not just current files** ⬜ · leak incident procedure ⬜.

## Incident-response plan ✅ (`docs/INCIDENT-RESPONSE-PLAN.md`)

Written playbooks for all 12 incident types (cross-tenant exposure · stolen API
token · compromised user/admin account · secret leak · malicious dependency ·
Stripe webhook abuse · DB corruption · R2 report leak · email-account compromise ·
mass scan abuse · Cloudflare account compromise), each with Detect → Contain →
Investigate → Recover → Notify. Includes a break-glass command reference
(worker rollback, per-secret rotation, session/token revoke, account freeze,
evidence snapshot), SEV1/2/3 targets, the ICO 72-hour notification decision path,
and RPO/RTO. Each answers: who decides · which access is cut · how secrets rotate ·
how logs are preserved · how affected customers are identified · who notifies ·
whether the regulator must be told.

---

## The release gate (formalise the discipline we already follow)

Pre-release, all must pass: build · unit tests · integration tests · tenant-isolation
tests · security scan · no unresolved critical/high · migration tested · rollback plan
ready · staging smoke · monitoring enabled · release notes · owner assigned.

Merge policy: critical/high vuln → **blocked** · secret detected → **blocked** ·
failed tenant test → **blocked** · failed migration test → **blocked** · coverage
drop beyond threshold → **blocked**.

Post-release smoke (we do this manually today — automate it): `/health` · anon
auth 401 · tenant isolation spot-check · scan trigger · report access · billing
webhook · error-rate watch · cron health.

---

## Reference frameworks

- **OWASP ASVS 5.0** — verifiable security requirements (target Level 2).
- **NIST SSDF (SP 800-218)** — integrate secure practices continuously into the SDLC.
- **OWASP SAMM** — maturity across governance, design, implementation, verification, operations.
- **CISA Secure by Design** — secure defaults; the vendor owns the outcome, not the customer.

---

## The one rule that ties it together

> Every security finding closes as **a code fix _and_ an automated regression
> test**. Today's proof: palette drift → `serviceColors.test.js`; the PLAN_LIMITS
> import break → CI `validate-pipeline`; signup enumeration + notification scoping
> + trial recycle → fixes landed with the invariants they protect now guarded.
> A finding without a regression test is not closed — it is deferred.
