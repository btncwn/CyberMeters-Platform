# P0 blockers — controlled invite-only → PUBLIC (open sign-up) beta

> Compiled 2026-07-12 from a 3-way audit (beta-readiness docs · pentest/threat docs
> · live codebase reality-check), each item reconciled against the others and
> spot-verified in code. **Scope:** what must close to open *public self-service
> sign-up at scale* — controlled invite-only beta is already GO.

## TL;DR — calibration first

The platform is **unusually well-hardened for a beta.** Every abuse-prone
unauth endpoint is already throttled and fail-closed; SSRF is well-mitigated; no
hardcoded secrets; single-use reset tokens; all sessions killed on password
change; enumeration defended; tenant-isolation, purge, Stripe-signature, DMARC-XXE
and ~31 security contracts are CI-locked. So the true P0 set is **short**: two
small code fixes, one internal manual-pentest pass, two ops/dashboard steps, and a
capacity check. Nothing here is a gaping hole.

Several items flagged in older docs are **already done** — see the "Do NOT re-do"
list so no effort is wasted.

---

## P0 — must close before opening public sign-up

### Security (code — small, concrete)
1. **Per-account login lockout.** Login throttle is **per-IP only**
   (`routes/auth.js:188`, key `login_<iphash>`). A distributed/botnet attack
   spreading guesses across IPs faces no per-account ceiling. Add a per-account
   failure counter + progressive backoff/lockout. *Effort: S.*
2. **Fail-OPEN throttles under D1 stress.** `consumeApiRateLimit` allows on any D1
   error unless `failClosed` is set (`index.js:1850`). Abuse endpoints set it, but
   **`scan_start` (`routes/scans.js:77`) and the global read/write guard
   (`index.js:1978`) do not** — throttles evaporate during exactly the D1 overload
   an attack causes. Set `failClosed` on both. *Effort: S.*

### Manual pentest pass (internal — Turhan Sec+ / team; do before opening)
3. **Free-scan public abuse (§32, P0).** `POST /api/free-scan` (unauth) — confirm
   end-to-end: (a) no SSRF pivot incl. **public-domain→302→internal** redirect,
   (b) per-IP cap can't be trivially botnet-spread into cost/DoS abuse, (c) response
   leaks only public data, (d) not usable for enumeration. *SSRF input-gate + 5/hr
   throttle exist (`validate-ssrf-domain-guard.js`, `routes/billing.js:59`) — this
   is manual confirmation of the gaps those can't prove.*
4. **Stored-XSS in Exposure digest/timeline + digest email render (§31, P0).**
   Inject payloads via domain / workspace / asset-hostname / finding names; verify
   render-time escaping in the timeline UI and the weekly-digest email. CSP is
   hardened but output-encoding is not CI-proven.
5. **R2 object-key authorization (§14).** Can workspace A read workspace B's report
   by guessing/enumerating the R2 object key? Purge is automated; read-auth-by-key
   is not. Verify the report route checks ownership, not just key existence.
6. **Microsoft SSO click-through (§6) + session-fixation (§3).** State param,
   redirect_uri allow-list, one-time-code single-use, and session-not-fixated —
   need a real browser intercept (can't be proven by unit CI).

### Ops (Turhan / Cloudflare dashboard — before opening at scale)
7. **Error-rate alert + external uptime monitor on `/ready`.** Ops-health heartbeat
   is CI (`validate-ops-health.js`), but the Cloudflare **Notification policy**
   (worker 5xx / error-rate) and an external uptime monitor on `/ready` are manual
   dashboard steps. Without them, failures are invisible until customers report.
8. **Capacity / quota headroom.** Resend + Cloudflare (Workers/D1/Pages) limits are
   sized for ~10 users (CONTROLLED-BETA §4, open checkbox). Verify headroom for
   public volume, and add a **concurrency cap on scheduled-scan bursts** — all due
   schedules fire in one cron tick and approach the Workers 1,000-subrequest limit
   as the schedule population grows (Backlog P2-R1).

---

## P1 — close soon (not blocking the first public cohort)

- **Verification tokens hashed at rest** — currently plaintext; D1 exfil = usable token pool (Backlog P2-S1).
- **Session hardening** — migrate token from `localStorage` → httpOnly cookie (XSS→ATO); add a per-user session cap (unbounded `user_sessions` growth) (Backlog P2-S2, P2-M2).
- **Stripe webhook ownership check** — validate `metadata.workspace_id` against the actual owner on `checkout.session.completed` (wrong-tenant grant) (Backlog P2-S4). *Signature + lifecycle are DONE; confirm duplicate-event idempotency uses `stripe_processed_events` (migration 069).*
- **Prune `api_rate_limits`** — never cleaned; grows continuously, degrading the hot-path SELECT (add a cron prune).
- **Atomic rate-limit** — read-then-increment overshoots under concurrent bursts (`index.js:1801`); migrate to Durable Object / queue.
- **PBKDF2 100k → ~600k** (rehash-on-login) + a breached/common-password denylist (`lib/password.js:16`, `routes/auth.js:34`).
- **`scheduled_scans` created via inline DDL** — move to a real migration (schema drift / no rollback) (Backlog P1-6).
- **Worker fault isolation** (Sprint 10) — a scanner fault can take the API down; the explicit reliability gate for public scale (Sprint-9 modularisation is done but is *not* fault isolation).
- **Business-logic abuse matrix as tests** — invite reuse/replay, plan-gate bypass, quota reset, workspace-delete race, notification send-rate abuse (§29/§22).

---

## P2 — non-blocking cleanups

- ~~**A probe that never executed was reported as healthy**~~ — **FIXED 15 July 2026 (PR #105).** Reproduced end-to-end: `safeFetch` returns null on a 10s timeout, a redirect loop, `>MAX_REDIRECT_HOPS`, a blocked target or any throw; `runHeadersModule` returned that as an ordinary success (`accessible:false`, no error/incomplete/skipped), so `buildScanQuality` graded the scan **`complete`**, `moduleAssessed` said the module ran, scoring emitted nothing (it gates on `accessible`), and the eight-domain resolver rendered **Website Security = `assessed_healthy`, "Assessed — no material issue observed", coverage `complete`** for a site nobody could reach. `ssl-scan` had the mirror defect: a timed-out HTTPS probe became `https_available:false` and scoring turned it into a **critical** finding asserting "TLS handshake failed or connection refused on port 443" — a claim a timeout cannot support. **Fix:** headers/ssl declare `incomplete` when the probe did not execute; `https_available` is tri-state (null = we did not look); scoring + posture-scoring claim unavailability only on an observed `=== false`; CE signals are tri-state; CE returns `not_assessed` with no scan; the resolver renders that as `evidence_insufficient`. Proof: `validate-probe-evidence-honesty.js` (68 assertions), fixtures generated by driving the REAL modules against a failing fetch, mutation-tested.

- ~~**`cyber_essentials_answers` survived every workspace purge**~~ — **FIXED 15 July 2026 (PR #106).** The table was never in `WORKSPACE_PURGE_TABLES` for its entire life. It holds `note` (free customer text) and `answered_by`, and has no FK to `workspaces(id)` so D1 could not block the parent delete either — while `purgeWorkspaceRequest` emails the owner that the workspace "and all of its data have now been permanently removed". **Why it was invisible:** `validate-purge-completeness` seeded rows by iterating `WORKSPACE_PURGE_TABLES`, so it could only prove the list purges the tables *on the list*; a forgotten table was never seeded and never counted, and the suite reported 10/10. `index.js` also claimed the list was "kept in sync by `purge_covers_all_workspace_fk_tables`" — **that test never existed**, and neither did `purge_covers_all_scan_fk_tables` cited beside it. **Fix:** the table is purged, and the guard is now derived from the SCHEMA — every `workspace_id`-bearing table (57) must be purged or in an explicit exception allowlist with a stated reason. Mutation-tested: removing the table leaves 3 customer notes alive after a completed purge.

- ~~**CE graded one workspace from another workspace's scan**~~ — **FIXED 15 July 2026 (PR #106).** `workspace_domains` is PK `(workspace_id, domain_id)`, so one domain may be linked by several workspaces by design (an MSP and its client both owning acme.com). CE resolved evidence with `(s.workspace_id = ? OR wd.workspace_id = ?)`; the OR arm matched on merely *linking* the domain, so `ORDER BY s.created_at DESC LIMIT 1` deterministically resolved the MSP's hourly scan and graded the client from it. **Fix:** `s.workspace_id = ?` only, and `buildScorecardData` gained an explicit `scanScope` option because CE's counts came through it as a back door. Legacy `workspace_id IS NULL` scans belong to nobody and are excluded → `not_assessed`, never a pass.

- **`buildScorecardData`'s default scope lets a co-owning workspace's newer scan supply another's posture VIEW** (added 15 July 2026, from PR #106; **founder product decision required**). The PDF and the workspace scorecard route still resolve the newest completed scan of any *linked* domain, whoever ran it. For a computed view of a domain both parties verifiably own, that is defensible — it is external observation of their own domain — which is why the default was left unchanged rather than altered silently. CE opts into `scanScope: "workspace"` because alerting evidence must be strict. **Decide:** should the view be strict too? A one-line default change. **Note the migration-021 risk:** pre-021 scans carry `workspace_id NULL` and would drop out of a strict view.

- **Website Security's `ssl_not_available` resolves a `certificates_trust` remediation** (added 16 July 2026, from the corrective Alerts phase). The eight-domain resolver attributes `ssl_*` to `website_security` (`cyber-mot-domains.js`), while the registry maps `ssl_not_available` → `cert.tls.install` with `domain_key: "certificates_trust"`. The alert copy is correct and useful ("Enable HTTPS with a valid certificate" genuinely is a certificate action); only the attribution is inconsistent. **Impact:** none customer-facing. Same class: `dse_cookie_*`/`dse_hsts_*` are registered `website_security` but classified `attack_surface` by the resolver regex, and `csp_weak_policy` (medium) matches **no** domain regex at all, so a material finding is counted in zero domains.

- **`tech_*` findings score Website Security while `technology_detection` is declared a Shadow IT module** (added 16 July 2026). Presentation/attribution inconsistency only; `tech_*` is info/low and cannot alert.

- **The historical baseline is selected without a `workspace_id`, so "new since your last scan" can mean another tenant's scan** (added 15 July 2026, from PR-B4b). `runHistoricalModule` (`engines/historical-scan.js`) picks the comparison baseline with `WHERE domain = ? AND status='completed' AND scan_quality='complete'` — **no workspace scope** — and `workspace_domains` is keyed `(workspace_id, domain_id)`, so one domain may be linked to several workspaces. Workspace B's `new_findings` / `score_change` / `previous_scan_id` can therefore be derived from workspace A's scan of the same domain, on a clock B does not control. **This is NOT a cross-tenant data exposure and must not be reported as one:** `requireScanReadAccess` (`index.js`) scopes every scan read to the scan's own workspace and returns null (404, no existence oracle), so B cannot fetch A's scan from the leaked id; and both workspaces are verified owners of that same domain, so the findings are external observations both are entitled to. **Impact:** the *claim* is wrong, not the access. It is why PR-B4b suppressed `new_finding` outbound. It still affects the in-app trend and `previous_scan_id`. **Fix:** scope the baseline to the scanning workspace (prefer `scans.workspace_id`), and treat a cross-workspace baseline as no baseline rather than as a comparable one. **Reachability:** requires two workspaces to have verified the same domain (an MSP and its client is the realistic case).

- **The weekly digest is not entitlement- or preference-gated** (added 15 July 2026, from PR-B4b inventory; **product decision required, not an engineering fix**). `sendWeeklyDigests` (`engines/weekly-digest.js`) calls `deliverEmail` directly, bypassing `sendTenantAlertEmail`. It checks `email_verified` and its own DB-backed per-ISO-week dedupe (`lifecycle_email_events.dedupe_key`, `ON CONFLICT DO NOTHING` — sound), but performs **no entitlement check and honours no alert preference**: a customer who set `managed_alert.enabled = 0` still receives it, and so does a free workspace. **Whether that is correct depends on what the digest IS** — a paid alerts feature (then it must be gated) or a free lifecycle/product email like a newsletter (then it is right as-is). That is a founder call, so B4b deliberately left it unchanged. **Not an evidence-honesty defect:** the digest is a summary and asserts no occurrence-level urgency, so it does not violate the alert honesty rules. Note `ALERT_EMAIL_FREQUENCIES` (`alert-gate.js`) still carries a comment saying no digest sender exists — that comment is now wrong.

- **Three parallel alert-email retry sweeps, each with its own storage and backoff policy** (added 15 July 2026, from PR-B4b inventory). `alert_delivery_retry` (canonical `alert_deliveries`), `asset_alert_retry` (legacy `asset_alert_records`) and `lifecycle_email_retry` (`lifecycle_email_events`) each have a separate storage model, backoff and terminal-vs-transient classification. This is the fragmentation `managed-alerts.js` says it exists to end; the canonical sweep currently covers only the six wired domains. **Impact:** maintenance and consistency only — all three work. **Fix:** fold `asset_change` into the canonical ledger once Attack Surface owns asset-change occurrences.

- **`buildAssetAlertEmail` has no label for four event types it can alert on** (added 15 July 2026, from PR-B4b inventory). `assetAlertSeverity`/`assetAlertWorthy` (`engines/asset-alerts.js`) grade and count `admin_surface_detected` (→ `high`) and the three `certificate_new_*` types (→ `medium`), but the `LABELS` map in `buildAssetAlertEmail` has **no entry** for any of them, and `topHostnames` (`asset-alert-delivery.js`) also omits `admin_surface_detected`. **Impact:** an alert can fire at `high` and render an empty list — the customer gets a severity-coloured email that names nothing. Customer-facing quality defect, not an honesty or security one; `asset_change` is otherwise well-evidenced (append-only `asset_events`, DB-backed dedupe) and was retained by B4b for that reason. **Fix:** add the four labels, or stop grading those types as alert-worthy.

- **Managed-alert retry backoff uses raw `Date.parse` on mixed ISO/SQLite UTC timestamps; replace with the canonical `parseUtcMs` contract** (added 15 July 2026, from PR-B1). `retryDue` and `retryEligible` (`engines/managed-alerts.js:565-580`) compare `Date.parse(row.created_at)` — SQLite UTC text, timezone-implicit — against `Date.parse(now)` — ISO UTC. `Date.parse` reads the first as **local** time and the second as UTC, so the backoff and max-age windows shift by the runtime's offset. **Impact:** none in production — Workers run UTC, which is precisely why it is invisible; it would surface on any non-UTC runtime and in local testing. This is the same defect class PR-B1 fixed in the watermark path, deliberately left out of that PR to keep it narrow (founder decision). **Fix:** route both sides through `parseUtcMs` (`engines/alert-occurrence.js`), which accepts both persisted shapes and fails closed on anything ambiguous. Add a non-UTC test run, as `validate-alert-b1-canonical-cases.js` does — a UTC-only gate cannot catch this class.

- ~~**ALERT FOUNDATION — `findConditionOccurrence` tie-breaks same-second occurrences on a random id, and can suppress a real alert. MUST BE ASSESSED BEFORE PR-B4b**~~ — **FIXED 15 July 2026 (PR-B4-pre, alerts episode).** Assessed as recorded below; the analysis held. Fix option **(a)** shipped: `findConditionOccurrence` now orders `created_at DESC, rowid DESC`. Option (b) stayed rejected for the reason given below. **Why (a) is watermark-safe, proven rather than argued:** a rowid tie-break only ever re-selects among rows whose `created_at` are IDENTICAL, so `observed_at` is bit-for-bit unchanged and every `observationIsAfterWatermark` decision (strict `>`) is invariant; when `created_at` differs the tie-break is never consulted. **Schema facts verified against the real schema, not assumed:** all five source tables are physical rowid tables — no `WITHOUT ROWID`, no views, every PK is `TEXT` so rowid is not aliased, no `AUTOINCREMENT`, and no `VACUUM` anywhere in the repo. Rowid reuse after a purge is real (asserted) but cannot invert order: SQLite assigns `max(rowid)+1` over the rows that REMAIN, so a new append always sorts above every survivor. **No migration was required** — rowid already exists on every source. **Proof:** `scripts/validate-alert-occurrence-ordering.js` (65 assertions, CI-blocking), which mutation-tests itself — it rebuilds the resolver with the old `id DESC` and asserts the defect reproduces, so a green run means the suite can actually catch the regression. Reverting the fix fails it 16 times across **all six** wired domains. **Original entry, for the record:** `findConditionOccurrence` (`engines/alert-occurrence.js`) orders candidates `created_at DESC, id DESC`, but every lifecycle event is stamped by SQLite `datetime('now')` — **second precision**. Two occurrences of the *same* recurrence on the *same* record inside one second therefore tie on `created_at` and fall through to the id, which is random hex (`epe-`/`cle-`/`iee-`/`case_`…). The resolver can return the **older** occurrence, whose `dedupe_key` already exists, so `INSERT OR IGNORE` silences the newer alert as a duplicate. **Fail-silent, not fail-loud.** **Scope: all six wired domains** (`certificates_trust`, `identity_exposure`, `shadow_it_unmanaged_technology`, `brand_protection`, `attack_surface`, `email_protection`) — this predates PR-B3 and was not introduced by it. **Impact today: believed nil, but unproven.** The shipped sequences are far apart in wall-clock (certificate bands are days; Identity/Shadow IT evaluate hourly; B3's recovery→re-entry needs a 7-day window to empty and refill). The realistic reachable case is two evaluations of one record inside one second — e.g. two aggregate reports ingested back-to-back, or a future evaluator that fans out. **Evidence it is real:** PR-B3 hit exactly this class in its own `lastGradedCondition`, because the hosted sweep assesses impact and auto-rolls-back *in the same iteration* — it was fixed there by ordering on `rowid DESC` (insertion order), which is the candidate fix here. **Why deferred:** the resolver is shared, so a change re-risks five already-deployed domains; it needs its own PR, its own mutation-tested suite and its own production proof. **Do not fold it into a feature PR.** **Fix options to weigh:** (a) `ORDER BY created_at DESC, rowid DESC` — minimal, matches the B3 precedent, SQLite/D1-specific; (b) sub-second `created_at` via `strftime('%Y-%m-%d %H:%M:%f','now')` — **rejected on first analysis**: `observationIsAfterWatermark` compares event `created_at` against second-truncated `alert_activation.activated_at`, so added precision would flip same-second events from "at the watermark" to "after it" and could release a backlog. Option (a) is the safer default. **Assess before B4b**, since B4b touches the same alert foundation.

- **Cron verification attempts are labelled `actor_type='anonymous'`** (added 15 July 2026, from the domain-verification incident). `recordVerificationAttempt` (`lib/domain-verification.js`) derives `actor_type` as `user_id ? "customer" : "anonymous"`, and the hourly recheck has no `user_id` — so its `domain_verification_attempted` rows claim an anonymous external caller for what is a scheduled system task. The `domain_verified` audit written beside it in the same tick correctly says `system`, so one tick labels itself two ways. **Impact:** observability only — an operator filtering `actor_type='anonymous'` sees cron work mixed in with unauthenticated 401 probes. **Fix:** thread an explicit `actor_type` through the recorder (do not re-derive it from the absence of a user); cron passes `"system"`, the route passes `"customer"`/`"anonymous"` as today. Not a security or data-integrity issue; no customer impact.

---

## Do NOT re-do — already handled (verified)

Auth: per-IP throttles on signup/login/forgot/resend + MFA (all fail-closed);
single-use 1h reset tokens; **all sessions deleted on password change**;
enumeration defended on login/signup/forgot; constant-time compare; MFA issues no
pre-TOTP session. · SSRF input-gate (`validate-ssrf-domain-guard.js`, reserved-TLD
denylist). · No hardcoded secrets (generated RUA secret is log-redacted). · Tenant
isolation matrix incl. existence-oracle (`validate-tenant-isolation.js`, 57). ·
Purge completeness incl. R2 (`validate-purge-completeness.js`). · Stripe signature
+ lifecycle (`validate-stripe-events.js`). · DMARC XXE (`validate-dmarc-xml-safety.js`).
· Error-contract, log-redaction, maintenance-mode, licenses. · **ToS / Privacy /
Cookie / DPA pages exist** (`TermsPage`/`PrivacyPage`/`CookiePolicyPage`/`DpaPage`)
— the older "legal not live" note is stale; only verify content + linkage. ·
Stuck-scan: scan-engine guards against stuck `running` + ops-health heartbeat
monitors it (verify the owner-notification path).

---

## Suggested sequence
1. Ship the two code fixes (#1 per-account lockout, #2 fail-closed) — small, high-value.
2. Turhan runs the manual pentest pass (#3–#6) on staging + the ops dashboard steps (#7) + capacity check (#8).
3. Open sign-up to a small public cohort; watch the new monitoring; then widen.
P1 items land during/after the first cohort.
