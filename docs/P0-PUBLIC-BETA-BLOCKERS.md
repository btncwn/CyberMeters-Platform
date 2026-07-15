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

- **Managed-alert retry backoff uses raw `Date.parse` on mixed ISO/SQLite UTC timestamps; replace with the canonical `parseUtcMs` contract** (added 15 July 2026, from PR-B1). `retryDue` and `retryEligible` (`engines/managed-alerts.js:565-580`) compare `Date.parse(row.created_at)` — SQLite UTC text, timezone-implicit — against `Date.parse(now)` — ISO UTC. `Date.parse` reads the first as **local** time and the second as UTC, so the backoff and max-age windows shift by the runtime's offset. **Impact:** none in production — Workers run UTC, which is precisely why it is invisible; it would surface on any non-UTC runtime and in local testing. This is the same defect class PR-B1 fixed in the watermark path, deliberately left out of that PR to keep it narrow (founder decision). **Fix:** route both sides through `parseUtcMs` (`engines/alert-occurrence.js`), which accepts both persisted shapes and fails closed on anything ambiguous. Add a non-UTC test run, as `validate-alert-b1-canonical-cases.js` does — a UTC-only gate cannot catch this class.

- **ALERT FOUNDATION — `findConditionOccurrence` tie-breaks same-second occurrences on a random id, and can suppress a real alert. MUST BE ASSESSED BEFORE PR-B4b** (added 15 July 2026, from PR-B3; founder-deferred out of that PR). `findConditionOccurrence` (`engines/alert-occurrence.js`) orders candidates `created_at DESC, id DESC`, but every lifecycle event is stamped by SQLite `datetime('now')` — **second precision**. Two occurrences of the *same* recurrence on the *same* record inside one second therefore tie on `created_at` and fall through to the id, which is random hex (`epe-`/`cle-`/`iee-`/`case_`…). The resolver can return the **older** occurrence, whose `dedupe_key` already exists, so `INSERT OR IGNORE` silences the newer alert as a duplicate. **Fail-silent, not fail-loud.** **Scope: all six wired domains** (`certificates_trust`, `identity_exposure`, `shadow_it_unmanaged_technology`, `brand_protection`, `attack_surface`, `email_protection`) — this predates PR-B3 and was not introduced by it. **Impact today: believed nil, but unproven.** The shipped sequences are far apart in wall-clock (certificate bands are days; Identity/Shadow IT evaluate hourly; B3's recovery→re-entry needs a 7-day window to empty and refill). The realistic reachable case is two evaluations of one record inside one second — e.g. two aggregate reports ingested back-to-back, or a future evaluator that fans out. **Evidence it is real:** PR-B3 hit exactly this class in its own `lastGradedCondition`, because the hosted sweep assesses impact and auto-rolls-back *in the same iteration* — it was fixed there by ordering on `rowid DESC` (insertion order), which is the candidate fix here. **Why deferred:** the resolver is shared, so a change re-risks five already-deployed domains; it needs its own PR, its own mutation-tested suite and its own production proof. **Do not fold it into a feature PR.** **Fix options to weigh:** (a) `ORDER BY created_at DESC, rowid DESC` — minimal, matches the B3 precedent, SQLite/D1-specific; (b) sub-second `created_at` via `strftime('%Y-%m-%d %H:%M:%f','now')` — **rejected on first analysis**: `observationIsAfterWatermark` compares event `created_at` against second-truncated `alert_activation.activated_at`, so added precision would flip same-second events from "at the watermark" to "after it" and could release a backlog. Option (a) is the safer default. **Assess before B4b**, since B4b touches the same alert foundation.

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
