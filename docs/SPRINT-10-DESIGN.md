# Sprint 10 Design — Worker Decomposition Phase 2: Fault Isolation

Status: **APPROVED** (founder, 2026-07-08) — including the RPC-not-Queues
decision, the staged rollout, and decision points §10.1-4 in principle (the
Stage B routing repoint and Stage B secret remain founder actions at stage
time; Stage C cutover proposed 14:10 UTC).
Author: Lead Engineering. Date: 2026-07-08.
Prerequisite: Sprint 9 formally closed (first production cron proof) — Stage A
starts only after that evidence lands.

---

## 1. Scope

**In scope (Phase 2):**
- Split the single deployment into **three Workers**: `cybermeters-api` (the
  existing worker, minus the email entry), `cybermeters-email` (inbound RUA
  ingestion — the Email Routing target), `cybermeters-cron` (thin scheduled
  dispatcher).
- Dissolve the Sprint 9 `index ⇄ email/inbound` import cycle by extracting the
  shared service layer into real `src/lib/` modules with **measured** closures.
- Per-worker health, observability, deploy and rollback.

**Explicitly out of scope (Phase 3+, do not creep):**
- Splitting the scan engine / reports / PDF into their own workers.
- Cloudflare Queues and any at-least-once job pipeline (see §4 — not needed for
  this phase, avoids a Workers-Paid dependency and idempotency complexity).
- Decomposing the 12k-line `fetch()` router inside the API worker.
- Any D1 schema change. **Zero migrations in this sprint.**

## 2. Measured feasibility (why this topology)

Dependency-closure analysis on the current code (tool from Sprint 9):

| unit | closure | lines |
|---|---|---:|
| `email/inbound.js` (already extracted) | 29 decls | ~560 |
| `ingestDmarcReport` chain | 19 decls | 488 |
| `sendLifecycleEmail` chain | 23 decls | 456 |
| audit + notification writers | 5 decls | 153 |
| recipient/auth-header helpers | 3 decls | 83 |
| **combined lib surface for a standalone email worker** | **44 decls** | **~1,023** |

→ A standalone email worker is **~1,600 lines total** (vs 37k today). Small,
parseable, independently deployable. This number is why the design is viable.

The cron task bodies' closure is **~19,350 lines** (reaches the scan engine) —
which is why the cron worker must be a **thin dispatcher**, not a host for the
tasks themselves.

## 3. Service boundaries & ownership

| worker | owns | must never do |
|---|---|---|
| `cybermeters-api` | all HTTP routes, scan engine, scoring, PDF, billing, auth, **cron task bodies** (internal RPC entrypoints) | receive inbound email |
| `cybermeters-email` | Email Routing `email()` handler, RUA parse/ingest, drop audit/notifications | serve public HTTP (health only), send lifecycle email beyond ingest notifications |
| `cybermeters-cron` | the `0 * * * *` trigger; per-task dispatch + timing/telemetry | contain any task body or DB write beyond metrics |

Ownership (solo team) maps to **resource ownership**, not people:
- D1 `cybermeters-db`: shared binding in api + email. cron has **no D1 binding**
  (it only dispatches — this is enforced isolation, not convention).
- R2 `cybermeters-reports`: api only.
- Analytics Engine `cybermeters_metrics`: all three (shared dataset, see §7).
- Email Routing rule on `reports.cybermeters.com`: points to `cybermeters-email`.

### 3.1 Secret ownership (verified against actual `env.*` usage — minimization)

| secret | api | email | cron |
|---|:-:|:-:|:-:|
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | ✓ | — | — |
| `MFA_ENCRYPTION_KEY` | ✓ | — | — |
| `AZURE_CLIENT_SECRET` (Microsoft SSO) | ✓ | — | — |
| `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ZONE_ID` (hosted DMARC) | ✓ | — | — |
| `RESEND_API_KEY` | ✓ | ✓ (drop-notification lifecycle email only) | — |
| **total** | 7 | **1** | **0** |

A compromised or buggy cron worker can leak nothing; the email worker can leak
one revocable key. Today all seven live in one blast radius.

## 4. Communication: Service-Binding RPC, not Queues

**Decision: cron → api via Cloudflare service binding (WorkerEntrypoint RPC).**

- The API worker exposes a `CronTasks extends WorkerEntrypoint` class with one
  method per task (same registry as today). RPC entrypoints are **not publicly
  routable** — no URL, no auth surface, no header-secret scheme to get wrong.
- Service bindings are available on every plan; **Queues requires Workers Paid
  and brings at-least-once/dedup/DLQ semantics we do not need for idempotent
  hourly tasks that already self-heal** (retry-failed-emails, verification
  retry are themselves retry loops). Queues is the right tool later for
  scan-job backpressure (Phase 3), not for a clock.
- email → api: **this edge deliberately does not exist.** The email worker is
  self-sufficient (lib + D1); giving it an api binding would re-couple the two
  planes the split exists to separate. If a future feature needs it, it enters
  the contract below with a version bump.

### 4.1 RPC contract (versioned — workers speak this, never each other's internals)

```ts
// workers/api — the ONLY cross-worker surface. Version bumps on any change.
export class CronTasks extends WorkerEntrypoint {
  // v1. One method, task name as data — adding a task is a registry entry,
  // not a new RPC method (keeps the contract stable).
  async runTask(taskName: CronTaskName, invocation: {
    contract_version: 1,
    scheduled_for: string,   // ISO hour the trigger fired for
    request_id: string,      // dispatcher-generated UUID, logged both sides
  }): Promise<{
    ok: boolean,
    task: CronTaskName,
    duration_ms: number,
    error: string | null,    // customer-safe class, never a raw stack
  }>
}

type CronTaskName =
  | "scheduled_scans" | "scheduled_reports" | "user_scheduled_reports"
  | "hosted_dns_sweep" | "report_retention" | "deletion_purge"
  | "lifecycle_email_retry" | "asset_alert_retry" | "domain_verify_retry";
```

- Unknown `taskName` or `contract_version` → `{ok:false, error:"contract_mismatch"}`
  and an alertable log line — a version-skewed deploy fails loudly, not weirdly.
- **Stage C implementation guidance (CTO review, 2026-07-08):** when the RPC
  contract lands, the task registry graduates from a name→fn map to a
  metadata-carrying structure — one entry per task:

  ```js
  { name: "asset_alert_retry", schedule: "hourly", owner: "billing",
    timeoutMs: 300_000, criticality: "medium",
    idempotency: "at-least-once", healthCheck: true,
    handler: retryFailedAssetAlerts }
  ```

  The point is not tests — it is a SINGLE SOURCE feeding /health/dependencies,
  the scheduler dashboard, cron metrics dimensions, RPC validation and doc
  generation, so they can never disagree about what the scheduler owns. The
  pipeline suite's name-set + all-ok assertions then read their expectations
  from this registry instead of a hand-maintained list (fine at 7 tasks,
  maintenance debt at 12).

  Anti-rot rule: **a metadata field ships together with its first consumer.**
  `name/schedule/handler` have consumers on day one (dispatch + metrics);
  `owner/criticality/healthCheck` enter when the dashboard or
  /health/dependencies actually reads them — declared-but-unread metadata is
  the documentation equivalent of dead code.
- `request_id` appears in both workers' logs + the cron_task metric, so one
  dispatch is traceable end to end.

### 4.2 Idempotency (verified against current code, not designed on hope)

| surface | mechanism | status |
|---|---|---|
| duplicate inbound email (same RUA report delivered twice) | `ingestDmarcReport` dedupes on the report's natural key `(workspace, domain, org_name, external_report_id, date_range)` and writes a `dmarc_report_duplicate` audit event | **already in production** — verified in code; stronger than message-id hashing (the same report can arrive via different messages) |
| cron task double-fire | **no-retry policy** (see 4.3): a failed/timed-out RPC is NOT retried — the next hourly tick is the retry. No retry ⇒ no duplicate execution path at the dispatch layer | design rule |
| double-cron during Stage C cutover | remove-then-add deploy sequence (§6) — at most a missed hour, never a doubled one | staged rollout |
| RPC delivered but response lost (dispatcher sees timeout, task actually ran) | tolerated by task design: every task is a self-healing sweep (idempotent per hour by construction — e.g. report generation checks what already exists; retention/purge are naturally idempotent) | existing property, asserted in the matrix below |

### 4.3 Timeout / retry matrix

| call | timeout | retry | on failure |
|---|---|---|---|
| cron → api `runTask` | 5 min soft per task (`Promise.race`), inside the scheduled handler's 15-min wall budget | **none** — next hour self-heals | `cron_task` metric with error class + `[cron-error]` log (alertable) |
| email → api | — (edge does not exist) | — | — |
| email → D1 (ingest) | platform default | none — sender's SMTP retry (Email Routing returns transient failure) is the retry | drop-with-audit path (already built) |
| api → D1/R2/Stripe/Resend | unchanged from today | unchanged (CF 429 backoff exists) | unchanged |

## 5. Failure matrix

| failure | api | email ingest | cron tasks | customer impact |
|---|---|---|---|---|
| api worker bad deploy | DOWN | **unaffected** | dispatch OK, RPC fails → task metrics show errors | app down (as today), reports still ingest |
| email worker bad deploy | unaffected | DOWN | unaffected | inbound RUA rejected → sender retries per SMTP (Email Routing returns transient failure); ingest gap self-heals on next report |
| cron worker bad deploy | unaffected | unaffected | DOWN | schedules/reports pause ≤ deploy-fix time; hourly cadence self-heals |
| D1 outage | degraded (as today) | degraded | tasks error, recorded | shared dependency — unchanged from today, inherited SLO |
| double-cron (transition bug) | duplicate task runs | — | duplicates | **worst customer-visible risk** — mitigated in §6 sequence |

Net: today ANY bad deploy takes all three planes down. After Phase 2, each
plane fails alone. That is the sprint's entire value.

## 6. Deployment & rollback (coexistence plan)

Staged, each stage shippable and reversible, suites green throughout:

| stage | sequence | rollback trigger (criterion) | rollback action |
|---|---|---|---|
| **A — lib extraction** (no topology change) | move the measured 44-decl service layer into `src/lib/` (dmarc-ingest, lifecycle-email, audit, notifications); dissolves the index ⇄ inbound cycle; single deploy | any suite red; /health or /ready degraded post-deploy; any 5xx delta in the first hour | `npx wrangler rollback` (same as Sprint 9) |
| **B — email worker** | 1) deploy `workers/email-ingest/` **dark** (D1+AE bindings, RUA vars) → 2) verify its /health → 3) founder repoints the Email Routing rule → 4) observe first inbound | /health not 200 before repoint (→ never repoint); after repoint: any `dmarc_inbound_email_dropped` spike or missing expected ingest within 24h | point the routing rule back to `cybermeters-platform` (dashboard, seconds, **zero deploy** — api's handler stays dormant as fallback) |
| **C — cron worker** | at ~xx:10 (proposed 14:10 UTC): 1) deploy api with `CronTasks` entrypoint **and crons removed** → 2) immediately deploy `workers/cron-dispatch/` with the trigger + binding → 3) watch the next hour | next hourly tick produces ≠1 run set (0 after two hours, or any doubled task), or any `contract_mismatch` error | redeploy api with crons restored; remove cron worker's trigger (two commands, no data risk) |
| **D — 48h observation** | per-worker cron_task datapoints, inbound RUA ingest on the two live domains, 5xx delta = 0 | any criterion above regressing | stage-specific action above |

**Stage B status: CUTOVER DONE (2026-07-08 16:34 UTC).** RESEND_API_KEY set
(worker version `a90a59c7`); both `cmrua_…@reports.cybermeters.com` routing
rules repointed to `cybermeters-email`; smoke test proven end to end — Gmail →
new worker (`Email … — Ok`, tail) → D1 `dmarc_inbound_email_dropped` audit with
reason `no_dmarc_attachment`, one second end-to-end. The api worker's email
handler remains as dormant rollback fallback until Stage C. 24h observation
running; the first real RUA report (blackbullbarbers) is expected ~09 Jul
morning and will be the real-data confirmation.

**Stage C entry gate (CTO, 2026-07-08 — change isolation):** Stage C does NOT
start until all three real-production criteria pass, so any anomaly stays
attributable to exactly one architectural change:
1. The first REAL DMARC aggregate report is processed by the new email worker
   end to end (row in `dmarc_aggregate_reports`, endpoint `last_inbound_at`
   updated, visible in the UI).
2. Email-worker error rate over 24-48h ≈ zero (no unexpected exceptions, no
   duplicate rows).
3. Cron tasks keep running normally on the api worker throughout.

**Stage A status: DONE (2026-07-08).** Deployed `324b4a18`, all suites green,
live /health + /ready verified, no rollback criterion triggered. Deviation
from §1's module list, driven by measurement: audit.js + notifications.js
became ONE module (`src/lib/events.js`) — their closures are identical
(mutually referencing writers; splitting would create a lib cycle) — and
`src/lib/util.js` was added for dependency-free leaf helpers. The Sprint 9
index ⇄ inbound cycle is dissolved: nothing under lib/, email/ or cron/
imports index.js.

Max failure exposure at any point: **one missed cron hour** (self-healing) or
**minutes of email-routing gap** (sender SMTP retries). Never a doubled task,
never a lost report, never an api outage caused by the split.

Secrets: `RESEND_API_KEY` (email worker sends ingest notifications via
lifecycle lib) must be `wrangler secret put` into the new worker — founder
action, listed in the runbook. Secret drift risk is in §8.

## 7. Observability

- **One shared AE dataset** (`cybermeters_metrics`) with a `worker` blob added
  by `recordMetric` — one query surface, per-worker filtering. (Chosen over
  per-worker datasets: three dashboards nobody reads is worse than one that
  answers "which worker".)
- Health endpoint matrix:

| endpoint | api | email | cron |
|---|:-:|:-:|:-:|
| `/health` (version + deployment_id) | ✓ | ✓ | ✓ |
| `/ready` (dependency probes) | ✓ D1+R2 | ✓ D1 | ✓ RPC-binding ping (`runTask("noop")`-class check) |
| `/health/dependencies` (per-binding detail: D1, R2, AE, service binding, secret presence booleans — **names only, never values**) | ✓ | — | — |

- `request_id` from the RPC contract appears in both workers' logs and the
  cron_task metric — one dispatch traceable end to end.
- `wrangler tail` per worker; `[cron-error]` stays the alertable string.
- OPERATIONS.md gains a per-worker deploy/rollback/secrets matrix.

## 8. Risk register

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| **CONFIRMED 2026-07-08 (dashboard): Workers Builds deploys `cybermeters-platform` on every push to main.** Config: repo-connected, production branch `main`, deploy command `npx wrangler deploy`, root `/workers/scan-api`, include paths `*` (any change anywhere triggers a build — docs included), **builds for non-production branches ENABLED** (branch pushes upload preview versions) | confirmed | high (unreviewed deploys; breaks Stage C choreography) | **DECISION (founder, 2026-07-08): Path A — disable Workers Builds for the worker; Pages auto-deploy stays.** Release flow becomes: feature branch → PR/CI → merge main → manual `wrangler deploy` → tag → CHANGELOG. If builds are ever re-enabled: narrow include paths to `workers/scan-api/**` and disable non-production-branch builds. Toggle state verified empirically before resuming the release chain |
| double-cron during Stage C | med | high (duplicate customer emails/reports) | §6 sequence: remove-then-add within minutes, off-peak; verify next hour = exactly one run set. **Under auto-deploy this choreography is unsafe — resolve the row above first** |
| Email Routing repoint gap | low | med (bounced reports; senders retry) | dark-deploy + /health first; repoint is instant; rollback instant |
| secret drift across workers | med | med (email notifications silently fail) | runbook checklist + `/ready` asserts binding presence; fail-open sends already logged |
| lib extraction pulls hidden state (module-level caches shared today, split tomorrow) | low | med | closure tool flags module-level `const` state; suites + 48h watch |
| bundle triplication (lib in 3 bundles) | certain | none (KiB-scale) | accepted; measured in success metrics |
| RPC entrypoint compat (compatibility_date / wrangler version) | low | low | spike first in Stage C branch; wrangler ^3 → verify or bump pinned version |
| D1 remains shared | certain | — | **accepted & explicit**: data-plane isolation is NOT a goal of this phase |

## 9. Success metrics (measured at close, honest)

| metric | before (S9) | target (S10) |
|---|---:|---:|
| deploys that touch email ingest | every deploy | email-worker deploys only |
| deploys that touch the clock | every deploy | cron-worker deploys only |
| email worker bundle | 1,382 KiB (shared) | **< 150 KiB** |
| cron worker bundle | 1,382 KiB (shared) | **< 50 KiB** |
| planes down on a bad api deploy | 3/3 | **1/3** |
| suites | all green | all green throughout every stage |

## 10. Founder decision points (approve/answer before code)

1. Approve the three-worker topology + Service-Binding-RPC (no Queues) design.
2. Stage B requires you to repoint the Email Routing rule in the dashboard
   (guided, instant, instantly reversible) — OK?
3. Stage C picks a low-activity hour for the cron cutover — propose 14:10 UTC.
4. `wrangler secret put RESEND_API_KEY` on the email worker at Stage B — OK?
