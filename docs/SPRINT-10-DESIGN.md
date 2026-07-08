# Sprint 10 Design — Worker Decomposition Phase 2: Fault Isolation

Status: **DRAFT — awaiting founder approval. No implementation before approval.**
Author: Lead Engineering. Date: 2026-07-08.
Prerequisite: Sprint 9 formally closed (first production cron proof).

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
- email → api: none needed at runtime (email worker is self-sufficient via
  lib + D1). No binding = no coupling.

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

1. **Stage A — lib extraction (no topology change).** Move the measured 44-decl
   service layer into `src/lib/` (dmarc-ingest.js, lifecycle-email.js,
   audit.js, notifications.js). Dissolves the index ⇄ inbound cycle. Single
   deploy, behaviour-identical, same rollback as Sprint 9 (`wrangler rollback`).
2. **Stage B — email worker.** New `workers/email-ingest/` with its own
   wrangler.toml (D1 + AE bindings, RUA vars, `/health`), importing the same
   `src/lib/` + `src/email/` source. Deploy it **dark** (no traffic). Verify
   /health. Then repoint the Email Routing rule to it (dashboard — founder
   action). The API worker's email handler stays in place, dormant.
   **Rollback = point the routing rule back. Seconds, zero deploy.**
3. **Stage C — cron worker.** New `workers/cron-dispatch/` with the trigger +
   RPC binding. API worker gains the `CronTasks` entrypoint. Sequence to avoid
   double-execution: deploy API (entrypoint added, **crons removed from its
   wrangler.toml**) at minute ~xx:10, immediately deploy cron worker with the
   trigger. Max exposure: one missed hour (safe — every task self-heals);
   never a doubled hour. **Rollback = redeploy API with crons restored, delete
   cron worker's trigger.**
4. **Stage D — 48h observation** on the two live domains (cron_task datapoints
   per worker, inbound RUA ingest, zero 5xx delta), then Sprint 10 closes.

Secrets: `RESEND_API_KEY` (email worker sends ingest notifications via
lifecycle lib) must be `wrangler secret put` into the new worker — founder
action, listed in the runbook. Secret drift risk is in §8.

## 7. Observability

- **One shared AE dataset** (`cybermeters_metrics`) with a `worker` blob added
  by `recordMetric` — one query surface, per-worker filtering. (Chosen over
  per-worker datasets: three dashboards nobody reads is worse than one that
  answers "which worker".)
- Each worker: `/health` (version + deployment_id) and `/ready` where it has
  dependencies (api: D1+R2; email: D1; cron: binding ping).
- `wrangler tail` per worker; `[cron-error]` stays the alertable string.
- OPERATIONS.md gains a per-worker deploy/rollback/secrets matrix.

## 8. Risk register

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| double-cron during Stage C | med | high (duplicate customer emails/reports) | §6 sequence: remove-then-add within minutes, off-peak; verify next hour = exactly one run set |
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
