# Monitoring & Alerting — CyberMeters

How we know the platform is healthy, and what fires when it isn't. Three layers,
each catching a different failure class. Pairs with
`docs/INCIDENT-RESPONSE-PLAN.md` (what to do once an alert fires) and
`docs/BACKUP-RESTORE-DRILL.md`.

## Layer 1 — Liveness & readiness probes (built-in)

| Endpoint | Answers | Use |
|---|---|---|
| `GET /health` | Is the worker process up? | Fast liveness; returns version + deployment_id |
| `GET /ready` | Are D1 **and** R2 reachable? | Readiness — `200 ready` / `503 degraded` with per-dependency `checks` |

Point an external uptime monitor at **`/ready`** (not `/health`) so "process up
but database down" is caught. `/ready` is fail-open per check and never mutates.

> **Turhan (setup):** add an uptime monitor (status-page provider, e.g.
> Instatus/BetterStack) hitting `https://<api-host>/ready` every 1–5 min, alerting
> on non-200 or the `degraded` status.

## Layer 2 — Real-time error-rate alerting (Cloudflare, needs dashboard)

The worker already emits the signals; the alerting policy is a dashboard config.

- **`http_5xx` metric** → written to the `METRICS` Analytics Engine dataset on
  every 5xx (`recordMetric(env, "http_5xx", …)`), tagged with the failing scope.
- **`[request-error]` logs** → structured, secret-redacted (`redactedJson`), one
  per server error with a `request_id`.
- **`[cron-error]` / `cron_task` metric** → per scheduled-task failures.

> **Turhan (setup, Cloudflare dashboard):**
> 1. **Workers → Notifications:** alert on error rate / CPU / invocation failures
>    for `cybermeters-platform`.
> 2. **Logpush (optional):** ship Worker logs to a sink and alert on a spike of
>    `[request-error]` / `[cron-error]` lines.
> 3. Route alerts to the same inbox as `ALERT_EMAIL_TO`.

## Layer 3 — Daily ops-health heartbeat (built-in, self-alerting)

Real-time metrics miss failures that **accumulate silently** — a backlog of
undelivered emails, scans stuck mid-run, deletion purges that never completed.
A daily cron self-check (`opsHealthHeartbeat`, 08:00 UTC) runs read-only signal
queries and **emails ops only when a threshold is breached** — a healthy system
stays silent (at most one alert per day, no noise).

| Signal | Breach threshold | Why it matters |
|---|---|---|
| Scans stuck in `running` (>15 min) | ≥ 3 | Scan engine dying mid-run (CPU/subrequest limits) |
| Undelivered lifecycle emails (past retry) | ≥ 10 | Email delivery (Resend) degraded — customers miss verify/billing mail |
| Undelivered asset-change alerts | ≥ 10 | Alert delivery degraded |
| Deletion requests overdue for purge (>35d) | ≥ 1 | Retention/compliance failure — data not purged on time |

- Thresholds live in `OPS_THRESHOLDS` (`workers/scan-api/src/lib/ops-health.js`) —
  tune there as real traffic sets a baseline.
- If **every** query is skipped, the database is treated as unreachable and the
  alert says so explicitly.
- Alert email goes to `ALERT_EMAIL_TO` from `ALERT_EMAIL_FROM` (already
  configured in `wrangler.toml`). Also logged as `[ops-health]`.
- A per-run `ops_health` metric records healthy/unhealthy for trend visibility.
- Guarded by CI: `scripts/validate-ops-health.js` (29 assertions — real-schema
  query validity + threshold boundaries + DB-down detection).

### Responding to an ops-health alert
1. Read the breached signals in the email.
2. **Stuck scans** → check Worker logs for CPU/subrequest kills; the scan-detail
   and list endpoints self-reconcile from R2, so confirm whether it's display or
   real. 3. **Email/alert backlog** → check Resend status + `RESEND_API_KEY`; the
   hourly retry crons drain the backlog once delivery recovers. 4. **Overdue
   purges** → inspect `deletion_requests` stuck in `pending`/`purging`; check the
   `deletion_purge` cron logs. Escalate per `INCIDENT-RESPONSE-PLAN.md`.

## Layer 4 — Internal observability & external deadman (F-027, built-in)

Real-time metrics and the daily heartbeat still leave one gap: a failure that
produces **no signal at all** — a stopped cron, an alert email swallowed by a
silent `.catch`, a scan dead-lettered with nobody watching. F-027 turns those
absences into **durable, externally observable facts**.

- **Append-only `operational_events` ledger** (migration `108`): customer-safe
  records — `event_type`, a safe `correlation_id`, `status`, `attempts` — written
  only by ops paths. No raw body/error prose; tenant-isolated; idempotent on
  `(event_type, correlation_id)`. Single boundary:
  `workers/scan-api/src/lib/operational-events.js` (fails closed on any write
  error). See the module header for the full contract.
- **Scan DLQ observer** (`workers/scan-api/src/queues/scan-dlq-observer.js`): the
  scan-dispatch dead-letter queue now has a distinct consumer, dispatched by
  queue identity. It **persists before it acks** and **never runs the scan
  engine** on a dead-letter; a failed persist redelivers.
- **Cron liveness**: `runScheduled` writes one idempotent `cron_tick` per hour.
- **Alert-delivery honesty**: `sendAlertEmail` returning `{sent:false}` (or
  throwing) becomes a durable `alert_delivery_failed` event via
  `recordAlertDeliveryOutcome` — **replacing** the old silent `.catch(() => {})`.
  A refusal and a transport throw are recorded as distinct `status` reasons.
- **/ready extension**: unchanged HTTP contract (200 iff D1 and R2 reachable),
  plus an additive non-sensitive `operational` block (`cron_fresh`,
  `backup_fresh`, `recent_dlq`, `recent_dlq_events`, `recent_dlq_readable`,
  `stale_queued_scan`). Every freshness check fails closed — an unreadable signal
  reports the unhealthy value. The recent-DLQ read distinguishes a proven-empty
  window (`recent_dlq_events: 0`, `recent_dlq_readable: true`) from an unreadable
  one (`recent_dlq_events: null`, `recent_dlq_readable: false`); an unreadable
  window is operationally **unhealthy**, never a fabricated zero.
- **External deadman** (`.github/workflows/ops-deadman.yml`): an hourly
  GitHub-scheduled probe of `/ready` that requires **both** a 200 **and** valid
  JSON with true operational fields. A 200 with garbled JSON or stale booleans is
  **not healthy** (fail closed). The workflow checks out the repo and computes the
  verdict by invoking the SAME strict `evaluateDeadman` (`scripts/ops-deadman-verdict.mjs`),
  so the shipped decision IS the unit-tested one — it does not re-implement the
  check in shell/jq (jq's `//` collapses a boolean `false` to a default and `jq -r`
  renders the string `"false"` like the boolean, which would reject the correct
  healthy payload and accept string impostors). Opens/updates one generic durable
  issue on failure, closes it on recovery. No customer data enters GitHub.

> **Turhan (setup):** set the `OPS_READY_URL` GitHub Actions secret to
> `https://<api-host>/ready` so the deadman can probe it.

Guarded by CI: `scripts/validate-f027-internal-observability.js` and its
`-mutations.js` twin (seven false-healthy guards).

## Coverage summary

| Failure class | Caught by |
|---|---|
| Worker down / dependency down | Layer 1 (`/ready` + uptime monitor) |
| Request error spike (5xx) | Layer 2 (Cloudflare notifications on `http_5xx`) |
| Silent backlog / stuck state | Layer 3 (daily heartbeat, self-alerting) |
| No-signal failure (stopped cron, swallowed alert, unseen DLQ) | Layer 4 (operational_events + /ready booleans + external deadman) |

Layers 1, 3 and 4 ship in the worker today. Layer 2's signals ship today; the
**notification policy is the one outstanding Turhan/dashboard task.**
