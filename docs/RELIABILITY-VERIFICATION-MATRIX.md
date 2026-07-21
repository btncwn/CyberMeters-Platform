# Reliability & Debugging Hardening — Delta-Scoped Verification

Status: **CODE-LAYER DELTA CLOSED (21 July 2026); runtime exercises scoped to RC.** Gate 9 of the pre-public-beta sequence. Delta-scoped per the founder-approved re-sequencing (#224): proven artifacts (incident runbook, backup drill, monitoring heartbeat, hardening v2) are NOT re-done — only the genuine remaining reliability deltas are audited/closed here.

## What this is
A systematic pass over the reliability dimensions in CLAUDE.md's Debugging & Reliability list, each marked **PROVEN** (with the artifact/evidence), **DELTA-CLOSED** (audited today), or **RUNTIME-GAP** (needs a live exercise — scoped to RC, not code-fixable). Honest bar: a dimension not exercised is **RUNTIME-GAP**, never silently "done".

## Already proven — NOT re-done (delta-scoping)
| Dimension | Evidence |
|-----------|----------|
| Incident response | `docs/INCIDENT-RESPONSE-PLAN.md` |
| Backup / restore | `docs/BACKUP-RESTORE-DRILL.md` (drill proven) |
| Production observability | `docs/MONITORING.md` + `ops_health_heartbeat` cron |
| Security hardening v2 | #191 — SSRF per-hop guard, Stripe CAS idempotency |
| Release / rollback discipline | `docs/07-RELEASE-CHECKLIST.md`; every deploy records live+rollback Worker IDs in CHANGELOG |

## Reliability delta — audited 21 July 2026
| # | Dimension | Status | Evidence |
|---|-----------|--------|----------|
| R1 | Cron failure isolation | **PROVEN** | `cron/scheduled.js`: `runCronTask` wraps every task in try/catch + duration/outcome telemetry + `[cron-error]` log; `runBoundedPool` isolates per item ("one bad item, the pool continues"); each cron on its own `ctx.waitUntil` — one failing never blocks the others |
| R2 | Retry bounding (no infinite retry) | **PROVEN** | `alert-outcomes.js`: provider outcomes classified terminal-vs-retryable; **unknown outcome → permanent (terminal), fail-closed** ("a wrong stop is safer than infinite retry"); 4xx → permanent_rejection → terminal; `brand-cases.js` bounded `attempt < maxRetries` |
| R3 | Subrequest-budget / bounded execution | **PROVEN** | `isSubrequestBudgetError`; scan engine marks budget-starved modules `incomplete` (degrades, never crashes); subrequest-heavy alert send deferred to a clean full-budget invocation |
| R4 | R2 failure / missing object | **PROVEN** | Read paths `if (!obj) return null` (historical-scan, report-branding, ce-readiness); purge deletes `.catch(() => {})` non-fatal |
| R5 | N+1 / unbounded queries | **PROVEN** | Past unbounded notification scan fixed + LIMIT-bounded (`alerts.js`); batch reads use `IN (?…)` placeholder lists (verified in the SQLi audit); 1013 prepared statements |
| R6 | D1 hot-path indexing | **PROVEN** | 27 hot-column indexes; live `EXPLAIN QUERY PLAN` on the case-queue read = `SEARCH managed_cases USING INDEX idx_managed_cases_queue (workspace_id=? AND status=?)` — indexed, not full-table SCAN |
| R7 | Idempotency | **PROVEN** | Stripe CAS + `stripe_processed_events` (#191); webhook replay proven idempotent (#243 D3); scan build via the 081 atomic claim; `current_period_end` monotonic (never rewound by a stale event) |
| R8 | Error-path sanitisation | **PROVEN** | `customerSafeFailure` logs internally, returns only a generic message; no raw error/stack/D1/SQL in responses (security matrix A5) |
| R9 | Race conditions / TOCTOU | **PROVEN** | Case transition writes `WHERE …AND status=?` (optimistic concurrency); first-ever-alert watermark race fixed (#222); ownership persists atomically with the transition that requires it |
| R10 | Load / CPU / memory under volume | **RUNTIME-GAP** | Needs load injection against a founder test env — scoped to RC |
| R11 | Failure injection (R2/D1/Stripe chaos) | **RUNTIME-GAP** | Needs a chaos exercise — scoped to RC |
| R12 | Live rollback drill | **RUNTIME-GAP** | Mechanism proven (rollback IDs recorded every deploy; `wrangler deployments list` shows the prior version deployable) but no live roll-back-and-verify drill run — scoped to RC |
| R13 | D1 latency profiling under real volume | **RUNTIME-GAP** | Indexing verified statically (R6); latency-at-volume needs data volume — scoped to RC |

## Verdict
The **code-layer / architectural reliability is verified strong and evidence-backed** — cron isolation, bounded retry (fail-closed), subrequest-budget degradation, R2/error handling, idempotency, TOCTOU guards, and hot-path indexing are all PROVEN. The reliability delta that remains (R10–R13) is genuinely **runtime** — load, chaos, and a rollback drill — and is small, well-defined, and low-risk given the foundation. It is scoped to the RC phase with the founder test environment; it is not code-fixable today and is **not** claimed done.

This closes the code-audit portion of gate 9. The runtime exercises fold into RC alongside the founder-controlled acceptance testing.

Related: [[security-hardening-v2-closure-shipped]], [[pre-beta-execution-resequencing]]. Security counterpart: `docs/SECURITY-VERIFICATION-MATRIX.md`.
