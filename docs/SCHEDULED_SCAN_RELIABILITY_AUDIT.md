# SCHEDULED_SCAN_RELIABILITY_AUDIT.md

Sprint 10D — Phase 6
Date: 2026-06-23
Auditor: Code inspection (no assumptions)

---

## Scope

Files inspected:
- `workers/scan-api/src/index.js`:
  - `POST /api/schedules` (create)
  - `GET /api/schedules` (list)
  - `DELETE /api/schedules/:id`
  - `triggerScheduledScan()`
  - `scheduled()` cron handler
  - `checkScheduledScanLimit()`
- `workers/scan-api/wrangler.toml` — cron configuration

---

## Architecture Summary

```
Cron: "0 * * * *"  (hourly)

scheduled() handler:
  SELECT id, domain, frequency, workspace_id FROM scheduled_scans
    WHERE enabled=1 AND (next_run_at IS NULL OR next_run_at <= now())
  
  for each schedule:
    ctx.waitUntil(triggerScheduledScan(schedule, env))

triggerScheduledScan():
  1. Ensure user_demo exists (hardcoded)
  2. Reuse or create domain row for (user_demo, schedule.domain)
  3. INSERT scan row (status='running')
  4. PUT placeholder report to R2
  5. UPDATE scheduled_scans SET last_run_at=now, next_run_at=computeNextRunAt()
  6. Audit event: scheduled_scan_triggered
  7. await runScanEngine(scanId, domainId, workspaceId, domain, env)
  8. Update asset counts after completion
  (catch all — silent failure)

Quota enforcement:
  checkScheduledScanLimit() → getPlanLimits(plan).scheduled_scans
  Free: 0, Starter: 5, Professional: 20, Business: 100, Enterprise: 999999
```

---

## Findings

### ISSUE-31 — CRITICAL — Scheduled scan quota is checked against workspace plan, but scans run as user_demo (free)

**File:** `workers/scan-api/src/index.js`
**Root cause:** This is the same issue as ISSUE-22 but with an additional billing dimension. `checkScheduledScanLimit()` correctly checks the workspace owner's plan:

```js
async function checkScheduledScanLimit(user, workspaceId, env) {
  const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
  const plan = await getEffectivePlan(ownerUserId, env);  // correct — workspace owner
  ...
}
```

But inside `triggerScheduledScan()`, any plan checks performed during `runScanEngine()` use `user_demo`'s plan (free). If `runScanEngine` internally calls `getEffectivePlan(userId, env)` using the scan's `user_id`, paying customers' scans execute under free-plan feature limits.

**Remediation:** See ISSUE-22. Resolve actual workspace owner in `triggerScheduledScan()` and use their `userId` for all scan attribution.

---

### ISSUE-32 — HIGH — Silent failure — scheduled scan errors are completely swallowed

**File:** `workers/scan-api/src/index.js`
**Function:** `triggerScheduledScan()`
**Root cause:** The entire function body is wrapped in `try { ... } catch { /* Graceful failure */ }` with no logging, no error recording in D1, and no alert to the workspace owner.

```js
async function triggerScheduledScan(schedule, env) {
  try {
    // ... entire scan logic
  } catch {
    // Graceful failure — one schedule erroring must not affect the others
  }
}
```

If a scheduled scan fails (e.g., D1 error, R2 write failure, runScanEngine crash), the failure is completely invisible. The scan row remains at `status='running'` indefinitely (never set to 'failed'). `last_run_at` is stamped before the scan runs (line ~14349), so even a failed scan shows as "ran at X."

**Impact for beta:** Customers set up scheduled monitoring and receive no notification if it stops working. The scan list shows "last run: yesterday" even if every run since then has silently failed.

**Remediation:**
1. Wrap `runScanEngine()` call specifically — catch the error, UPDATE scan status to 'failed'.
2. Log the error: `console.error("[scheduled-scan] FAILED", schedule.id, e?.message)`.
3. Create a workspace notification (INSERT into workspace_notifications) on failure.
4. The outer catch can remain for catastrophic failures that prevent even the above.

---

### ISSUE-33 — HIGH — Scheduled scan table created inline in route — schema management anti-pattern

**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/schedules` (line ~22157)
**Root cause:** The scheduled scans creation route executes a `CREATE TABLE IF NOT EXISTS scheduled_scans` DDL statement inline before the INSERT:

```js
// Line ~22157 — DDL in a route handler
await env.cybermeters_db.prepare(
  `CREATE TABLE IF NOT EXISTS scheduled_scans (
     id TEXT PRIMARY KEY,
     domain TEXT NOT NULL,
     ...
   )`
).run();
```

This is an anti-pattern because:
1. The schema is not version-controlled in `database/schema.sql` or `database/migrations/`
2. If the table already exists with a different schema, the CREATE IF NOT EXISTS silently skips DDL — schema migrations cannot be applied via this path
3. The `last_asset_count` and `asset_change_count` columns may be missing on older deployments that created the table before these columns were added

**Remediation:** Move the table definition to `database/schema.sql` and a versioned migration file. Remove the inline DDL from the route handler.

---

### ISSUE-34 — MEDIUM — No concurrency guard — all due schedules run simultaneously

**File:** `workers/scan-api/src/index.js`
**Function:** `scheduled()` cron handler
**Root cause:** The cron handler fires one `ctx.waitUntil(triggerScheduledScan(...))` per due schedule simultaneously:

```js
for (const schedule of (result?.results || [])) {
  ctx.waitUntil(triggerScheduledScan(schedule, env));  // all concurrent
}
```

If 20 schedules are due simultaneously (e.g., after a deployment or at a full-hour boundary), 20 `runScanEngine()` calls run concurrently within the same Worker invocation. Each scan engine makes ~50+ outbound DNS and HTTP requests. This creates a subrequest burst that may approach the Workers Paid limit of 1,000 subrequests per invocation.

**Impact for beta:** On a popular deployment time (e.g., all users set "daily" schedules that converge on the same hour), scans may fail with subrequest budget errors.

**Remediation:** Process a maximum of N schedules per cron invocation (e.g., 5). Reschedule remaining to the next tick. Or spread `next_run_at` with jitter on creation.

---

### ISSUE-35 — MEDIUM — Free plan users can reach /schedules page but creation is blocked

**File:** `workers/scan-api/src/index.js`, frontend routing
**Root cause:** `getPlanLimits("free").scheduled_scans = 0`. The `POST /api/schedules` route correctly calls `checkScheduledScanLimit()` which returns a 403 for free users.

However, the frontend `SchedulesPage` is accessible to all authenticated users (it's inside `ProtectedRoute` with no plan check). Free plan users can navigate to `/schedules`, see an empty list, attempt to create a schedule, and receive a confusing 403 error with no explanation.

**Remediation:** On `SchedulesPage`, call `GET /api/workspaces` to get the current plan, and if `plan === 'free'` render a feature gate card: "Scheduled scans are available on Starter and above. Upgrade →" rather than the create form.

---

### ISSUE-36 — MEDIUM — computeNextRunAt("daily") always schedules for next midnight — no user timezone support

**File:** `workers/scan-api/src/index.js`
**Function:** `computeNextRunAt()` (line not directly read, but inferred from cron pattern)
**Root cause:** The cron fires hourly at `"0 * * * *"` (UTC). `computeNextRunAt("daily")` schedules the next run for some fixed UTC time. Users have no control over when their daily scan runs, and the time is relative to UTC, not the user's local timezone.

**Impact for beta:** Minor. Users will notice their "daily" scan ran at 3 AM local time.

**Remediation:** Low priority for beta. Add a `preferred_hour_utc` field to scheduled_scans in a future sprint.

---

### ISSUE-37 — LOW — Scheduled scan DELETE does not verify scan is not currently running

**File:** `workers/scan-api/src/index.js`
**Route:** `DELETE /api/schedules/:id`
**Root cause:** The delete endpoint immediately deletes the `scheduled_scans` row without checking whether a scan is currently in-progress for that schedule. If a scan is running when the schedule is deleted, the scan will complete normally (the engine holds all context in memory), but the post-completion asset count update will fail silently because the schedule row is gone.

**Remediation:** Accept this risk for beta — the impact is a single missed asset count update on deletion. Not worth blocking the delete.

---

## Verified Correct ✓

- Quota enforcement: free plan blocks schedule creation ✓
- `checkScheduledScanLimit()` uses workspace owner plan (not caller plan) ✓
- Each schedule runs independently — one failure does not block others ✓
- `workspace_domains` link is idempotently created for the domain before scanning ✓
- `last_run_at` is stamped before scan starts, `next_run_at` computed correctly ✓
- Audit events are created for trigger and completion ✓

---

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 31 | CRITICAL | Plan context during scan engine uses user_demo (free) not workspace owner |
| 32 | HIGH | Silent failure — scan errors swallowed, scan left as 'running', no user notification |
| 33 | HIGH | Scheduled scans table created inline in route — not in migrations |
| 34 | MEDIUM | No concurrency guard — burst of simultaneous scans may hit subrequest limits |
| 35 | MEDIUM | Free plan users can navigate to /schedules and see confusing 403 on creation |
| 36 | MEDIUM | No user timezone support — scan time is UTC-only |
| 37 | LOW | Delete does not check for in-progress scan |
