# WORKSPACE_LIFECYCLE_AUDIT.md

Sprint 10D — Phase 4
Date: 2026-06-23
Auditor: Code inspection (no assumptions)

---

## Scope

Files inspected:
- `workers/scan-api/src/index.js`:
  - `GET /api/workspaces`
  - `POST /api/workspaces`
  - `POST /api/workspaces/:id/delete-request`
  - `DELETE /api/workspaces/:id/domains/:domainId`
  - `requireWorkspaceRole()`, `getAccessibleWorkspaceIds()`, `createWorkspaceTrialSubscription()`
  - `triggerScheduledScan()`

---

## Lifecycle Summary

```
Create:
  POST /api/workspaces
    → INSERT workspaces (id, name, owner_user_id, created_at)
    → INSERT workspace_members (role='owner')
    → createWorkspaceTrialSubscription() — 14-day Professional trial
    → Audit event: workspace_created

Rename:
  No PATCH /api/workspaces/:id endpoint found.

Delete:
  POST /api/workspaces/:id/delete-request
    → INSERT deletion_requests (status='pending')
    → No actual deletion handler found anywhere in codebase

Add domain:
  (handled via domain verification flow)

Remove domain:
  DELETE /api/workspaces/:id/domains/:domainId
    → DELETE FROM workspace_domains WHERE workspace_id=? AND domain_id=?
    → No cascade to scans, assets, scheduled_scans

Member management:
  GET/POST/PATCH/DELETE /api/workspaces/:id/members — implemented
```

---

## Findings

### ISSUE-19 — CRITICAL — Workspace delete-request has no deletion handler

**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/workspaces/:id/delete-request` (line ~28159)
**Root cause:** The delete request endpoint creates a row in `deletion_requests` with `status='pending'`. No cron job, no webhook handler, and no admin API were found anywhere in the Worker that process these pending requests. The workspace row is never deleted.

```js
// Line ~28190 — inserts request but no processor exists
await env.cybermeters_db.prepare(
  `INSERT INTO deletion_requests
     (id, request_type, user_id, workspace_id, requested_by, status, created_at, updated_at)
   VALUES (?, 'workspace', ?, ?, ?, 'pending', ?, ?)`
).bind(requestId, user.id, workspaceId, user.id, now, now).run();
return json({ request_id: requestId, status: "pending", ... }, 202);
```

**Impact for beta:** Workspace deletion is completely non-functional. Users who request deletion receive a "202 Accepted" response and their workspace never goes away. This is a data retention and contractual compliance risk.

**Remediation:** Two options:
1. (Recommended for beta) Add a DELETE endpoint that immediately soft-deletes the workspace (`UPDATE workspaces SET deleted_at = datetime('now') WHERE id = ?`) and disables all member access. Scope all workspace queries to `WHERE deleted_at IS NULL`.
2. (Long-term) Process deletion_requests in the hourly cron: find pending requests, perform the deletion, update status='completed'.

---

### ISSUE-20 — HIGH — No PATCH /api/workspaces/:id — workspace rename is impossible

**File:** `workers/scan-api/src/index.js`
**Root cause:** No `PATCH /api/workspaces/:id` route was found in the entire Worker. Workspaces can be created (POST) and "deleted" (delete-request) but cannot be renamed. There is no `UPDATE workspaces SET name = ? WHERE id = ?` path.

**Impact for beta:** Users who make a typo in their workspace name at creation have no recourse. This is a basic CRUD gap.

**Remediation:** Add `PATCH /api/workspaces/:id` with body `{ name }`. Enforce `requireWorkspaceRole(user, id, "workspace:manage", env)`. Audit log the rename.

---

### ISSUE-21 — HIGH — Domain removal does not cascade to scans, assets, or scheduled scans

**File:** `workers/scan-api/src/index.js`
**Route:** `DELETE /api/workspaces/:id/domains/:domainId` (line ~28016)
**Root cause:** The endpoint only deletes the `workspace_domains` link row. It does not:
- Delete or archive scans for that domain
- Delete or archive workspace_assets for that domain
- Disable scheduled_scans for that domain
- Delete asset_events for that domain

```js
// Line ~28031 — only removes the link, no cascade
`DELETE FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?`
```

**Impact for beta:** After removing a domain, the workspace appears clean in the UI but the underlying D1 tables retain orphaned scans, assets, and events. Scheduled scans for the removed domain continue to run. This will cause phantom asset counts, orphaned scan history, and unexpected billing implications.

**Remediation:** When removing a domain from a workspace:
1. `UPDATE scheduled_scans SET enabled=0 WHERE workspace_id=? AND domain_id=?` (disable, don't delete — preserve history)
2. `UPDATE workspace_assets SET status='inactive' WHERE workspace_id=? AND domain_id=?` (archive, don't delete)
3. Retain scans and reports — they are historical and must not be deleted per Rule 5.

---

### ISSUE-22 — HIGH — triggerScheduledScan uses hardcoded "user_demo" as scan owner

**File:** `workers/scan-api/src/index.js`
**Function:** `triggerScheduledScan()` (line ~14270)
**Root cause:** The function creates scan rows using a hardcoded demo user:

```js
const userId = "user_demo";
await env.cybermeters_db.prepare(
  `INSERT INTO users (id, email, name, plan) VALUES (?, ?, ?, ?)
   ON CONFLICT(id) DO NOTHING`
).bind(userId, "demo@cybermeters.com", "Demo User", "free").run();
```

All scheduled scans in the `domains` table are attributed to `user_demo`, not the workspace owner. This means:
- Scan history shows `user_demo` as the creator
- `getEffectivePlan("user_demo", env)` always returns `free`
- Plan limits during scheduled scan creation use the demo user's plan, not the workspace owner's
- Audit events for scheduled scans show `user_demo` as the actor

**Impact for beta:** Scheduled scans for paying customers run under the free plan context. Feature gates that check the plan during scan engine execution will use the demo user's plan.

**Remediation:** Resolve the workspace owner via `SELECT owner_user_id FROM workspaces WHERE id = ?` and use that `userId` for the domain row and audit events. Fall back to `user_demo` only if owner resolution fails.

---

### ISSUE-23 — MEDIUM — Legacy workspace RBAC fallback creates silent permission gap

**File:** `workers/scan-api/src/index.js`
**Function:** `requireWorkspaceRole()` (line ~16379)
**Root cause:** Workspaces created before the RBAC sprint have no rows in `workspace_members`. The fallback logic:

```js
// If no members exist, allow only the workspace owner
if ((ws?.member_count ?? 0) === 0 && ws?.owner_user_id && ws.owner_user_id === user.id) {
  return { role: "owner" };
}
return null;  // all other users blocked
```

This is correct in isolation, but creates a gap: if `owner_user_id` is NULL (possible if a workspace was created by an unauthenticated path or a migration), the legacy workspace becomes inaccessible to everyone, including the intended owner. There is no repair path in the API.

**Remediation:** Add a migration that backfills `workspace_members` rows for all workspaces where `owner_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM workspace_members WHERE workspace_id=w.id)`.

---

### ISSUE-24 — LOW — Workspace creation entitlement check is by user, not per-subscription

**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/workspaces` (line ~22963)
**Root cause:** The workspace limit check uses `getEntitlementUsage(creator, env)` which counts workspaces owned by the user across all subscriptions. The `multi_workspace` plan feature is correctly gated. However, the check counts `SELECT id FROM workspaces WHERE owner_user_id = ?` — this includes soft-deleted workspaces if deleted_at is not implemented (see ISSUE-19). Once deletion is implemented, the count must exclude deleted workspaces.

**Remediation:** When soft-delete is added, update workspace count query to `WHERE owner_user_id = ? AND deleted_at IS NULL`.

---

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 19 | CRITICAL | Workspace delete-request has no deletion handler — deletion is a no-op |
| 20 | HIGH | No PATCH /api/workspaces/:id — workspace rename impossible |
| 21 | HIGH | Domain removal does not cascade — orphaned scans/assets/schedules persist |
| 22 | HIGH | triggerScheduledScan uses hardcoded user_demo — plan context wrong for paying users |
| 23 | MEDIUM | Legacy RBAC fallback: NULL owner_user_id → workspace permanently inaccessible |
| 24 | LOW | Workspace count for entitlement must exclude deleted workspaces (once deletion is added) |
