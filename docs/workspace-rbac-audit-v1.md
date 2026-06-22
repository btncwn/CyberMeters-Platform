# CyberMeters Workspace RBAC Audit v1

**Sprint 10B — Workspace Governance**
**Date:** June 2026
**Status:** Audit complete — implementation to follow

---

## Overview

This audit covers the full workspace RBAC stack: database schema, backend helper functions, per-route enforcement, audit logging, and frontend role-gated UI. The goal is to confirm what is safe for multi-user beta workspaces and identify any remaining gaps.

---

## Schema

### `workspace_members` (migration 015)

```sql
CREATE TABLE IF NOT EXISTS workspace_members (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'viewer',  -- owner | admin | analyst | viewer
    invited_by   TEXT,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (workspace_id, user_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (user_id)      REFERENCES users(id)
);
```

Indexes: `idx_wm_user_id`, `idx_wm_workspace_id`, `idx_wm_workspace_role`. Correct.

### `workspace_invitations` (migration 020)

```sql
CREATE TABLE IF NOT EXISTS workspace_invitations (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    email        TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'viewer',
    token_hash   TEXT NOT NULL UNIQUE,   -- raw token never stored
    invited_by   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    expires_at   TEXT NOT NULL,
    accepted_at  TEXT,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    ...
);
```

7-day expiry enforced at application level. Status values: `pending`, `accepted`, `cancelled`, `expired`.

---

## Role Model

| Role    | Rank | Description |
|---------|------|-------------|
| viewer  | 0    | Read-only: reports, scans, assets, findings |
| analyst | 1    | viewer + trigger scans |
| admin   | 2    | analyst + manage domains, generate reports, invite viewer/analyst |
| owner   | 3    | admin + manage all members, delete workspace, invite admins |

---

## Permission Matrix (PERMISSION_MIN_ROLE)

| Permission              | Min Role | Scope (API token) |
|-------------------------|----------|-------------------|
| workspace:read          | viewer   | read              |
| member:read             | viewer   | read              |
| notification:mark_read  | viewer   | read              |
| audit:read              | admin    | read              |
| scan:create             | analyst  | write             |
| domain:add              | admin    | write             |
| domain:remove           | admin    | write             |
| domain:import           | admin    | write             |
| domain:verify           | admin    | write             |
| report:generate         | admin    | write             |
| report:delete           | admin    | write             |
| schedule:manage         | admin    | write             |
| workspace:invite        | admin    | admin             |
| workspace:manage_members| owner    | admin             |
| workspace:delete        | owner    | admin             |
| workspace:transfer      | owner    | admin             |

---

## Backend Helpers

### `requireWorkspaceAccess(user, workspaceId, env)`
- Validates membership row in `workspace_members`.
- API token workspace boundary: rejects if `token_workspace_id !== workspaceId`.
- Legacy fallback: workspaces with no member rows allow only the `owner_user_id`.
- Returns `{ role }` on success, `null` on failure.

### `requireWorkspaceRole(user, workspaceId, permission, env)`
- Calls `requireWorkspaceAccess`, then checks ROLE_RANK and PERMISSION_SCOPE.
- Session callers bypass scope check; token callers must meet required scope.
- Returns membership object or `null`.

### `requireDomainRole(user, domainId, permission, env)`
- Looks up `workspace_domains` to find all workspace memberships for a domain.
- Delegates to `requireWorkspaceRole` for each; grants if any match.

### `getAccessibleWorkspaceIds(user, env)`
- Returns all workspace IDs the user owns or is a member of.
- Token-bound sessions return only the token's workspace.

---

## Backend Route Enforcement — Current State

| Route | Method | Permission enforced | Status |
|-------|--------|---------------------|--------|
| /api/workspaces | GET | auth | ✓ |
| /api/workspaces | POST | auth + plan limit | ✓ |
| /api/workspaces/:id | GET | workspace:read | ✓ |
| /api/workspaces/:id/domains | GET | workspace:read | ✓ |
| /api/workspaces/:id/domains | POST | domain:add | ✓ |
| /api/workspaces/:id/domains/:id | DELETE | domain:remove | ✓ |
| /api/domains/:id/generate-verification | POST | domain:verify | ✓ |
| /api/domains/:id/verify | POST | domain:verify | ✓ |
| /api/domains/:id/verify-check | GET | domain:verify | ✓ |
| /api/workspaces/:id/domains/import | POST | domain:import | ✓ |
| /api/scans (workspace-scoped) | POST | scan:create | ✓ |
| /api/scheduled-scans (workspace) | POST | scan:create | ✓ |
| /api/workspaces/:id/reports/generate | POST | report:generate | ✓ |
| /api/workspaces/:id/reports/:id | DELETE | report:delete | ✓ |
| /api/workspaces/:id/delete-request | POST | workspace:delete | ✓ |
| /api/workspaces/:id/invitations | GET | workspace:invite (admin+) | ✓ |
| /api/workspaces/:id/invitations | POST | workspace:invite (admin+) | **⚠ gap** |
| /api/workspaces/:id/invitations/:id | DELETE | workspace:invite (admin+) | ✓ |
| /api/workspaces/:id/members | GET | member:read (viewer+) | ✓ |
| /api/workspaces/:id/members | POST | workspace:manage_members (owner) | ✓ |
| /api/workspaces/:id/members/:id | DELETE | workspace:manage_members (owner) | **⚠ gap** |
| /api/workspaces/:id/members/:id | PATCH | workspace:manage_members (owner) | **⚠ gap** |

All other workspace-scoped routes (assets, posture, vendors, reports, activity, audit, notifications, scorecard, identity, supply-chain, usage, summary, health) enforce `workspace:read` or stronger. ✓

---

## Audit Events — Current State

| Event | Emitted | Where |
|-------|---------|-------|
| workspace_created | ✓ | POST /api/workspaces |
| workspace_bootstrapped | ✓ | POST /api/account/bootstrap |
| workspace_deletion_requested | ✓ | POST /api/workspaces/:id/delete-request |
| workspace_member_added | ✓ | POST /api/workspaces/:id/members |
| workspace_member_removed | ✓ | DELETE /api/workspaces/:id/members/:id |
| workspace_member_role_changed | ✓ | POST /api/workspaces/:id/members (upsert) |
| workspace_role_changed | ✓ | PATCH /api/workspaces/:id/members/:id |
| workspace_invitation_created | ✓ | POST /api/workspaces/:id/invitations |
| workspace_invitation_cancelled | ✓ | DELETE /api/workspaces/:id/invitations/:id |
| domain_added | ✓ | POST /api/workspaces/:id/domains |
| domain_removed | ✓ | DELETE /api/workspaces/:id/domains/:id |
| domain_verified | ✓ | POST /api/domains/:id/verify |
| scan_started | ✓ | POST /api/scans |
| scheduled_scan_created | ✓ | POST /api/scheduled-scans |

All required governance events are already emitted. ✓

---

## Frontend — Current State

### WorkspaceMembersPage (`/ws/members`)
- Member list: name, email, role badge. ✓
- Owner: role change dropdown + remove button per non-owner member. ✓
- Admin+: invite form + pending invitations section. ✓
- Analyst/viewer: read-only notice. ✓
- **Gap**: invite form shows `Admin` option to admins — admin should only invite viewer/analyst.

### WorkspaceMembersPanel (compact sidebar component)
- Member list with role badges, remove button for owner. ✓
- Invite form visible to admin+ (canInvite). ✓

### api.js
- `getWorkspaceMembers` ✓
- `addWorkspaceMember` ✓
- `removeWorkspaceMember` ✓
- `updateMemberRole` ✓
- `getWorkspaceInvitations` ✓
- `createWorkspaceInvitation` ✓
- `cancelWorkspaceInvitation` ✓

---

## Gaps — Implementation Required

### Gap 1 — Admin invite ceiling (CRITICAL)
**Where:** `POST /api/workspaces/:id/invitations` (line 25132 in Worker)

**Problem:** `VALID_INVITE_ROLES = new Set(["viewer", "analyst", "admin"])` applies regardless of inviter's role. An admin can invite another admin, which violates the principle that admins cannot grant their own privilege level.

**Fix (backend):** After resolving `access`, if `access.role === "admin"` and `role === "admin"`, return 403. Admins can invite viewer or analyst only. Owners can invite viewer, analyst, or admin.

**Fix (frontend):** In `InviteForm` and `WorkspaceMembersPanel`, hide the `Admin` option when `callerRole !== "owner"`.

### Gap 2 — Admin cannot remove or reassign analyst/viewer members
**Where:** `DELETE /api/workspaces/:id/members/:id` (line 25404) and `PATCH /api/workspaces/:id/members/:id` (line 25458)

**Problem:** Both routes require `workspace:manage_members` (= owner minimum). Spec says admin can remove analysts/viewers and change their roles. Currently only owners can do this.

**Fix (backend):**
- Downgrade gate from `workspace:manage_members` to `workspace:invite` (admin+).
- Add ceiling check: if `access.role === "admin"`, target row must be `analyst` or `viewer`. Admin cannot remove or reassign owners or other admins.
- For PATCH: if `access.role === "admin"`, restrict new role to `viewer` or `analyst` only (cannot promote to admin).

**Fix (frontend):** In `WorkspaceMembersPage`, update `canManage` logic:
- Currently: `isOwner(callerRole) && member.role !== 'owner'`
- Updated: `isAdminPlus(callerRole) && member.role !== 'owner' && !(callerRole === 'admin' && member.role === 'admin')`
- In `RoleSelector`, restrict options shown to admins: viewer/analyst only (no admin option).

---

## Protection Already in Place

| Rule | Status |
|------|--------|
| Last-owner removal prevention | ✓ |
| Owner cannot remove themselves | ✓ |
| Cannot demote owner via role-change endpoint | ✓ |
| Cannot assign owner role via invite | ✓ |
| Self-invitation blocked | ✓ |
| Rate limiting: 10/hour, 25/day per workspace | ✓ |
| Pending invitation cooldown: 24h per address | ✓ |
| Invitation token: SHA-256 hashed, raw never stored | ✓ |
| API token workspace boundary enforcement | ✓ |
| Legacy workspace backward compat (owner_user_id fallback) | ✓ |
| Plan seat limits enforced on invite | ✓ |

---

## Summary

The RBAC system is fundamentally well-built. Schemas, helpers, and the majority of routes are correct and production-grade. Two targeted gaps remain:

1. **Admin invite ceiling** — backend + frontend (2 code locations)
2. **Admin member management scope** — backend + frontend (4 code locations)

No schema migration is required. All fixes are additive logic changes to existing route handlers and the UI component.
