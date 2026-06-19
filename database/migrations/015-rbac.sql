-- ── 015-rbac.sql ──────────────────────────────────────────────────────────────
-- Adds workspace-level role-based access control.
-- All changes are additive — existing tables are not altered.
--
-- Roles (least → most privileged):
--   viewer   — read-only access to scans, findings, assets, reports
--   analyst  — viewer + can trigger scans, view full intelligence
--   admin    — analyst + manage domains, generate reports, manage notifications
--   owner    — admin + manage members, delete workspace, transfer ownership
--
-- Membership model:
--   One row per (workspace_id, user_id) pair.
--   A user can only have one role per workspace.
--   The workspace creator is automatically seeded as owner via the application
--   layer (POST /api/workspaces inserts a membership row).
--
-- Backward compat:
--   Existing workspaces that have owner_user_id set are backfilled with an
--   owner membership row. Rows where owner_user_id is NULL are left without
--   any member (the workspace is accessible to all authenticated users until
--   a member is explicitly assigned — preserves pre-RBAC behaviour).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/015-rbac.sql
--
-- Rollback strategy:
--   DROP TABLE workspace_members;  -- no data is lost; membership can be re-seeded.

-- ── workspace_members ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS workspace_members (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'viewer',  -- owner | admin | analyst | viewer
    invited_by   TEXT,                             -- user_id of the inviter (nullable in v1)
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (workspace_id, user_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (user_id)      REFERENCES users(id)
);

-- Fast lookup: "what workspaces can this user access?"
CREATE INDEX IF NOT EXISTS idx_wm_user_id
  ON workspace_members (user_id);

-- Fast lookup: "who are the members of this workspace?"
CREATE INDEX IF NOT EXISTS idx_wm_workspace_id
  ON workspace_members (workspace_id);

-- Fast lookup: "is this user an owner of this workspace?"
CREATE INDEX IF NOT EXISTS idx_wm_workspace_role
  ON workspace_members (workspace_id, role);

-- ── Backfill existing workspaces ──────────────────────────────────────────────
-- Seed owner membership rows for workspaces that already have owner_user_id set.
-- The owner_user_id column was added in migration 013-authentication.sql.
-- Uses INSERT OR IGNORE so re-running this migration is safe.

INSERT OR IGNORE INTO workspace_members (id, workspace_id, user_id, role, created_at)
SELECT
    'wm_seed_' || workspaces.id,
    workspaces.id,
    workspaces.owner_user_id,
    'owner',
    workspaces.created_at
FROM workspaces
WHERE workspaces.owner_user_id IS NOT NULL;
