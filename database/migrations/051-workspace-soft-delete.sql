-- Migration 051: Workspace Soft-Delete
-- Adds deleted_at column to workspaces table so that workspace deletion is
-- non-destructive (scans, reports, findings, assets are preserved per Rule 5).
--
-- A workspace with deleted_at IS NOT NULL is excluded from all queries.
-- Scheduled scans for the workspace are disabled on deletion.
-- workspace_assets are archived (status='inactive') on deletion.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/051-workspace-soft-delete.sql
--
-- Rollback:
--   ALTER TABLE in D1/SQLite does not support DROP COLUMN.
--   Safe to leave: deleted_at defaults to NULL and all queries treat NULL as active.

ALTER TABLE workspaces ADD COLUMN deleted_at TEXT;

CREATE INDEX IF NOT EXISTS idx_workspaces_deleted_at
  ON workspaces (deleted_at)
  WHERE deleted_at IS NOT NULL;
