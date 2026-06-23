-- Migration 052: Add updated_at column to workspaces table
-- Required for PATCH /api/workspaces/:id (workspace rename — Sprint B / B1).
-- The column is set via datetime('now') on each rename.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/052-workspace-updated-at.sql
--
-- Rollback:
--   ALTER TABLE in D1/SQLite does not support DROP COLUMN.
--   Safe to leave: updated_at defaults to NULL and no queries depend on a non-NULL value.

ALTER TABLE workspaces ADD COLUMN updated_at TEXT;
