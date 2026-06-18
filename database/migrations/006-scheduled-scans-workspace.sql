-- Migration 006: Add workspace_id and asset tracking columns to scheduled_scans
-- Apply: wrangler d1 execute cybermeters-db --remote --file=database/migrations/006-scheduled-scans-workspace.sql

-- workspace_id: links a schedule to a workspace so inventory stays scoped correctly.
-- last_asset_count: active asset count after the last run (for UI display).
-- asset_change_count: new/reappeared assets in the last run (for UI display).

ALTER TABLE scheduled_scans ADD COLUMN workspace_id        TEXT;
ALTER TABLE scheduled_scans ADD COLUMN last_asset_count    INTEGER DEFAULT 0;
ALTER TABLE scheduled_scans ADD COLUMN asset_change_count  INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_workspace
    ON scheduled_scans (workspace_id);
