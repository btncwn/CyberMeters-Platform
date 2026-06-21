-- Migration 044: Workspace Retention Settings
-- Optional per-workspace retention controls. If no row exists, plan defaults apply.

CREATE TABLE IF NOT EXISTS workspace_retention_settings (
    workspace_id    TEXT PRIMARY KEY,
    retention_days  INTEGER, -- 30 | 90 | 365 | 730, NULL means unlimited/forever
    auto_cleanup    INTEGER NOT NULL DEFAULT 1,
    updated_by      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_retention_auto_cleanup
  ON workspace_retention_settings (auto_cleanup);

-- Preserve report metadata after retention cleanup and prepare for accurate
-- storage metering. Existing report rows are intentionally not backfilled.
ALTER TABLE workspace_reports
  ADD COLUMN deleted_reason TEXT;

ALTER TABLE workspace_reports
  ADD COLUMN report_size_bytes INTEGER;
