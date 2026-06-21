-- Migration 041: Executive Report Schedules
-- Backend foundation for recurring executive report schedule configuration.
-- This table does not send email or generate reports automatically in v1.

CREATE TABLE IF NOT EXISTS report_schedules (
    id               TEXT PRIMARY KEY,
    workspace_id     TEXT NOT NULL,
    created_by       TEXT NOT NULL,
    frequency        TEXT NOT NULL, -- weekly | monthly
    enabled          INTEGER NOT NULL DEFAULT 1,
    email_recipients TEXT NOT NULL DEFAULT '[]',
    last_run_at      TEXT,
    next_run_at      TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_report_schedules_workspace
  ON report_schedules (workspace_id, enabled);

CREATE INDEX IF NOT EXISTS idx_report_schedules_due
  ON report_schedules (enabled, next_run_at);
