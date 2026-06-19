-- Migration 019: Scheduled Reporting
-- Allows workspaces to auto-generate executive reports on a schedule.

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    report_type  TEXT NOT NULL DEFAULT 'monthly_executive',
    frequency    TEXT NOT NULL DEFAULT 'monthly',  -- weekly | monthly | quarterly
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_run_at  TEXT,
    next_run_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scheduled_reports_workspace
    ON scheduled_reports (workspace_id, enabled);

CREATE INDEX IF NOT EXISTS idx_scheduled_reports_next_run
    ON scheduled_reports (next_run_at)
    WHERE enabled = 1;
