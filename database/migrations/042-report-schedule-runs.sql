-- Migration 042: Report Schedule Runs
-- Tracks execution attempts for report_schedules.

CREATE TABLE IF NOT EXISTS report_schedule_runs (
    id            TEXT PRIMARY KEY,
    schedule_id   TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    status        TEXT NOT NULL, -- running | completed | failed
    report_id     TEXT,
    error_message TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (schedule_id) REFERENCES report_schedules(id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (report_id) REFERENCES workspace_reports(id)
);

CREATE INDEX IF NOT EXISTS idx_report_schedule_runs_workspace
  ON report_schedule_runs (workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_report_schedule_runs_schedule
  ON report_schedule_runs (schedule_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_report_schedule_runs_status
  ON report_schedule_runs (status, created_at DESC);
