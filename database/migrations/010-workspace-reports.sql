-- ── 010-workspace-reports.sql ────────────────────────────────────────────────
-- Executive report archive.
-- Each row tracks one generated (or failed) PDF report for a workspace.
-- The actual PDF bytes live in R2 at `report_key`.

CREATE TABLE IF NOT EXISTS workspace_reports (
  id             TEXT NOT NULL PRIMARY KEY,
  workspace_id   TEXT NOT NULL,
  report_type    TEXT NOT NULL,          -- manual | scan_snapshot | weekly_executive | monthly_executive
  report_period  TEXT,                   -- e.g. "2026-W25", "2026-06", "manual-20260619-143000"
  report_key     TEXT NOT NULL,          -- R2 object key
  status         TEXT NOT NULL DEFAULT 'pending',  -- pending | completed | failed
  generated_at   TEXT,                   -- ISO-8601 timestamp; NULL while pending/failed
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  metadata_json  TEXT                    -- JSON blob for error messages or extra context
);

CREATE INDEX IF NOT EXISTS idx_workspace_reports_workspace_id
  ON workspace_reports (workspace_id);

CREATE INDEX IF NOT EXISTS idx_workspace_reports_type
  ON workspace_reports (report_type);

CREATE INDEX IF NOT EXISTS idx_workspace_reports_period
  ON workspace_reports (report_period);

CREATE INDEX IF NOT EXISTS idx_workspace_reports_generated_at
  ON workspace_reports (generated_at);

CREATE INDEX IF NOT EXISTS idx_workspace_reports_status
  ON workspace_reports (status);
