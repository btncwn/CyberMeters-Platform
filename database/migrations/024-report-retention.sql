-- ── 024-report-retention.sql ────────────────────────────────────────────────
-- Adds report retention metadata used by report lifecycle cleanup.
-- Allowed values:
--   30_days | 90_days | 1_year | 2_years | 7_years | forever

ALTER TABLE workspace_reports
  ADD COLUMN retention_policy TEXT NOT NULL DEFAULT '2_years';

CREATE INDEX IF NOT EXISTS idx_workspace_reports_retention
  ON workspace_reports (retention_policy, generated_at);
