-- ── 025-report-soft-delete.sql ──────────────────────────────────────────────
-- Adds soft-delete metadata for report lifecycle auditability.

ALTER TABLE workspace_reports
  ADD COLUMN deleted_at TEXT;

ALTER TABLE workspace_reports
  ADD COLUMN deleted_by TEXT;

CREATE INDEX IF NOT EXISTS idx_workspace_reports_deleted_at
  ON workspace_reports (workspace_id, deleted_at);

CREATE INDEX IF NOT EXISTS idx_workspace_reports_retention_deleted
  ON workspace_reports (retention_policy, deleted_at, generated_at, created_at);
