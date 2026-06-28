-- Migration 053: Query hardening indexes
-- Supports bounded Public Beta list, authorization, entitlement, and cron queries.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/053-query-hardening-indexes.sql
--
-- Rollback:
--   DROP INDEX IF EXISTS idx_scans_workspace_created;
--   DROP INDEX IF EXISTS idx_scheduled_scans_workspace_enabled;
--   DROP INDEX IF EXISTS idx_scheduled_scans_due;
--   DROP INDEX IF EXISTS idx_workspace_domains_domain_workspace;

CREATE INDEX IF NOT EXISTS idx_scans_workspace_created
  ON scans (workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_workspace_enabled
  ON scheduled_scans (workspace_id, enabled);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_due
  ON scheduled_scans (enabled, next_run_at);

CREATE INDEX IF NOT EXISTS idx_workspace_domains_domain_workspace
  ON workspace_domains (domain_id, workspace_id);
