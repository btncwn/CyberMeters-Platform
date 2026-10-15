-- Audit events are written as both SQLite timestamps and ISO UTC strings.
-- Index their parsed time so the daily 12-month retention sweep can find its
-- oldest rows without scanning the full audit trail. NULL/malformed dates do
-- not qualify for automatic deletion and require separate investigation.
CREATE INDEX IF NOT EXISTS idx_audit_events_retention_epoch
  ON audit_events (unixepoch(created_at));
