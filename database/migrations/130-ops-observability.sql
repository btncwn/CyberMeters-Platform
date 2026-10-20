-- Migration 130: see errors before customers report them.
--
-- ops_daily_counters: one row per UTC day, metric and label, incremented by
-- the API (5xx responses, free-scan and free-tool outcomes, browser error
-- reports). Labels are fixed vocabulary and route families (":id" in place of
-- identifiers), never a domain, IP, email or free text. Read by the founder's
-- daily 08:00 email; rows older than 180 days are deleted by the daily cron.
--
-- feedback_reports: the "Something wrong?" button. The message the visitor
-- typed, the page path (secret-looking segments redacted), the app build and
-- the error code shown on screen. No IP, no user id, no session. Deleted after
-- 90 days by the daily cron.
--
-- Not workspace-scoped and not linked to any account: nothing to purge with a
-- workspace or account deletion.
--
-- Additive only.
--
-- Apply (before the Worker deploy — the routes and the cron write these tables):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/130-ops-observability.sql
--
-- Rollback:
--   Roll the Worker back first. The tables can stay; nothing else reads them.

CREATE TABLE IF NOT EXISTS ops_daily_counters (
  day        TEXT NOT NULL,
  metric     TEXT NOT NULL,
  label      TEXT NOT NULL,
  count      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (day, metric, label)
);

CREATE TABLE IF NOT EXISTS feedback_reports (
  id         TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  surface    TEXT NOT NULL,
  tool       TEXT,
  path       TEXT NOT NULL,
  build      TEXT NOT NULL,
  error_code TEXT,
  message    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_reports_created
  ON feedback_reports (created_at);
