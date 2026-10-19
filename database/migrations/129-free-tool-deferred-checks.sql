-- Migration 129: free-tool results to email later, while the daily breaker is on.
--
-- The public free tools (/tools/dmarc-checker, /tools/spf-checker) have a daily
-- emergency budget far above real demand. When it trips, a visitor is not sent
-- away: they may leave an email address, with consent, for that one result. The
-- hourly cron runs the check once capacity returns, emails the result and
-- deletes the row. Rows older than 72 hours, or that failed three times, are
-- deleted unsent. This is the only place a queried domain is stored, and only
-- because the visitor asked for the result to be sent.
--
-- Not workspace-scoped and not linked to any account: nothing to purge with a
-- workspace or account deletion.
--
-- Additive only.
--
-- Apply (before the Worker deploy — the defer route and the cron read it):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/129-free-tool-deferred-checks.sql
--
-- Rollback:
--   Roll the Worker back first. The table can stay; it empties itself within
--   72 hours only while the new Worker runs, so after a rollback remove any
--   remaining rows by hand if they are no longer wanted.

CREATE TABLE IF NOT EXISTS free_tool_deferred_checks (
  id              TEXT PRIMARY KEY,
  tool            TEXT NOT NULL,
  domain          TEXT NOT NULL,
  email           TEXT NOT NULL,
  consent_at      TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_attempt_at TEXT,
  UNIQUE (tool, domain, email)
);

CREATE INDEX IF NOT EXISTS idx_free_tool_deferred_checks_created
  ON free_tool_deferred_checks (created_at);
