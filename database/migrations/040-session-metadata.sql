-- Migration 040: Session Metadata
-- Adds ip_address, user_agent, and last_seen_at to user_sessions to support
-- the Login History & Session Visibility feature (Sprint v1).
--
-- All columns are nullable — existing session rows are not affected.
-- ip_address and user_agent are captured at session creation time.
-- last_seen_at is updated fire-and-forget on each authenticated request.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/040-session-metadata.sql
--
-- Rollback strategy:
--   ALTER TABLE DROP COLUMN not supported in D1/older SQLite.
--   Columns are nullable with no default — safe to leave in place.
--   Remove capture logic in index.js if rollback is needed.

ALTER TABLE user_sessions ADD COLUMN ip_address   TEXT;
ALTER TABLE user_sessions ADD COLUMN user_agent   TEXT;
ALTER TABLE user_sessions ADD COLUMN last_seen_at TEXT;

-- Index for efficient active-session listing per user
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active
  ON user_sessions (user_id, expires_at)
  WHERE expires_at > datetime('now');

-- Validation:
-- SELECT name FROM sqlite_master WHERE type='table' AND name='user_sessions';
-- PRAGMA table_info(user_sessions);
-- Expect: id, user_id, token_hash, created_at, expires_at, ip_address, user_agent, last_seen_at
