-- ── 026-api-rate-limits.sql ────────────────────────────────────────────────
-- D1-backed burst rate limiting for authenticated API actions.

CREATE TABLE IF NOT EXISTS api_rate_limits (
    id             TEXT PRIMARY KEY,
    scope          TEXT NOT NULL,
    scope_id       TEXT NOT NULL,
    action         TEXT NOT NULL,
    window_start   TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    request_count  INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_rate_limits_scope_action_window
  ON api_rate_limits (scope, scope_id, action, window_start);
