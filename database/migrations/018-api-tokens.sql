-- ── 018-api-tokens.sql ──────────────────────────────────────────────────────
-- Adds personal API tokens for authenticated users.
-- Raw tokens are never stored; only SHA-256 hashes are persisted.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/018-api-tokens.sql

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    last_used_at TEXT,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at   TEXT,
    status       TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id
  ON api_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash
  ON api_tokens (token_hash);
