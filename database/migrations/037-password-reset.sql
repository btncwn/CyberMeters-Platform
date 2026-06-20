-- Migration 037: Password Reset Tokens
-- Stores hashed short-lived tokens for the forgot/reset-password flow.
-- Raw token is sent to the user's email; only the SHA-256 hash is stored.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  token_hash  TEXT UNIQUE NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_prt_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_prt_user_id    ON password_reset_tokens(user_id);

-- Validation:
-- SELECT name FROM sqlite_master WHERE type='table' AND name='password_reset_tokens';
-- SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_prt_%';
