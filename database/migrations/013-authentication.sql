-- ── 013-authentication.sql ────────────────────────────────────────────────────
-- Adds authentication columns to the existing users table and creates a
-- user_sessions table for server-side session management.
-- Also adds owner_user_id to workspaces for future RBAC scoping.
--
-- All changes are backward-compatible:
--   - New columns on users are nullable / have defaults
--   - owner_user_id on workspaces is nullable (existing rows get NULL)
--   - user_demo rows created by existing scan code continue to work
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/013-authentication.sql
--
-- Rollback strategy:
--   - Drop user_sessions table (no data loss risk, sessions are ephemeral)
--   - ALTER TABLE DROP COLUMN not supported in older SQLite/D1 for users
--   - Safe to leave unused columns; they default to NULL and don't affect queries

-- ── Extend users table ────────────────────────────────────────────────────────

-- Password hash (format: pbkdf2:sha256:<iterations>:<salt_hex>:<hash_hex>)
ALTER TABLE users ADD COLUMN password_hash TEXT;

-- Timestamp of last successful login
ALTER TABLE users ADD COLUMN last_login_at TEXT;

-- Account status: 'active' | 'suspended' | 'unverified'
ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active';

-- ── Session tokens ────────────────────────────────────────────────────────────
-- Sessions store a SHA-256 hash of the raw bearer token.
-- The raw token is only ever transmitted over HTTPS to the client.
-- A compromised D1 backup cannot be used to forge sessions.

CREATE TABLE IF NOT EXISTS user_sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash
  ON user_sessions (token_hash);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
  ON user_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at
  ON user_sessions (expires_at);

-- ── Workspace ownership ───────────────────────────────────────────────────────
-- Nullable: existing workspaces are not owned by any specific user in v1.
-- Future RBAC sprints will enforce this constraint and backfill rows.

ALTER TABLE workspaces ADD COLUMN owner_user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_user_id
  ON workspaces (owner_user_id)
  WHERE owner_user_id IS NOT NULL;

-- ── Email index on users ──────────────────────────────────────────────────────
-- email is already UNIQUE in schema.sql; add explicit index for fast lookup.
CREATE INDEX IF NOT EXISTS idx_users_email
  ON users (email);

-- ── Backfill existing rows ────────────────────────────────────────────────────
-- Existing users (e.g. user_demo) get status='active' and NULL password_hash.
-- They cannot log in via password auth until a real account is created.
UPDATE users SET status = 'active' WHERE status IS NULL;
