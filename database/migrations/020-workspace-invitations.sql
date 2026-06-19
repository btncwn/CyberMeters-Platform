-- ── 020-workspace-invitations.sql ───────────────────────────────────────────
-- Adds pending workspace invitations.
-- Raw invitation tokens are never stored; only SHA-256 hashes are persisted.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/020-workspace-invitations.sql

CREATE TABLE IF NOT EXISTS workspace_invitations (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    email        TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'viewer',
    token_hash   TEXT NOT NULL UNIQUE,
    invited_by   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    expires_at   TEXT NOT NULL,
    accepted_at  TEXT,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (invited_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_invitations_workspace
  ON workspace_invitations (workspace_id, status);

CREATE INDEX IF NOT EXISTS idx_workspace_invitations_token_hash
  ON workspace_invitations (token_hash);

CREATE INDEX IF NOT EXISTS idx_workspace_invitations_email_status
  ON workspace_invitations (email, status);
