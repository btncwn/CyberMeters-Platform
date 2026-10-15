-- Portfolio MCP consent binds an explicit, finite set of workspaces to a
-- connection. A later membership or workspace addition never widens a grant.
CREATE TABLE IF NOT EXISTS mcp_oauth_connection_workspaces (
  connection_id TEXT NOT NULL REFERENCES mcp_oauth_connections(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  PRIMARY KEY (connection_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_connection_workspaces_workspace
  ON mcp_oauth_connection_workspaces(workspace_id, connection_id);

-- Existing portfolio grants did not record a chosen set. Revoke them instead
-- of interpreting the new empty set as permission to read every workspace.
UPDATE mcp_oauth_connections
   SET status = 'revoked', revoked_at = COALESCE(revoked_at, datetime('now'))
 WHERE portfolio_read = 1 AND status = 'active';

-- The provider's stable grant ID is recorded at code exchange. It lets the
-- token endpoint revoke the correct D1 connection if a refresh token is reused.
ALTER TABLE mcp_oauth_connections ADD COLUMN oauth_grant_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_oauth_connections_grant
  ON mcp_oauth_connections(user_id, oauth_grant_id)
  WHERE oauth_grant_id IS NOT NULL;

-- A revoked D1 connection rejects access immediately. Keep a durable KV
-- cleanup queue so a provider outage or bounded Worker budget cannot lose the
-- follow-up deletion. This trigger covers every revocation path, including
-- password reset, MFA reset, membership changes, and customer removal.
ALTER TABLE mcp_oauth_connections ADD COLUMN kv_cleanup_pending INTEGER NOT NULL DEFAULT 0
  CHECK (kv_cleanup_pending IN (0, 1));
ALTER TABLE mcp_oauth_connections ADD COLUMN kv_cleanup_attempted_at TEXT;
UPDATE mcp_oauth_connections SET kv_cleanup_pending = 1 WHERE status = 'revoked';
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_connections_kv_cleanup
  ON mcp_oauth_connections(kv_cleanup_pending, kv_cleanup_attempted_at, id);
CREATE TRIGGER IF NOT EXISTS trg_mcp_oauth_revoke_cleanup
  AFTER UPDATE OF status ON mcp_oauth_connections
  WHEN OLD.status = 'active' AND NEW.status = 'revoked'
BEGIN
  UPDATE mcp_oauth_connections SET kv_cleanup_pending = 1,
    kv_cleanup_attempted_at = NULL WHERE id = NEW.id;
END;

-- Only SHA-256 hashes are stored. The primary key makes refresh redemption
-- single-use across concurrent requests, stricter than the SDK's lost-response
-- previous-token grace. Seven-day grants plus one-day retention buffer.
CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_uses (
  token_hash TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES mcp_oauth_connections(id) ON DELETE CASCADE,
  used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL DEFAULT (datetime('now', '+8 days'))
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_refresh_uses_expiry
  ON mcp_oauth_refresh_uses(expires_at);
