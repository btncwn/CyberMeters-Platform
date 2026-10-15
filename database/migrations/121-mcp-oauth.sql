-- MCP customer OAuth. The public MCP gateway has no database binding; these
-- rows are owned and checked by the existing API Worker over a private RPC.
-- No workspace is enrolled by this migration.

CREATE TABLE IF NOT EXISTS mcp_beta_workspace_access (
  workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id),
  status TEXT NOT NULL DEFAULT 'paused' CHECK (status IN ('enabled', 'paused')),
  enrolled_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mcp_oauth_connections (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  workspace_id TEXT REFERENCES workspaces(id),
  portfolio_read INTEGER NOT NULL DEFAULT 0 CHECK (portfolio_read IN (0, 1)),
  granted_scopes TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  revoked_at TEXT,
  CHECK ((workspace_id IS NOT NULL AND portfolio_read = 0) OR
         (workspace_id IS NULL AND portfolio_read = 1))
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_connections_user
  ON mcp_oauth_connections(user_id, status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_connections_workspace
  ON mcp_oauth_connections(workspace_id, status);

-- The initial /authorize request cannot read the web app's localStorage bearer.
-- Its validated request is kept behind an opaque 256-bit intent while the app
-- exchanges its existing web session for a short-lived, host-only API cookie.
CREATE TABLE IF NOT EXISTS mcp_oauth_login_intents (
  id_hash TEXT PRIMARY KEY,
  authorization_url TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_login_intents_expiry
  ON mcp_oauth_login_intents(expires_at);

CREATE TABLE IF NOT EXISTS mcp_oauth_browser_sessions (
  cookie_hash TEXT PRIMARY KEY,
  intent_hash TEXT NOT NULL UNIQUE REFERENCES mcp_oauth_login_intents(id_hash),
  user_id TEXT NOT NULL REFERENCES users(id),
  web_session_id TEXT NOT NULL REFERENCES user_sessions(id),
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_browser_sessions_expiry
  ON mcp_oauth_browser_sessions(expires_at);
