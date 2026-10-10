-- Customer-supplied workforce inventory and explicitly requested Entra actions.
-- No provider credentials, passwords, tokens or raw leaked material are stored.
CREATE TABLE IF NOT EXISTS identity_workforce_accounts (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  upn TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  vip INTEGER NOT NULL DEFAULT 0 CHECK(vip IN (0,1)),
  source TEXT NOT NULL CHECK(source IN ('customer','entra')),
  domain_id TEXT,
  tenant_id TEXT,
  client_id TEXT,
  provider_user_id TEXT,
  observation_json TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, upn)
);
CREATE INDEX IF NOT EXISTS idx_identity_workforce_workspace ON identity_workforce_accounts(workspace_id, vip, updated_at);
CREATE TABLE IF NOT EXISTS identity_response_actions (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES identity_workforce_accounts(id) ON DELETE CASCADE,
  requested_by TEXT NOT NULL,
  concern TEXT NOT NULL,
  preview_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('previewed','applying','provider_accepted','uncertain','not_completed')),
  outcome_json TEXT,
  verification_json TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identity_response_workspace ON identity_response_actions(workspace_id, account_id, created_at);
