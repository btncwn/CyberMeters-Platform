-- Masked evidence from explicit checks of customer-verified public web sources.
-- Raw source bodies and credential values are never persisted.
CREATE TABLE IF NOT EXISTS identity_public_source_checks (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  domain_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identity_public_checks_workspace
  ON identity_public_source_checks(workspace_id, domain_id, created_at DESC);
