-- Known, explicitly submitted addresses only. Neither raw email nor the
-- provider's truncated email hash is retained. Subject hashes are pseudonymous.
CREATE TABLE identity_breach_checks (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  domain_id TEXT NOT NULL REFERENCES domains(id),
  requested_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  request_id TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  masked_address TEXT NOT NULL,
  consent_version TEXT NOT NULL,
  consented_at TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'leakcheck_public',
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sources_found','no_matches','unavailable','rate_limited')),
  reason TEXT,
  found_count INTEGER CHECK(found_count IS NULL OR found_count >= 0),
  fields_json TEXT NOT NULL DEFAULT '[]',
  sources_json TEXT NOT NULL DEFAULT '[]',
  checked_at TEXT NOT NULL,
  expires_at TEXT,
  UNIQUE(workspace_id,request_id)
);
CREATE INDEX idx_identity_breach_checks_workspace_time ON identity_breach_checks(workspace_id,checked_at);

-- Bounded daily cleanup rotates through workspaces, including those whose
-- retention is disabled. Only a lexical cursor is stored; no subject data.
CREATE TABLE identity_breach_cleanup_state (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  workspace_cursor TEXT NOT NULL DEFAULT ''
);
INSERT INTO identity_breach_cleanup_state(id) VALUES(1);
