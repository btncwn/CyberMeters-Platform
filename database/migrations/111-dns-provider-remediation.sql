-- Customer-zone credentials are AES-GCM ciphertext with tenant/domain/zone AAD.
CREATE TABLE dns_provider_connections (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  domain_id TEXT NOT NULL REFERENCES domains(id),
  zone_id TEXT NOT NULL,
  zone_name TEXT NOT NULL,
  token_ciphertext TEXT NOT NULL,
  credential_revision TEXT NOT NULL,
  connected_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  connected_at TEXT NOT NULL,
  UNIQUE(workspace_id,domain_id)
);
CREATE TABLE dns_provider_changes (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  domain_id TEXT NOT NULL REFERENCES domains(id),
  connection_id TEXT NOT NULL,
  credential_revision TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  remediation_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  input_fingerprint TEXT NOT NULL,
  record_name TEXT NOT NULL,
  before_json TEXT NOT NULL,
  desired_json TEXT NOT NULL,
  postimage_json TEXT,
  provider_record_id TEXT,
  reporting_endpoint_id TEXT,
  case_id TEXT,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  operation_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  operation_started_at TEXT,
  applied_at TEXT,
  verified_at TEXT,
  rolled_back_at TEXT,
  apply_request_id TEXT,
  rollback_request_id TEXT,
  status TEXT NOT NULL CHECK(status IN ('preview','applying','provider_accepted','dns_verified','uncertain','conflict','unavailable','rolling_back','rolled_back','rollback_uncertain')),
  reason TEXT,
  verification_json TEXT NOT NULL DEFAULT '{"state":"not_checked","checked_at":null,"reason":null}',
  UNIQUE(workspace_id,request_id)
);
CREATE INDEX idx_dns_provider_changes_workspace_time ON dns_provider_changes(workspace_id,created_at);
CREATE UNIQUE INDEX idx_dns_provider_changes_inflight ON dns_provider_changes(workspace_id,domain_id,record_name)
  WHERE status IN ('applying','uncertain','rolling_back','rollback_uncertain');
