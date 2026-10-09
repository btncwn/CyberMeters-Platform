-- Explicitly authorized IP/CIDR scope; no synthetic domain or domain ownership.
CREATE TABLE network_targets (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  target TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK(target_type IN ('ip','cidr')),
  addresses_json TEXT NOT NULL,
  address_count INTEGER NOT NULL CHECK(address_count BETWEEN 1 AND 32),
  label TEXT,
  authorization_status TEXT NOT NULL CHECK(authorization_status = 'attested'),
  authorized_by TEXT NOT NULL REFERENCES users(id),
  authorized_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(workspace_id,target)
);
CREATE TABLE network_scans (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  target_id TEXT NOT NULL REFERENCES network_targets(id),
  requested_by TEXT NOT NULL REFERENCES users(id),
  retest_of TEXT REFERENCES network_scans(id),
  ports_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed')),
  quality TEXT CHECK(quality IN ('complete','partial')),
  reason TEXT,
  receipt_key TEXT NOT NULL UNIQUE,
  receipt_sha256 TEXT,
  coverage_json TEXT,
  changes_json TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);
CREATE INDEX idx_network_scans_workspace ON network_scans(workspace_id,created_at DESC);
CREATE UNIQUE INDEX idx_network_scans_one_active ON network_scans(workspace_id) WHERE status IN ('queued','running');
CREATE TABLE network_assets (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  address TEXT NOT NULL,
  port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  transport TEXT NOT NULL CHECK(transport = 'tcp'),
  state TEXT NOT NULL CHECK(state IN ('open','closed','timeout','error','not_run')),
  last_observed_state TEXT CHECK(last_observed_state IN ('open','closed')),
  service_json TEXT,
  tls_json TEXT,
  first_seen_at TEXT,
  last_seen_at TEXT,
  last_checked_at TEXT NOT NULL,
  last_scan_id TEXT NOT NULL REFERENCES network_scans(id),
  PRIMARY KEY(workspace_id,address,port,transport)
);
