-- Permission records only. Saving permission never schedules a scan.
-- Runtime must also recheck domain verification, target attestation, DNS/IP
-- binding, active service scope and the current workspace generation.
-- Rollback: disable special TLS execution; retain permission/audit history.
CREATE TABLE IF NOT EXISTS workspace_tls_authorizations (
  workspace_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
  consent_version TEXT,
  authorized_by TEXT,
  authorized_at TEXT,
  revoked_by TEXT,
  revoked_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspace_tls_service_authorizations (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  domain_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  sni TEXT NOT NULL CHECK(sni = hostname),
  port INTEGER NOT NULL,
  application_protocol TEXT NOT NULL,
  network_target_id TEXT NOT NULL,
  authorization_status TEXT NOT NULL CHECK(authorization_status IN ('active','revoked')),
  generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1),
  authorized_by TEXT NOT NULL,
  authorized_at TEXT NOT NULL,
  revoked_by TEXT,
  revoked_at TEXT,
  updated_at TEXT NOT NULL,
  CHECK((application_protocol = 'https' AND port IN (443,8443))
    OR (application_protocol = 'smtp' AND port IN (25,587))
    OR (application_protocol = 'smtps' AND port = 465)
    OR (application_protocol = 'imap' AND port = 143)
    OR (application_protocol = 'imaps' AND port = 993)
    OR (application_protocol = 'pop3' AND port = 110)
    OR (application_protocol = 'pop3s' AND port = 995))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tls_service_active_scope
  ON workspace_tls_service_authorizations(workspace_id,domain_id,hostname,port,application_protocol,network_target_id)
  WHERE authorization_status = 'active';
CREATE INDEX IF NOT EXISTS idx_tls_service_workspace
  ON workspace_tls_service_authorizations(workspace_id,authorization_status,domain_id);
