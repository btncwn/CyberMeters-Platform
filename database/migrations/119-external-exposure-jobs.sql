-- Resumable work for the existing scan Queue, not a second finding/case store.
-- Network reservations commit BEFORE execution. Expired leases retain their full
-- reservation, so uncertain attempts after crashes are charged rather than free.
-- Rollback: disable EXPOSURE_SCAN_MODE, roll application back, retain tables.
-- No scan FK: report retention may remove scans before workspace work history.
CREATE TABLE IF NOT EXISTS external_exposure_jobs (
  scan_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  domain_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','complete','cancelled','budget_exhausted')),
  plan_json TEXT NOT NULL,
  dispatch_json TEXT NOT NULL DEFAULT '{}',
  cursor INTEGER NOT NULL DEFAULT 0,
  results_json TEXT NOT NULL DEFAULT '[]',
  costs_json TEXT NOT NULL DEFAULT '{}',
  charged_requests INTEGER NOT NULL DEFAULT 0,
  charged_bytes INTEGER NOT NULL DEFAULT 0,
  unknown_attempts INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0,
  lease_token TEXT,
  lease_until INTEGER NOT NULL DEFAULT 0,
  created_ms INTEGER NOT NULL,
  deadline_ms INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id,domain_id,scan_id)
);
CREATE INDEX IF NOT EXISTS idx_external_exposure_workspace_budget ON external_exposure_jobs(workspace_id,created_ms);
CREATE INDEX IF NOT EXISTS idx_external_exposure_pending ON external_exposure_jobs(state,lease_until);
CREATE TABLE IF NOT EXISTS external_exposure_visits (
  workspace_id TEXT NOT NULL,
  domain_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  last_attempt_ms INTEGER NOT NULL DEFAULT 0,
  last_scan_id TEXT,
  PRIMARY KEY(workspace_id,domain_id,hostname)
);
