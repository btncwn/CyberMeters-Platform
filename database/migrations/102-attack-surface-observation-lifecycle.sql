-- Migration 102: Attack Surface per-signal observations and asset lifecycle.
--
-- Item 10 P2. Additive only.
--
-- workspace_assets.status remains the legacy active|inactive projection. It is
-- deliberately NOT redefined as confirmed removal: historical inactive rows may
-- represent workspace archival or the former one-scan disappearance rule.
-- lifecycle_state and last_observation_state are separate, explicit truths.
--
-- Existing rows backfill through the column defaults to not_assessed. No active
-- or inactive value is interpreted as observed, removed, or unavailable.
--
-- The two observation tables are append-only. scan_id is provenance without a
-- foreign key because observation history must outlive ordinary scan purges.
-- JSON columns contain bounded source detail only; lifecycle state always lives
-- in real constrained columns.
--
-- Rollback:
--   Roll back application code only. Leaving the additive columns/tables in
--   place is backward compatible and preserves already-recorded evidence.

ALTER TABLE workspace_assets ADD COLUMN lifecycle_state TEXT NOT NULL
  DEFAULT 'not_assessed'
  CHECK (lifecycle_state IN (
    'not_assessed', 'observed', 'not_observed', 'confirmed_removed'
  ));

ALTER TABLE workspace_assets ADD COLUMN last_observation_state TEXT NOT NULL
  DEFAULT 'not_assessed'
  CHECK (last_observation_state IN (
    'not_assessed', 'observed', 'not_observed',
    'observation_unavailable', 'observation_incomplete'
  ));

ALTER TABLE workspace_assets ADD COLUMN lifecycle_policy_version TEXT;
ALTER TABLE workspace_assets ADD COLUMN confirmed_removed_at TEXT;
ALTER TABLE workspace_assets ADD COLUMN last_observation_scan_id TEXT;

CREATE TABLE IF NOT EXISTS attack_surface_signal_observations (
  id                 TEXT PRIMARY KEY,
  workspace_id       TEXT NOT NULL,
  domain_id          TEXT NOT NULL,
  scan_id            TEXT NOT NULL,
  signal_key         TEXT NOT NULL CHECK (signal_key IN (
    'subdomain_discovery',
    'dns_resolution',
    'http_https_service',
    'technology',
    'exposure_admin_surface',
    'takeover_candidate',
    'cve',
    'kev',
    'cloud_storage'
  )),
  state              TEXT NOT NULL CHECK (state IN (
    'observed', 'not_observed', 'absent',
    'unavailable', 'incomplete', 'not_assessed'
  )),
  reason             TEXT,
  evidence_count     INTEGER NOT NULL DEFAULT 0,
  sources_json       TEXT NOT NULL DEFAULT '[]',
  limitations_json   TEXT NOT NULL DEFAULT '[]',
  model_version      TEXT NOT NULL,
  observed_at        TEXT NOT NULL,
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),

  UNIQUE (workspace_id, domain_id, scan_id, signal_key),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_attack_surface_signal_observations_ws_time
  ON attack_surface_signal_observations
    (workspace_id, domain_id, signal_key, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_attack_surface_signal_observations_scan
  ON attack_surface_signal_observations (workspace_id, scan_id);

CREATE TABLE IF NOT EXISTS asset_lifecycle_observations (
  id                    TEXT PRIMARY KEY,
  workspace_id          TEXT NOT NULL,
  domain_id             TEXT NOT NULL,
  asset_id              TEXT NOT NULL,
  scan_id               TEXT NOT NULL,
  observation_state     TEXT NOT NULL CHECK (observation_state IN (
    'not_assessed', 'observed', 'not_observed',
    'observation_unavailable', 'observation_incomplete'
  )),
  dns_state             TEXT NOT NULL CHECK (dns_state IN (
    'observed', 'not_observed', 'absent',
    'unavailable', 'incomplete', 'not_assessed'
  )),
  http_state            TEXT NOT NULL CHECK (http_state IN (
    'observed', 'not_observed', 'absent',
    'unavailable', 'incomplete', 'not_assessed'
  )),
  qualifies_removal     INTEGER NOT NULL DEFAULT 0
    CHECK (qualifies_removal IN (0, 1)),
  policy_version        TEXT NOT NULL,
  source_detail_json    TEXT NOT NULL DEFAULT '{}',
  observed_at           TEXT NOT NULL,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),

  UNIQUE (workspace_id, asset_id, scan_id),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
  FOREIGN KEY (asset_id) REFERENCES workspace_assets(id)
);

CREATE INDEX IF NOT EXISTS idx_asset_lifecycle_observations_asset_time
  ON asset_lifecycle_observations
    (workspace_id, asset_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_asset_lifecycle_observations_scan
  ON asset_lifecycle_observations (workspace_id, scan_id);
