-- Migration 004: Persistent Asset Inventory
-- CyberMeters ASM — persistent cross-scan asset tracking
-- Apply: wrangler d1 execute cybermeters-db --remote --file=database/migrations/004-asset-inventory.sql

-- ── workspace_assets ─────────────────────────────────────────────────────────
-- One row per unique (workspace_id, hostname) pair.
-- first_seen is set once on initial discovery; last_seen is updated every scan.
-- status: 'active' | 'inactive' (not seen in most recent scan for this domain)

CREATE TABLE IF NOT EXISTS workspace_assets (
    id               TEXT PRIMARY KEY,
    workspace_id     TEXT NOT NULL,
    domain_id        TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    asset_type       TEXT NOT NULL DEFAULT 'subdomain',  -- subdomain | apex | cloud_storage | exposed_service
    source           TEXT,                               -- crt_sh | certspotter | dns_bruteforce | exposure_probe
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    wildcard_dns     INTEGER NOT NULL DEFAULT 0,         -- 1 if discovered during a wildcard-DNS scan
    ip_addresses     TEXT,                               -- JSON array of IPs, e.g. '["1.2.3.4"]'
    cname            TEXT,                               -- CNAME target if known
    redirect_to      TEXT,                               -- final redirect URL if known
    cloud_provider   TEXT,                               -- 'aws_s3' | 'azure_blob' | 'gcs' | null
    risk_level       TEXT,                               -- info | low | medium | high | critical
    metadata_json    TEXT,                               -- arbitrary extra data per asset type
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,

    -- Enforce one row per workspace+hostname combination
    UNIQUE (workspace_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_workspace_assets_workspace
    ON workspace_assets (workspace_id);

CREATE INDEX IF NOT EXISTS idx_workspace_assets_domain
    ON workspace_assets (workspace_id, domain_id);

CREATE INDEX IF NOT EXISTS idx_workspace_assets_status
    ON workspace_assets (workspace_id, status);

-- ── asset_events ─────────────────────────────────────────────────────────────
-- Append-only event log.  One row per notable change detected during a scan.
-- event_type values:
--   new_asset_discovered | asset_reappeared | asset_no_longer_seen
--   takeover_risk_detected | wildcard_dns_detected | cloud_storage_detected

CREATE TABLE IF NOT EXISTS asset_events (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id    TEXT NOT NULL,
    asset_id     TEXT,              -- FK to workspace_assets.id (nullable for domain-level events)
    scan_id      TEXT,              -- scan that produced this event
    event_type   TEXT NOT NULL,
    hostname     TEXT,
    severity     TEXT NOT NULL DEFAULT 'info',
    description  TEXT,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_events_workspace
    ON asset_events (workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_asset_events_asset
    ON asset_events (asset_id);
