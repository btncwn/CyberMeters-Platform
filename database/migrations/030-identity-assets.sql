-- ── 030-identity-assets.sql ──────────────────────────────────────────────────
-- Identity Asset Discovery Layer v1.
--
-- Creates a dedicated table for authentication surfaces, login portals,
-- SSO endpoints, and identity provider relationships discovered by the
-- Identity Discovery module (Phase 7j of runScanEngine).
--
-- Separate from workspace_assets so identity assets carry extended metadata
-- (provider, identity_type, risk_score) without polluting the general asset
-- inventory schema.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/030-identity-assets.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS identity_assets;

CREATE TABLE IF NOT EXISTS identity_assets (
    id               TEXT PRIMARY KEY,
    workspace_id     TEXT NOT NULL,
    domain_id        TEXT NOT NULL,
    scan_id          TEXT NOT NULL,
    hostname         TEXT,
    asset_type       TEXT NOT NULL DEFAULT 'portal',
    identity_type    TEXT NOT NULL,
    provider         TEXT,
    internet_exposed INTEGER NOT NULL DEFAULT 1,
    source           TEXT NOT NULL DEFAULT 'identity_discovery',
    risk_score       INTEGER NOT NULL DEFAULT 0,
    evidence         TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TEXT,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Workspace lookup (primary query pattern)
CREATE INDEX IF NOT EXISTS idx_identity_assets_workspace
    ON identity_assets (workspace_id, status);

-- Provider aggregation (vendor risk integration)
CREATE INDEX IF NOT EXISTS idx_identity_assets_provider
    ON identity_assets (workspace_id, provider);

-- Hostname dedup (upsert logic)
CREATE INDEX IF NOT EXISTS idx_identity_assets_hostname
    ON identity_assets (workspace_id, hostname, identity_type);
