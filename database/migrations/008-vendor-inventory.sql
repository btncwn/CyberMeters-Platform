-- Migration 008: Vendor Inventory
-- CyberMeters ASM — persistent cross-scan vendor tracking per workspace.
-- Apply: wrangler d1 execute cybermeters-db --remote --file=database/migrations/008-vendor-inventory.sql

-- ── workspace_vendors ──────────────────────────────────────────────────────────
-- One row per unique (workspace_id, vendor_name, category) triple.
-- first_seen is set once on initial detection; last_seen is updated every scan.
-- status: 'active' | 'inactive'  (inactive = not seen in most recent scan for any
--         domain in the workspace)

CREATE TABLE IF NOT EXISTS workspace_vendors (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL,
    vendor_name   TEXT NOT NULL,
    category      TEXT,          -- infrastructure|cloud|email_identity|hosting|saas|support|collaboration|ecommerce
    source        TEXT,          -- primary signal source: spf|mx|ns|dkim|csp|server|cname|tech
    evidence      TEXT,          -- JSON array of {source, detail} objects
    confidence    TEXT,          -- high|medium|low  (based on number of independent signals)
    risk_level    TEXT,          -- low|medium|high
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    metadata_json TEXT,          -- reserved for future enrichment data
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,

    -- One row per (workspace, vendor name, category) — same vendor can appear in
    -- multiple categories only if signatures declare different categories, which
    -- they currently do not.
    UNIQUE (workspace_id, vendor_name, category)
);

CREATE INDEX IF NOT EXISTS idx_workspace_vendors_workspace
    ON workspace_vendors (workspace_id);

CREATE INDEX IF NOT EXISTS idx_workspace_vendors_name
    ON workspace_vendors (workspace_id, vendor_name);

CREATE INDEX IF NOT EXISTS idx_workspace_vendors_status
    ON workspace_vendors (workspace_id, status);

CREATE INDEX IF NOT EXISTS idx_workspace_vendors_risk
    ON workspace_vendors (workspace_id, risk_level);
