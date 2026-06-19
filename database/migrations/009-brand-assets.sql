-- Migration 009: Brand Monitoring — Typosquat & Brand Asset Tracking
-- CyberMeters ASM — persistent brand domain tracking per workspace.
-- Apply: wrangler d1 execute cybermeters-db --remote --file=database/migrations/009-brand-assets.sql

-- ── workspace_brand_assets ──────────────────────────────────────────────────
-- One row per (workspace_id, domain, candidate_domain) triple.
-- Candidates are generated from the workspace's primary domain's brand name.
-- first_seen is set once on initial detection; last_seen is updated on re-validation.
-- status: 'active'     — DNS resolves (confirmed live)
--         'inactive'   — no longer resolves (or not re-detected recently)
--         'unverified' — generated but not yet validated via DNS
-- dns_resolves and https_available are set by the validation endpoint (POST /brand-monitoring/refresh)
-- and are NULL until the first validation pass completes.

CREATE TABLE IF NOT EXISTS workspace_brand_assets (
    id               TEXT PRIMARY KEY,
    workspace_id     TEXT NOT NULL,
    domain           TEXT NOT NULL,    -- original registered domain (e.g. tesla.com)
    candidate_domain TEXT NOT NULL,    -- generated typosquat candidate (e.g. tesIa.com)
    variant_type     TEXT,             -- substitution|omission|duplication|transposition|hyphen_keyword|prefix_keyword
    risk_level       TEXT,             -- critical|high|medium|low
    risk_reasons     TEXT,             -- JSON array of strings explaining the risk score
    dns_resolves     INTEGER,          -- 0|1 (NULL = not yet checked)
    https_available  INTEGER,          -- 0|1 (NULL = not yet checked)
    ip_address       TEXT,             -- resolved A record IP, if any
    status           TEXT NOT NULL DEFAULT 'unverified',  -- active|inactive|unverified
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,

    UNIQUE (workspace_id, domain, candidate_domain)
);

CREATE INDEX IF NOT EXISTS idx_brand_assets_workspace
    ON workspace_brand_assets (workspace_id);

CREATE INDEX IF NOT EXISTS idx_brand_assets_status
    ON workspace_brand_assets (workspace_id, status);

CREATE INDEX IF NOT EXISTS idx_brand_assets_risk
    ON workspace_brand_assets (workspace_id, risk_level);

CREATE INDEX IF NOT EXISTS idx_brand_assets_domain
    ON workspace_brand_assets (workspace_id, domain);
