-- ── 058-brand-protection-intelligence.sql ───────────────────────────────────
-- Brand Protection Intelligence v1.
-- Reuses workspace_brand_assets so the existing Brand Monitoring APIs and
-- historical first_seen/last_seen data remain intact.
--
-- Apply before deploying the corresponding Worker:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/058-brand-protection-intelligence.sql
--
-- Rollback strategy:
--   DROP INDEX IF EXISTS idx_brand_assets_classification;
--   DROP TABLE IF EXISTS workspace_brand_profiles;
--   Leave nullable additive asset columns in place and deploy the prior Worker.
--   Removing SQLite columns would require a risky table rebuild.

CREATE TABLE IF NOT EXISTS workspace_brand_profiles (
    id                     TEXT PRIMARY KEY,
    workspace_id           TEXT NOT NULL UNIQUE,
    brand_name             TEXT NOT NULL,
    primary_domain         TEXT NOT NULL,
    keywords_json          TEXT,
    protected_domains_json TEXT,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

ALTER TABLE workspace_brand_assets ADD COLUMN brand_profile_id TEXT;
ALTER TABLE workspace_brand_assets ADD COLUMN similarity_score INTEGER;
ALTER TABLE workspace_brand_assets ADD COLUMN classification TEXT NOT NULL DEFAULT 'unreviewed';
ALTER TABLE workspace_brand_assets ADD COLUMN last_checked_at TEXT;
ALTER TABLE workspace_brand_assets ADD COLUMN mx_present INTEGER;
ALTER TABLE workspace_brand_assets ADD COLUMN registrar_or_whois_summary TEXT;
ALTER TABLE workspace_brand_assets ADD COLUMN evidence_json TEXT;

CREATE INDEX IF NOT EXISTS idx_brand_assets_classification
    ON workspace_brand_assets (workspace_id, classification, risk_level);

