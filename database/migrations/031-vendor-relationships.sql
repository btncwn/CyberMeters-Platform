-- Migration 031: Vendor Relationship Discovery
-- Adds source_module tracking to workspace_vendors so vendor_risk entries
-- (DNS/MX/SPF signal detection) can be distinguished from vendor_relationship
-- entries (CSP directive analysis, external JS, SaaS hostname patterns).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/031-vendor-relationships.sql
--
-- Rollback:
--   ALTER TABLE workspace_vendors DROP COLUMN source_module;
--   DROP INDEX IF EXISTS idx_workspace_vendors_source;

-- Add source_module column (safe to run multiple times — ADD COLUMN is idempotent
-- in SQLite when the column does not already exist; D1 will silently succeed on
-- a re-run if the column already exists via a prior partial run).
ALTER TABLE workspace_vendors ADD COLUMN source_module TEXT NOT NULL DEFAULT 'vendor_risk';

-- Index to support filtering by source module (e.g. vendor-relationships endpoint)
CREATE INDEX IF NOT EXISTS idx_workspace_vendors_source
    ON workspace_vendors (workspace_id, source_module, status);
