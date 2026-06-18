-- Migration 005: Asset Change Alert Records
-- CyberMeters ASM — dedup log for per-workspace per-scan asset change emails.
-- Apply: wrangler d1 execute cybermeters-db --remote --file=database/migrations/005-asset-alerts.sql

-- One row per (workspace_id, scan_id).
-- UNIQUE constraint is the primary spam-prevention mechanism:
--   INSERT OR IGNORE fails silently when a record already exists, so
--   sendAssetChangeAlert() never fires twice for the same scan.

CREATE TABLE IF NOT EXISTS asset_alert_records (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL,
    scan_id       TEXT NOT NULL,
    domain        TEXT,
    severity      TEXT NOT NULL DEFAULT 'info',  -- info | medium | high | critical
    event_counts  TEXT NOT NULL,                 -- JSON { new_asset_discovered: N, ... }
    top_hostnames TEXT,                          -- JSON array of up to 5 hostnames
    sent_at       TEXT NOT NULL,

    UNIQUE (workspace_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_alert_records_workspace
    ON asset_alert_records (workspace_id, sent_at DESC);
