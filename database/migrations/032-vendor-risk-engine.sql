-- ── 032-vendor-risk-engine.sql ──────────────────────────────────────────────
-- Vendor Risk Engine v1.
--
-- Adds persisted vendor scoring records. Existing workspace_vendors remains the
-- source inventory table; vendor_risk_scores stores the latest calculated score
-- per workspace vendor relationship. vendor_risk_scores_history is append-only
-- and records a minimal score snapshot every time recompute runs.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/032-vendor-risk-engine.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS vendor_risk_scores;
--   DROP TABLE IF EXISTS vendor_risk_scores_history;

CREATE TABLE IF NOT EXISTS vendor_risk_scores (
    vendor_id             TEXT NOT NULL,
    workspace_id          TEXT NOT NULL,
    score                 INTEGER NOT NULL DEFAULT 0,
    category_multiplier   REAL NOT NULL DEFAULT 1.0,
    concentration_penalty INTEGER NOT NULL DEFAULT 0,
    updated_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vendor_id, workspace_id),
    FOREIGN KEY (vendor_id) REFERENCES workspace_vendors(id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_vendor_risk_scores_workspace
    ON vendor_risk_scores (workspace_id, score DESC);

CREATE TABLE IF NOT EXISTS vendor_risk_scores_history (
    id            TEXT PRIMARY KEY,
    vendor_id     TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    score         INTEGER NOT NULL DEFAULT 0,
    snapshot_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES workspace_vendors(id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_vendor_risk_scores_history_workspace
    ON vendor_risk_scores_history (workspace_id, snapshot_time DESC);

CREATE INDEX IF NOT EXISTS idx_vendor_risk_scores_history_vendor
    ON vendor_risk_scores_history (vendor_id, snapshot_time DESC);
