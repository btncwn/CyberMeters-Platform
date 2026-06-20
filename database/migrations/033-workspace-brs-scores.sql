-- ── 033-workspace-brs-scores.sql ────────────────────────────────────────────
-- Business Risk Score Engine v1 lightweight persistence.
--
-- Stores the latest calculated Business Risk Score per workspace. The score is
-- fully derived from existing ASM scan, asset, findings, and vendor-risk data.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/033-workspace-brs-scores.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS workspace_brs_scores;

CREATE TABLE IF NOT EXISTS workspace_brs_scores (
    workspace_id   TEXT PRIMARY KEY,
    score          INTEGER NOT NULL,
    risk_band      TEXT NOT NULL,
    calculated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);
