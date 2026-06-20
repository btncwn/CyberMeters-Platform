-- ── 034-workspace-brs-score-history.sql ─────────────────────────────────────
-- Business Risk Score Engine v1 append-only score snapshots.
--
-- Keeps historical BRS calculations while workspace_brs_scores remains the
-- latest snapshot table.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/034-workspace-brs-score-history.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS workspace_brs_score_history;

CREATE TABLE IF NOT EXISTS workspace_brs_score_history (
    id             TEXT PRIMARY KEY,
    workspace_id   TEXT NOT NULL,
    score          INTEGER NOT NULL,
    risk_band      TEXT NOT NULL,
    calculated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_brs_score_history_workspace
    ON workspace_brs_score_history (workspace_id, calculated_at DESC);
