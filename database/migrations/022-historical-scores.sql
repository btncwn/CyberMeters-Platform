-- ── 022-historical-scores.sql ───────────────────────────────────────────────
-- Stores one workspace-attributed score snapshot per completed scan.
-- This is additive and does not alter existing scan/report data.

CREATE TABLE IF NOT EXISTS historical_scores (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id    TEXT NOT NULL,
    scan_id      TEXT NOT NULL,
    domain       TEXT NOT NULL,
    score        INTEGER,
    rating       TEXT,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (workspace_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_historical_scores_workspace_created
  ON historical_scores (workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_historical_scores_domain_created
  ON historical_scores (domain_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_historical_scores_scan
  ON historical_scores (scan_id);
