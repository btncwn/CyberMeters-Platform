-- Migration 007: Posture & Attack Surface Growth Metrics — supporting indexes
-- Apply: wrangler d1 execute cybermeters-db --remote --file=database/migrations/007-posture-indexes.sql

-- Covers: workspace_assets WHERE workspace_id = ? AND first_seen >= ?
-- Used by: GET /api/workspaces/:id/posture (new_assets_30d)
CREATE INDEX IF NOT EXISTS idx_workspace_assets_first_seen
    ON workspace_assets (workspace_id, first_seen);

-- Covers: scans WHERE domain_id = ? AND created_at >= ? (AND status = 'completed')
-- Used by: GET /api/workspaces/:id/posture (score/risk trend via JOIN with workspace_domains)
CREATE INDEX IF NOT EXISTS idx_scans_domain_created
    ON scans (domain_id, created_at);
