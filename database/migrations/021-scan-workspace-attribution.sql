-- Migration 021: Scan Workspace Attribution
-- Adds workspace_id to scans table for direct scan→workspace attribution.
-- Historical scans (workspace_id IS NULL) continue to work via the existing
-- workspace_domains→domains→scans join fallback.

ALTER TABLE scans ADD COLUMN workspace_id TEXT;

CREATE INDEX IF NOT EXISTS idx_scans_workspace ON scans (workspace_id);
