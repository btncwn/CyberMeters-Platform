-- Migration 043: Deletion Requests
-- Stores GDPR/account and workspace deletion requests for manual review.
-- No data is hard-deleted by this migration or the v1 API.

CREATE TABLE IF NOT EXISTS deletion_requests (
    id           TEXT PRIMARY KEY,
    request_type TEXT NOT NULL, -- account | workspace
    user_id      TEXT NOT NULL,
    workspace_id TEXT,
    requested_by TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    reason       TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_deletion_requests_user
  ON deletion_requests (user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_deletion_requests_workspace
  ON deletion_requests (workspace_id, status, created_at DESC);
