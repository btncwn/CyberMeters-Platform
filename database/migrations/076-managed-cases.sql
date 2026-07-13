-- ── 076-managed-cases.sql ─────────────────────────────────────────────────
-- Generic managed remediation cases + tenant-scoped case timeline.
-- Additive only: enums are application-owned; no CHECK constraints.

ALTER TABLE audit_events ADD COLUMN actor_type TEXT;

CREATE TABLE IF NOT EXISTS managed_cases (
    id                       TEXT PRIMARY KEY,
    workspace_id             TEXT NOT NULL,
    case_type                TEXT NOT NULL,
    domain                   TEXT,
    finding_id               TEXT,
    asset_ref                TEXT,
    severity                 TEXT NOT NULL DEFAULT 'medium',
    status                   TEXT NOT NULL DEFAULT 'open',
    owner_type               TEXT,
    owner_ref                TEXT,
    assigned_by              TEXT,
    evidence_json            TEXT,
    recommended_actions_json TEXT,
    reason                   TEXT,
    risk_accepted_until      TEXT,
    due_at                   TEXT,
    last_verified_at         TEXT,
    resolved_at              TEXT,
    reopened_count           INTEGER NOT NULL DEFAULT 0,
    created_by               TEXT,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at               TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_managed_cases_queue
  ON managed_cases (workspace_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_managed_cases_workspace_finding
  ON managed_cases (workspace_id, domain, finding_id);

CREATE INDEX IF NOT EXISTS idx_managed_cases_status
  ON managed_cases (status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_cases_open_dedup
  ON managed_cases (workspace_id, domain, finding_id)
  WHERE status NOT IN ('false_positive', 'closed', 'risk_accepted');

CREATE TABLE IF NOT EXISTS managed_case_events (
    id           TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    actor_type   TEXT NOT NULL,
    actor_id     TEXT,
    from_status  TEXT,
    to_status    TEXT,
    action       TEXT NOT NULL,
    detail_json  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_managed_case_events_case
  ON managed_case_events (case_id, created_at);
