-- ── 017-audit-trail.sql ────────────────────────────────────────────────────
-- Adds the audit_events table for workspace activity and audit trail v1.
-- Purely additive — no existing tables are modified.
--
-- Design notes:
--   workspace_id  — nullable for user-level events (login, logout)
--   user_id       — nullable for system-generated events (scheduled scans)
--   entity_type   — the type of object acted upon (domain, scan, member, report…)
--   entity_id     — the specific object's id
--   metadata_json — arbitrary JSON context for the event
--
-- Event types:
--   auth:     login | logout
--   workspace: workspace_created | workspace_member_added | workspace_member_removed
--   domain:   domain_added | domain_imported | domain_verified
--   report:   report_generated
--   scan:     scan_started | scan_completed
--   notification: notification_read
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/017-audit-trail.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS audit_events;

CREATE TABLE IF NOT EXISTS audit_events (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT,                      -- nullable: login/logout have no workspace
    user_id       TEXT,                      -- nullable: system events (scheduled scans)
    event_type    TEXT NOT NULL,             -- e.g. 'domain_verified', 'scan_completed'
    entity_type   TEXT,                      -- e.g. 'domain', 'scan', 'member', 'report'
    entity_id     TEXT,                      -- id of the entity acted upon
    description   TEXT,                      -- human-readable summary
    metadata_json TEXT,                      -- arbitrary JSON context
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Fast lookup: all events for a workspace (primary query for /activity endpoint)
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_id
  ON audit_events (workspace_id, created_at DESC)
  WHERE workspace_id IS NOT NULL;

-- Fast lookup: all events by a specific user (user activity history)
CREATE INDEX IF NOT EXISTS idx_audit_events_user_id
  ON audit_events (user_id, created_at DESC)
  WHERE user_id IS NOT NULL;

-- Fast lookup: events by type within a workspace (filtering)
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type
  ON audit_events (workspace_id, event_type, created_at DESC)
  WHERE workspace_id IS NOT NULL;
