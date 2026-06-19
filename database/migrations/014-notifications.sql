-- ── 014-notifications.sql ─────────────────────────────────────────────────────
-- Adds in-app notification infrastructure.
-- All changes are additive — no existing tables modified.
--
-- notification_events  — the canonical log of events to surface in the UI.
-- notification_preferences — per-user per-workspace opt-in/out settings (v1 stub).
--
-- Event types (type column):
--   scan_completed        — a domain scan finished successfully
--   scan_failed           — a scan engine error occurred
--   critical_finding      — ≥1 critical severity finding in a completed scan
--   high_finding          — ≥1 high severity finding in a completed scan
--   domain_verified       — domain ownership verification succeeded
--   report_generated      — an executive report was generated
--   asset_change          — surface change detected (new/removed asset)
--
-- Status values:
--   unread  — created, not yet seen by the user
--   read    — user has dismissed/viewed the notification
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/014-notifications.sql

-- ── notification_events ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS notification_events (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    user_id      TEXT,                        -- NULL means workspace-global
    type         TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'info', -- critical | high | medium | low | info
    title        TEXT NOT NULL,
    message      TEXT,
    metadata_json TEXT,                        -- arbitrary JSON payload (scan_id, domain, etc.)
    status       TEXT NOT NULL DEFAULT 'unread',
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    read_at      TEXT,
    sent_at      TEXT                          -- when/if an email was also sent
);

-- Fast per-workspace listing (most common query)
CREATE INDEX IF NOT EXISTS idx_notif_workspace_created
  ON notification_events (workspace_id, created_at DESC);

-- Filter by status (unread badge count)
CREATE INDEX IF NOT EXISTS idx_notif_workspace_status
  ON notification_events (workspace_id, status);

-- Filter by type
CREATE INDEX IF NOT EXISTS idx_notif_type
  ON notification_events (type);

-- ── notification_preferences ──────────────────────────────────────────────────
-- v1 stub: stores default preferences per workspace.
-- Expanded in a future sprint to support per-user channel preferences.

CREATE TABLE IF NOT EXISTS notification_preferences (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    user_id      TEXT,
    event_type   TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,   -- 1 = on, 0 = off
    channel      TEXT NOT NULL DEFAULT 'in_app', -- in_app | email (future)
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (workspace_id, user_id, event_type, channel)
);

CREATE INDEX IF NOT EXISTS idx_notif_prefs_workspace
  ON notification_preferences (workspace_id);
