-- ── 059-lifecycle-emails.sql ─────────────────────────────────────────────────
-- Customer Lifecycle Emails v1.
--
-- Persisted, idempotent record of lifecycle (activation) emails so each one is
-- sent at most once per scope. The UNIQUE index on dedupe_key is the dedupe
-- guarantee — sends are gated by INSERT ... ON CONFLICT(dedupe_key) DO NOTHING.
-- Additive and backwards-compatible: no existing table or API changes.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/059-lifecycle-emails.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS lifecycle_email_events;

CREATE TABLE IF NOT EXISTS lifecycle_email_events (
    id           TEXT PRIMARY KEY,
    user_id      TEXT,
    workspace_id TEXT,
    domain       TEXT,
    type         TEXT NOT NULL,        -- lifecycle_welcome | lifecycle_workspace_created | ...
    dedupe_key   TEXT NOT NULL,        -- stable per (type + scope); see lifecycleDedupeKey()
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | sent | failed
    provider_id  TEXT,                 -- Resend message id (never a secret)
    error        TEXT,                 -- safe reason enum only (e.g. 'timeout'); never raw errors
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at      TEXT
);

-- Dedupe guarantee: one lifecycle email per scope.
CREATE UNIQUE INDEX IF NOT EXISTS idx_lifecycle_email_dedupe
    ON lifecycle_email_events (dedupe_key);

-- Operational lookups.
CREATE INDEX IF NOT EXISTS idx_lifecycle_email_ws
    ON lifecycle_email_events (workspace_id, type);
