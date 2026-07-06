-- ── 062-hosted-dns-records.sql ───────────────────────────────────────────────
-- Hosted Records Engine, Phase A: hosted DMARC.
--
-- The customer touches their DNS once (CNAME _dmarc.<domain> →
-- <id>.dmarc.cybermeters.com); CyberMeters manages the TXT value on its own
-- zone via the Cloudflare DNS API. Phase A hosts a value that mirrors the
-- customer's existing record (merged with our RUA) — policy transitions come
-- in Phase B. The hourly sweep verifies both sides (our TXT live, customer
-- CNAME still pointing) and never deletes a hosted TXT while the customer's
-- _dmarc still depends on it.
--
-- Statuses:
--   pending_dns     — row created; our TXT not observable yet (CF create retried by sweep)
--   awaiting_cname  — our TXT live; customer CNAME not detected yet
--   connected       — customer's _dmarc resolves to our value
--   disconnected    — was connected; customer CNAME no longer points at us (alerted)
--   pending_removal — deletion requested; TXT kept until CNAME is gone or grace expires
--
-- Known limitation (documented): purging a workspace removes these rows but
-- cannot call the Cloudflare API; orphaned TXT records on our zone are inert
-- (nothing points at them) and are cleaned up manually or by a later sweep.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/062-hosted-dns-records.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS hosted_dns_records;

CREATE TABLE IF NOT EXISTS hosted_dns_records (
    id               TEXT PRIMARY KEY,     -- 'hd-' + 12 hex; DNS-safe (LDH), doubles as the host label
    workspace_id     TEXT NOT NULL,
    domain           TEXT NOT NULL,        -- customer domain the record serves (lowercase)
    record_type      TEXT NOT NULL DEFAULT 'dmarc' CHECK (record_type IN ('dmarc')),
    hosted_name      TEXT NOT NULL,        -- '<id>.dmarc.cybermeters.com'
    current_value    TEXT NOT NULL,        -- the TXT value we serve
    previous_value   TEXT,                 -- one-click rollback target (Phase B)
    cf_record_id     TEXT,                 -- Cloudflare DNS record id; never exposed via API
    status           TEXT NOT NULL DEFAULT 'pending_dns'
                     CHECK (status IN ('pending_dns','awaiting_cname','connected','disconnected','pending_removal')),
    last_verified_at TEXT,
    last_change_at   TEXT,
    created_by       TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- One hosted record per (workspace, domain, type).
CREATE UNIQUE INDEX IF NOT EXISTS idx_hosted_dns_scope
    ON hosted_dns_records (workspace_id, domain, record_type);

CREATE INDEX IF NOT EXISTS idx_hosted_dns_status
    ON hosted_dns_records (status);
