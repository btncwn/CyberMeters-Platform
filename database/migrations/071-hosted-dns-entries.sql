-- Hosted DNS v2 — one bounded-context table for every managed record kind.
--
-- 062's hosted_dns_records pinned record_type with CHECK (record_type IN ('dmarc')),
-- which cannot be widened in SQLite without a DROP TABLE rebuild — forbidden by
-- our additive-only migration guard. So Hosted DNS is rebuilt as a clean bounded
-- context: hosted_dns_entries carries DMARC, TLS-RPT, MTA-STS and SPF on one
-- schema, with NO CHECK on record_kind / verification_state (both enums live in
-- application code, so a new record kind never needs another migration).
--
-- Fully additive: hosted_dns_records is left in place (retired only by a separate,
-- explicitly-approved cleanup). The backfill is idempotent (INSERT OR IGNORE on
-- the id PK) so it is safe to re-run after cutover to sweep up stragglers.
-- Built for real customer volume — the column mapping is exhaustive and verified
-- by scripts/validate-hosted-dns-v2.js, not eyeballed.

CREATE TABLE IF NOT EXISTS hosted_dns_entries (
    id                  TEXT PRIMARY KEY,   -- 'hd-'+12hex; DNS-safe, doubles as the managed host label
    workspace_id        TEXT NOT NULL,
    domain              TEXT NOT NULL,       -- customer domain the record serves (lowercase)
    domain_id           TEXT,                -- optional FK-ish link; populated on new creates
    record_kind         TEXT NOT NULL DEFAULT 'dmarc',   -- dmarc|tlsrpt|mtasts|spf — enum in code, NO CHECK
    customer_name       TEXT NOT NULL,       -- the record the customer CNAMEs to us (_dmarc.<d>, _smtp._tls.<d>, …)
    target_name         TEXT NOT NULL,       -- our managed name they point at ('<id>.dmarc.cybermeters.com')
    target_value        TEXT NOT NULL,       -- the value we serve (e.g. the TXT body)
    provider            TEXT NOT NULL DEFAULT 'cloudflare',  -- DNS provider abstraction seam
    provider_record_id  TEXT,                -- provider's record id; never exposed via API
    verification_state  TEXT NOT NULL DEFAULT 'pending_dns', -- pending_dns|awaiting_cname|connected|disconnected|pending_removal — enum in code, NO CHECK
    -- write-ahead saga / retry (generic to every kind)
    previous_value      TEXT,
    pending_value       TEXT,
    pending_since       TEXT,
    failure_count       INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,
    -- dmarc-only ramp/self-driving state (nullable; other kinds leave these NULL)
    autopilot           INTEGER NOT NULL DEFAULT 0,
    pass_rate_at_change REAL,
    -- lifecycle timestamps + audit
    published_at        TEXT,
    verified_at         TEXT,
    last_change_at      TEXT,
    created_by          TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- One hosted record per (workspace, domain, kind) — same guarantee 062 gave DMARC.
CREATE UNIQUE INDEX IF NOT EXISTS idx_hosted_dns_entries_scope
    ON hosted_dns_entries (workspace_id, domain, record_kind);
CREATE INDEX IF NOT EXISTS idx_hosted_dns_entries_state
    ON hosted_dns_entries (verification_state);

-- Idempotent backfill of existing hosted DMARC records into the unified table.
-- INSERT OR IGNORE keeps re-runs safe (id PK). On a fresh schema (harness) the
-- source table is empty and this is a no-op.
INSERT OR IGNORE INTO hosted_dns_entries (
    id, workspace_id, domain, domain_id, record_kind, customer_name, target_name,
    target_value, provider, provider_record_id, verification_state,
    previous_value, pending_value, pending_since, failure_count, last_error,
    autopilot, pass_rate_at_change, published_at, verified_at, last_change_at,
    created_by, created_at, updated_at
)
SELECT
    id, workspace_id, domain, NULL, record_type, '_dmarc.' || domain, hosted_name,
    current_value, 'cloudflare', cf_record_id, status,
    previous_value, pending_value, pending_since, failure_count, last_error,
    autopilot, pass_rate_at_change, NULL, last_verified_at, last_change_at,
    created_by, created_at, updated_at
FROM hosted_dns_records
WHERE record_type = 'dmarc';
