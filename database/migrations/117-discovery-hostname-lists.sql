-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 117: Attack Surface — hostname lists supplied by the customer
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Additive only. A workspace admin may list hostnames under one of the
-- workspace's VERIFIED domains (a plain list, a CSV with a hostname column or a
-- DNS zone file), so each scan asks DNS about them. A listed name is a
-- candidate, never a discovered host: it joins discovery only when DNS answers
-- for it in a scan (engines/discovery-hostname-list.js).
--
-- Only in-scope hostnames are stored (at most 200 per list), never the
-- uploaded text. History is append-only: a save supersedes the active list and
-- adds a new row; clearing, or removing the domain from the workspace, marks
-- the active list cleared. Rows are hard-deleted only by the workspace purge.
--
-- Rollback: leave the schema; roll back application code (no reader/writer =
-- inert). Purge: workspace-scoped and in WORKSPACE_PURGE_TABLES.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/117-discovery-hostname-lists.sql

CREATE TABLE IF NOT EXISTS discovery_hostname_lists (
    id                     TEXT PRIMARY KEY,          -- dhl_<uuid>
    workspace_id           TEXT NOT NULL,
    domain_id              TEXT NOT NULL,
    status                 TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'cleared')),
    import_format          TEXT NOT NULL CHECK (import_format IN ('list', 'csv', 'zone')),
    hostnames_json         TEXT NOT NULL,             -- sorted in-scope hostnames
    hostname_count         INTEGER NOT NULL CHECK (hostname_count BETWEEN 1 AND 200),
    entries_examined       INTEGER NOT NULL DEFAULT 0,
    out_of_scope_count     INTEGER NOT NULL DEFAULT 0,
    rejected_count         INTEGER NOT NULL DEFAULT 0,
    truncated              INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    rejected_reasons_json  TEXT NOT NULL DEFAULT '[]', -- reason codes only
    created_by             TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    ended_at               TEXT,                      -- superseded or cleared
    ended_by               TEXT
);

-- At most one active list per workspace domain.
CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_hostname_lists_active
    ON discovery_hostname_lists(workspace_id, domain_id) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_discovery_hostname_lists_ws_domain
    ON discovery_hostname_lists(workspace_id, domain_id, created_at DESC);
