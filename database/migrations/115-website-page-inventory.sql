-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 115: Website Security important-page inventory
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Additive only. Website Security observed exactly one page (the homepage and its
-- canonical/www variants). engines/page-discovery.js now observes a bounded set of the
-- site's own public pages (homepage links, sitemap, a short well-known list; at most
-- 15 pages, passive GETs, the scanned host and its www/apex sibling only). These
-- tables give those pages CONTINUITY: when a page was first seen, when it was last
-- seen, and whether a page that existed now answers 404/410.
--
-- WHY NEW TABLES, not website_security_conditions (mig 089): that table's identity is
-- (workspace, domain, condition_key) by an explicit honesty decision — no website
-- finding carried a path. A page is a different entity (workspace, domain, path) with
-- its own evidence; folding pages into condition rows would invent attribution 089
-- deliberately refused. Not workspace_assets either: that is one row per HOST owned by
-- Attack Surface.
--
-- HONESTY (permanent):
--   • a page is `not_found` ONLY when it was actually requested in that scan and
--     answered 404/410; a page not requested in a scan is left untouched (the crawl
--     is bounded and its selection can vary, so absence from one run proves nothing);
--   • `unconfirmed` means it was requested but the answer could not establish the
--     page (redirect to the homepage, error, timeout, off-site redirect, not HTML);
--   • observation JSON never contains cookie values or raw HTML.
--
-- Rollback: leave the schema; roll back application code. With no writer the tables
-- simply stop receiving rows. Purge: all three are workspace-scoped and registered in
-- WORKSPACE_PURGE_TABLES (events and runs before pages).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/115-website-page-inventory.sql

CREATE TABLE IF NOT EXISTS website_pages (
    id                     TEXT PRIMARY KEY,      -- wsp-<hex>
    workspace_id           TEXT NOT NULL,
    domain_id              TEXT NOT NULL,
    domain                 TEXT NOT NULL,         -- display only
    path                   TEXT NOT NULL,         -- normalised path, no query/fragment

    monitoring_status      TEXT NOT NULL,         -- observed | not_found | unconfirmed
    sensitive_kind         TEXT,                  -- login | admin | account | checkout | NULL
    discovery_source       TEXT,                  -- homepage | homepage_link | sitemap | well_known
    last_outcome           TEXT NOT NULL,         -- page-discovery outcome of the last request
    last_status_code       INTEGER,
    last_final_url         TEXT,
    last_observation_json  TEXT,                  -- headers/cookie flags/forms/mixed/scripts (no values, no HTML)

    first_seen_at          TEXT,                  -- first time the page was OBSERVED
    last_seen_at           TEXT,                  -- last time the page was OBSERVED
    last_checked_at        TEXT NOT NULL,         -- last time it was requested at all
    last_scan_id           TEXT,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,

    UNIQUE (workspace_id, domain_id, path)
);

CREATE INDEX IF NOT EXISTS idx_website_pages_ws_domain
    ON website_pages (workspace_id, domain_id, monitoring_status);

-- Append-only page history. Deterministic ids make a re-run of the same scan a no-op.
CREATE TABLE IF NOT EXISTS website_page_events (
    id            TEXT PRIMARY KEY,               -- wspe-<scan>-<page>-<type>
    workspace_id  TEXT NOT NULL,
    domain_id     TEXT NOT NULL,
    page_id       TEXT NOT NULL,
    path          TEXT NOT NULL,
    scan_id       TEXT,
    event_type    TEXT NOT NULL,                  -- page_first_seen | page_not_found | page_reappeared
    detail_json   TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_website_page_events_ws_page
    ON website_page_events (workspace_id, page_id, created_at);

-- One row per (workspace, domain, scan): what this crawl covered and why it was
-- partial. Lets a surface say "15 of up to 15 pages checked" or "partial: time budget"
-- without re-reading the R2 report.
CREATE TABLE IF NOT EXISTS website_page_discovery_runs (
    id                    TEXT PRIMARY KEY,       -- wspr-<scan>-<workspace>
    workspace_id          TEXT NOT NULL,
    domain_id             TEXT NOT NULL,
    scan_id               TEXT NOT NULL,
    coverage              TEXT NOT NULL,          -- complete | partial | not_run
    partial_reasons_json  TEXT,
    counts_json           TEXT,
    module_version        TEXT,
    observed_at           TEXT NOT NULL,
    UNIQUE (workspace_id, domain_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_website_page_runs_ws_domain
    ON website_page_discovery_runs (workspace_id, domain_id, observed_at);
