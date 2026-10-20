-- Migration 131: the daily free-check canary.
--
-- Each morning the API runs the free-scan target check and the DMARC and SPF
-- free tools against a fixed list of about twenty public domains (the corpus
-- the free scan is regression-tested against) and keeps one row per domain:
-- the latest short outcome fingerprint, the one before it, and when it last
-- changed. A change or an error is put at the top of the founder's 08:00
-- email. Only those public corpus domains are stored; no customer domain,
-- account or workspace is involved.
--
-- Additive only.
--
-- Apply (before the Worker deploy — the 07:00 cron writes this table):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/131-ops-canary-results.sql
--
-- Rollback:
--   Roll the Worker back first. The table can stay; nothing else reads it.

CREATE TABLE IF NOT EXISTS ops_canary_results (
  domain               TEXT PRIMARY KEY,
  checked_at           TEXT NOT NULL,
  fingerprint          TEXT NOT NULL,
  previous_fingerprint TEXT,
  changed_at           TEXT,
  outcome              TEXT NOT NULL
);
