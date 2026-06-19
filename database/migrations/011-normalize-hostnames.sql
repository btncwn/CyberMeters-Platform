-- ── 011-normalize-hostnames.sql ──────────────────────────────────────────────
-- Backfill: normalize hostname values in workspace_assets and asset_events.
-- Fixes rows written before normalizeHostname() was applied to all code paths.
--
-- Three passes per table, each idempotent (safe to re-run):
--   1. Strip https:// and http:// scheme prefixes
--   2. Strip path suffix (everything from the first "/" onward)
--   3. Lowercase
--
-- Port-stripping (e.g. "host:8443") is not handled in SQLite without a regex
-- extension; port-bearing hostnames are extremely rare in practice.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/011-normalize-hostnames.sql

-- ── workspace_assets ──────────────────────────────────────────────────────────

-- Pass 1a: strip https://
UPDATE workspace_assets
SET hostname = REPLACE(hostname, 'https://', '')
WHERE hostname LIKE 'https://%';

-- Pass 1b: strip http://
UPDATE workspace_assets
SET hostname = REPLACE(hostname, 'http://', '')
WHERE hostname LIKE 'http://%';

-- Pass 2: strip path (everything from first "/" onward)
UPDATE workspace_assets
SET hostname = SUBSTR(hostname, 1, INSTR(hostname, '/') - 1)
WHERE INSTR(hostname, '/') > 0;

-- Pass 3: lowercase
UPDATE workspace_assets
SET hostname = LOWER(hostname)
WHERE hostname != LOWER(hostname);

-- ── asset_events ──────────────────────────────────────────────────────────────

UPDATE asset_events
SET hostname = REPLACE(hostname, 'https://', '')
WHERE hostname LIKE 'https://%';

UPDATE asset_events
SET hostname = REPLACE(hostname, 'http://', '')
WHERE hostname LIKE 'http://%';

UPDATE asset_events
SET hostname = SUBSTR(hostname, 1, INSTR(hostname, '/') - 1)
WHERE hostname IS NOT NULL AND INSTR(hostname, '/') > 0;

UPDATE asset_events
SET hostname = LOWER(hostname)
WHERE hostname IS NOT NULL AND hostname != LOWER(hostname);
