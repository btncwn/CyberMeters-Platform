-- ── 057-dmarc-email-route-automation.sql ────────────────────────────────────
-- Cloudflare Email Routing exact-address automation state.
--
-- Apply before deploying the corresponding Worker:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/057-dmarc-email-route-automation.sql
--
-- Additive rollback strategy:
--   Leave nullable columns in place and deploy the previous Worker version.
--   SQLite/D1 column removal would require a table rebuild and is intentionally
--   avoided for production safety.
--
-- CLOUDFLARE_API_TOKEN is never stored in D1. cloudflare_route_error contains
-- only a stable allow-listed reason, never a raw Cloudflare response body.

ALTER TABLE dmarc_ingest_endpoints ADD COLUMN cloudflare_route_id TEXT;
ALTER TABLE dmarc_ingest_endpoints ADD COLUMN cloudflare_route_status TEXT;
ALTER TABLE dmarc_ingest_endpoints ADD COLUMN cloudflare_route_error TEXT;
ALTER TABLE dmarc_ingest_endpoints ADD COLUMN cloudflare_route_created_at TEXT;
ALTER TABLE dmarc_ingest_endpoints ADD COLUMN cloudflare_route_updated_at TEXT;

