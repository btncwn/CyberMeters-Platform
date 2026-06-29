-- ── 056-dmarc-inbound-rua.sql ────────────────────────────────────────────────
-- Assisted RUA Ingestion v1 (Phase 2).
--
-- Additive only. Adds inbound-reporting bookkeeping to the existing ingestion
-- endpoint table so a workspace+domain can receive DMARC aggregate (RUA) reports
-- by email at an opaque address (dmarc_ingest_endpoints.address_local, already
-- present from migration 055). No existing column is altered or dropped, no
-- existing API response changes, and the DMARC dedupe UNIQUE index is untouched
-- (dedupe stays source-agnostic across manual_paste / signed_upload / inbound_email).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/056-dmarc-inbound-rua.sql
--
-- Rollback:
--   DROP INDEX IF EXISTS idx_dmarc_ingest_endpoints_address;
--   -- last_inbound_at / last_signed_upload_at are harmless to leave in place.

-- Distinguish the two automated ingestion paths in the UI ("last received" vs
-- "last uploaded"). last_used_at continues to track the most recent of either.
ALTER TABLE dmarc_ingest_endpoints ADD COLUMN last_inbound_at TEXT;
ALTER TABLE dmarc_ingest_endpoints ADD COLUMN last_signed_upload_at TEXT;

-- Inbound email resolves the recipient localpart to exactly one endpoint. A
-- UNIQUE index guarantees no two endpoints share an address. SQLite/D1 allows
-- multiple NULLs in a UNIQUE index, so Sprint-1 endpoints (address_local IS NULL)
-- until they are activated do not conflict.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dmarc_ingest_endpoints_address
    ON dmarc_ingest_endpoints (address_local);
