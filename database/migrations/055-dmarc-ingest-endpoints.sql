-- ── 055-dmarc-ingest-endpoints.sql ───────────────────────────────────────────
-- Assisted DMARC Upload v1 Foundation.
--
-- Adds ingestion-source tracking to the existing DMARC report table and a new
-- per-workspace+domain ingestion endpoint (signed-upload key) table. This is
-- the secure shared-ingestion foundation that later supports true inbound RUA
-- email ingestion (Phase 2). Additive and backwards-compatible — no existing
-- table column is altered or dropped, no existing API response changes, and the
-- DMARC dedupe behaviour is intentionally left untouched and source-agnostic.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/055-dmarc-ingest-endpoints.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS dmarc_ingest_endpoints;
--   -- NOTE: SQLite/D1 cannot DROP COLUMN cleanly; the `source` column is
--   -- harmless to leave in place (defaults to 'manual_paste'). To fully revert,
--   -- rebuild dmarc_aggregate_reports without the column.

-- ── Source tracking on the existing report table ─────────────────────────────
-- Records which ingestion path produced a report. Existing rows backfill to
-- 'manual_paste' via the column default. Valid values:
--   manual_paste   (Phase 1 — existing UI paste)
--   signed_upload  (Phase 1 — token-authenticated POST /api/dmarc-ingest)
--   inbound_email  (Phase 2 — reserved; not used yet)
-- The report dedupe UNIQUE index (idx_dmarc_reports_dedupe) does NOT include
-- source, so the same report arriving via two different sources is counted once.
ALTER TABLE dmarc_aggregate_reports
    ADD COLUMN source TEXT NOT NULL DEFAULT 'manual_paste';

-- ── Ingestion endpoints (one signed-upload key per workspace+domain) ─────────
-- Stores ONLY the SHA-256 hash of the upload token. The raw token is shown to
-- the user exactly once at create/rotate time and is never persisted. The token
-- is scoped to exactly one workspace + domain and may only append DMARC report
-- data — it cannot read data, classify senders, or access workspace details.
-- address_local is reserved for Phase 2 (inbound RUA email) and stays NULL here.
CREATE TABLE IF NOT EXISTS dmarc_ingest_endpoints (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL,
    domain_id     TEXT NOT NULL,
    domain        TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    address_local TEXT,
    status        TEXT NOT NULL DEFAULT 'active',   -- active | revoked
    created_by    TEXT,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    rotated_at    TEXT,
    revoked_at    TEXT,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Primary lookup: resolve a workspace+domain's current endpoint (management UI).
CREATE INDEX IF NOT EXISTS idx_dmarc_ingest_endpoints_ws_domain
    ON dmarc_ingest_endpoints (workspace_id, domain, status);

-- Token resolution at ingest time is by token_hash (already UNIQUE above).
