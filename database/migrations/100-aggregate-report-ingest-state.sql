-- ── 100-aggregate-report-ingest-state.sql ───────────────────────────────────
-- PR-5.5 Gate 3B: atomic, repairable DMARC / TLS-RPT ingestion.
--
-- One claim is the durable state machine for one report identity in one trust
-- scope. Every identity column participating in the UNIQUE index is NOT NULL,
-- so SQLite NULL semantics cannot bypass dedupe. `source_scope` deliberately
-- separates authenticated customer submissions from observational inbound
-- email; an untrusted first arrival cannot suppress a later authoritative copy.
--
-- New ingestion writes a pending claim first, then commits report metadata,
-- children/rollups, and the complete transition in one D1 batch transaction.
-- A failed batch leaves no partial report rows and the claim becomes failed,
-- ready for a later delivery to reacquire.
--
-- Existing reports are backfilled as complete only when their persisted child
-- count matches the parent count; known partials become failed/repairable.
-- INSERT OR IGNORE keeps this additive and safe even if a legacy nullable-key
-- duplicate already exists; no historical report row is deleted or rewritten.
--
-- Apply (founder-gated; NOT applied by this PR):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/100-aggregate-report-ingest-state.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS aggregate_report_ingest_claims;
--   ALTER TABLE tlsrpt_aggregate_reports DROP COLUMN source;

ALTER TABLE tlsrpt_aggregate_reports
    ADD COLUMN source TEXT NOT NULL DEFAULT 'inbound_email';

CREATE TABLE IF NOT EXISTS aggregate_report_ingest_claims (
    id                    TEXT PRIMARY KEY,
    report_type           TEXT NOT NULL CHECK (report_type IN ('dmarc', 'tlsrpt')),
    workspace_id          TEXT NOT NULL,
    domain                TEXT NOT NULL,
    source                TEXT NOT NULL,
    source_scope          TEXT NOT NULL CHECK (source_scope IN ('authoritative', 'observational')),
    identity_org_name     TEXT NOT NULL,
    identity_report_id    TEXT NOT NULL,
    identity_date_begin   TEXT NOT NULL,
    identity_date_end     TEXT NOT NULL,
    report_id             TEXT NOT NULL,
    content_hash          TEXT NOT NULL,
    ingest_state          TEXT NOT NULL CHECK (ingest_state IN ('pending', 'complete', 'failed')),
    attempt_token         TEXT NOT NULL,
    lease_expires_at      TEXT,
    failure_code          TEXT,
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at          TEXT,
    failed_at             TEXT,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_aggregate_report_ingest_identity
    ON aggregate_report_ingest_claims (
        report_type,
        workspace_id,
        domain,
        source_scope,
        identity_org_name,
        identity_report_id,
        identity_date_begin,
        identity_date_end
    );

CREATE INDEX IF NOT EXISTS idx_aggregate_report_ingest_report
    ON aggregate_report_ingest_claims (report_type, report_id);

CREATE INDEX IF NOT EXISTS idx_aggregate_report_ingest_repair
    ON aggregate_report_ingest_claims (workspace_id, ingest_state, lease_expires_at);

INSERT OR IGNORE INTO aggregate_report_ingest_claims (
    id, report_type, workspace_id, domain, source, source_scope,
    identity_org_name, identity_report_id, identity_date_begin, identity_date_end,
    report_id, content_hash, ingest_state, attempt_token,
    lease_expires_at, failure_code, created_at, updated_at, completed_at, failed_at
)
SELECT
    'legacy_dmarc_' || id,
    'dmarc',
    workspace_id,
    domain,
    COALESCE(source, 'unknown'),
    CASE
      WHEN source IN ('manual_paste', 'signed_upload') THEN 'authoritative'
      ELSE 'observational'
    END,
    COALESCE(org_name, ''),
    external_report_id,
    COALESCE(CAST(date_range_begin AS TEXT), ''),
    COALESCE(CAST(date_range_end AS TEXT), ''),
    id,
    COALESCE(raw_hash, ''),
    CASE
      WHEN (SELECT COUNT(*) FROM dmarc_aggregate_records r WHERE r.report_id = dmarc_aggregate_reports.id)
           = record_count
      THEN 'complete'
      ELSE 'failed'
    END,
    'legacy',
    NULL,
    CASE
      WHEN (SELECT COUNT(*) FROM dmarc_aggregate_records r WHERE r.report_id = dmarc_aggregate_reports.id)
           = record_count
      THEN NULL
      ELSE 'legacy_partial_ingest'
    END,
    created_at,
    created_at,
    CASE
      WHEN (SELECT COUNT(*) FROM dmarc_aggregate_records r WHERE r.report_id = dmarc_aggregate_reports.id)
           = record_count
      THEN created_at
      ELSE NULL
    END,
    CASE
      WHEN (SELECT COUNT(*) FROM dmarc_aggregate_records r WHERE r.report_id = dmarc_aggregate_reports.id)
           = record_count
      THEN NULL
      ELSE created_at
    END
FROM dmarc_aggregate_reports
ORDER BY created_at, id;

INSERT OR IGNORE INTO aggregate_report_ingest_claims (
    id, report_type, workspace_id, domain, source, source_scope,
    identity_org_name, identity_report_id, identity_date_begin, identity_date_end,
    report_id, content_hash, ingest_state, attempt_token,
    lease_expires_at, failure_code, created_at, updated_at, completed_at, failed_at
)
SELECT
    'legacy_tlsrpt_' || id,
    'tlsrpt',
    workspace_id,
    domain,
    COALESCE(source, 'inbound_email'),
    CASE
      WHEN source IN ('manual_paste', 'signed_upload') THEN 'authoritative'
      ELSE 'observational'
    END,
    '',
    external_report_id,
    '',
    '',
    id,
    COALESCE(raw_hash, ''),
    CASE
      WHEN (SELECT COUNT(*) FROM tlsrpt_failure_details f WHERE f.report_id = tlsrpt_aggregate_reports.id)
           = failure_count
      THEN 'complete'
      ELSE 'failed'
    END,
    'legacy',
    NULL,
    CASE
      WHEN (SELECT COUNT(*) FROM tlsrpt_failure_details f WHERE f.report_id = tlsrpt_aggregate_reports.id)
           = failure_count
      THEN NULL
      ELSE 'legacy_partial_ingest'
    END,
    created_at,
    created_at,
    CASE
      WHEN (SELECT COUNT(*) FROM tlsrpt_failure_details f WHERE f.report_id = tlsrpt_aggregate_reports.id)
           = failure_count
      THEN created_at
      ELSE NULL
    END,
    CASE
      WHEN (SELECT COUNT(*) FROM tlsrpt_failure_details f WHERE f.report_id = tlsrpt_aggregate_reports.id)
           = failure_count
      THEN NULL
      ELSE created_at
    END
FROM tlsrpt_aggregate_reports
ORDER BY created_at, id;
