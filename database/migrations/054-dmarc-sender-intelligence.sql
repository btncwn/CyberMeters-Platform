-- ── 054-dmarc-sender-intelligence.sql ────────────────────────────────────────
-- DMARC Report Ingestion & Sender Intelligence v1.
--
-- Backend data foundation for Managed DMARC: stores manually imported DMARC
-- aggregate (RUA) report metadata, the per-source record rows, and a rolled-up
-- sending-source inventory used to guide the move from p=none towards
-- quarantine/reject. Additive and backwards-compatible — no existing table
-- or API response is changed.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/054-dmarc-sender-intelligence.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS email_sender_sources;
--   DROP TABLE IF EXISTS dmarc_aggregate_records;
--   DROP TABLE IF EXISTS dmarc_aggregate_reports;

-- ── Aggregate report metadata (one row per imported XML report) ──────────────
CREATE TABLE IF NOT EXISTS dmarc_aggregate_reports (
    id                 TEXT PRIMARY KEY,
    workspace_id       TEXT NOT NULL,
    domain             TEXT NOT NULL,
    org_name           TEXT,
    report_email       TEXT,
    external_report_id TEXT NOT NULL,
    date_range_begin   INTEGER,
    date_range_end     INTEGER,
    policy_domain      TEXT,
    policy_adkim       TEXT,
    policy_aspf        TEXT,
    policy_p           TEXT,
    policy_sp          TEXT,
    policy_pct         INTEGER,
    record_count       INTEGER NOT NULL DEFAULT 0,
    message_count      INTEGER NOT NULL DEFAULT 0,
    raw_hash           TEXT,
    created_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Dedupe: the same report must never be double-counted.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dmarc_reports_dedupe
    ON dmarc_aggregate_reports
    (workspace_id, domain, org_name, external_report_id, date_range_begin, date_range_end);

-- Primary lookup pattern (summary queries).
CREATE INDEX IF NOT EXISTS idx_dmarc_reports_ws_domain
    ON dmarc_aggregate_reports (workspace_id, domain, date_range_end);

-- ── Per-source record rows (one row per <record> in a report) ────────────────
CREATE TABLE IF NOT EXISTS dmarc_aggregate_records (
    id                  TEXT PRIMARY KEY,
    report_id           TEXT NOT NULL,
    workspace_id        TEXT NOT NULL,
    domain              TEXT NOT NULL,
    source_ip           TEXT,
    message_count       INTEGER NOT NULL DEFAULT 0,
    disposition         TEXT,
    dkim_aligned_result TEXT,
    spf_aligned_result  TEXT,
    header_from         TEXT,
    envelope_from       TEXT,
    dkim_domain         TEXT,
    dkim_selector       TEXT,
    dkim_result         TEXT,
    spf_domain          TEXT,
    spf_result          TEXT,
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES dmarc_aggregate_reports(id)
);

CREATE INDEX IF NOT EXISTS idx_dmarc_records_report
    ON dmarc_aggregate_records (report_id);

CREATE INDEX IF NOT EXISTS idx_dmarc_records_ws_domain_ip
    ON dmarc_aggregate_records (workspace_id, domain, source_ip);

-- ── Rolled-up sending-source inventory (one row per workspace+domain+IP) ─────
CREATE TABLE IF NOT EXISTS email_sender_sources (
    id                   TEXT PRIMARY KEY,
    workspace_id         TEXT NOT NULL,
    domain               TEXT NOT NULL,
    source_ip            TEXT NOT NULL,
    provider_guess       TEXT,
    provider_confidence  TEXT,
    provider_reason      TEXT,
    header_from          TEXT,
    first_seen           TEXT,
    last_seen            TEXT,
    total_messages       INTEGER NOT NULL DEFAULT 0,
    aligned_messages     INTEGER NOT NULL DEFAULT 0,
    failed_messages      INTEGER NOT NULL DEFAULT 0,
    quarantined_messages INTEGER NOT NULL DEFAULT 0,
    rejected_messages    INTEGER NOT NULL DEFAULT 0,
    pass_rate            REAL NOT NULL DEFAULT 0,
    classification       TEXT NOT NULL DEFAULT 'unknown',
    notes                TEXT,
    created_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TEXT,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- One inventory row per source IP per domain per workspace (upsert key).
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_sender_sources_key
    ON email_sender_sources (workspace_id, domain, source_ip);

-- Workspace/domain listing + classification filtering.
CREATE INDEX IF NOT EXISTS idx_email_sender_sources_ws_domain
    ON email_sender_sources (workspace_id, domain, classification);
