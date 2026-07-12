-- TLS-RPT (RFC 8460) report ingestion storage. TLS-RPT reports are JSON (not
-- DMARC XML) and arrive at the same reports.cybermeters.com mailbox; the inbound
-- handler routes by attachment type into a separate parser + these tables. Never
-- touches the DMARC XML path or dmarc_aggregate_* tables. Additive, idempotent.

CREATE TABLE IF NOT EXISTS tlsrpt_aggregate_reports (
    id                        TEXT PRIMARY KEY,
    workspace_id              TEXT NOT NULL,
    domain                    TEXT NOT NULL,       -- domain this endpoint is bound to (lowercase)
    org_name                  TEXT,                -- reporter (organization-name)
    contact_info              TEXT,
    external_report_id        TEXT NOT NULL,       -- report-id from the report (dedup key)
    date_range_begin          TEXT,                -- ISO start-datetime
    date_range_end            TEXT,                -- ISO end-datetime
    policy_type               TEXT,                -- sts | tlsa | no-policy-found (primary policy)
    policy_domain             TEXT,
    total_successful_sessions INTEGER NOT NULL DEFAULT 0,
    total_failure_sessions    INTEGER NOT NULL DEFAULT 0,
    failure_count             INTEGER NOT NULL DEFAULT 0,   -- # of failure-detail rows
    raw_hash                  TEXT,
    provenance                TEXT,                -- verified | unverified (header-From trust)
    created_at                TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Dedup: one stored report per (workspace, domain, report-id).
CREATE UNIQUE INDEX IF NOT EXISTS idx_tlsrpt_reports_dedup
    ON tlsrpt_aggregate_reports (workspace_id, domain, external_report_id);
CREATE INDEX IF NOT EXISTS idx_tlsrpt_reports_ws_domain
    ON tlsrpt_aggregate_reports (workspace_id, domain, created_at);

CREATE TABLE IF NOT EXISTS tlsrpt_failure_details (
    id                    TEXT PRIMARY KEY,
    report_id             TEXT NOT NULL,           -- FK → tlsrpt_aggregate_reports.id
    workspace_id          TEXT NOT NULL,
    domain                TEXT NOT NULL,
    result_type           TEXT,                    -- e.g. certificate-expired, starttls-not-supported
    sending_mta_ip        TEXT,
    receiving_mx_hostname  TEXT,
    receiving_ip          TEXT,
    failed_session_count  INTEGER NOT NULL DEFAULT 0,
    additional_info       TEXT,
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES tlsrpt_aggregate_reports(id)
);
CREATE INDEX IF NOT EXISTS idx_tlsrpt_failures_report
    ON tlsrpt_failure_details (report_id);
CREATE INDEX IF NOT EXISTS idx_tlsrpt_failures_ws_domain
    ON tlsrpt_failure_details (workspace_id, domain);
