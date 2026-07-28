-- CT-R1: Certificate Transparency provider-attempt telemetry.
-- Additive and observational only. This migration is founder-gated and must not be
-- applied as part of the CT-R1 implementation PR.

CREATE TABLE IF NOT EXISTS ct_provider_telemetry (
    id                    TEXT PRIMARY KEY,
    scan_id               TEXT NOT NULL,
    module                TEXT NOT NULL CHECK (module IN ('ssl', 'subdomains')),
    provider              TEXT NOT NULL CHECK (provider IN ('crt_sh', 'certspotter')),
    outcome               TEXT NOT NULL CHECK (
                            outcome IN (
                              'ok', 'timeout', 'http_error', 'parse_error',
                              'rate_limited', 'network_error'
                            )
                          ),
    http_status           INTEGER CHECK (
                            http_status IS NULL OR
                            (http_status BETWEEN 100 AND 599)
                          ),
    latency_ms            INTEGER NOT NULL CHECK (latency_ms >= 0),
    result_count          INTEGER CHECK (result_count IS NULL OR result_count >= 0),
    started_at            TEXT NOT NULL,
    completed_at          TEXT NOT NULL,
    completeness_impact   INTEGER NOT NULL DEFAULT 0 CHECK (
                            completeness_impact IN (0, 1)
                          ),
    affected_signal       TEXT CHECK (
                            (completeness_impact = 0 AND affected_signal IS NULL) OR
                            (completeness_impact = 1 AND affected_signal IN (
                              'certificate_transparency',
                              'subdomain_discovery'
                            ))
                          ),
    cache_state           TEXT NOT NULL DEFAULT 'miss' CHECK (
                            cache_state IN ('miss', 'fresh_hit', 'stale_available')
                          ),
    cache_age_s           INTEGER CHECK (cache_age_s IS NULL OR cache_age_s >= 0),
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_ct_provider_telemetry_scan
  ON ct_provider_telemetry (scan_id, module, provider);

CREATE INDEX IF NOT EXISTS idx_ct_provider_telemetry_provider_time
  ON ct_provider_telemetry (provider, started_at);

-- Two providers × two module consumers × the existing two-attempt hard cap.
-- Runtime collection is bounded too; this trigger is the durable fail-closed guard.
CREATE TRIGGER IF NOT EXISTS trg_ct_provider_telemetry_scan_row_bound
BEFORE INSERT ON ct_provider_telemetry
WHEN (
  SELECT COUNT(*)
  FROM ct_provider_telemetry
  WHERE scan_id = NEW.scan_id
) >= 8
BEGIN
  SELECT RAISE(ABORT, 'ct_provider_telemetry row bound exceeded');
END;
