-- ── 078-scan-observability.sql ────────────────────────────────────────────
-- Additive scan diagnosability (Tier 1: make waitUntil-cancellation failures
-- observable). Heartbeat columns on `scans` let us see how far a scan got before
-- it was cancelled; `scan_module_telemetry` records per-module timing/outcome so a
-- future orphan is diagnosable from D1 alone. No behavioural change — every column
-- is nullable, the table is create-if-not-exists, and nothing reads these to gate
-- scan flow. Additive only.

ALTER TABLE scans ADD COLUMN last_heartbeat_at TEXT;
ALTER TABLE scans ADD COLUMN current_stage TEXT;
ALTER TABLE scans ADD COLUMN completed_modules INTEGER;

CREATE TABLE IF NOT EXISTS scan_module_telemetry (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL,
    module         TEXT NOT NULL,
    started_at     TEXT,
    completed_at   TEXT,
    duration_ms    INTEGER,
    outbound_calls INTEGER,
    outcome        TEXT,
    timeout        INTEGER,
    error_class    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_module_telemetry_scan
  ON scan_module_telemetry (scan_id, module);
