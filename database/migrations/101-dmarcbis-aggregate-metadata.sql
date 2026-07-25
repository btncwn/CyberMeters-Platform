-- Migration 101: additive RFC 9990 aggregate-report metadata.
--
-- No DMARC policy observation or condition table is introduced. Policy DNS
-- evidence remains in immutable R2 reports/snapshots, while lifecycle
-- occurrence identity continues to use email_protection_events (migration 088).
--
-- These columns preserve report-generator claims. They never overwrite or
-- replace the current DNS observation, and all are nullable so every RFC
-- 7489-era row remains valid without backfill or reinterpretation.
--
-- Rollback: application-code rollback only. Leaving unused nullable columns in
-- place is backward compatible and preserves any evidence already written.

ALTER TABLE dmarc_aggregate_reports ADD COLUMN report_format_version TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN xml_namespace TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN discovery_method TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN policy_np TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN policy_testing TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN policy_fo TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN schema_conformance TEXT;
ALTER TABLE dmarc_aggregate_reports ADD COLUMN parser_version TEXT;
