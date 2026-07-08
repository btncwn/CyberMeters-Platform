-- Migration 067: Asset alert delivery status (retry enrolment)
-- Adds delivery-outcome tracking to asset_alert_records so a failed alert
-- email (e.g. Resend unreachable inside a subrequest-heavy scheduled-scan
-- invocation) is re-sent by the hourly cron instead of being permanently
-- swallowed by its own dedupe row. Mirrors lifecycle_email_events.status.
--
-- status: 'sent' | 'failed' | 'pending'
--   'sent'    — delivered, and the DEFAULT: pre-067 rows and rows written by a
--               worker deployed ahead of this migration read as already
--               handled, so the sweep never retro-retries them. The INSERT in
--               sendAssetChangeAlert deliberately keeps the pre-067 column
--               list for the same deploy-ordering tolerance.
--   'failed'  — delivery failed; picked up by the hourly asset_alert_retry
--               cron (retryFailedAssetAlerts).
--   'pending' — transient claim state while the retry cron re-sends.
-- error: safe reason enum from the delivery layer (e.g. 'network_error',
--   'timeout', 'provider_rejected') — never a raw provider error.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/067-asset-alert-retry.sql
--
-- Re-run safety: SAFE TO RE-RUN, but NOT strictly idempotent — SQLite/D1
-- ALTER TABLE ADD COLUMN has no IF NOT EXISTS, so a second apply fails loudly
-- with "duplicate column name" and changes nothing (verified empirically:
-- schema is byte-identical after the failed re-run). Same limitation as
-- migrations 050/052. Treat the duplicate-column error as the expected
-- "already applied" signal, not a failure.
--
-- Rollback:
--   Leave the schema in place. Roll back APPLICATION CODE only.
--   The status column is backward compatible: pre-067 code never reads it,
--   and with every row at status='sent' the retry sweep matches nothing —
--   behaviour is identical to pre-migration. (D1/SQLite offers no DROP
--   COLUMN path here, and none is needed.)

ALTER TABLE asset_alert_records ADD COLUMN status TEXT NOT NULL DEFAULT 'sent';
ALTER TABLE asset_alert_records ADD COLUMN error TEXT;

-- Retry sweep lookup: failed rows inside a bounded recent window.
CREATE INDEX IF NOT EXISTS idx_asset_alert_records_status
    ON asset_alert_records (status, sent_at);
