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
-- Idempotency limitation: SQLite/D1 ALTER TABLE ADD COLUMN has no IF NOT
-- EXISTS. Re-applying this file fails with "duplicate column name" and makes
-- no changes — same limitation as migrations 050/052.
--
-- Rollback:
--   ALTER TABLE in D1/SQLite does not support DROP COLUMN here. Safe to
--   leave: with every row at status='sent' the retry sweep matches nothing
--   and behaviour is identical to pre-migration.

ALTER TABLE asset_alert_records ADD COLUMN status TEXT NOT NULL DEFAULT 'sent';
ALTER TABLE asset_alert_records ADD COLUMN error TEXT;

-- Retry sweep lookup: failed rows inside a bounded recent window.
CREATE INDEX IF NOT EXISTS idx_asset_alert_records_status
    ON asset_alert_records (status, sent_at);
