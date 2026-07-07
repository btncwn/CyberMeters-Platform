-- ── 063-hosted-dns-failure-tracking.sql ──────────────────────────────────────
-- K2: transient-vs-config error tracking for hosted DNS records.
--
-- failure_count — consecutive Cloudflare failures during creation; reset to 0
--   on success. last_error — customer-safe issue class: 'config_error' (our
--   token is bad/insufficient — surfaced to the customer and our logs) or
--   'temporary_issue' (rate-limit/outage/network — self-heals on the next
--   hourly sweep). Ends the previous behaviour of retrying forever in silence.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/063-hosted-dns-failure-tracking.sql
--
-- Rollback (SQLite ≥ 3.35 supports DROP COLUMN):
--   ALTER TABLE hosted_dns_records DROP COLUMN failure_count;
--   ALTER TABLE hosted_dns_records DROP COLUMN last_error;
--
-- Limitation: SQLite ALTER TABLE ADD COLUMN is not idempotent (no IF NOT
-- EXISTS). Running this twice errors on the second run — that is expected and
-- safe; the columns already exist.

ALTER TABLE hosted_dns_records ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosted_dns_records ADD COLUMN last_error TEXT;
