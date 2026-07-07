-- ── 064-hosted-dmarc-selfdriving.sql ─────────────────────────────────────────
-- Phase B: Self-Driving DMARC (policy ramp-up with pass-rate interlock).
--
-- autopilot — when 1, the hourly sweep advances the policy ladder
--   (none → quarantine 5→25→50→100 → reject) one step at a time, only while
--   the pass-rate interlock holds (enough volume, healthy pass rate, minimum
--   days since the last change).
-- pass_rate_at_change — the DMARC pass rate observed when the value last
--   changed; the auto-rollback monitor compares against it and reverts to
--   previous_value if compliance drops materially after a change.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/064-hosted-dmarc-selfdriving.sql
--
-- Rollback:
--   ALTER TABLE hosted_dns_records DROP COLUMN autopilot;
--   ALTER TABLE hosted_dns_records DROP COLUMN pass_rate_at_change;
--
-- Limitation: SQLite ALTER TABLE ADD COLUMN is not idempotent; a second run
-- errors because the columns already exist. That is expected and safe.

ALTER TABLE hosted_dns_records ADD COLUMN autopilot INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosted_dns_records ADD COLUMN pass_rate_at_change REAL;
