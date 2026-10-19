-- Migration 127: record what happened the last time a customer's scheduled
-- report was due, so the customer can see a report that was not created.
--
-- A failed run used to leave scheduled_reports unchanged, so the schedule kept
-- showing its old next run and the customer never learned a report was missing.
-- last_outcome is completed | skipped | failed; last_outcome_reason is a reason
-- code (never error text) that the API turns into plain words.
-- consecutive_failures lets the customer be told once per run of failures, not
-- on every hourly retry.
--
-- Additive only. Existing rows read as "no outcome recorded yet".
--
-- Apply (before the Worker deploy — the Worker reads these columns):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/127-scheduled-report-failure-state.sql
--
-- Rollback:
--   Roll the Worker back first. The columns are nullable / defaulted and can
--   stay in place afterwards.

ALTER TABLE scheduled_reports ADD COLUMN last_outcome TEXT;
ALTER TABLE scheduled_reports ADD COLUMN last_outcome_reason TEXT;
ALTER TABLE scheduled_reports ADD COLUMN last_outcome_at TEXT;
ALTER TABLE scheduled_reports ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
