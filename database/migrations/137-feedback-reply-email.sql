-- Migration 137: an optional "Reply to me at" address on feedback (S2-FEEDBACK-NOW).
--
-- The "Something wrong?" form may now carry an address the sender chose to give
-- so the founder can answer. It is optional, validated, stored with the report
-- and deleted with it by the existing 90-day retention. Nothing else changes:
-- feedback stays anonymous otherwise (no IP, no account).
--
-- Additive: one nullable column; existing reports keep NULL.
--
-- Apply (before the Worker deploy, which writes this column):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/137-feedback-reply-email.sql
--
-- Rollback:
--   Roll the Worker back first. The column can stay; the previous Worker does not
--   read or write it.

ALTER TABLE feedback_reports ADD COLUMN reply_email TEXT;
