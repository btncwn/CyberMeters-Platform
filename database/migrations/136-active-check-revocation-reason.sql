-- Migration 136: an optional reason on an Active Checks revocation (S2-A2).
--
-- Seat 1's consent receipt shows why a permission was withdrawn. The reason is
-- written once, on the revocation row itself (≤ 240 characters, optional). The
-- table stays append-only: the no-update trigger from migration 135 still
-- refuses every UPDATE, and nothing existing is rewritten.
--
-- Additive: one nullable column. Existing revocations keep NULL ("no reason
-- given").
--
-- Apply (before the Worker deploy, which writes this column):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/136-active-check-revocation-reason.sql
--
-- Rollback:
--   Roll the Worker back first. The column can stay; the previous Worker does
--   not read or write it.

ALTER TABLE active_check_consents ADD COLUMN revocation_reason TEXT;
