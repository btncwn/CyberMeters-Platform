-- Migration 140: a customer can remove a network target (founder-approved,
-- 25 Oct 2026). Removal is a soft withdrawal, never a delete: past network
-- scans join network_targets for their target, so the row must stay.
--
-- withdrawn_at / withdrawn_by record who removed the target and when. Every
-- reader that decides whether a target may be probed requires
-- withdrawn_at IS NULL (scan start, dispatch, TLS planning, exposure jobs,
-- TLS service authorisation, the 24 h ownership re-check). Re-adding the same
-- target clears both (UNIQUE(workspace_id, target)).
--
-- Additive: two nullable columns; existing targets keep NULL (not withdrawn).
--
-- Apply (before the Worker deploy, which reads these columns):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/140-network-target-withdrawal.sql
--
-- Rollback:
--   Roll the Worker back first. The columns can stay; the previous Worker does
--   not read or write them (a withdrawn target would read as active again, so
--   roll back only together with the Worker).

ALTER TABLE network_targets ADD COLUMN withdrawn_at TEXT;
ALTER TABLE network_targets ADD COLUMN withdrawn_by TEXT;
