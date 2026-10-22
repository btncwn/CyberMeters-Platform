-- Migration 138: written consent for customer-declared network ranges.
--
-- Founder principle (22 Oct 2026, 00:40): a network target whose addresses are
-- not observed in the workspace's verified-domain DNS stays usable, but only
-- under a scoped, revocable authorisation from someone who states they hold it.
-- The checkbox alone (network_targets.authorization_status = 'attested') never
-- authorises such an address; this table is the record that does. Executive
-- decision B: a separate append-only store read by the same gates as the
-- Active Checks consent (migration 135), not a rebuild of that table.
--
-- Append-only, exactly like 135: a grant is one row naming the exact addresses
-- and ports; revoking it adds a 'revocation' row. Rows are never updated
-- (trigger below), the product has no delete path, and only the workspace purge
-- erases them (WORKSPACE_PURGE_TABLES). Shared provider infrastructure is never
-- grantable (enforced by the Worker, which refuses those addresses).
--
-- network_scans.range_consent_id records which grant authorised a scan of a
-- declared range (NULL when the addresses were observed in verified DNS). The
-- dispatch claim re-checks that grant in SQL, so a revocation stops queued work.
--
-- Additive: one new table, its indexes and triggers, and one nullable column.
-- Nothing existing changes.
--
-- Apply (before the Worker deploy, which reads and writes this table):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/138-network-range-consents.sql
--
-- Rollback:
--   Roll the Worker back first. The table and column can stay; the previous
--   Worker does not read them, and keeping them preserves the consent history.

CREATE TABLE IF NOT EXISTS network_range_consents (
  id                    TEXT PRIMARY KEY,
  workspace_id          TEXT NOT NULL,
  kind                  TEXT NOT NULL CHECK (kind IN ('grant', 'revocation')),
  -- revocation → the grant it ends; NULL on a grant.
  grant_id              TEXT,
  -- Exact scope (grants only): the network target, its canonical target text
  -- and address list at signing time, and the exact ports (TCP).
  network_target_id     TEXT,
  target                TEXT,
  addresses_json        TEXT,
  ports_json            TEXT,
  -- Who: the signed-in account and its workspace role at that moment, plus the
  -- name and title the signer typed.
  actor_user_id         TEXT NOT NULL,
  actor_email           TEXT,
  actor_workspace_role  TEXT NOT NULL,
  signer_name           TEXT,
  signer_title          TEXT,
  ip_address            TEXT,
  user_agent            TEXT,
  -- What they agreed to, verbatim, and its version.
  authority_text        TEXT,
  authority_version     TEXT,
  -- Optional, revocation rows only.
  revocation_reason     TEXT,
  created_at            TEXT NOT NULL,
  CHECK (
    (kind = 'grant' AND grant_id IS NULL AND network_target_id IS NOT NULL AND target IS NOT NULL
      AND addresses_json IS NOT NULL AND ports_json IS NOT NULL AND signer_name IS NOT NULL
      AND signer_title IS NOT NULL AND authority_text IS NOT NULL AND authority_version IS NOT NULL
      AND revocation_reason IS NULL)
    OR (kind = 'revocation' AND grant_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_network_range_consents_scope
  ON network_range_consents (workspace_id, network_target_id, kind, created_at);

-- A grant is revoked at most once.
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_range_consents_one_revocation
  ON network_range_consents (grant_id) WHERE kind = 'revocation';

-- Immutable rows.
CREATE TRIGGER IF NOT EXISTS trg_network_range_consents_no_update
BEFORE UPDATE ON network_range_consents
BEGIN
  SELECT RAISE(ABORT, 'network_range_consents is append-only');
END;

-- A revocation must name a grant of the same workspace.
CREATE TRIGGER IF NOT EXISTS trg_network_range_consents_revocation_target
BEFORE INSERT ON network_range_consents
WHEN NEW.kind = 'revocation' AND NOT EXISTS (
  SELECT 1 FROM network_range_consents g
   WHERE g.id = NEW.grant_id AND g.kind = 'grant' AND g.workspace_id = NEW.workspace_id
)
BEGIN
  SELECT RAISE(ABORT, 'revocation must name a grant of this workspace');
END;

ALTER TABLE network_scans ADD COLUMN range_consent_id TEXT;
