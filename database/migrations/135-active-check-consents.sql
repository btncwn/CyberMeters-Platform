-- Migration 135: written consent for Active Checks (S2-A, 22 Oct 2026).
--
-- An active check touches a customer system beyond passive observation. It runs
-- only under a scoped grant from someone who states they hold the authority
-- (engines/active-check-consent.js, isAuthorised). This table is the record.
--
-- Append-only: a grant is one row; revoking it adds a 'revocation' row naming the
-- grant. Rows are never updated (trigger below), and the product has no delete
-- path; only the workspace purge erases them (WORKSPACE_PURGE_TABLES), because
-- deleting a customer's data on request is the one deletion we owe them.
--
-- No scheduling fields: a grant authorises on-demand checks only.
--
-- Additive: one new table, its indexes and triggers. Nothing existing changes;
-- the TLS special-controls permission (migration 120) is untouched.
--
-- Apply (before the Worker deploy, which reads and writes this table):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/135-active-check-consents.sql
--
-- Rollback:
--   Roll the Worker back first. The table can stay; the previous Worker does not
--   read it, and keeping it preserves the consent history.

CREATE TABLE IF NOT EXISTS active_check_consents (
  id                    TEXT PRIMARY KEY,
  workspace_id          TEXT NOT NULL,
  kind                  TEXT NOT NULL CHECK (kind IN ('grant', 'revocation')),
  -- revocation → the grant it ends; NULL on a grant.
  grant_id              TEXT,
  -- Exact scope (grants only): a verified domain of this workspace, the exact
  -- hostnames under it (empty list = the apex only), and the exact check ids.
  domain_id             TEXT,
  domain                TEXT,
  hosts_json            TEXT,
  checks_json           TEXT,
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
  created_at            TEXT NOT NULL,
  CHECK (
    (kind = 'grant' AND grant_id IS NULL AND domain_id IS NOT NULL AND domain IS NOT NULL
      AND hosts_json IS NOT NULL AND checks_json IS NOT NULL AND signer_name IS NOT NULL
      AND signer_title IS NOT NULL AND authority_text IS NOT NULL AND authority_version IS NOT NULL)
    OR (kind = 'revocation' AND grant_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_active_check_consents_scope
  ON active_check_consents (workspace_id, domain_id, kind, created_at);

-- A grant is revoked at most once.
CREATE UNIQUE INDEX IF NOT EXISTS idx_active_check_consents_one_revocation
  ON active_check_consents (grant_id) WHERE kind = 'revocation';

-- Immutable rows.
CREATE TRIGGER IF NOT EXISTS trg_active_check_consents_no_update
BEFORE UPDATE ON active_check_consents
BEGIN
  SELECT RAISE(ABORT, 'active_check_consents is append-only');
END;

-- A revocation must name a grant of the same workspace.
CREATE TRIGGER IF NOT EXISTS trg_active_check_consents_revocation_target
BEFORE INSERT ON active_check_consents
WHEN NEW.kind = 'revocation' AND NOT EXISTS (
  SELECT 1 FROM active_check_consents g
   WHERE g.id = NEW.grant_id AND g.kind = 'grant' AND g.workspace_id = NEW.workspace_id
)
BEGIN
  SELECT RAISE(ABORT, 'revocation must name a grant of this workspace');
END;
