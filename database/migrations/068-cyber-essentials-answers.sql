-- Migration 068: Cyber Essentials Readiness — self-attestation answers
-- Stores the guided-questionnaire responses for the CE controls we CANNOT
-- observe externally (access control, malware protection on endpoints, internal
-- patch/firewall config). The readiness endpoint merges these with the measured
-- external signals; where a measured signal contradicts an optimistic answer
-- (e.g. answer says "secure config OK" but we observe an exposed admin panel),
-- the MEASURED signal wins and the control is flagged as a gap. This is
-- READINESS / gap analysis, never certification (IASME-licensed bodies certify).
--
-- control_key mirrors cyberEssentialsCategory() keys already in the worker:
--   boundary_protection | secure_configuration | access_control |
--   malware_protection | patch_management_readiness
-- answer: 'yes' | 'no' | 'partial' | 'unknown'
--
-- Re-run safety: SAFE TO RE-RUN, NOT strictly idempotent — a second apply fails
-- with "table already exists" and changes nothing (D1/SQLite has no ADD COLUMN
-- IF NOT EXISTS; CREATE TABLE IF NOT EXISTS covers the table but the second run
-- is still a no-op error surface). Treat that error as "already applied".
--
-- Rollback: leave the schema in place; roll back application code only. The
-- readiness endpoint tolerates an empty answers set (falls back to measured-only,
-- i.e. today's behaviour), so an un-read table is inert.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/068-cyber-essentials-answers.sql

CREATE TABLE IF NOT EXISTS cyber_essentials_answers (
  id            TEXT PRIMARY KEY,
  workspace_id  TEXT NOT NULL,
  control_key   TEXT NOT NULL,
  question_key  TEXT NOT NULL,
  answer        TEXT NOT NULL DEFAULT 'unknown',
  note          TEXT,
  answered_by   TEXT,
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One current answer per (workspace, control, question) — upsert target.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ce_answers_unique
  ON cyber_essentials_answers (workspace_id, control_key, question_key);

-- Readiness lookup: all answers for a workspace.
CREATE INDEX IF NOT EXISTS idx_ce_answers_workspace
  ON cyber_essentials_answers (workspace_id);
