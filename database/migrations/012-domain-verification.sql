-- ── 012-domain-verification.sql ──────────────────────────────────────────────
-- Adds domain ownership verification columns to the domains table.
-- All new columns are nullable / default-safe so existing rows are untouched.
--
-- Verification states:
--   unverified  — default; no verification attempted
--   pending     — token generated, awaiting customer action
--   verified    — ownership confirmed via DNS TXT or HTML file method
--   failed      — most-recent verification attempt was unsuccessful
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/012-domain-verification.sql
--
-- Rollback (remove added columns — SQLite requires table rebuild):
--   Not possible in SQLite via ALTER TABLE DROP COLUMN in older D1 versions.
--   To roll back: recreate domains table without these columns and re-insert.
--   In practice, columns can be safely left unused if the feature is disabled.

-- ── Extend domains table ──────────────────────────────────────────────────────

ALTER TABLE domains ADD COLUMN verification_status TEXT DEFAULT 'unverified';
ALTER TABLE domains ADD COLUMN verification_method TEXT;
ALTER TABLE domains ADD COLUMN verification_token  TEXT;
ALTER TABLE domains ADD COLUMN verified_at         TEXT;
ALTER TABLE domains ADD COLUMN verification_initiated_at TEXT;

-- ── Indexes ───────────────────────────────────────────────────────────────────

-- Fast lookup by verification state (e.g. list all unverified domains)
CREATE INDEX IF NOT EXISTS idx_domains_verification_status
  ON domains (verification_status);

-- Lookup by token during the verify callback (must be fast + unique-safe)
CREATE INDEX IF NOT EXISTS idx_domains_verification_token
  ON domains (verification_token)
  WHERE verification_token IS NOT NULL;

-- ── Backfill ──────────────────────────────────────────────────────────────────
-- Existing rows default to 'unverified' via the column default above.
-- Explicit UPDATE is a no-op safety net for any rows written before the ALTER.
UPDATE domains
SET verification_status = 'unverified'
WHERE verification_status IS NULL;
