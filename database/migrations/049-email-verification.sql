-- Migration 049: Email verification fields
-- Adds email verification state to the users table.
--
-- Existing users are grandfathered as verified so they are not locked out.
-- New local-auth signups will have email_verified = 0 until they click the link.
-- Microsoft OAuth signups are set to email_verified = 1 at account creation time.
--
-- Rollback: SQLite (D1) does not support DROP COLUMN, so this migration is
-- forward-only. To roll back, redeploy the prior Worker build (which ignores
-- the new columns) and leave the columns in place.

ALTER TABLE users ADD COLUMN email_verified              INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN email_verified_at           TEXT;
ALTER TABLE users ADD COLUMN verification_token          TEXT;
ALTER TABLE users ADD COLUMN verification_token_expires_at TEXT;

-- Grandfather all existing accounts as verified.
UPDATE users SET email_verified = 1 WHERE email_verified = 0;

-- Index for fast token lookups on the verify-email endpoint.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_verification_token
  ON users (verification_token) WHERE verification_token IS NOT NULL;
