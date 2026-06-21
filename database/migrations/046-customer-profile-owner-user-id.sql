-- Migration 046: Add owner_user_id to customer_profiles
--
-- Root cause:
--   The customer_profiles table was created in production from an early version
--   of migration 016 that did not yet include the owner_user_id column.
--   Because 016 uses CREATE TABLE IF NOT EXISTS, every subsequent run silently
--   skipped recreation, leaving the column absent.
--   The CREATE INDEX on (owner_user_id) in 016 also silently failed for the
--   same reason, so no index exists in production either.
--
-- Why owner_user_id is required:
--   Every Worker query uses it as the user-scoping key:
--     - WHERE owner_user_id = ?          (GET lookups)
--     - ON CONFLICT(owner_user_id)       (upsert in PUT handler)
--     - LEFT JOIN ... ON cp.owner_user_id = u.id  (admin listing)
--   Removing it from queries is not an option; it is the design key.
--
-- Why a UNIQUE index (not plain index):
--   SQLite requires a unique constraint or unique index on the conflict
--   target column for INSERT ... ON CONFLICT(col) DO UPDATE to work.
--   ALTER TABLE ADD COLUMN cannot declare UNIQUE in SQLite, so we create
--   a separate unique index. We DROP the plain index from 016 first (if it
--   somehow exists) to avoid a name collision.
--
-- Existing rows:
--   owner_user_id is added as nullable TEXT. Any rows that exist will have
--   NULL, which is fine — multiple NULLs are permitted in a SQLite UNIQUE
--   index. New upserts will populate the column correctly via the Worker.
--
-- FOREIGN KEY:
--   SQLite does not support adding foreign key constraints via ALTER TABLE.
--   The referential integrity is enforced at the application layer (requireAuth
--   guarantees user.id is a valid users.id before any query).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/046-customer-profile-owner-user-id.sql
--
-- Rollback strategy:
--   ALTER TABLE DROP COLUMN not supported in D1/SQLite.
--   Column is nullable with no default — safe to leave in place if reverted.
--   Remove Worker references and drop the index if rollback is needed.

ALTER TABLE customer_profiles ADD COLUMN owner_user_id TEXT;

-- Drop the plain (non-unique) index created by 016 if it exists, then
-- create a unique index. ON CONFLICT(owner_user_id) requires uniqueness.
DROP INDEX IF EXISTS idx_customer_profiles_owner;
CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_profiles_owner
  ON customer_profiles (owner_user_id)
  WHERE owner_user_id IS NOT NULL;

-- Validation:
-- PRAGMA table_info(customer_profiles);
-- Expect columns: id, company_name, website, industry, company_size,
--                 contact_email, contact_name, created_at, updated_at,
--                 owner_user_id
--
-- SELECT name, type FROM sqlite_master
--   WHERE type='index' AND tbl_name='customer_profiles';
-- Expect: idx_customer_profiles_owner (unique, partial on NOT NULL)
--
-- Smoke test (replace USER_ID with a real users.id):
-- SELECT * FROM customer_profiles WHERE owner_user_id = 'USER_ID';
-- Should return 0 rows (not an error).
