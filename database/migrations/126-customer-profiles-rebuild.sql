-- Migration 126: rebuild customer_profiles to the shape the Worker writes.
--
-- Root cause:
--   Production created customer_profiles from a pre-016 draft (user_id TEXT
--   NOT NULL UNIQUE, country). 016's CREATE TABLE IF NOT EXISTS then skipped,
--   and 046 could only ADD owner_user_id as a nullable column with a PARTIAL
--   unique index (WHERE owner_user_id IS NOT NULL). SQLite does not accept a
--   partial index as the target of a plain ON CONFLICT(owner_user_id), so
--   PUT /api/account/company fails on every call in production, and report
--   branding (which requires a profile) can never be saved. The upsert also
--   omits user_id, which the live table requires.
--
-- Shape:
--   Ends in the same table on both starting shapes — the live pre-016 table and
--   the schema.sql/016 table CI builds — because the table is created here
--   explicitly: the 016 columns, owner_user_id NOT NULL UNIQUE, no user_id, and
--   country kept as a nullable column.
--
-- Non-destructive:
--   The old table is RENAMED to customer_profiles_legacy_pre016, never dropped,
--   so every original row (including user_id and country) stays recoverable.
--   Only columns present in both starting shapes are copied, so this file runs
--   unchanged on either. A row the new constraints cannot hold (no
--   owner_user_id or no company_name) fails the copy instead of being silently
--   left behind. Production held 0 rows when this was written (19 Oct 2026).
--
-- References:
--   No view, trigger or other table's foreign key names customer_profiles in
--   production or in the repository schema (checked read-only, 19 Oct 2026),
--   so the rename cannot repoint anything to the legacy table. The legacy
--   table's own indexes move with it under their old names; they are dropped
--   from the legacy table so the canonical index names can be reused on the
--   new one. Dropping an index removes no data.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/126-customer-profiles-rebuild.sql
--
-- Rollback:
--   Only while the new table is still empty (check
--   SELECT COUNT(*) FROM customer_profiles first), reverse the rename:
--     DROP TABLE customer_profiles;
--     ALTER TABLE customer_profiles_legacy_pre016 RENAME TO customer_profiles;
--     CREATE UNIQUE INDEX idx_customer_profiles_owner
--       ON customer_profiles (owner_user_id) WHERE owner_user_id IS NOT NULL;
--   Once customers have saved profiles, roll forward instead of reverting.

ALTER TABLE customer_profiles RENAME TO customer_profiles_legacy_pre016;

DROP INDEX IF EXISTS idx_customer_profiles_owner;
DROP INDEX IF EXISTS idx_customer_profiles_user_id;

CREATE TABLE customer_profiles (
    id                 TEXT PRIMARY KEY,
    owner_user_id      TEXT NOT NULL UNIQUE,
    company_name       TEXT NOT NULL,
    website            TEXT,
    industry           TEXT,
    company_size       TEXT,
    contact_email      TEXT,
    contact_name       TEXT,
    created_at         TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at         TEXT,
    brand_logo         TEXT,
    brand_accent       TEXT,
    report_white_label INTEGER NOT NULL DEFAULT 0,
    country            TEXT,
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_profiles_owner
  ON customer_profiles (owner_user_id)
  WHERE owner_user_id IS NOT NULL;

INSERT INTO customer_profiles
  (id, owner_user_id, company_name, website, industry, company_size,
   contact_email, contact_name, created_at, updated_at,
   brand_logo, brand_accent, report_white_label)
SELECT id, owner_user_id, company_name, website, industry, company_size,
       contact_email, contact_name, created_at, updated_at,
       brand_logo, brand_accent, report_white_label
  FROM customer_profiles_legacy_pre016;
