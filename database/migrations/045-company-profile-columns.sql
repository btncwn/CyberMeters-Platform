-- Migration 045: Company Profile Columns
-- Adds contact_email and contact_name to customer_profiles.
--
-- Background: migration 016 was applied to production before these columns
-- were present in that file, so the live table is missing them.
-- The CREATE TABLE IF NOT EXISTS in 016 silently skipped re-creation,
-- leaving the table without these columns and causing:
--   D1_ERROR: no such column: contact_email
--
-- All columns are nullable — existing rows are not affected.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/045-company-profile-columns.sql
--
-- Rollback strategy:
--   ALTER TABLE DROP COLUMN not supported in D1/SQLite.
--   Columns are nullable with no default — safe to leave in place.
--   Remove references in index.js if rollback is needed.

ALTER TABLE customer_profiles ADD COLUMN contact_email TEXT;
ALTER TABLE customer_profiles ADD COLUMN contact_name  TEXT;

-- Validation:
-- PRAGMA table_info(customer_profiles);
-- Expect columns: id, owner_user_id, company_name, website, industry,
--                 company_size, contact_email, contact_name,
--                 created_at, updated_at
