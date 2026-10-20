-- Migration 133: a certificate's expected hostnames start as its monitored host.
--
-- A certificate lifecycle record was created with no expected hostnames, and
-- only the customer's "Expected hosts" action could set them. With none, SAN
-- coverage is "unknown" and the replacement verifier can never conclude, so a
-- customer who never opened that action could never have a renewal verified.
-- The record now starts with its monitored host (primary_hostname), and
-- expected_hostnames_source says where the list came from:
--   'observed_primary_host'  seeded from the monitored host
--   'customer'               set by the customer
--
-- Additive: one nullable column, plus a backfill of records whose list is
-- still empty and was never set by the customer. A customer's list is never
-- touched. The stored coverage_status is recomputed by the next scan; the
-- verifier computes coverage from the list itself when it runs.
--
-- Apply (before the Worker deploy — the scan writes the new column):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/133-cert-expected-host-default.sql
--
-- Rollback:
--   Roll the Worker back first. To undo the backfill:
--   UPDATE certificate_lifecycle SET expected_hostnames_json = '[]'
--    WHERE expected_hostnames_source = 'observed_primary_host';
--   The column can stay; nothing else reads it.

ALTER TABLE certificate_lifecycle ADD COLUMN expected_hostnames_source TEXT;

UPDATE certificate_lifecycle
   SET expected_hostnames_json = json_array(lower(trim(primary_hostname))),
       expected_hostnames_source = 'observed_primary_host'
 WHERE (expected_hostnames_json IS NULL OR expected_hostnames_json = '[]')
   AND expected_hostnames_source IS NULL
   AND primary_hostname IS NOT NULL
   AND trim(primary_hostname) <> ''
   AND primary_hostname NOT LIKE '*.%';
