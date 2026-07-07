-- ── 065-hosted-dmarc-write-ahead-intent.sql ──────────────────────────────────
-- Zero-Fail architecture: write-ahead intent for every DNS-mutating change.
--
-- Every policy change/rollback now runs Prepare → Execute → Verify → Commit:
--   Prepare  — the intended value is written to pending_value BEFORE the
--              Cloudflare call, so a crash at any later point leaves evidence.
--   Execute  — the Cloudflare PATCH (the only side effect).
--   Verify   — the served content is read back and asserted equal to intent.
--   Commit   — one atomic UPDATE swaps previous/current from pending_value.
-- The hourly sweep reconciles stranded intents (commit if Cloudflare already
-- serves the intent, abort if it does not after the grace window), so a
-- half-applied change can never diverge D1 from DNS.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/065-hosted-dmarc-write-ahead-intent.sql
--
-- Rollback:
--   ALTER TABLE hosted_dns_records DROP COLUMN pending_value;
--   ALTER TABLE hosted_dns_records DROP COLUMN pending_since;
--
-- Limitation: SQLite ALTER TABLE ADD COLUMN is not idempotent; a second run
-- errors because the columns already exist. That is expected and safe.

ALTER TABLE hosted_dns_records ADD COLUMN pending_value TEXT;
ALTER TABLE hosted_dns_records ADD COLUMN pending_since TEXT;
