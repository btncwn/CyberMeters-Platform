-- ── 029-billing-schema-alignment.sql ────────────────────────────────────────
-- Aligns the subscriptions table with the billing runtime source-of-truth model.
-- All changes are additive and safe to re-run only if columns do not already
-- exist in the target D1 database.
--
-- Adds:
--   owner_user_id
--   subscription_status
--   current_period_end
--   updated_at
--
-- Backfills:
--   subscriptions.owner_user_id        <- workspaces.owner_user_id
--   subscriptions.subscription_status  <- subscriptions.status
--   subscriptions.current_period_end   <- subscriptions.expires_at
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/029-billing-schema-alignment.sql

ALTER TABLE subscriptions ADD COLUMN owner_user_id TEXT;
ALTER TABLE subscriptions ADD COLUMN subscription_status TEXT;
ALTER TABLE subscriptions ADD COLUMN current_period_end TEXT;
ALTER TABLE subscriptions ADD COLUMN updated_at TEXT;

UPDATE subscriptions
SET owner_user_id = (
  SELECT workspaces.owner_user_id
  FROM workspaces
  WHERE workspaces.id = subscriptions.workspace_id
)
WHERE owner_user_id IS NULL
  AND workspace_id IS NOT NULL;

UPDATE subscriptions
SET subscription_status = status
WHERE subscription_status IS NULL
  AND status IS NOT NULL;

UPDATE subscriptions
SET current_period_end = expires_at
WHERE current_period_end IS NULL
  AND expires_at IS NOT NULL;

UPDATE subscriptions
SET updated_at = CURRENT_TIMESTAMP
WHERE updated_at IS NULL;
