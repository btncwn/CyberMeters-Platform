-- ── 028-stripe-billing.sql ─────────────────────────────────────────────────
-- Stripe Billing Foundation v1.
-- Extends the existing manual subscription_accounts table with nullable Stripe
-- metadata fields. This migration does not add checkout, portal, webhook, or
-- invoice processing.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/028-stripe-billing.sql
--
-- Rollback: D1 (SQLite) does not support DROP COLUMN. Leave columns in place
-- and stop writing to them if rollback is required.

ALTER TABLE subscription_accounts ADD COLUMN stripe_customer_id    TEXT;
ALTER TABLE subscription_accounts ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE subscription_accounts ADD COLUMN stripe_price_id        TEXT;
ALTER TABLE subscription_accounts ADD COLUMN billing_interval       TEXT DEFAULT 'monthly';
ALTER TABLE subscription_accounts ADD COLUMN cancel_at_period_end   INTEGER DEFAULT 0;
ALTER TABLE subscription_accounts ADD COLUMN cancelled_at           TEXT;
ALTER TABLE subscription_accounts ADD COLUMN payment_failed_at      TEXT;
ALTER TABLE subscription_accounts ADD COLUMN payment_retry_count    INTEGER DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_stripe_customer
  ON subscription_accounts (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_stripe_subscription
  ON subscription_accounts (stripe_subscription_id)
  WHERE stripe_subscription_id IS NOT NULL;
