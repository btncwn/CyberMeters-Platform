-- Migration 047: Create subscriptions table (comprehensive DDL)
--
-- Context:
--   The subscriptions table was created manually in the initial production
--   deployment and was never tracked in a migration file. Migrations 028 and
--   029 extended it with ALTER TABLE statements, but the base CREATE TABLE
--   does not exist in the migration chain.
--
--   This migration retroactively documents the full table schema so that:
--     - The schema is source-controlled
--     - New CI/staging environments can be bootstrapped from migrations alone
--     - The complete column set (base + 028 + 029) is visible in one place
--
-- On production (existing deployment):
--   CREATE TABLE IF NOT EXISTS is a no-op — the table already exists with all
--   columns from migrations 028 and 029. The CREATE UNIQUE INDEX statements
--   use IF NOT EXISTS and are safe to re-run.
--
-- On fresh deployments:
--   Creates the complete table. Migrations 028 and 029 will then produce
--   "duplicate column" errors because the columns already exist. Those
--   migrations should be skipped on a fresh install by applying this file
--   in their place. See docs/migrations.md for bootstrapping guidance.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/047-subscriptions-table.sql
--
-- Validation:
--   PRAGMA table_info(subscriptions);
--   Expect all columns listed below.
--   SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='subscriptions';

CREATE TABLE IF NOT EXISTS subscriptions (
  -- ── Identity ──────────────────────────────────────────────────────────────
  id                    TEXT PRIMARY KEY,

  -- ── User & workspace scope ────────────────────────────────────────────────
  -- owner_user_id: account-level owner. Added by migration 029.
  -- Used by getUserPlan(), GET /api/account/subscription, webhook upserts.
  owner_user_id         TEXT,

  -- workspace_id: workspace-level FK from the pre-billing era.
  -- Kept for backward compatibility; owner_user_id is the active billing key.
  workspace_id          TEXT,

  -- ── Plan & subscription state ─────────────────────────────────────────────
  plan                  TEXT NOT NULL DEFAULT 'free',
  status                TEXT NOT NULL DEFAULT 'active',

  -- subscription_status: Stripe-aligned lifecycle status (active, trialing,
  -- past_due, canceled, incomplete). Added by migration 029.
  -- Separate from status to preserve the legacy status column.
  -- getUserPlan() reads subscription_status; status is the legacy field.
  subscription_status   TEXT,

  -- ── Billing cycle ─────────────────────────────────────────────────────────
  -- billing_interval: 'monthly' | 'annual'. Added by migration 028.
  -- Returned as billing_cycle in API responses.
  billing_interval      TEXT DEFAULT 'monthly',

  -- ── Stripe identifiers ────────────────────────────────────────────────────
  -- Added by migration 028.
  stripe_customer_id     TEXT,
  stripe_subscription_id TEXT,
  stripe_price_id        TEXT,

  -- ── Period & cancellation ─────────────────────────────────────────────────
  -- expires_at: legacy period-end field. Backfilled to current_period_end
  -- by migration 029.
  expires_at            TEXT,

  -- current_period_end: ISO-8601 timestamp. Added by migration 029.
  -- getUserPlan() checks this against Date.now() for expiry.
  current_period_end    TEXT,

  -- cancel_at_period_end: 1 = subscription will not renew. Added by 028.
  cancel_at_period_end  INTEGER DEFAULT 0,
  cancelled_at          TEXT,

  -- ── Payment failure tracking ──────────────────────────────────────────────
  -- Added by migration 028. Set by invoice.payment_failed webhook.
  payment_failed_at     TEXT,
  payment_retry_count   INTEGER DEFAULT 0,

  -- ── Timestamps ───────────────────────────────────────────────────────────
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  -- updated_at: Added by migration 029.
  updated_at            TEXT
);

-- ── Indexes ────────────────────────────────────────────────────────────────
-- owner_user_id lookup: used by getUserPlan(), subscription fetch, upsert
CREATE INDEX IF NOT EXISTS idx_subscriptions_owner_user_id
  ON subscriptions (owner_user_id)
  WHERE owner_user_id IS NOT NULL;

-- stripe_customer_id: used by findSubscriptionRowId()
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer
  ON subscriptions (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;

-- stripe_subscription_id: used by findSubscriptionRowId()
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription
  ON subscriptions (stripe_subscription_id)
  WHERE stripe_subscription_id IS NOT NULL;
