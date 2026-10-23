-- Migration 139: one row per Stripe subscription, written from Stripe's CURRENT
-- view of that subscription (23 Oct 2026, billing P1 / Codex C-49).
--
-- Webhooks used to write the account `subscriptions` row from each event's own
-- payload, in delivery order. Stripe does not order deliveries, so late or
-- older events changed plans, revived cancelled subscriptions, opened payment
-- grace from stale invoices, and one subscription's events could overwrite
-- another's row. The Worker now fetches the subscription from Stripe on every
-- subscription/invoice/checkout event (the payload is only a trigger), stores
-- that truth here per subscription id, and derives the account row from the
-- customer's best entitled lineage.
--
-- `terminal` = 1 once a subscription is cancelled (or Stripe no longer knows
-- it): it never becomes entitled again; only a NEW subscription id can.
-- latest_invoice_* is Stripe's latest invoice for the subscription; the payment
-- grace window is anchored on its creation time, so a retried webhook never
-- restarts the grace.
--
-- Additive: one new table and two indexes. Nothing existing changes. Retained
-- on workspace purge for accounting, exactly like `subscriptions`.
--
-- Apply (before the Worker deploy, which reads and writes this table):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/139-stripe-subscription-lineages.sql
--
-- Rollback:
--   Roll the Worker back first. The table can stay; the previous Worker does
--   not read it.

CREATE TABLE IF NOT EXISTS stripe_subscription_lineages (
  stripe_subscription_id   TEXT PRIMARY KEY,
  stripe_customer_id       TEXT,
  owner_user_id            TEXT,
  workspace_id             TEXT,
  status                   TEXT NOT NULL,
  plan                     TEXT,
  stripe_price_id          TEXT,
  billing_interval         TEXT,
  current_period_start     TEXT,
  current_period_end       TEXT,
  cancel_at_period_end     INTEGER NOT NULL DEFAULT 0,
  latest_invoice_id        TEXT,
  latest_invoice_status    TEXT,
  latest_invoice_created   TEXT,
  latest_invoice_attempts  INTEGER,
  terminal                 INTEGER NOT NULL DEFAULT 0 CHECK (terminal IN (0, 1)),
  fetched_at               TEXT NOT NULL,
  created_at               TEXT NOT NULL,
  updated_at               TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stripe_subscription_lineages_customer
  ON stripe_subscription_lineages (stripe_customer_id);

CREATE INDEX IF NOT EXISTS idx_stripe_subscription_lineages_workspace
  ON stripe_subscription_lineages (workspace_id);
