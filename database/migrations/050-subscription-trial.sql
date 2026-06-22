-- ── 050-subscription-trial.sql ─────────────────────────────────────────────
-- Sprint 14 — Billing & Trial Foundation
--
-- Adds:
--   subscriptions.trial_start          ISO-8601 timestamp, set on workspace creation
--   subscriptions.trial_end            ISO-8601 = trial_start + 14 days
--   subscriptions.current_period_start ISO-8601, set on Stripe subscription update
--
--   subscription_events                Audit log for subscription lifecycle events
--
-- Context:
--   The subscriptions table was created manually and documented retroactively
--   in migration 047. Migrations 028 and 029 added Stripe and billing alignment
--   columns. This migration adds trial tracking columns and the events table.
--
-- On production (existing deployment):
--   ALTER TABLE statements are additive and safe to apply. Existing rows get
--   NULL for the new columns; the application handles NULL gracefully.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/050-subscription-trial.sql
--
-- Validation:
--   PRAGMA table_info(subscriptions);
--   -- Expect: trial_start, trial_end, current_period_start columns present
--
--   PRAGMA table_info(subscription_events);
--   -- Expect: id, subscription_id, event_type, payload_json, created_at
--
--   SELECT name FROM sqlite_master
--   WHERE type='index' AND tbl_name='subscription_events';
--   -- Expect: idx_subscription_events_subscription_id
--
-- Rollback:
--   D1 (SQLite) does not support DROP COLUMN. To rollback:
--   1. Stop writing to trial_start, trial_end, current_period_start
--   2. Drop subscription_events if needed: DROP TABLE IF EXISTS subscription_events;
--   Columns remain but are ignored by the application.

-- ── Add trial tracking columns to subscriptions ─────────────────────────────

ALTER TABLE subscriptions ADD COLUMN trial_start          TEXT;
ALTER TABLE subscriptions ADD COLUMN trial_end            TEXT;
ALTER TABLE subscriptions ADD COLUMN current_period_start TEXT;

-- ── subscription_events ──────────────────────────────────────────────────────
-- Immutable audit log for all subscription lifecycle events.
--
-- event_type values:
--   trial_started       — workspace created, 14-day trial begins
--   trial_expired       — trial_end passed without upgrade
--   plan_upgraded       — subscription plan increased
--   plan_downgraded     — subscription plan decreased
--   payment_succeeded   — invoice.payment_succeeded webhook
--   payment_failed      — invoice.payment_failed webhook
--   subscription_cancelled — customer.subscription.deleted webhook
--   subscription_created   — checkout.session.completed webhook
--   subscription_updated   — customer.subscription.updated webhook

CREATE TABLE IF NOT EXISTS subscription_events (
  id              TEXT    PRIMARY KEY,
  subscription_id TEXT    NOT NULL,
  event_type      TEXT    NOT NULL,
  payload_json    TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
);

CREATE INDEX IF NOT EXISTS idx_subscription_events_subscription_id
  ON subscription_events (subscription_id);

CREATE INDEX IF NOT EXISTS idx_subscription_events_event_type
  ON subscription_events (event_type);

CREATE INDEX IF NOT EXISTS idx_subscription_events_created_at
  ON subscription_events (created_at);
