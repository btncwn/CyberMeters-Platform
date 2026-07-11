-- 069 — Stripe webhook idempotency / replay protection.
--
-- Stripe retries webhook deliveries and can re-send the same event; without a
-- record of what we've already handled, a replayed (or duplicated) event could
-- re-apply a subscription state transition. Each event id is recorded here on
-- first handling; a second delivery of the same id is acknowledged and skipped.
--
-- Additive and idempotent (IF NOT EXISTS). No rollback needed — dropping this
-- table only re-enables replays; the webhook still verifies signatures.

CREATE TABLE IF NOT EXISTS stripe_processed_events (
    id           TEXT PRIMARY KEY,             -- Stripe event id (evt_...)
    event_type   TEXT,                         -- e.g. checkout.session.completed
    processed_at TEXT DEFAULT CURRENT_TIMESTAMP
);
