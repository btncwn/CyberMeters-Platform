-- F-027 internal observability. Append-only operational-event ledger: durable,
-- customer-safe records of platform health facts (DLQ observations, cron ticks,
-- alert-delivery failures) that a deadman monitor and /ready can read.
--
-- Additive and isolated: this table is written ONLY by the ops paths, never by a
-- customer request, and carries NO raw body or error prose — only safe
-- correlation IDs, attempt counts and status. Tenant isolation applies: rows may
-- carry a workspace_id and reads are workspace-scoped where a workspace owns the
-- event; platform-level events carry NULL and are never returned to a tenant read.
--
-- Idempotency: (event_type, correlation_id) is UNIQUE, so a retried consumer
-- INSERT OR IGNOREs — one logical event, one row, regardless of redelivery.
CREATE TABLE IF NOT EXISTS operational_events (
  id             TEXT PRIMARY KEY,
  workspace_id   TEXT,                       -- NULL for platform-level events
  event_type     TEXT NOT NULL,              -- e.g. scan_dlq_observed, cron_tick, alert_delivery_failed
  correlation_id TEXT NOT NULL,              -- safe id (scan id / cron name+hour / message id) — never raw content
  status         TEXT NOT NULL,              -- e.g. observed, ok, failed
  attempts       INTEGER NOT NULL DEFAULT 1, -- delivery/redelivery attempt count
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (event_type, correlation_id)
);

-- Freshness / recency reads: newest-first by type, and tenant-scoped listing.
CREATE INDEX IF NOT EXISTS idx_operational_events_type_created
  ON operational_events (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_events_workspace
  ON operational_events (workspace_id, created_at DESC);
