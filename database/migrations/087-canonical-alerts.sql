-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 087: Canonical alert identity, domain attribution, delivery ledger
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Alerts Across All Eight Domains. Additive only. Three gaps this closes:
--
-- 1. NO ALERT IDENTITY. notification_events (mig 014) has no UNIQUE constraint,
--    so deduplication was advisory read-then-write (isAlertDuplicate) — two
--    concurrent scans could both read "not a duplicate" and both send.
--    dedupe_key + a partial UNIQUE index makes duplicate suppression a database
--    guarantee (INSERT OR IGNORE → meta.changes === 0), not a hope.
--
-- 2. NO DOMAIN ATTRIBUTION. Nothing recorded WHICH of the eight canonical
--    domains an alert belongs to. The existing `domain` metadata field is a
--    HOSTNAME (it is rendered as one in the bell UI and carried in the frozen
--    signed-webhook envelope), so it cannot be repurposed. domain_key is a new,
--    distinctly-named column holding a CYBER_MOT_DOMAINS key.
--
-- 3. NO APPEND-ONLY DELIVERY HISTORY. workspace_alert_channels' three
--    last_delivery_* columns are OVERWRITTEN on every send: one data point per
--    channel, zero per alert. A managed platform that claims to alert could not
--    prove it did, and could not distinguish "suppressed on purpose" from
--    "silently lost". alert_deliveries is the append-only ledger: one row per
--    alert per channel per attempt, with an explicit terminal/retryable outcome.
--
-- 4. NO ACTIVATION BASELINE. The lifecycle evaluators already carry recurrence
--    state for rows that predate alerting, so switching alerts on would announce
--    the entire existing backlog as if it were new. alert_activation is the
--    per-(workspace, domain) watermark that makes pre-existing state history.
--
-- Honest scope: this records what CyberMeters ATTEMPTED and what the provider
-- ACCEPTED. Provider acceptance is not proof a human read the alert; no column
-- here should ever be presented as "the customer was informed".
--
-- Backward compatible: both new notification_events columns are nullable, so
-- pre-087 writers keep working and pre-087 rows stay valid. The UNIQUE index is
-- partial (WHERE dedupe_key IS NOT NULL) so the existing rows — which all have
-- NULL dedupe_key — cannot collide.
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer
--   setting dedupe_key/domain_key the columns stay NULL and the partial index
--   matches nothing, so behaviour is identical to pre-migration. alert_deliveries
--   simply stops receiving rows. (D1/SQLite has no DROP COLUMN path here, and
--   none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/087-canonical-alerts.sql

-- ── notification_events: canonical alert identity + domain attribution ────────

-- The canonical domain this alert belongs to (a CYBER_MOT_DOMAINS key, e.g.
-- 'certificates_trust'). NULL for pre-087 rows and for any writer that has not
-- been migrated. NOT the same thing as the `domain` metadata field, which is a
-- hostname.
ALTER TABLE notification_events ADD COLUMN domain_key TEXT;

-- Deterministic alert identity. Same real-world event => same key => at most one
-- alert. Built server-side from stable inputs (workspace + domain_key + kind +
-- subject + period), never from customer input or mutable display copy.
ALTER TABLE notification_events ADD COLUMN dedupe_key TEXT;

-- Duplicate suppression as a DB guarantee. Partial so the pre-087 rows (all NULL)
-- are unaffected, and so a writer that supplies no key degrades to the old
-- behaviour rather than erroring.
CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_dedupe
    ON notification_events (workspace_id, dedupe_key)
    WHERE dedupe_key IS NOT NULL;

-- Per-domain alert history for the bell/notifications surface.
CREATE INDEX IF NOT EXISTS idx_notif_workspace_domain
    ON notification_events (workspace_id, domain_key, created_at);

-- ── alert_deliveries — append-only delivery ledger ───────────────────────────
--
-- One row per (alert, channel) attempt. Append-only: rows are never updated or
-- deleted, so the history of what was attempted, suppressed or delivered is
-- reconstructable. A retry appends a NEW row rather than overwriting the last.
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id                TEXT PRIMARY KEY,
    workspace_id      TEXT NOT NULL,
    -- The notification_events row this delivery belongs to. Nullable so a
    -- delivery suppressed BEFORE the event was written is still recordable.
    notification_id   TEXT,
    domain_key        TEXT,
    alert_kind        TEXT NOT NULL,
    dedupe_key        TEXT,
    severity          TEXT,

    -- Channel this attempt targeted: in_app | email | webhook | slack | teams.
    channel           TEXT NOT NULL,
    -- Channel row (workspace_alert_channels.id) when the channel is configurable.
    channel_id        TEXT,

    -- What happened. Exactly one of:
    --   delivered   — the provider accepted it (NOT proof a human read it)
    --   suppressed  — we deliberately did not send (see reason)
    --   failed      — we tried and it did not land
    outcome           TEXT NOT NULL,

    -- Why, as a closed vocabulary. Terminal suppressions:
    --   feature_not_entitled | channel_disabled | no_verified_recipient |
    --   workspace_deleted | deduplicated | cooldown_active |
    --   recipient_undeliverable
    -- Retryable failures:
    --   provider_rejected | provider_unavailable | recipient_lookup_failed |
    --   missing_api_key | invalid_sender | send_failed
    reason            TEXT,

    -- 1 = this outcome is final and must NEVER be retried. A terminal
    -- suppression is a decision, not a transient error; retrying it would both
    -- waste budget and, for feature_not_entitled/channel_disabled, override a
    -- deliberate rule.
    terminal          INTEGER NOT NULL DEFAULT 0,

    -- Provider's id for the accepted message, when there is one.
    provider_id       TEXT,
    -- How many verified recipients this attempt targeted (never the addresses:
    -- the ledger must not become a second copy of customer PII).
    recipient_count   INTEGER NOT NULL DEFAULT 0,
    attempt           INTEGER NOT NULL DEFAULT 1,

    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Delivery history for one workspace, newest first.
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_workspace
    ON alert_deliveries (workspace_id, created_at);

-- Retry sweep: non-terminal failures inside a bounded recent window.
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_retry
    ON alert_deliveries (outcome, terminal, created_at);

-- Per-alert audit: every attempt against one notification.
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_notification
    ON alert_deliveries (notification_id, created_at);

-- ── alert_activation — the first-run flood guard ─────────────────────────────
--
-- Wiring alerts onto the shipped lifecycle evaluators would otherwise fire
-- RETROACTIVELY: certificate_lifecycle, identity_exposure and shadow_it_inventory
-- rows already exist in production carrying non-null recurrence_type, recomputed on
-- every evaluation. Without a watermark, the first evaluation after deploy would
-- alert on every pre-existing row at once — the first invited customers would open
-- an inbox flood describing conditions that are not new to them.
--
-- So each (workspace, domain) is ACTIVATED exactly once. The activating evaluation
-- establishes the baseline and alerts on nothing; only changes observed strictly
-- after activated_at may alert. Pre-existing state is history, not news.
--
-- Idempotent by construction: UNIQUE (workspace_id, domain_key) + INSERT OR IGNORE
-- means a concurrent or repeated pass cannot re-baseline or double-activate, and
-- cannot un-suppress what a previous pass already treated as history.
--
-- Tenant-scoped: keyed by workspace_id with an FK, and purged with the workspace.
CREATE TABLE IF NOT EXISTS alert_activation (
    id             TEXT PRIMARY KEY,
    workspace_id   TEXT NOT NULL,
    -- A CYBER_MOT_DOMAINS key. Activation is per-domain so a domain wired later
    -- baselines on its own first evaluation rather than inheriting another's.
    domain_key     TEXT NOT NULL,
    -- The watermark. Anything observed at or before this instant is pre-existing
    -- state and must never become an alert.
    activated_at   TEXT NOT NULL,
    -- How many records the baseline pass saw. Diagnostic only — it is NOT a claim
    -- that the customer was told about them.
    baseline_count INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (workspace_id, domain_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_alert_activation_workspace
    ON alert_activation (workspace_id, domain_key);
