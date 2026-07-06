-- ── 061-alert-channels.sql ───────────────────────────────────────────────────
-- Workspace alert channels: Slack, Microsoft Teams and signed generic webhooks.
--
-- SMBs live in Teams/Slack, not in another dashboard. A channel receives the
-- same events that already trigger alert emails (scan completed, asset
-- changes, certificate expiry) as a provider-formatted POST. Generic webhooks
-- are signed (HMAC-SHA256, X-CyberMeters-Signature) so receivers can verify
-- authenticity. URLs are validated at create time (https only, provider host
-- allow-list for slack/teams, private/loopback hosts rejected).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/061-alert-channels.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS workspace_alert_channels;

CREATE TABLE IF NOT EXISTS workspace_alert_channels (
    id                   TEXT PRIMARY KEY,
    workspace_id         TEXT NOT NULL,
    channel_type         TEXT NOT NULL CHECK (channel_type IN ('slack','teams','webhook')),
    webhook_url          TEXT NOT NULL,   -- validated https endpoint; never exposed in full via the API
    secret               TEXT,            -- HMAC secret for channel_type='webhook'; returned once at creation
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_by           TEXT,            -- user id that added the channel
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    last_delivery_at     TEXT,            -- last attempt timestamp (success or failure)
    last_delivery_status TEXT,            -- 'ok' | 'failed:<reason>' — customer-safe, no raw errors
    failure_count        INTEGER NOT NULL DEFAULT 0,  -- consecutive failures; reset on success
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_alert_channels_ws
    ON workspace_alert_channels (workspace_id, enabled);
