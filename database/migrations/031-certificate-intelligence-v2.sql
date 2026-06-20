-- ── 031-certificate-intelligence-v2.sql ─────────────────────────────────────
-- Certificate Intelligence v2.
--
-- Adds cross-scan certificate timeline, SAN count, issuer history, and churn
-- support. Scanner writes are additive and non-fatal.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/031-certificate-intelligence-v2.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS certificate_observations;

CREATE TABLE IF NOT EXISTS certificate_observations (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL,
    domain_id       TEXT NOT NULL,
    scan_id         TEXT,
    certificate_key TEXT NOT NULL,
    subject         TEXT,
    issuer          TEXT,
    san_count       INTEGER NOT NULL DEFAULT 0,
    expires_at      TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    evidence_json   TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT,
    UNIQUE (workspace_id, domain_id, certificate_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_certificate_observations_workspace
    ON certificate_observations (workspace_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_certificate_observations_domain
    ON certificate_observations (workspace_id, domain_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_certificate_observations_issuer
    ON certificate_observations (workspace_id, issuer, first_seen);
