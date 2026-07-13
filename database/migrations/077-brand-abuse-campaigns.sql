-- ── 077-brand-abuse-campaigns.sql ─────────────────────────────────────────
-- Campaign linking for managed Brand abuse cases. Additive only; enums live
-- in application code.

CREATE TABLE IF NOT EXISTS brand_abuse_campaigns (
    id                    TEXT PRIMARY KEY,
    workspace_id          TEXT NOT NULL,
    brand_profile_id      TEXT,
    linked_domains        TEXT,
    linked_ips            TEXT,
    shared_certs          TEXT,
    shared_favicon_hashes TEXT,
    first_seen_at         TEXT,
    last_seen_at          TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_brand_abuse_campaigns_profile
  ON brand_abuse_campaigns (workspace_id, brand_profile_id);

CREATE TABLE IF NOT EXISTS brand_evidence_bundles (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    version       INTEGER NOT NULL,
    content_hash  TEXT NOT NULL,
    bundle_json   TEXT NOT NULL,
    captured_at   TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (case_id) REFERENCES managed_cases(id),
    UNIQUE (workspace_id, case_id, version),
    UNIQUE (workspace_id, case_id, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_brand_evidence_bundles_case
  ON brand_evidence_bundles (workspace_id, case_id, version DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_cases_brand_open_dedup
  ON managed_cases (workspace_id, finding_id)
  WHERE case_type = 'brand_abuse'
    AND status NOT IN ('false_positive', 'closed', 'risk_accepted');
