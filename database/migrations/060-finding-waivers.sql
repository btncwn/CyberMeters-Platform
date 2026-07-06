-- ── 060-finding-waivers.sql ──────────────────────────────────────────────────
-- Risk acceptance (waivers) for scan findings.
--
-- A waiver records that a workspace has explicitly accepted the risk of a
-- recurring finding (keyed by the finding's stable id) for one domain, with a
-- reason and an audit trail. Waived findings stay visible in an "Accepted
-- risks" section — they are never silently hidden — and are excluded from
-- open-finding counts.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/060-finding-waivers.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS finding_waivers;

CREATE TABLE IF NOT EXISTS finding_waivers (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain       TEXT NOT NULL,          -- lowercase domain the waiver applies to
    finding_id   TEXT NOT NULL,          -- stable finding id, e.g. email_missing_dmarc
    reason       TEXT,                   -- customer-supplied justification (optional)
    waived_by    TEXT NOT NULL,          -- user id that accepted the risk
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- One waiver per (workspace, domain, finding) — POST upserts the reason.
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_waivers_scope
    ON finding_waivers (workspace_id, domain, finding_id);

CREATE INDEX IF NOT EXISTS idx_finding_waivers_ws_domain
    ON finding_waivers (workspace_id, domain);
