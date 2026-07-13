-- Managed DMARC change-workflow — analyst review queue persistence (Level 3).
--
-- A proposed managed-policy change becomes a governed, reviewable request:
-- an analyst must approve it (and may not be the requester) before it executes.
-- This table is the record of intent + governance; it never holds DNS state
-- (that stays in hosted_dns_entries). The state machine lives in
-- engines/dmarc-change-workflow.js — the `state` enum is enforced in code, with
-- NO CHECK constraint, matching the hosted-dns-v2 convention so a new state
-- never needs another migration.
--
-- Fully additive: a new table only. Existing managed/autopilot flows are
-- untouched; routing a change through this queue is opt-in.

CREATE TABLE IF NOT EXISTS dmarc_change_requests (
    id                TEXT PRIMARY KEY,   -- 'cr-'+12hex
    workspace_id      TEXT NOT NULL,
    domain            TEXT NOT NULL,       -- customer domain (lowercase)
    record_kind       TEXT NOT NULL DEFAULT 'dmarc',  -- enum in code, NO CHECK
    state             TEXT NOT NULL DEFAULT 'pending_review', -- workflow state — enum in code, NO CHECK
    -- what the change does
    from_policy       TEXT,                -- e.g. 'none' / 'quarantine'
    to_policy         TEXT,                -- e.g. 'reject'
    from_value        TEXT,                -- full DMARC record before
    to_value          TEXT,                -- full DMARC record after
    -- governance / audit
    requested_by      TEXT,                -- user id who proposed it
    reason            TEXT,                -- rejection / rollback reason (required by the state machine)
    reviewed_by       TEXT,                -- analyst who approved / rejected (must differ from requested_by)
    reviewed_at       TEXT,
    scheduled_at      TEXT,                -- optional scheduled execution time
    applied_at        TEXT,
    evidence_snapshot TEXT,                -- JSON: readiness score/checks captured at proposal time
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- The analyst queue query: pending requests for a workspace, oldest first.
CREATE INDEX IF NOT EXISTS idx_dmarc_change_requests_queue
    ON dmarc_change_requests (workspace_id, state, created_at);
-- Cross-workspace sweep by state (e.g. scheduled changes due to fire).
CREATE INDEX IF NOT EXISTS idx_dmarc_change_requests_state
    ON dmarc_change_requests (state);
