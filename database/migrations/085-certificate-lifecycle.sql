-- ── 085-certificate-lifecycle.sql ─────────────────────────────────────────
-- Certificates Managed Lifecycle: the canonical, workspace-scoped MANAGED
-- lifecycle record for a monitored domain's certificate, plus its append-only
-- history. Additive only. This is the source of truth for OWNERSHIP, RENEWAL
-- PLANNING, VERIFICATION STATE and MONITORING — the raw externally-observed
-- certificate evidence stays in `certificate_observations` (mig 031), which is
-- referenced (never duplicated) and never overwritten on replacement.
--
-- Honest scope (permanent). External observation only — no live TLS handshake,
-- no chain/root/OCSP/revocation, no private-key possession. A real X.509
-- fingerprint and serial are NOT captured and stay NULL/"unknown"; the stable
-- identity is the existing certificate_key surrogate (hash of
-- issuer|subject|expires_at|sorted-SANs). An unexpired certificate is NOT
-- "fully trusted"; a customer-asserted "renewed" is NOT externally verified —
-- verification requires a NEW distinct certificate observed on the expected
-- hostname(s) with acceptable coverage and a later expiry. Incomplete coverage
-- cannot verify. Follow-up uses the Universal Managed-Case Model
-- (certificate_case → cert.* canonical remediation).

CREATE TABLE IF NOT EXISTS certificate_lifecycle (
    id                          TEXT PRIMARY KEY,            -- cl-<hex>  (certificate_lifecycle_id)
    workspace_id                TEXT NOT NULL,
    domain_id                   TEXT NOT NULL,
    -- The hostname this lifecycle record tracks (the monitored domain / cert CN).
    primary_hostname            TEXT NOT NULL,

    -- ── Certificate identity (external-observation only) ──────────────────
    -- Stable surrogate identity = certificate_observations.certificate_key
    -- (hash of issuer|subject|expires_at|sorted-SANs). NOT a real X.509
    -- fingerprint. A renewal/replacement produces a NEW certificate_identity
    -- and a NEW certificate_observations row (the old row is preserved).
    certificate_identity        TEXT,
    -- Real cryptographic identity is NOT captured (no live TLS). Kept NULL and
    -- honest — populated only if a verified live-TLS source is ever added.
    fingerprint_sha256          TEXT,
    serial_number               TEXT,
    -- Links into the raw evidence store (never duplicated here).
    current_certificate_observation_id   TEXT,
    previous_certificate_observation_id  TEXT,               -- preserved on replacement

    issuer                      TEXT,
    not_before                  TEXT,                        -- often unknown (NULL) without live TLS
    not_after                   TEXT,                        -- = observed expires_at
    days_remaining              INTEGER,                     -- from canonical renewal policy

    -- ── Coverage (expected vs observed, kept separate) ────────────────────
    expected_hostnames_json     TEXT,                        -- CUSTOMER-declared expected hostnames
    observed_sans_json          TEXT,                        -- SANs observed on the current certificate
    coverage_status             TEXT NOT NULL DEFAULT 'unknown', -- complete|partial|missing|unexpected|unknown
    coverage_detail_json        TEXT,                        -- { covered[], missing[], unexpected[], wildcard_notes }

    -- ── Ownership (server-derived status, separate from planning) ─────────
    business_owner              TEXT,
    technical_owner             TEXT,
    renewal_owner               TEXT,
    ownership_status            TEXT NOT NULL DEFAULT 'missing', -- known|partial|missing
    provider                    TEXT,                        -- customer-recorded CA/registrar (planning only)

    -- ── Renewal planning (customer/workflow state) ────────────────────────
    renewal_status              TEXT NOT NULL DEFAULT 'not_started', -- not_started|planned|in_progress|awaiting_replacement|awaiting_verification|verified|exception|retired
    renewal_readiness           TEXT NOT NULL DEFAULT 'unknown',     -- monitoring|planning|preparation|high|critical|expired|unknown
    renewal_due_at              TEXT,                        -- = not_after
    renewal_start_by            TEXT,                        -- policy-derived latest safe start
    renewal_started_at          TEXT,
    replacement_expected_at     TEXT,                        -- customer-planned replacement date
    replacement_detected_at     TEXT,                        -- when a NEW cert identity was first observed
    replacement_recorded_at     TEXT,                        -- customer ASSERTED replacement (not verified)
    replacement_recorded_by     TEXT,

    -- ── Verification (evidence-gated; customer "done" != verified) ────────
    verification_status         TEXT NOT NULL DEFAULT 'not_verified', -- not_verified|verified_replaced|failed|inconclusive
    verification_method         TEXT,                        -- external_observation (only supported method)
    verification_detail_json    TEXT,                        -- structured verification evidence contract
    verified_at                 TEXT,

    -- ── Monitoring / recurrence (deterministic evaluator snapshot) ────────
    monitoring_status           TEXT NOT NULL DEFAULT 'observed', -- observed|no_longer_observed|reappeared
    monitoring_reason           TEXT,
    risk_status                 TEXT,                        -- ok|attention|urgent|critical|expired
    recurrence_type             TEXT,
    required_case_action        TEXT,                        -- none|open_or_reopen|assign_owner|plan_renewal|verify_replacement
    material_change             INTEGER NOT NULL DEFAULT 0,
    evidence_age_days           INTEGER,
    evaluated_at                TEXT,

    -- ── Exceptions (require reason + expiry) ──────────────────────────────
    exception_until             TEXT,
    exception_reason            TEXT,

    -- Machine-stable overall state, derived from the above.
    lifecycle_state             TEXT NOT NULL DEFAULT 'observed',

    linked_case_id              TEXT,                        -- managed_cases.id when follow-up is open
    first_seen_at               TEXT NOT NULL,
    last_seen_at                TEXT NOT NULL,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    -- Exactly one managed lifecycle record per monitored certificate host.
    UNIQUE (workspace_id, domain_id, primary_hostname),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_ws
  ON certificate_lifecycle (workspace_id, renewal_readiness, not_after);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_domain
  ON certificate_lifecycle (workspace_id, domain_id);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_monitoring
  ON certificate_lifecycle (workspace_id, monitoring_status);

-- Append-only history / audit for each lifecycle record. Every observation,
-- customer action, verification and evaluator transition appends here; nothing
-- rewrites a prior row (old-certificate evidence is never overwritten).
CREATE TABLE IF NOT EXISTS certificate_lifecycle_events (
    id            TEXT PRIMARY KEY,          -- cle-<hex>
    lifecycle_id  TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    actor_type    TEXT NOT NULL,             -- system|customer
    actor_id      TEXT,
    event_type    TEXT NOT NULL,             -- observed|replacement_detected|coverage_changed|owner_assigned|owner_missing|renewal_planned|renewal_started|replacement_expected|replacement_recorded|verification_requested|verified_replaced|verification_failed|exception_set|exception_cleared|retired|reopened|monitoring_changed|case_linked
    detail_json   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_rec
  ON certificate_lifecycle_events (lifecycle_id, created_at);
