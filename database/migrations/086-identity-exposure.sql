-- ── 086-identity-exposure.sql ─────────────────────────────────────────────
-- Identity Exposure Managed Workflow: the canonical, workspace-scoped MANAGED
-- record for each externally-observed identity/login surface, plus its
-- append-only history. Additive only. This is the source of truth for customer
-- CLASSIFICATION, OWNERSHIP, REMEDIATION, VERIFICATION and MONITORING — the raw
-- externally-observed identity evidence stays in `identity_assets` (mig 030),
-- which is referenced (never duplicated) and never overwritten on change.
--
-- Honest scope (permanent). External observation only — public login pages,
-- authentication portals, identity-provider surfaces, admin/management login
-- surfaces, federation/OAuth/SAML endpoints where observable. A publicly visible
-- identity entry point is NOT automatically a vulnerability. CyberMeters does NOT
-- observe leaked/breached credentials, dark-web/stealer data, MFA enrolment,
-- Conditional Access, internal Entra/Google/Okta policy, sign-in telemetry or
-- account takeover — those stay unknown/unavailable. Customer classification is
-- separate from observation; a customer-recorded change/removal is NOT verified
-- until externally re-observed. Follow-up uses the Universal Managed-Case Model
-- (identity_case → identity.* canonical remediation).

CREATE TABLE IF NOT EXISTS identity_exposure (
    id                        TEXT PRIMARY KEY,            -- ie-<hex>  (identity_exposure_id)
    workspace_id              TEXT NOT NULL,
    domain_id                 TEXT NOT NULL,

    -- ── Deterministic managed-record identity ────────────────────────────
    -- Stable key from provider/surface/hostname (NOT a mutable display label).
    -- A hostname-anchored surface keeps its identity across a provider change
    -- (so the change is a material event, not a new record); a provider-level
    -- detection (no hostname) is anchored on provider_key + surface_type.
    canonical_identity_key    TEXT NOT NULL,
    provider_key              TEXT,                        -- normalized (alias-resolved) provider slug
    provider_name             TEXT,                        -- observed display name (mutable)
    surface_type              TEXT,                        -- identity_provider|sso_portal|saml_federation|login_portal|admin_login|vpn_portal|oauth_endpoint
    primary_hostname          TEXT,

    observed_urls_json        TEXT,                        -- JSON array of observed URLs
    observed_endpoints_json   TEXT,                        -- JSON array of observed endpoints
    observed_protocols_json   TEXT,                        -- JSON array (saml/oidc/oauth/...) where observable
    tenant_identifier         TEXT,                        -- public tenant id where safely observable
    realm_identifier          TEXT,                        -- public realm id where safely observable

    source_types_json         TEXT,                        -- correlated source modules
    source_evidence_json      TEXT,                        -- structured refs into identity_assets (+ others)
    first_seen_at             TEXT NOT NULL,
    last_seen_at              TEXT NOT NULL,
    last_changed_at           TEXT,                        -- last MATERIAL change (provider/endpoint/tenant/protocol)
    confidence                TEXT,                        -- high|medium|low (external-observation confidence)

    -- Externally-observed state — separate from customer classification and from
    -- verification. Disappearance is NEVER auto-equated to verified removal.
    exposure_status           TEXT NOT NULL DEFAULT 'observed', -- observed|no_longer_observed|reappeared
    risk_status               TEXT,                        -- ok|low|attention|elevated|high (explainable, not alarmist)

    -- ── Customer classification (a decision, separate from observation) ───
    customer_classification   TEXT NOT NULL DEFAULT 'unreviewed', -- unreviewed|expected|unexpected|investigate|exception|retired
    classification_reason     TEXT,

    -- ── Ownership (customer-provided operational metadata; not verified) ──
    business_owner            TEXT,
    technical_owner           TEXT,
    identity_owner            TEXT,
    ownership_status          TEXT NOT NULL DEFAULT 'missing', -- known|partial|missing
    business_purpose          TEXT,

    -- ── Remediation planning + customer action (assertions) ──────────────
    remediation_status        TEXT NOT NULL DEFAULT 'not_started', -- not_started|in_progress|customer_actioned|verified|exception|retired
    customer_action_status    TEXT,                        -- configuration_changed|surface_removed (customer-asserted)

    -- ── Verification (external-observation only; customer action != verified)
    verification_status       TEXT NOT NULL DEFAULT 'not_verified', -- not_verified|verified|failed|inconclusive|unsupported|pending
    verification_method       TEXT,                        -- external_observation|unsupported
    verification_detail_json  TEXT,                        -- structured verification evidence contract
    verified_at               TEXT,

    -- ── Monitoring / recurrence (deterministic evaluator snapshot) ───────
    monitoring_status         TEXT NOT NULL DEFAULT 'observed', -- observed|no_longer_observed|reappeared
    monitoring_reason         TEXT,
    material_change           INTEGER NOT NULL DEFAULT 0,
    evidence_age_days         INTEGER,
    recurrence_type           TEXT,
    required_case_action      TEXT,                        -- none|open_or_reopen|assign_owner|verify_action

    -- ── Exceptions (require reason + expiry) ─────────────────────────────
    exception_reason          TEXT,
    exception_until           TEXT,

    lifecycle_state           TEXT NOT NULL DEFAULT 'observed',  -- machine-stable overall rollup
    linked_case_id            TEXT,                        -- managed_cases.id when follow-up is open
    created_at                TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                TEXT NOT NULL DEFAULT (datetime('now')),
    evaluated_at              TEXT,
    -- Exactly one managed record per correlated identity surface per domain.
    UNIQUE (workspace_id, domain_id, canonical_identity_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_identity_exposure_ws
  ON identity_exposure (workspace_id, customer_classification, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_identity_exposure_domain
  ON identity_exposure (workspace_id, domain_id);
CREATE INDEX IF NOT EXISTS idx_identity_exposure_monitoring
  ON identity_exposure (workspace_id, monitoring_status);

-- Append-only history / audit for each managed identity record. Every
-- observation, provider/endpoint transition, customer action, verification and
-- evaluator transition appends here; nothing rewrites a prior row (previous
-- provider/endpoint evidence is never overwritten).
CREATE TABLE IF NOT EXISTS identity_exposure_events (
    id            TEXT PRIMARY KEY,          -- iee-<hex>
    record_id     TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    actor_type    TEXT NOT NULL,             -- system|customer
    actor_id      TEXT,
    event_type    TEXT NOT NULL,             -- observed|material_change|provider_change|classified|owner_assigned|owner_missing|purpose_set|remediation_started|customer_action_recorded|verification_requested|verified|verification_failed|exception_set|exception_cleared|retired|reopened|monitoring_changed|case_linked
    detail_json   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_identity_exposure_events_rec
  ON identity_exposure_events (record_id, created_at);
