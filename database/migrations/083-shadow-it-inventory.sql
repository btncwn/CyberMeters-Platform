-- ── 083-shadow-it-inventory.sql ───────────────────────────────────────────
-- Shadow IT & Unmanaged Technology: the canonical, workspace-scoped approved
-- inventory of EXTERNALLY OBSERVED technology, plus its append-only history.
-- Additive only. This is the source of truth for CLASSIFICATION / OWNERSHIP /
-- LIFECYCLE of a correlated technology; the raw observation evidence stays in
-- workspace_vendors / workspace_assets (referenced, not duplicated).
--
-- Honest scope: items are EXTERNALLY OBSERVED. Classification is a CUSTOMER
-- decision, separate from observation; nothing is "unauthorised" until the
-- customer classifies it. No internal-network / endpoint / CASB / EDR claim.

CREATE TABLE IF NOT EXISTS shadow_it_inventory (
    id                        TEXT PRIMARY KEY,            -- sii-<hex>  (inventory_item_id)
    workspace_id              TEXT NOT NULL,
    -- Stable product-level identity (slug of the observed technology name);
    -- NEVER a mutable display name. Distinct products of the same provider keep
    -- distinct keys (google_workspace vs google_cloud).
    canonical_technology_key  TEXT NOT NULL,
    display_name              TEXT,                        -- mutable label (observed name)
    provider                  TEXT,                        -- inferred provider/parent (display only)
    category                  TEXT,                        -- infrastructure|cloud|email_identity|hosting|saas|support|collaboration|ecommerce|other
    source_type               TEXT,                        -- correlated source module(s): vendor_risk|vendor_relationship|saas_exposure|identity_discovery|certificate_authority
    observed_identifiers_json TEXT,                        -- JSON array of raw identifiers (source labels/ips)
    observed_hostnames_json   TEXT,                        -- JSON array of observed hostnames / portal URLs
    observed_domains_json     TEXT,                        -- JSON array of observed domains
    first_seen_at             TEXT NOT NULL,
    last_seen_at              TEXT NOT NULL,
    last_changed_at           TEXT,                        -- last MATERIAL change (provider/category/new hostname)
    confidence                TEXT,                        -- high|medium|low (external-observation confidence)
    -- Customer classification — separate from observation. approved != secure;
    -- rejected != removed. Default unreviewed.
    classification            TEXT NOT NULL DEFAULT 'unreviewed', -- unreviewed|approved|rejected|exception|unknown_owner|retired
    classification_reason     TEXT,
    business_purpose          TEXT,
    business_owner            TEXT,
    technical_owner           TEXT,
    approved_at               TEXT,
    approved_by               TEXT,
    rejected_at               TEXT,
    rejected_by               TEXT,
    exception_until           TEXT,                        -- exception REQUIRES expiry + reason
    exception_reason          TEXT,
    onboarding_status         TEXT,                        -- not_started|in_progress|onboarded
    removal_status            TEXT,                        -- not_started|in_progress|removed (customer-asserted, NOT verified-gone)
    -- Observation state — disappearance is NEVER auto-equated to verified removal.
    monitoring_status         TEXT NOT NULL DEFAULT 'observed', -- observed|no_longer_observed|reappeared
    source_evidence_json      TEXT,                        -- references to workspace_vendors rows + evidence
    linked_case_id            TEXT,                        -- managed_cases.id when follow-up is open
    created_at                TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                TEXT NOT NULL DEFAULT (datetime('now')),
    -- Exactly one canonical inventory identity per correlated technology.
    UNIQUE (workspace_id, canonical_technology_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_shadow_it_inventory_ws
  ON shadow_it_inventory (workspace_id, classification, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_shadow_it_inventory_monitoring
  ON shadow_it_inventory (workspace_id, monitoring_status);

-- Append-only history / audit for each inventory item. Repeated evidence and
-- every customer action append here; nothing rewrites prior rows.
CREATE TABLE IF NOT EXISTS shadow_it_inventory_events (
    id            TEXT PRIMARY KEY,          -- sie-<hex>
    item_id       TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    actor_type    TEXT NOT NULL,             -- system|customer
    actor_id      TEXT,
    event_type    TEXT NOT NULL,             -- observed|material_change|classified|owner_assigned|purpose_set|onboarding_changed|removal_changed|retired|reopened|case_linked|monitoring_changed
    detail_json   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_shadow_it_inventory_events_item
  ON shadow_it_inventory_events (item_id, created_at);
