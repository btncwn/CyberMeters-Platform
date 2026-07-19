-- 098 — M6 Phase B1: Deterministic Related Changes.
--
-- Persists correlation CLUSTERS and their EVIDENCE POINTERS. Per the design note
-- (docs/M6-PHASE-B1-RELATED-CHANGES-DESIGN.md §7), a cluster is produced only when a
-- deterministic rule pairs >=2 INDEPENDENT signal families for the SAME registrable
-- domain inside a bounded window. There is no statistics and no AI here (that is
-- B2/B3): the rule DECIDES, the wording stays "related / correlated / requires
-- verification", and change != compromise.
--
-- Two tables, mirroring the platform's persistent-lifecycle + append-only-event
-- shape (managed_cases + managed_case_events):
--
--   related_changes           — the persistent cluster. Its customer_state
--                               (new|expected|unrelated|unexpected_confirmed) is the
--                               real training signal for B2 and is customer-mutable;
--                               recurrence bookkeeping (last_seen/recurrence_count)
--                               updates in place. Identity is a stable cluster_key so
--                               the same correlation recurring across scans updates
--                               ONE row rather than piling up.
--   related_change_evidence   — APPEND-ONLY pointers to the contributing producer
--                               rows. NO raw evidence is ever copied here (design §7):
--                               the cluster references evidence by pointer to prevent
--                               drift/duplication. Idempotent per scan.
--
-- Both are workspace_id-scoped tenant resources: they enter WORKSPACE_PURGE_TABLES
-- (workers/scan-api/src/index.js) and RESOURCE_CLASSES
-- (scripts/security/lib/tenant-resources.js), or the assurance gates block — exactly
-- as they did for workspace_branding (096).
--
-- Additive and backward-compatible. No existing table is altered. Applied BEFORE the
-- dependent Worker deploy.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/098-related-changes.sql

CREATE TABLE IF NOT EXISTS related_changes (
  id                          TEXT PRIMARY KEY,      -- rc-<hex>
  workspace_id                TEXT NOT NULL,         -- tenant boundary; purge key
  -- Stable cluster identity = sha256(registrable_domain | rule_id), scoped per
  -- workspace by the UNIQUE index below. The same rule firing on the same
  -- registrable domain in a later scan updates THIS row (recurrence), never a new one.
  cluster_key                 TEXT NOT NULL,
  registrable_domain          TEXT NOT NULL,         -- eTLD+1 (UK-scoped resolver, design §3a); cross-tier join key
  rule_id                     TEXT NOT NULL,         -- a registered deterministic rule (related-changes-rules.js)
  direction                   TEXT NOT NULL,         -- appeared|changed|degraded — the consistent-direction contract (§4.5)

  -- Independence counters (§4.3). event_count is raw; these two gate the cluster.
  signal_family_count         INTEGER NOT NULL,      -- distinct INDEPENDENT signal families (>=2 required)
  independent_producer_count  INTEGER NOT NULL,      -- distinct independent producers (a producer's two events count once)

  -- Deterministic label ONLY. Never a statistic, never a probability. The rule
  -- decided; this records WHICH honesty tier the evidence reached.
  confidence                  TEXT NOT NULL DEFAULT 'correlated',
  completeness                TEXT NOT NULL,         -- complete|partial (min-evidence-completeness contract §4.7)

  -- The customer's word. This is the signal that trains rule quality for B2.
  -- 'new' on first observation; the customer may mark expected/unrelated or confirm
  -- unexpected. A recurrence NEVER silently resets a customer declaration.
  customer_state              TEXT NOT NULL DEFAULT 'new',  -- new|expected|unrelated|unexpected_confirmed

  first_seen                  TEXT NOT NULL,         -- first correlated observation = occurrence identity (never now())
  last_seen                   TEXT NOT NULL,         -- most recent correlated observation
  recurrence_count            INTEGER NOT NULL DEFAULT 1,
  last_scan_id                TEXT,                  -- most recent scan that contributed — recurrence idempotency

  linked_case_id              TEXT,                  -- managed_cases.id; MANUAL link/create only (no auto case in v1)

  created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at                  TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- One cluster per (workspace, cluster_key). The tenant column is explicit in the
-- index so identity can never collide across workspaces.
CREATE UNIQUE INDEX IF NOT EXISTS idx_related_changes_cluster
  ON related_changes (workspace_id, cluster_key);

-- List surface: newest correlated activity first, tenant-scoped.
CREATE INDEX IF NOT EXISTS idx_related_changes_ws_last_seen
  ON related_changes (workspace_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS related_change_evidence (
  id                 TEXT PRIMARY KEY,               -- rce-<hex>
  related_change_id  TEXT NOT NULL,                  -- related_changes.id
  -- Denormalised tenant key so a purge/isolation audit needs no join. Every write
  -- sets it to the parent cluster's workspace_id.
  workspace_id       TEXT NOT NULL,
  producer_family    TEXT NOT NULL,                  -- asset|cert|email_config|email_sender|identity|brand|shadow_it
  source_table       TEXT NOT NULL,                  -- physical producer table — a POINTER, not a copy
  source_record_id   TEXT NOT NULL DEFAULT '',       -- id within source_table ('' for ephemeral producers)
  source_event_type  TEXT NOT NULL DEFAULT '',       -- the producer's own event_type string
  entity_key         TEXT NOT NULL,                  -- host:<fqdn> | domain:<d> | brand-target:<d> | campaign:<id>
  observed_at        TEXT NOT NULL,                  -- the producer's observation time (never now())
  evidence_ref       TEXT,                           -- immutable id/hash where the producer offers one
  scan_id            TEXT,                            -- the scan that FIRST cited this pointer (provenance; not part of identity)
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (related_change_id) REFERENCES related_changes(id),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- A source event is cited AT MOST ONCE per cluster — NOT once per scan. This keeps
-- recurrence honest: a spanning "same/adjacent scan" window (design §4.2) re-sees the
-- previous scan's events every time, so if scan_id were part of identity the same
-- evidence would pile up and inflate recurrence. Excluding it means re-correlation adds
-- a row only when a genuinely NEW source event joins the cluster. source_record_id /
-- source_event_type default to '' (never NULL) so the key is total — NULLs are distinct
-- in a SQLite unique index and would defeat the dedupe.
CREATE UNIQUE INDEX IF NOT EXISTS idx_related_change_evidence_dedupe
  ON related_change_evidence (related_change_id, source_table, source_record_id, source_event_type, entity_key);

CREATE INDEX IF NOT EXISTS idx_related_change_evidence_rc
  ON related_change_evidence (related_change_id);

CREATE INDEX IF NOT EXISTS idx_related_change_evidence_ws
  ON related_change_evidence (workspace_id);

-- Frozen Related Changes summary for the report PDFs. Lazily written on first report
-- generation and never overwritten (the branding_json precedent, mig 096), so a later
-- correlation never rewrites a historical PDF. NULL until first render = "no summary
-- frozen yet", which the renderer treats as absent, never as "no related changes".
ALTER TABLE scan_report_snapshots ADD COLUMN related_changes_json TEXT;
