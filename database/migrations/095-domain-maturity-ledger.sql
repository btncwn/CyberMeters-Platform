-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 095: Canonical per-workspace eight-domain maturity ledger
-- ─────────────────────────────────────────────────────────────────────────────
--
-- M5.f Maturity Ledger. Additive only.
--
-- ── WHAT THIS RECORDS, AND WHY IT IS NOT AN EXISTING TABLE ───────────────────
-- One workspace's honest, evidenced managed-control DEPTH per canonical domain, over
-- time. "Maturity" here is the lifecycle distance a workspace has travelled for a
-- domain — from "not reliably observed" toward "fixed, CyberMeters-verified and under
-- recurrence watch". It is DERIVED deterministically from truth that already exists and
-- must never grow a second opinion about any of it:
--   • the domain STATE for the scan (engines/cyber-mot-domains.js resolver — the ONLY
--     source of domain state; mirrored verbatim into cyber_mot_domain_states, mig 091);
--   • the managed-case LIFECYCLE for the same (workspace, domain_key)
--     (managed_cases phase timestamps + status + reopened_count, migs 076/082);
--   • the platform's verification CAPABILITY for the domain, read from the Canonical
--     Remediation Registry (verification_method per finding) — NOT hand-declared.
--
-- Nothing existing can be extended into it:
--   • cyber_mot_domain_states (091) records the resolver's per-domain STATE verbatim.
--     Maturity is a DIFFERENT axis (lifecycle depth, folding in managed-case progress
--     the resolver never sees). Overloading that table would make maturity a "second
--     opinion about domain state", which its own header forbids.
--   • managed_cases (076/082) is per-CASE, not per-domain, and mutable. Maturity is a
--     per-domain, append-only conclusion attributable to one completed eligible scan.
--   • The static CYBER_MOT_DOMAINS[].maturity ("M0".."M5") tag is a hand-declared,
--     workspace-INDEPENDENT product-lifecycle label. This table is per-WORKSPACE and
--     evidence-derived. They are different concepts (the static tag is left untouched).
--
-- ── HONEST SCOPE (permanent) ─────────────────────────────────────────────────
-- Only a COMPLETE-quality scan produces a maturity row (scan_quality='complete').
-- Missing / failed / partial / degraded / unavailable / not-yet-assessed evidence NEVER
-- produces a mature row and never advances maturity — a partial scan writes NOTHING here,
-- so the current view honestly stays "as of the last complete assessment". An absent row
-- means NOT ESTABLISHED, never "healthy" and never "mature". A customer attestation or an
-- approved-inventory classification ALONE can never reach the verified/monitored stages —
-- those are reserved for CyberMeters' own re-observation (verification-vocabulary.md).
--
-- ── ATTRIBUTION / APPEND-ONLY ────────────────────────────────────────────────
-- Every row is attributed to exactly one completed eligible scan (scan_id + assessed_at =
-- the SCAN's completion time, never now()). Append-only: a later scan appends a NEW row;
-- prior rows are never updated. Regression (a domain dropping stage after a recurrence) is
-- recorded as a new, lower row with previous_stage set — history is preserved, never edited.
--
-- ── NO FOREIGN KEY TO scans ─────────────────────────────────────────────────
-- The 085/086/088/089/090/091/093 precedent: history must outlive the scan it describes,
-- and an FK would force this table into SCAN_CHILD_TABLES where a missed entry stalls the
-- purge forever. scan_id is provenance only.
--
-- ── PURGE ────────────────────────────────────────────────────────────────────
-- workspace_id is NOT NULL so scripts/validate-purge-completeness.js discovers the table.
-- Registered in WORKSPACE_PURGE_TABLES (workers/scan-api/src/index.js) — pure D1, no R2
-- object, so a plain DELETE FROM ... WHERE workspace_id = ? (the 091 pattern).
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer the table
--   stops receiving rows; readers return the honest eight-domain "not_established"
--   skeleton. (D1/SQLite has no DROP COLUMN path, and none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/095-domain-maturity-ledger.sql

CREATE TABLE IF NOT EXISTS domain_maturity_ledger (
  id                       TEXT PRIMARY KEY,        -- dml-<hex>
  workspace_id             TEXT NOT NULL,           -- tenant boundary; purge key
  domain_id                TEXT NOT NULL,           -- domains.id — the domain RECORD, not the hostname
  scan_id                  TEXT NOT NULL,           -- provenance; no FK (history outlives the scan)
  domain_key               TEXT NOT NULL,           -- one of the canonical eight (CYBER_MOT_DOMAINS)

  -- The deterministic conclusion. Never re-derived on read.
  maturity_stage           TEXT NOT NULL,           -- not_established|observed|managed|verified|monitored
  capability_ceiling       TEXT NOT NULL,           -- highest stage the domain CAN reach (registry-derived)
  reason_code              TEXT NOT NULL,           -- machine reason the stage was concluded
  previous_stage           TEXT,                    -- set only on a recorded regression (current < prior)

  -- Honest annotations that are NOT ladder rungs. JSON: {attested, regressed,
  -- has_unmanaged_issue}. Evidence: {source_scan_id, case_ids[], finding_ids[]}.
  flags_json               TEXT NOT NULL DEFAULT '{}',
  evidence_json            TEXT NOT NULL DEFAULT '{}',

  scan_quality             TEXT,                    -- complete only produces rows; recorded for audit
  resolver_version         TEXT NOT NULL,           -- CYBER_MOT_RESOLVER_VERSION at write time
  ledger_contract_version  TEXT NOT NULL,           -- MATURITY_LEDGER_CONTRACT_VERSION — compare only within a version

  assessed_at              TEXT NOT NULL,           -- the SCAN's completion time = occurrence identity
  created_at               TEXT NOT NULL DEFAULT (datetime('now')),

  -- Exactly one row per domain per scan per tenant: this is what makes a re-finalize or a
  -- reconciler re-run an idempotent no-op rather than a second identity.
  UNIQUE (workspace_id, domain_id, scan_id, domain_key),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Current maturity per (tenant, domain, domain_key) and the ordered history behind it.
-- Leading column is workspace_id — the tenant boundary is never an afterthought in an index.
CREATE INDEX IF NOT EXISTS idx_dml_current
  ON domain_maturity_ledger (workspace_id, domain_id, domain_key, assessed_at DESC);

-- "Everything this scan concluded" (idempotency checks, provenance drill-down).
CREATE INDEX IF NOT EXISTS idx_dml_scan
  ON domain_maturity_ledger (workspace_id, scan_id);
