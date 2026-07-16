-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 091: Canonical per-domain Cyber MOT state history (append-only)
-- ─────────────────────────────────────────────────────────────────────────────
--
-- MSP Portfolio Per-Domain State and Trend phase. Additive only.
--
-- ── WHY THIS TABLE, AND WHY NOT AN EXISTING ONE ─────────────────────────────
-- The eight-domain resolver (engines/cyber-mot-domains.js) is compute-on-read from the
-- R2 scan report and says so in its own header: "No new storage, no migration." That is
-- the right design for "what is true right now" on ONE workspace — the Dashboard, Scan
-- Detail, Executive Report and PDF each read one report and resolve eight states from
-- it. It is the wrong design for a portfolio, for two independent reasons, and either
-- alone would force this table:
--
--   1. IT DOES NOT SCALE. State comes from R2, one object per scan, and R2 has no
--      multi-get. A 50-customer portfolio page = 50 R2 reads + ~100 D1 reads + 50 full
--      report JSON parses, on every load, uncached. The deliberately-cheap portfolio
--      path next door (portfolio-customers.js) answers the whole portfolio in 9 D1
--      queries and ZERO R2 reads. Compute-on-read is 1 read for one workspace and 50×
--      unbatchable for fifty.
--
--   2. IT HAS NO PAST TENSE. Re-deriving history through today's resolver rewrites what
--      the customer saw last month. A trend built on that attributes OUR engineering to
--      THEIR security posture. See resolver_version below.
--
-- Nothing existing can be extended into it:
--   • portfolio_risk_snapshots (036) — four scalars keyed by users.id. No workspace
--     dimension, no domain dimension, no Cyber-MOT-domain dimension, zero rows ever,
--     and its writer was deliberately deleted (#116). It stays dead. Reviving it would
--     mean a new PK, three new columns and the first writer — a new table wearing an
--     old name.
--   • historical_scores (022) — one SCORE per scan. Not eight states. "domain" there is
--     a hostname, never one of the eight product domains.
--   • The 085–090 lifecycle tables — four of eight domains, at four incompatible
--     grains, and cyber_essentials_control_records has no domain_id by an explicit
--     honesty decision (090). They cannot be unioned into "what state was domain X in
--     on date D", and they do not carry the resolver's own vocabulary (provisional /
--     evidence_insufficient / not_yet_assessed / monitoring_only) at all — those are
--     derived from scan_quality + module presence, which live in scans and R2.
--   • asset_events (004) — the right skeleton (workspace_id + domain_id + scan_id +
--     created_at) but a hostname/DNS/cert vocabulary, no domain_key, and no state
--     column. It records transitions, not resolved states.
--
-- This table stores the CANONICAL RESOLVER'S OWN OUTPUT, verbatim. It is a cache with
-- a memory, not a second opinion: there is exactly one place that decides what state a
-- domain is in, and this is a record of what it decided and when.
--
-- ── ENTITY GRANULARITY — (workspace, domain-record, scan, domain_key) ────────
-- Keyed on workspace_id AND domain_id, never on hostname. The same hostname can exist
-- in two workspaces as two distinct domains.id rows (domains has no UNIQUE on domain),
-- and one domains.id can be linked into several workspaces (workspace_domains PK is
-- composite). Migration 079 settled the rule for this exact shape: "A domain verified
-- in one workspace must NOT authorize scanning in another." The same applies to state —
-- two MSP clients on the same hostname are two independent customers and must never
-- share a row, a trend, or a verdict.
--
-- docs/P0-PUBLIC-BETA-BLOCKERS.md:95 records the live bug from getting this wrong: the
-- trend baseline in runHistoricalModule selects `WHERE domain = ?` with no workspace
-- scope, so one workspace's score_change can be derived from another's scan. That is
-- why the UNIQUE below leads with workspace_id and there is no hostname column.
--
-- ── APPEND-ONLY, AND WHAT THAT COSTS ────────────────────────────────────────
-- One row per (workspace, domain, scan, domain_key) — eight rows per assessed scan.
-- INSERT OR IGNORE against the UNIQUE makes a re-finalize or a reconciler re-run
-- idempotent rather than a second identity. Nothing UPDATEs this table; a state that
-- was true is true forever, and a resolver change adds rows rather than editing them.
--
-- assessed_at is the SCAN's time, not now(). It is the occurrence identity — when the
-- evidence was actually observed. Migration 090's rule: evaluated_at "drifts every
-- pass" and is never a condition-start. There is no evaluated_at here at all, because
-- the write happens once, at finalize, and never re-evaluates.
--
-- ── NO FOREIGN KEY TO scans ─────────────────────────────────────────────────
-- Deliberate, and it is the 085/086/088/089/090 precedent: history must outlive the
-- record it describes. A plain nullable scan_id also keeps this table OUT of
-- SCAN_CHILD_TABLES — with an FK, purging a scan would fail and, in index.js's own
-- words, "the purge stalls forever".
--
-- ── PURGE ────────────────────────────────────────────────────────────────────
-- workspace_id is present and NOT NULL, which is what makes
-- scripts/validate-purge-completeness.js see this table at all: it discovers
-- tenant-scoped tables by PRAGMA table_info and fails CI on any workspace_id-bearing
-- table that is neither purged nor explicitly excepted. Registered in
-- WORKSPACE_PURGE_TABLES (workers/scan-api/src/index.js). This is exactly the gate that
-- portfolio_risk_snapshots evades by being keyed on owner_id.
--
-- ── Honest scope (permanent) ────────────────────────────────────────────────
-- A row records WHAT THE RESOLVER SAID about one domain from one scan's evidence. It
-- does NOT prove:
--   • that the customer's posture actually changed — only that the state did;
--   • that a state resolved under a different resolver_version is comparable to this
--     one (it is not, and the trend refuses to compare them);
--   • that evidence is current — assessed_at is a fact about the past, and freshness is
--     computed against it at read time, never baked in;
--   • that an absent row means healthy. An absent row means NOT ASSESSED. The portfolio
--     renders a domain with no row as not_yet_assessed and a domain with no history as
--     insufficient_history — never as stable, and never as green.
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer the
--   table simply stops receiving rows — behaviour identical to pre-migration, and the
--   portfolio degrades to "not yet assessed", which is honest rather than wrong.
--   (D1/SQLite has no DROP COLUMN path, and none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/091-cyber-mot-domain-states.sql

CREATE TABLE IF NOT EXISTS cyber_mot_domain_states (
  id                   TEXT PRIMARY KEY,          -- cmds-<hex>
  workspace_id         TEXT NOT NULL,             -- tenant boundary; purge key
  domain_id            TEXT NOT NULL,             -- domains.id — the domain RECORD, not the hostname
  scan_id              TEXT NOT NULL,             -- provenance; no FK (history outlives the scan)
  domain_key           TEXT NOT NULL,             -- one of the canonical eight (CYBER_MOT_DOMAINS)

  -- The resolver's verbatim output. Never re-derived, never second-guessed.
  state                TEXT NOT NULL,             -- assessed_healthy|issue_detected|provisional|evidence_insufficient|not_yet_assessed|customer_input_required|monitoring_only|degraded|unavailable|not_configured
  coverage             TEXT,                      -- complete|partial|degraded|unknown|NULL
  summary              TEXT,                      -- the resolver's own customer-safe prose
  highest_severity     TEXT,                      -- critical|high|medium|low|info|NULL
  finding_count        INTEGER NOT NULL DEFAULT 0,
  evidence_count       INTEGER NOT NULL DEFAULT 0,

  -- Sorted, de-duplicated canonical finding ids behind `state`, JSON array.
  -- The trend diffs THIS, not a score: a set difference names which evidence changed
  -- and is stable against scoring-weight churn (the migration 090 fingerprint rule).
  finding_ids_json     TEXT NOT NULL DEFAULT '[]',

  scan_quality         TEXT,                      -- complete|partial|degraded|unknown|NULL. NULL is NEVER complete.
  -- Comparability gate. Only rows sharing a resolver_version may be compared, and only
  -- scan_quality='complete' rows may establish a trend.
  resolver_version     TEXT NOT NULL,

  assessed_at          TEXT NOT NULL,             -- the SCAN's assessment time = occurrence identity
  created_at           TEXT NOT NULL DEFAULT (datetime('now')),

  -- Exactly one row per domain per scan per tenant: this is what makes a re-finalize or
  -- a reconciler re-run an idempotent no-op rather than a second identity.
  UNIQUE (workspace_id, domain_id, scan_id, domain_key),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- Serves the portfolio's core question: latest state per (tenant, domain, domain_key),
-- and the ordered history behind it. Leading column is workspace_id — the tenant
-- boundary is never an afterthought in an index.
CREATE INDEX IF NOT EXISTS idx_cmds_current
  ON cyber_mot_domain_states (workspace_id, domain_id, domain_key, assessed_at DESC);

-- Serves "everything this scan resolved" (idempotency checks, provenance drill-down).
CREATE INDEX IF NOT EXISTS idx_cmds_scan
  ON cyber_mot_domain_states (workspace_id, scan_id);
