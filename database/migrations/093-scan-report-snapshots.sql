-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 093: Canonical per-scan Cyber MOT reporting snapshot index
-- ─────────────────────────────────────────────────────────────────────────────
--
-- M5.c Unified Reporting Stage 1. Additive only.
--
-- ── WHY THIS TABLE, AND WHY NOT AN EXISTING ONE ─────────────────────────────
-- The founder-approved Unified Reporting decision package (2026-07-16) requires ONE
-- completed Cyber MOT to produce ONE immutable canonical snapshot, later consumed by
-- the online report and the PDF as render-only clients. Today five render paths and
-- three calculation brains re-derive score/risk/state/remediation truth on every
-- read, so what a customer sees from the SAME scan changes as code changes.
--
-- This table is the D1 index for that snapshot: one row per build attempt, with the
-- canonical JSON persisted in R2 (reports/snapshots/{workspace}/{scan}/{id}.json)
-- and a checksum binding the row to the exact bytes it indexed.
--
-- Nothing existing can be extended into it:
--   • reports (schema.sql:77) — dead: zero writers, zero readers, no workspace_id
--     (invisible to validate-purge-completeness), no status, no UNIQUE on scan_id,
--     and an FK to scans. Reviving a dead table under an old name is what the 091
--     header rejects for portfolio_risk_snapshots. It stays dead.
--   • workspace_reports (010) — the stored-PDF occurrence index: customer-deletable
--     (routes/workspace-reports.js DELETE removes the R2 object), retention-swept,
--     PDF-oriented, and mostly per-period. A canonical snapshot must be none of
--     those: it is the historical record the platform itself stands behind.
--   • cyber_mot_domain_states (091) — eight STATE rows per scan, deliberately
--     narrow. The snapshot is the whole assessment (score, BRI, findings,
--     remediation, CE methodology block), not a per-domain state. 091 rows remain
--     the portfolio's cheap read; the snapshot references the same resolver output
--     verbatim so the two can never disagree.
--
-- ── STATUS MACHINE / ATOMIC CLAIM (the 081 pattern) ─────────────────────────
-- status: 'building' → 'completed' (terminal, immutable) or 'failed' (terminal,
-- retryable). INSERT OR IGNORE against the partial UNIQUE below is the atomic
-- claim: exactly one concurrent builder gets meta.changes=1; losers do zero side
-- effects (workspace_reports' claimReportOccurrence precedent, migration 081).
-- A 'building' row older than the stale threshold is flipped to 'failed'
-- (guarded WHERE status='building') and the claim retried — failed rows are
-- excluded from the UNIQUE so a retry can create a fresh attempt.
--
-- Write ordering is R2-first: the row claims 'completed' only AFTER the JSON is
-- durable in R2 (scan-engine.js finalize doctrine — never claim completed before
-- the object exists). Readers serve ONLY status='completed' rows, so a crash
-- between the two writes can never expose a half-written snapshot.
--
-- ── IMMUTABILITY ─────────────────────────────────────────────────────────────
-- A 'completed' row is never updated and its R2 object is never overwritten.
-- A later completed Cyber MOT creates a NEW snapshot that records
-- supersedes_snapshot_id at creation; the superseded row itself is not touched
-- ("superseded" is derived on read from the chain — history is never edited).
-- A methodology change adds snapshots, it does not rewrite them.
--
-- ── NO FOREIGN KEY TO scans ─────────────────────────────────────────────────
-- The 085/086/088/089/090/091 precedent: history must outlive the record it
-- describes, and an FK would force this table into SCAN_CHILD_TABLES where, in
-- index.js's own words, a missed entry means "the purge stalls forever".
--
-- ── PURGE ────────────────────────────────────────────────────────────────────
-- workspace_id is NOT NULL so scripts/validate-purge-completeness.js discovers the
-- table. Purged in purgeWorkspaceData (workers/scan-api/src/index.js) by a
-- pointer-driven pass exactly like workspace_reports: the R2 object (r2_key) is
-- deleted BEFORE its D1 pointer row, so a crash between the two leaves only
-- orphan-free state.
--
-- ── Honest scope (permanent) ────────────────────────────────────────────────
-- A snapshot records WHAT THE PLATFORM ASSESSED from one scan's evidence at one
-- moment, stamped with every methodology version that produced it. It does NOT
-- prove the customer's posture — only what was observed. An absent snapshot means
-- NO SNAPSHOT (e.g. scans completed before this migration, or reconciled
-- stuck-scans, which skip all post-terminal recording — the 091 precedent), never
-- an error and never a healthy default.
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer the
--   table stops receiving rows; readers return "Snapshot not found", which is
--   honest. (D1/SQLite has no DROP COLUMN path, and none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/093-scan-report-snapshots.sql

CREATE TABLE IF NOT EXISTS scan_report_snapshots (
  id                       TEXT PRIMARY KEY,      -- snap-<hex>
  workspace_id             TEXT NOT NULL,         -- tenant boundary; purge key
  domain_id                TEXT NOT NULL,         -- domains.id — the domain RECORD, not the hostname
  scan_id                  TEXT NOT NULL,         -- provenance; no FK (history outlives the scan)

  status                   TEXT NOT NULL DEFAULT 'building',  -- building|completed|failed
  r2_key                   TEXT NOT NULL,         -- reports/snapshots/{ws}/{scan}/{id}.json
  checksum_sha256          TEXT,                  -- set only at completion; binds row to bytes
  size_bytes               INTEGER,

  -- Version contract. The snapshot JSON carries the full methodology block; these
  -- two are duplicated into D1 because list/read paths gate on them without R2.
  snapshot_schema_version  TEXT NOT NULL,
  resolver_version         TEXT NOT NULL,         -- CYBER_MOT_RESOLVER_VERSION at build time

  scan_quality             TEXT,                  -- complete|partial|degraded|unknown|NULL. NULL is NEVER complete.
  assessed_at              TEXT NOT NULL,         -- the SCAN's completion time = occurrence identity, never now()

  -- Set at creation when a previous completed snapshot exists for the same
  -- (workspace_id, domain_id). Append-only: the OLD row is never updated;
  -- "superseded_by" is derived on read by following this chain forward.
  supersedes_snapshot_id   TEXT,

  created_at               TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at             TEXT,
  metadata_json            TEXT,                  -- failure reason etc. (010 precedent)

  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- The atomic build-once claim (081 pattern): at most one ACTIVE (building or
-- completed) snapshot per scan. Failed attempts are excluded so a retry can claim.
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_report_snapshots_active
  ON scan_report_snapshots (scan_id) WHERE status != 'failed';

-- History per tenant+domain, newest first. Leading column is workspace_id — the
-- tenant boundary is never an afterthought in an index (091 rule).
CREATE INDEX IF NOT EXISTS idx_scan_report_snapshots_ws
  ON scan_report_snapshots (workspace_id, domain_id, assessed_at DESC);
