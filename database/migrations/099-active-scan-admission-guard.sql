-- 099 — PR-2: Atomic active-scan admission guard.
--
-- Invariant (founder-approved, 22 Jul 2026 scan-lifecycle sequence PR-2):
--   For one workspace and one canonical domain, at most ONE scan may exist in an
--   active state. Active states: 'queued', 'running', 'retrying' — the DB-level
--   set deliberately includes the PR-3 (durable Queue dispatch) pre-run states
--   before any code writes them, so the guard never lags the dispatcher.
--
-- WHY the database, not the application: the 22 Jul incident produced three
-- concurrent same-domain manual scans stuck `running`. Frontend button state,
-- pre-insert SELECTs and in-memory locks all lose the read-then-write race when
-- two Worker invocations interleave; a partial UNIQUE index makes the INSERT
-- itself the admission decision, so exactly one racing request wins and the
-- loser fails with a UNIQUE-constraint error the route converts to an honest
-- 409 (workers/scan-api/src/lib/scan-admission.js).
--
-- WHY (workspace_id, domain) and not (workspace_id, domain_id): domains rows are
-- keyed per (user_id, domain) — the same canonical domain legitimately exists
-- under SEVERAL domain ids (documented at the verification gate in
-- workers/scan-api/src/routes/scans.js), so two members of one workspace would
-- carry different domain_ids for the same domain and a domain_id index would not
-- enforce the invariant. `scans.domain` is written normalized on BOTH creation
-- paths (manual POST /api/scan and the scheduled cron runner): trim().toLowerCase()
-- gated by isValidDomain at the API boundary.
--
-- NULL-workspace defense: SQLite UNIQUE indexes treat NULLs as DISTINCT, so the
-- primary index cannot constrain rows with workspace_id IS NULL. No current
-- creation path can produce such a row (the manual path requires an authorised
-- workspace; evaluateScheduledScanEligibility fails closed on a missing
-- workspace_id), and every historical NULL-workspace row is terminal
-- (completed/failed). The second index closes the hole fail-closed anyway: if a
-- future path ever inserted an active NULL-workspace scan, it would still be
-- limited to one active scan per domain rather than escaping the guard.
--
-- Safety: additive only — two partial unique indexes, no table rebuild, no data
-- change. Production scans contain only terminal statuses ('completed','failed'
-- — PR-2 discovery, 22 Jul 2026), so ZERO existing rows match the partial WHERE
-- and index creation cannot fail on historical duplicates.
--
-- Rollback: DROP INDEX idx_scans_one_active_per_workspace_domain;
--           DROP INDEX idx_scans_one_active_per_domain_null_ws;
-- (index-only — no data is touched in either direction).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/099-active-scan-admission-guard.sql
--
-- Verify:
--   SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='scans';

CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_one_active_per_workspace_domain
  ON scans (workspace_id, domain)
  WHERE status IN ('queued', 'running', 'retrying');

CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_one_active_per_domain_null_ws
  ON scans (domain)
  WHERE status IN ('queued', 'running', 'retrying') AND workspace_id IS NULL;
