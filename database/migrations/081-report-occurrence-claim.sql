-- ── 081-report-occurrence-claim.sql ─────────────────────────────────────────
-- Atomic claim for a scheduled/executive report OCCURRENCE.
--
-- v2026.07.14-7 bounded scheduled-report generation but left a concurrency gap:
-- two overlapping cron invocations could both see "no completed row", both INSERT a
-- pending row, both build the PDF, and both flip to completed — duplicating the
-- workspace_reports row, the notification, and the monthly usage count (which is a
-- COUNT of completed rows).
--
-- This partial UNIQUE index makes the pending INSERT an ATOMIC claim: exactly one
-- ACTIVE occurrence row can exist per (workspace_id, report_type, report_period).
-- generateWorkspaceExecutiveReport now uses INSERT OR IGNORE, so a concurrent loser
-- gets changes=0 and performs zero generation side effects.
--
-- Partial-index scope (verified: D1/SQLite supports partial indexes — migration 076
-- already uses one for managed_cases):
--   • deleted_at IS NULL  — soft-deleted history rows never occupy the claim, so a
--     period can be legitimately regenerated after a report is deleted;
--   • status != 'failed'  — a failed occurrence is retryable: it is excluded, so a
--     fresh pending claim can be inserted;
--   • report_period IS NOT NULL — never enforce on a null period.
--
-- Additive only: no DROP, no data change. Pre-checked against production D1 — zero
-- existing conflicting active duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_workspace_reports_active_occurrence
  ON workspace_reports (workspace_id, report_type, report_period)
  WHERE deleted_at IS NULL AND status != 'failed' AND report_period IS NOT NULL;
