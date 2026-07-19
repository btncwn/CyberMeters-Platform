-- ─────────────────────────────────────────────────────────────────────────────
-- production-integrity-assertions.sql   (READ-ONLY)
--
-- Safe, read-only tenant-lineage integrity checks for the production D1 database.
-- Every statement is a SELECT that COUNTS anomalies; a healthy database returns 0
-- for every check. NOTHING here writes, updates, deletes, or backfills — running
-- it cannot change production data.
--
-- HOW TO RUN (founder / release-gate activity — requires production D1 access):
--   npx wrangler d1 execute cybermeters_db --remote --file scripts/security/production-integrity-assertions.sql
--
-- Interpretation: any non-zero `anomalies` row is a lineage defect to investigate.
-- This script is NOT run in CI (no production binding); its SQLite syntax is
-- validated against the in-memory schema by scripts/validate-production-integrity-sql.js.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. Scans whose workspace_id disagrees with their domain's workspace lineage.
--    (A scan attributed to workspace X but whose domain is monitored only by Y.)
SELECT '1_scan_workspace_domain_conflict' AS check_name, COUNT(*) AS anomalies
FROM scans s
WHERE s.workspace_id IS NOT NULL
  AND s.domain_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM workspace_domains wd
    WHERE wd.domain_id = s.domain_id AND wd.workspace_id = s.workspace_id
  );

-- 2. Assets whose domain_id belongs to a different workspace than the asset row.
SELECT '2_asset_domain_workspace_conflict' AS check_name, COUNT(*) AS anomalies
FROM workspace_assets a
WHERE a.domain_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM workspace_domains wd
    WHERE wd.domain_id = a.domain_id AND wd.workspace_id = a.workspace_id
  );

-- 3. Report snapshots whose workspace_id disagrees with their scan's workspace_id.
SELECT '3_snapshot_scan_workspace_conflict' AS check_name, COUNT(*) AS anomalies
FROM scan_report_snapshots snap
JOIN scans s ON s.id = snap.scan_id
WHERE s.workspace_id IS NOT NULL
  AND snap.workspace_id IS NOT NULL
  AND snap.workspace_id <> s.workspace_id;

-- 4. Managed cases whose domain is not monitored by the case's own workspace.
SELECT '4_case_domain_not_in_workspace' AS check_name, COUNT(*) AS anomalies
FROM managed_cases mc
WHERE mc.domain IS NOT NULL
  AND mc.domain <> ''
  AND NOT EXISTS (
    SELECT 1 FROM workspace_domains wd
    JOIN domains d ON d.id = wd.domain_id
    WHERE wd.workspace_id = mc.workspace_id AND d.domain = mc.domain
  );

-- 5. Active scheduled scans under a soft-deleted workspace (should be inert).
SELECT '5_scheduled_scan_under_deleted_ws' AS check_name, COUNT(*) AS anomalies
FROM scheduled_scans ss
JOIN workspaces w ON w.id = ss.workspace_id
WHERE w.deleted_at IS NOT NULL
  AND COALESCE(ss.enabled, 1) = 1;

-- 6. Active report schedules under a soft-deleted workspace.
SELECT '6_report_schedule_under_deleted_ws' AS check_name, COUNT(*) AS anomalies
FROM report_schedules rs
JOIN workspaces w ON w.id = rs.workspace_id
WHERE w.deleted_at IS NOT NULL
  AND COALESCE(rs.enabled, 1) = 1;

-- 7. Workspace members that reference a workspace that no longer exists.
SELECT '7_orphan_workspace_member' AS check_name, COUNT(*) AS anomalies
FROM workspace_members m
WHERE NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.id = m.workspace_id);

-- 8. Managed-case events whose parent case no longer exists (orphan lifecycle rows).
SELECT '8_orphan_managed_case_event' AS check_name, COUNT(*) AS anomalies
FROM managed_case_events e
WHERE NOT EXISTS (SELECT 1 FROM managed_cases c WHERE c.id = e.case_id);

-- 9. Invitations that reference a workspace that no longer exists.
SELECT '9_orphan_invitation' AS check_name, COUNT(*) AS anomalies
FROM workspace_invitations i
WHERE NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.id = i.workspace_id);

-- 10. Workspace-domain links pointing at a domain row that no longer exists.
SELECT '10_orphan_workspace_domain' AS check_name, COUNT(*) AS anomalies
FROM workspace_domains wd
WHERE NOT EXISTS (SELECT 1 FROM domains d WHERE d.id = wd.domain_id);

-- 11. Report snapshots with no owning workspace row (unresolvable tenant).
SELECT '11_snapshot_without_workspace' AS check_name, COUNT(*) AS anomalies
FROM scan_report_snapshots snap
WHERE snap.workspace_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.id = snap.workspace_id);

-- 12. Managed cases whose owning workspace row no longer exists.
SELECT '12_case_without_workspace' AS check_name, COUNT(*) AS anomalies
FROM managed_cases mc
WHERE NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.id = mc.workspace_id);
