import { suppressedLegacyTlsRemediationSql, visibleFindingSql } from "./finding-identity.js";

// ── Executive-report data queries (customer-facing PDF) ───────────────────────
// The workspace executive report (GET /api/workspaces/:id/report) must show the
// CURRENT posture: each finding / recommendation from the LATEST completed scan per
// domain, exactly once.
//
// Without a latest-scan scope the report piles up one row per historical scan — e.g.
// an "HTTPS Not Available" finding from four old scans renders as four separate
// CRITICAL items, and a "DMARC p=none" finding from nine scans as nine MEDIUM items —
// and it resurfaces issues already resolved by a newer scan. Both inflate the counts
// and read as raw database output: a customer-trust defect (permanent #1).
//
// This is the ONE canonical "current authoritative findings per domain" scope,
// reused by the executive report/PDF, the Executive Dashboard and Workspace
// Insights, so every customer-facing current-finding count agrees.
//
// Two properties matter for trust:
//   • COMPLETE-quality only — a partial/degraded/unknown scan is not authoritative,
//     so it must never fabricate or replace current findings (partial-scan honesty).
//   • DETERMINISTIC — exactly one scan per (workspace, domain), chosen by
//     ORDER BY created_at DESC, id DESC. A plain `created_at = MAX(...)` join
//     double-counts when two scans share a timestamp; the id tie-break prevents it.
// Every consumer binds the workspace id TWICE (the outer workspace filter, then the
// scope's inner `sx.workspace_id`).
export const LATEST_COMPLETED_SCAN_SCOPE = `s.id IN (
    SELECT sx.id FROM scans sx
    WHERE sx.workspace_id = ? AND sx.status = 'completed' AND sx.scan_quality = 'complete'
      AND sx.id = (
        SELECT sy.id FROM scans sy
        WHERE sy.workspace_id = sx.workspace_id AND sy.domain = sx.domain
          AND sy.status = 'completed' AND sy.scan_quality = 'complete'
        ORDER BY sy.created_at DESC, sy.id DESC
        LIMIT 1
      )
  )`;

// Top findings for the executive report — latest completed scan per domain only.
// Binds: (workspaceId, workspaceId).
export const REPORT_FINDINGS_SQL = `SELECT f.title, f.severity, f.recommendation, s.domain
   FROM findings f
   JOIN scans s ON s.id = f.scan_id
   JOIN domains d ON d.id = s.domain_id
   JOIN workspace_domains wd ON wd.domain_id = d.id
   WHERE wd.workspace_id = ?
     AND ${visibleFindingSql("f", "s")}
     AND ${LATEST_COMPLETED_SCAN_SCOPE}
   ORDER BY CASE f.severity
     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
     WHEN 'medium'   THEN 3                ELSE 4 END,
     s.created_at DESC
   LIMIT 30`;

// Recommendations for the executive report — latest completed scan per domain only.
// Binds: (workspaceId, workspaceId).
export const REPORT_RECOMMENDATIONS_SQL = `SELECT r.title, r.priority, r.action, r.reason, s.domain
   FROM remediation_items r
   JOIN scans s ON s.id = r.scan_id
   JOIN domains d ON d.id = s.domain_id
   JOIN workspace_domains wd ON wd.domain_id = d.id
   WHERE wd.workspace_id = ?
     AND ${LATEST_COMPLETED_SCAN_SCOPE}
     AND NOT ${suppressedLegacyTlsRemediationSql("r")}
   ORDER BY r.priority ASC
   LIMIT 10`;
