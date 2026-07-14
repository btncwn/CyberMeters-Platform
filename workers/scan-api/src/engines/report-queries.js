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
// This scope mirrors the proven subquery in collectPdfData() (pdf.js), so both
// executive-PDF paths agree. Every consumer binds the workspace id TWICE (the outer
// workspace filter, then the scope's inner `sx.workspace_id`).

const LATEST_COMPLETED_SCAN_SCOPE = `s.id IN (
    SELECT sx.id FROM scans sx
    WHERE sx.workspace_id = ? AND sx.status = 'completed'
      AND sx.created_at = (
        SELECT MAX(sy.created_at) FROM scans sy
        WHERE sy.workspace_id = sx.workspace_id AND sy.domain = sx.domain
          AND sy.status = 'completed'
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
   ORDER BY r.priority ASC
   LIMIT 10`;
