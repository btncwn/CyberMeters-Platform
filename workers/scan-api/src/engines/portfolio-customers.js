// ── MSP portfolio — per-customer risk rows + executive summary ────────────────
// The heart of the MSP wedge: "which of my customers needs attention today?".
// computePortfolioCustomerRows returns one row per workspace (customer) with its
// posture, standing findings, AND this week's Exposure-Timeline change counts,
// sorted so the customer that needs attention floats to the top. Shared by
// GET /portfolio/workspaces and /portfolio/executive-summary; unit-testable.

// Returns the sorted customer rows for a set of workspace ids (already scoped to
// the caller's accessible workspaces by the route). Read-only; never throws
// beyond a rejected DB promise (route wraps in serverError).
export async function computePortfolioCustomerRows(db, workspaceIds) {
  if (!workspaceIds || workspaceIds.length === 0) return [];
  const wsIn = workspaceIds.map(() => "?").join(",");
  const q = (sql) => db.prepare(sql).bind(...workspaceIds).all();

  const [
    wsRes, domRes, assetRes, vendorRes, brandRes, findingsRes, scanRes, rptRes, changesRes,
  ] = await Promise.allSettled([
    db.prepare(`SELECT id, name, created_at FROM workspaces WHERE id IN (${wsIn}) ORDER BY created_at`).bind(...workspaceIds).all(),
    q(`SELECT workspace_id, COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn}) GROUP BY workspace_id`),
    q(`SELECT workspace_id, COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`),
    q(`SELECT workspace_id, COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`),
    q(`SELECT workspace_id, COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`),
    q(`WITH lpd AS (SELECT domain_id, MAX(created_at) AS mx FROM scans WHERE status='completed' GROUP BY domain_id)
       SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt
       FROM findings f JOIN scans s ON f.scan_id = s.id
       JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE f.severity IN ('critical','high') AND wd.workspace_id IN (${wsIn})
       GROUP BY wd.workspace_id, f.severity`),
    q(`WITH lpd AS (SELECT domain_id, MAX(created_at) AS mx FROM scans WHERE status='completed' GROUP BY domain_id)
       SELECT wd.workspace_id, AVG(s.score) AS avg_score, MAX(s.created_at) AS last_scan_at
       FROM scans s JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE s.score IS NOT NULL AND wd.workspace_id IN (${wsIn})
       GROUP BY wd.workspace_id`),
    q(`SELECT workspace_id, MAX(generated_at) AS last_report_at FROM workspace_reports
       WHERE status='completed' AND deleted_at IS NULL AND workspace_id IN (${wsIn}) GROUP BY workspace_id`),
    // NEW: this week's Exposure-Timeline change counts per customer.
    q(`SELECT workspace_id, COUNT(*) AS total,
              SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) AS high
       FROM asset_events
       WHERE workspace_id IN (${wsIn}) AND created_at > datetime('now','-7 days')
       GROUP BY workspace_id`),
  ]);

  const rows0 = (r) => (r.status === "fulfilled" ? (r.value?.results ?? []) : []);
  const byWs = (r, pick) => { const m = {}; for (const x of rows0(r)) m[x.workspace_id] = pick(x); return m; };

  const domMap    = byWs(domRes,    (x) => x.count);
  const assetMap  = byWs(assetRes,  (x) => x.count);
  const vendorMap = byWs(vendorRes, (x) => x.count);
  const brandMap  = byWs(brandRes,  (x) => x.count);
  const scanMap   = byWs(scanRes,   (x) => x);
  const rptMap    = byWs(rptRes,    (x) => x.last_report_at);
  const changeMap = byWs(changesRes,(x) => ({ total: Number(x.total) || 0, high: Number(x.high) || 0 }));
  const findingsMap = {};
  for (const x of rows0(findingsRes)) {
    (findingsMap[x.workspace_id] ??= { critical: 0, high: 0 })[x.severity] = x.cnt;
  }

  const now = Date.now();
  const rows = rows0(wsRes).map((ws) => {
    const scan = scanMap[ws.id] ?? {};
    const findings = findingsMap[ws.id] ?? {};
    const changes = changeMap[ws.id] ?? { total: 0, high: 0 };
    const avgScore = scan.avg_score != null ? Math.round(scan.avg_score) : null;
    let risk_rating = null;
    if (avgScore !== null) risk_rating = avgScore >= 80 ? "Low" : avgScore >= 60 ? "Medium" : avgScore >= 40 ? "High" : "Critical";
    const lastScanAt = scan.last_scan_at ?? null;
    const status = lastScanAt && now - new Date(lastScanAt).getTime() < 30 * 24 * 3600 * 1000 ? "active" : "inactive";
    return {
      workspace_id: ws.id, workspace_name: ws.name,
      domains: domMap[ws.id] ?? 0, active_assets: assetMap[ws.id] ?? 0,
      vendors: vendorMap[ws.id] ?? 0, brand_candidates: brandMap[ws.id] ?? 0,
      latest_score: avgScore, security_posture_score: avgScore, risk_rating,
      critical_findings: findings.critical ?? 0, high_findings: findings.high ?? 0,
      changes_7d: changes.total, changes_7d_high: changes.high,
      last_scan_at: lastScanAt, last_report_at: rptMap[ws.id] ?? null, status,
    };
  });

  // Attention order: standing criticals → NEW high/critical changes this week →
  // standing highs → lowest score → most recently scanned.
  rows.sort((a, b) => {
    if (b.critical_findings !== a.critical_findings) return b.critical_findings - a.critical_findings;
    if (b.changes_7d_high   !== a.changes_7d_high)   return b.changes_7d_high   - a.changes_7d_high;
    if (b.high_findings     !== a.high_findings)     return b.high_findings     - a.high_findings;
    const sa = a.latest_score ?? 999, sb = b.latest_score ?? 999;
    if (sa !== sb) return sa - sb;
    return (b.last_scan_at ?? "").localeCompare(a.last_scan_at ?? "");
  });
  return rows;
}

// Pure: aggregate the customer rows into a portfolio-level executive summary the
// MSP can review or share. No DB access.
export function buildExecutiveSummary(rows) {
  const customers = rows.length;
  const scored = rows.filter((r) => r.latest_score != null);
  const avg_score = scored.length ? Math.round(scored.reduce((s, r) => s + r.latest_score, 0) / scored.length) : null;
  const distribution = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  for (const r of rows) if (r.risk_rating) distribution[r.risk_rating]++;
  const total_changes_7d = rows.reduce((s, r) => s + (r.changes_7d || 0), 0);
  const high_changes_7d = rows.reduce((s, r) => s + (r.changes_7d_high || 0), 0);

  const attention = rows.filter((r) => r.critical_findings > 0 || r.changes_7d_high > 0 || (r.latest_score != null && r.latest_score < 60));
  const top_attention = attention.slice(0, 3).map((r) => ({
    workspace_id: r.workspace_id, workspace_name: r.workspace_name, risk_rating: r.risk_rating,
    latest_score: r.latest_score, critical_findings: r.critical_findings, high_findings: r.high_findings,
    changes_7d: r.changes_7d, changes_7d_high: r.changes_7d_high,
  }));

  let executive_summary;
  if (customers === 0) {
    executive_summary = "No customers in your portfolio yet.";
  } else {
    const lead = top_attention[0];
    const why = lead
      ? (lead.critical_findings ? ` (${lead.critical_findings} critical finding${lead.critical_findings === 1 ? "" : "s"})`
        : lead.changes_7d_high ? ` (${lead.changes_7d_high} new high-severity change${lead.changes_7d_high === 1 ? "" : "s"} this week)`
        : "")
      : "";
    executive_summary =
      `Across your ${customers} customer${customers === 1 ? "" : "s"}, average posture is ${avg_score ?? "—"}/100. ` +
      (attention.length
        ? `${attention.length} need${attention.length === 1 ? "s" : ""} attention, starting with ${lead.workspace_name}${why}.`
        : "No customers currently need urgent attention.") +
      (high_changes_7d ? ` ${high_changes_7d} high-severity change${high_changes_7d === 1 ? "" : "s"} across the portfolio this week.` : "");
  }

  return {
    portfolio: { customers, avg_score, distribution, total_changes_7d, high_changes_7d, customers_needing_attention: attention.length },
    top_attention,
    executive_summary,
  };
}
