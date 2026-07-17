// ── MSP portfolio — per-customer risk rows + executive summary ────────────────
// The heart of the MSP wedge: "which of my customers needs attention today?".
// computePortfolioCustomerRows returns one row per workspace (customer) with its
// posture, standing findings, AND this week's Exposure-Timeline change counts,
// sorted so the customer that needs attention floats to the top. Shared by
// GET /portfolio/workspaces and /portfolio/executive-summary; unit-testable.
//
// Imports the canonical score-sayability resolver from portfolio-risk.js rather than
// re-deriving one. portfolio-risk.js imports nothing, so this is a one-way edge.
import { riskLevelForScore } from "./scoring.js";
import { PORTFOLIO_SCORE_STATES, resolvePortfolioScoreState } from "./portfolio-risk.js";

// Deterministic "latest completed scan per domain" CTE body. Selecting on
// MAX(created_at) alone double-counts a domain when two completed scans share the
// SAME timestamp (both match `created_at = mx`). Ranking by (created_at DESC, id
// DESC) and taking rn=1 picks EXACTLY ONE scan per domain — the scan id is the
// deterministic tie-break. Consumers write:
//   `WITH ${LATEST_SCAN_CTE} SELECT ... JOIN lpd ON lpd.scan_id = s.id`
// Shared by portfolio.js (overview) and the queries below so both agree.
export const LATEST_SCAN_CTE = `lpd AS (
    SELECT scan_id, domain_id FROM (
      SELECT id AS scan_id, domain_id,
             ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY created_at DESC, id DESC) AS rn
      FROM scans WHERE status='completed'
    ) WHERE rn = 1
  )`;

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
    q(`WITH ${LATEST_SCAN_CTE}
       SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt
       FROM findings f JOIN scans s ON f.scan_id = s.id
       JOIN lpd ON lpd.scan_id = s.id
       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE f.severity IN ('critical','high') AND wd.workspace_id IN (${wsIn})
       GROUP BY wd.workspace_id, f.severity`),
    // Authoritative per-customer posture uses the latest COMPLETE scan per domain — a
    // partial/degraded latest never establishes the customer's rating (honesty).
    q(`WITH lcd AS (
         SELECT scan_id, domain_id FROM (
           SELECT id AS scan_id, domain_id,
                  ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY created_at DESC, id DESC) AS rn
           FROM scans WHERE status='completed' AND scan_quality='complete'
         ) WHERE rn = 1
       )
       SELECT wd.workspace_id, AVG(s.score) AS avg_score, MAX(s.created_at) AS last_scan_at
       FROM scans s JOIN lcd ON lcd.scan_id = s.id
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

  // M5.e: a REJECTED query is recorded, not silently emptied — computePortfolioCustomerRows
  // returns degraded_queries so callers can disclose partial data instead of
  // rendering a failure as "0 findings".
  const degradedQueries = [];
  const rows0 = (r, name = "query") => {
    if (r.status === "fulfilled") return r.value?.results ?? [];
    degradedQueries.push(name);
    return [];
  };
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
    // M5.e-C: the avg is a Cyber Metrics Score average, so its rating speaks
    // the CANONICAL band vocabulary (riskLevelForScore) — the local 80/60/40
    // Low/Medium/High ladder was drift on a score-labelled surface.
    const risk_rating = avgScore !== null ? riskLevelForScore(avgScore) : null;
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
  // Non-breaking disclosure channel: an array property, so both existing
  // consumers keep their contract while the route can disclose degradation.
  rows.degraded_queries = degradedQueries;
  return rows;
}

// Pure: aggregate the customer rows into a portfolio-level executive summary the
// MSP can review or share. No DB access.
//
// ── Why this function imports the score-state resolver ────────────────────────
// #117/#118 fixed exactly these two defects in the SIBLING engine (portfolio-risk.js,
// GET /api/portfolio/risk) and never touched this one, which serves GET
// /api/portfolio/executive-summary. Both were still here, verbatim:
//
//   1. The all-clear by absence. `attention` filters on `latest_score != null &&
//      latest_score < 60`, so a never-scanned customer (score null) is excluded from
//      it. With N unassessed customers `attention.length === 0` and the else branch
//      said "No customers currently need urgent attention." — an all-clear about a
//      portfolio nobody had looked at. Zero findings out of zero assessments is
//      silence, not an all-clear.
//   2. The undisclosed partial mean. `avg_score` is the mean of the SCORED rows only,
//      so one 90 among five customers published "average posture is 90/100" and the
//      missing evidence silently flattered the verdict.
//
// resolvePortfolioScoreState() is the canonical authority for whether a portfolio
// score is sayable at all. It is imported rather than re-derived so this surface can
// never disagree with /api/portfolio/risk about the same portfolio — a second ladder
// here is how the two would drift apart again.
export function buildExecutiveSummary(rows) {
  const customers = rows.length;
  const scored = rows.filter((r) => Number.isFinite(r.latest_score));
  const avg_score = scored.length
    ? Math.round(scored.reduce((s, r) => s + r.latest_score, 0) / scored.length)
    : null;
  // The single source of truth for sayability. Basis is disclosed to the caller so the
  // frontend renders a decision it did not make.
  const scoreState = resolvePortfolioScoreState({
    workspaceCount: customers,
    scoredCount:    scored.length,
    score:          avg_score,
  });
  // Canonical band vocabulary (M5.e-C) — buckets match riskLevelForScore.
  const distribution = { excellent: 0, good: 0, moderate: 0, high: 0, critical: 0 };
  for (const r of rows) if (r.risk_rating in distribution) distribution[r.risk_rating]++;
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

    const parts = [];

    // Lead sentence — only claim an average when there is one. `${avg_score ?? "—"}/100`
    // printed an em-dash where the number goes but kept the sentence's claim ("average
    // posture is") intact, which reads as a measurement that happens to be missing
    // rather than a measurement that was never taken. Say why instead.
    if (scoreState.state === PORTFOLIO_SCORE_STATES.AVAILABLE) {
      parts.push(`Across your ${customers} customer${customers === 1 ? "" : "s"}, average posture is ${avg_score}/100.`);
    } else if (scoreState.state === PORTFOLIO_SCORE_STATES.PARTIAL) {
      // A real mean, but of a subset — disclose the basis in the sentence that gets read.
      parts.push(`Across your ${customers} customer${customers === 1 ? "" : "s"}, average posture is ${avg_score}/100. ${scoreState.reason}`);
    } else {
      parts.push(`An average posture score is not available for your ${customers} customer${customers === 1 ? "" : "s"} yet. ${scoreState.reason}`);
    }

    // Attention callout. `attention` is evidence-driven (standing criticals, new
    // high-severity changes, a low score), so when it is non-empty it is always
    // sayable regardless of score state — those are real observations.
    if (attention.length) {
      parts.push(`${attention.length} need${attention.length === 1 ? "s" : ""} attention, starting with ${lead.workspace_name}${why}.`);
    } else if (scoreState.state === PORTFOLIO_SCORE_STATES.AVAILABLE) {
      parts.push("No customers currently need urgent attention.");
    } else if (scoreState.state === PORTFOLIO_SCORE_STATES.PARTIAL) {
      // Clean bill of health for the assessed subset only — never for the portfolio.
      parts.push("None of the assessed customers currently need urgent attention; the customers without a completed assessment are not covered by this statement.");
    }
    // no_workspaces / evidence_insufficient: withhold the all-clear entirely. An
    // unassessed customer cannot need attention because nothing has looked at it, and
    // saying so out loud turns that silence into reassurance.

    if (high_changes_7d) {
      parts.push(`${high_changes_7d} high-severity change${high_changes_7d === 1 ? "" : "s"} across the portfolio this week.`);
    }

    executive_summary = parts.join(" ");
  }

  return {
    portfolio: {
      customers,
      avg_score,
      distribution,
      total_changes_7d,
      high_changes_7d,
      customers_needing_attention: attention.length,
      // Additive: avg_score keeps its meaning and value; these say whether it may be
      // spoken and what it is drawn from.
      avg_score_state:  scoreState.state,
      avg_score_reason: scoreState.reason,
      avg_score_basis:  { scored_customers: scoreState.basis.scored_workspaces, total_customers: scoreState.basis.total_workspaces },
    },
    top_attention,
    executive_summary,
  };
}
