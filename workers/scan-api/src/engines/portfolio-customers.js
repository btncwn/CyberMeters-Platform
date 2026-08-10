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
import { visibleFindingSql } from "./finding-identity.js";
import {
  phase5EvidenceReadCoverage,
  projectPhase5ScanRowsForCustomer,
  resolvePhase5CustomerAggregate,
} from "./phase5-evidence.js";
import {
  ASSET_LIFECYCLE_D1_BINDING_LIMIT,
  createAssetLifecycleUnavailableProjection,
  loadAssetLifecycleEventSupportForWorkspaces,
  projectLifecycleCollectionForCustomer,
  summariseLifecycleClaimProjection,
} from "./asset-lifecycle-event-support.js";

export const PORTFOLIO_MAX_QUERY_CONCURRENCY = 4;

// Shared by the portfolio summary and alert route. Workspace ids are already
// authorised by the caller; every statement remains scoped to one bounded slice.
// A rejected slice is attributed to exactly its workspaces instead of turning
// the whole collection into a fabricated empty result.
export async function readPortfolioWorkspaceSources(db, workspaceIds, sources = []) {
  const ids = [...new Set((workspaceIds || []).filter(Boolean))];
  const output = Object.fromEntries((sources || []).map((source) => [source.key, {
    results: [],
    failed_workspace_ids: new Set(),
  }]));
  const tasks = [];
  for (const source of sources || []) {
    const extraBindings = source.extraBindings || [];
    const workspaceCapacity = ASSET_LIFECYCLE_D1_BINDING_LIMIT - extraBindings.length;
    if (workspaceCapacity < 1) throw new RangeError("Portfolio query has no workspace binding capacity");
    for (let offset = 0; offset < ids.length; offset += workspaceCapacity) {
      const workspaceBatch = ids.slice(offset, offset + workspaceCapacity);
      tasks.push({ source, workspaceBatch, extraBindings });
    }
  }
  for (let index = 0; index < tasks.length; index += PORTFOLIO_MAX_QUERY_CONCURRENCY) {
    const wave = tasks.slice(index, index + PORTFOLIO_MAX_QUERY_CONCURRENCY);
    const settled = await Promise.allSettled(wave.map(
      ({ source, workspaceBatch, extraBindings }) => Promise.resolve().then(() => {
        const placeholders = workspaceBatch.map(() => "?").join(",");
        return db.prepare(source.sql(placeholders))
          .bind(...workspaceBatch, ...extraBindings)
          .all();
      }),
    ));
    settled.forEach((result, offset) => {
      const task = wave[offset];
      const target = output[task.source.key];
      if (result.status === "fulfilled") {
        target.results.push(...(result.value?.results || []));
      } else {
        for (const workspaceId of task.workspaceBatch) {
          target.failed_workspace_ids.add(workspaceId);
        }
      }
    });
  }
  return output;
}

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
export async function computePortfolioCustomerRows(db, workspaceIds, { env = null } = {}) {
  if (!workspaceIds || workspaceIds.length === 0) return [];
  const authorisedWorkspaceIds = [...new Set(workspaceIds.filter(Boolean))];
  const sourceReads = await readPortfolioWorkspaceSources(db, authorisedWorkspaceIds, [
    { key: "workspaces", sql: (wsIn) =>
      `SELECT id, name, created_at FROM workspaces WHERE id IN (${wsIn}) ORDER BY created_at` },
    { key: "domains", sql: (wsIn) =>
      `SELECT workspace_id, COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn}) GROUP BY workspace_id` },
    { key: "assets", sql: (wsIn) =>
      `SELECT workspace_id, COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id` },
    { key: "vendors", sql: (wsIn) =>
      `SELECT workspace_id, COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id` },
    { key: "brand_assets", sql: (wsIn) =>
      `SELECT workspace_id, COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id` },
    { key: "findings", sql: (wsIn) => `WITH ${LATEST_SCAN_CTE}
       SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt
       FROM findings f JOIN scans s ON f.scan_id = s.id
       JOIN lpd ON lpd.scan_id = s.id
       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE f.severity IN ('critical','high')
         AND ${visibleFindingSql("f", "s")}
         AND wd.workspace_id IN (${wsIn})
       GROUP BY wd.workspace_id, f.severity` },
    // Authoritative per-customer posture uses the latest COMPLETE scan per domain — a
    // partial/degraded latest never establishes the customer's rating (honesty).
    { key: "scores", sql: (wsIn) => `WITH lcd AS (
         SELECT scan_id, domain_id FROM (
           SELECT id AS scan_id, domain_id,
                  ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY created_at DESC, id DESC) AS rn
           FROM scans WHERE status='completed' AND scan_quality='complete'
         ) WHERE rn = 1
       )
       SELECT wd.workspace_id, s.id AS scan_id, s.score, s.rating,
              s.scan_quality, s.created_at
       FROM scans s JOIN lcd ON lcd.scan_id = s.id
       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE s.score IS NOT NULL AND wd.workspace_id IN (${wsIn})
       ORDER BY wd.workspace_id, s.created_at DESC` },
    { key: "reports", sql: (wsIn) =>
      `SELECT workspace_id, MAX(generated_at) AS last_report_at FROM workspace_reports
       WHERE status='completed' AND deleted_at IS NULL AND workspace_id IN (${wsIn}) GROUP BY workspace_id` },
    // Exact legacy aggregates are independent of the bounded projection read.
    { key: "changes", sql: (wsIn) =>
      `SELECT workspace_id, COUNT(*) AS count,
              SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) AS high_count,
              SUM(CASE WHEN event_type IN ('asset_no_longer_seen','asset_reappeared') THEN 1 ELSE 0 END) AS lifecycle_count,
              SUM(CASE WHEN event_type IN ('asset_no_longer_seen','asset_reappeared')
                        AND severity IN ('high','critical') THEN 1 ELSE 0 END) AS lifecycle_high_count
       FROM asset_events
       WHERE workspace_id IN (${wsIn}) AND created_at > datetime('now','-7 days')
       GROUP BY workspace_id` },
    // Only lifecycle events consume the bounded evidence projection universe.
    { key: "lifecycle_changes", sql: (wsIn) =>
      `SELECT id, workspace_id, domain_id, asset_id, scan_id, event_type,
              hostname, severity, description, created_at
       FROM (
         SELECT ae.*,
                ROW_NUMBER() OVER (
                  PARTITION BY workspace_id ORDER BY created_at DESC, id DESC
                ) AS workspace_rank
         FROM asset_events ae
         WHERE workspace_id IN (${wsIn})
           AND created_at > datetime('now','-7 days')
           AND event_type IN ('asset_no_longer_seen','asset_reappeared')
       )
       WHERE workspace_rank <= 2001
       ORDER BY workspace_id, created_at DESC, id DESC` },
  ]);

  // M5.e: a REJECTED query is recorded, not silently emptied — computePortfolioCustomerRows
  // returns degraded_queries so callers can disclose partial data instead of
  // rendering a failure as "0 findings".
  const degradedQueries = [];
  const rows0 = (key, name = key) => {
    const source = sourceReads[key];
    if (source?.failed_workspace_ids?.size && !degradedQueries.includes(name)) {
      degradedQueries.push(name);
    }
    return source?.results || [];
  };
  const byWs = (key, name, pick) => { const m = {}; for (const x of rows0(key, name)) m[x.workspace_id] = pick(x); return m; };

  const domMap    = byWs("domains",      "domains",      (x) => x.count);
  const assetMap  = byWs("assets",       "assets",       (x) => x.count);
  const vendorMap = byWs("vendors",      "vendors",      (x) => x.count);
  const brandMap  = byWs("brand_assets", "brand_assets", (x) => x.count);
  const rawScanRows = rows0("scores", "scores");
  const customerScanRows = await projectPhase5ScanRowsForCustomer(
    env,
    rawScanRows.map((row) => ({ ...row, status: "completed" })),
  );
  const scanMap = {};
  for (const row of customerScanRows) {
    const value = (scanMap[row.workspace_id] ??= {
      rows: [],
      last_scan_at: null,
    });
    value.rows.push(row);
    if (!value.last_scan_at || row.created_at > value.last_scan_at) {
      value.last_scan_at = row.created_at;
    }
  }
  const rptMap = byWs("reports", "reports", (x) => x.last_report_at);
  const aggregateChangeMap = byWs("changes", "changes", (x) => ({
    total: Number(x.count || 0),
    high: Number(x.high_count || 0),
    lifecycle: Number(x.lifecycle_count || 0),
    lifecycle_high: Number(x.lifecycle_high_count || 0),
  }));
  const rawLifecycleRows = rows0("lifecycle_changes", "changes_projection");
  const lifecycleRowsByWorkspace = new Map(authorisedWorkspaceIds.map((id) => [id, []]));
  for (const event of rawLifecycleRows) lifecycleRowsByWorkspace.get(event.workspace_id)?.push(event);
  const aggregateFailures = sourceReads.changes.failed_workspace_ids;
  const projectionFailures = sourceReads.lifecycle_changes.failed_workspace_ids;
  const loadableWorkspaceIds = authorisedWorkspaceIds.filter((id) =>
    !aggregateFailures.has(id) && !projectionFailures.has(id));
  const loadableWorkspaceIdSet = new Set(loadableWorkspaceIds);
  const lifecycleEnv = { ...(env || {}), cybermeters_db: db };
  let projectionsByWorkspace;
  try {
    projectionsByWorkspace = await loadAssetLifecycleEventSupportForWorkspaces(lifecycleEnv, {
      workspaceIds: loadableWorkspaceIds,
      events: rawLifecycleRows.filter((event) => loadableWorkspaceIdSet.has(event.workspace_id)),
      collectionLimit: 2000,
      scope: "portfolio_customer_changes_7d",
    });
  } catch {
    projectionsByWorkspace = new Map();
  }
  const changeMap = {};
  for (const workspaceId of authorisedWorkspaceIds) {
    const events = lifecycleRowsByWorkspace.get(workspaceId) || [];
    const legacy = aggregateChangeMap[workspaceId] || { total: 0, high: 0, lifecycle: 0, lifecycle_high: 0 };
    const sourceUnavailable = aggregateFailures.has(workspaceId) || projectionFailures.has(workspaceId);
    let projection = sourceUnavailable
      ? createAssetLifecycleUnavailableProjection({
          events,
          scope: "portfolio_customer_changes_7d",
          coverageReason: "event_collection_read_failed",
        })
      : projectionsByWorkspace.get(workspaceId);
    if (!projection) projection = createAssetLifecycleUnavailableProjection({
      events,
      scope: "portfolio_customer_changes_7d",
      coverageReason: "event_collection_read_failed",
    });
    let lifecycleSummary = summariseLifecycleClaimProjection(events, projection);
    if (lifecycleSummary.coverage === "complete" && lifecycleSummary.total !== legacy.lifecycle) {
      projection = createAssetLifecycleUnavailableProjection({
        events,
        scope: "portfolio_customer_changes_7d",
        coverageReason: "event_collection_read_failed",
      });
      lifecycleSummary = summariseLifecycleClaimProjection(events, projection);
    }
    const projectedEvents = projectLifecycleCollectionForCustomer(events, projection);
    const customerEvents = lifecycleSummary.coverage === "complete"
      ? projectedEvents.filter((event) =>
          event.lifecycle_claim_support?.state === "supported")
      : [];
    const exact = lifecycleSummary.coverage === "complete";
    const nonLifecycle = legacy.total - legacy.lifecycle;
    const summary = exact ? {
      ...lifecycleSummary,
      total: legacy.total,
      non_lifecycle: nonLifecycle,
      customer_change_count: nonLifecycle + lifecycleSummary.supported,
      customer_change_count_basis: "supported_lifecycle_plus_non_lifecycle_event_records",
    } : lifecycleSummary;
    changeMap[workspaceId] = {
      total: legacy.total,
      high: legacy.high,
      customer_total: exact ? summary.customer_change_count : null,
      customer_high: exact
        ? legacy.high - legacy.lifecycle_high + customerEvents.filter(
            (event) => ["high", "critical"].includes(event.severity),
          ).length
        : null,
      projection: summary,
    };
  }
  if (
    Object.values(changeMap).some((changes) => changes.projection?.coverage !== "complete") &&
    !degradedQueries.includes("lifecycle_claim_projection")
  ) {
    degradedQueries.push("lifecycle_claim_projection");
  }
  const findingsMap = {};
  for (const x of rows0("findings", "findings")) {
    (findingsMap[x.workspace_id] ??= { critical: 0, high: 0 })[x.severity] = x.cnt;
  }

  const now = Date.now();
  const rows = rows0("workspaces", "workspaces").map((ws) => {
    const scan = scanMap[ws.id] ?? {};
    const findings = findingsMap[ws.id] ?? {};
    const changes = changeMap[ws.id] ?? { total: 0, high: 0 };
    const aggregate = resolvePhase5CustomerAggregate(scan.rows ?? []);
    const avgScore = aggregate.score == null ? null : Math.round(aggregate.score);
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
      score_evidence_coverage: aggregate.evidence_coverage,
      critical_findings: findings.critical ?? 0, high_findings: findings.high ?? 0,
      // Legacy raw fields remain byte-compatible. Projection-aware consumers
      // use the additive customer_* fields and coverage object.
      changes_7d: changes.total, changes_7d_high: changes.high,
      customer_changes_7d: changes.customer_total,
      customer_changes_7d_high: changes.customer_high,
      lifecycle_claim_projection_7d: changes.projection,
      last_scan_at: lastScanAt, last_report_at: rptMap[ws.id] ?? null, status,
    };
  });

  // Attention order: standing criticals → NEW high/critical changes this week →
  // standing highs → lowest score → most recently scanned.
  rows.sort((a, b) => {
    if (b.critical_findings !== a.critical_findings) return b.critical_findings - a.critical_findings;
    const bProjectedHigh = b.customer_changes_7d_high ?? 0;
    const aProjectedHigh = a.customer_changes_7d_high ?? 0;
    if (bProjectedHigh !== aProjectedHigh) return bProjectedHigh - aProjectedHigh;
    if (b.high_findings     !== a.high_findings)     return b.high_findings     - a.high_findings;
    const sa = a.latest_score ?? 999, sb = b.latest_score ?? 999;
    if (sa !== sb) return sa - sb;
    return (b.last_scan_at ?? "").localeCompare(a.last_scan_at ?? "");
  });
  // Non-breaking disclosure channel: an array property, so both existing
  // consumers keep their contract while the route can disclose degradation.
  rows.degraded_queries = degradedQueries;
  rows.phase5_evidence_coverage = phase5EvidenceReadCoverage(customerScanRows);
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
  const degradedQueries = Array.isArray(rows?.degraded_queries) ? rows.degraded_queries : [];
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
  const lifecycleProjectionComplete = rows.every(
    (r) => r.lifecycle_claim_projection_7d?.coverage === "complete",
  );
  const customer_total_changes_7d = lifecycleProjectionComplete
    ? rows.reduce((sum, row) => sum + (row.customer_changes_7d || 0), 0)
    : null;
  const customer_high_changes_7d = lifecycleProjectionComplete
    ? rows.reduce((sum, row) => sum + (row.customer_changes_7d_high || 0), 0)
    : null;

  const attention = rows.filter((r) =>
    r.critical_findings > 0 ||
    (r.customer_changes_7d_high ?? 0) > 0 ||
    (r.latest_score != null && r.latest_score < 60));
  const top_attention = attention.slice(0, 3).map((r) => ({
    workspace_id: r.workspace_id, workspace_name: r.workspace_name, risk_rating: r.risk_rating,
    latest_score: r.latest_score, critical_findings: r.critical_findings, high_findings: r.high_findings,
    changes_7d: r.changes_7d, changes_7d_high: r.changes_7d_high,
    customer_changes_7d: r.customer_changes_7d,
    customer_changes_7d_high: r.customer_changes_7d_high,
  }));

  let executive_summary;
  if (customers === 0) {
    executive_summary = degradedQueries.length
      ? "Portfolio summary is unavailable because one or more customer data queries failed."
      : "No customers in your portfolio yet.";
  } else {
    const lead = top_attention[0];
    const why = lead
      ? (lead.critical_findings ? ` (${lead.critical_findings} critical finding${lead.critical_findings === 1 ? "" : "s"})`
        : lead.customer_changes_7d_high ? ` (${lead.customer_changes_7d_high} new high-severity supported change${lead.customer_changes_7d_high === 1 ? "" : "s"} this week)`
        : "")
      : "";

    const parts = [];
    if (degradedQueries.length) {
      parts.push(`Portfolio summary is partially unavailable: ${degradedQueries.join(", ")} data could not be read.`);
    }

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
    } else if (
      scoreState.state === PORTFOLIO_SCORE_STATES.AVAILABLE &&
      lifecycleProjectionComplete
    ) {
      parts.push("No customers currently need urgent attention.");
    } else if (
      scoreState.state === PORTFOLIO_SCORE_STATES.PARTIAL &&
      lifecycleProjectionComplete
    ) {
      // Clean bill of health for the assessed subset only — never for the portfolio.
      parts.push("None of the assessed customers currently need urgent attention; the customers without a completed assessment are not covered by this statement.");
    }
    // no_workspaces / evidence_insufficient: withhold the all-clear entirely. An
    // unassessed customer cannot need attention because nothing has looked at it, and
    // saying so out loud turns that silence into reassurance.

    if (customer_high_changes_7d) {
      parts.push(`${customer_high_changes_7d} high-severity supported change${customer_high_changes_7d === 1 ? "" : "s"} across the portfolio this week.`);
    } else if (!lifecycleProjectionComplete) {
      parts.push("Lifecycle support for one or more customer change collections was not evaluated completely.");
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
      customer_total_changes_7d,
      customer_high_changes_7d,
      lifecycle_claim_projection_coverage:
        lifecycleProjectionComplete ? "complete" : "unavailable",
      customers_needing_attention: attention.length,
      // Additive: avg_score keeps its meaning and value; these say whether it may be
      // spoken and what it is drawn from.
      avg_score_state:  scoreState.state,
      avg_score_reason: scoreState.reason,
      avg_score_basis:  { scored_customers: scoreState.basis.scored_workspaces, total_customers: scoreState.basis.total_workspaces },
      partial_failure: degradedQueries.length > 0,
      unavailable_metrics: degradedQueries,
    },
    top_attention,
    executive_summary,
  };
}
