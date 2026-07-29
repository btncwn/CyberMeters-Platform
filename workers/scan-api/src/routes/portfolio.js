// ── Portfolio + workspace list routes ──
// Workspace scan-report PDF, the portfolio risk APIs (overview / workspaces /
// alerts / trends / risk) and workspace list/create endpoints. Extracted
// near-verbatim from index.js (router split, Phase 2 PR #15). Receives the
// per-request routeCtx from index.js; returns a Response when a route
// matches, or null so the main router continues.
import { getEffectivePlan, hasFeatureEntitlement } from "../engines/entitlements.js";
import { buildWorkspaceExecutivePdf } from "../engines/pdf.js";
import { readLatestWorkspaceSnapshots } from "../engines/report-snapshot.js";
import { resolveReportBrandingV2, loadBrandingLogoDataUri } from "../engines/report-branding-v2.js";
import { prepareLogoXObject } from "../engines/pdf-image.js";
import { getEntitlementUsage, getPlanLimits, planLimitExceeded } from "../engines/plan-usage.js";
import { computePortfolioRisk } from "../engines/portfolio-risk.js";
import { computePortfolioCustomerRows, buildExecutiveSummary, LATEST_SCAN_CTE } from "../engines/portfolio-customers.js";
import {
  applyPortfolioView, buildPortfolioDomainSummary, computePortfolioDomainRows,
  PORTFOLIO_FILTERS, PORTFOLIO_SORTS,
} from "../engines/portfolio-domains.js";
import { CYBER_MOT_DOMAIN_KEYS, readDomainStateHistory } from "../engines/cyber-mot-state-history.js";
import { MATURITY_LEDGER_CONTRACT_VERSION, computePortfolioMaturity } from "../engines/domain-maturity.js";
import { collapseCustomerTimelineEvents } from "../engines/timeline-trust.js";
import { auditApiTokenSessionRouteDenied, createWorkspaceTrialSubscription } from "../engines/subscription-state.js";
import { createAuditEvent } from "../lib/events.js";
import { sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { createId, parseBoundedInteger } from "../lib/util.js";
import {
  phase5EvidenceReadCoverage,
  projectPhase5ScanRowsForCustomer,
  resolvePhase5CustomerAggregate,
} from "../engines/phase5-evidence.js";

export function portfolioBrandAlertPresentation(row = {}) {
  let evidence = [];
  try {
    const parsed = JSON.parse(row.evidence_json || "[]");
    evidence = Array.isArray(parsed) ? parsed : [];
  } catch { evidence = []; }
  const isIdn = row.variant_type === "homoglyph_idn" ||
    evidence.some((item) => item?.signal === "idn_visual_confusable" && item.value === true);
  return {
    title: `${isIdn ? "IDN lookalike" : "Brand risk"}: ${row.candidate_domain}`,
    description: isIdn
      ? "Active visually confusable IDN lookalike resolving via DNS. This is a lookalike signal, not proof of abuse."
      : `Active lookalike candidate (${row.variant_type ?? "unknown variant"}) resolving via DNS`,
  };
}

export async function portfolioRoutes(rctx) {
  const { request, env, url, json, serverError, corsHeaders,
          requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds } = rctx;

  // Portfolio (MSP multi-customer view) is a Business+/MSP feature: every
  // /api/portfolio/* endpoint requires the existing `portfolio_monitoring`
  // entitlement (Business + Enterprise). Returns a 403 Response — the exact shape
  // /risk already used — when the caller's effective plan lacks it, else null to
  // proceed. Reuses getEffectivePlan + hasFeatureEntitlement; no new entitlement,
  // plan, route or pricing rule. Isolation is still enforced separately per query.
  const requirePortfolioEntitlement = async (user) => {
    const plan = await getEffectivePlan(user.id, env);
    if (!hasFeatureEntitlement(plan, "portfolio_monitoring")) {
      return json({ error: "plan_feature_required", feature: "portfolio_monitoring", required_plan: "business", upgrade_url: "/billing" }, 403);
    }
    return null;
  };

    // ── Workspace Routes ──────────────────────────────────────────────────

    // GET /api/workspaces/:id/report — workspace PDF report
    // Snapshot-native (M5.d): an explicit "latest completed canonical snapshot
    // per domain" rendering — the inline stats/domain/finding/trend queries and
    // the local score-band brains (scoreToRating et al.) are retired. Latest
    // live state never masquerades as a historical report: every fact shown is
    // a dated immutable snapshot, and domains without one appear as honestly
    // not-yet-available. Tested before the generic wsMatch so "/report" is
    // never confused with a domain ID.
    const reportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report$/);
    if (reportMatch && request.method === "GET") {
      const wsId = reportMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const ws = await env.cybermeters_db
          .prepare(`SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
          .bind(wsId).first();
        if (!ws) return json({ error: "Workspace not found" }, 404);
        const reads = await readLatestWorkspaceSnapshots(env, wsId);
        let branding = null, logoImage = null;
        try {
          branding = await resolveReportBrandingV2(env, { workspaceId: wsId });
          const dataUri = await loadBrandingLogoDataUri(env, branding);
          if (dataUri) logoImage = await prepareLogoXObject(dataUri, branding.accent);
        } catch { branding = null; logoImage = null; }
        const generatedAt = new Date().toISOString();
        const pdfBytes = buildWorkspaceExecutivePdf({ workspaceName: ws.name, reads, branding, generatedAt, logoImage });
        const safeName = (ws.name || "workspace").replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase();
        return new Response(pdfBytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type":        "application/pdf",
            "Content-Disposition": `attachment; filename="cybermeters-${safeName}-report.pdf"`,
            "Content-Length":      String(pdfBytes.length),
          },
        });
      } catch (e) {
        return serverError("portfolio/report-pdf", e, "PDF generation failed. Please try again.");
      }
    }

    // ── Portfolio Risk Engine ─────────────────────────────────────────────────
    // GET /api/portfolio/risk — MSP portfolio risk intelligence (see below)

    // ── Portfolio APIs ────────────────────────────────────────────────────────
    // GET /api/portfolio/overview   — aggregate stats across all workspaces
    // GET /api/portfolio/workspaces — per-workspace risk rows, sorted by risk
    // GET /api/portfolio/alerts     — cross-workspace alert feed
    // GET /api/portfolio/trends     — 30-day daily aggregate trend
    // ─────────────────────────────────────────────────────────────────────────

    if (request.method === "GET" && url.pathname === "/api/portfolio/overview") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) {
          return json({
            total_workspaces: 0, total_domains: 0, total_assets: 0,
            total_vendors: 0, total_brand_candidates: 0, total_reports: 0,
            critical_findings: 0, high_findings: 0, new_assets_7d: 0,
            new_reports_30d: 0, average_score: null,
            highest_risk_workspace: null, generated_at: new Date().toISOString(),
          });
        }
        const wsIn = workspaceIds.map(() => "?").join(",");
        const [
          wsRes, domRes, assetRes, vendorRes, brandRes, rptRes,
          findingsRes, newAssetsRes, newRptsRes,
          verifiedDomsRes, unverifiedDomsRes, failedVerifRes,
          avgScoreRes, highRiskRes,
        ] = await Promise.allSettled([
          db.prepare(`SELECT COUNT(*) AS count FROM workspaces WHERE id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_reports WHERE status='completed' AND deleted_at IS NULL AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          // Critical + high findings from the latest completed scan per domain
          db.prepare(`
            WITH ${LATEST_SCAN_CTE}
            SELECT f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd ON lpd.scan_id = s.id
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE f.severity IN ('critical','high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY f.severity
          `).bind(...workspaceIds).all(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_assets WHERE first_seen >= datetime('now','-7 days') AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_reports WHERE status='completed' AND deleted_at IS NULL AND generated_at >= datetime('now','-30 days') AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          // Domain verification counts
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id IN (${wsIn}) AND d.verification_status = 'verified'`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id IN (${wsIn}) AND d.verification_status NOT IN ('verified')`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id IN (${wsIn}) AND d.verification_status = 'failed'`).bind(...workspaceIds).first(),
          // Candidate scores across the latest complete scan per domain. The
          // stored rows are projected through immutable Phase-5 evidence below
          // before any portfolio average is published.
          db.prepare(`
            WITH ${LATEST_SCAN_CTE}
            SELECT s.id AS scan_id, s.score, s.rating, s.scan_quality, s.created_at
            FROM scans s
            JOIN lpd ON lpd.scan_id = s.id
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.score IS NOT NULL
              AND s.scan_quality = 'complete'
              AND wd.workspace_id IN (${wsIn})
          `).bind(...workspaceIds).all(),
          // Workspace with most critical findings from latest scans
          db.prepare(`
            WITH ${LATEST_SCAN_CTE},
            crit AS (
              SELECT s.domain_id, COUNT(*) AS cnt
              FROM findings f
              JOIN scans s ON f.scan_id = s.id
              JOIN lpd ON lpd.scan_id = s.id
              WHERE f.severity = 'critical'
              GROUP BY s.domain_id
            ),
            ws_crit AS (
              SELECT wd.workspace_id, SUM(c.cnt) AS total_crit
              FROM crit c
              JOIN workspace_domains wd ON c.domain_id = wd.domain_id
              WHERE wd.workspace_id IN (${wsIn})
              GROUP BY wd.workspace_id
            )
            SELECT w.id, w.name, wc.total_crit
            FROM ws_crit wc
            JOIN workspaces w ON w.id = wc.workspace_id
            ORDER BY wc.total_crit DESC
            LIMIT 1
          `).bind(...workspaceIds).first(),
        ]);

        // M5.e honesty: a REJECTED query is not a clean zero. Each metric from
        // a failed query is null, and partial_failure discloses the degradation
        // — a D1 error must never render as "0 critical findings".
        const settled = [];
        const count = (res, name) => {
          if (res.status === 'fulfilled') return res.value?.count ?? 0;
          settled.push(name);
          return null;
        };
        const findingsBySev = {};
        let findingsFailed = false;
        if (findingsRes.status === 'fulfilled') {
          for (const r of (findingsRes.value?.results ?? [])) findingsBySev[r.severity] = r.cnt;
        } else { findingsFailed = true; settled.push('findings'); }

        let avgRaw = null;
        let averageEvidenceCoverage = null;
        if (avgScoreRes.status === 'fulfilled') {
          const customerScoreRows = await projectPhase5ScanRowsForCustomer(
            env,
            (avgScoreRes.value?.results ?? []).map((row) => ({
              ...row,
              status: "completed",
            })),
          );
          const aggregate = resolvePhase5CustomerAggregate(customerScoreRows);
          avgRaw = aggregate.score;
          averageEvidenceCoverage = aggregate.evidence_coverage;
        } else {
          settled.push('average_score');
        }
        const hrw    = highRiskRes.status === 'fulfilled'  ? highRiskRes.value : (settled.push('highest_risk_workspace'), null);

        return json({
          total_workspaces:       count(wsRes, 'total_workspaces'),
          total_domains:          count(domRes, 'total_domains'),
          total_assets:           count(assetRes, 'total_assets'),
          total_vendors:          count(vendorRes, 'total_vendors'),
          total_brand_candidates: count(brandRes, 'total_brand_candidates'),
          total_reports:          count(rptRes, 'total_reports'),
          critical_findings:      findingsFailed ? null : (findingsBySev['critical'] ?? 0),
          high_findings:          findingsFailed ? null : (findingsBySev['high'] ?? 0),
          new_assets_7d:          count(newAssetsRes, 'new_assets_7d'),
          new_reports_30d:        count(newRptsRes, 'new_reports_30d'),
          average_score:          avgRaw != null ? Math.round(avgRaw) : null,
          average_score_basis:    'complete_scans',
          score_evidence_coverage: averageEvidenceCoverage,
          highest_risk_workspace: hrw ? { id: hrw.id, name: hrw.name, critical_findings: hrw.total_crit } : null,
          verified_domains:       count(verifiedDomsRes, 'verified_domains'),
          unverified_domains:     count(unverifiedDomsRes, 'unverified_domains'),
          verification_failures:  count(failedVerifRes, 'verification_failures'),
          partial_failure:
            settled.length > 0 ||
            averageEvidenceCoverage?.assessment_complete === false,
          unavailable_metrics:    settled,
          generated_at:           new Date().toISOString(),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const rows = await computePortfolioCustomerRows(env.cybermeters_db, workspaceIds, { env });
        return json({
          workspaces: rows,
          partial_failure:
            (rows.degraded_queries?.length ?? 0) > 0 ||
            rows.phase5_evidence_coverage?.complete !== true,
          unavailable_metrics: rows.degraded_queries ?? [],
          phase5_evidence_coverage: rows.phase5_evidence_coverage,
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/portfolio/executive-summary ─────────────────────────────────
    // Portfolio-level exec summary the MSP can review or share: posture spread,
    // this week's movement, and the top customers needing attention. Scoped to
    // the caller's accessible workspaces (getAccessibleWorkspaceIds).
    if (request.method === "GET" && url.pathname === "/api/portfolio/executive-summary") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const rows = await computePortfolioCustomerRows(env.cybermeters_db, workspaceIds, { env });
        return json({
          ...buildExecutiveSummary(rows),
          partial_failure:
            (rows.degraded_queries?.length ?? 0) > 0 ||
            rows.phase5_evidence_coverage?.complete !== true,
          unavailable_metrics: rows.degraded_queries ?? [],
          phase5_evidence_coverage: rows.phase5_evidence_coverage,
          generated_at: new Date().toISOString(),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/alerts") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const db    = env.cybermeters_db;
        const limit = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ alerts: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [eventsRes, brandRes, failedRptsRes] = await Promise.allSettled([
          // Asset events — presentation-collapsed before the existing per-day
          // dedupe so short-lived remove/reappear churn never becomes an MSP alert.
          db.prepare(`
            SELECT ae.id, ae.workspace_id, w.name AS workspace_name,
                   ae.domain_id, ae.scan_id, ae.event_type,
                   ae.severity,
                   ae.hostname,
                   ae.description,
                   ae.created_at
            FROM asset_events ae
            JOIN workspaces w ON w.id = ae.workspace_id
            WHERE ae.workspace_id IN (${wsIn})
            ORDER BY ae.created_at DESC, ae.id DESC
            LIMIT ?
          `).bind(...workspaceIds, limit * 3).all(),
          // Active brand risks that resolve via DNS
          db.prepare(`
            SELECT ba.workspace_id, w.name AS workspace_name,
                   ba.candidate_domain, ba.risk_level, ba.variant_type,
                   ba.evidence_json, ba.updated_at
            FROM workspace_brand_assets ba
            JOIN workspaces w ON w.id = ba.workspace_id
            WHERE ba.status = 'active' AND ba.dns_resolves = 1
              AND ba.workspace_id IN (${wsIn})
            ORDER BY ba.updated_at DESC
            LIMIT ?
          `).bind(...workspaceIds, Math.ceil(limit / 3)).all(),
          // Failed report generations
          db.prepare(`
            SELECT wr.workspace_id, w.name AS workspace_name,
                   wr.report_type, wr.metadata_json, wr.created_at
            FROM workspace_reports wr
            JOIN workspaces w ON w.id = wr.workspace_id
            WHERE wr.status = 'failed'
              AND wr.deleted_at IS NULL
              AND wr.workspace_id IN (${wsIn})
            ORDER BY wr.created_at DESC
            LIMIT ?
          `).bind(...workspaceIds, Math.ceil(limit / 5)).all(),
        ]);

        const alerts = [];

        const collapsedEvents = collapseCustomerTimelineEvents(eventsRes.status === 'fulfilled' ? (eventsRes.value?.results ?? []) : []);
        const dedupedEvents = [];
        const eventKeys = new Set();
        for (const ev of collapsedEvents) {
          const day = String(ev.created_at || "").slice(0, 10);
          const key = `${ev.workspace_id}:${ev.event_type}:${ev.hostname || ""}:${day}`;
          if (eventKeys.has(key)) continue;
          eventKeys.add(key);
          dedupedEvents.push(ev);
          if (dedupedEvents.length >= limit) break;
        }

        for (const r of dedupedEvents) {
          let title = (r.event_type ?? '').replace(/_/g, ' ');
          const et = r.event_type;
          if      (et === 'new_asset_discovered')      title = `New asset: ${r.hostname ?? ''}`;
          else if (et === 'takeover_risk_detected')    title = `Takeover risk: ${r.hostname ?? ''}`;
          else if (et === 'wildcard_dns_detected')     title = `Wildcard DNS: ${r.hostname ?? ''}`;
          else if (et === 'cloud_storage_detected')    title = `Cloud storage exposed: ${r.hostname ?? ''}`;
          else if (et === 'certificate_expiry_warning')title = `Certificate expiring: ${r.hostname ?? ''}`;
          else if (et === 'certificate_expired')       title = `Certificate expired: ${r.hostname ?? ''}`;
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           et ?? 'unknown',
            severity:       r.severity ?? 'info',
            title,
            description:    r.description ?? null,
            created_at:     r.created_at,
          });
        }

        for (const r of (brandRes.status === 'fulfilled' ? (brandRes.value?.results ?? []) : [])) {
          const sev = (r.risk_level === 'critical' || r.risk_level === 'high') ? r.risk_level : 'medium';
          const presentation = portfolioBrandAlertPresentation(r);
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'brand_risk',
            severity:       sev,
            title:          presentation.title,
            description:    presentation.description,
            created_at:     r.updated_at,
          });
        }

        for (const r of (failedRptsRes.status === 'fulfilled' ? (failedRptsRes.value?.results ?? []) : [])) {
          let errMsg = null;
          try { errMsg = JSON.parse(r.metadata_json)?.error ?? null; } catch {}
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'report_generation_failed',
            severity:       'high',
            title:          `Report generation failed (${r.report_type})`,
            description:    errMsg ?? 'Report generation failed',
            created_at:     r.created_at,
          });
        }

        // Unified sort by created_at desc, then trim to limit
        alerts.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''));

        return json({ alerts: alerts.slice(0, limit) });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/trends") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ trend: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [scanTrendRes, findingsTrendRes, assetTrendRes] = await Promise.allSettled([
          // Score candidates per day. Aggregate only after the immutable
          // Phase-5 evidence contract has projected each stored row.
          db.prepare(`
            SELECT s.id AS scan_id, date(s.created_at) AS day,
                   s.score, s.rating, s.scan_quality, s.created_at
            FROM scans s
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.scan_quality = 'complete'
              AND s.created_at >= datetime('now', '-30 days')
              AND s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            ORDER BY s.created_at
          `).bind(...workspaceIds).all(),
          // Critical + high finding counts per day from scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at) AS day, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.scan_quality = 'complete'
              AND s.created_at >= datetime('now', '-30 days')
              AND f.severity IN ('critical', 'high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY date(s.created_at), f.severity
            ORDER BY day
          `).bind(...workspaceIds).all(),
          // New assets discovered per day in last 30 days
          db.prepare(`
            SELECT date(first_seen) AS day, COUNT(*) AS new_assets
            FROM workspace_assets
            WHERE first_seen >= datetime('now', '-30 days')
              AND workspace_id IN (${wsIn})
            GROUP BY date(first_seen)
            ORDER BY day
          `).bind(...workspaceIds).all(),
        ]);

        // Merge into a single map keyed by day
        const dayMap = {};

        const rawScoreRows =
          scanTrendRes.status === 'fulfilled'
            ? (scanTrendRes.value?.results ?? [])
            : [];
        const customerScoreRows = scanTrendRes.status === 'fulfilled'
          ? await projectPhase5ScanRowsForCustomer(
              env,
              rawScoreRows.map((row) => ({ ...row, status: "completed" })),
            )
          : [];
        const scoreRowsByDay = new Map();
        for (const row of customerScoreRows) {
          const bucket = scoreRowsByDay.get(row.day) ?? { scans: 0, rows: [] };
          bucket.scans += 1;
          bucket.rows.push(row);
          scoreRowsByDay.set(row.day, bucket);
        }
        for (const [day, bucket] of scoreRowsByDay) {
          const aggregate = resolvePhase5CustomerAggregate(bucket.rows);
          dayMap[day] = {
            date: day,
            scans: bucket.scans,
            average_score: aggregate.score == null
              ? null
              : Math.round(aggregate.score * 10) / 10,
            lowest_score: aggregate.scores.length
              ? Math.min(...aggregate.scores)
              : null,
            highest_score: aggregate.scores.length
              ? Math.max(...aggregate.scores)
              : null,
            score_evidence_coverage: aggregate.evidence_coverage,
            critical_findings: 0,
            high_findings: 0,
            new_assets: 0,
          };
        }

        for (const r of (findingsTrendRes.status === 'fulfilled' ? (findingsTrendRes.value?.results ?? []) : [])) {
          if (!dayMap[r.day]) dayMap[r.day] = { date: r.day, scans: 0, average_score: null, lowest_score: null, highest_score: null, critical_findings: 0, high_findings: 0, new_assets: 0 };
          if (r.severity === 'critical') dayMap[r.day].critical_findings = r.cnt;
          else if (r.severity === 'high') dayMap[r.day].high_findings   = r.cnt;
        }

        for (const r of (assetTrendRes.status === 'fulfilled' ? (assetTrendRes.value?.results ?? []) : [])) {
          if (!dayMap[r.day]) dayMap[r.day] = { date: r.day, scans: 0, average_score: null, lowest_score: null, highest_score: null, critical_findings: 0, high_findings: 0, new_assets: 0 };
          dayMap[r.day].new_assets = r.new_assets;
        }

        const trend = Object.values(dayMap).sort((a, b) => a.date.localeCompare(b.date));
        // M5.e honesty: a rejected series is disclosed, never an empty-looking
        // clean trend; the score series is complete-quality only.
        const failedSeries = [
          scanTrendRes.status !== 'fulfilled' ? 'scores' : null,
          findingsTrendRes.status !== 'fulfilled' ? 'findings' : null,
          assetTrendRes.status !== 'fulfilled' ? 'assets' : null,
        ].filter(Boolean);
        return json({
          trend,
          comparable_basis: 'complete_scans',
          partial_failure:
            failedSeries.length > 0 ||
            phase5EvidenceReadCoverage(customerScoreRows).complete !== true,
          unavailable_series: failedSeries,
          phase5_evidence_coverage:
            phase5EvidenceReadCoverage(customerScoreRows),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // GET /api/portfolio/risk — MSP Portfolio Risk Engine v1
    //   Aggregates BRS, supply chain, and vendor intelligence across all workspaces
    //   accessible to the authenticated user. Returns ranked workspace list,
    //   portfolio-level alerts, shared vendor dependencies, and executive summary.
    //   Pure read: performs no domain write. It used to append a
    //   portfolio_risk_snapshots row per request — see portfolio-risk.js and
    //   scripts/validate-portfolio-read-purity.js.
    if (request.method === 'GET' && url.pathname === '/api/portfolio/risk') {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const result = await computePortfolioRisk(workspaceIds, env);
        return json(result);
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/portfolio/domains ───────────────────────────────────────────
    // MSP Portfolio Per-Domain State and Trend: one row per authorised (workspace,
    // domain) carrying all EIGHT canonical Cyber MOT states, each with its own trend,
    // freshness and attributable reasons.
    //
    // Reads persisted resolver output (cyber_mot_domain_states, mig 091) — four D1
    // queries for the whole portfolio, no R2, no per-domain query, no write. The eight
    // states are the canonical resolver's own verdict, recorded at scan finalize; this
    // route never re-derives one.
    //
    // Pure read: the only writes on this path are the platform's own (api_rate_limits,
    // user_sessions.last_seen_at), which fire before any handler runs. See
    // scripts/validate-portfolio-read-purity.js.
    if (request.method === "GET" && url.pathname === "/api/portfolio/domains") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const limit  = parseBoundedInteger(url.searchParams.get("limit"), 25, 1, 100);
        const offset = parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 100000);
        const sort   = url.searchParams.get("sort") || "priority";
        const filter = url.searchParams.get("filter") || null;
        const domainKey = url.searchParams.get("domain_key") || null;
        const state  = url.searchParams.get("state") || null;

        // No accessible workspace is NOT an empty portfolio with a clean bill of health
        // — it is a portfolio with nothing in it, and it says so.
        if (workspaceIds.length === 0) {
          return json({
            domains: [],
            summary: buildPortfolioDomainSummary([]),
            portfolio_state: "no_workspaces",
            portfolio_state_reason: "No customer environments are being monitored yet.",
            pagination: { limit, offset, total: 0 },
            available_filters: PORTFOLIO_FILTERS, available_sorts: PORTFOLIO_SORTS,
            domain_keys: CYBER_MOT_DOMAIN_KEYS,
            generated_at: new Date().toISOString(),
          });
        }

        const all = await computePortfolioDomainRows(env.cybermeters_db, workspaceIds, { env });
        // The summary folds the SAME array the caller pages through, so totals can never
        // disagree with the rows, and a filtered view cannot leak the unfiltered count.
        const summary = buildPortfolioDomainSummary(all);
        const view = applyPortfolioView(all, { filter, domainKey, state, sort, limit, offset });

        const assessed = summary.assessed_domains;
        const portfolioState =
          all.length === 0        ? "no_domains" :
          assessed === 0          ? "evidence_insufficient" :
          assessed < all.length   ? "partial" : "available";

        return json({
          domains: view.rows,
          summary,
          portfolio_state: portfolioState,
          portfolio_state_reason:
            portfolioState === "no_domains"            ? "No domains are being monitored in your portfolio yet."
            : portfolioState === "evidence_insufficient" ? `None of the ${all.length} monitored domain${all.length === 1 ? " has" : "s have"} a completed assessment yet, so no state can be reported for them.`
            : portfolioState === "partial"               ? summary.coverage_note
            : `Based on all ${all.length} monitored domain${all.length === 1 ? "" : "s"}.`,
          pagination: { limit, offset, total: view.total },
          available_filters: PORTFOLIO_FILTERS, available_sorts: PORTFOLIO_SORTS,
          domain_keys: CYBER_MOT_DOMAIN_KEYS,
          phase5_evidence_coverage: phase5EvidenceReadCoverage(all),
          generated_at: new Date().toISOString(),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/portfolio/maturity ──────────────────────────────────────────
    // MSP portfolio eight-domain MATURITY aggregation (M5.f). Read-only. Only
    // eligible complete-scan maturity rows exist, so partial/ineligible evidence is
    // excluded by construction. No mean — a worst-case fold per domain. A query
    // failure surfaces `unavailable`, never a clean zero or a healthy default.
    // Scoped to the caller's accessible workspaces (getAccessibleWorkspaceIds).
    if (request.method === "GET" && url.pathname === "/api/portfolio/maturity") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const gate = await requirePortfolioEntitlement(user);
      if (gate) return gate;
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const result = await computePortfolioMaturity(env.cybermeters_db, workspaceIds);
        return json({
          ...result,
          domain_keys: CYBER_MOT_DOMAIN_KEYS,
          contract_version: MATURITY_LEDGER_CONTRACT_VERSION,
          generated_at: new Date().toISOString(),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/portfolio/domains/:workspaceId/:domainId ────────────────────
    // Per-domain detail + the eight-domain history series behind its trend.
    // Non-enumerating: a domain in a workspace the caller cannot reach returns the SAME
    // 404 as one that does not exist, and the workspace check runs before the lookup so
    // the two cannot be told apart by timing either.
    {
      const m = url.pathname.match(/^\/api\/portfolio\/domains\/([^/]+)\/([^/]+)$/);
      if (m && request.method === "GET") {
        const [, wsId, domainId] = m;
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const gate = await requirePortfolioEntitlement(user);
        if (gate) return gate;
        try {
          const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
          if (!access) return json({ error: "Not found" }, 404);

          const rows = await computePortfolioDomainRows(
            env.cybermeters_db,
            [wsId],
            { env },
          );
          const row = rows.find((r) => r.domain_id === domainId);
          if (!row) return json({ error: "Not found" }, 404);

          const history = await readDomainStateHistory(env.cybermeters_db, wsId, domainId, {
            limit: parseBoundedInteger(url.searchParams.get("history_limit"), 20, 1, 100),
          });
          return json({
            ...row,
            history,
            phase5_evidence_coverage: phase5EvidenceReadCoverage(rows),
            generated_at: new Date().toISOString(),
          });
        } catch (err) {
          return serverError("api", err);
        }
      }
    }

    // GET /api/workspaces — list all workspaces
    if (request.method === "GET" && url.pathname === "/api/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        // Return only workspaces the caller owns or is a member of. Workspace-
        // bound API tokens are collapsed by getAccessibleWorkspaceIds() to the
        // single token workspace.
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ workspaces: [], default_workspace_id: null });
        const placeholders = workspaceIds.map(() => "?").join(",");
        const result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT w.id, w.name, w.created_at,
                    wm.role
             FROM workspaces w
             LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
             WHERE w.id IN (${placeholders})
             ORDER BY w.created_at ASC`
          )
          .bind(user.id, ...workspaceIds)
          .all();
        const workspaces = result.results ?? [];
        // default_workspace_id: prefer the workspace where the user is owner
        // (earliest-created), falling back to first accessible workspace.
        const ownerWs  = workspaces.find(w => w.role === "owner");
        const defaultWs = ownerWs ?? workspaces[0] ?? null;
        return json({ workspaces, default_workspace_id: defaultWs?.id ?? null });
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // POST /api/workspaces — create a workspace
    if (request.method === "POST" && url.pathname === "/api/workspaces") {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const name = (body.name || "").trim();
      if (!name) {
        return json({ error: "name is required" }, 400);
      }
      if (name.length > 100) return json({ error: "name must be 100 characters or fewer" }, 400);
      const id         = `workspace_${crypto.randomUUID()}`;
      const created_at = new Date().toISOString();
      try {
        // Creator must be authenticated — no anonymous workspace creation.
        const creator = await requireAuth(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401);
        // Workspace creation establishes a new tenant and owner membership;
        // require an interactive user session rather than an API token.
        if (creator.api_token_id) {
          await auditApiTokenSessionRouteDenied(env, creator, request);
          return json({ error: "Session authentication required" }, 403);
        }
        // A workspace must always have an owner. Reject rather than silently
        // writing owner_user_id = NULL, which would create an orphan workspace
        // that no one can access via the UI (see tenant-isolation invariants).
        if (!creator.id) {
          return serverError("workspaces/create", new Error("authenticated session has no user id"),
            "Could not create workspace. Please sign in again and retry.");
        }

        // Entitlement: workspace limit
        const creatorPlan = await getEffectivePlan(creator.id, env);
        const wsUsage = await getEntitlementUsage(creator, env);
        const wsLimits = getPlanLimits(creatorPlan);
        if (wsUsage.workspaces >= wsLimits.workspaces) {
          return json(planLimitExceeded("workspaces", wsLimits.workspaces, wsUsage.workspaces), 403);
        }

        await env.cybermeters_db
          .prepare(`INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)`)
          .bind(id, name, creator.id, created_at)
          .run();
        // Seed owner membership row if creator is authenticated
        if (creator) {
          await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_members (id, workspace_id, user_id, role, created_at)
               VALUES (?, ?, ?, 'owner', datetime('now'))`
            )
            .bind(createId("wm"), id, creator.id)
            .run();
        }
        // Audit: workspace created
        await createAuditEvent(env, {
          workspace_id: id,
          user_id:      creator?.id ?? null,
          event_type:   "workspace_created",
          entity_type:  "workspace",
          entity_id:    id,
          description:  `Workspace "${name}" created`,
          metadata:     { workspace_name: name },
        });
        // Lifecycle: workspace created (once per workspace; owner's verified address).
        await sendLifecycleEmail(env, { type: "lifecycle_workspace_created", user_id: creator?.id ?? null, workspace_id: id, wsName: name }).catch(() => {});
        // Billing: auto-create 14-day Professional trial for the new workspace
        await createWorkspaceTrialSubscription(id, creator.id, env);
        return json({ workspace: { id, name, created_at } }, 201);
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }


  return null;
}
