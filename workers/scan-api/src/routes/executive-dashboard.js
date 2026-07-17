// ── Executive dashboard routes ──
// Workspace executive-dashboard KPI endpoint (with its nested activity feed
// route). Extracted near-verbatim from index.js (router split, Phase 2 PR #8).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { getCurrentPosturePresentation } from "../engines/current-posture.js";
import { resolveCyberMotDomainStates } from "../engines/cyber-mot-domains.js";
import { getCyberEssentialsSnapshot } from "../engines/ce-readiness.js";
import { LATEST_COMPLETED_SCAN_SCOPE } from "../engines/report-queries.js";
import { getEffectivePlan, hasFeatureEntitlement } from "../engines/entitlements.js";
import { getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { parseBoundedInteger } from "../lib/util.js";

export async function executiveDashboardRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole } = rctx;

    // ── GET /api/workspaces/:id/cyber-mot-domains ────────────────────────────
    // Canonical eight-domain Cyber MOT coverage states for a workspace, resolved
    // server-side from the authoritative (latest-complete) scan — or the canonical
    // NO-SCAN states when none exists. ALWAYS returns eight domains so the Dashboard
    // renders all eight even before any scan, and the frontend never invents states.
    // Core coverage: workspace:read only, NO feature gate. Never fails to fewer than
    // eight (any error returns the canonical no-scan set).
    const motMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/cyber-mot-domains$/);
    if (motMatch && request.method === "GET") {
      const wsId = motMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const posture = await getCurrentPosturePresentation(env, { workspaceId: wsId });
        const authScanId = posture?.authoritative_scan_id ?? null;
        let report = null;
        if (authScanId) {
          const obj = await env.cybermeters_reports.get(`reports/${authScanId}.json`);
          report = obj ? await obj.json() : null;
        }
        let ceSnap = null;
        try { ceSnap = await getCyberEssentialsSnapshot(wsId, env); } catch { ceSnap = null; }
        return json({
          workspace_id:   wsId,
          source_scan_id: authScanId,
          cyber_mot_domains: resolveCyberMotDomainStates(report, { scanId: authScanId, cyberEssentials: ceSnap }),
        });
      } catch (e) {
        return json({ workspace_id: wsId, source_scan_id: null, cyber_mot_domains: resolveCyberMotDomainStates(null) });
      }
    }

    // ── GET /api/workspaces/:id/executive-dashboard ──────────────────────────
    // Single-call aggregation for the Executive Risk Intelligence Dashboard.
    // Returns summary, score_trend, risk_distribution, top_risks, changes,
    // remediation priorities, and KPI bar — all in one response.
    const execDashMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/executive-dashboard$/);
    if (execDashMatch && request.method === "GET") {
      const wsId = execDashMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // ── Feature gate: executive_dashboard — professional+ only ─────────────
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan    = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, "executive_dashboard")) {
          return json({
            error:         "plan_feature_required",
            feature:       "executive_dashboard",
            required_plan: "professional",
            upgrade_url:   "/billing",
          }, 403);
        }
      }

      try {
        const [
          domainRow,
          latestScanRow,
          activeAssetsRow,
          criticalRow,
          highRow,
          scoreTrendRows,
          riskDistRows,
          topRisksRows,
          scoreHistoryRows,
          newAssetsRow,
          remediationRows,
          reportsRow,
        ] = await env.cybermeters_db.batch([

          // 1. Domain summary — total + verified count
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(d.id) AS total,
                      SUM(CASE WHEN d.verification_status = 'verified' THEN 1 ELSE 0 END) AS verified
               FROM workspace_domains wd
               JOIN domains d ON d.id = wd.domain_id
               WHERE wd.workspace_id = ?`
            )
            .bind(wsId),

          // 2. Latest completed scan in workspace.
          // Executive Dashboard security_score intentionally uses this latest
          // completed scan; /summary may use average latest score across domains.
          env.cybermeters_db
            .prepare(
              `SELECT s.id, s.domain, s.score, s.rating, s.created_at
               FROM scans s
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL
               ORDER BY s.created_at DESC LIMIT 1`
            )
            .bind(wsId),

          // 3. Active assets
          env.cybermeters_db
            .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
            .bind(wsId),

          // 4. Critical CURRENT findings — canonical latest-complete-scan-per-domain
          // scope (deterministic, complete-only) so the same finding across several
          // scans is counted once and never inflated. Binds wsId twice (outer filter
          // + scope's inner sx.workspace_id).
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(f.id) AS n
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND f.severity = 'critical'
                 AND ${LATEST_COMPLETED_SCAN_SCOPE}`
            )
            .bind(wsId, wsId),

          // 5. High CURRENT findings — same canonical scope.
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(f.id) AS n
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND f.severity = 'high'
                 AND ${LATEST_COMPLETED_SCAN_SCOPE}`
            )
            .bind(wsId, wsId),

          // 6. Score trend — last 30 historical_scores ordered oldest→newest for chart
          env.cybermeters_db
            .prepare(
              `SELECT score, rating, domain, created_at
               FROM (SELECT score, rating, domain, created_at
                     FROM historical_scores WHERE workspace_id = ? AND scan_quality = 'complete'
                     ORDER BY created_at DESC LIMIT 30)
               ORDER BY created_at ASC`
            )
            .bind(wsId),

          // 7. Risk distribution — CURRENT severity counts, canonical scope.
          env.cybermeters_db
            .prepare(
              `SELECT f.severity, COUNT(*) AS n
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND ${LATEST_COMPLETED_SCAN_SCOPE}
               GROUP BY f.severity`
            )
            .bind(wsId, wsId),

          // 8. Top risks — CURRENT top 10 by severity, canonical scope (not a 30-day
          // window, so a finding is never listed once per historical scan).
          env.cybermeters_db
            .prepare(
              `SELECT f.title, f.severity, f.created_at, s.domain
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND f.severity IN ('critical', 'high', 'medium')
                 AND ${LATEST_COMPLETED_SCAN_SCOPE}
               ORDER BY CASE f.severity
                 WHEN 'critical' THEN 1
                 WHEN 'high'     THEN 2
                 WHEN 'medium'   THEN 3
                 ELSE 4 END ASC,
                 f.created_at DESC
               LIMIT 10`
            )
            .bind(wsId, wsId),

          // 9. Last 2 historical scores for score delta
          env.cybermeters_db
            .prepare(
              `SELECT score, created_at, domain
               FROM historical_scores WHERE workspace_id = ? AND scan_quality = 'complete'
               ORDER BY created_at DESC, id DESC LIMIT 2`
            )
            .bind(wsId),

          // 10. New assets discovered in last 7 days
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM asset_events
               WHERE workspace_id = ?
                 AND event_type IN ('asset_discovered', 'new_asset_discovered')
                 AND created_at >= datetime('now', '-7 days')`
            )
            .bind(wsId),

          // 11. Remediation items from last 30 days scans
          env.cybermeters_db
            .prepare(
              `SELECT ri.priority, ri.title, ri.reason, s.domain, ri.created_at
               FROM remediation_items ri
               JOIN scans s ON ri.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')
               ORDER BY CAST(ri.priority AS INTEGER) ASC
               LIMIT 30`
            )
            .bind(wsId),

          // 12. Workspace reports generated
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM workspace_reports
               WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL`
            )
            .bind(wsId),
        ]);

        // ── Assemble response ───────────────────────────────────────────────

        const domainData    = domainRow.results[0]       ?? { total: 0, verified: 0 };
        const latestScan    = latestScanRow.results[0]   ?? null;
        // Canonical current posture: authoritative = latest COMPLETE scan; the raw
        // security_score/risk_level are shown ONLY for a complete assessment.
        const posture = await getCurrentPosturePresentation(env, { workspaceId: wsId });
        const activeAssets  = activeAssetsRow.results[0]?.n ?? 0;
        const criticalCount = criticalRow.results[0]?.n  ?? 0;
        const highCount     = highRow.results[0]?.n      ?? 0;

        const trendPoints = (scoreTrendRows.results || []).map(r => ({
          score:      r.score,
          rating:     r.rating,
          domain:     r.domain,
          scanned_at: r.created_at,
        }));

        const riskDist = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        for (const r of (riskDistRows.results || [])) {
          const sev = r.severity?.toLowerCase();
          if (sev in riskDist) riskDist[sev] += r.n;
          riskDist.total += r.n;
        }

        const topRisks = (topRisksRows.results || []).map(r => ({
          title:       r.title,
          severity:    r.severity,
          domain:      r.domain,
          detected_at: r.created_at,
        }));

        const scoreHistory  = scoreHistoryRows.results || [];
        const scoreCurrent  = scoreHistory[0]?.score  ?? null;
        const scorePrevious = scoreHistory[1]?.score  ?? null;
        const scoreDelta    = (scoreCurrent != null && scorePrevious != null)
          ? scoreCurrent - scorePrevious : null;

        const newAssets7d = newAssetsRow.results[0]?.n ?? 0;

        const remItems = remediationRows.results || [];
        const fixNow  = remItems.filter(r => String(r.priority) === "1");
        const fixNext = remItems.filter(r => String(r.priority) === "2");
        const monitor = remItems.filter(r => parseInt(r.priority, 10) >= 3);

        const totalDomains     = domainData.total   ?? 0;
        const verifiedCount    = domainData.verified ?? 0;
        const verificationRate = totalDomains > 0
          ? Math.round((verifiedCount / totalDomains) * 100) : 0;

        // M5.e: complete-quality points only (query above is gated), a missing
        // score is EXCLUDED rather than averaged as 0, and the no-trend fallback
        // is the authoritative posture score, never a raw any-quality scan row.
        const scoredPoints = trendPoints.filter((p) => Number.isFinite(p.score));
        const avgScore = scoredPoints.length > 0
          ? Math.round(scoredPoints.reduce((s, p) => s + p.score, 0) / scoredPoints.length)
          : (posture?.authoritative?.display_score ?? null);

        return json({
          workspace_id: wsId,
          generated_at: new Date().toISOString(),

          summary: {
            // Authoritative posture only (complete). display_rating is null for a
            // provisional latest — never an unqualified rating. Full canonical
            // decision + any provisional latest are exposed under current_posture.
            security_score:    posture.authoritative?.display_score  ?? null,
            risk_level:        posture.authoritative?.display_rating ?? null,
            current_posture:   posture,
            domains:           totalDomains,
            verified_domains:  verifiedCount,
            verification_rate: verificationRate,
            active_assets:     activeAssets,
            critical_findings: criticalCount,
            high_findings:     highCount,
            last_scan_at:      latestScan?.created_at ?? null,
            last_scan_domain:  latestScan?.domain     ?? null,
          },

          score_trend:       trendPoints,
          risk_distribution: riskDist,
          top_risks:         topRisks,

          changes: {
            score_current:  scoreCurrent,
            score_previous: scorePrevious,
            score_delta:    scoreDelta,
            score_direction: scoreDelta == null ? null
              : scoreDelta > 0 ? "up" : scoreDelta < 0 ? "down" : "flat",
            new_assets_7d:  newAssets7d,
          },

          remediation: {
            fix_now:  fixNow.map(r  => ({ title: r.title, reason: r.reason, domain: r.domain })),
            fix_next: fixNext.map(r => ({ title: r.title, reason: r.reason, domain: r.domain })),
            monitor:  monitor.slice(0, 10).map(r => ({ title: r.title, reason: r.reason, domain: r.domain })),
          },

          kpis: {
            verification_rate: verificationRate,
            average_score:     avgScore,
            critical_risks:    criticalCount,
            reports_generated: reportsRow.results[0]?.n ?? 0,
            assets_discovered: activeAssets,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

        // ── GET /api/workspaces/:id/activity ─────────────────────────────────────
    // Returns paginated audit events for a workspace.
    // Query params: ?limit=N (max 100) &event_type=X &offset=N
    const activityMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/activity$/);
    if (activityMatch && request.method === "GET") {
      const workspaceId = activityMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const limit     = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 100);
        const offset    = parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 100000);
        const eventType = url.searchParams.get("event_type") || null;

        let query, binds;
        if (eventType) {
          query = `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
                   FROM audit_events
                   WHERE workspace_id = ? AND event_type = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?`;
          binds = [workspaceId, eventType, limit, offset];
        } else {
          query = `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
                   FROM audit_events
                   WHERE workspace_id = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?`;
          binds = [workspaceId, limit, offset];
        }

        const result = await env.cybermeters_db.prepare(query).bind(...binds).all();
        const events = (result.results || []).map(r => ({
          ...r,
          metadata: r.metadata_json ? JSON.parse(r.metadata_json) : null,
          metadata_json: undefined,
        }));

        // Enrich with actor email from users table (best-effort JOIN avoided via batch)
        const userIds = [...new Set(events.map(e => e.user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const placeholders = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, name, email FROM users WHERE id IN (${placeholders})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { name: u.name, email: u.email };
        }

        const enriched = events.map(e => ({
          ...e,
          actor: e.user_id ? (userMap[e.user_id] ?? { name: null, email: null }) : null,
        }));

        return json({ events: enriched, limit, offset, count: enriched.length });
      } catch (e) {
        return serverError("api", e);
      }
    }



  return null;
}
