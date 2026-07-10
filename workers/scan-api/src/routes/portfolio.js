// ── Portfolio + workspace list routes ──
// Workspace scan-report PDF, the portfolio risk APIs (overview / workspaces /
// alerts / trends / risk) and workspace list/create endpoints. Extracted
// near-verbatim from index.js (router split, Phase 2 PR #15). Receives the
// per-request routeCtx from index.js; returns a Response when a route
// matches, or null so the main router continues.
import { getEffectivePlan, hasFeatureEntitlement } from "../engines/entitlements.js";
import { assemblePdf, buildPdfStreams } from "../engines/pdf.js";
import { getEntitlementUsage, getPlanLimits, planLimitExceeded } from "../engines/plan-usage.js";
import { computePortfolioRisk } from "../engines/portfolio-risk.js";
import { auditApiTokenSessionRouteDenied, createWorkspaceTrialSubscription } from "../engines/subscription-state.js";
import { createAuditEvent } from "../lib/events.js";
import { sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { createId, parseBoundedInteger } from "../lib/util.js";

export async function portfolioRoutes(rctx) {
  const { request, env, url, json, serverError, corsHeaders,
          requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds } = rctx;

    // ── Workspace Routes ──────────────────────────────────────────────────

    // GET /api/workspaces/:id/report — executive PDF report
    // Tested before the generic wsMatch so "/report" is never confused with a
    // domain ID.
    const reportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report$/);
    if (reportMatch && request.method === "GET") {
      const wsId = reportMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Workspace row
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces WHERE id = ?`)
          .bind(wsId).first();
      } catch { /* fall through */ }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // 2. Stats (4 parallel D1 queries)
      const [domRow, scanRow, avgRow, latestRow] = await Promise.all([
        env.cybermeters_db.prepare(
          `SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT COUNT(DISTINCT s.id) AS n
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed'`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT AVG(s.score) AS avg
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT s.id, s.domain, s.created_at
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed'
           ORDER BY s.created_at DESC LIMIT 1`
        ).bind(wsId).first(),
      ]).catch(() => [null, null, null, null]);

      const stats = {
        total_domains:        domRow?.n    ?? 0,
        total_scans:          scanRow?.n   ?? 0,
        cyber_score_average:  avgRow?.avg  ?? null,
        latest_scan:          latestRow    ?? null,
      };

      // 3. Domains enriched with latest scan
      let domains = [];
      try {
        const dr = await env.cybermeters_db.prepare(
          `SELECT d.id AS domain_id, d.domain,
                  s.id AS last_scan_id, s.score AS latest_score,
                  s.status AS latest_status, s.created_at AS last_scanned_at
           FROM workspace_domains wd
           JOIN domains d ON d.id = wd.domain_id
           LEFT JOIN scans s ON s.id = (
             SELECT id FROM scans WHERE domain_id = d.id ORDER BY created_at DESC LIMIT 1
           )
           WHERE wd.workspace_id = ?
           ORDER BY d.domain ASC`
        ).bind(wsId).all();
        domains = dr.results || [];
      } catch { /* tolerate */ }

      // 4. Top findings (ordered by severity then recency)
      let findings = [];
      try {
        const fr = await env.cybermeters_db.prepare(
          `SELECT f.title, f.severity, f.recommendation, s.domain
           FROM findings f
           JOIN scans s ON s.id = f.scan_id
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ?
           ORDER BY CASE f.severity
             WHEN 'critical' THEN 1 WHEN 'high' THEN 2
             WHEN 'medium'   THEN 3                ELSE 4 END,
             s.created_at DESC
           LIMIT 30`
        ).bind(wsId).all();
        findings = fr.results || [];
      } catch { /* tolerate */ }

      // 5. Recommendations
      let recommendations = [];
      try {
        const rr = await env.cybermeters_db.prepare(
          `SELECT r.title, r.priority, r.action, r.reason, s.domain
           FROM remediation_items r
           JOIN scans s ON s.id = r.scan_id
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ?
           ORDER BY r.priority ASC
           LIMIT 10`
        ).bind(wsId).all();
        recommendations = rr.results || [];
      } catch { /* tolerate */ }

      // 6. Historical trend — last 2 completed scans per domain
      let trend = [];
      try {
        const tr = await env.cybermeters_db.prepare(
          `SELECT s.domain, s.score AS current_score, s.created_at
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL
           ORDER BY s.created_at DESC
           LIMIT 20`
        ).bind(wsId).all();

        // Group by domain, keep newest two
        const byDomain = {};
        for (const row of (tr.results || [])) {
          if (!byDomain[row.domain]) byDomain[row.domain] = [];
          if (byDomain[row.domain].length < 2) byDomain[row.domain].push(row);
        }
        for (const [domain, rows] of Object.entries(byDomain)) {
          const cur  = rows[0];
          const prev = rows[1] ?? null;
          trend.push({
            domain,
            date: cur.created_at
              ? new Date((cur.created_at || "").replace(" ", "T") + "Z")
                  .toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
              : "—",
            current_score:  cur.current_score,
            previous_score: prev?.current_score ?? null,
            score_change:   prev != null ? cur.current_score - prev.current_score : null,
          });
        }
      } catch { /* tolerate */ }

      // 7. Build PDF
      try {
        const streams = buildPdfStreams({ workspace: ws, stats, domains, findings, recommendations, trend });
        const pdfText = assemblePdf(streams);
        const pdfBytes = new TextEncoder().encode(pdfText);
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
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd   ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
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
          // Average score across latest scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT AVG(s.score) AS avg_score
            FROM scans s
            JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
          `).bind(...workspaceIds).first(),
          // Workspace with most critical findings from latest scans
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            ),
            crit AS (
              SELECT s.domain_id, COUNT(*) AS cnt
              FROM findings f
              JOIN scans s ON f.scan_id = s.id
              JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
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

        const findingsBySev = {};
        for (const r of (findingsRes.status === 'fulfilled' ? (findingsRes.value?.results ?? []) : [])) {
          findingsBySev[r.severity] = r.cnt;
        }

        const avgRaw = avgScoreRes.status === 'fulfilled' ? avgScoreRes.value?.avg_score : null;
        const hrw    = highRiskRes.status === 'fulfilled'  ? highRiskRes.value : null;

        return json({
          total_workspaces:       wsRes.status === 'fulfilled'    ? (wsRes.value?.count    ?? 0) : 0,
          total_domains:          domRes.status === 'fulfilled'   ? (domRes.value?.count   ?? 0) : 0,
          total_assets:           assetRes.status === 'fulfilled' ? (assetRes.value?.count ?? 0) : 0,
          total_vendors:          vendorRes.status === 'fulfilled'? (vendorRes.value?.count?? 0) : 0,
          total_brand_candidates: brandRes.status === 'fulfilled' ? (brandRes.value?.count ?? 0) : 0,
          total_reports:          rptRes.status === 'fulfilled'   ? (rptRes.value?.count   ?? 0) : 0,
          critical_findings:      findingsBySev['critical'] ?? 0,
          high_findings:          findingsBySev['high']     ?? 0,
          new_assets_7d:          newAssetsRes.status === 'fulfilled' ? (newAssetsRes.value?.count ?? 0) : 0,
          new_reports_30d:        newRptsRes.status === 'fulfilled'   ? (newRptsRes.value?.count   ?? 0) : 0,
          average_score:          avgRaw != null ? Math.round(avgRaw) : null,
          highest_risk_workspace: hrw ? { id: hrw.id, name: hrw.name, critical_findings: hrw.total_crit } : null,
          verified_domains:       verifiedDomsRes.status === 'fulfilled'   ? (verifiedDomsRes.value?.count   ?? 0) : 0,
          unverified_domains:     unverifiedDomsRes.status === 'fulfilled' ? (unverifiedDomsRes.value?.count ?? 0) : 0,
          verification_failures:  failedVerifRes.status === 'fulfilled'    ? (failedVerifRes.value?.count    ?? 0) : 0,
          generated_at:           new Date().toISOString(),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ workspaces: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");
        const [
          wsRes, domCountRes, assetCountRes, vendorCountRes, brandCountRes,
          findingsRes, scanRes, rptRes,
        ] = await Promise.allSettled([
          db.prepare(`SELECT id, name, created_at FROM workspaces WHERE id IN (${wsIn}) ORDER BY created_at`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          // Critical + high per workspace from latest scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd   ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON s.domain_id = wd.domain_id
            WHERE f.severity IN ('critical','high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY wd.workspace_id, f.severity
          `).bind(...workspaceIds).all(),
          // Latest scan avg score + last_scan_at per workspace
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT wd.workspace_id,
                   AVG(s.score)      AS avg_score,
                   MAX(s.created_at) AS last_scan_at
            FROM scans s
            JOIN lpd              ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON s.domain_id = wd.domain_id
            WHERE s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            GROUP BY wd.workspace_id
          `).bind(...workspaceIds).all(),
          db.prepare(`
            SELECT workspace_id, MAX(generated_at) AS last_report_at
            FROM workspace_reports WHERE status='completed' AND deleted_at IS NULL AND workspace_id IN (${wsIn})
            GROUP BY workspace_id
          `).bind(...workspaceIds).all(),
        ]);

        const workspaces = wsRes.status === 'fulfilled' ? (wsRes.value?.results ?? []) : [];

        // Build lookup maps
        const domMap    = {};
        for (const r of (domCountRes.status    === 'fulfilled' ? (domCountRes.value?.results    ?? []) : [])) domMap[r.workspace_id]    = r.count;
        const assetMap  = {};
        for (const r of (assetCountRes.status  === 'fulfilled' ? (assetCountRes.value?.results  ?? []) : [])) assetMap[r.workspace_id]  = r.count;
        const vendorMap = {};
        for (const r of (vendorCountRes.status === 'fulfilled' ? (vendorCountRes.value?.results ?? []) : [])) vendorMap[r.workspace_id] = r.count;
        const brandMap  = {};
        for (const r of (brandCountRes.status  === 'fulfilled' ? (brandCountRes.value?.results  ?? []) : [])) brandMap[r.workspace_id]  = r.count;

        const findingsMap = {};
        for (const r of (findingsRes.status === 'fulfilled' ? (findingsRes.value?.results ?? []) : [])) {
          if (!findingsMap[r.workspace_id]) findingsMap[r.workspace_id] = { critical: 0, high: 0 };
          findingsMap[r.workspace_id][r.severity] = r.cnt;
        }

        const scanMap = {};
        for (const r of (scanRes.status === 'fulfilled' ? (scanRes.value?.results ?? []) : [])) scanMap[r.workspace_id] = r;

        const rptMap = {};
        for (const r of (rptRes.status === 'fulfilled' ? (rptRes.value?.results ?? []) : [])) rptMap[r.workspace_id] = r.last_report_at;

        const now = Date.now();
        const rows = workspaces.map(ws => {
          const scan    = scanMap[ws.id]    ?? {};
          const findings = findingsMap[ws.id] ?? {};
          const avgScore = scan.avg_score != null ? Math.round(scan.avg_score) : null;

          let risk_rating = null;
          if (avgScore !== null) {
            if      (avgScore >= 80) risk_rating = 'Low';
            else if (avgScore >= 60) risk_rating = 'Medium';
            else if (avgScore >= 40) risk_rating = 'High';
            else                     risk_rating = 'Critical';
          }

          const lastScanAt = scan.last_scan_at ?? null;
          const status = lastScanAt && (now - new Date(lastScanAt).getTime()) < 30 * 24 * 3600 * 1000
            ? 'active' : 'inactive';

          return {
            workspace_id:          ws.id,
            workspace_name:        ws.name,
            domains:               domMap[ws.id]    ?? 0,
            active_assets:         assetMap[ws.id]  ?? 0,
            vendors:               vendorMap[ws.id] ?? 0,
            brand_candidates:      brandMap[ws.id]  ?? 0,
            latest_score:          avgScore,
            security_posture_score: avgScore,
            risk_rating,
            critical_findings:     findings.critical ?? 0,
            high_findings:         findings.high     ?? 0,
            last_scan_at:          lastScanAt,
            last_report_at:        rptMap[ws.id] ?? null,
            status,
          };
        });

        // Sort: critical desc → high desc → score asc (lowest=most risk) → last_scan desc
        rows.sort((a, b) => {
          if (b.critical_findings !== a.critical_findings) return b.critical_findings - a.critical_findings;
          if (b.high_findings     !== a.high_findings)     return b.high_findings     - a.high_findings;
          const sa = a.latest_score ?? 999, sb = b.latest_score ?? 999;
          if (sa !== sb) return sa - sb;
          return (b.last_scan_at ?? '').localeCompare(a.last_scan_at ?? '');
        });

        return json({ workspaces: rows });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/alerts") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db    = env.cybermeters_db;
        const limit = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ alerts: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [eventsRes, brandRes, failedRptsRes] = await Promise.allSettled([
          // Asset events — deduplicated to one row per (workspace, event_type, hostname, day)
          // Uses MAX(created_at) to keep the most recent occurrence of each group.
          db.prepare(`
            SELECT ae.workspace_id, w.name AS workspace_name,
                   ae.event_type,
                   MAX(ae.severity)    AS severity,
                   ae.hostname,
                   ae.description,
                   MAX(ae.created_at) AS created_at
            FROM asset_events ae
            JOIN workspaces w ON w.id = ae.workspace_id
            WHERE ae.workspace_id IN (${wsIn})
            GROUP BY ae.workspace_id, ae.event_type, ae.hostname, date(ae.created_at)
            ORDER BY MAX(ae.created_at) DESC
            LIMIT ?
          `).bind(...workspaceIds, limit).all(),
          // Active brand risks that resolve via DNS
          db.prepare(`
            SELECT ba.workspace_id, w.name AS workspace_name,
                   ba.candidate_domain, ba.risk_level, ba.variant_type, ba.updated_at
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

        for (const r of (eventsRes.status === 'fulfilled' ? (eventsRes.value?.results ?? []) : [])) {
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
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'brand_risk',
            severity:       sev,
            title:          `Brand risk: ${r.candidate_domain}`,
            description:    `Active typosquat candidate (${r.variant_type ?? 'unknown variant'}) resolving via DNS`,
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
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ trend: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [scanTrendRes, findingsTrendRes, assetTrendRes] = await Promise.allSettled([
          // Score aggregates per day from all completed scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at)     AS day,
                   COUNT(DISTINCT s.id)   AS scans,
                   ROUND(AVG(s.score), 1) AS average_score,
                   MIN(s.score)           AS lowest_score,
                   MAX(s.score)           AS highest_score
            FROM scans s
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.created_at >= datetime('now', '-30 days')
              AND s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            GROUP BY date(s.created_at)
            ORDER BY day
          `).bind(...workspaceIds).all(),
          // Critical + high finding counts per day from scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at) AS day, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
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

        for (const r of (scanTrendRes.status === 'fulfilled' ? (scanTrendRes.value?.results ?? []) : [])) {
          dayMap[r.day] = {
            date:             r.day,
            scans:            r.scans,
            average_score:    r.average_score,
            lowest_score:     r.lowest_score,
            highest_score:    r.highest_score,
            critical_findings: 0,
            high_findings:    0,
            new_assets:       0,
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
        return json({ trend });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // GET /api/portfolio/risk — MSP Portfolio Risk Engine v1
    //   Aggregates BRS, supply chain, and vendor intelligence across all workspaces
    //   accessible to the authenticated user. Returns ranked workspace list,
    //   portfolio-level alerts, shared vendor dependencies, and executive summary.
    //   Persists a snapshot to portfolio_risk_snapshots (append-only).
    if (request.method === 'GET' && url.pathname === '/api/portfolio/risk') {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      {
        const plan = await getEffectivePlan(user.id, env);
        if (!hasFeatureEntitlement(plan, 'portfolio_monitoring')) {
          return json({ error: 'plan_feature_required', feature: 'portfolio_monitoring', required_plan: 'business', upgrade_url: '/billing' }, 403);
        }
      }
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const result = await computePortfolioRisk(user.id, workspaceIds, env);
        return json(result);
      } catch (err) {
        console.error('[portfolio/risk] error:', err);
        return json({ error: 'Internal server error' }, 500);
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
