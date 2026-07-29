// ── Workspace insight routes ──
// QA validation benchmark, workspace usage metering, workspace summary and
// workspace health endpoints. Extracted near-verbatim from index.js (router
// split, Phase 2 PR #17). Receives the per-request routeCtx from index.js;
// returns a Response when a route matches, or null so the main router
// continues.
import { runDnsModule } from "../engines/dns-scan.js";
import { runEmailModule } from "../engines/email-scan.js";
import { getEffectivePlan } from "../engines/entitlements.js";
import { runHeadersModule } from "../engines/headers-scan.js";
import { LATEST_COMPLETED_SCAN_SCOPE } from "../engines/report-queries.js";
import { getMonthStart, getPlanLimits, getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { ENTERPRISE_BENCHMARK, ENTERPRISE_DOMAINS } from "../engines/scoring-config.js";
import { computeScore, isEmailApplicable } from "../engines/scoring.js";
import { runSslModule } from "../engines/ssl-scan.js";
import { createAuditEvent } from "../lib/events.js";
import {
  projectPhase5ScanRowsForCustomer,
  resolvePhase5CustomerAggregate,
} from "../engines/phase5-evidence.js";

export async function workspaceInsightRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;

    // ── GET /api/validation/benchmark — QA-only, no frontend ────────────
    //
    // Enterprise Validation Dataset — expected behaviour for mature domains.
    // Used as regression check: if header or email scoring findings appear
    // on these domains, validation_status = "regression_detected".
    //
    // Subrequest budget: headers module may use 2 subrequests (GET + HEAD
    // fallback) when bot protection is detected, so limit to 1 domain per call.
    //   1 domain × (5 DNS + 3 SSL + 2 headers + 15 email) ≈ 25 subrequests.
    //
    // Usage:
    //   GET /api/validation/benchmark              → test google.com (default)
    //   GET /api/validation/benchmark?domain=X     → test domain X
    //   GET /api/validation/benchmark?all=1        → meta: list all benchmark domains

    // ENTERPRISE_BENCHMARK and ENTERPRISE_DOMAINS are module-level constants
    // (defined near the top of this file, after SECURITY_HEADERS).

    if (url.pathname === "/api/validation/benchmark" && request.method === "GET") {
      // QA-only diagnostic that runs live scan modules against an arbitrary
      // domain — authenticated + rate-limited so anonymous traffic can't use
      // it to burn Worker CPU/subrequests (it was previously fully public).
      const bmUser = await requireAuth(request, env);
      if (!bmUser) return json({ error: "Unauthorized" }, 401);
      const bmRl = await consumeApiRateLimit(
        env, [{ scope: "user", scope_id: bmUser.id }], "validation_benchmark", 10, 3600
      );
      if (bmRl) return json(bmRl.body, bmRl.status);
      try {
        // ?all=1 → return the benchmark domain list without running scans
        if (url.searchParams.get("all") === "1") {
          return json({ benchmark_domains: ENTERPRISE_BENCHMARK, note: "Use ?domain=X to test a specific domain." });
        }

        const targetDomain = url.searchParams.get("domain") ?? "google.com";
        const baseline     = ENTERPRISE_BENCHMARK.find(b => b.domain === targetDomain) ?? null;

        // Run core modules — parallel, within subrequest budget
        const [dnsR, sslR, headersR, emailR] = await Promise.allSettled([
          runDnsModule(targetDomain),
          runSslModule(targetDomain),
          runHeadersModule(targetDomain),
          runEmailModule(targetDomain),
        ]);

        const mods = {
          dns:            dnsR.status     === "fulfilled" ? dnsR.value     : { error: "module failed" },
          ssl:            sslR.status     === "fulfilled" ? sslR.value     : { error: "module failed" },
          headers:        headersR.status === "fulfilled" ? headersR.value : { error: "module failed" },
          email_security: emailR.status   === "fulfilled" ? emailR.value   : { error: "module failed" },
          brand_monitoring: null, // opt-out: brand findings not applicable to lightweight public scan
        };

        const { score, risk_level, findings } = computeScore(mods, targetDomain);

        const scoringFindings  = findings.filter(f => f.score_impact < 0);
        const headerFindings   = scoringFindings.filter(f => f.module === "headers");
        const emailFindings    = scoringFindings.filter(f => f.module === "email_security");
        const infoFindings     = findings.filter(f => f.score_impact === 0);
        const emailApp         = isEmailApplicable(targetDomain, mods.dns);

        // ── Regression check ─────────────────────────────────────────────
        const regressionViolations = [];
        if (baseline) {
          if (headerFindings.length > baseline.max_header_findings) {
            regressionViolations.push(
              `header_findings: got ${headerFindings.length}, max allowed ${baseline.max_header_findings}`
            );
          }
          if (emailFindings.length > baseline.max_email_findings) {
            regressionViolations.push(
              `email_findings: got ${emailFindings.length}, max allowed ${baseline.max_email_findings}`
            );
          }
          // Only fail the redirect check when:
          //   • the redirect chain was observable (not blocked by firewall/bot protection)
          //   • the scoring engine did NOT downgrade the finding to info/low-confidence
          //     (which happens for enterprise edge uncertain domains where the HTTP probe
          //     returned a non-redirecting response but HTTPS headers probed successfully)
          //   • validation_uncertain is false
          // If any of these conditions apply, we cannot conclude the redirect is missing.
          const redirectValidated   = mods.ssl?.http_redirect_chain?.http_redirect_validated !== false;
          const redirectDowngraded  = findings.some(f =>
            f.id           === "ssl_no_http_redirect" &&
            f.severity     === "info"                 &&
            f.confidence   === "low"                  &&
            Number(f.score_impact ?? 0) === 0
          );
          const validationUncertain = !!mods.headers?.validation_uncertain;
          if (
            baseline.expect_https_redirect &&
            redirectValidated              &&
            !mods.ssl?.http_redirects_to_https &&
            !redirectDowngraded            &&
            !validationUncertain
          ) {
            regressionViolations.push("expected http_redirects_to_https = true (chain was observable)");
          }
        }

        const passed             = regressionViolations.length === 0;
        const regressionDetected = !passed;

        return json({
          domain:                     targetDomain,
          score,
          risk_level,
          passed,
          regression_detected:        regressionDetected,
          regression_violations:      regressionViolations,
          baseline:                   baseline ?? "no baseline — custom domain",
          email_applicable:           emailApp.applicable,
          email_applicability_reason: emailApp.reason ?? null,
          http_redirects_to_https:    mods.ssl?.http_redirects_to_https ?? null,
          http_redirect_chain:        mods.ssl?.http_redirect_chain ?? null,
          http_redirect_validated:    mods.ssl?.http_redirect_chain?.http_redirect_validated ?? null,
          headers_final_https:        mods.headers?.final_https ?? null,
          headers_status_code:        mods.headers?.status_code ?? null,
          validation_uncertain:       mods.headers?.validation_uncertain ?? false,
          bot_protection_signals:     mods.headers?.bot_protection_signals ?? [],
          raw_capture:                mods.headers?.raw_capture ?? null,
          finding_count:              scoringFindings.length,
          header_findings:            headerFindings.length,   // renamed from header_finding_count
          email_findings:             emailFindings.length,    // renamed from email_finding_count
          info_count:                 infoFindings.length,
          findings: findings.map(f => ({
            id:           f.id,
            module:       f.module,
            severity:     f.severity,
            confidence:   f.confidence ?? null,
            title:        f.title,
            score_impact: f.score_impact,
          })),
          note: "One domain per call (subrequest budget). Use ?domain=X to target a specific domain.",
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

	    // ── GET /api/workspaces/:id/usage ────────────────────────────────────────
	    const workspaceUsageMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/usage$/);
	    if (workspaceUsageMatch && request.method === "GET") {
	      const workspaceId = workspaceUsageMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const periodStart = getMonthStart();
	        const billingUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
	        const plan = await getEffectivePlan(billingUserId, env);
	        const limits = getPlanLimits(plan);
	        const [
	          scansUsed,
	          scansCompleted,
	          reportsGenerated,
	          scheduledReportsGenerated,
	          reportRuns,
	          reportCount,
	          activeAssets,
	        ] = await Promise.all([
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(DISTINCT s.id) AS n
	             FROM scans s
	             LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
	             WHERE s.created_at >= ?
	               AND (s.workspace_id = ? OR (s.workspace_id IS NULL AND wd.workspace_id = ?))`
	          ).bind(periodStart, workspaceId, workspaceId).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(DISTINCT s.id) AS n
	             FROM scans s
	             LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
	             WHERE s.status = 'completed' AND s.created_at >= ?
	               AND (s.workspace_id = ? OR (s.workspace_id IS NULL AND wd.workspace_id = ?))`
	          ).bind(periodStart, workspaceId, workspaceId).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_reports
	             WHERE workspace_id = ? AND status = 'completed'
	               AND deleted_at IS NULL AND created_at >= ?`
	          ).bind(workspaceId, periodStart).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_reports
	             WHERE workspace_id = ? AND status = 'completed'
	               AND deleted_at IS NULL AND report_type IN ('weekly_executive', 'monthly_executive')
	               AND created_at >= ?`
	          ).bind(workspaceId, periodStart).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM report_schedule_runs
	             WHERE workspace_id = ? AND created_at >= ?`
	          ).bind(workspaceId, periodStart).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_reports
	             WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL`
	          ).bind(workspaceId).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_assets
	             WHERE workspace_id = ? AND status = 'active'`
	          ).bind(workspaceId).first(),
	        ]);
	        const completedReportCount = Number(reportCount?.n ?? 0);
	        const estimatedReportBytes = 250_000;
	        const storageBytes = completedReportCount * estimatedReportBytes;

	        createAuditEvent(env, {
	          workspace_id: workspaceId,
	          user_id: user.id,
	          event_type: "usage_viewed",
	          entity_type: "workspace",
	          entity_id: workspaceId,
	          description: "Workspace usage metering viewed",
	          metadata: { period_start: periodStart },
	        }).catch(() => {});

	        return json({
	          workspace_id: workspaceId,
	          plan,
	          period_start: periodStart,
	          current_period: {
	            scans_used: Number(scansUsed?.n ?? 0),
	            scans_completed: Number(scansCompleted?.n ?? 0),
	            reports_generated: Number(reportsGenerated?.n ?? 0),
	            scheduled_reports_generated: Number(scheduledReportsGenerated?.n ?? 0),
	            report_schedule_runs: Number(reportRuns?.n ?? 0),
	            storage_bytes: storageBytes,
	            storage_estimated: true,
	            active_assets: Number(activeAssets?.n ?? 0),
	            workspace_report_count: completedReportCount,
	          },
	          limits,
	        });
	      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── GET /api/workspaces/:id/summary ──────────────────────────────────────
	    const summaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/summary$/);
    if (summaryMatch && request.method === "GET") {
      const workspaceId = summaryMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id, name FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        const [
          domainsResult,
          assetsResult,
          vendorsResult,
          scoreResult,
          findingsResult,
          lastScanResult,
          lastReportResult,
          reportsCountResult,
        ] = await Promise.allSettled([
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          // Average current score — canonical latest-COMPLETE-scan-per-domain scope
          // (deterministic id tie-break), so a tied timestamp cannot double-count a
          // domain and a partial scan never contributes. Same constant the
          // dashboard/report/PDF use.
          env.cybermeters_db
            .prepare(`SELECT s.id, s.status, s.score, s.rating, s.scan_quality, s.created_at
                      FROM scans s WHERE ${LATEST_COMPLETED_SCAN_SCOPE}`)
            .bind(workspaceId)
            .all(),
          // Current critical/high finding counts — same canonical scope, so the same
          // finding across several scans is counted once.
          env.cybermeters_db
            .prepare(`
              SELECT
                SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings,
                SUM(CASE WHEN f.severity = 'high'     THEN 1 ELSE 0 END) AS high_findings
              FROM findings f
              JOIN scans s ON s.id = f.scan_id
              WHERE ${LATEST_COMPLETED_SCAN_SCOPE}
            `)
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(created_at) AS last_scan_at FROM scans WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(generated_at) AS last_report_at FROM workspace_reports WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_reports WHERE workspace_id = ? AND deleted_at IS NULL")
            .bind(workspaceId)
            .first(),
        ]);

        const v = (r) => (r.status === "fulfilled" ? r.value : null);
        const customerScoreRows = await projectPhase5ScanRowsForCustomer(
          env,
          v(scoreResult)?.results ?? [],
        );
        const customerAggregate =
          resolvePhase5CustomerAggregate(customerScoreRows);
        const latestScore = customerAggregate.score == null
          ? null
          : Math.round(customerAggregate.score);

        return json({
          workspace_id:      ws.id,
          workspace_name:    ws.name,
          domains:           v(domainsResult)?.cnt          ?? 0,
          active_assets:     v(assetsResult)?.cnt           ?? 0,
          vendors:           v(vendorsResult)?.cnt          ?? 0,
          latest_score:      latestScore,
          score_evidence_coverage: customerAggregate.evidence_coverage,
          critical_findings: v(findingsResult)?.critical_findings ?? 0,
          high_findings:     v(findingsResult)?.high_findings     ?? 0,
          last_scan_at:      v(lastScanResult)?.last_scan_at      ?? null,
          last_report_at:    v(lastReportResult)?.last_report_at  ?? null,
          reports_count:     v(reportsCountResult)?.cnt           ?? 0,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/health ────────────────────────────────────────
    const healthMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/health$/);
    if (healthMatch && request.method === "GET") {
      const workspaceId = healthMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        const [domR, assetR, reportR, scanR] = await Promise.allSettled([
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_reports WHERE workspace_id = ? AND deleted_at IS NULL")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(created_at) AS last_scan_at FROM scans WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
        ]);

        const v = (r) => (r.status === "fulfilled" ? r.value : null);

        const domains_monitored  = v(domR)?.cnt    ?? 0;
        const assets_discovered  = v(assetR)?.cnt  ?? 0;
        const reports_generated  = v(reportR)?.cnt ?? 0;
        const lastScanAt         = v(scanR)?.last_scan_at ?? null;

        let latest_scan_age_hours = null;
        if (lastScanAt) {
          const ageMs = Date.now() - new Date(lastScanAt.includes("T") ? lastScanAt : lastScanAt + "Z").getTime();
          latest_scan_age_hours = Math.round(ageMs / 3_600_000);
        }

        // workspace_status
        let workspace_status;
        if (domains_monitored === 0) {
          workspace_status = "no_domains";
        } else if (!lastScanAt) {
          workspace_status = "no_scans";
        } else if (latest_scan_age_hours !== null && latest_scan_age_hours > 168) {
          workspace_status = "stale"; // older than 7 days
        } else {
          workspace_status = "active";
        }

        // monitoring_health
        let monitoring_health;
        if (workspace_status === "no_domains" || workspace_status === "no_scans") {
          monitoring_health = "stale";
        } else if (latest_scan_age_hours !== null && latest_scan_age_hours > 72) {
          monitoring_health = "warning";
        } else {
          monitoring_health = "healthy";
        }

        return json({
          workspace_status,
          domains_monitored,
          assets_discovered,
          reports_generated,
          latest_scan_age_hours,
          latest_report_age_hours: null, // reserved — not critical path
          monitoring_health,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }


  return null;
}
