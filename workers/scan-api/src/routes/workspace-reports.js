// ── Workspace report routes ──
// Report generation/listing/download/delete + scheduled-report CRUD endpoints.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #5).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { calculateNextRun, checkReportLimit, computeScheduledReportNextRunAt, generateWorkspaceExecutiveReport, getEntitlementUsage, getPlanLimits, getPlanRetentionDays, getReportExpiresAt, getReportRetentionPolicyForWorkspace, getWorkspaceReportStorageMetrics, getWorkspaceRetentionSettings, normalizeReportScheduleFrequency, normalizeReportScheduleRecipients, planLimitExceeded } from "../engines/plan-usage.js";
import { getEffectivePlan, normalizePlan } from "../engines/entitlements.js";
import { createAuditEvent } from "../lib/events.js";
import { createId, pageMeta, paginationParams } from "../lib/util.js";

export async function workspaceReportsRoutes(rctx) {
  const { request, env, url, json, serverError, corsHeaders,
          requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId } = rctx;

    // ── POST /api/workspaces/:id/reports/generate ────────────────────────────
	    // Generates a new executive PDF report and stores it in R2 + workspace_reports.
    // Body: { "report_type": "manual" | "weekly_executive" | "monthly_executive" | "scan_snapshot" }
    //       Optional: { "report_period": "...", "scan_id": "..." }
    const rptGenMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/generate$/);
    if (rptGenMatch && request.method === 'POST') {
      const wsId = rptGenMatch[1];
      // RBAC: admin or above required to generate reports — auth is mandatory
      const rptUser = await requireAuth(request, env);
      if (!rptUser) return json({ error: "Unauthorized" }, 401);
      const rptAccess = await requireWorkspaceRole(rptUser, wsId, "report:generate", env);
      if (!rptAccess) return json({ error: "Forbidden — admin role required to generate reports" }, 403);
      try {
        // ── Enforce monthly report quota ────────────────────────────────────
        const reportLimitError = await checkReportLimit(rptUser, wsId, env);
        if (reportLimitError) return json(reportLimitError.body, reportLimitError.status);

        let body = {};
        try { body = await request.json(); } catch { /* body is optional */ }
        const VALID_TYPES = ['manual', 'scan_snapshot', 'weekly_executive', 'monthly_executive', 'quarterly_executive'];
        const report_type = VALID_TYPES.includes(body.report_type) ? body.report_type : 'manual';
        const row = await generateWorkspaceExecutiveReport(wsId, env, {
          report_type,
          report_period: body.report_period ?? null,
          scan_id:       body.scan_id       ?? null,
        });
        return json({ report: row }, 201);
      } catch (err) {
        return serverError("api", err);
      }
    }

	    // ── GET /api/workspaces/:id/report-retention ────────────────────────────
	    const storageMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/storage$/);
	    if (storageMatch && request.method === "GET") {
	      const wsId = storageMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        return json(await getWorkspaceReportStorageMetrics(wsId, env));
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const retentionMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/retention$/);
	    if (retentionMatch && request.method === "GET") {
	      const wsId = retentionMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const retention = await getWorkspaceRetentionSettings(wsId, env);
	        const storage = await getWorkspaceReportStorageMetrics(wsId, env);
	        return json({ ...retention, storage });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    if (retentionMatch && request.method === "PUT") {
	      const wsId = retentionMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage retention" }, 403);
	      try {
	        let body = {};
	        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
	        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
	        const plan = await getEffectivePlan(ownerId, env);
	        const planDefaultDays = getPlanRetentionDays(plan);
	        const requestedDays = body.retention_days === null ? null : Number(body.retention_days);
	        const allowedDays = [30, 90, 365, 730];
	        if (requestedDays !== null && (!Number.isFinite(requestedDays) || !allowedDays.includes(requestedDays))) {
	          return json({ error: "retention_days must be one of 30, 90, 365, 730, or null for enterprise." }, 400);
	        }
	        if (requestedDays === null && normalizePlan(plan) !== "enterprise") {
	          return json({ error: "Unlimited retention requires enterprise plan." }, 403);
	        }
	        if (planDefaultDays !== null && requestedDays !== null && requestedDays > planDefaultDays) {
	          return json({ error: "retention_days exceeds current plan entitlement.", max_retention_days: planDefaultDays }, 403);
	        }
	        const autoCleanup = body.auto_cleanup === false ? 0 : 1;
	        const now = new Date().toISOString();
	        await env.cybermeters_db
	          .prepare(
	            `INSERT INTO workspace_retention_settings
	               (workspace_id, retention_days, auto_cleanup, updated_by, created_at, updated_at)
	             VALUES (?, ?, ?, ?, ?, ?)
	             ON CONFLICT(workspace_id) DO UPDATE SET
	               retention_days = excluded.retention_days,
	               auto_cleanup = excluded.auto_cleanup,
	               updated_by = excluded.updated_by,
	               updated_at = excluded.updated_at`
	          )
	          .bind(wsId, requestedDays, autoCleanup, user.id, now, now)
	          .run();
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "retention_policy_updated",
	          entity_type: "workspace",
	          entity_id: wsId,
	          description: "Workspace retention settings updated",
	          metadata: { retention_days: requestedDays, auto_cleanup: autoCleanup === 1 },
	        }).catch(() => {});
	        return json(await getWorkspaceRetentionSettings(wsId, env));
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const rptRetentionMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-retention$/);
    if (rptRetentionMatch && request.method === 'GET') {
      const wsId = rptRetentionMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const retentionPolicy = await getReportRetentionPolicyForWorkspace(wsId, env);
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, status, retention_policy, generated_at, created_at, report_key
             FROM workspace_reports
             WHERE workspace_id = ? AND deleted_at IS NULL`
          )
          .bind(wsId)
          .all();

        const nowMs = Date.now();
        const in30Ms = nowMs + 30 * 86_400_000;
        const in90Ms = nowMs + 90 * 86_400_000;
        let expiring30 = 0;
        let expiring90 = 0;

        for (const report of (rows.results || [])) {
          const effectiveAt = report.generated_at || report.created_at;
          const expiresAt = getReportExpiresAt(report.retention_policy || retentionPolicy, effectiveAt);
          if (!expiresAt) continue;
          const expiresMs = new Date(expiresAt).getTime();
          if (Number.isNaN(expiresMs) || expiresMs <= nowMs) continue;
          if (expiresMs <= in30Ms) expiring30 += 1;
          if (expiresMs <= in90Ms) expiring90 += 1;
        }

        const activeReports = rows.results || [];
        return json({
          total_reports: activeReports.length,
          storage_reports: activeReports.filter((r) => r.report_key && r.status === "completed").length,
          reports_expiring_30_days: expiring30,
          reports_expiring_90_days: expiring90,
          retention_policy: retentionPolicy,
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/reports ──────────────────────────────────────
    // List archived reports for a workspace.
    // Query params: ?report_type=  ?status=
    const rptListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports$/);
    if (rptListMatch && request.method === 'GET') {
      const wsId         = rptListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      const typeFilter   = url.searchParams.get('report_type');
      const statusFilter = url.searchParams.get('status');
      try {
        const { limit, offset } = paginationParams(url, { defaultLimit: 100, maxLimit: 100 });
        let sql    = `SELECT id, workspace_id, report_type, report_period,
                             status, generated_at, created_at, metadata_json, retention_policy
                      FROM workspace_reports WHERE workspace_id = ? AND deleted_at IS NULL`;
        const params = [wsId];
        if (typeFilter)   { sql += ' AND report_type = ?'; params.push(typeFilter); }
        if (statusFilter) { sql += ' AND status = ?';      params.push(statusFilter); }
        sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        const { results } = await env.cybermeters_db.prepare(sql).bind(...params).all();
        const reports = results ?? [];
        return json({ reports, pagination: pageMeta({ items: reports, limit, offset }) });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/report-snapshots ─────────────────────────────
    // History of canonical M5.c reporting snapshots (D1 metadata only — the
    // snapshot body is served by GET /api/scans/:id/snapshot). Completed rows
    // by default; ?status= widens to building/failed for operational visibility.
    // superseded_by is DERIVED on read from the append-only supersession chain —
    // historical rows are never edited.
    const snapListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-snapshots$/);
    if (snapListMatch && request.method === 'GET') {
      const wsId = snapListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      const statusFilter = url.searchParams.get('status');
      try {
        const { limit, offset } = paginationParams(url, { defaultLimit: 100, maxLimit: 100 });
        // Scalar subquery, not a JOIN: if the supersession chain ever forks
        // (two concurrent same-domain builds sharing a predecessor), a JOIN
        // would fan the superseded row out into duplicate list entries and
        // break pagination. The subquery keeps one row per snapshot and picks
        // the earliest completed successor deterministically.
        let sql = `SELECT s.id, s.workspace_id, s.domain_id, s.scan_id, s.status,
                          s.snapshot_schema_version, s.resolver_version, s.scan_quality,
                          s.assessed_at, s.supersedes_snapshot_id, s.created_at, s.completed_at,
                          (SELECT n.id FROM scan_report_snapshots n
                            WHERE n.supersedes_snapshot_id = s.id
                              AND n.status = 'completed'
                              AND n.workspace_id = s.workspace_id
                            ORDER BY n.assessed_at ASC LIMIT 1) AS superseded_by
                   FROM scan_report_snapshots s
                   WHERE s.workspace_id = ?`;
        const params = [wsId];
        if (statusFilter) { sql += ' AND s.status = ?'; params.push(statusFilter); }
        else              { sql += ` AND s.status = 'completed'`; }
        sql += ' ORDER BY s.assessed_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        const { results } = await env.cybermeters_db.prepare(sql).bind(...params).all();
        const snapshots = results ?? [];
        return json({ snapshots, pagination: pageMeta({ items: snapshots, limit, offset }) });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── DELETE /api/workspaces/:id/reports/:reportId ─────────────────────────
    // Permanently deletes the archived PDF from R2 and soft-deletes the D1 row.
    const rptDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)$/);
    if (rptDeleteMatch && request.method === 'DELETE') {
      const wsId     = rptDeleteMatch[1];
      const reportId = rptDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "report:delete", env);
      if (!access) return json({ error: "Forbidden — admin role required to delete reports" }, 403);

      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT id, workspace_id, report_type, report_period, report_key, status,
                  retention_policy
           FROM workspace_reports
           WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(reportId, wsId).first();
        if (!row) return json({ error: 'Report not found' }, 404);

        await env.cybermeters_reports.delete(row.report_key);

        const deletedAt = new Date().toISOString();
        const del = await env.cybermeters_db.prepare(
          `UPDATE workspace_reports
           SET deleted_at = ?, deleted_by = ?
           WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(deletedAt, user.id, reportId, wsId).run();
        if (del.meta?.changes === 0) return json({ error: 'Report not found' }, 404);

        await createAuditEvent(env, {
          workspace_id: wsId,
          user_id:      user.id,
          event_type:   "report_deleted",
          entity_type:  "report",
          entity_id:    reportId,
          description:  `Executive report deleted (${row.report_type})`,
          metadata:     {
            report_id: reportId,
            workspace_id: wsId,
            user_id: user.id,
            report_type: row.report_type,
            report_period: row.report_period,
            report_key: row.report_key,
            retention_policy: row.retention_policy,
            deletion_reason: "user_deleted",
          },
        });

        return json({ success: true, deleted_id: reportId });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/reports/:reportId/download ────────────────────
    // Stream the PDF from R2.  Must be tested before the bare /:reportId route.
    const rptDownloadMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)\/download$/);
    if (rptDownloadMatch && request.method === 'GET') {
      const wsId     = rptDownloadMatch[1];
      const reportId = rptDownloadMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT report_key, report_type, report_period, status
           FROM workspace_reports WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(reportId, wsId).first();
        if (!row)                       return json({ error: 'Report not found' }, 404);
        if (row.status !== 'completed') return json({ error: `Report not ready: ${row.status}` }, 409);

        const obj = await env.cybermeters_reports.get(row.report_key);
        if (!obj) return json({ error: 'Report file missing from storage' }, 404);

        await createAuditEvent(env, {
          workspace_id: wsId,
          user_id:      user.id,
          event_type:   "report_downloaded",
          entity_type:  "report",
          entity_id:    reportId,
          description:  `Executive report downloaded (${row.report_type})`,
          metadata:     { report_id: reportId, report_type: row.report_type, report_period: row.report_period },
        });

        const slug     = `${row.report_type}-${row.report_period ?? reportId}`;
        const filename = `cybermeters-report-${slug}.pdf`;
        return new Response(obj.body, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type':        'application/pdf',
            'Content-Disposition': `attachment; filename="${filename}"`,
          },
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/reports/:reportId ─────────────────────────────
    // Fetch metadata for a single report.
    const rptGetMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)$/);
    if (rptGetMatch && request.method === 'GET') {
      const wsId     = rptGetMatch[1];
      const reportId = rptGetMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT id, workspace_id, report_type, report_period,
                  status, generated_at, created_at, metadata_json, retention_policy
           FROM workspace_reports WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(reportId, wsId).first();
        if (!row) return json({ error: 'Report not found' }, 404);
        return json({ report: row });
      } catch (err) {
        return serverError("api", err);
      }
	    }
	
	    // ── Executive Report Scheduling v1 ──────────────────────────────────
	    const reportScheduleRunsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-schedule-runs$/);
	    if (reportScheduleRunsMatch && request.method === "GET") {
	      const wsId = reportScheduleRunsMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const { results } = await env.cybermeters_db
	          .prepare(
	            `SELECT id, schedule_id, workspace_id, started_at, completed_at,
	                    status, report_id, error_message, created_at
	             FROM report_schedule_runs
	             WHERE workspace_id = ?
	             ORDER BY created_at DESC
	             LIMIT 100`
	          )
	          .bind(wsId)
	          .all();
	        return json({ runs: results || [] });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const reportScheduleListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-schedules$/);
	    if (reportScheduleListMatch && request.method === "GET") {
	      const wsId = reportScheduleListMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const { results } = await env.cybermeters_db
	          .prepare(
	            `SELECT id, workspace_id, created_by, frequency, enabled, email_recipients,
	                    last_run_at, next_run_at, created_at, updated_at
		             FROM report_schedules
		             WHERE workspace_id = ?
		             ORDER BY created_at DESC
		             LIMIT 100`
	          )
	          .bind(wsId)
	          .all();
	        const schedules = (results || []).map((row) => ({
	          ...row,
	          enabled: row.enabled === 1,
	          email_recipients: (() => { try { return JSON.parse(row.email_recipients || "[]"); } catch { return []; } })(),
	        }));
	        return json({ schedules });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    if (reportScheduleListMatch && request.method === "POST") {
	      const wsId = reportScheduleListMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
	      try {
	        let body = {};
	        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
	        const frequency = normalizeReportScheduleFrequency(body.frequency);
	        if (!frequency) return json({ error: "Invalid frequency. Use weekly or monthly." }, 400);
	        const recipients = normalizeReportScheduleRecipients(body.email_recipients);
	        if (!recipients) return json({ error: "email_recipients must contain 1-20 valid email addresses." }, 400);
	        const now = new Date().toISOString();
	        const scheduleId = createId("rs");
	        const nextRunAt = calculateNextRun(frequency, now);
	        await env.cybermeters_db
	          .prepare(
	            `INSERT INTO report_schedules
	               (id, workspace_id, created_by, frequency, enabled, email_recipients,
	                next_run_at, created_at, updated_at)
	             VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)`
	          )
	          .bind(scheduleId, wsId, user.id, frequency, JSON.stringify(recipients), nextRunAt, now, now)
	          .run();
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "report_schedule_created",
	          entity_type: "report_schedule",
	          entity_id: scheduleId,
	          description: `Executive report schedule created (${frequency})`,
	          metadata: { frequency, recipient_count: recipients.length, next_run_at: nextRunAt },
	        });
	        return json({
	          schedule: { id: scheduleId, workspace_id: wsId, created_by: user.id, frequency, enabled: true, email_recipients: recipients, last_run_at: null, next_run_at: nextRunAt, created_at: now, updated_at: now },
	        }, 201);
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const reportScheduleItemMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-schedules\/([^/]+)$/);
	    if (reportScheduleItemMatch && request.method === "PUT") {
	      const wsId = reportScheduleItemMatch[1];
	      const scheduleId = reportScheduleItemMatch[2];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
	      try {
	        const existing = await env.cybermeters_db
	          .prepare("SELECT id FROM report_schedules WHERE id = ? AND workspace_id = ? LIMIT 1")
	          .bind(scheduleId, wsId)
	          .first();
	        if (!existing) return json({ error: "Schedule not found" }, 404);
	        let body = {};
	        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
	        const frequency = normalizeReportScheduleFrequency(body.frequency);
	        if (!frequency) return json({ error: "Invalid frequency. Use weekly or monthly." }, 400);
	        const recipients = normalizeReportScheduleRecipients(body.email_recipients);
	        if (!recipients) return json({ error: "email_recipients must contain 1-20 valid email addresses." }, 400);
	        const enabled = body.enabled === false ? 0 : 1;
	        const now = new Date().toISOString();
	        const nextRunAt = calculateNextRun(frequency, now);
	        await env.cybermeters_db
	          .prepare(
	            `UPDATE report_schedules
	             SET frequency = ?, enabled = ?, email_recipients = ?, next_run_at = ?, updated_at = ?
	             WHERE id = ? AND workspace_id = ?`
	          )
	          .bind(frequency, enabled, JSON.stringify(recipients), nextRunAt, now, scheduleId, wsId)
	          .run();
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "report_schedule_updated",
	          entity_type: "report_schedule",
	          entity_id: scheduleId,
	          description: `Executive report schedule updated (${frequency})`,
	          metadata: { frequency, enabled: enabled === 1, recipient_count: recipients.length, next_run_at: nextRunAt },
	        });
	        return json({ updated: true, schedule: { id: scheduleId, workspace_id: wsId, frequency, enabled: enabled === 1, email_recipients: recipients, next_run_at: nextRunAt, updated_at: now } });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    if (reportScheduleItemMatch && request.method === "DELETE") {
	      const wsId = reportScheduleItemMatch[1];
	      const scheduleId = reportScheduleItemMatch[2];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
	      try {
	        const now = new Date().toISOString();
	        const result = await env.cybermeters_db
	          .prepare("UPDATE report_schedules SET enabled = 0, updated_at = ? WHERE id = ? AND workspace_id = ?")
	          .bind(now, scheduleId, wsId)
	          .run();
	        if ((result.meta?.changes ?? 0) === 0) return json({ error: "Schedule not found" }, 404);
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "report_schedule_deleted",
	          entity_type: "report_schedule",
	          entity_id: scheduleId,
	          description: "Executive report schedule disabled",
	          metadata: { schedule_id: scheduleId },
	        });
	        return json({ deleted: true, enabled: false });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    // ── GET /api/workspaces/:id/scheduled-reports ────────────────────────────
	    // List all scheduled report configs for a workspace.
	    const srListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scheduled-reports$/);
    if (srListMatch && request.method === 'GET') {
      const wsId = srListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const { results } = await env.cybermeters_db
          .prepare(
            `SELECT id, workspace_id, report_type, frequency, enabled, last_run_at, next_run_at, created_at
             FROM scheduled_reports
             WHERE workspace_id = ?
             ORDER BY created_at DESC`
          )
          .bind(wsId)
          .all();
        return json({ scheduled_reports: results ?? [] });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── POST /api/workspaces/:id/scheduled-reports ────────────────────────────
    // Create a new scheduled report. Body: { report_type, frequency }
    // Frequencies: weekly | monthly | quarterly
    if (srListMatch && request.method === 'POST') {
      const wsId = srListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* optional */ }

        const VALID_TYPES = ['weekly_executive', 'monthly_executive', 'quarterly_executive', 'manual'];
        const VALID_FREQS = ['weekly', 'monthly', 'quarterly'];
        const report_type = VALID_TYPES.includes(body.report_type) ? body.report_type : 'monthly_executive';
        const frequency   = VALID_FREQS.includes(body.frequency)   ? body.frequency   : 'monthly';

        // Prevent duplicate active schedules for same type+frequency
        const existing = await env.cybermeters_db
          .prepare(
            `SELECT id FROM scheduled_reports
             WHERE workspace_id = ? AND report_type = ? AND frequency = ? AND enabled = 1 LIMIT 1`
          )
          .bind(wsId, report_type, frequency)
          .first();
        if (existing) return json({ error: "A schedule for this report type and frequency already exists" }, 409);

        // Entitlement: scheduled report limit per workspace
        const scheduleBillingUserId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const srPlan = await getEffectivePlan(scheduleBillingUserId, env);
        const srUsage  = await getEntitlementUsage(user, env, wsId);
        const srLimits = getPlanLimits(srPlan);
        if (srUsage.scheduled_reports_in_workspace >= srLimits.scheduled_reports_per_workspace) {
          return json(planLimitExceeded("scheduled_reports", srLimits.scheduled_reports_per_workspace, srUsage.scheduled_reports_in_workspace), 403);
        }

        const srId      = createId("sr");
        const nextRunAt = computeScheduledReportNextRunAt(frequency);
        const now       = new Date().toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO scheduled_reports (id, workspace_id, report_type, frequency, enabled, next_run_at, created_at)
             VALUES (?, ?, ?, ?, 1, ?, ?)`
          )
          .bind(srId, wsId, report_type, frequency, nextRunAt, now)
          .run();

        // Audit
        try {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_created",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  `Scheduled report created: ${report_type} (${frequency})`,
            metadata:     { scheduled_report_id: srId, report_type, frequency },
          });
        } catch { /* non-fatal */ }

        return json({
          scheduled_report: { id: srId, workspace_id: wsId, report_type, frequency, enabled: 1, next_run_at: nextRunAt, created_at: now }
        }, 201);
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── DELETE /api/workspaces/:id/scheduled-reports/:srId ───────────────────
    const srDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scheduled-reports\/([^/]+)$/);
    if (srDeleteMatch && request.method === 'DELETE') {
      const wsId = srDeleteMatch[1];
      const srId = srDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id FROM scheduled_reports WHERE id = ? AND workspace_id = ? LIMIT 1")
          .bind(srId, wsId)
          .first();
        if (!row) return json({ error: "Schedule not found" }, 404);

        await env.cybermeters_db
          .prepare("DELETE FROM scheduled_reports WHERE id = ?")
          .bind(srId)
          .run();

        try {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_deleted",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  "Scheduled report deleted",
            metadata:     { scheduled_report_id: srId },
          });
        } catch { /* non-fatal */ }

        return json({ deleted: true });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── PATCH /api/workspaces/:id/scheduled-reports/:srId ────────────────────
    // Toggle enabled. Body: { enabled: true|false }
    if (srDeleteMatch && request.method === 'PATCH') {
      const wsId = srDeleteMatch[1];
      const srId = srDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* optional */ }
        const enabled = body.enabled === false ? 0 : 1;
        const update = await env.cybermeters_db
          .prepare("UPDATE scheduled_reports SET enabled = ? WHERE id = ? AND workspace_id = ?")
          .bind(enabled, srId, wsId)
          .run();
        if ((update.meta?.changes ?? 0) > 0) {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_updated",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  `Scheduled report ${enabled ? "enabled" : "disabled"}`,
            metadata:     { scheduled_report_id: srId, enabled: enabled === 1 },
          });
        }
        return json({ updated: true, enabled: enabled === 1 });
      } catch (err) {
        return serverError("api", err);
      }
    }


  return null;
}
