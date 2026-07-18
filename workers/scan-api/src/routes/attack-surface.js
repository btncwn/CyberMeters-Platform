// ── Attack surface routes ──
// Workspace asset inventory (list/events/summary/timeline/detail), alert
// feed/summary, security-posture (+timeline) and vendor intelligence
// endpoints. Extracted near-verbatim from index.js (router split, Phase 2
// PR #16). Receives the per-request routeCtx from index.js; returns a
// Response when a route matches, or null so the main router continues.
import { buildCaConcentrationAnalytics, buildCertificateLifecycleIntelligence, detectSelfSignedCertificate, mapCertificateAuthorityOwner, normalizeCertificateIssuer } from "../engines/cert-analysis.js";
import { buildCertificateTrustL2 } from "../engines/cert-trust-l2.js";
import { assignManagedCaseOwner, getManagedCase, listManagedCaseEvents, listManagedCases, managedCaseToApi, transitionManagedCase, verifyManagedCaseById } from "../engines/asm-cases.js";
import { remapToThirdPartyCategory } from "../engines/discovery-scan.js";
import { computeWorkspaceVendorRisk, confidenceToScore, normalizeVendorKey, normalizeVendorRiskCategory, signalWeightForVendor } from "../engines/vendor-risk.js";
import { collapseCustomerTimelineEvents, countCustomerTimelineEventsByDay } from "../engines/timeline-trust.js";
import { SEVERITY_RANK, enrichEvent, eventTypesForCategory } from "../lib/exposure-events.js";
import { pageMeta, paginationParams, parseBoundedInteger } from "../lib/util.js";

export async function attackSurfaceRoutes(rctx) {
  const { request, env, url, json,
          requireAuth, requireWorkspaceRole } = rctx;

    // ── /api/workspaces/:id/managed-cases ──────────────────────────────────
    const casesMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/managed-cases(?:\/([^/]+)(?:\/([^/]+))?)?$/);
    if (casesMatch) {
      const wsId = casesMatch[1];
      const caseId = casesMatch[2] || null;
      const action = casesMatch[3] || null;

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
      const access = await requireWorkspaceRole(user, wsId, permission, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id FROM workspaces WHERE id = ?`)
        .bind(wsId)
        .first()
        .catch(() => null);
      if (!ws) return json({ error: "Workspace not found" }, 404);

      if (request.method === "GET" && !caseId) {
        try {
          const cases = await listManagedCases(env, wsId, {
            status: url.searchParams.get("status"),
            case_type: url.searchParams.get("case_type") || "asm_exposure",
            limit: parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200),
          });
          return json({ workspace_id: wsId, count: cases.length, cases });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      if (!caseId) return json({ error: "Not found" }, 404);
      const row = await getManagedCase(env, wsId, caseId).catch(() => null);
      if (!row) return json({ error: "Managed case not found" }, 404);

      if (request.method === "GET" && !action) {
        const events = await listManagedCaseEvents(env, wsId, caseId).catch(() => []);
        return json({ case: managedCaseToApi(row), events });
      }

      if (request.method === "POST" && action === "assign") {
        const body = await request.json().catch(() => null);
        const ownerRef = String(body?.owner_ref || "").trim();
        if (!ownerRef) return json({ error: "owner_ref is required" }, 400);
        try {
          let current = row;
          if (current.status === "open") {
            const triage = await transitionManagedCase(env, current, "triage", {
              actor_type: "customer", actor_id: user.id, action: "transition",
            });
            if (!triage.ok) return json({ error: triage.error }, 400);
            current = triage.case;
          }
          const assigned = await assignManagedCaseOwner(env, current, {
            owner_type: body?.owner_type || "unknown",
            owner_ref: ownerRef,
            assigned_by: "customer",
            actor_id: user.id,
          });
          if (!assigned.ok) return json({ error: assigned.error }, 400);
          const fresh = await getManagedCase(env, wsId, caseId);
          return json({ case: managedCaseToApi(fresh || assigned.case) });
        } catch {
          return json({ error: "Could not assign owner" }, 500);
        }
      }

      if (request.method === "POST" && action === "verify") {
        // Managed-verification profile trigger. Trusted: requires workspace:manage (checked
        // above). ALL scope is derived from the stored case — no hostname/domain_id/
        // finding_type is accepted from the client. Foreign case → 404 (non-enumerating).
        // Concurrency is CAS-based (single-invocation dedup); the optional header is an
        // audit correlation id only, not durable cross-window idempotency.
        const correlationId = (request.headers.get("x-correlation-id") || request.headers.get("idempotency-key") || "").trim().slice(0, 200) || null;
        let result;
        try {
          result = await verifyManagedCaseById(env, { workspaceId: wsId, caseId, actorId: user.id, correlationId });
        } catch {
          return json({ error: "Could not run verification" }, 500);
        }
        if (!result.ok) {
          // Non-enumerating: scope failures return the same 404 as a missing case.
          if (["not_found", "host_scope_mismatch", "domain_ineligible"].includes(result.code)) {
            return json({ error: "Managed case not found" }, 404);
          }
          if (result.code === "ineligible_state") return json({ error: "Case is not in a verification-eligible state" }, 409);
          if (result.code === "unsupported_finding_type") return json({ error: "Verification is not supported for this finding type" }, 422);
          return json({ error: "Verification could not run" }, 400);
        }
        const fresh = await getManagedCase(env, wsId, caseId).catch(() => null);
        return json({
          case: fresh ? managedCaseToApi(fresh) : null,
          verification: { profile: "managed_verification", code: result.code, decision: result.decision || null, completeness: result.completeness || null, outbound_calls: result.outbound_calls ?? null, idempotent: result.idempotent || false },
        });
      }

      if (request.method === "POST" && action === "transition") {
        const body = await request.json().catch(() => null);
        const target = String(body?.status || "").trim();
        if (!target) return json({ error: "status is required" }, 400);
        try {
          const result = await transitionManagedCase(env, row, target, {
            actor_type: "customer",
            actor_id: user.id,
            action: body?.action || "transition",
            reason: body?.reason || null,
            risk_accepted_until: body?.risk_accepted_until || null,
            detail: { reason: body?.reason || null, risk_accepted_until: body?.risk_accepted_until || null },
          });
          if (!result.ok) return json({ error: result.error }, 400);
          return json({ case: managedCaseToApi(result.case) });
        } catch {
          return json({ error: "Could not update managed case" }, 500);
        }
      }

      return json({ error: "Not found" }, 404);
    }

    // ── GET /api/workspaces/:id/exposure/feed ───────────────────────────────
    const feedMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/exposure\/feed$/);
    if (feedMatch && request.method === "GET") {
      const wsId = feedMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      const { limit, offset } = paginationParams(url, { defaultLimit: 50, maxLimit: 100 });
      const where = ["workspace_id = ?"];
      const binds = [wsId];

      const severity = url.searchParams.get("severity");
      if (severity && SEVERITY_RANK[severity] != null) {
        const allowed = Object.entries(SEVERITY_RANK)
          .filter(([, rank]) => rank >= SEVERITY_RANK[severity])
          .map(([name]) => name);
        where.push(`severity IN (${allowed.map(() => "?").join(",")})`);
        binds.push(...allowed);
      }

      const category = url.searchParams.get("category");
      if (category) {
        const eventTypes = eventTypesForCategory(category);
        if (eventTypes.length > 0) {
          where.push(`event_type IN (${eventTypes.map(() => "?").join(",")})`);
          binds.push(...eventTypes);
        } else {
          where.push("1 = 0");
        }
      }

      const eventType = url.searchParams.get("event_type");
      if (eventType) {
        where.push("event_type = ?");
        binds.push(eventType);
      }

      const hostname = url.searchParams.get("hostname");
      if (hostname) {
        where.push("hostname = ?");
        binds.push(hostname);
      }

      const domainId = url.searchParams.get("domain_id");
      if (domainId) {
        where.push("domain_id = ?");
        binds.push(domainId);
      }

      const since = url.searchParams.get("since");
      if (since && Number.isFinite(Date.parse(since))) {
        where.push("created_at >= ?");
        binds.push(since);
      }

      const until = url.searchParams.get("until");
      if (until && Number.isFinite(Date.parse(until))) {
        where.push("created_at <= ?");
        binds.push(until);
      }

      const whereSql = where.join(" AND ");
      try {
        const [pageResult, totalResult] = await env.cybermeters_db.batch([
          env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id, event_type,
                      hostname, severity, description, created_at
               FROM asset_events
               WHERE ${whereSql}
               ORDER BY created_at DESC, id DESC
               LIMIT ? OFFSET ?`
            )
            .bind(...binds, limit, offset),
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM asset_events
               WHERE ${whereSql}`
            )
            .bind(...binds),
        ]);

        const events = collapseCustomerTimelineEvents(pageResult.results || []).map(enrichEvent);
        const total = totalResult.results?.[0]?.n ?? 0;
        return json({
          workspace_id: wsId,
          events,
          pagination: pageMeta({ items: events, limit, offset, total }),
        });
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // ── /api/workspaces/:id/assets/* ────────────────────────────────────────
    // Handles list, events, summary, timeline, and per-asset detail.
    const assetsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/assets(\/[^/]*)?$/);
    if (assetsMatch && request.method === "GET") {
      const wsId  = assetsMatch[1];
      const sub   = assetsMatch[2] ?? "";   // "", "/events", "/summary", "/timeline", "/:assetId"

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/assets ───────────────────────────────────
      if (sub === "") {
        const statusFilter = url.searchParams.get("status");
        const limit        = parseBoundedInteger(url.searchParams.get("limit"), 200, 1, 500);
        try {
          const where = statusFilter ? "AND status = ?" : "";
          const binds = statusFilter ? [wsId, statusFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, hostname, asset_type, source,
                      first_seen, last_seen, status, wildcard_dns,
                      ip_addresses, cname, redirect_to, cloud_provider,
                      risk_level, metadata_json, created_at, updated_at
               FROM workspace_assets
               WHERE workspace_id = ? ${where}
               ORDER BY last_seen DESC LIMIT ?`
            )
            .bind(...binds)
            .all();
          return json({ workspace_id: wsId, count: result.results.length, assets: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/events ────────────────────────────
      if (sub === "/events") {
        const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE workspace_id = ?
               ORDER BY created_at DESC LIMIT ?`
            )
            .bind(wsId, limit)
            .all();
          const events = collapseCustomerTimelineEvents(result.results || []);
          return json({ workspace_id: wsId, count: events.length, events });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/summary ───────────────────────────
      if (sub === "/summary") {
        try {
          const [all, active, inactive, rootDomains, subdomains, exposedSvcs, cloudStorage, wildcardAssets, takeoverRisks] =
            await env.cybermeters_db.batch([
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'inactive'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'root_domain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'subdomain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'exposed_service'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'cloud_storage'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND wildcard_dns = 1`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND risk_level IN ('high','critical')`).bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total_assets:       all.results[0]?.n         ?? 0,
            active_assets:      active.results[0]?.n      ?? 0,
            inactive_assets:    inactive.results[0]?.n    ?? 0,
            root_domains:       rootDomains.results[0]?.n ?? 0,
            subdomains:         subdomains.results[0]?.n  ?? 0,
            exposed_services:   exposedSvcs.results[0]?.n ?? 0,
            cloud_storage_assets: cloudStorage.results[0]?.n ?? 0,
            wildcard_assets:    wildcardAssets.results[0]?.n ?? 0,
            takeover_risks:     takeoverRisks.results[0]?.n  ?? 0,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/timeline ──────────────────────────
      if (sub === "/timeline") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, scan_id, event_type, hostname, created_at
               FROM asset_events
               WHERE workspace_id = ?
               ORDER BY created_at ASC, id ASC`
            )
            .bind(wsId)
            .all();

          // Pivot rows into { day, new_asset_discovered, asset_reappeared, ... }
          const EVENT_TYPES = [
            "new_asset_discovered", "asset_reappeared", "asset_no_longer_seen",
            "takeover_risk_detected", "wildcard_dns_detected", "cloud_storage_detected",
          ];
          return json({ workspace_id: wsId, timeline: countCustomerTimelineEventsByDay(result.results || [], EVENT_TYPES) });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/:assetId ──────────────────────────
      {
        const assetId = sub.slice(1);   // strip leading "/"
        try {
          const asset = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, hostname, asset_type, source,
                      first_seen, last_seen, status, wildcard_dns,
                      ip_addresses, cname, redirect_to, cloud_provider,
                      risk_level, metadata_json, created_at, updated_at
               FROM workspace_assets
               WHERE id = ? AND workspace_id = ?`
            )
            .bind(assetId, wsId)
            .first();
          if (!asset) return json({ error: "Asset not found" }, 404);

          const eventsResult = await env.cybermeters_db
            .prepare(
              `SELECT id, scan_id, event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE asset_id = ? AND workspace_id = ?
               ORDER BY created_at DESC LIMIT 50`
            )
            .bind(assetId, wsId)
            .all();

          return json({ asset, events: eventsResult.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── /api/workspaces/:id/alerts/* ────────────────────────────────────────
    // GET /api/workspaces/:id/alerts          — list alerts, filterable by severity
    // GET /api/workspaces/:id/alerts/summary  — severity counts + last alert timestamp
    const alertsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/alerts(\/[^/]*)?$/);
    if (alertsMatch && request.method === "GET") {
      const wsId = alertsMatch[1];
      const sub  = alertsMatch[2] ?? "";   // "" or "/summary"

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/alerts/summary ─────────────────────────────
      if (sub === "/summary") {
        try {
          const [total, critical, high, medium, low, latest] =
            await env.cybermeters_db.batch([
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ?`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'critical'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'high'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'medium'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'low'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT sent_at FROM asset_alert_records WHERE workspace_id = ? ORDER BY sent_at DESC LIMIT 1`)
                .bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total:              total.results[0]?.n    ?? 0,
            critical:           critical.results[0]?.n ?? 0,
            high:               high.results[0]?.n     ?? 0,
            medium:             medium.results[0]?.n   ?? 0,
            low:                low.results[0]?.n      ?? 0,
            last_alert_at:      latest.results[0]?.sent_at ?? null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/alerts ─────────────────────────────────────
      if (sub === "") {
        const severityFilter = url.searchParams.get("severity");
        const limit          = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

        if (severityFilter && !VALID_SEVERITIES.has(severityFilter)) {
          return json({ error: "Invalid severity value" }, 400);
        }

        try {
          const where  = severityFilter ? "AND severity = ?" : "";
          const binds  = severityFilter ? [wsId, severityFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, scan_id, domain, severity,
                      event_counts, top_hostnames, sent_at
               FROM asset_alert_records
               WHERE workspace_id = ? ${where}
               ORDER BY sent_at DESC
               LIMIT ?`
            )
            .bind(...binds)
            .all();

          // Parse JSON columns so consumers don't have to
          const alerts = (result.results || []).map((row) => ({
            ...row,
            event_counts:  row.event_counts  ? JSON.parse(row.event_counts)  : {},
            top_hostnames: row.top_hostnames ? JSON.parse(row.top_hostnames) : [],
          }));

          return json({ workspace_id: wsId, count: alerts.length, alerts });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // Unknown sub-resource
      return json({ error: "Not found" }, 404);
    }

    // ── /api/workspaces/:id/posture[/timeline] ──────────────────────────────
    // GET /api/workspaces/:id/posture          — current attack surface posture snapshot
    // GET /api/workspaces/:id/posture/timeline — daily metric series (last 90 days)
    //
    // Both routes use existing data only (workspace_assets, asset_events, scans,
    // findings, workspace_domains).  No new scanning modules, no scoring changes.
    const postureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/posture(\/timeline)?$/);
    if (postureMatch && request.method === "GET") {
      const wsId    = postureMatch[1];
      const isTimeline = !!postureMatch[2];   // true → /posture/timeline

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── Attack Surface Size classification ────────────────────────────────
      // 0-10 = Small, 11-50 = Medium, 51-200 = Large, 201+ = Very Large
      function classifyAttackSurface(assetCount) {
        if (assetCount <= 10)  return "Small";
        if (assetCount <= 50)  return "Medium";
        if (assetCount <= 200) return "Large";
        return "Very Large";
      }

      // ── Risk trend helper ─────────────────────────────────────────────────
      // Higher score = safer. Score drop = risk going up.
      function scoreTrend(avgLast, avgPrev) {
        if (avgLast === null || avgPrev === null) return "stable";
        const delta = avgLast - avgPrev;
        if (delta >= 3)  return "down";   // score improved → risk down
        if (delta <= -3) return "up";     // score fell → risk up
        return "stable";
      }

      // ── GET /api/workspaces/:id/posture ───────────────────────────────────
      if (!isTimeline) {
        try {
          const [
            totalRow,
            activeRow,
            newAssets30dRow,
            removedAssets30dRow,
            criticalNow30dRow,
            criticalPrev30dRow,
            avgScoreLast30dRow,
            avgScorePrev30dRow,
          ] = await env.cybermeters_db.batch([

            // Total assets ever tracked in this workspace
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`)
              .bind(wsId),

            // Currently active assets
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Assets first discovered in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND first_seen >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Assets removed (no-longer-seen events) in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = ? AND event_type = 'asset_no_longer_seen' AND created_at >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Critical findings from scans in the last 30 days (via workspace_domains join)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Critical findings from scans in the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the last 30 days (for risk trend)
            env.cybermeters_db
              .prepare(
                `SELECT AVG(s.score) AS avg_score
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT AVG(s.score) AS avg_score
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),
          ]);

          const totalAssets    = totalRow.results[0]?.n          ?? 0;
          const activeAssets   = activeRow.results[0]?.n         ?? 0;
          const newAssets30d   = newAssets30dRow.results[0]?.n   ?? 0;
          const removedAssets30d = removedAssets30dRow.results[0]?.n ?? 0;
          const criticalNow    = criticalNow30dRow.results[0]?.n    ?? 0;
          const criticalPrev   = criticalPrev30dRow.results[0]?.n   ?? 0;
          const avgScoreLast30d = avgScoreLast30dRow.results[0]?.avg_score ?? null;
          const avgScorePrev30d = avgScorePrev30dRow.results[0]?.avg_score ?? null;

          const trend = scoreTrend(avgScoreLast30d, avgScorePrev30d);

          return json({
            workspace_id:                wsId,
            attack_surface_size:         classifyAttackSurface(totalAssets),
            total_assets:                totalAssets,
            active_assets:               activeAssets,
            new_assets_30d:              newAssets30d,
            removed_assets_30d:          removedAssets30d,
            asset_growth_30d:            newAssets30d - removedAssets30d,
            critical_findings:           criticalNow,
            critical_findings_change_30d: criticalNow - criticalPrev,
            risk_trend:                  trend,
            score_trend:                 trend,   // same signal; both exposed for consumer flexibility
            avg_score_last_30d:          avgScoreLast30d !== null ? Math.round(avgScoreLast30d) : null,
            avg_score_prev_30d:          avgScorePrev30d !== null ? Math.round(avgScorePrev30d) : null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/posture/timeline ──────────────────────────
      // Returns one entry per day for the last 90 days.
      // asset_count is derived by applying daily deltas backward from today's total.
      if (isTimeline) {
        try {
          const [totalActiveRow, eventRows, findingRows] = await env.cybermeters_db.batch([

            // Current active asset count — used as the anchor for backward derivation
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Raw new / removed events for the last 90 days. Collapse first,
            // then aggregate, so short-lived churn does not drive trend counts.
            env.cybermeters_db
              .prepare(
                `SELECT id, scan_id, event_type, hostname, created_at
                 FROM asset_events
                 WHERE workspace_id = ?
                   AND created_at >= datetime('now', '-90 days')
                   AND event_type IN ('new_asset_discovered', 'asset_no_longer_seen', 'asset_reappeared')
                 ORDER BY created_at ASC, id ASC`
              )
              .bind(wsId),

            // Per-day critical findings count (from scans run that day)
            env.cybermeters_db
              .prepare(
                `SELECT date(s.created_at) AS day, COUNT(f.id) AS critical_findings
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-90 days')
                 GROUP BY day
                 ORDER BY day ASC`
              )
              .bind(wsId),
          ]);

          // Build day-keyed maps from query results
          const eventMap    = new Map();
          const findingMap  = new Map();

          for (const row of countCustomerTimelineEventsByDay(eventRows.results || [], ["new_asset_discovered", "asset_no_longer_seen"])) {
            eventMap.set(row.day, {
              new_assets: row.new_asset_discovered ?? 0,
              removed_assets: row.asset_no_longer_seen ?? 0,
            });
          }
          for (const row of (findingRows.results || [])) {
            findingMap.set(row.day, row.critical_findings ?? 0);
          }

          // Collect every day that appears in either dataset
          const daySet = new Set([...eventMap.keys(), ...findingMap.keys()]);
          const days   = [...daySet].sort();

          // Derive asset_count by walking forward from the earliest day.
          // anchor = total active assets today; walk backward from end → start to seed the
          // starting count, then walk forward to fill in each day's snapshot.
          let runningCount = totalActiveRow.results[0]?.n ?? 0;

          // First pass: walk backward from today to compute the count at the start of `days`
          for (let i = days.length - 1; i >= 0; i--) {
            const d = days[i];
            const ev = eventMap.get(d) ?? { new_assets: 0, removed_assets: 0 };
            runningCount -= ev.new_assets;
            runningCount += ev.removed_assets;
          }

          // Second pass: walk forward, incrementally updating the running count per day
          const timeline = [];
          for (const day of days) {
            const ev = eventMap.get(day) ?? { new_assets: 0, removed_assets: 0 };
            runningCount += ev.new_assets;
            runningCount -= ev.removed_assets;
            timeline.push({
              day,
              asset_count:       Math.max(0, runningCount),
              new_assets:        ev.new_assets,
              removed_assets:    ev.removed_assets,
              critical_findings: findingMap.get(day) ?? 0,
            });
          }

          return json({ workspace_id: wsId, days: timeline.length, timeline });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── Certificate Intelligence routes ────────────────────────────────────
    // GET /api/workspaces/:id/certificates
    //   Returns latest certificate_intelligence per domain in workspace.
    //   Each entry: { domain, certificate_risk_level, days_until_expiry,
    //     expires_at, total_certificates_seen, issued_for_sensitive_hosts,
    //     wildcard_dns, suspicious_certificate_signals, ct_sources }
    //
    // GET /api/workspaces/:id/certificates/timeline
    //   Returns certificate-related asset_events from the last 90 days,
    //   grouped by day: [{ day, events:[{event_type, severity, description}] }]
    const certMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/certificates(\/timeline)?$/
    );
    if (certMatch && request.method === "GET") {
      const wsId        = certMatch[1];
      const isTimeline  = !!certMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // ── /certificates/timeline ──────────────────────────────────────────
      if (isTimeline) {
        if (domainIds.length === 0) {
          return json({ workspace_id: wsId, days: 90, timeline: [] });
        }

        // Query asset_events for cert-related event types in this workspace
        let events;
        try {
          const cutoff = new Date(Date.now() - 90 * 86_400_000).toISOString();
          const r = await env.cybermeters_db
            .prepare(
              `SELECT event_type, severity, description, hostname,
                      DATE(created_at) AS day
               FROM asset_events
               WHERE workspace_id = ?
                 AND event_type IN (
                       'certificate_sensitive_host_detected',
                       'certificate_expiring_soon',
                       'certificate_growth_detected',
                       'certificate_new_detected',
                       'certificate_new_san_detected',
                       'certificate_new_issuer_detected'
                     )
                 AND created_at >= ?
               ORDER BY created_at DESC`
            )
            .bind(wsId, cutoff)
            .all();
          events = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        // Group by day
        const dayMap = new Map();
        for (const ev of collapseCustomerTimelineEvents(events)) {
          if (!dayMap.has(ev.day)) dayMap.set(ev.day, []);
          dayMap.get(ev.day).push({
            event_type:  ev.event_type,
            severity:    ev.severity,
            description: ev.description,
            hostname:    ev.hostname || null,
          });
        }

        const timeline = [...dayMap.entries()]
          .sort(([a], [b]) => b.localeCompare(a))
          .map(([day, evts]) => ({ day, events: evts }));

	        let issuer_history = [];
	        let certificate_timeline = [];
	        let ca_concentration = buildCaConcentrationAnalytics([], {
	          source: "historical_certificate_observations",
	        });
	        let churn = {
	          certificates_last_30_days: 0,
	          certificates_last_90_days: 0,
	          classification: "low",
        };
        try {
          const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
          const ninetyDaysAgo = new Date(Date.now() - 90 * 86_400_000).toISOString();

          const [issuerRows, certRows, churn30, churn90] = await Promise.all([
            env.cybermeters_db
              .prepare(
                `SELECT issuer, MIN(first_seen) AS first_seen,
                        MAX(last_seen) AS last_seen, COUNT(*) AS certificates
                 FROM certificate_observations
                 WHERE workspace_id = ?
                 GROUP BY issuer
                 ORDER BY first_seen ASC`
              )
              .bind(wsId)
              .all(),
            env.cybermeters_db
              .prepare(
                `SELECT subject, issuer, san_count, expires_at,
                        first_seen, last_seen
                 FROM certificate_observations
                 WHERE workspace_id = ?
                 ORDER BY first_seen DESC`
              )
              .bind(wsId)
              .all(),
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(*) AS n FROM certificate_observations
                 WHERE workspace_id = ? AND first_seen >= ?`
              )
              .bind(wsId, thirtyDaysAgo)
              .first(),
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(*) AS n FROM certificate_observations
                 WHERE workspace_id = ? AND first_seen >= ?`
              )
              .bind(wsId, ninetyDaysAgo)
              .first(),
          ]);

	          issuer_history = issuerRows.results || [];
	          certificate_timeline = certRows.results || [];
	          ca_concentration = buildCaConcentrationAnalytics(certificate_timeline, {
	            source: "historical_certificate_observations",
	          });
	          const count30 = churn30?.n ?? 0;
	          const count90 = churn90?.n ?? 0;
          const classification =
            count90 >= 25 ? "unusual" :
            count90 >= 10 ? "high" :
            count90 >= 3  ? "medium" : "low";
          churn = {
            certificates_last_30_days: count30,
            certificates_last_90_days: count90,
            classification,
          };
        } catch { /* v2 migration may not be applied yet */ }

	        return json({ workspace_id: wsId, days: 90, timeline, certificate_timeline, issuer_history, churn, ca_concentration });
	      }

      // ── /certificates ───────────────────────────────────────────────────
      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, certificates: [] });
      }

      // Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id, domain_id FROM scans WHERE domain_id = ? " +
              "AND status = 'completed' ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanRows = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value : null))
        .filter(Boolean);

      // Fetch R2 reports in parallel
	      const r2Results = await Promise.allSettled(
	        scanRows.map((s) => env.cybermeters_reports.get(`reports/${s.id}.json`))
	      );

	      const caConcentrationByDomain = new Map();
	      const certificateHistoryByDomain = new Map();
	      try {
	        const observed = await env.cybermeters_db
	          .prepare(
	            `SELECT domain_id, subject, issuer, san_count, expires_at,
	                    first_seen, last_seen, evidence_json
	             FROM certificate_observations
	             WHERE workspace_id = ?`
	          )
	          .bind(wsId)
	          .all();
	        const byDomain = new Map();
	        for (const row of (observed.results || [])) {
	          if (!row.domain_id) continue;
	          if (!byDomain.has(row.domain_id)) byDomain.set(row.domain_id, []);
	          byDomain.get(row.domain_id).push(row);
	        }
	        for (const [domainId, rows] of byDomain.entries()) {
	          certificateHistoryByDomain.set(domainId, rows);
	          caConcentrationByDomain.set(domainId, buildCaConcentrationAnalytics(rows, {
	            source: "historical_certificate_observations",
	          }));
	        }
	      } catch { /* certificate_observations may not exist in older environments */ }

	      const certificates = [];
	      for (let i = 0; i < r2Results.length; i++) {
        if (r2Results[i].status !== "fulfilled" || !r2Results[i].value) continue;
        let report;
        try { report = await r2Results[i].value.json(); } catch { continue; }

        const ci = report?.modules?.certificate_intelligence;
        if (!ci) continue;

        const certificate = {
          domain:                       report.domain || null,
          certificate_risk_level:       ci.certificate_risk_level,
	          certificate_status:           ci.certificate_status,
	          issuer:                       ci.issuer || null,
	          issuer_normalized:            ci.issuer_normalized || normalizeCertificateIssuer(ci.issuer || null),
	          ca_owner:                     ci.ca_owner || mapCertificateAuthorityOwner(normalizeCertificateIssuer(ci.issuer || null)),
	          subject:                      ci.subject || null,
	          san_count:                    ci.san_count || 0,
	          san_hostnames:                ci.san_hostnames || [],
	          days_until_expiry:            ci.days_until_expiry,
	          expires_at:                   ci.expires_at,
	          lifecycle:                    ci.lifecycle || buildCertificateLifecycleIntelligence(ci),
	          key_algorithm:                ci.key_algorithm || "unknown",
	          key_size_bits:                ci.key_size_bits || "unknown",
	          signature_algorithm:          ci.signature_algorithm || "unknown",
	          crypto_metadata:              ci.crypto_metadata || {
	            key_algorithm: ci.key_algorithm || "unknown",
	            key_size_bits: ci.key_size_bits || "unknown",
	            signature_algorithm: ci.signature_algorithm || "unknown",
	          },
	          self_signed:                  ci.self_signed ?? detectSelfSignedCertificate(ci.issuer || null, ci.subject || null),
	          ca_concentration:             caConcentrationByDomain.get(scanRows[i]?.domain_id) || ci.ca_concentration || buildCaConcentrationAnalytics(ci.issuer ? [ci.issuer] : []),
	          total_certificates_seen:      ci.total_certificates_seen,
	          issued_for_sensitive_hosts:   ci.issued_for_sensitive_hosts || [],
          wildcard_dns:                 ci.wildcard_dns,
          wildcard_warning:             ci.wildcard_warning || null,
          ct_sources:                   ci.ct_sources || {},
          suspicious_certificate_signals: ci.suspicious_certificate_signals || [],
          scan_id:                      scanRows[i]?.id || null,
        };
        Object.assign(certificate, buildCertificateTrustL2(certificate, {
          history: certificateHistoryByDomain.get(scanRows[i]?.domain_id) || [],
        }));
        certificates.push(certificate);
      }

      // Sort: critical first, then high, medium, low
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      certificates.sort(
        (a, b) => (riskOrder[a.certificate_risk_level] ?? 5) - (riskOrder[b.certificate_risk_level] ?? 5)
      );

      return json({
        workspace_id: wsId,
        total:        certificates.length,
        certificates,
      });
    }

    // ── SaaS Exposure Discovery route ─────────────────────────────────────
    // GET /api/workspaces/:id/saas-exposure
    //   Filters: ?exposure_type=login_portal|email_gateway|saas_tenant|
    //                           support_portal|crm_portal|dev_portal|ecommerce_portal
    //            ?risk_level=low|medium|high
    //            ?category=email_identity|collaboration|crm|support|ecommerce
    //   Returns: { workspace_id, total, high_risk, exposures: [...] }
    const saasExpMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/saas-exposure$/
    );
    if (saasExpMatch && request.method === "GET") {
      const wsId = saasExpMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, high_risk: 0, exposures: [] });
      }

      // 2. Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge saas_exposure.exposures across all reports (dedup by name)
      const seen      = new Set();
      const exposures = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const mod = report?.modules?.saas_exposure;
        if (!mod?.exposures?.length) continue;

        for (const exp of mod.exposures) {
          if (seen.has(exp.name)) continue;
          seen.add(exp.name);
          exposures.push({
            name:           exp.name,
            category:       exp.category,
            exposure_type:  exp.exposure_type,
            risk_level:     exp.risk_level,
            portal_url:     exp.portal_url     || null,
            admin_url:      exp.admin_url      || null,
            tenant_hint:    exp.tenant_hint    || null,
            tenant_url:     exp.tenant_url     || null,
            attack_surface: exp.attack_surface || null,
            confidence:     exp.confidence,
            domain:         report.domain      || null,
          });
        }
      }

      // Sort high → medium → low
      const riskOrder = { high: 0, medium: 1, low: 2 };
      exposures.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      // Apply filters
      const filterExpType  = url.searchParams.get("exposure_type");
      const filterRisk     = url.searchParams.get("risk_level");
      const filterCategory = url.searchParams.get("category");

      const filtered = exposures.filter((e) => {
        if (filterExpType  && e.exposure_type !== filterExpType)  return false;
        if (filterRisk     && e.risk_level    !== filterRisk)     return false;
        if (filterCategory && e.category      !== filterCategory) return false;
        return true;
      });

      return json({
        workspace_id: wsId,
        total:     filtered.length,
        high_risk: filtered.filter((e) => e.risk_level === "high").length,
        exposures: filtered,
      });
    }

    // ── Cloud Asset Discovery routes ───────────────────────────────────────
    // GET /api/workspaces/:id/cloud-assets
    //   Filters: ?category=storage|cdn|serverless|paas|hosting
    //            ?provider=<name>  ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/cloud-assets/summary
    //   Returns: { workspace_id, total, by_category:{storage,cdn,serverless,paas,hosting},
    //              high_risk, medium_risk, low_risk, providers:[{name,count}] }
    const cloudAssetsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cloud-assets(\/summary)?$/
    );
    if (cloudAssetsMatch && request.method === "GET") {
      const wsId      = cloudAssetsMatch[1];
      const isSummary = !!cloudAssetsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        const empty = isSummary
          ? { workspace_id: wsId, total: 0,
              by_category: { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 },
              high_risk: 0, medium_risk: 0, low_risk: 0, providers: [] }
          : { workspace_id: wsId, total: 0, assets: [] };
        return json(empty);
      }

      // 2. Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge cloud_storage_discovery.findings across all reports (dedup by asset+provider)
      const seen   = new Set();
      const assets = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const cloudMod = report?.modules?.cloud_storage_discovery;
        if (!cloudMod?.findings?.length) continue;

        for (const f of cloudMod.findings) {
          const key = `${f.asset}::${f.provider}`;
          if (seen.has(key)) continue;
          seen.add(key);
          assets.push({
            asset:        f.asset,
            provider:     f.provider,
            category:     f.category     || "storage",  // backward-compat for old reports
            service_type: f.service_type || "unknown",
            evidence:     f.evidence,
            risk_level:   f.risk_level,
            domain:       report.domain  || null,
          });
        }
      }

      // Sort: high first
      const riskOrder = { high: 0, medium: 1, low: 2 };
      assets.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      if (isSummary) {
        const by_category = { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 };
        const providerCount = {};
        let high_risk = 0, medium_risk = 0, low_risk = 0;

        for (const a of assets) {
          const cat = a.category;
          if (cat in by_category) by_category[cat]++;
          if (a.risk_level === "high")        high_risk++;
          else if (a.risk_level === "medium") medium_risk++;
          else if (a.risk_level === "low")    low_risk++;
          providerCount[a.provider] = (providerCount[a.provider] || 0) + 1;
        }

        const providers = Object.entries(providerCount)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count);

        return json({
          workspace_id: wsId,
          total: assets.length,
          by_category,
          high_risk,
          medium_risk,
          low_risk,
          providers,
        });
      }

      // Apply optional filters
      const filterCategory = url.searchParams.get("category");
      const filterProvider = url.searchParams.get("provider");
      const filterRisk     = url.searchParams.get("risk_level");

      const filtered = assets.filter((a) => {
        if (filterCategory && a.category   !== filterCategory) return false;
        if (filterProvider && a.provider   !== filterProvider) return false;
        if (filterRisk     && a.risk_level !== filterRisk)     return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Admin Surfaces route ───────────────────────────────────────────────
    // GET /api/workspaces/:id/admin-surfaces
    //   Filters: ?severity=critical|high|medium|low
    //            ?category=admin_panel|monitoring|vpn|collaboration|infrastructure|source_control
    //            ?confidence=confirmed|high|medium
    //   Returns: { workspace_id, total, critical, high, medium, services: [...] }
    //
    // Reads the admin_surface_detection module from the latest completed scan
    // R2 report for each domain in the workspace, then merges and deduplicates.
    const adminSurfacesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/admin-surfaces$/
    );
    if (adminSurfacesMatch && request.method === "GET") {
      const wsId = adminSurfacesMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get all domain IDs for this workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({
          workspace_id: wsId,
          total: 0, critical: 0, high: 0, medium: 0, services: [],
        });
      }

      // 2. Latest completed scan per domain (parallel D1 queries)
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Extract and merge admin_surface_detection.services across reports
      const seen     = new Set();
      const services = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const adminMod = report?.modules?.admin_surface_detection;
        if (!adminMod?.services?.length) continue;

        for (const svc of adminMod.services) {
          const key = `${svc.hostname}::${svc.product}`;
          if (seen.has(key)) continue;
          seen.add(key);
          services.push({
            hostname:   svc.hostname,
            url:        svc.url        || `https://${svc.hostname}`,
            product:    svc.product,
            category:   svc.category,
            severity:   svc.severity   || svc.risk_level,
            confidence: svc.confidence,
            risk_level: svc.risk_level,
            ip_address: svc.ip_address || null,
            server:     svc.server     || null,
            title:      svc.title      || null,
            domain:     report.domain  || null,
          });
        }
      }

      // 5. Apply query-string filters
      const filterSeverity   = url.searchParams.get("severity");
      const filterCategory   = url.searchParams.get("category");
      const filterConfidence = url.searchParams.get("confidence");

      const filtered = services.filter((s) => {
        if (filterSeverity   && s.severity   !== filterSeverity)   return false;
        if (filterCategory   && s.category   !== filterCategory)   return false;
        if (filterConfidence && s.confidence !== filterConfidence)  return false;
        return true;
      });

      // Sort: confirmed+critical first
      const confOrder = { confirmed: 0, high: 1, medium: 2, low: 3 };
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      filtered.sort((a, b) => {
        const cd = (confOrder[a.confidence] ?? 4) - (confOrder[b.confidence] ?? 4);
        if (cd !== 0) return cd;
        return (riskOrder[a.risk_level] ?? 4) - (riskOrder[b.risk_level] ?? 4);
      });

      return json({
        workspace_id: wsId,
        total:    filtered.length,
        critical: filtered.filter((s) => s.risk_level === "critical").length,
        high:     filtered.filter((s) => s.risk_level === "high").length,
        medium:   filtered.filter((s) => s.risk_level === "medium").length,
        services: filtered,
      });
    }

    // ── Third-Party Asset Discovery routes ────────────────────────────────
    // GET /api/workspaces/:id/third-party-assets
    //   Filters: ?category=email|crm|support|collaboration|marketing|ecommerce
    //            ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/third-party-assets/summary
    //   Returns: { workspace_id, total, email, crm, support, collaboration,
    //              marketing, ecommerce, high_risk, medium_risk, low_risk }
    const tpaMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/third-party-assets(\/summary)?$/
    );
    if (tpaMatch && request.method === "GET") {
      const wsId      = tpaMatch[1];
      const isSummary = !!tpaMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Read all workspace_vendors for this workspace; remap + filter in JS.
      // workspace_vendors uses the vendor-risk category taxonomy; we remap here.
      let rows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name, category, source, evidence, confidence,
                    risk_level, status, first_seen, last_seen
             FROM workspace_vendors
             WHERE workspace_id = ? AND status = 'active'`
          )
          .bind(wsId)
          .all();
        rows = r.results || [];
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // Remap to third-party taxonomy; skip infrastructure/cloud/hosting
      const assets = [];
      for (const row of rows) {
        const tpCategory = remapToThirdPartyCategory(row.vendor_name, row.category);
        if (!tpCategory) continue;

        let parsedEvidence = [];
        try { parsedEvidence = JSON.parse(row.evidence); } catch { /* ignore */ }

        assets.push({
          name:       row.vendor_name,
          category:   tpCategory,
          source:     row.source,
          evidence:   parsedEvidence,
          confidence: row.confidence,
          risk_level: row.risk_level,
          first_seen: row.first_seen,
          last_seen:  row.last_seen,
        });
      }

      // Sort: email → crm → collaboration → support → marketing → ecommerce
      const catOrder = {
        email: 0, crm: 1, collaboration: 2, support: 3, marketing: 4, ecommerce: 5,
      };
      assets.sort((a, b) => (catOrder[a.category] ?? 9) - (catOrder[b.category] ?? 9));

      if (isSummary) {
        const summary = {
          workspace_id:  wsId,
          total:         assets.length,
          email:         0,
          crm:           0,
          support:       0,
          collaboration: 0,
          marketing:     0,
          ecommerce:     0,
          high_risk:     0,
          medium_risk:   0,
          low_risk:      0,
        };
        for (const a of assets) {
          if (a.category in summary) summary[a.category]++;
          if (a.risk_level === "high")        summary.high_risk++;
          else if (a.risk_level === "medium") summary.medium_risk++;
          else if (a.risk_level === "low")    summary.low_risk++;
        }
        return json(summary);
      }

      // Apply optional filters from query string
      const filterCategory = url.searchParams.get("category");
      const filterRisk     = url.searchParams.get("risk_level");
      const filtered = assets.filter((a) => {
        if (filterCategory && a.category !== filterCategory) return false;
        if (filterRisk     && a.risk_level !== filterRisk)   return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Vendor Inventory routes ────────────────────────────────────────────
    // GET /api/workspaces/:id/vendors
    //   Filters: ?status=active|inactive  ?risk_level=low|medium|high
    //            ?category=infrastructure|cloud|email_identity|hosting|saas|
    //                      support|collaboration|ecommerce|certificate_authority
    //   Returns: { workspace_id, count, vendors: [...] }
    //
    // GET /api/workspaces/:id/vendors/summary
    //   Returns: { total_vendors, active_vendors, inactive_vendors,
    //              infrastructure, cloud, email_identity, hosting, saas,
    //              support, ecommerce, certificate_authority,
    //              high_risk, medium_risk, low_risk }
    const vendorsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/vendors(\/summary)?$/);
    if (vendorsMatch && request.method === "GET") {
      const wsId      = vendorsMatch[1];
      const isSummary = !!vendorsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      if (isSummary) {
        // Aggregate counts directly from D1 — one query
        let rows;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT status, category, risk_level, COUNT(*) AS cnt
               FROM workspace_vendors
               WHERE workspace_id = ?
               GROUP BY status, category, risk_level`
            )
            .bind(wsId)
            .all();
          rows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        const summary = {
          workspace_id:    wsId,
          total_vendors:   0,
          active_vendors:  0,
          inactive_vendors:0,
          infrastructure:  0,
          cloud:           0,
          email_identity:  0,
          hosting:         0,
          saas:            0,
          support:         0,
          ecommerce:       0,
          certificate_authority: 0,
          // vendor_relationship categories (Phase 7k)
          analytics:       0,
          payments:        0,
          crm:             0,
          identity:        0,
          collaboration:   0,
          cdn:             0,
          security:        0,
          // identity cross-population (Phase 8f)
          identity_provider: 0,
          high_risk:       0,
          medium_risk:     0,
          low_risk:        0,
        };

        // We need unique vendor counts, not row counts (a vendor appears once).
        // First collect unique vendor names per bucket using a Set approach via JS.
        // Re-query for unique vendor names with their attributes.
        let vendorRows;
        try {
          const r2 = await env.cybermeters_db
            .prepare(
              `SELECT vendor_name, category, risk_level, status
               FROM workspace_vendors
               WHERE workspace_id = ?`
            )
            .bind(wsId)
            .all();
          vendorRows = r2.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        for (const v of vendorRows) {
          summary.total_vendors++;
          if (v.status === "active")   summary.active_vendors++;
          else                         summary.inactive_vendors++;
          const cat = v.category;
          if (cat in summary) summary[cat]++;
          const rl = v.risk_level;
          if (rl === "high")   summary.high_risk++;
          else if (rl === "medium") summary.medium_risk++;
          else if (rl === "low")    summary.low_risk++;
        }

        // Backward-compatible aliases used by the current frontend.
        summary.active = summary.active_vendors;
        summary.by_risk = {
          high: summary.high_risk,
          medium: summary.medium_risk,
          low: summary.low_risk,
        };

        return json(summary);
      }

      // ── GET /api/workspaces/:id/vendors ──
      const params    = url.searchParams;
      const filterStatus   = params.get("status");
      const filterRisk     = params.get("risk_level");
      const filterCategory = params.get("category");

      // Build WHERE clause dynamically
      const whereClauses = ["workspace_id = ?"];
      const binds        = [wsId];

      if (filterStatus)   { whereClauses.push("status = ?");     binds.push(filterStatus); }
      if (filterRisk)     { whereClauses.push("risk_level = ?"); binds.push(filterRisk); }
      if (filterCategory) { whereClauses.push("category = ?");   binds.push(filterCategory); }

      const whereSQL = whereClauses.join(" AND ");
      const scoredWhereSQL = whereSQL
        .replace(/\bworkspace_id\b/g, "wv.workspace_id")
        .replace(/\bstatus\b/g, "wv.status")
        .replace(/\brisk_level\b/g, "wv.risk_level")
        .replace(/\bcategory\b/g, "wv.category");

      let vendorRows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT wv.id, wv.vendor_name, wv.vendor_name AS name, wv.category,
                    wv.source, wv.evidence, wv.confidence,
                    wv.risk_level, wv.status, wv.first_seen, wv.last_seen,
                    wv.metadata_json,
                    vrs.score AS persisted_score,
                    vrs.category_multiplier,
                    vrs.concentration_penalty
             FROM workspace_vendors wv
             LEFT JOIN vendor_risk_scores vrs
               ON vrs.vendor_id = wv.id
              AND vrs.workspace_id = wv.workspace_id
             WHERE ${scoredWhereSQL}
             ORDER BY
               COALESCE(vrs.score, 0) DESC,
               CASE wv.risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               wv.vendor_name`
          )
          .bind(...binds)
          .all();
        vendorRows = r.results || [];
      } catch {
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT id, vendor_name, vendor_name AS name, category, source,
                      evidence, confidence, risk_level, status, first_seen,
                      last_seen, metadata_json
               FROM workspace_vendors
               WHERE ${whereSQL}
               ORDER BY
                 CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                 vendor_name`
            )
            .bind(...binds)
            .all();
          vendorRows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      const aggregate = computeWorkspaceVendorRisk(vendorRows);
      const vendors = aggregate.scored_vendors
        .slice()
        .sort((a, b) => b.score - a.score || String(a.vendor_name || a.name).localeCompare(String(b.vendor_name || b.name)))
        .map((row) => {
        const evidence = (() => { try { return JSON.parse(row.evidence); } catch { return []; } })();
        const sources = [...new Set([...(row._sources || []), ...getVendorSources(row)].filter(Boolean))];
        return {
          id: row.id,
          name: row.name || row.vendor_name,
          vendor_name: row.name || row.vendor_name,
          vendor_key: row.vendor_key || normalizeVendorKey(row.name || row.vendor_name),
          category: row.normalized_category || normalizeVendorRiskCategory(row.category, row.name || row.vendor_name, row.source),
          normalized_category: row.normalized_category || normalizeVendorRiskCategory(row.category, row.name || row.vendor_name, row.source),
          raw_category: row.category,
          source: row.source,
          sources,
          confidence: row.confidence,
          confidence_score: row.confidence_score ?? confidenceToScore(row.confidence),
          signal_weight: row.signal_weight ?? signalWeightForVendor(row),
          score: row.score ?? row.persisted_score ?? 0,
          category_multiplier: row.category_multiplier ?? 1,
          concentration_penalty: row.concentration_penalty ?? 0,
          risk_level: row.risk_level,
          status: row.status,
          first_seen: row.first_seen,
          last_seen: row.last_seen,
          evidence,
          metadata: (() => { try { return JSON.parse(row.metadata_json || "{}"); } catch { return {}; } })(),
        };
      });

      return json({
        workspace_id: wsId,
        count: vendors.length,
        vendors,
        top_vendors: aggregate.top_vendors.map((v) => ({
          id: v.id,
          name: v.vendor_name,
          vendor_key: v.vendor_key,
          category: v.normalized_category,
          score: v.score,
          risk_level: v.risk_level,
        })),
        concentration_risk: aggregate.concentration_risk,
        workspace_vendor_risk_score: aggregate.workspace_vendor_risk_score,
      });
    }


  return null;
}
