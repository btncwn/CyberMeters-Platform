// ── Workspace activity routes ──
// Audit-event listing/CSV-export and notification list/read/preferences
// endpoints. Extracted near-verbatim from index.js (router split, Phase 2 PR #6).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { alertEmailFrequencyForUser, ALERT_EMAIL_FREQUENCIES, ALERT_PREF_CRITICAL_ONLY, ALERT_PREF_EVENT } from "../engines/alert-gate.js";
import { getEffectivePlan, hasFeatureEntitlement } from "../engines/entitlements.js";
import { getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { createAuditEvent, sanitizeAuditMetadata } from "../lib/events.js";
import { createId, pageMeta, parseBoundedInteger } from "../lib/util.js";

export async function workspaceActivityRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole } = rctx;

    // ── GET /api/workspaces/:id/audit-events ─────────────────────────────────
    // Customer-facing compliance endpoint. Returns filtered, paginated audit events.
    // Access: admin or owner only (audit:read permission).
    // Metadata is sanitized — no secrets, tokens, or credentials returned.
    const auditEventsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/audit-events$/);
    if (auditEventsMatch && request.method === "GET") {
      const workspaceId = auditEventsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "audit:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // ── Feature gate: audit_logs — professional+ only ──────────────────────
      {
        const ownerId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
        const plan    = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, "audit_logs")) {
          return json({
            error:         "plan_feature_required",
            feature:       "audit_logs",
            required_plan: "professional",
            upgrade_url:   "/billing",
          }, 403);
        }
      }

      try {
        const limit       = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 100);
        const offset      = parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 100000);
        const eventType   = url.searchParams.get("event_type")   || null;
        const actorUserId = url.searchParams.get("actor_user_id") || null;
        const entityType  = url.searchParams.get("entity_type")  || null;
        const entityId    = url.searchParams.get("entity_id")    || null;
        const dateFrom    = url.searchParams.get("date_from")    || null;
        const dateTo      = url.searchParams.get("date_to")      || null;
        const search      = url.searchParams.get("search")       || null;

        // Build dynamic WHERE clauses
        const conditions = ["workspace_id = ?"];
        const binds      = [workspaceId];

        if (eventType)   { conditions.push("event_type = ?");   binds.push(eventType);   }
        if (actorUserId) { conditions.push("user_id = ?");      binds.push(actorUserId); }
        if (entityType)  { conditions.push("entity_type = ?");  binds.push(entityType);  }
        if (entityId)    { conditions.push("entity_id = ?");    binds.push(entityId);    }
        if (dateFrom)    { conditions.push("created_at >= ?");  binds.push(dateFrom);    }
        if (dateTo)      { conditions.push("created_at <= ?");  binds.push(dateTo + "T23:59:59.999Z"); }
        if (search) {
          conditions.push(
            "(event_type LIKE ? OR entity_type LIKE ? OR entity_id LIKE ? OR description LIKE ?)"
          );
          const q = `%${search.replace(/[%_]/g, "\$&")}%`;
          binds.push(q, q, q, q);
        }

        const whereClause = conditions.join(" AND ");

        // Count total matching rows
        const countRow = await env.cybermeters_db
          .prepare(`SELECT COUNT(*) AS total FROM audit_events WHERE ${whereClause}`)
          .bind(...binds)
          .first();
        const total = countRow?.total ?? 0;

        // Fetch page
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
             FROM audit_events
             WHERE ${whereClause}
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?`
          )
          .bind(...binds, limit, offset)
          .all();

        const events = (rows.results || []).map(r => ({
          id:            r.id,
          created_at:    r.created_at,
          event_type:    r.event_type,
          actor_user_id: r.user_id,
          workspace_id:  workspaceId,
          entity_type:   r.entity_type,
          entity_id:     r.entity_id,
          description:   r.description,
          metadata:      r.metadata_json ? sanitizeAuditMetadata(JSON.parse(r.metadata_json)) : null,
        }));

        // Enrich actor emails (batch lookup — no N+1)
        const userIds = [...new Set(events.map(e => e.actor_user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const ph = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, email, name FROM users WHERE id IN (${ph})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { email: u.email, name: u.name };
        }

        const enriched = events.map(e => ({
          ...e,
          actor_email: e.actor_user_id ? (userMap[e.actor_user_id]?.email ?? null) : null,
          actor_name:  e.actor_user_id ? (userMap[e.actor_user_id]?.name  ?? null) : null,
        }));

        // Non-fatal meta-audit event
        createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "audit_log_viewed",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  `Audit log viewed`,
          metadata:     { limit, offset, filters: { event_type: eventType, entity_type: entityType, search } },
        }).catch(() => {});

        return json({
          events: enriched,
          pagination: pageMeta({ items: enriched, limit, offset, total }),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/audit-events/export ──────────────────────────
    // CSV or JSON export of audit events. Same filters as the list endpoint.
    // Max 10,000 rows. Default 1,000.
    const auditExportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/audit-events\/export$/);
    if (auditExportMatch && request.method === "GET") {
      const workspaceId = auditExportMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "audit:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const format      = (url.searchParams.get("format") || "csv").toLowerCase();
        if (format !== "csv" && format !== "json") return json({ error: "format must be csv or json" }, 400);

        const exportLimit = parseBoundedInteger(url.searchParams.get("limit"), 1000, 1, 10000);
        const eventType   = url.searchParams.get("event_type")   || null;
        const actorUserId = url.searchParams.get("actor_user_id") || null;
        const entityType  = url.searchParams.get("entity_type")  || null;
        const entityId    = url.searchParams.get("entity_id")    || null;
        const dateFrom    = url.searchParams.get("date_from")    || null;
        const dateTo      = url.searchParams.get("date_to")      || null;
        const search      = url.searchParams.get("search")       || null;

        const conditions = ["workspace_id = ?"];
        const binds      = [workspaceId];

        if (eventType)   { conditions.push("event_type = ?");   binds.push(eventType);   }
        if (actorUserId) { conditions.push("user_id = ?");      binds.push(actorUserId); }
        if (entityType)  { conditions.push("entity_type = ?");  binds.push(entityType);  }
        if (entityId)    { conditions.push("entity_id = ?");    binds.push(entityId);    }
        if (dateFrom)    { conditions.push("created_at >= ?");  binds.push(dateFrom);    }
        if (dateTo)      { conditions.push("created_at <= ?");  binds.push(dateTo + "T23:59:59.999Z"); }
        if (search) {
          conditions.push(
            "(event_type LIKE ? OR entity_type LIKE ? OR entity_id LIKE ? OR description LIKE ?)"
          );
          const q = `%${search.replace(/[%_]/g, "\$&")}%`;
          binds.push(q, q, q, q);
        }

        const whereClause = conditions.join(" AND ");
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
             FROM audit_events
             WHERE ${whereClause}
             ORDER BY created_at DESC
             LIMIT ?`
          )
          .bind(...binds, exportLimit)
          .all();

        // Enrich with actor emails
        const rawEvents = rows.results || [];
        const userIds   = [...new Set(rawEvents.map(r => r.user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const ph = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, email, name FROM users WHERE id IN (${ph})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { email: u.email, name: u.name };
        }

        const events = rawEvents.map(r => ({
          id:            r.id,
          created_at:    r.created_at,
          event_type:    r.event_type,
          actor_user_id: r.user_id,
          actor_email:   r.user_id ? (userMap[r.user_id]?.email ?? null) : null,
          actor_name:    r.user_id ? (userMap[r.user_id]?.name  ?? null) : null,
          workspace_id:  workspaceId,
          entity_type:   r.entity_type,
          entity_id:     r.entity_id,
          description:   r.description,
          metadata:      r.metadata_json ? sanitizeAuditMetadata(JSON.parse(r.metadata_json)) : null,
        }));

        // Non-fatal meta-audit event
        createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "audit_log_exported",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  `Audit log exported as ${format.toUpperCase()} (${events.length} rows)`,
          metadata:     { format, rows: events.length },
        }).catch(() => {});

        if (format === "json") {
          const filters = { event_type: eventType, actor_user_id: actorUserId, entity_type: entityType,
                            entity_id: entityId, date_from: dateFrom, date_to: dateTo, search };
          return new Response(
            JSON.stringify({ exported_at: new Date().toISOString(), workspace_id: workspaceId, filters, events }, null, 2),
            { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="audit-log-${workspaceId}.json"` } }
          );
        }

        // CSV output
        function csvCell(v) {
          if (v === null || v === undefined) return "";
          const s = typeof v === "object" ? JSON.stringify(sanitizeAuditMetadata(v)) : String(v);
          if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
            return `"${s.replace(/"/g, '""')}"`;
          }
          return s;
        }
        const header = ["id", "created_at", "event_type", "actor_user_id", "actor_email", "actor_name",
                         "entity_type", "entity_id", "description", "metadata"];
        const csvRows = [header.join(",")];
        for (const e of events) {
          csvRows.push([
            csvCell(e.id), csvCell(e.created_at), csvCell(e.event_type),
            csvCell(e.actor_user_id), csvCell(e.actor_email), csvCell(e.actor_name),
            csvCell(e.entity_type), csvCell(e.entity_id), csvCell(e.description),
            csvCell(e.metadata),
          ].join(","));
        }
        return new Response(csvRows.join("\r\n"), {
          headers: {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": `attachment; filename="audit-log-${workspaceId}.csv"`,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/notifications ────────────────────────────────
    const notifListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notifications$/);
    if (notifListMatch && request.method === "GET") {
      const workspaceId = notifListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      // If the user is authenticated but not a member of this workspace
      // (e.g. stale localStorage workspace ID, invited workspace that no longer
      // exists, or first login before any workspace is created), return an empty
      // notification list rather than 403. A 403 here is never actionable by the
      // client and causes noisy console errors with no user-visible explanation.
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) {
        return json({
          workspace_id:  workspaceId,
          unread_count:  0,
          count:         0,
          notifications: [],
        });
      }
      try {
        const limit  = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const status = url.searchParams.get("status") || null; // 'unread' | 'read' | null (all)
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        // Scope to this user's view: workspace-global notifications (user_id IS
        // NULL) are visible to every member; user-specific ones only to their
        // owner. Without this a member sees — and can mark read — another
        // member's private notifications.
        let query, binds;
        if (status) {
          query  = `SELECT id, type, severity, title, message, metadata_json, status, created_at, read_at
                    FROM notification_events
                    WHERE workspace_id = ? AND status = ? AND (user_id IS NULL OR user_id = ?)
                    ORDER BY created_at DESC LIMIT ?`;
          binds  = [workspaceId, status, user.id, limit];
        } else {
          query  = `SELECT id, type, severity, title, message, metadata_json, status, created_at, read_at
                    FROM notification_events
                    WHERE workspace_id = ? AND (user_id IS NULL OR user_id = ?)
                    ORDER BY created_at DESC LIMIT ?`;
          binds  = [workspaceId, user.id, limit];
        }

        const [rows, unreadRow] = await env.cybermeters_db.batch([
          env.cybermeters_db.prepare(query).bind(...binds),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM notification_events WHERE workspace_id = ? AND status = 'unread' AND (user_id IS NULL OR user_id = ?)")
            .bind(workspaceId, user.id),
        ]);

        const notifications = (rows.results || []).map(n => ({
          ...n,
          metadata: n.metadata_json ? (() => { try { return JSON.parse(n.metadata_json); } catch { return null; } })() : null,
          metadata_json: undefined,
        }));

        return json({
          workspace_id:   workspaceId,
          unread_count:   unreadRow.results?.[0]?.cnt ?? 0,
          count:          notifications.length,
          notifications,
          pagination:     pageMeta({ items: notifications, limit, offset: 0 }),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/workspaces/:id/notifications/:notifId/read ─────────────────
    const notifReadMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notifications\/([^/]+)\/read$/);
    if (notifReadMatch && request.method === "POST") {
      const workspaceId  = notifReadMatch[1];
      const notifId      = notifReadMatch[2];
      const notifUser = await requireAuth(request, env);
      if (!notifUser) return json({ error: "Unauthorized" }, 401);
      const notifAccess = await requireWorkspaceRole(notifUser, workspaceId, "notification:mark_read", env);
      if (!notifAccess) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        if (notifId === "all") {
          // Mark all unread notifications visible to THIS user as read — global
          // ones plus their own, never another member's user-specific ones.
          await env.cybermeters_db
            .prepare(`UPDATE notification_events SET status = 'read', read_at = datetime('now')
                      WHERE workspace_id = ? AND status = 'unread' AND (user_id IS NULL OR user_id = ?)`)
            .bind(workspaceId, notifUser.id)
            .run();
          // Audit: bulk mark read
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      notifUser?.id ?? null,
            event_type:   "notification_read",
            entity_type:  "notification",
            description:  "All notifications marked as read",
            metadata:     { bulk: true },
          });
          return json({ success: true, marked: "all" });
        }
        // Mark a specific notification as read — only if it is global or the
        // caller's own, so a member cannot read-off another member's private one.
        const row = await env.cybermeters_db
          .prepare("SELECT id FROM notification_events WHERE id = ? AND workspace_id = ? AND (user_id IS NULL OR user_id = ?)")
          .bind(notifId, workspaceId, notifUser.id)
          .first();
        if (!row) return json({ error: "Notification not found" }, 404);
        await env.cybermeters_db
          .prepare(`UPDATE notification_events SET status = 'read', read_at = datetime('now') WHERE id = ?`)
          .bind(notifId)
          .run();
        // Audit: single notification read
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      notifUser?.id ?? null,
          event_type:   "notification_read",
          entity_type:  "notification",
          entity_id:    notifId,
          description:  "Notification marked as read",
        });
        return json({ success: true, id: notifId });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/notification-preferences ────────────────────
    // Returns the current user's notification preferences for this workspace.
    // Defaults (no rows) are treated as "all_alerts" — absence of a preference is
    // not a preference, and silently defaulting monitoring off would be its own
    // dishonesty.
    //
    // Response: {
    //   workspace_id, user_id,
    //   email_frequency: 'all_alerts' | 'critical_only' | 'disabled',
    //   supported: string[]   // the canonical list, so a client cannot offer a
    //                         // choice this endpoint will reject
    // }
    //
    // Resolved by alertEmailFrequencyForUser (engines/alert-gate.js) — the SAME
    // function the alert pipeline calls, so what this endpoint reports is by
    // construction what will actually happen. It previously derived the value from
    // a private vocabulary {critical_finding, high_finding, daily_digest,
    // email_alerts} that no engine ever read.
    const notifPrefsGetMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notification-preferences$/);
    if (notifPrefsGetMatch && request.method === "GET") {
      const workspaceId = notifPrefsGetMatch[1];
      const prefUser = await requireAuth(request, env);
      if (!prefUser) return json({ error: "Unauthorized" }, 401);
      const prefAccess = await requireWorkspaceRole(prefUser, workspaceId, "workspace:read", env);
      if (!prefAccess) return json({ error: "Forbidden" }, 403);
      try {
        // Read through the SAME resolver the alert pipeline uses, so what the
        // customer is shown here is by construction what will actually happen.
        //
        // The old derivation read a private vocabulary
        // {critical_finding, high_finding, daily_digest, email_alerts} that no
        // engine ever consulted — the page reported a setting the pipeline had
        // never heard of. It also had a dead branch: both arms of its final
        // ternary returned "all_alerts".
        const pref = await alertEmailFrequencyForUser(env, workspaceId, prefUser.id);
        if (!pref.ok) return serverError("api", new Error("preference lookup failed"));

        return json({
          workspace_id:    workspaceId,
          user_id:         prefUser.id,
          email_frequency: pref.frequency,
          // The supported set, so the client cannot offer a choice the backend
          // will reject. `daily_digest` is deliberately absent — see alert-gate.js.
          supported:       ALERT_EMAIL_FREQUENCIES,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PUT /api/workspaces/:id/notification-preferences ────────────────────
    // Updates the current user's notification email frequency preference.
    //
    // Body: { email_frequency: 'all_alerts' | 'critical_only' | 'disabled' }
    //
    // Upserts the canonical per-user rows into notification_preferences. Anything
    // outside the supported set is rejected, never coerced.
    if (notifPrefsGetMatch && request.method === "PUT") {
      const workspaceId = notifPrefsGetMatch[1];
      const prefPutUser = await requireAuth(request, env);
      if (!prefPutUser) return json({ error: "Unauthorized" }, 401);
      const prefPutAccess = await requireWorkspaceRole(prefPutUser, workspaceId, "workspace:read", env);
      if (!prefPutAccess) return json({ error: "Forbidden" }, 403);
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

        // Closed set, shared with the alert gate and echoed by the GET. Anything
        // else — including the removed `daily_digest` — is rejected outright and
        // never coerced into a neighbouring behaviour: silently treating an
        // unsupported choice as "send" is how a preference control starts lying.
        const { email_frequency } = body;
        if (!ALERT_EMAIL_FREQUENCIES.includes(email_frequency)) {
          return json({
            error: `email_frequency must be one of: ${ALERT_EMAIL_FREQUENCIES.join(", ")}`,
            code: "unsupported_email_frequency",
          }, 400);
        }

        // Write the CANONICAL vocabulary — the exact rows the pipeline reads.
        // Two booleans encode the three states (see alert-gate.js); the table
        // stores no value column and this episode ships no migration.
        //
        // These rows are per-user (user_id = the caller): one member silencing
        // their own email must not silence a colleague's.
        const prefs = {
          [ALERT_PREF_EVENT]:         email_frequency !== "disabled" ? 1 : 0,
          [ALERT_PREF_CRITICAL_ONLY]: email_frequency === "critical_only" ? 1 : 0,
        };

        const now = new Date().toISOString();
        const upserts = Object.entries(prefs).map(([event_type, enabled]) =>
          env.cybermeters_db
            .prepare(
              `INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
               VALUES (?, ?, ?, ?, ?, 'email', ?)
               ON CONFLICT (workspace_id, user_id, event_type, channel)
               DO UPDATE SET enabled = excluded.enabled`
            )
            .bind(createId("np"), workspaceId, prefPutUser.id, event_type, enabled, now)
        );

        await env.cybermeters_db.batch(upserts);

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      prefPutUser.id,
          event_type:   "notification_preferences_updated",
          entity_type:  "notification_preferences",
          description:  `Email notification frequency set to ${email_frequency}`,
          metadata:     { email_frequency },
        });

        return json({ success: true, workspace_id: workspaceId, email_frequency });
      } catch (e) {
        return serverError("api", e);
      }
    }


  return null;
}
