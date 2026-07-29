// ── Workspaces core routes ──
// Workspace detail (with inline statistics) / rename / stats, workspace-domain
// link add/remove/list, and the workspace delete-request / restore lifecycle.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #11).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { getCurrentPosturePresentation } from "../engines/current-posture.js";
import { domainLimitRejection, getAccountUsage, getEffectiveDomainState, getEntitlementUsage, getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { createAuditEvent } from "../lib/events.js";
import { escapeEmailHtml, sendCustomerEmail, sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { createId, isValidDomain, isValidEmail } from "../lib/util.js";
import {
  phase5EvidenceReadCoverage,
  projectPhase5ScanRowsForCustomer,
  resolvePhase5CustomerAggregate,
} from "../engines/phase5-evidence.js";

export async function workspacesCoreRoutes(rctx) {
  const { request, env, ctx, url, json, serverError,
          requireAuth, requireWorkspaceRole, DELETION_PURGE_WINDOW_DAYS } = rctx;

    // Routes that carry a workspace ID
    // Matches:  /api/workspaces/:id
    //           /api/workspaces/:id/domains
    //           /api/workspaces/:id/domains/:domainId
    //           /api/workspaces/:id/stats
    const wsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)(\/domains(?:\/([^/]+))?|\/stats)?$/
    );

    if (wsMatch) {
      const workspaceId   = wsMatch[1];
      const subResource   = wsMatch[2];          // "/domains", "/domains/:id", "/stats", or undefined
      const linkedDomainId = wsMatch[3];         // domain ID component if present

      // Authenticate and authorize before looking up the workspace so callers
      // cannot distinguish inaccessible workspace IDs from nonexistent ones.
      const wsUser = await requireAuth(request, env);
      if (!wsUser) return json({ error: "Unauthorized" }, 401);
      const wsAccess = await requireWorkspaceRole(wsUser, workspaceId, "workspace:read", env);
      if (!wsAccess) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists for all sub-routes
      let workspace;
      try {
        workspace = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces WHERE id = ?`)
          .bind(workspaceId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!workspace) {
        return json({ error: "Workspace not found" }, 404);
      }

      // ── GET /api/workspaces/:id ── (with inline statistics) ──────────
      if (request.method === "GET" && !subResource) {
        try {
          const [domainsRow, scansRow, avgRow, latestRow] = await Promise.all([
            // total_domains
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`)
              .bind(workspaceId).first(),

            // total_scans — the workspace's own RETAINED scan total (lifetime),
            // including scans whose domains were later removed and are no longer in
            // workspace_domains. Tenant-safe by construction:
            //   • branch 1 counts only scans directly attributed to THIS workspace_id
            //     (ownership; never a foreign scan, never hostname-only);
            //   • branch 2 counts historical UNATTRIBUTED (workspace_id IS NULL) scans
            //     for domains CURRENTLY monitored by this workspace.
            // The earlier INNER JOIN to workspace_domains under-counted, because it
            // dropped a workspace's own scans once their domain was removed — the
            // "Total Scans: 12 (should be 22)" defect. No hostname join, no global
            // fallback, no migration, same response field.
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(DISTINCT s.id) AS n
                 FROM scans s
                 WHERE s.workspace_id = ?
                    OR (
                      s.workspace_id IS NULL
                      AND s.domain_id IN (
                        SELECT domain_id FROM workspace_domains WHERE workspace_id = ?
                      )
                    )`
              )
              .bind(workspaceId, workspaceId).first(),

            // Latest complete candidate per domain. The average is calculated
            // only after each row is projected through immutable Phase-5
            // evidence below.
            env.cybermeters_db
              .prepare(
                `SELECT id, score, rating, scan_quality, created_at, status
                 FROM (
                   SELECT s.id, s.score, s.rating, s.scan_quality, s.created_at,
                          s.status,
                          ROW_NUMBER() OVER (
                            PARTITION BY s.domain_id
                            ORDER BY s.created_at DESC, s.id DESC
                          ) AS rn
                   FROM scans s
                   JOIN domains d ON d.id = s.domain_id
                   JOIN workspace_domains wd ON wd.domain_id = d.id
                   WHERE (
                     s.workspace_id = ?
                     OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
                   )
                     AND s.status = 'completed'
                     AND s.score IS NOT NULL
                     AND s.scan_quality = 'complete'
                 )
                 WHERE rn = 1`
              )
              .bind(workspaceId, workspaceId).all(),

            // latest_scan — direct attribution + fallback for NULL workspace_id
            env.cybermeters_db
              .prepare(
                `SELECT s.id, s.domain, s.status, s.score, s.rating, s.scan_quality, s.created_at
                 FROM scans s
                 JOIN domains d ON d.id = s.domain_id
                 JOIN workspace_domains wd ON wd.domain_id = d.id
                 WHERE (
                   s.workspace_id = ?
                   OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
                 )
                 ORDER BY s.created_at DESC
                 LIMIT 1`
              )
              .bind(workspaceId, workspaceId).first(),
          ]);

          // Canonical authoritative posture (latest COMPLETE scan) — the client
          // renders THIS as the Cyber Score KPI + rating, never a rating derived
          // from the raw average, so a partial-heavy workspace shows
          // "Current posture not yet established" instead of a clean grade.
          let posture = null;
          try { posture = await getCurrentPosturePresentation(env, { workspaceId }); } catch { /* tolerate */ }
          const averageRows = await projectPhase5ScanRowsForCustomer(
            env,
            avgRow?.results ?? [],
          );
          const average = resolvePhase5CustomerAggregate(averageRows);
          const customerAverage = average.score == null
            ? null
            : Math.round(average.score * 10) / 10;
          const [customerLatest] = await projectPhase5ScanRowsForCustomer(
            env,
            latestRow ? [latestRow] : [],
          );

          return json({
            workspace: {
              id:         workspace.id,
              name:       workspace.name,
              created_at: workspace.created_at,
              // Caller's role in this workspace (additive) — the frontend gates the
              // owner-only Danger Zone on this. Authorisation is still enforced
              // server-side by the delete-request route (owner-only), never by the UI.
              role:       wsAccess?.role ?? null,
            },
            stats: {
              total_domains:       domainsRow?.n ?? 0,
              total_scans:         scansRow?.n  ?? 0,
              cyber_score_average: customerAverage,
              cyber_score_evidence_coverage: average.evidence_coverage,
              latest_scan:         customerLatest ?? null,
              // Completeness-aware headline posture.
              posture_established: posture?.state === "established",
              posture_score:       posture?.authoritative?.display_score  ?? null,
              posture_rating:      posture?.authoritative?.display_rating ?? null,
              posture_message:     posture?.posture_message ?? null,
            },
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── PATCH /api/workspaces/:id ─────────────────────────────────────────
      // Renames the workspace. Requires admin role or above.
      if (request.method === "PATCH" && !subResource) {
        const patchAccess = await requireWorkspaceRole(wsUser, workspaceId, "workspace:manage", env);
        if (!patchAccess) return json({ error: "Forbidden — admin role required to rename workspace" }, 403);
        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
        const newName = (body?.name ?? "").trim();
        if (!newName) return json({ error: "name is required" }, 400);
        if (newName.length > 100) return json({ error: "name must be 100 characters or fewer" }, 400);
        const oldName = workspace.name;
        try {
          await env.cybermeters_db
            .prepare(`UPDATE workspaces SET name = ?, updated_at = datetime('now') WHERE id = ? AND deleted_at IS NULL`)
            .bind(newName, workspaceId)
            .run();
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "workspace_renamed",
            entity_type:  "workspace",
            entity_id:    workspaceId,
            description:  `Workspace renamed from "${oldName}" to "${newName}"`,
            metadata:     { name: newName, old_name: oldName },
          });
          return json({ workspace: { id: workspaceId, name: newName } });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── DELETE /api/workspaces/:id/domains/:domainId ──────────────────
      // Removes the workspace↔domain link only. Domain row is untouched.
      if (request.method === "DELETE" && subResource && linkedDomainId) {
        const delAccess = await requireWorkspaceRole(wsUser, workspaceId, "domain:remove", env);
        if (!delAccess) return json({ error: "Forbidden — admin role required to remove domains" }, 403);
        try {
          let domainRow = null;
          try {
            domainRow = await env.cybermeters_db
              .prepare("SELECT d.id, d.domain FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ? AND wd.domain_id = ? LIMIT 1")
              .bind(workspaceId, linkedDomainId)
              .first();
          } catch { /* audit metadata lookup only */ }
          const del = await env.cybermeters_db
            .prepare(
              `DELETE FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?`
            )
            .bind(workspaceId, linkedDomainId)
            .run();
          if (del.meta.changes === 0) {
            return json({ error: "Domain link not found" }, 404);
          }

          // ── Cascade cleanup ─────────────────────────────────────────────
          // Disable scheduled scans and deactivate assets/brand candidates
          // for this domain within this workspace. Use fire-and-forget so
          // cascade failures never block the 200 response.
          if (domainRow?.domain) {
            env.cybermeters_db
              .prepare(`UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = ? AND domain = ?`)
              .bind(workspaceId, domainRow.domain)
              .run()
              .catch(e => console.error("[domain_remove_cascade] scheduled_scans:", e?.message));
            env.cybermeters_db
              .prepare(`UPDATE workspace_brand_assets SET status = 'inactive', updated_at = datetime('now') WHERE workspace_id = ? AND domain = ?`)
              .bind(workspaceId, domainRow.domain)
              .run()
              .catch(e => console.error("[domain_remove_cascade] brand_assets:", e?.message));
          }
          env.cybermeters_db
            .prepare(`UPDATE workspace_assets SET status = 'inactive', updated_at = datetime('now') WHERE workspace_id = ? AND domain_id = ?`)
            .bind(workspaceId, linkedDomainId)
            .run()
            .catch(e => console.error("[domain_remove_cascade] workspace_assets:", e?.message));

          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "domain_removed",
            entity_type:  "domain",
            entity_id:    linkedDomainId,
            description:  `Domain ${domainRow?.domain || linkedDomainId} removed from workspace`,
            metadata:     { domain: domainRow?.domain || null, domain_id: linkedDomainId },
          });
          return json({ success: true, workspace_id: workspaceId, domain_id: linkedDomainId });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/domains ───────────────────────────────
      // Returns linked domains enriched with latest scan data per domain.
      if (request.method === "GET" && subResource === "/domains") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT
                 d.id                        AS domain_id,
                 d.domain,
                 -- Verification state comes from the workspace_domains LINK, which
                 -- migration 079 made authoritative and which the scan gate reads
                 -- (isWorkspaceDomainVerified). The legacy domains.verification_*
                 -- columns are read-only compatibility data and are per-USER, not
                 -- per-workspace — reading them here made this list report a
                 -- verification state the scan gate does not honour, so a domain
                 -- could show "verified" while every scan was refused (and the
                 -- reverse). Same column names, authoritative source.
                 wd.verification_status,
                 wd.verification_method,
                 wd.verification_token,
                 wd.verified_at,
                 wd.verification_initiated_at,
                 s.id                        AS last_scan_id,
                 s.score                     AS latest_score,
                 s.rating                    AS latest_rating,
                 s.scan_quality              AS latest_scan_quality,
                 s.status                    AS latest_status,
                 s.created_at               AS last_scanned_at
               FROM workspace_domains wd
               JOIN   domains d ON d.id = wd.domain_id
               LEFT JOIN scans s ON s.id = (
                 SELECT id FROM scans
                 WHERE  domain_id = d.id
                 ORDER  BY created_at DESC LIMIT 1
               )
               WHERE wd.workspace_id = ?
               ORDER BY d.domain ASC`
            )
            .bind(workspaceId)
            .all();
          const customerScans = await projectPhase5ScanRowsForCustomer(
            env,
            (result.results ?? []).map((row) => ({
              id: row.last_scan_id,
              status: row.latest_status,
              score: row.latest_score,
              rating: row.latest_rating,
              scan_quality: row.latest_scan_quality,
            })),
          );
          return json({
            workspace_id: workspaceId,
            domains: (result.results ?? []).map((row, index) => ({
              ...row,
              latest_score: customerScans[index]?.score ?? null,
              latest_rating: customerScans[index]?.rating ?? null,
              latest_scan_quality:
                customerScans[index]?.scan_quality ?? row.latest_scan_quality ?? null,
            })),
            phase5_evidence_coverage:
              phase5EvidenceReadCoverage(customerScans),
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── POST /api/workspaces/:id/domains ─────────────────────────────
      // Reuse existing domain row if present; create new one otherwise.
      // Idempotent link via INSERT OR IGNORE.
      if (request.method === "POST" && subResource === "/domains") {
        // RBAC: admin or above required to add domains
        // wsUser is already authenticated by the wsMatch guard above
        const addDomAccess = await requireWorkspaceRole(wsUser, workspaceId, "domain:add", env);
        if (!addDomAccess) return json({ error: "Forbidden — admin role required to add domains" }, 403);
        let body;
        try { body = await request.json(); } catch { body = {}; }
        const raw = (body.domain || "").trim().toLowerCase();
        if (!isValidDomain(raw)) {
          return json({ error: "domain is required and must be a valid domain" }, 400);
        }
        try {
          // Entitlement: per-workspace limit + account-level cross-workspace limit.
          // Trial-aware (trial = 1 domain) and business-aware honest rejection.
          const domainBillingUserId = await getWorkspaceBillingUserId(workspaceId, wsUser.id, env);
          const domState = await getEffectiveDomainState(domainBillingUserId, env);
          const domUsage  = await getEntitlementUsage(wsUser, env, workspaceId);
          // (a) Per-workspace limit
          if (domUsage.domains_in_workspace >= domState.domains) {
            return json(domainLimitRejection(domState.plan, domState.is_trial, domState.domains, domUsage.domains_in_workspace), 403);
          }
          // (b) Account-level limit: total unique domains across all owned workspaces.
          //     Uses the billing owner's workspace set so non-owner members are scoped correctly.
          const domOwnerAcct = await getAccountUsage(domainBillingUserId, env);
          if (domOwnerAcct.domains >= domState.domains) {
            return json(domainLimitRejection(domState.plan, domState.is_trial, domState.domains, domOwnerAcct.domains), 403);
          }

          // Scoped by user_id to prevent cross-user domain aliasing.
          let domainRow = await env.cybermeters_db
            .prepare(`SELECT id, domain FROM domains WHERE domain = ? AND user_id = ? LIMIT 1`)
            .bind(raw, wsUser.id)
            .first();

          if (!domainRow) {
            const newId = createId("domain");
            await env.cybermeters_db
              .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
              .bind(newId, wsUser.id, raw)
              .run();
            domainRow = { id: newId, domain: raw };
          }

          const linkRes = await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)`
            )
            .bind(workspaceId, domainRow.id)
            .run();
          // A genuinely new workspace↔domain link (not a duplicate/no-op add).
          const newlyLinked = (linkRes.meta?.changes ?? 0) > 0;

          // Audit: domain added
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "domain_added",
            entity_type:  "domain",
            entity_id:    domainRow.id,
            description:  `Domain ${domainRow.domain} added to workspace`,
            metadata:     { domain: domainRow.domain, domain_id: domainRow.id },
          });

          // Lifecycle: domain added — only on a real new link; deduped once per
          // workspace+domain; delivered to the workspace owner's verified email.
          // Non-blocking via waitUntil; never throws.
          if (newlyLinked) {
            ctx.waitUntil(sendLifecycleEmail(env, {
              type: "lifecycle_domain_added",
              workspace_id: workspaceId,
              domain: domainRow.domain,
            }).catch(() => {}));
          }

          return json(
            { domain: { domain_id: domainRow.id, domain: domainRow.domain, workspace_id: workspaceId } },
            201
          );
        } catch {
          return json({ error: "Database error" }, 500);
        }
	      }
	    }
	
	    // ── POST /api/workspaces/:id/delete-request ─────────────────────────
	    const workspaceDeleteRequestMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/delete-request$/);
	    if (workspaceDeleteRequestMatch && request.method === "POST") {
	      const workspaceId = workspaceDeleteRequestMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
	      const access = await requireWorkspaceRole(user, workspaceId, "workspace:delete", env);
	      if (!access) return json({ error: "Forbidden — owner role required to request workspace deletion" }, 403);
	      try {
	        const workspace = await env.cybermeters_db
	          .prepare("SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL LIMIT 1")
	          .bind(workspaceId)
	          .first();
	        if (!workspace) return json({ error: "Workspace not found" }, 404);

	        const now = new Date().toISOString();

	        // Soft-delete the workspace
	        await env.cybermeters_db
	          .prepare("UPDATE workspaces SET deleted_at = ? WHERE id = ?")
	          .bind(now, workspaceId)
	          .run();

	        // Disable all scheduled scans for this workspace
	        await env.cybermeters_db
	          .prepare("UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = ?")
	          .bind(workspaceId)
	          .run();

	        // Archive active assets for this workspace (preserve history per Rule 5)
	        await env.cybermeters_db
	          .prepare("UPDATE workspace_assets SET status = 'inactive' WHERE workspace_id = ? AND status = 'active'")
	          .bind(workspaceId)
	          .run();

	        // Schedule the hard purge: one pending request per workspace. The
	        // purge cron only acts DELETION_PURGE_WINDOW_DAYS after created_at,
	        // so the owner can restore any time before then.
	        const existingReq = await env.cybermeters_db
	          .prepare("SELECT id FROM deletion_requests WHERE request_type = 'workspace' AND workspace_id = ? AND status IN ('pending', 'purging') LIMIT 1")
	          .bind(workspaceId)
	          .first()
	          .catch(() => null);
	        if (!existingReq) {
	          await env.cybermeters_db
	            .prepare(`INSERT INTO deletion_requests
	                        (id, request_type, user_id, workspace_id, requested_by, status, created_at, updated_at)
	                      VALUES (?, 'workspace', ?, ?, ?, 'pending', ?, ?)`)
	            .bind(createId("delreq"), user.id, workspaceId, user.id, now, now)
	            .run()
	            .catch(() => {});
	        }
	        const purgeAfter = new Date(Date.now() + DELETION_PURGE_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();

	        await createAuditEvent(env, {
	          workspace_id: workspaceId,
	          user_id: user.id,
	          event_type: "workspace_deleted",
	          entity_type: "workspace",
	          entity_id: workspaceId,
	          description: `Workspace "${workspace.name}" soft-deleted; permanent deletion scheduled`,
	          metadata: { deleted_at: now, purge_after: purgeAfter },
	        }).catch(() => {});

	        // Confirmation email — states the restore window honestly.
	        try {
	          if (user.email && isValidEmail(String(user.email).toLowerCase())) {
	            const wsName = escapeEmailHtml(workspace.name);
	            const untilDay = new Date(purgeAfter).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
	            const text = `Your CyberMeters workspace was deleted\n\nThe workspace "${workspace.name}" has been deleted and is no longer visible in CyberMeters.\n\nIts data will be permanently removed after ${untilDay}. Until then you can restore the workspace by contacting support or using the restore option.\n\nCyberMeters`;
	            const html = `<p>The workspace <strong>${wsName}</strong> has been deleted and is no longer visible in CyberMeters.</p><p>Its data will be permanently removed after <strong>${untilDay}</strong>. Until then you can restore the workspace by contacting support or using the restore option.</p><p>CyberMeters</p>`;
	            await sendCustomerEmail("Your CyberMeters workspace was deleted", text, html, env, "HELLO_EMAIL_FROM", [String(user.email).toLowerCase()]);
	          }
	        } catch { /* deletion must succeed even if the email cannot be sent */ }

	        return json({ deleted: true, workspace_id: workspaceId, deleted_at: now, purge_after: purgeAfter, restorable_until: purgeAfter });
	      } catch {
	        return json({ error: "Unable to delete workspace" }, 500);
	      }
	    }

	    // ── POST /api/workspaces/:id/restore ─────────────────────────────────────
    // Undo a soft-delete inside the purge window. Owner-only; authorized
    // directly against the workspaces row because role resolution may exclude
    // deleted workspaces. Once purging has started, restore is refused.
    const workspaceRestoreMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/restore$/);
    if (workspaceRestoreMatch && request.method === "POST") {
      const workspaceId = workspaceRestoreMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id, name, owner_user_id, deleted_at FROM workspaces WHERE id = ? LIMIT 1")
          .bind(workspaceId)
          .first();
        // Authorize BEFORE revealing existence: a nonexistent workspace and a
        // foreign workspace owned by another tenant both return an identical 403,
        // so a caller cannot probe which soft-deleted workspace ids exist. (Restore
        // is owner-only; the canonical role helper can't resolve soft-deleted rows,
        // so the owner check is genuinely route-local — see below.) The remaining
        // checks run only after ownership is proven, so they are not an oracle.
        if (!ws || ws.owner_user_id !== user.id) return json({ error: "Forbidden" }, 403);
        if (!ws.deleted_at) return json({ error: "Workspace is not deleted" }, 400);

        const delReq = await env.cybermeters_db
          .prepare("SELECT id, status, created_at FROM deletion_requests WHERE request_type = 'workspace' AND workspace_id = ? AND status IN ('pending', 'purging') ORDER BY created_at DESC LIMIT 1")
          .bind(workspaceId)
          .first()
          .catch(() => null);
        if (delReq?.status === "purging") {
          return json({ error: "This workspace can no longer be restored — permanent deletion has already started." }, 409);
        }
        const deletedAtMs = new Date(ws.deleted_at).getTime();
        if (!Number.isNaN(deletedAtMs) && Date.now() > deletedAtMs + DELETION_PURGE_WINDOW_DAYS * 24 * 60 * 60 * 1000) {
          return json({ error: "The restore window for this workspace has passed." }, 409);
        }

        await env.cybermeters_db
          .prepare("UPDATE workspaces SET deleted_at = NULL WHERE id = ?")
          .bind(workspaceId)
          .run();
        if (delReq?.id) {
          await env.cybermeters_db
            .prepare("UPDATE deletion_requests SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?")
            .bind(delReq.id)
            .run()
            .catch(() => {});
        }

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id: user.id,
          event_type: "workspace_restored",
          entity_type: "workspace",
          entity_id: workspaceId,
          description: `Workspace "${ws.name}" restored within the deletion window`,
          metadata: { deletion_request_id: delReq?.id ?? null },
        }).catch(() => {});

        // Schedules stay disabled and archived assets stay inactive — the
        // owner re-enables what they still need.
        return json({ restored: true, workspace_id: workspaceId, note: "Scheduled scans remain paused and archived assets remain inactive; re-enable them as needed." });
      } catch {
        return json({ error: "Unable to restore workspace" }, 500);
      }
    }


  return null;
}
