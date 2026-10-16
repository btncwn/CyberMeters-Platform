// ── Workspaces core routes ──
// Workspace detail (with inline statistics) / rename / stats, workspace-domain
// link add/remove/list, and the workspace delete-request / restore lifecycle.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #11).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { getCurrentPosturePresentation } from "../engines/current-posture.js";
import { resolveAssessmentPresentation } from "../engines/assessment-presentation.js";
import { domainLimitRejection, getAccountUsage, getEffectiveDomainState, getEntitlementUsage, getOwnedWorkspaceIds, getPlanLimits, getWorkspaceBillingUserId, planLimitExceeded } from "../engines/plan-usage.js";
import { getEffectiveDomainLimit, getEffectivePlanState } from "../engines/entitlements.js";
import { createAuditEvent } from "../lib/events.js";
import { escapeEmailHtml, sendCustomerEmail, sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { canonicalDomainInput, createId, isValidDomain, isValidEmail } from "../lib/util.js";
import { drainRevokedMcpOAuthGrantBacklog, prepareMcpOAuthWorkspaceRevocation } from "./mcp-oauth-purge.js";
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
        if (body?.name != null && typeof body.name !== "string") return json({ error: "name must be a string" }, 400);
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
              .prepare(`UPDATE workspace_brand_assets
                           SET status = 'inactive', updated_at = datetime('now')
                         WHERE workspace_id = ? AND domain = ?
                           AND EXISTS (
                                 SELECT 1 FROM workspaces w
                                  WHERE w.id = workspace_brand_assets.workspace_id
                                    AND w.deleted_at IS NULL
                               )`)
              .bind(workspaceId, domainRow.domain)
              .run()
              .catch(e => console.error("[domain_remove_cascade] brand_assets:", e?.message));
          }
          // Stored sign-in credentials for this domain are destroyed with the
          // link (awaited: credentials must not outlive the domain's scope).
          // Scans and routes refuse an unlinked domain regardless.
          try {
            await env.cybermeters_db
              .prepare(`DELETE FROM website_sign_in_profiles WHERE workspace_id = ? AND domain_id = ?`)
              .bind(workspaceId, linkedDomainId)
              .run();
          } catch (e) { console.error("[domain_remove_cascade] website_sign_in_profiles:", e?.message); }
          // A hostname list belongs to the domain link: it ends with it
          // (marked cleared, kept as history). Scans refuse an unlinked domain.
          try {
            await env.cybermeters_db
              .prepare(`UPDATE discovery_hostname_lists SET status = 'cleared', ended_at = ?, ended_by = ?
                         WHERE workspace_id = ? AND domain_id = ? AND status = 'active'`)
              .bind(new Date().toISOString(), wsUser.id, workspaceId, linkedDomainId)
              .run();
          } catch (e) { console.error("[domain_remove_cascade] discovery_hostname_lists:", e?.message); }
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
                   AND (workspace_id = wd.workspace_id OR workspace_id IS NULL)
                 ORDER  BY created_at DESC, id DESC LIMIT 1
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
          const domains = (result.results ?? []).map((row, index) => {
            const customerScan = customerScans[index] ?? null;
            const latestAssessment = customerScan?.assessment ??
              resolveAssessmentPresentation({
                score: null,
                scanQuality: customerScan?.scan_quality ?? row.latest_scan_quality,
                status: customerScan?.status ?? row.latest_status,
              });
            return {
              ...row,
              // Compatibility fields remain additive for existing clients. New
              // customer renderers consume the canonical assessment object and
              // never reconstruct provisionality from these legacy aliases.
              latest_score: customerScan?.score ?? null,
              latest_rating: customerScan?.rating ?? null,
              latest_scan_quality:
                customerScan?.scan_quality ?? row.latest_scan_quality ?? null,
              latest_assessment: latestAssessment,
            };
          });
          return json({
            workspace_id: workspaceId,
            domains,
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
        // Canonical monitored domain: scheme/path/port stripped and a leading
        // "www." reduced to the apex, so a pasted URL or www-host can never
        // lock a one-domain trial onto the wrong name.
        const raw = canonicalDomainInput(body.domain, { stripWww: true });
        if (!raw || !isValidDomain(raw)) {
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

	        // The access fence is part of the same D1 transaction as deletion.
	        // Its queued KV cleanup runs only after that transaction commits.
	        const oauthRevocation = await prepareMcpOAuthWorkspaceRevocation(env, workspaceId);
	        // Schedule the hard purge: one pending request per workspace. The
	        // purge cron only acts DELETION_PURGE_WINDOW_DAYS after created_at,
	        // so the owner can restore any time before then.
	        const existingReq = await env.cybermeters_db
	          .prepare("SELECT id FROM deletion_requests WHERE request_type = 'workspace' AND workspace_id = ? AND status IN ('pending', 'purging') LIMIT 1")
	          .bind(workspaceId)
	          .first();
	        const db = env.cybermeters_db;
	        const changes = [
	          db.prepare("UPDATE workspaces SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
	            .bind(now, workspaceId),
	          ...(oauthRevocation ? [oauthRevocation] : []),
	          db.prepare("UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = ?")
	            .bind(workspaceId),
	          db.prepare("UPDATE workspace_assets SET status = 'inactive' WHERE workspace_id = ? AND status = 'active'")
	            .bind(workspaceId),
	        ];
	        if (!existingReq) {
	          changes.push(db.prepare(`INSERT INTO deletion_requests
	                        (id, request_type, user_id, workspace_id, requested_by, status, created_at, updated_at)
	                      VALUES (?, 'workspace', ?, ?, ?, 'pending', ?, ?)`)
	            .bind(createId("delreq"), user.id, workspaceId, user.id, now, now));
	        }
	        const results = await db.batch(changes);
	        if (Number(results?.[0]?.meta?.changes ?? 0) !== 1) {
	          return json({ error: "Workspace deletion could not be confirmed; please retry" }, 503);
	        }
	        if (oauthRevocation) {
	          await drainRevokedMcpOAuthGrantBacklog(env).catch((error) => {
	            console.error("[workspace-delete] OAuth cleanup queued", String(error?.message ?? error));
	          });
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
	        return json({ error: "Workspace deletion could not be completed; please retry" }, 503);
	      }
	    }

    // ── Restore-window clock ────────────────────────────────────────────────
    // The purge cron is due DELETION_PURGE_WINDOW_DAYS after the OLDEST open
    // workspace deletion request (isDeletionPurgeDue on created_at), which can
    // predate deleted_at when a delete re-used an old pending request. The
    // customer-facing deadline is therefore the earlier of the two; an
    // unparseable deleted_at has no honest deadline and is not restorable.
    const restoreWindowMs = DELETION_PURGE_WINDOW_DAYS * 24 * 60 * 60 * 1000;
    const restoreClockMs = (deletedAt, oldestPendingAt) => {
      const deletedMs = new Date(deletedAt).getTime();
      if (!deletedAt || Number.isNaN(deletedMs)) return NaN;
      const pendingMs = oldestPendingAt ? new Date(oldestPendingAt).getTime() : NaN;
      return Number.isNaN(pendingMs) ? deletedMs : Math.min(deletedMs, pendingMs);
    };

    // ── GET /api/account/deleted-workspaces ─────────────────────────────────
    // The owner's soft-deleted workspaces that can still be restored: inside the
    // purge window, with no workspace purge started or finished and no account
    // deletion in progress (an account purge destroys every owned workspace).
    // Session only, owner-scoped by owner_user_id, bounded. Read failures are a
    // 503, never an empty list that would hide a restorable workspace.
    if (request.method === "GET" && url.pathname === "/api/account/deleted-workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT w.id, w.name, w.deleted_at,
                    (SELECT MIN(p.created_at) FROM deletion_requests p
                      WHERE p.request_type = 'workspace' AND p.workspace_id = w.id
                        AND p.status = 'pending') AS oldest_pending_at
               FROM workspaces w
              WHERE w.owner_user_id = ?
                AND w.deleted_at IS NOT NULL
                AND julianday(w.deleted_at) > julianday('now', ?)
                AND NOT EXISTS (
                  SELECT 1 FROM deletion_requests d
                   WHERE d.request_type = 'workspace'
                     AND d.workspace_id = w.id
                     AND d.status IN ('purging', 'completed')
                )
                AND NOT EXISTS (
                  SELECT 1 FROM deletion_requests a
                   WHERE a.request_type = 'account'
                     AND a.user_id = ?
                     AND a.status IN ('pending', 'purging')
                )
              ORDER BY w.deleted_at DESC
              LIMIT 50`
          )
          .bind(user.id, `-${DELETION_PURGE_WINDOW_DAYS} days`, user.id)
          .all();
        const now = Date.now();
        const workspaces = [];
        for (const w of rows?.results || []) {
          const clock = restoreClockMs(w.deleted_at, w.oldest_pending_at);
          if (Number.isNaN(clock) || now >= clock + restoreWindowMs) continue;
          workspaces.push({
            id: w.id,
            name: w.name,
            deleted_at: w.deleted_at,
            restorable_until: new Date(clock + restoreWindowMs).toISOString(),
          });
        }
        return json({ workspaces, restore_window_days: DELETION_PURGE_WINDOW_DAYS });
      } catch {
        return json({ error: "Deleted workspaces are temporarily unavailable" }, 503);
      }
    }

    // ── POST /api/workspaces/:id/restore ─────────────────────────────────────
    // Undo a soft-delete inside the purge window. Owner-only; authorized
    // directly against the workspaces row because role resolution may exclude
    // deleted workspaces.
    //
    // Refused (409) when ANY workspace deletion request for it is purging or
    // completed, when an account deletion is in progress, when the deadline has
    // passed, or when deleted_at cannot be read. A failed read fails closed (503).
    //
    // The restore is ONE D1 batch (a single transaction): undelete the workspace
    // only if no purge has been claimed, then — only if it is live — cancel every
    // pending request, reactivate the assets and re-enable the schedules the
    // deletion switched off for domains still linked to the workspace. The purge
    // claim is a compare-and-swap on 'pending', so either the batch cancels the
    // requests first or the claim makes the guarded undelete change nothing:
    // exactly one side wins, and a partial restore cannot be committed.
    const workspaceRestoreMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/restore$/);
    if (workspaceRestoreMatch && request.method === "POST") {
      const workspaceId = workspaceRestoreMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
      const NO_LONGER = "This workspace can no longer be restored — permanent deletion has already started.";
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

        let requests, accountDeletion;
        try {
          requests = (await env.cybermeters_db
            .prepare("SELECT id, status, created_at FROM deletion_requests WHERE request_type = 'workspace' AND workspace_id = ? AND status IN ('pending', 'purging', 'completed')")
            .bind(workspaceId)
            .all())?.results || [];
          accountDeletion = await env.cybermeters_db
            .prepare("SELECT id FROM deletion_requests WHERE request_type = 'account' AND user_id = ? AND status IN ('pending', 'purging') LIMIT 1")
            .bind(user.id)
            .first();
        } catch {
          return json({ error: "Restore is temporarily unavailable. Please try again." }, 503);
        }
        if (requests.some((r) => r.status === "purging" || r.status === "completed")) {
          return json({ error: NO_LONGER }, 409);
        }
        if (accountDeletion) {
          return json({ error: "Your account is scheduled for deletion, so its workspaces cannot be restored." }, 409);
        }
        const pendingTimes = requests.filter((r) => r.status === "pending").map((r) => r.created_at).filter(Boolean).sort();
        const clock = restoreClockMs(ws.deleted_at, pendingTimes[0] ?? null);
        if (Number.isNaN(clock) || Date.now() >= clock + restoreWindowMs) {
          return json({ error: "The restore window for this workspace has passed." }, 409);
        }

        // Plan limits — a restore must not give the owner more than they could
        // create today (deleting frees domain/workspace slots that may since
        // have been reused). Same canonical helpers as domain-add and
        // workspace-create; any read failure fails closed.
        let planState, liveIds, linkedIds, accountDomainIds, enabledSchedules, candidateSchedules;
        try {
          planState = await getEffectivePlanState(user.id, env);
          liveIds = await getOwnedWorkspaceIds(user.id, env);
          linkedIds = ((await env.cybermeters_db
            .prepare("SELECT DISTINCT domain_id FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId).all())?.results || []).map((r) => r.domain_id);
          accountDomainIds = liveIds.length
            ? ((await env.cybermeters_db
                .prepare(`SELECT DISTINCT domain_id FROM workspace_domains WHERE workspace_id IN (${liveIds.map(() => "?").join(",")})`)
                .bind(...liveIds).all())?.results || []).map((r) => r.domain_id)
            : [];
          enabledSchedules = Number((await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS n FROM scheduled_scans WHERE workspace_id = ? AND enabled = 1")
            .bind(workspaceId).first())?.n ?? 0);
          candidateSchedules = Number((await env.cybermeters_db
            .prepare(`SELECT COUNT(DISTINCT s.domain) AS n FROM scheduled_scans s
                       WHERE s.workspace_id = ? AND s.enabled = 0
                         AND s.domain IN (SELECT d.domain FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ?)`)
            .bind(workspaceId, workspaceId).first())?.n ?? 0);
        } catch {
          return json({ error: "Restore is temporarily unavailable. Please try again." }, 503);
        }
        if (planState?.source === "error") {
          return json({ error: "Your plan could not be checked. Please try again." }, 503);
        }
        const limits = getPlanLimits(planState.plan);
        const domainLimit = getEffectiveDomainLimit(planState.plan, planState.is_trial);
        if (liveIds.length + 1 > limits.workspaces) {
          return json({
            ...planLimitExceeded("workspaces", limits.workspaces, liveIds.length),
            upgrade_message: `Your plan includes ${limits.workspaces} workspace${limits.workspaces === 1 ? "" : "s"}. Delete another workspace or upgrade your plan to restore this one.`,
          }, 403);
        }
        const domainsAfter = new Set([...accountDomainIds, ...linkedIds]).size;
        if (linkedIds.length > domainLimit || domainsAfter > domainLimit) {
          return json(domainLimitRejection(planState.plan, planState.is_trial, domainLimit, Math.max(domainsAfter, linkedIds.length)), 403);
        }
        // Schedules come back one per domain, only within the plan's scheduled
        // scan allowance (0 on plans without scheduled scans); the rest stay off.
        const scheduleCap = Math.max(0, Number(limits.scheduled_scans ?? 0) - enabledSchedules);

        const db = env.cybermeters_db;
        const LIVE = "EXISTS (SELECT 1 FROM workspaces lw WHERE lw.id = ? AND lw.owner_user_id = ? AND lw.deleted_at IS NULL)";
        const LINKED_DOMAIN_IDS = "SELECT wd.domain_id FROM workspace_domains wd WHERE wd.workspace_id = ?";
        const results = await db.batch([
          db.prepare(
            `UPDATE workspaces SET deleted_at = NULL
              WHERE id = ? AND owner_user_id = ? AND deleted_at IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM deletion_requests d
                                 WHERE d.request_type = 'workspace' AND d.workspace_id = ?
                                   AND d.status IN ('purging', 'completed'))
                AND NOT EXISTS (SELECT 1 FROM deletion_requests a
                                 WHERE a.request_type = 'account' AND a.user_id = ?
                                   AND a.status IN ('pending', 'purging'))`
          ).bind(workspaceId, user.id, workspaceId, user.id),
          db.prepare(
            `UPDATE deletion_requests SET status = 'cancelled', updated_at = datetime('now')
              WHERE request_type = 'workspace' AND workspace_id = ? AND status = 'pending' AND ${LIVE}`
          ).bind(workspaceId, workspaceId, user.id),
          db.prepare(
            `UPDATE workspace_assets SET status = 'active', updated_at = datetime('now')
              WHERE workspace_id = ? AND status = 'inactive'
                AND domain_id IN (${LINKED_DOMAIN_IDS}) AND ${LIVE}`
          ).bind(workspaceId, workspaceId, workspaceId, user.id),
          db.prepare(
            `UPDATE scheduled_scans SET enabled = 1
              WHERE id IN (
                SELECT MIN(s.id) FROM scheduled_scans s
                 WHERE s.workspace_id = ? AND s.enabled = 0
                   AND s.domain IN (SELECT d.domain FROM domains d WHERE d.id IN (${LINKED_DOMAIN_IDS}))
                   AND NOT EXISTS (SELECT 1 FROM scheduled_scans e
                                    WHERE e.workspace_id = s.workspace_id AND e.domain = s.domain AND e.enabled = 1)
                 GROUP BY s.domain
                 ORDER BY s.domain
                 LIMIT ?)
                AND ${LIVE}`
          ).bind(workspaceId, workspaceId, scheduleCap, workspaceId, user.id),
        ]);
        const changed = (r) => Number(r?.meta?.changes ?? 0);
        if (changed(results?.[0]) !== 1) {
          const now = await db.prepare("SELECT deleted_at FROM workspaces WHERE id = ? LIMIT 1").bind(workspaceId).first().catch(() => null);
          if (now && !now.deleted_at) return json({ error: "This workspace has already been restored." }, 409);
          return json({ error: NO_LONGER }, 409);
        }

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id: user.id,
          event_type: "workspace_restored",
          entity_type: "workspace",
          entity_id: workspaceId,
          description: `Workspace "${ws.name}" restored within the deletion window`,
          metadata: {
            cancelled_deletion_requests: changed(results[1]),
            reactivated_assets: changed(results[2]),
            reenabled_schedules: changed(results[3]),
          },
        }).catch(() => {});

        const reenabled = changed(results[3]);
        const leftOff = Math.max(0, candidateSchedules - reenabled);
        return json({
          restored: true,
          workspace_id: workspaceId,
          reactivated_assets: changed(results[2]),
          reenabled_schedules: reenabled,
          schedules_left_off: leftOff,
          note: leftOff > 0
            ? `Restored. ${reenabled} scheduled scan${reenabled === 1 ? " was" : "s were"} switched back on; ${leftOff} stayed off because your plan's scheduled-scan allowance is used. Assets for the workspace's current domains are active again.`
            : "Restored. Scheduled scans for the workspace's current domains are switched back on and their assets are active again. Scans still run only while your plan and domain verification allow.",
        });
      } catch {
        return json({ error: "Unable to restore workspace" }, 500);
      }
    }

  return null;
}
