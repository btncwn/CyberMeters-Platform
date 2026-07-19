// ── Workspace membership routes ──
// Invitation list/create/cancel + public invitation preview/accept and member
// list/add/remove/change-role endpoints. Extracted near-verbatim from index.js
// (router split, Phase 2 PR #7). Receives the per-request routeCtx from
// index.js; returns a Response when a route matches, or null so the main
// router continues.
import { getEffectivePlan } from "../engines/entitlements.js";
import { getPlanLimits, getWorkspaceBillingUserId, planLimitExceeded } from "../engines/plan-usage.js";
import { generateInviteToken, hashToken } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import { createId, isValidEmail } from "../lib/util.js";

export async function workspaceMembersRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole, consumeApiRateLimit, ROLE_RANK } = rctx;

    // ── GET /api/workspaces/:id/invitations ─────────────────────────────────
    const invitationsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/invitations$/);
    if (invitationsMatch && request.method === "GET") {
      const workspaceId = invitationsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage invitations" }, 403);
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT wi.id, wi.workspace_id, wi.email, wi.role, wi.invited_by,
                    wi.status, wi.expires_at, wi.accepted_at, wi.created_at,
                    u.email AS invited_by_email, u.name AS invited_by_name
             FROM workspace_invitations wi
             LEFT JOIN users u ON u.id = wi.invited_by
             WHERE wi.workspace_id = ?
             ORDER BY wi.created_at DESC
             LIMIT 100`
          )
          .bind(workspaceId)
          .all();
        return json({ invitations: result.results || [] });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/workspaces/:id/invitations ────────────────────────────────
    if (invitationsMatch && request.method === "POST") {
      const workspaceId = invitationsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to invite members" }, 403);

      // ── Task 1: Rate limiting — 10/hour, 25/day per workspace ────────────
      // Uses the shared D1-backed consumeApiRateLimit helper. Fail-CLOSED: each
      // invite sends an email from our domain, so a rate_limit outage must not
      // become an open spam/reputation window. A brief inability to invite is
      // the safer failure mode than unbounded outbound mail.
      const inviteScopes = [{ scope: "workspace", scope_id: workspaceId }];
      const rlHourly = await consumeApiRateLimit(env, inviteScopes, "invite_send", 10, 3600, { failClosed: true });
      if (rlHourly) {
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "invitation_rate_limit_hit",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  "Invitation rate limit hit (hourly)",
          metadata:     { action: "invite_send", window: "hourly", limit: 10 },
        });
        return json({ error: "Too many invitations sent. Please try again later.", code: "rate_limit_exceeded" }, 429);
      }
      const rlDaily = await consumeApiRateLimit(env, inviteScopes, "invite_send_daily", 25, 86400, { failClosed: true });
      if (rlDaily) {
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "invitation_rate_limit_hit",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  "Invitation rate limit hit (daily)",
          metadata:     { action: "invite_send", window: "daily", limit: 25 },
        });
        return json({ error: "Too many invitations sent. Please try again later.", code: "rate_limit_exceeded" }, 429);
      }

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      const role  = (body.role || "viewer").trim().toLowerCase();
      const VALID_INVITE_ROLES = new Set(["viewer", "analyst", "admin"]);

      if (!email) return json({ error: "email is required" }, 400);
      if (!isValidEmail(email)) return json({ error: "email must be valid" }, 400);
      if (!VALID_INVITE_ROLES.has(role)) return json({ error: "role must be one of: viewer, analyst, admin" }, 400);

      // ── Admin invite ceiling — admins cannot grant their own privilege level ──
      // owner → may invite viewer | analyst | admin
      // admin → may invite viewer | analyst only
      if (access.role === "admin" && role === "admin") {
        return json({ error: "Admins can only invite viewers and analysts. Only owners can invite admins." }, 403);
      }

      // ── Task 4a: Self-invitation guard ───────────────────────────────────
      if (email === (user.email || "").toLowerCase()) {
        return json({ error: "You cannot invite yourself to this workspace." }, 400);
      }

      try {
        const workspace = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!workspace) return json({ error: "Workspace not found" }, 404);

        const billingUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
        const invitePlan    = await getEffectivePlan(billingUserId, env);
        const inviteLimits  = getPlanLimits(invitePlan);

        // Member seat limit (existing)
        const memberCount = await env.cybermeters_db
          .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ?")
          .bind(workspaceId)
          .first();
        if ((memberCount?.cnt ?? 0) >= inviteLimits.users) {
          return json(planLimitExceeded("users", inviteLimits.users, memberCount?.cnt ?? 0), 403);
        }

        // ── Task 2: Pending invitation limit (plan-gated) ─────────────────
        // free=10, starter=25, professional=50, business=250, enterprise=unlimited
        const pendingRow = await env.cybermeters_db
          .prepare(
            `SELECT COUNT(*) AS cnt FROM workspace_invitations
             WHERE workspace_id = ? AND status = 'pending'
               AND expires_at > datetime('now')`
          )
          .bind(workspaceId)
          .first();
        const pendingLimit = inviteLimits.pending_invitations ?? 10;
        if (pendingLimit < 999999 && (pendingRow?.cnt ?? 0) >= pendingLimit) {
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      user.id,
            event_type:   "invitation_limit_reached",
            entity_type:  "workspace",
            entity_id:    workspaceId,
            description:  "Pending invitation limit reached",
            metadata:     { plan: invitePlan, pending_count: pendingRow?.cnt ?? 0, limit: pendingLimit },
          });
          return json({ error: "Invitation limit reached for your plan.", code: "invitation_limit_reached" }, 403);
        }

        // ── Task 4b: Existing member check (hardened — no role/status leakage) ─
        const existingUser = await env.cybermeters_db
          .prepare("SELECT id FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (existingUser) {
          const existingMember = await env.cybermeters_db
            .prepare("SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
            .bind(workspaceId, existingUser.id)
            .first();
          // Generic message — does not reveal whether address is a registered user
          if (existingMember) return json({ error: "This address cannot be invited to this workspace." }, 409);
        }

        // ── Task 4c: Active (pending) invitation check — hardened message ──
        const existingInvite = await env.cybermeters_db
          .prepare(
            `SELECT id FROM workspace_invitations
             WHERE workspace_id = ? AND email = ? AND status = 'pending'
               AND expires_at > datetime('now')
             LIMIT 1`
          )
          .bind(workspaceId, email)
          .first();
        // Generic message — does not reveal whether a token or invite exists
        if (existingInvite) return json({ error: "This address cannot be invited to this workspace." }, 409);

        // ── Task 3: Cooldown — 24 h between sends to the same address ─────
        // Exceptions: if the previous invite is already cancelled, expired, or
        // accepted the cooldown does not apply — re-inviting is permitted.
        const cooldownRow = await env.cybermeters_db
          .prepare(
            `SELECT id FROM workspace_invitations
             WHERE workspace_id = ? AND email = ?
               AND created_at > datetime('now', '-24 hours')
               AND status NOT IN ('cancelled', 'expired', 'accepted')
             LIMIT 1`
          )
          .bind(workspaceId, email)
          .first();
        if (cooldownRow) {
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      user.id,
            event_type:   "invitation_cooldown_blocked",
            entity_type:  "workspace",
            entity_id:    workspaceId,
            description:  "Invitation cooldown — duplicate send within 24 h",
            // No email or token in metadata — safe to store
            metadata:     { workspace_id: workspaceId },
          });
          return json({ error: "This address was recently invited. Please wait before sending another invitation.", code: "invitation_cooldown" }, 429);
        }

        // ── All checks passed — create invitation ─────────────────────────
        const { raw: token, hash: tokenHash } = await generateInviteToken();
        const inviteId  = createId("wsi");
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_invitations
               (id, workspace_id, email, role, token_hash, invited_by, status, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`
          )
          .bind(inviteId, workspaceId, email, role, tokenHash, user.id, expiresAt)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_invitation_created",
          entity_type:  "workspace_invitation",
          entity_id:    inviteId,
          description:  `${user.email} invited ${email} as ${role}`,
          metadata:     { invitation_id: inviteId, email, role, expires_at: expiresAt },
        });

        return json({
          invitation: {
            id: inviteId, workspace_id: workspaceId, email, role,
            status: "pending", expires_at: expiresAt,
          },
          token,
        }, 201);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/members ──────────────────────────────────────
    const membersListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/members$/);
    if (membersListMatch && request.method === "GET") {
      const workspaceId = membersListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "member:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.created_at,
                    u.email, u.name
             FROM workspace_members wm
             JOIN users u ON u.id = wm.user_id
             WHERE wm.workspace_id = ?
             ORDER BY
               CASE wm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'analyst' THEN 2 ELSE 3 END,
               wm.created_at ASC`
          )
          .bind(workspaceId)
          .all();
        return json({
          workspace_id: workspaceId,
          caller_role:  access.role,
          members:      result.results || [],
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/workspaces/:id/members — add member ─────────────────────────
    if (membersListMatch && request.method === "POST") {
      const workspaceId = membersListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:manage_members", env);
      if (!access) return json({ error: "Forbidden — owner role required to manage members" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email   = (body.email || "").trim().toLowerCase();
      const rawRole = (body.role  || "viewer").trim().toLowerCase();

      if (!email)                          return json({ error: "email is required" }, 400);
      if (!ROLE_RANK.hasOwnProperty(rawRole)) return json({ error: `role must be one of: ${Object.keys(ROLE_RANK).join(", ")}` }, 400);
      if (rawRole === "owner")             return json({ error: "Cannot assign owner role via invite. Transfer ownership instead." }, 400);

      try {
        // Resolve target user by email
        const target = await env.cybermeters_db
          .prepare("SELECT id, email, name FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (!target) return json({ error: `No account found for ${email}. The user must sign up first.` }, 404);

        // Prevent demoting an owner via this route
        const existing = await env.cybermeters_db
          .prepare("SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
          .bind(workspaceId, target.id)
          .first();
        if (existing?.role === "owner") return json({ error: "Cannot change the owner's role via this endpoint." }, 409);

        if (!existing) {
          const billingUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
          const memberPlan = await getEffectivePlan(billingUserId, env);
          const memberLimits = getPlanLimits(memberPlan);
          const memberCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ?")
            .bind(workspaceId)
            .first();
          if ((memberCount?.cnt ?? 0) >= memberLimits.users) {
            return json(planLimitExceeded("users", memberLimits.users, memberCount?.cnt ?? 0), 403);
          }
        }

        const memberId = createId("wm");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by, created_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role`
          )
          .bind(memberId, workspaceId, target.id, rawRole, user.id)
          .run();

        const memberAuditType = existing ? "workspace_member_role_changed" : "workspace_member_added";
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   memberAuditType,
          entity_type:  "member",
          entity_id:    target.id,
          description:  existing
            ? `${user.email} changed ${target.email} role from ${existing.role} to ${rawRole}`
            : `${user.email} added ${target.email} as ${rawRole}`,
          metadata:     {
            user_id: target.id,
            email: target.email,
            role: rawRole,
            previous_role: existing?.role ?? null,
          },
        });

        return json({
          member: {
            workspace_id: workspaceId,
            user_id:      target.id,
            email:        target.email,
            name:         target.name,
            role:         rawRole,
          },
        }, 201);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── DELETE /api/workspaces/:id/members/:memberId ──────────────────────────
    const memberDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/members\/([^/]+)$/);
    if (memberDeleteMatch && request.method === "DELETE") {
      const workspaceId = memberDeleteMatch[1];
      const memberId    = memberDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Admin+ can remove members, but admins are limited to analyst/viewer targets.
      // Owner can remove any non-last-owner member.
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to remove members" }, 403);

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, user_id, role FROM workspace_members WHERE id = ? AND workspace_id = ?")
          .bind(memberId, workspaceId)
          .first();
        if (!row) return json({ error: "Member not found" }, 404);

        // Admin ceiling: admins can only remove analyst or viewer members.
        if (access.role === "admin" && row.role !== "analyst" && row.role !== "viewer") {
          return json({ error: "Admins can only remove analyst and viewer members. Only owners can remove admins." }, 403);
        }
        // Owner cannot remove themselves
        if (row.role === "owner" && row.user_id === user.id) {
          return json({ error: "Owner cannot remove themselves. Transfer ownership first." }, 409);
        }
        // Cannot remove the last owner
        if (row.role === "owner") {
          const ownerCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ? AND role = 'owner'")
            .bind(workspaceId)
            .first();
          if ((ownerCount?.cnt ?? 0) <= 1) {
            return json({ error: "Cannot remove the only owner of a workspace." }, 409);
          }
        }

        await env.cybermeters_db
          .prepare("DELETE FROM workspace_members WHERE id = ?")
          .bind(memberId)
          .run();

        // Audit: member removed
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_member_removed",
          entity_type:  "member",
          entity_id:    row.user_id,
          description:  `${user.email} removed member with role ${row.role}`,
          metadata:     { removed_member_id: memberId, removed_user_id: row.user_id, role: row.role },
        });

        return json({ success: true, removed_id: memberId });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PATCH /api/workspaces/:id/members/:memberId — change role ────────────
    const memberRoleMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/members\/([^\/]+)$/);
    if (memberRoleMatch && request.method === "PATCH") {
      const workspaceId = memberRoleMatch[1];
      const targetMemberId = memberRoleMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Admin+ can change roles; admins are limited to analyst/viewer targets and
      // cannot promote anyone to admin. Owners have no ceiling.
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to change member roles" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const newRole = (body.role || "").trim().toLowerCase();
      // Admins can only assign viewer or analyst; owners can assign viewer, analyst, or admin.
      const CHANGEABLE_ROLES = access.role === "owner"
        ? new Set(["viewer", "analyst", "admin"])
        : new Set(["viewer", "analyst"]);
      if (!CHANGEABLE_ROLES.has(newRole)) {
        return json({
          error: access.role === "owner"
            ? "role must be one of: viewer, analyst, admin"
            : "Admins can only assign viewer or analyst roles.",
        }, 400);
      }

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, user_id, role FROM workspace_members WHERE id = ? AND workspace_id = ?")
          .bind(targetMemberId, workspaceId)
          .first();
        if (!row) return json({ error: "Member not found" }, 404);
        if (row.role === "owner") return json({ error: "Cannot change the owner's role. Transfer ownership instead." }, 409);
        if (row.user_id === user.id) return json({ error: "Cannot change your own role." }, 409);
        // Admin ceiling: cannot change roles of other admins.
        if (access.role === "admin" && row.role === "admin") {
          return json({ error: "Admins cannot change the role of other admins. Only owners can do this." }, 403);
        }

        const prevRole = row.role;
        await env.cybermeters_db
          .prepare("UPDATE workspace_members SET role = ? WHERE id = ?")
          .bind(newRole, targetMemberId)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_role_changed",
          entity_type:  "member",
          entity_id:    row.user_id,
          description:  `${user.email} changed member role from ${prevRole} to ${newRole}`,
          metadata:     { member_id: targetMemberId, user_id: row.user_id, previous_role: prevRole, new_role: newRole },
        });

        return json({ success: true, member_id: targetMemberId, role: newRole, previous_role: prevRole });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── DELETE /api/workspaces/:id/invitations/:invId — cancel invitation ──────
    const invitationCancelMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/invitations\/([^\/]+)$/);
    if (invitationCancelMatch && request.method === "DELETE") {
      const workspaceId    = invitationCancelMatch[1];
      const invitationId   = invitationCancelMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to cancel invitations" }, 403);

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, email, role, status FROM workspace_invitations WHERE id = ? AND workspace_id = ?")
          .bind(invitationId, workspaceId)
          .first();
        if (!row) return json({ error: "Invitation not found" }, 404);
        if (row.status !== "pending") return json({ error: `Invitation is already ${row.status}` }, 409);

        await env.cybermeters_db
          .prepare("UPDATE workspace_invitations SET status = 'cancelled' WHERE id = ?")
          .bind(invitationId)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_invitation_cancelled",
          entity_type:  "workspace_invitation",
          entity_id:    invitationId,
          description:  `${user.email} cancelled invitation for ${row.email}`,
          metadata:     { invitation_id: invitationId, email: row.email, role: row.role },
        });

        return json({ success: true, cancelled_id: invitationId });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/invitations/:token — public preview (no auth required) ─────
    const invitationPreviewMatch = url.pathname.match(/^\/api\/invitations\/([^/]+)$/);
    if (invitationPreviewMatch && request.method === "GET") {
      const rawToken = invitationPreviewMatch[1];
      try {
        const tokenHash = await hashToken(rawToken);
        const invite = await env.cybermeters_db
          .prepare(`
            SELECT wi.role, wi.status, wi.expires_at,
                   w.name AS workspace_name,
                   u.name AS invited_by_name, u.email AS invited_by_email
            FROM workspace_invitations wi
            JOIN workspaces w ON w.id = wi.workspace_id
            LEFT JOIN users u ON u.id = wi.invited_by
            WHERE wi.token_hash = ?
            LIMIT 1
          `)
          .bind(tokenHash)
          .first();

        if (!invite) return json({ error: "Invitation not found" }, 404);

        return json({
          workspace_name:   invite.workspace_name,
          invited_by_name:  invite.invited_by_name || invite.invited_by_email || "A team member",
          role:             invite.role,
          expires_at:       invite.expires_at,
          status:           invite.status,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/invitations/:token/accept ─────────────────────────────────
    const invitationAcceptMatch = url.pathname.match(/^\/api\/invitations\/([^/]+)\/accept$/);
    if (invitationAcceptMatch && request.method === "POST") {
      const rawToken = invitationAcceptMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      try {
        const tokenHash = await hashToken(rawToken);
        const invite = await env.cybermeters_db
          .prepare(
            // Join workspaces with deleted_at IS NULL so an invitation to a
            // soft-deleted workspace resolves to null → the same "Invitation not
            // found" 404 as a nonexistent token (no enumeration oracle). Accept is
            // the one membership-mutating path that does not flow through the shared
            // requireWorkspaceRole gate (which already filters deleted_at), so the
            // soft-delete invariant — soft-deleted workspaces must not receive new
            // members — has to be enforced explicitly here.
            `SELECT wi.id, wi.workspace_id, wi.email, wi.role, wi.invited_by, wi.status, wi.expires_at
             FROM workspace_invitations wi
             JOIN workspaces w ON w.id = wi.workspace_id AND w.deleted_at IS NULL
             WHERE wi.token_hash = ?
             LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!invite) return json({ error: "Invitation not found" }, 404);
        if (invite.status !== "pending") return json({ error: `Invitation is ${invite.status}` }, 409);

        const expiresAt = new Date(invite.expires_at);
        if (!invite.expires_at || Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
          await env.cybermeters_db
            .prepare("UPDATE workspace_invitations SET status = 'expired' WHERE id = ?")
            .bind(invite.id)
            .run();
          await createAuditEvent(env, {
            workspace_id: invite.workspace_id,
            user_id:      user.id,
            event_type:   "workspace_invitation_expired",
            entity_type:  "workspace_invitation",
            entity_id:    invite.id,
            description:  `Workspace invitation for ${invite.email} expired`,
            metadata:     { invitation_id: invite.id, invited_email: invite.email, role: invite.role, expires_at: invite.expires_at },
          });
          return json({ error: "Invitation expired" }, 410);
        }

        if ((user.email || "").trim().toLowerCase() !== invite.email) {
          return json({ error: "Invitation email does not match authenticated user" }, 403);
        }

        const existingMember = await env.cybermeters_db
          .prepare("SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
          .bind(invite.workspace_id, user.id)
          .first();
        if (!existingMember) {
          const billingUserId = await getWorkspaceBillingUserId(invite.workspace_id, invite.invited_by, env);
          const acceptPlan = await getEffectivePlan(billingUserId, env);
          const acceptLimits = getPlanLimits(acceptPlan);
          const memberCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ?")
            .bind(invite.workspace_id)
            .first();
          if ((memberCount?.cnt ?? 0) >= acceptLimits.users) {
            return json(planLimitExceeded("users", acceptLimits.users, memberCount?.cnt ?? 0), 403);
          }
        }

        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by, created_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role`
          )
          .bind(createId("wm"), invite.workspace_id, user.id, invite.role, invite.invited_by)
          .run();

        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_invitations
             SET status = 'accepted', accepted_at = datetime('now')
             WHERE id = ?`
          )
          .bind(invite.id)
          .run();

        await createAuditEvent(env, {
          workspace_id: invite.workspace_id,
          user_id:      user.id,
          event_type:   "workspace_invitation_accepted",
          entity_type:  "workspace_invitation",
          entity_id:    invite.id,
          description:  `${user.email} accepted workspace invitation as ${invite.role}`,
          metadata:     { invitation_id: invite.id, invited_email: invite.email, role: invite.role },
        });

        return json({
          success: true,
          workspace_id: invite.workspace_id,
          role: invite.role,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }


  return null;
}
