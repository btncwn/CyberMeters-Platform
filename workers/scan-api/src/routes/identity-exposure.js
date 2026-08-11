// ── Identity Exposure Managed Workflow routes ───────────────────────────────
// Workspace-scoped managed identity-exposure records. Reads fold the canonical
// managed record; the action endpoint routes every classification / ownership /
// remediation / verification change through the lifecycle service (which audits
// an append-only event and links a Universal Managed Case when follow-up is due).
// Verification is external-observation only: a customer-recorded change/removal
// is never treated as verified until re-observed externally. Non-enumerating: a
// foreign or nonexistent record returns the SAME 404; a soft-deleted workspace
// behaves like a nonexistent one.
//
// Base path is /identity-surfaces (NOT /identity-exposure): the existing
// /identity-exposure route serves the consolidated exposure-level verdict and
// /identity-assets serves the raw inventory — both are preserved unchanged. This
// managed-record family is deliberately a distinct, non-colliding path.
import {
  listIdentityExposure, getIdentityExposureRecord, listIdentityExposureEvents,
  countIdentityExposureByClassification, identityExposureAction,
  IDENTITY_WORKFLOW_ACTIONS, IDENTITY_CLASSIFICATIONS, IDENTITY_OWNERSHIP_STATUSES,
} from "../engines/identity-lifecycle.js";
import { SURFACE_TYPES, RISK_STATUSES } from "../engines/identity-policy.js";
import { identityAllowedActionsForClaim } from "../engines/identity-evidence-contract.js";
import { parseBoundedInteger } from "../lib/util.js";

export async function identityExposureRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-surfaces(?:\/([^/]+)(?:\/([^/]+))?)?$/);
  if (!m) return null;
  const wsId = m[1];
  const recId = m[2] || null;
  const action = m[3] || null;

  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
  const access = await requireWorkspaceRole(user, wsId, permission, env);
  if (!access) return json({ error: "Forbidden" }, 403);

  // Existence + soft-delete gate: a deleted workspace behaves like a missing one.
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(wsId).first().catch(() => null);
  if (!ws) return json({ error: "Workspace not found" }, 404);

  // ── GET /identity-exposure — list + classification counts ────────────────
  if (request.method === "GET" && !recId) {
    try {
      const items = await listIdentityExposure(env, wsId, {
        customer_classification: url.searchParams.get("customer_classification"),
        risk_status: url.searchParams.get("risk_status"),
        monitoring_status: url.searchParams.get("monitoring_status"),
        surface_type: url.searchParams.get("surface_type"),
        limit: parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500),
      });
      const counts = await countIdentityExposureByClassification(env, wsId);
      return json({
        workspace_id: wsId, count: items.length, counts,
        classifications: IDENTITY_CLASSIFICATIONS, ownership_statuses: IDENTITY_OWNERSHIP_STATUSES,
        surface_types: SURFACE_TYPES, risk_statuses: RISK_STATUSES,
        // Deprecated compatibility metadata. Authoritative eligibility is the
        // per-item allowed_actions field and the same server helper below.
        actions: IDENTITY_WORKFLOW_ACTIONS,
        actions_deprecated: true,
        items,
        scope_note: "Current evidence identifies provider relationships and possible identity-facing hostnames. Endpoint reachability is not evaluated. No leaked-credential, breached-password, dark-web, MFA, Conditional Access or internal-policy visibility.",
      });
    } catch { return json({ error: "Database error" }, 500); }
  }

  if (!recId) return json({ error: "Not found" }, 404);
  const rec = await getIdentityExposureRecord(env, wsId, recId);
  if (!rec) return json({ error: "Identity exposure record not found" }, 404); // same for foreign + nonexistent

  // ── GET /identity-exposure/:id — record + append-only history + case ─────
  if (request.method === "GET" && (!action || action === "history")) {
    const events = await listIdentityExposureEvents(env, wsId, recId);
    let linked_case = null;
    if (rec.linked_case_id) {
      linked_case = await env.cybermeters_db
        .prepare(`SELECT id, case_type, status, remediation_id FROM managed_cases WHERE id = ? AND workspace_id = ?`)
        .bind(rec.linked_case_id, wsId).first().catch(() => null);
    }
    return json({ item: rec, events, linked_case });
  }

  // ── POST /identity-exposure/:id/action — classify / assign / remediate ───
  // POST /identity-exposure/:id/verify — request external verification.
  if (request.method === "POST" && (action === "action" || action === "verify")) {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const act = action === "verify" ? "request_verification" : String(body.action || "");
    if (!IDENTITY_WORKFLOW_ACTIONS.includes(act)) return json({ error: "invalid_action", allowed: IDENTITY_WORKFLOW_ACTIONS }, 400);
    const allowedActions = identityAllowedActionsForClaim(rec.identity_claim);
    if (!allowedActions.includes(act)) return json({ error: "action_not_allowed", allowed: allowedActions }, 422);
    const result = await identityExposureAction(env, wsId, recId, act, {
      actor_id: user.id,
      owner: body.owner ?? null,
      reason: body.reason ?? null,
      business_purpose: body.business_purpose ?? null,
      exception_until: body.exception_until ?? null,
    });
    if (!result.ok) {
      const status = result.code === "not_found" ? 404
        : result.code === "invalid_action" ? 400 : 422;
      return json({ error: result.code }, status);
    }
    return json({ item: result.item });
  }

  return json({ error: "Not found" }, 404);
}
