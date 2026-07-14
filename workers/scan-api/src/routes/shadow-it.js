// ── Shadow IT approved-inventory routes ─────────────────────────────────────
// Workspace-scoped managed inventory of externally-observed technology. Reads
// fold the canonical inventory; the action endpoint routes every classification/
// ownership/lifecycle change through the classification service (which audits an
// append-only event and links a Universal Managed Case when follow-up is due).
// Non-enumerating: a foreign or nonexistent item returns the SAME 404; a soft-
// deleted workspace behaves like a nonexistent one.
import {
  listShadowItInventory, getShadowItItem, listShadowItItemEvents,
  countShadowItByClassification, classifyShadowItItem, SHADOW_IT_WORKFLOW_ACTIONS,
  SHADOW_IT_CLASSIFICATIONS,
} from "../engines/shadow-it-inventory.js";
import { parseBoundedInteger } from "../lib/util.js";

export async function shadowItRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/shadow-it\/inventory(?:\/([^/]+)(?:\/([^/]+))?)?$/);
  if (!m) return null;
  const wsId = m[1];
  const itemId = m[2] || null;
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

  // ── GET /shadow-it/inventory — list + counts ─────────────────────────────
  if (request.method === "GET" && !itemId) {
    try {
      const items = await listShadowItInventory(env, wsId, {
        classification: url.searchParams.get("classification"),
        monitoring_status: url.searchParams.get("monitoring_status"),
        limit: parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500),
      });
      const counts = await countShadowItByClassification(env, wsId);
      return json({
        workspace_id: wsId, count: items.length, counts,
        classifications: SHADOW_IT_CLASSIFICATIONS, actions: SHADOW_IT_WORKFLOW_ACTIONS,
        items,
        scope_note: "Externally observed technology only — no internal-network, endpoint, CASB or EDR visibility.",
      });
    } catch { return json({ error: "Database error" }, 500); }
  }

  if (!itemId) return json({ error: "Not found" }, 404);
  const item = await getShadowItItem(env, wsId, itemId);
  if (!item) return json({ error: "Inventory item not found" }, 404); // same for foreign + nonexistent

  // ── GET /shadow-it/inventory/:id — item + append-only history + case ─────
  if (request.method === "GET" && !action) {
    const events = await listShadowItItemEvents(env, wsId, itemId);
    let linked_case = null;
    if (item.linked_case_id) {
      linked_case = await env.cybermeters_db
        .prepare(`SELECT id, case_type, status, remediation_id FROM managed_cases WHERE id = ? AND workspace_id = ?`)
        .bind(item.linked_case_id, wsId).first().catch(() => null);
    }
    return json({ item, events, linked_case });
  }

  // ── POST /shadow-it/inventory/:id/action — classify / assign / lifecycle ─
  if (request.method === "POST" && action === "action") {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const act = String(body.action || "");
    if (!SHADOW_IT_WORKFLOW_ACTIONS.includes(act)) return json({ error: "invalid_action", allowed: SHADOW_IT_WORKFLOW_ACTIONS }, 400);
    const result = await classifyShadowItItem(env, wsId, itemId, act, {
      actor_id: user.id,
      reason: body.reason ?? null,
      exception_until: body.exception_until ?? null,
      owner: body.owner ?? null,
      business_purpose: body.business_purpose ?? null,
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
