// ── M6 Phase B1: Related Changes routes ─────────────────────────────────────
// Workspace-scoped read + managed-feedback surface over the deterministic Related
// Changes clusters (mig 098). Every statement is filtered by workspace_id; reads need
// workspace:read, writes need workspace:manage; a soft-deleted workspace is a 404.
//
// The customer can view a cluster and its evidence POINTERS, declare it expected /
// unrelated / confirmed-unexpected (with an optional note), and — manually only — link
// it to an existing case or open a new one. There is NO automatic case or alert
// creation here (design §8). Wording stays "related change", never attack/compromise.
import {
  listRelatedChanges, getRelatedChange, setRelatedChangeCustomerState,
  linkRelatedChangeToCase, createCaseFromRelatedChange,
  CUSTOMER_STATES, CUSTOMER_FEEDBACK_STATES,
} from "../engines/related-changes.js";
import { parseBoundedInteger } from "../lib/util.js";

// Customer-safe projection — never exposes the internal cluster_key.
function clusterToApi(row) {
  return {
    id: row.id,
    registrable_domain: row.registrable_domain,
    rule_id: row.rule_id,
    direction: row.direction,
    signal_family_count: row.signal_family_count,
    independent_producer_count: row.independent_producer_count,
    confidence: row.confidence,
    completeness: row.completeness,
    customer_state: row.customer_state,
    first_seen: row.first_seen ?? null,
    last_seen: row.last_seen ?? null,
    recurrence_count: row.recurrence_count ?? 1,
    linked_case_id: row.linked_case_id ?? null,
    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

export async function relatedChangesRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/related-changes(?:\/([^/]+)(?:\/([^/]+))?)?$/);
  if (!m) return null;
  const wsId = m[1];
  const rcId = m[2] || null;
  const action = m[3] || null;

  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
  const access = await requireWorkspaceRole(user, wsId, permission, env);
  if (!access) return json({ error: "Forbidden" }, 403);

  // Existence + soft-delete gate AFTER authz (a deleted workspace behaves as absent).
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(wsId).first().catch(() => null);
  if (!ws) return json({ error: "Workspace not found" }, 404);

  // ── GET /related-changes — list ──────────────────────────────────────────
  if (request.method === "GET" && !rcId) {
    try {
      const customerState = url.searchParams.get("customer_state");
      if (customerState && !CUSTOMER_STATES.includes(customerState)) {
        return json({ error: "invalid_customer_state" }, 400);
      }
      const limit = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
      const offset = parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 100000);
      const rows = await listRelatedChanges(env, wsId, { customer_state: customerState, limit, offset });
      return json({
        workspace_id: wsId,
        customer_states: CUSTOMER_STATES,
        count: rows.length,
        related_changes: rows.map(clusterToApi),
      });
    } catch {
      return json({ error: "Database error" }, 500);
    }
  }

  if (!rcId) return json({ error: "Not found" }, 404);

  // ── GET /related-changes/:id — cluster + evidence pointers ───────────────
  if (request.method === "GET") {
    const detail = await getRelatedChange(env, wsId, rcId);
    if (!detail) return json({ error: "Related change not found" }, 404); // same for foreign + nonexistent
    return json({
      related_change: clusterToApi(detail.cluster),
      evidence: detail.evidence.map((e) => ({
        producer_family: e.producer_family,
        source_table: e.source_table,
        source_record_id: e.source_record_id || null,
        source_event_type: e.source_event_type || null,
        entity_key: e.entity_key,
        observed_at: e.observed_at,
        evidence_ref: e.evidence_ref || null,
      })),
    });
  }

  // ── POST /related-changes/:id/:action ────────────────────────────────────
  if (request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }

    if (action === "feedback") {
      const res = await setRelatedChangeCustomerState(env, wsId, rcId, body.state, { userId: user.id, note: body.note ?? null });
      if (!res.ok) {
        const status = res.code === "not_found" ? 404 : 400;
        return json({ error: res.code, allowed_states: CUSTOMER_FEEDBACK_STATES }, status);
      }
      return json({ ok: true, customer_state: res.customer_state });
    }

    if (action === "link-case") {
      if (!body.case_id) return json({ error: "case_id_required" }, 400);
      const res = await linkRelatedChangeToCase(env, wsId, rcId, body.case_id);
      if (!res.ok) return json({ error: res.code }, res.code === "not_found" || res.code === "case_not_found" ? 404 : 400);
      return json({ ok: true, linked_case_id: res.linked_case_id });
    }

    if (action === "create-case") {
      const res = await createCaseFromRelatedChange(env, wsId, rcId, {
        userId: user.id,
        domainKey: body.domain_key ?? null,
        caseType: body.case_type ?? null,
      });
      if (!res.ok) {
        const status = res.code === "not_found" ? 404 : res.code === "no_base_case_type" ? 409 : 400;
        return json({ error: res.code }, status);
      }
      return json({ ok: true, case_id: res.case.id, case_type: res.case.case_type }, 201);
    }

    return json({ error: "Unknown action" }, 404);
  }

  return json({ error: "Method not allowed" }, 405);
}
