// ── Certificates Managed Lifecycle routes ───────────────────────────────────
// Workspace-scoped managed certificate lifecycle. Reads fold the canonical
// lifecycle record; the action endpoint routes every ownership / planning /
// verification change through the lifecycle service (which audits an append-only
// event and links a Universal Managed Case when follow-up is due). Verification
// is external-observation only: a recorded renewal is never treated as verified
// until a distinct new certificate is observed with acceptable coverage and a
// later expiry. Non-enumerating: a foreign or nonexistent record returns the
// SAME 404; a soft-deleted workspace behaves like a nonexistent one.
import {
  listCertificateLifecycle, getCertificateLifecycle, listCertificateLifecycleEvents,
  countCertificateLifecycleByReadiness, certificateLifecycleAction,
  CERT_WORKFLOW_ACTIONS, CERT_OWNERSHIP_STATUSES, COVERAGE_STATUSES, CERT_LIFECYCLE_STATES,
} from "../engines/certificate-lifecycle.js";
import { CERT_RENEWAL_BANDS } from "../engines/certificate-policy.js";
import { parseBoundedInteger } from "../lib/util.js";

export async function certificatesLifecycleRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/certificates\/lifecycle(?:\/([^/]+)(?:\/([^/]+))?)?$/);
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

  // ── GET /certificates/lifecycle — list + readiness counts ────────────────
  if (request.method === "GET" && !recId) {
    try {
      const items = await listCertificateLifecycle(env, wsId, {
        renewal_readiness: url.searchParams.get("renewal_readiness"),
        lifecycle_state: url.searchParams.get("lifecycle_state"),
        coverage_status: url.searchParams.get("coverage_status"),
        limit: parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500),
      });
      const counts = await countCertificateLifecycleByReadiness(env, wsId);
      return json({
        workspace_id: wsId, count: items.length, counts,
        renewal_bands: CERT_RENEWAL_BANDS, lifecycle_states: CERT_LIFECYCLE_STATES,
        coverage_statuses: COVERAGE_STATUSES, ownership_statuses: CERT_OWNERSHIP_STATUSES,
        actions: CERT_WORKFLOW_ACTIONS,
        items,
        scope_note: "Externally observed certificates only — no live TLS, chain, root, OCSP, revocation or private-key check. A recorded renewal is not verified until a distinct new certificate is observed with acceptable coverage and a later expiry.",
      });
    } catch { return json({ error: "Database error" }, 500); }
  }

  if (!recId) return json({ error: "Not found" }, 404);
  const rec = await getCertificateLifecycle(env, wsId, recId);
  if (!rec) return json({ error: "Certificate lifecycle record not found" }, 404); // same for foreign + nonexistent

  // ── GET /certificates/lifecycle/:id — record + append-only history + case ─
  if (request.method === "GET" && (!action || action === "history")) {
    const events = await listCertificateLifecycleEvents(env, wsId, recId);
    let linked_case = null;
    if (rec.linked_case_id) {
      linked_case = await env.cybermeters_db
        .prepare(`SELECT id, case_type, status, remediation_id FROM managed_cases WHERE id = ? AND workspace_id = ?`)
        .bind(rec.linked_case_id, wsId).first().catch(() => null);
    }
    return json({ item: rec, events, linked_case });
  }

  // ── POST /certificates/lifecycle/:id/action — ownership / planning / etc ──
  // POST /certificates/lifecycle/:id/verify — request external verification.
  if (request.method === "POST" && (action === "action" || action === "verify")) {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const act = action === "verify" ? "request_verification" : String(body.action || "");
    if (!CERT_WORKFLOW_ACTIONS.includes(act)) return json({ error: "invalid_action", allowed: CERT_WORKFLOW_ACTIONS }, 400);
    const result = await certificateLifecycleAction(env, wsId, recId, act, {
      actor_id: user.id,
      owner: body.owner ?? null,
      expected_hostnames: body.expected_hostnames ?? null,
      provider: body.provider ?? null,
      replacement_expected_at: body.replacement_expected_at ?? null,
      reason: body.reason ?? null,
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
