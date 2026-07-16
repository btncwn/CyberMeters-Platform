// ── Cyber Essentials external-evidence control routes ────────────────────────
// The read surface migration 090 never had. `listCeControlRecords` existed with ZERO
// callers repo-wide: the engine has been recording per-control readiness, the evidence
// behind it, and recovery history on every scan — and alerting on it — while the CE page
// showed only the questionnaire and the merged readiness. Customers received alerts about
// control records that no endpoint could return.
//
// Shaped exactly like routes/certificates-lifecycle.js and routes/website-security.js:
// auth, then role, then the soft-delete gate, then the record. Non-enumerating — a
// foreign or nonexistent record returns the SAME 404.
//
// ── THE HONESTY BOUNDARY, WHICH THIS ROUTE EXISTS TO PRESERVE ──
// There is NO "verified" value in this domain's vocabulary and there must never be one.
// `readiness_state` is ready | not_ready | unknown | not_externally_assessable, and even
// `ready` means only that the externally observable part of a control looks aligned.
// CyberMeters does not certify Cyber Essentials, and self-attested questionnaire answers
// are never verification — they live in a different table, on a different route, under a
// different label class (lib/cyber-essentials.js: self_attested_only /
// externally_corroborated / contradicted_by_scan / externally_confirmed_gap).
//
// `external_coverage` therefore ships on every record: two of the five controls
// (access_control, malware_protection) are PERMANENTLY `not_externally_assessable`
// because nothing external can observe them, and a surface that hid that would let a
// customer read four silent controls as four passing ones.
import {
  listCeControlRecords, countCeControlRecords, getCeControlRecord, listCeControlEvents,
} from "../engines/ce-lifecycle.js";
import { pageMeta, paginationParams } from "../lib/util.js";

const CE_SCOPE_NOTE =
  "Indicative readiness from externally observable evidence only. CyberMeters does not certify Cyber Essentials and does not verify these controls. "
  + "Coverage is partial by nature: controls marked `not_externally_assessable` cannot be observed from outside at all, and their absence from this list's "
  + "findings is not evidence that they pass. Questionnaire answers are a customer self-assessment, are never treated as verification, and are served separately.";

export async function cyberEssentialsControlsRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/cyber-essentials\/controls(?:\/([^/]+)(?:\/([^/]+))?)?$/);
  if (!m) return null;
  const wsId = m[1];
  const recId = m[2] || null;
  const sub = m[3] || null;

  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
  if (!access) return json({ error: "Forbidden" }, 403);

  // Existence + soft-delete gate. NOT the primary defence: requireWorkspaceRole above
  // already excludes deleted workspaces via its own join (index.js:1417), so this only
  // closes the delete-between-checks window. See routes/website-security.js.
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(wsId).first().catch(() => null);
  if (!ws) return json({ error: "Workspace not found" }, 404);

  // ── GET /cyber-essentials/controls — the list ──────────────────────────────
  if (request.method === "GET" && !recId) {
    try {
      const { limit, offset } = paginationParams(url, { defaultLimit: 50, maxLimit: 200 });
      const filters = { readiness_state: url.searchParams.get("readiness_state") };
      const items = await listCeControlRecords(env, wsId, { ...filters, limit, offset });
      const total = await countCeControlRecords(env, wsId, filters);
      return json({
        workspace_id: wsId,
        items,
        pagination: pageMeta({ items, limit, offset, total }),
        scope_note: CE_SCOPE_NOTE,
      });
    } catch { return json({ error: "Database error" }, 500); }
  }

  if (!recId) return json({ error: "Not found" }, 404);

  const rec = await getCeControlRecord(env, wsId, recId);
  if (!rec) return json({ error: "Cyber Essentials control record not found" }, 404); // foreign === nonexistent

  // ── GET /cyber-essentials/controls/:id — record + append-only history ──────
  if (request.method === "GET" && (!sub || sub === "history")) {
    const events = await listCeControlEvents(env, wsId, recId);
    let linked_case = null;
    if (rec.linked_case_id) {
      linked_case = await env.cybermeters_db
        .prepare(`SELECT id, case_type, status, remediation_id FROM managed_cases WHERE id = ? AND workspace_id = ?`)
        .bind(rec.linked_case_id, wsId).first().catch(() => null);
    }
    return json({ item: rec, events, linked_case, scope_note: CE_SCOPE_NOTE });
  }

  return json({ error: "Not found" }, 404);
}
