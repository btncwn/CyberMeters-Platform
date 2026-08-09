// ── Website Security managed lifecycle routes ────────────────────────────────
// The read surface migration 089 never had. The engine has recorded durable per-condition
// identity and append-only history on every scan since it shipped, and it alerts on them
// — but nothing could read them: no route, no page, and both of the engine's own read
// helpers had zero callers. Customers were told a condition began without any way to see
// what it was, when it started, or whether it ever cleared.
//
// Shaped exactly like routes/certificates-lifecycle.js — auth, then role, then the
// soft-delete gate, then the record — because three read surfaces landing in one episode
// is precisely how a codebase acquires three API styles.
//
// Non-enumerating: a foreign or nonexistent record returns the SAME 404. A soft-deleted
// workspace is refused by the role check before this module reads anything (403) — see
// the gate below for why the route still carries its own deleted_at predicate.
//
// HONESTY: this domain's state vocabulary is not a health verdict. `no_longer_observed`
// means the condition is absent AND the detecting module provably ran; `unknown` means we
// could not tell, and is NEVER recovery (mig 089:98-106). The scope_note says so, and
// `last_scan_quality` + `unknown_reason` travel with every record so a surface cannot
// quietly present "we did not look" as "you fixed it".
import {
  listWebsiteSecurityConditions, countWebsiteSecurityConditions,
  getWebsiteSecurityCondition, listWebsiteSecurityEvents,
} from "../engines/website-security-lifecycle.js";
import { pageMeta, paginationParams } from "../lib/util.js";

const WS_SCOPE_NOTE =
  "Externally observed website evidence only — passive HTTPS/header inspection, no authenticated crawl, no application testing. "
  + "A condition is only ever recorded as no-longer-observed when the module that detects it provably ran on a complete scan; "
  + "where it did not, the state stays `unknown`, which means CyberMeters could not tell — never that the issue was fixed.";

export async function websiteSecurityRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/website-security\/conditions(?:\/([^/]+)(?:\/([^/]+))?)?$/);
  if (!m) return null;
  const wsId = m[1];
  const recId = m[2] || null;
  const sub = m[3] || null;

  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  // Read-only surface: no write path exists here, so read is the only permission needed.
  const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
  if (!access) return json({ error: "Forbidden" }, 403);

  // Existence + soft-delete gate. NOT the primary defence, and this says so rather than
  // implying it: requireWorkspaceRole above already joins `workspaces ... AND deleted_at
  // IS NULL` (index.js:1417), so a deleted workspace has no members and the caller is
  // already forbidden. What this closes is the window where a workspace is deleted
  // BETWEEN that check and this read. Kept because every lifecycle sibling carries it and
  // a read path should not depend on another function's join for its own correctness.
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(wsId).first().catch(() => null);
  if (!ws) return json({ error: "Workspace not found" }, 404);

  // ── GET /website-security/conditions — the list ────────────────────────────
  if (request.method === "GET" && !recId) {
    try {
      // A domain filter is resolved to the workspace's OWN domain row first, so a
      // caller cannot reach another tenant's conditions by naming their domain: the
      // filter narrows within the tenant, it never widens across one.
      let domainId = null;
      const domain = url.searchParams.get("domain");
      if (domain) {
        const row = await env.cybermeters_db
          .prepare(`SELECT d.id AS id FROM domains d
                    JOIN workspace_domains wd ON wd.domain_id = d.id
                    WHERE wd.workspace_id = ? AND d.domain = ?`)
          .bind(wsId, String(domain).toLowerCase()).first().catch(() => null);
        // An unknown or foreign domain yields an empty list, not a 404: whether a
        // domain exists elsewhere is not this workspace's business to reveal.
        if (!row) {
          return json({
            workspace_id: wsId, items: [],
            pagination: pageMeta({ items: [], limit: 50, offset: 0, total: 0 }),
            scope_note: WS_SCOPE_NOTE,
          });
        }
        domainId = row.id;
      }

      // The shared pagination contract (lib/util.js) — limit AND offset, with an exact
      // total. The lifecycle siblings take a limit only, which is fine for a list a
      // customer can see the end of; it is not fine here, because a workspace accumulates
      // a condition per domain per header and a customer who cannot page cannot audit.
      const { limit, offset } = paginationParams(url, { defaultLimit: 50, maxLimit: 200 });
      const filters = {
        domainId,
        monitoring_status: url.searchParams.get("monitoring_status"),
        severity: url.searchParams.get("severity"),
      };
      const items = await listWebsiteSecurityConditions(env, wsId, { ...filters, limit, offset });
      const total = await countWebsiteSecurityConditions(env, wsId, filters);
      return json({
        workspace_id: wsId,
        items,
        pagination: pageMeta({ items, limit, offset, total }),
        scope_note: WS_SCOPE_NOTE,
      });
    } catch { return json({ error: "Database error" }, 500); }
  }

  if (!recId) return json({ error: "Not found" }, 404);

  const rec = await getWebsiteSecurityCondition(env, wsId, recId);
  if (!rec) return json({ error: "Website security condition not found" }, 404); // foreign === nonexistent

  // ── GET /website-security/conditions/:id — record + append-only history ────
  if (request.method === "GET" && (!sub || sub === "history")) {
    const events = await listWebsiteSecurityEvents(env, wsId, recId);
    // linked_case_id resolves both canonical Website cases and the bounded H-A
    // presentation link to an immutable historical ASM cookie case. The row itself
    // remains authoritative for its original case_type/domain; this read never relabels it.
    let linked_case = null;
    if (rec.linked_case_id) {
      linked_case = await env.cybermeters_db
        .prepare(`SELECT id, case_type, status, remediation_id FROM managed_cases WHERE id = ? AND workspace_id = ?`)
        .bind(rec.linked_case_id, wsId).first().catch(() => null);
    }
    return json({ item: rec, events, linked_case, scope_note: WS_SCOPE_NOTE });
  }

  return json({ error: "Not found" }, 404);
}
