// ── Attack Surface: customer hostname lists (migration 117) ──────────────────
//
//   GET    /api/workspaces/:id/attack-surface/hostname-lists          — every verified domain and its list
//   PUT    /api/workspaces/:id/attack-surface/hostname-lists/:domain  — save (replaces the active list)
//   DELETE /api/workspaces/:id/attack-surface/hostname-lists/:domain  — clear
//
// Reads need workspace membership. Writes need the domain-import permission on
// a live workspace and a domain verified in it; foreign and unverified domains
// get the same 403. Only in-scope hostnames are stored, never the upload.
import { boundedDnsJson, canonicalDomain } from "../engines/cloudflare-dns.js";
import {
  HOSTNAME_LIST_FORMATS, HOSTNAME_LIST_LIMITS, HostnameListError, clearHostnameList,
  hostnameListView, listHostnameLists, parseHostnameList, saveHostnameList,
} from "../engines/discovery-hostname-list.js";

export const HOSTNAME_LIST_SCOPE_NOTE =
  "List hostnames under a verified domain that you want every scan to check. Each scan asks DNS about each name; "
  + "a name is added to your inventory only when DNS answers for it, and names outside the domain are ignored. "
  + "Only the hostnames are kept, never the file you upload.";

const MESSAGES = {
  unauthorized: "Sign in to continue.",
  forbidden: "You do not have access to this workspace.",
  role_required: "A workspace owner or admin is required.",
  domain_not_verified: "Verify this domain in this workspace first.",
  unsupported_format: "Choose a list, CSV or zone file format.",
  unsupported_input: "Check the hostname list.",
  input_too_large: "The list is too large. Upload at most 256 KB.",
  no_hostnames_accepted: "No hostname under this domain was found in the list.",
};

const MAX_BODY_BYTES = 600_000;

function domainParam(raw) {
  try { return canonicalDomain(decodeURIComponent(raw)); } catch { throw new HostnameListError("unsupported_input", 400); }
}

export async function discoveryHostnameListRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;
  const listMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/attack-surface\/hostname-lists$/);
  const itemMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/attack-surface\/hostname-lists\/([^/]+)$/);
  const match = listMatch || itemMatch;
  if (!match) return null;
  const workspaceId = match[1], db = env.cybermeters_db;
  try {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: MESSAGES.unauthorized, code: "unauthorized" }, 401);
    const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
    if (!access) return json({ error: MESSAGES.forbidden, code: "forbidden" }, 403);
    const live = await db.prepare("SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL").bind(workspaceId).first();
    if (!live) return json({ error: "Workspace not found", code: "workspace_not_found" }, 404);

    if (listMatch) {
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      const manage = await requireWorkspaceRole(user, workspaceId, "domain:import", env);
      return json({
        workspace_id: workspaceId,
        can_manage: Boolean(manage),
        formats: HOSTNAME_LIST_FORMATS,
        limits: { max_hostnames: HOSTNAME_LIST_LIMITS.maxHostnames, max_bytes: HOSTNAME_LIST_LIMITS.maxInputBytes },
        domains: await listHostnameLists(db, workspaceId),
        scope_note: HOSTNAME_LIST_SCOPE_NOTE,
      });
    }

    if (!["PUT", "DELETE"].includes(request.method)) return json({ error: "Method not allowed" }, 405);
    if (!await requireWorkspaceRole(user, workspaceId, "domain:import", env)) throw new HostnameListError("role_required", 403);
    const domain = domainParam(match[2]);
    const owned = await db.prepare(
      `SELECT d.id, d.domain FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
        WHERE wd.workspace_id = ? AND d.domain = ? AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL`)
      .bind(workspaceId, domain).first();
    if (!owned) throw new HostnameListError("domain_not_verified", 403);
    const limited = await consumeApiRateLimit(env, [{ scope: "workspace", scope_id: workspaceId }],
      "discovery_hostname_list_change", 30, 3600, { atomic: true, failClosed: true });
    if (limited) return json(limited.body, limited.status);

    if (request.method === "DELETE") {
      const cleared = await clearHostnameList(db, { workspaceId, domainId: owned.id, domain, userId: user.id });
      return json({ domain, cleared });
    }

    if (!/^application\/json(?:;|$)/i.test(request.headers.get("content-type") || "")) throw new HostnameListError("unsupported_input");
    let body;
    try { body = await boundedDnsJson(request, MAX_BODY_BYTES); } catch { throw new HostnameListError("unsupported_input"); }
    if (!body || typeof body !== "object" || Array.isArray(body) ||
        Object.keys(body).some((key) => !["format", "text"].includes(key))) {
      throw new HostnameListError("unsupported_input");
    }
    const parsed = parseHostnameList(body.text, { format: body.format, domain });
    if (parsed.hostnames.length === 0) {
      return json({ error: MESSAGES.no_hostnames_accepted, code: "no_hostnames_accepted", result: parsed.summary }, 422);
    }
    const row = await saveHostnameList(db, { workspaceId, domainId: owned.id, domain, userId: user.id, parsed });
    return json({ domain, list: hostnameListView(row, domain), result: parsed.summary });
  } catch (error) {
    const known = error instanceof HostnameListError;
    const code = known ? error.code : "hostname_list_unavailable";
    return json({ error: MESSAGES[code] || "Hostname lists are temporarily unavailable.", code }, known ? error.status : 503);
  }
}
