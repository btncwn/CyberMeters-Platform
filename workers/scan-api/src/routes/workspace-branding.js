// ── Report branding routes (branding v2) ──────────────────────────────────────
// Per-workspace co-brand logo (all plans) + MSP white-label branding profiles.
// Ownership, MSP status, white-label entitlement and logo ownership are ALL
// derived server-side — never from the request body or a frontend flag.
//   GET    /api/workspaces/:id/branding          — read current branding config
//   PUT    /api/workspaces/:id/branding/logo     — upload/replace the workspace logo
//   DELETE /api/workspaces/:id/branding/logo     — clear the pointer (R2 objects kept
//                                                   so historical frozen reports survive)
//   GET    /api/account/branding/profiles        — list this account's MSP profiles
//   POST   /api/account/branding/profiles        — create an MSP profile (white_label entitled)
//   DELETE /api/account/branding/profiles/:pid   — delete an MSP profile
import { getEffectivePlan } from "../engines/entitlements.js";
import { hasFeatureEntitlement } from "../engines/entitlements.js";
import { getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { validateLogoUpload, workspaceLogoKey, mspLogoKey, resolveReportBrandingV2 } from "../engines/report-branding-v2.js";
import { createAuditEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";

function dataUriToBytes(uri) {
  const m = /^data:image\/(png|jpeg);base64,([A-Za-z0-9+/=]+)$/.exec(String(uri || ""));
  if (!m) return null;
  try {
    const bin = atob(m[2]);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return null; }
}

export async function workspaceBrandingRoutes(rctx) {
  const { request, env, url, json, serverError, requireAuth, requireWorkspaceRole } = rctx;

  // ── Workspace branding ──────────────────────────────────────────────────
  const wsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/branding(\/logo)?$/);
  if (wsMatch) {
    const workspaceId = wsMatch[1];
    const isLogo = !!wsMatch[2];
    const user = await requireAuth(request, env);
    if (!user) return json({ error: "Unauthorized" }, 401);

    // GET config — read access.
    if (request.method === "GET" && !isLogo) {
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db
          .prepare(`SELECT logo_mime, logo_sha256, logo_width, logo_height, logo_bytes, display_name, updated_at FROM workspace_branding WHERE workspace_id = ? LIMIT 1`)
          .bind(workspaceId).first();
        const descriptor = await resolveReportBrandingV2(env, { workspaceId });
        return json({
          has_logo: !!(row && row.logo_sha256),
          logo: row ? { mime: row.logo_mime, width: row.logo_width, height: row.logo_height, bytes: row.logo_bytes, sha256: row.logo_sha256, display_name: row.display_name, updated_at: row.updated_at } : null,
          effective_mode: descriptor.mode, effective_attribution: descriptor.attribution,
        });
      } catch (e) { return serverError("branding/get", e); }
    }

    // Writes require management permission.
    if ((request.method === "PUT" || request.method === "DELETE") && isLogo) {
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:manage", env);
      if (!access) return json({ error: "Forbidden — workspace manager role required" }, 403);

      if (request.method === "DELETE") {
        // Clear the pointer only; never delete R2 objects (frozen historical
        // reports still reference them by key).
        try {
          await env.cybermeters_db
            .prepare(`UPDATE workspace_branding SET logo_r2_key = NULL, logo_mime = NULL, logo_sha256 = NULL, logo_width = NULL, logo_height = NULL, logo_bytes = NULL, updated_at = datetime('now'), updated_by = ? WHERE workspace_id = ?`)
            .bind(user.id, workspaceId).run();
          await createAuditEvent(env, { workspace_id: workspaceId, user_id: user.id, event_type: "branding_logo_cleared", entity_type: "workspace", entity_id: workspaceId, description: "Workspace report logo cleared" }).catch(() => {});
          return json({ ok: true, has_logo: false });
        } catch (e) { return serverError("branding/delete", e); }
      }

      // PUT: validate + store.
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const bytes = dataUriToBytes(body.logo);
      if (!bytes) return json({ error: "logo must be a data: URI (image/png or image/jpeg, base64)" }, 400);
      const v = await validateLogoUpload(bytes);
      if (!v.ok) return json({ error: v.error }, 400);
      const displayName = typeof body.display_name === "string" ? body.display_name.trim().slice(0, 120) : null;
      const key = workspaceLogoKey(workspaceId, v.value.sha256, v.value.ext);
      try {
        await env.cybermeters_reports.put(key, v.value.bytes, { httpMetadata: { contentType: v.value.mime } });
        // Upsert (workspace_id is the PRIMARY KEY → one branding per workspace).
        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_branding (workspace_id, logo_r2_key, logo_mime, logo_sha256, logo_width, logo_height, logo_bytes, display_name, updated_at, updated_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
             ON CONFLICT(workspace_id) DO UPDATE SET
               logo_r2_key = excluded.logo_r2_key, logo_mime = excluded.logo_mime, logo_sha256 = excluded.logo_sha256,
               logo_width = excluded.logo_width, logo_height = excluded.logo_height, logo_bytes = excluded.logo_bytes,
               display_name = COALESCE(excluded.display_name, workspace_branding.display_name),
               updated_at = datetime('now'), updated_by = excluded.updated_by`
          )
          .bind(workspaceId, key, v.value.mime, v.value.sha256, v.value.width, v.value.height, v.value.size, displayName, user.id).run();
        await createAuditEvent(env, { workspace_id: workspaceId, user_id: user.id, event_type: "branding_logo_set", entity_type: "workspace", entity_id: workspaceId, description: "Workspace report logo set", metadata: { sha256: v.value.sha256, mime: v.value.mime } }).catch(() => {});
        return json({ ok: true, has_logo: true, logo: { mime: v.value.mime, width: v.value.width, height: v.value.height, sha256: v.value.sha256 } });
      } catch (e) { return serverError("branding/put", e); }
    }
    return json({ error: "Method not allowed" }, 405);
  }

  // ── MSP branding profiles (account-scoped, white_label entitled) ─────────
  const profListMatch = url.pathname === "/api/account/branding/profiles";
  const profItemMatch = url.pathname.match(/^\/api\/account\/branding\/profiles\/([^/]+)$/);
  if (profListMatch || profItemMatch) {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: "Unauthorized" }, 401);
    if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
    // Profiles belong to the account owner. A member manages only their own account's.
    const ownerId = user.id;
    const plan = await getEffectivePlan(ownerId, env);
    const whiteLabelEntitled = hasFeatureEntitlement(plan, "white_label");

    if (profListMatch && request.method === "GET") {
      try {
        const rows = await env.cybermeters_db
          .prepare(`SELECT id, name, logo_mime, logo_sha256, accent, mode, is_default, updated_at FROM msp_branding_profiles WHERE owner_user_id = ? ORDER BY is_default DESC, updated_at DESC`)
          .bind(ownerId).all();
        return json({ profiles: rows.results || [], white_label_available: whiteLabelEntitled });
      } catch (e) { return serverError("branding/profiles/list", e); }
    }

    if (profListMatch && request.method === "POST") {
      if (!whiteLabelEntitled) return json({ error: "plan_feature_required", feature: "white_label", required_plan: "business" }, 403);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const name = typeof body.name === "string" ? body.name.trim().slice(0, 120) : "";
      if (!name) return json({ error: "name is required" }, 400);
      const mode = body.mode === "white_label" ? "white_label" : "co_brand";
      const HEX = /^#[0-9a-fA-F]{6}$/;
      const accent = HEX.test(String(body.accent || "")) ? body.accent : null;
      let logoKey = null, logoMime = null, logoSha = null;
      if (body.logo) {
        const bytes = dataUriToBytes(body.logo);
        if (!bytes) return json({ error: "logo must be a data: URI (image/png or image/jpeg)" }, 400);
        const v = await validateLogoUpload(bytes);
        if (!v.ok) return json({ error: v.error }, 400);
        logoKey = mspLogoKey(ownerId, v.value.sha256, v.value.ext); logoMime = v.value.mime; logoSha = v.value.sha256;
        try { await env.cybermeters_reports.put(logoKey, v.value.bytes, { httpMetadata: { contentType: v.value.mime } }); } catch (e) { return serverError("branding/profiles/logo", e); }
      }
      const id = "mbp-" + createId();
      try {
        if (body.is_default) await env.cybermeters_db.prepare(`UPDATE msp_branding_profiles SET is_default = 0 WHERE owner_user_id = ?`).bind(ownerId).run();
        await env.cybermeters_db
          .prepare(`INSERT INTO msp_branding_profiles (id, owner_user_id, name, logo_r2_key, logo_mime, logo_sha256, accent, mode, is_default) VALUES (?,?,?,?,?,?,?,?,?)`)
          .bind(id, ownerId, name, logoKey, logoMime, logoSha, accent, mode, body.is_default ? 1 : 0).run();
        return json({ ok: true, id, mode, is_default: !!body.is_default }, 201);
      } catch (e) { return serverError("branding/profiles/create", e); }
    }

    if (profItemMatch && request.method === "DELETE") {
      const pid = profItemMatch[1];
      try {
        // Scoped delete — owner_user_id in the WHERE prevents cross-account deletion.
        const r = await env.cybermeters_db.prepare(`DELETE FROM msp_branding_profiles WHERE id = ? AND owner_user_id = ?`).bind(pid, ownerId).run();
        return json({ ok: true, deleted: (r.meta?.changes || 0) > 0 });
      } catch (e) { return serverError("branding/profiles/delete", e); }
    }
    return json({ error: "Method not allowed" }, 405);
  }

  return null;
}
