// ── Website Security: signed-in scanning routes (migration 116) ─────────────
//
//   GET    /api/workspaces/:id/website-security/sign-in            — profiles (no secrets)
//   PUT    /api/workspaces/:id/website-security/sign-in/:domain    — create / replace
//   DELETE /api/workspaces/:id/website-security/sign-in/:domain    — delete (secret destroyed)
//   POST   /api/workspaces/:id/website-security/sign-in/:domain/test — sign in now
//
// Writes and tests: an owner/admin SESSION only (never an API token), on a
// verified domain of a live workspace, with an active paid plan or trial and
// the dedicated key ring present. Membership, workspace and domain are
// re-checked after every network await, as the DNS connection routes do.
// Foreign and unverified domains get the same 403.
import { canonicalDomain, boundedDnsJson } from "../engines/cloudflare-dns.js";
import { getEffectivePlan } from "../engines/entitlements.js";
import { getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { dnsQuery } from "../engines/dns.js";
import { normalizeSignInInput } from "../engines/website-sign-in.js";
import {
  SignInError, planAllowsSignedInScanning, signInVaultAvailable, loadSignInProfile, saveSignInProfile,
  deleteSignInProfile, recordSignInAttempt, testSignInProfile, listSignInProfiles, signInProfileView,
} from "../engines/website-sign-in-profiles.js";

export const SIGN_IN_SCOPE_NOTE =
  "CyberMeters signs in to your own verified site with a test account you provide, then checks a small number of "
  + "pages behind the sign-in with read-only requests. The sign-in form is the only thing ever submitted; addresses "
  + "that could change something (sign-out, delete, unsubscribe) and API endpoints are never requested. Credentials "
  + "are encrypted, are never shown again, and are only ever sent over HTTPS to this domain. CAPTCHA, one-time codes "
  + "and sign-in through another site (single sign-on) are not bypassed. Use a dedicated low-privilege test account.";

const MESSAGES = {
  unauthorized: "Sign in to continue.",
  forbidden: "You do not have access to this workspace.",
  session_role_required: "A workspace owner or admin session is required.",
  domain_not_verified: "Verify this domain in this workspace first.",
  plan_required: "Signed-in scanning needs an active paid plan or trial.",
  vault_unavailable: "Signed-in scanning is temporarily unavailable.",
  unsupported_input: "Check the sign-in details.",
  authorization_required: "Confirm that you are allowed to let CyberMeters sign in to this site.",
  profile_not_found: "Signed-in scanning is not set up for this domain.",
  profile_not_saved: "Your changes were not saved. Reload and try again.",
  credentials_required: "Enter the sign-in details again.",
};

function domainParam(raw) {
  try { return canonicalDomain(decodeURIComponent(raw)); } catch { throw new SignInError("unsupported_input", 400); }
}

export async function websiteSignInRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;
  const listMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/website-security\/sign-in$/);
  const testMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/website-security\/sign-in\/([^/]+)\/test$/);
  const itemMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/website-security\/sign-in\/([^/]+)$/);
  const match = listMatch || testMatch || itemMatch;
  if (!match) return null;
  const workspaceId = match[1], db = env.cybermeters_db;
  try {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: MESSAGES.unauthorized, code: "unauthorized" }, 401);
    const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
    if (!access) return json({ error: MESSAGES.forbidden, code: "forbidden" }, 403);
    const live = await db.prepare("SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL").bind(workspaceId).first();
    if (!live) return json({ error: "Workspace not found", code: "workspace_not_found" }, 404);
    const canManage = !user.api_token_id && ["owner", "admin"].includes(access.role);
    const planAllows = async () => planAllowsSignedInScanning(await getEffectivePlan(await getWorkspaceBillingUserId(workspaceId, user.id, env), env));

    if (listMatch) {
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      const vault = signInVaultAvailable(env);
      const plan = canManage ? await planAllows() : null;
      return json({
        workspace_id: workspaceId,
        can_manage: canManage,
        can_use: canManage && vault && plan === true,
        reason: !canManage ? "session_role_required" : !vault ? "vault_unavailable" : !plan ? "plan_required" : null,
        domains: await listSignInProfiles(db, workspaceId),
        scope_note: SIGN_IN_SCOPE_NOTE,
      });
    }

    const isTest = Boolean(testMatch);
    if (isTest ? request.method !== "POST" : !["PUT", "DELETE"].includes(request.method)) return json({ error: "Method not allowed" }, 405);
    if (!canManage) throw new SignInError("session_role_required", 403);
    const domain = domainParam(match[2]);
    const lookupDomain = () => db.prepare(
      `SELECT d.id, d.domain FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
        WHERE wd.workspace_id = ? AND d.domain = ? AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL`)
      .bind(workspaceId, domain).first();
    const owned = await lookupDomain();
    if (!owned) throw new SignInError("domain_not_verified", 403);
    // Re-checked after every await that leaves the Worker.
    const authorize = async (requirePlan) => {
      const current = await requireAuth(request, env);
      if (!current || current.id !== user.id || current.api_token_id) throw new SignInError("session_role_required", 403);
      const role = await requireWorkspaceRole(current, workspaceId, "workspace:manage", env);
      if (!role || !["owner", "admin"].includes(role.role)) throw new SignInError("session_role_required", 403);
      const active = await db.prepare("SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL").bind(workspaceId).first();
      if (!active || !(await lookupDomain())) throw new SignInError("domain_not_verified", 403);
      if (requirePlan && !(await planAllows())) throw new SignInError("plan_required", 403);
    };
    const limit = async (action, max) => {
      const limited = await consumeApiRateLimit(env, [{ scope: "workspace", scope_id: workspaceId }], action, max, 3600, { atomic: true, failClosed: true });
      return limited ? json(limited.body, limited.status) : null;
    };

    if (request.method === "DELETE") {
      await authorize(false);
      const result = await deleteSignInProfile(env, { workspaceId, domainId: owned.id, domain, userId: user.id });
      return json(result);
    }

    if (request.method === "PUT") {
      if (!/^application\/json(?:;|$)/i.test(request.headers.get("content-type") || "")) throw new SignInError("unsupported_input", 400);
      const limited = await limit("website_sign_in_change", 20);
      if (limited) return limited;
      let body;
      try { body = await boundedDnsJson(request, 16_384); } catch { throw new SignInError("unsupported_input", 400); }
      await authorize(true);
      if (!signInVaultAvailable(env)) throw new SignInError("vault_unavailable", 503);
      const existing = await loadSignInProfile(db, workspaceId, owned.id);
      let input;
      try { input = normalizeSignInInput(body, { domain, existing }); }
      catch (e) { return json({ error: MESSAGES[e.code] || "Check the sign-in details.", code: e.code || "unsupported_input" }, 400); }
      const row = await saveSignInProfile(env, { workspaceId, domainId: owned.id, domain, userId: user.id, input, existing });
      return json({ profile: signInProfileView(row), scope_note: SIGN_IN_SCOPE_NOTE }, existing ? 200 : 201);
    }

    // POST …/test
    const limited = await limit("website_sign_in_test", 6);
    if (limited) return limited;
    await authorize(true);
    const profile = await loadSignInProfile(db, workspaceId, owned.id);
    if (!profile) throw new SignInError("profile_not_found", 404);
    // Bounded: 16 requests, 25 s. Same SSRF/public-DNS checks as scans.
    const startedAt = Date.now();
    const result = await testSignInProfile(env, {
      workspaceId, domainId: owned.id, domain, profile,
      opts: { dnsResolver: dnsQuery, dnsCache: new Map(), remainingMs: () => 25_000 - (Date.now() - startedAt), ...(rctx.signInOptions || {}) },
    });
    await authorize(false);
    await recordSignInAttempt(env, {
      workspaceId, domainId: owned.id, profile, source: "test", actorUserId: user.id,
      outcome: result.outcome, detail: result.detail,
    });
    const after = await loadSignInProfile(db, workspaceId, owned.id);
    return json({ outcome: result.outcome, detail: result.detail, profile: signInProfileView(after) });
  } catch (error) {
    const known = error instanceof SignInError;
    const code = known ? error.code : "sign_in_unavailable";
    return json({ error: MESSAGES[code] || "Signed-in scanning is temporarily unavailable.", code }, known ? error.status : 503);
  }
}
