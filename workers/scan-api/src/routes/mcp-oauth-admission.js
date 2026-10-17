import { getEffectivePlanState, hasFeatureEntitlement } from "../engines/entitlements.js";
import { drainRevokedMcpOAuthGrantBacklog } from "./mcp-oauth-purge.js";
import { mcpFounderCanaryAllowsUser, mcpFounderCanaryAllowsWorkspace } from "./mcp-founder-canary.js";

export const MCP_OAUTH_ISSUER = "https://api.cybermeters.com";
export const MCP_OAUTH_RESOURCE = "https://mcp.cybermeters.com/mcp";
export const MCP_OAUTH_APP_ORIGIN = "https://app.cybermeters.com";
const STAGING = Object.freeze({
  issuer: "https://api-staging.cybermeters.com",
  resource: "https://mcp-staging.cybermeters.com/mcp",
  appOrigin: "https://app-staging.cybermeters.com",
});
const PRODUCTION = Object.freeze({
  issuer: MCP_OAUTH_ISSUER, resource: MCP_OAUTH_RESOURCE,
  appOrigin: MCP_OAUTH_APP_ORIGIN,
});

/** Only an explicit staging tier selects the fixed staging origin trio. */
export function resolveMcpOAuthConfig(env) {
  const tier = env?.MCP_DEPLOYMENT_TIER;
  const expected = tier === "staging" ? STAGING : PRODUCTION;
  if (tier && tier !== "staging" && tier !== "production") {
    throw new Error("mcp_oauth_invalid_deployment_tier");
  }
  for (const [key, field] of [
    ["MCP_STAGING_ISSUER", "issuer"],
    ["MCP_STAGING_RESOURCE", "resource"],
    ["MCP_STAGING_APP_ORIGIN", "appOrigin"],
  ]) {
    if (env?.[key] !== undefined &&
        (tier !== "staging" || env[key] !== expected[field])) {
      throw new Error("mcp_oauth_invalid_staging_configuration");
    }
  }
  return expected;
}

const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const ROLES = new Set(["viewer", "analyst", "admin", "owner"]);
const MAX_CONSENT_WORKSPACES = 500;
const PKCE_S256 = /^[A-Za-z0-9_-]{43}$/;
const ALLOWED_SCOPES = new Set(["mcp:read", "portfolio:read", "offline_access"]);

export const mcpCimdEnabled = (env) => env?.MCP_OAUTH_CIMD_ENABLED === "true";

/** CIMD is a separate registration lane from DCR. Only reviewed, exact client
 * metadata URLs may enter it; a missing or malformed list disables CIMD. */
export function isMcpOAuthClientAllowed(env, clientId) {
  if (typeof clientId !== "string" || !clientId || clientId.length > 2048) return false;
  // DCR issues 16-character base64url-alphabet IDs. Treat only this bounded
  // opaque form as registration-backed; every URL-like or malformed ID fails.
  if (!/^https:/i.test(clientId)) return ID_RE.test(clientId);
  if (!mcpCimdEnabled(env)) return false;
  let parsed;
  try { parsed = new URL(clientId); } catch { return false; }
  if (parsed.protocol !== "https:" || clientId !== parsed.toString() ||
      parsed.username || parsed.password || parsed.hash || parsed.search ||
      parsed.pathname === "/" || clientId.length > 500) return false;
  let configured;
  try { configured = JSON.parse(env?.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS ?? "[]"); }
  catch { return false; }
  return Array.isArray(configured) && configured.length <= 20 &&
    configured.every((id) => typeof id === "string" && id.length <= 500) &&
    configured.includes(clientId);
}

function validId(value) {
  return typeof value === "string" && ID_RE.test(value);
}

function validScopes(scopes) {
  return Array.isArray(scopes) && scopes.length <= 3 &&
    scopes.every((scope) => ALLOWED_SCOPES.has(scope)) &&
    scopes.includes("mcp:read") && new Set(scopes).size === scopes.length;
}

// Trial is an explicit, unexpired billing state. A post-trial account has
// source "none" even though its historical evidence remains readable in the
// app; that state is not part of the invitation-only MCP beta.
function singleWorkspacePlanAllowed(state) {
  return ["trial", "paid", "grace"].includes(state?.source) &&
    ["starter", "professional", "business", "enterprise"].includes(state.plan);
}

function portfolioPlanAllowed(state) {
  return ["paid", "grace"].includes(state?.source) &&
    hasFeatureEntitlement(state.plan, "portfolio_monitoring");
}

/** A plan downgrade invalidates the whole selected-workspace consent. Revoke
 * the D1 fence immediately; migration 124 durably queues eventual KV deletion.
 * Single-workspace consent requires a new authorization by the customer. */
export async function reconcileMcpOAuthPortfolioPlan(env, userId, resolvedPlan) {
  if (!env?.cybermeters_db || !validId(userId)) throw new Error("mcp_oauth_plan_unavailable");
  const state = resolvedPlan ?? await getEffectivePlanState(userId, env);
  if (state.source === "error") throw new Error("mcp_oauth_plan_unavailable");
  if (portfolioPlanAllowed(state)) return { revoked: 0 };
  const result = await env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_connections SET status = 'revoked',
      revoked_at = COALESCE(revoked_at, datetime('now'))
      WHERE user_id = ? AND portfolio_read = 1 AND status = 'active'`,
  ).bind(userId).run();
  const revoked = Number(result?.meta?.changes ?? result?.changes ?? 0);
  if (revoked > 0) await drainRevokedMcpOAuthGrantBacklog(env).catch(() => {});
  return { revoked };
}

/** Called after a Stripe subscription transition using the persisted owner,
 * not an untrusted webhook metadata user ID. Legacy pre-MCP installs skip it. */
export async function reconcileMcpOAuthPortfolioSubscription(env, subscriptionRowId) {
  if (!env?.cybermeters_db || !validId(subscriptionRowId)) return { revoked: 0 };
  const installed = await env.cybermeters_db.prepare(
    `SELECT 1 FROM sqlite_master WHERE type = 'table'
      AND name = 'mcp_oauth_connections' LIMIT 1`,
  ).bind().first();
  if (!installed) return { revoked: 0 };
  const owner = await env.cybermeters_db.prepare(
    "SELECT owner_user_id FROM subscriptions WHERE id = ? LIMIT 1",
  ).bind(subscriptionRowId).first();
  if (!owner?.owner_user_id) return { revoked: 0 };
  return reconcileMcpOAuthPortfolioPlan(env, owner.owner_user_id);
}

/** A portfolio grant contains an explicit snapshot of selected workspaces.
 * Every selected workspace must still be live, enrolled and a membership;
 * losing any one fails the entire grant closed. Newly joined workspaces never
 * appear in an older grant. */
export async function listMcpOAuthGrantedWorkspaces(env, userId, connectionId) {
  if (!env?.cybermeters_db || !validId(userId) || !validId(connectionId)) return null;
  const data = await env.cybermeters_db.prepare(
    `SELECT selected.workspace_id AS id, w.name, w.owner_user_id, w.deleted_at, wm.role,
            b.status AS beta_status,
            EXISTS (SELECT 1 FROM deletion_requests d
              WHERE d.request_type = 'workspace' AND d.workspace_id = selected.workspace_id
                AND d.status NOT IN ('completed','cancelled')) AS deleting
       FROM mcp_oauth_connection_workspaces selected
       LEFT JOIN workspaces w ON w.id = selected.workspace_id
       LEFT JOIN workspace_members wm ON wm.workspace_id = selected.workspace_id
         AND wm.user_id = ?
       LEFT JOIN mcp_beta_workspace_access b ON b.workspace_id = selected.workspace_id
      WHERE selected.connection_id = ? ORDER BY selected.workspace_id ASC LIMIT ?`,
  ).bind(userId, connectionId, MAX_CONSENT_WORKSPACES + 1).all();
  if (!Array.isArray(data?.results) || data.results.length === 0 ||
      data.results.length > MAX_CONSENT_WORKSPACES ||
      data.results.some((row) => !validId(row.id) ||
        typeof row.name !== "string" || row.name.length > 256 ||
        !mcpFounderCanaryAllowsWorkspace(env, userId, row.owner_user_id) ||
        row.deleted_at !== null || row.beta_status !== "enabled" ||
        !ROLES.has(row.role) || Number(row.deleting) !== 0)) return null;
  return data.results.map((row) => ({ id: row.id, name: row.name, role: row.role }));
}

/** The library checks client, redirect and PKCE for public clients; our beta
 * also requires S256 for confidential clients and an explicit baseline scope. */
export function validMcpOAuthAuthorizationRequest(parsed, resource = MCP_OAUTH_RESOURCE) {
  return parsed?.responseType === "code" && parsed.resource === resource &&
    parsed.codeChallengeMethod === "S256" && PKCE_S256.test(parsed.codeChallenge ?? "") &&
    validScopes(parsed.scope);
}

/** The consent handle must resolve to exactly the request shown for this intent. */
export function sameMcpOAuthAuthorizationRequest(expected, approved) {
  if (!expected || !approved || !Array.isArray(expected.scope) ||
      !Array.isArray(approved.scope)) return false;
  return ["responseType", "clientId", "redirectUri", "state", "codeChallenge",
    "codeChallengeMethod", "resource", "issuer"].every((key) =>
    expected[key] === approved[key]) &&
    expected.scope.length === approved.scope.length &&
    expected.scope.every((scope, index) => scope === approved.scope[index]);
}

/**
 * Every token validation repeats this D1 fence. KV is eventually consistent,
 * so KV grant deletion alone cannot be the revocation or tenant boundary.
 * Database failures deliberately propagate to the resource server as 503.
 */
export async function admitMcpOAuthToken(env, token, resource = MCP_OAUTH_RESOURCE) {
  if (!env?.cybermeters_db) throw new Error("mcp_oauth_database_unavailable");
  if (!token || typeof token !== "object" ||
      token.audience !== resource || !validId(token.userId) ||
      !mcpFounderCanaryAllowsUser(env, token.userId) ||
      typeof token.clientId !== "string" || token.clientId.length > 2048 ||
      !isMcpOAuthClientAllowed(env, token.clientId) ||
      !validId(token.props?.connectionId) || token.props.userId !== token.userId ||
      !validScopes(token.scope)) return null;

  const connection = await env.cybermeters_db.prepare(
    `SELECT c.id, c.user_id, c.client_id, c.resource, c.workspace_id,
            c.portfolio_read, c.granted_scopes, c.status, u.status AS user_status,
            u.email_verified
       FROM mcp_oauth_connections c JOIN users u ON u.id = c.user_id
      WHERE c.id = ? LIMIT 1`,
  ).bind(token.props.connectionId).first();
  if (!connection || connection.status !== "active" ||
      connection.user_status !== "active" || Number(connection.email_verified) !== 1 ||
      connection.user_id !== token.userId || connection.client_id !== token.clientId ||
      connection.resource !== resource) return null;
  const deletingAccount = await env.cybermeters_db.prepare(
    `SELECT 1 FROM deletion_requests WHERE request_type = 'account' AND user_id = ?
      AND status NOT IN ('completed','cancelled') LIMIT 1`,
  ).bind(token.userId).first();
  if (deletingAccount) return null;

  let granted;
  try { granted = JSON.parse(connection.granted_scopes); } catch { return null; }
  if (!validScopes(granted) || token.scope.some((scope) => !granted.includes(scope))) return null;

  if (Number(connection.portfolio_read) === 1) {
    if (connection.workspace_id !== null || token.props.workspaceId !== null ||
        token.props.portfolioRead !== true || !granted.includes("portfolio:read") ||
        !token.scope.includes("portfolio:read")) return null;
    const plan = await getEffectivePlanState(token.userId, env);
    if (plan.source === "error") return null;
    if (!portfolioPlanAllowed(plan)) {
      await reconcileMcpOAuthPortfolioPlan(env, token.userId, plan);
      return null;
    }
    if (!(await listMcpOAuthGrantedWorkspaces(env, token.userId, connection.id))) return null;
  } else {
    if (!validId(connection.workspace_id) ||
        token.props.workspaceId !== connection.workspace_id ||
        token.props.portfolioRead !== false || granted.includes("portfolio:read") ||
        token.scope.includes("portfolio:read")) return null;
    const plan = await getEffectivePlanState(token.userId, env);
    if (!singleWorkspacePlanAllowed(plan)) return null;
    const access = await env.cybermeters_db.prepare(
      `SELECT wm.role, w.owner_user_id FROM workspaces w
         JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
         JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
        WHERE w.id = ? AND w.deleted_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM deletion_requests d
             WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
               AND d.status NOT IN ('completed','cancelled')) LIMIT 1`,
    ).bind(token.userId, connection.workspace_id).first();
    if (!ROLES.has(access?.role) ||
        !mcpFounderCanaryAllowsWorkspace(env, token.userId, access.owner_user_id)) return null;
  }
  return token;
}

/** Consent may name only live, beta-enrolled memberships. */
export async function listMcpOAuthConsentWorkspaces(env, userId) {
  if (!env?.cybermeters_db || !validId(userId) ||
      !mcpFounderCanaryAllowsUser(env, userId)) return null;
  const user = await env.cybermeters_db.prepare(
    `SELECT status, email_verified FROM users WHERE id = ?
       AND NOT EXISTS (SELECT 1 FROM deletion_requests d
          WHERE d.request_type = 'account' AND d.user_id = users.id
            AND d.status NOT IN ('completed','cancelled')) LIMIT 1`,
  ).bind(userId).first();
  if (user?.status !== "active" || Number(user.email_verified) !== 1) return null;
  // Do not offer consent choices to an expired Trial or an account without an
  // entitled plan: authorization would deny the same request at token issue.
  const plan = await getEffectivePlanState(userId, env);
  if (!singleWorkspacePlanAllowed(plan)) return null;
  const founderCanary = env.MCP_DEPLOYMENT_TIER !== "staging";
  const data = await env.cybermeters_db.prepare(
    `SELECT w.id, w.name, w.owner_user_id, wm.role FROM workspace_members wm
       JOIN workspaces w ON w.id = wm.workspace_id AND w.deleted_at IS NULL
       JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
      WHERE wm.user_id = ? AND wm.role IN ('viewer','analyst','admin','owner')
        ${founderCanary ? "AND w.owner_user_id = ?" : ""}
        AND NOT EXISTS (SELECT 1 FROM deletion_requests d
           WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
             AND d.status NOT IN ('completed','cancelled'))
      ORDER BY w.name ASC, w.id ASC LIMIT ?`,
  ).bind(userId, ...(founderCanary ? [userId] : []), MAX_CONSENT_WORKSPACES + 1).all();
  if (!Array.isArray(data?.results) ||
      data.results.length === 0 || data.results.length > MAX_CONSENT_WORKSPACES) return null;
  const valid = data.results.every((row) => validId(row.id) && ROLES.has(row.role) &&
    typeof row.name === "string" && row.name.length <= 256 &&
    mcpFounderCanaryAllowsWorkspace(env, userId, row.owner_user_id));
  return valid ? data.results.map(({ id, name, role }) => ({ id, name, role })) : null;
}

export async function canGrantMcpPortfolio(env, userId) {
  const plan = await getEffectivePlanState(userId, env);
  return portfolioPlanAllowed(plan);
}

/** Bounded owner-scoped history page for the customer's connection list. */
export async function listMcpOAuthConnections(env, userId, offset = 0) {
  if (!env?.cybermeters_db || !validId(userId) || !Number.isInteger(offset) ||
      offset < 0 || offset > 100_000) return null;
  await reconcileMcpOAuthPortfolioPlan(env, userId);
  const pageSize = 50;
  const rows = await env.cybermeters_db.prepare(
    `SELECT c.id, c.client_id, c.workspace_id, w.name AS workspace_name,
            c.portfolio_read, c.granted_scopes, c.status, c.created_at,
            c.last_used_at, c.revoked_at,
            (SELECT COUNT(*) FROM mcp_oauth_connection_workspaces selected
              WHERE selected.connection_id = c.id) AS selected_workspace_count
       FROM mcp_oauth_connections c LEFT JOIN workspaces w ON w.id = c.workspace_id
      WHERE c.user_id = ? ORDER BY c.status ASC, c.created_at DESC, c.id DESC
      LIMIT ? OFFSET ?`,
  ).bind(userId, pageSize + 1, offset).all();
  if (!Array.isArray(rows?.results)) throw new Error("mcp_oauth_connections_unavailable");
  const page = rows.results.slice(0, pageSize);
  const selectedByConnection = new Map(page.map((row) => [row.id, []]));
  if (page.length) {
    const placeholders = page.map(() => "?").join(",");
    const selected = await env.cybermeters_db.prepare(
      `SELECT s.connection_id, s.workspace_id, w.name AS workspace_name
         FROM mcp_oauth_connection_workspaces s
         JOIN mcp_oauth_connections c ON c.id = s.connection_id AND c.user_id = ?
         JOIN workspaces w ON w.id = s.workspace_id
        WHERE s.connection_id IN (${placeholders})
        ORDER BY s.connection_id ASC, s.workspace_id ASC LIMIT 2501`,
    ).bind(userId, ...page.map((row) => row.id)).all();
    if (!Array.isArray(selected?.results) || selected.results.length > 2500) {
      throw new Error("mcp_oauth_connections_unavailable");
    }
    for (const row of selected.results) {
      const list = selectedByConnection.get(row.connection_id);
      if (!list || !validId(row.workspace_id) ||
          typeof row.workspace_name !== "string" || row.workspace_name.length > 256 ||
          list.length >= 50) throw new Error("mcp_oauth_connections_unavailable");
      list.push({ workspace_id: row.workspace_id, workspace_name: row.workspace_name });
    }
  }
  const connections = page.map((row) => ({
    id: row.id, client_id: row.client_id, workspace_id: row.workspace_id,
    workspace_name: row.workspace_name ?? null,
    portfolio_read: Number(row.portfolio_read) === 1,
    selected_workspace_count: Number(row.selected_workspace_count),
    selected_workspaces: selectedByConnection.get(row.id),
    scopes: JSON.parse(row.granted_scopes), status: row.status,
    created_at: row.created_at, last_used_at: row.last_used_at, revoked_at: row.revoked_at,
  }));
  return { connections, next_offset: rows.results.length > pageSize ? offset + pageSize : null };
}

export function mcpOAuthScopeAllowed(scope, portfolioRead) {
  return validScopes(scope) && (portfolioRead ? scope.includes("portfolio:read") :
    !scope.includes("portfolio:read"));
}
