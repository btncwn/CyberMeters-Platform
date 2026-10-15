import { getEffectivePlanState, hasFeatureEntitlement } from "../engines/entitlements.js";

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

function validId(value) {
  return typeof value === "string" && ID_RE.test(value);
}

function validScopes(scopes) {
  return Array.isArray(scopes) && scopes.length <= 3 &&
    scopes.every((scope) => ALLOWED_SCOPES.has(scope)) &&
    scopes.includes("mcp:read") && new Set(scopes).size === scopes.length;
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
      typeof token.clientId !== "string" || token.clientId.length > 2048 ||
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
    if (plan.source === "error" || !hasFeatureEntitlement(plan.plan, "portfolio_monitoring")) return null;
    const member = await env.cybermeters_db.prepare(
      `SELECT w.id FROM workspace_members wm
         JOIN workspaces w ON w.id = wm.workspace_id AND w.deleted_at IS NULL
         JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
        WHERE wm.user_id = ? AND wm.role IN ('viewer','analyst','admin','owner')
          AND NOT EXISTS (SELECT 1 FROM deletion_requests d
             WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
               AND d.status NOT IN ('completed','cancelled'))
        LIMIT 1`,
    ).bind(token.userId).first();
    if (!member) return null;
  } else {
    if (!validId(connection.workspace_id) ||
        token.props.workspaceId !== connection.workspace_id ||
        token.props.portfolioRead !== false || granted.includes("portfolio:read") ||
        token.scope.includes("portfolio:read")) return null;
    const access = await env.cybermeters_db.prepare(
      `SELECT wm.role FROM workspaces w
         JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
         JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
        WHERE w.id = ? AND w.deleted_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM deletion_requests d
             WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
               AND d.status NOT IN ('completed','cancelled')) LIMIT 1`,
    ).bind(token.userId, connection.workspace_id).first();
    if (!ROLES.has(access?.role)) return null;
  }
  return token;
}

/** Consent may name only live, beta-enrolled memberships. */
export async function listMcpOAuthConsentWorkspaces(env, userId) {
  if (!env?.cybermeters_db || !validId(userId)) return null;
  const user = await env.cybermeters_db.prepare(
    `SELECT status, email_verified FROM users WHERE id = ?
       AND NOT EXISTS (SELECT 1 FROM deletion_requests d
          WHERE d.request_type = 'account' AND d.user_id = users.id
            AND d.status NOT IN ('completed','cancelled')) LIMIT 1`,
  ).bind(userId).first();
  if (user?.status !== "active" || Number(user.email_verified) !== 1) return null;
  const data = await env.cybermeters_db.prepare(
    `SELECT w.id, w.name, wm.role FROM workspace_members wm
       JOIN workspaces w ON w.id = wm.workspace_id AND w.deleted_at IS NULL
       JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
      WHERE wm.user_id = ? AND wm.role IN ('viewer','analyst','admin','owner')
        AND NOT EXISTS (SELECT 1 FROM deletion_requests d
           WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
             AND d.status NOT IN ('completed','cancelled'))
      ORDER BY w.name ASC, w.id ASC LIMIT ?`,
  ).bind(userId, MAX_CONSENT_WORKSPACES + 1).all();
  if (!Array.isArray(data?.results) ||
      data.results.length === 0 || data.results.length > MAX_CONSENT_WORKSPACES) return null;
  const workspaces = data.results.filter((row) => validId(row.id) && ROLES.has(row.role) &&
    typeof row.name === "string" && row.name.length <= 256);
  return workspaces.length === data.results.length && workspaces.length > 0 ? workspaces : null;
}

export async function canGrantMcpPortfolio(env, userId) {
  const plan = await getEffectivePlanState(userId, env);
  return plan.source !== "error" && hasFeatureEntitlement(plan.plan, "portfolio_monitoring");
}

/** Bounded owner-scoped history page for the customer's connection list. */
export async function listMcpOAuthConnections(env, userId, offset = 0) {
  if (!env?.cybermeters_db || !validId(userId) || !Number.isInteger(offset) ||
      offset < 0 || offset > 100_000) return null;
  const pageSize = 50;
  const rows = await env.cybermeters_db.prepare(
    `SELECT c.id, c.client_id, c.workspace_id, w.name AS workspace_name,
            c.portfolio_read, c.granted_scopes, c.status, c.created_at,
            c.last_used_at, c.revoked_at
       FROM mcp_oauth_connections c LEFT JOIN workspaces w ON w.id = c.workspace_id
      WHERE c.user_id = ? ORDER BY c.status ASC, c.created_at DESC, c.id DESC
      LIMIT ? OFFSET ?`,
  ).bind(userId, pageSize + 1, offset).all();
  if (!Array.isArray(rows?.results)) throw new Error("mcp_oauth_connections_unavailable");
  const connections = rows.results.slice(0, pageSize).map((row) => ({
    id: row.id, client_id: row.client_id, workspace_id: row.workspace_id,
    workspace_name: row.workspace_name ?? null,
    portfolio_read: Number(row.portfolio_read) === 1,
    scopes: JSON.parse(row.granted_scopes), status: row.status,
    created_at: row.created_at, last_used_at: row.last_used_at, revoked_at: row.revoked_at,
  }));
  return { connections, next_offset: rows.results.length > pageSize ? offset + pageSize : null };
}

export function mcpOAuthScopeAllowed(scope, portfolioRead) {
  return validScopes(scope) && (portfolioRead ? scope.includes("portfolio:read") :
    !scope.includes("portfolio:read"));
}
