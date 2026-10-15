import {
  AuthorizationError, CimdFetchError, OAuthAuthorizationServer, OAuthError,
} from "@cloudflare/workers-oauth-provider";
import { hashToken } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import {
  admitMcpOAuthToken, canGrantMcpPortfolio, listMcpOAuthConnections,
  listMcpOAuthConsentWorkspaces,
  MCP_OAUTH_APP_ORIGIN, MCP_OAUTH_ISSUER, MCP_OAUTH_RESOURCE,
  resolveMcpOAuthConfig, sameMcpOAuthAuthorizationRequest,
  validMcpOAuthAuthorizationRequest,
} from "./mcp-oauth-admission.js";
import {
  bridgeMcpOAuthBrowserSession, claimMcpOAuthBrowserSession, claimMcpOAuthStartBudget,
  claimMcpOAuthTokenBudget,
  clearMcpOAuthBrowserSession,
  createMcpOAuthIntent, expireMcpOAuthBrowserCookie, mcpOAuthCorsHeaders,
  mcpOAuthJson, readBoundedMcpOAuthBody, readMcpOAuthBrowserSession, readMcpOAuthIntent,
  requireMcpWebSession,
} from "./mcp-oauth-browser.js";
import { evaluateMcpDcrRegistration } from "./mcp-oauth-dcr.js";

const CONNECTION_RE = /^mcpconn_[a-f0-9-]{36}$/;
const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

function config(env, options = {}) {
  const canonical = resolveMcpOAuthConfig(env);
  // Internal options are for isolated local tests; HTTP input never reaches here.
  return {
    issuer: options.issuer ?? canonical.issuer,
    resource: options.resource ?? canonical.resource,
    appOrigin: options.appOrigin ?? canonical.appOrigin,
    ...(options.testClientIp ? { testClientIp: options.testClientIp } : {}),
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) =>
    `&#${character.charCodeAt(0)};`);
}

function plain(message, status = 400) {
  return new Response(message, { status, headers: {
    ...NO_STORE, "Content-Type": "text/plain; charset=utf-8",
  } });
}

export function createMcpOAuthAuthorizationServer(env, options = {}) {
  const { issuer, resource } = config(env, options);
  return new OAuthAuthorizationServer({
    issuer, resources: [resource],
    scopesSupported: ["mcp:read", "portfolio:read", "offline_access"],
    clientIdMetadataDocumentEnabled: true,
    ...(env?.MCP_OAUTH_DCR_ENABLED === "true" ? { clientRegistrationEndpoint: "/oauth/register" } : {}),
    clientRegistrationTTL: 90 * 24 * 60 * 60,
    clientRegistrationCallback: (input) => evaluateMcpDcrRegistration(input, env, options),
    allowTokenExchangeGrant: false,
    accessTokenTTL: 15 * 60,
    refreshTokenTTL: 7 * 24 * 60 * 60,
    cookiePrefix: "__Host-cm-mcp-oauth-",
    tokenExchangeCallback: async (input) => {
      const current = await admitMcpOAuthToken(input.env, {
        props: input.props, audience: input.resource, scope: input.scope,
        userId: input.userId, clientId: input.clientId,
      }, resource);
      if (!current) throw new OAuthError("invalid_grant", {
        description: "CyberMeters authorization was revoked or is no longer available",
      });
    },
  });
}

/** Shared by the gateway RPC and every backend read. D1 errors are not 401s. */
export async function validateMcpOAuthToken(env, resource, token, options = {}) {
  if (env?.MCP_CUSTOMER_OAUTH_ENABLED !== "true" || resource !== config(env, options).resource ||
      typeof token !== "string" || token.length < 32 || token.length > 4096) return null;
  if (!env.OAUTH_KV || !env.cybermeters_db) throw new Error("mcp_oauth_unconfigured");
  const validated = await createMcpOAuthAuthorizationServer(env, options)
    .validateToken(resource, token, env);
  return admitMcpOAuthToken(env, validated, resource);
}

export {
  revokeMcpOAuthUserGrantsForPurge,
  revokeMcpOAuthConnectionGrantsForPurge,
} from "./mcp-oauth-purge.js";

function validRequestOrigin(request, expected) {
  try { return new URL(request.url).origin === expected; } catch { return false; }
}

function authorizeUrlFromIntent(intent, expectedIssuer) {
  try {
    const url = new URL(intent.authorization_url);
    return url.origin === expectedIssuer && url.pathname === "/authorize" &&
      url.search.length <= 4096 && !url.searchParams.has("intent")
      ? url : null;
  } catch { return null; }
}

function consentPage(details, handle, intent, workspaces, portfolioAvailable, requestedScope) {
  const placeholder = '<option value="" selected disabled>Choose one workspace or portfolio access</option>';
  const workspaceOptions = workspaces.map((row) =>
    `<option value="${escapeHtml(row.id)}">${escapeHtml(row.name)} (${escapeHtml(row.role)})</option>`).join("");
  const portfolioOption = portfolioAvailable && requestedScope.includes("portfolio:read")
    ? `<option value="portfolio">All currently permitted CyberMeters workspaces (portfolio read)</option>` : "";
  const clientIdentity = details.clientDomain
    ? `Published by ${escapeHtml(details.clientDomain)}.`
    : "This app registered itself; its name has not been verified.";
  const localWarning = details.redirectIsLoopback
    ? `<p><strong>Access will be delivered to an app on this computer. Continue only if you started the connection.</strong></p>` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Connect CyberMeters</title></head>
<body><main><h1>Connect ${escapeHtml(details.clientName)} to CyberMeters?</h1>
<p>${clientIdentity}</p><p>Access will be delivered to ${escapeHtml(details.redirectHost)}.</p>${localWarning}
<p>This connection is read-only. It cannot change DNS, start scans, create cases, or manage users.</p>
<p>The app receives a 15-minute access token and can renew read access for up to 7 days from this authorization. After 7 days, you must reconnect. You can revoke access in CyberMeters at any time.</p>
<p>The connected app may retain data it reads under its own data handling terms. Review the app before allowing access.</p>
<form method="post" action="/authorize?intent=${encodeURIComponent(intent)}">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<label for="context">CyberMeters access</label><select id="context" name="context" required>${placeholder}${workspaceOptions}${portfolioOption}</select>
<p>Permission: read CyberMeters evidence${portfolioOption ? "; portfolio access is separate and shown above" : ""}.</p>
<p><button type="submit" name="decision" value="approve">Allow</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button></p></form></main></body></html>`;
}

function consentHeaders(headers) {
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  return headers;
}

async function processAuthorize(request, env, server, options) {
  const { issuer, resource, appOrigin } = config(env, options);
  const oauth = server.getOAuthApi(env);
  const url = new URL(request.url);
  const intentOpaque = url.searchParams.get("intent");
  if (request.method === "GET" && !intentOpaque) {
    if (request.url.length > 4096) return plain("Invalid authorization request");
    if (!(await claimMcpOAuthStartBudget(request, env, options))) {
      return plain("Authorization temporarily unavailable", 503);
    }
    const parsed = await oauth.parseAuthRequest(request);
    if (!validMcpOAuthAuthorizationRequest(parsed, resource)) return plain("Invalid authorization request");
    await oauth.describeConsent(parsed); // Verify CIMD before persisting any intent.
    const intent = await createMcpOAuthIntent(request, env, { ...options, budgetClaimed: true });
    if (!intent) return plain("Authorization temporarily unavailable", 503);
    return new Response(null, { status: 302, headers: {
      ...NO_STORE, Location: `${appOrigin}/mcp/connect?intent=${intent}`,
      "Referrer-Policy": "no-referrer",
    } });
  }
  if (!intentOpaque || !["GET", "POST"].includes(request.method)) return plain("Invalid authorization request");
  const intent = await readMcpOAuthIntent(env, intentOpaque);
  const original = intent && authorizeUrlFromIntent(intent, issuer);
  if (!intent || !original) return plain("Authorization expired", 400);
  const browser = await readMcpOAuthBrowserSession(request, env, intent.id_hash);
  if (!browser) return plain("Authorization session expired", 401);
  const originalRequest = new Request(original.toString(), { method: "GET" });
  const parsed = await oauth.parseAuthRequest(originalRequest);
  if (!validMcpOAuthAuthorizationRequest(parsed, resource)) return plain("Invalid authorization request");
  const workspaces = await listMcpOAuthConsentWorkspaces(env, browser.user_id);
  if (!workspaces) return plain("CyberMeters access unavailable", 403);
  const portfolioAvailable = parsed.scope.includes("portfolio:read") &&
    workspaces.length > 1 && await canGrantMcpPortfolio(env, browser.user_id);
  if (request.method === "GET") {
    const details = await oauth.describeConsent(parsed);
    const consent = await oauth.beginConsent(parsed);
    return new Response(consentPage(details, consent.handle, intentOpaque,
      workspaces, portfolioAvailable, parsed.scope), { headers: consentHeaders(consent.headers) });
  }

  if (request.headers.get("Origin") !== issuer ||
      request.headers.get("Content-Type")?.split(";")[0] !== "application/x-www-form-urlencoded") {
    return plain("Invalid authorization request", 403);
  }
  const formText = await readBoundedMcpOAuthBody(request, 4096);
  if (formText === null) return plain("Invalid authorization request", 400);
  const form = new URLSearchParams(formText);
  if (["handle", "decision"].some((name) => form.getAll(name).length !== 1) ||
      form.getAll("context").length > 1 ||
      [...form.keys()].some((name) => !["handle", "decision", "context"].includes(name))) {
    return plain("Invalid authorization request", 400);
  }
  const handle = form.get("handle");
  if (typeof handle !== "string" || handle.length > 512) return plain("Invalid authorization request");
  if (form.get("decision") !== "approve") {
    if (!(await claimMcpOAuthBrowserSession(request, env, intent.id_hash, browser.user_id))) {
      return plain("Authorization expired", 400);
    }
    const denied = await oauth.denyConsent(request, handle);
    await clearMcpOAuthBrowserSession(env, intent.id_hash);
    expireMcpOAuthBrowserCookie(denied.headers);
    return new Response(null, { status: 302, headers: denied.headers });
  }
  const selected = form.get("context");
  const portfolioRead = selected === "portfolio";
  if (form.getAll("context").length !== 1 || typeof selected !== "string" ||
      (portfolioRead ? !portfolioAvailable : !workspaces.some((row) => row.id === selected))) {
    return plain("CyberMeters access unavailable", 403);
  }
  const scope = ["mcp:read"];
  if (portfolioRead) scope.push("portfolio:read");
  if (parsed.scope.includes("offline_access")) scope.push("offline_access");
  if (!(await claimMcpOAuthBrowserSession(request, env, intent.id_hash, browser.user_id))) {
    return plain("Authorization expired", 400);
  }
  // Keep the transaction's original request intact for exact intent matching.
  // The grant is narrowed separately in completeAuthorization({ scope }).
  const approved = await oauth.approveConsent(request, handle);
  if (!sameMcpOAuthAuthorizationRequest(parsed, approved.request)) {
    return plain("Invalid authorization request");
  }

  const connectionId = `mcpconn_${crypto.randomUUID()}`;
  const workspaceId = portfolioRead ? null : selected;
  const insert = await env.cybermeters_db.prepare(
    `INSERT INTO mcp_oauth_connections
       (id, user_id, client_id, resource, workspace_id, portfolio_read, granted_scopes)
     SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (
       SELECT 1 FROM users u WHERE u.id = ? AND u.status = 'active' AND u.email_verified = 1
         AND NOT EXISTS (SELECT 1 FROM deletion_requests d
            WHERE d.request_type = 'account' AND d.user_id = u.id
              AND d.status NOT IN ('completed','cancelled'))
     ) AND (SELECT COUNT(*) FROM mcp_oauth_connections
              WHERE user_id = ? AND unixepoch(created_at) > unixepoch('now','-7 days')) < 25`,
  ).bind(connectionId, browser.user_id, parsed.clientId, resource,
    workspaceId, portfolioRead ? 1 : 0, JSON.stringify(scope),
    browser.user_id, browser.user_id).run();
  if (Number(insert?.meta?.changes ?? insert?.changes ?? 0) !== 1) return plain("CyberMeters access unavailable", 403);
  try {
    const admitted = await admitMcpOAuthToken(env, {
      props: { userId: browser.user_id, connectionId, workspaceId, portfolioRead },
      audience: resource, scope, userId: browser.user_id, clientId: parsed.clientId,
    }, resource);
    if (!admitted) throw new Error("mcp_oauth_grant_context_changed");
    const completed = await oauth.completeAuthorization({
      request: approved.request, userId: browser.user_id,
      metadata: { connectionId }, scope,
      props: { userId: browser.user_id, connectionId, workspaceId, portfolioRead },
      revokeExistingGrants: false,
    });
    const audit = await createAuditEvent(env, {
      workspace_id: workspaceId, user_id: browser.user_id,
      event_type: "mcp_oauth_grant_issued", entity_type: "mcp_oauth_connection",
      entity_id: connectionId, description: "MCP connection authorized",
      metadata: { client_id_hash: (await hashToken(parsed.clientId)).slice(0, 24),
        scopes: scope, portfolio_read: portfolioRead },
      required: true, active_workspace_required: Boolean(workspaceId),
    });
    if (audit !== true) throw new Error("mcp_audit_unavailable");
    await clearMcpOAuthBrowserSession(env, intent.id_hash);
    const headers = new Headers(approved.headers);
    headers.set("Location", completed.redirectTo);
    headers.set("Cache-Control", "no-store");
    expireMcpOAuthBrowserCookie(headers);
    return new Response(null, { status: 302, headers });
  } catch {
    await env.cybermeters_db.prepare(
      `UPDATE mcp_oauth_connections SET status = 'revoked', revoked_at = datetime('now')
        WHERE id = ?`,
    ).bind(connectionId).run();
    return plain("Authorization temporarily unavailable", 503);
  }
}

async function processConnections(request, env, server, options) {
  const cors = mcpOAuthCorsHeaders(request, options);
  if (request.method === "OPTIONS") return cors
    ? new Response(null, { status: 204, headers: { ...NO_STORE, ...cors } })
    : plain("Forbidden", 403);
  if (!cors) return plain("Forbidden", 403);
  const session = await requireMcpWebSession(request, env);
  if (!session) return mcpOAuthJson(request, { error: "unauthorized" }, 401, options);
  const url = new URL(request.url);
  if (url.pathname === "/api/mcp/oauth/connections" && request.method === "GET") {
    const rawOffset = url.searchParams.get("offset") ?? "0";
    if (url.searchParams.size > (url.searchParams.has("offset") ? 1 : 0) ||
        !/^(0|[1-9][0-9]{0,5})$/.test(rawOffset)) {
      return mcpOAuthJson(request, { error: "invalid_request" }, 400, options);
    }
    const page = await listMcpOAuthConnections(env, session.user_id, Number(rawOffset));
    const eligibleWorkspaces = await listMcpOAuthConsentWorkspaces(env, session.user_id);
    return page ? mcpOAuthJson(request, {
      ...page, eligible: Array.isArray(eligibleWorkspaces) && eligibleWorkspaces.length > 0,
    }, 200, options) :
      mcpOAuthJson(request, { error: "invalid_request" }, 400, options);
  }
  const match = /^\/api\/mcp\/oauth\/connections\/(mcpconn_[a-f0-9-]{36})$/.exec(url.pathname);
  if (!match || request.method !== "DELETE") return plain("Not found", 404);
  const connectionId = match[1];
  if (!CONNECTION_RE.test(connectionId)) return plain("Not found", 404);
  // D1 batch commits both statements or neither. A stable audit ID makes a
  // successful DELETE retryable after a lost response without duplicate events.
  const auditId = `audit_mcp_oauth_revoked_v1:${connectionId}`;
  const committed = await env.cybermeters_db.batch([
    env.cybermeters_db.prepare(
      `UPDATE mcp_oauth_connections
          SET status = 'revoked', revoked_at = COALESCE(revoked_at, datetime('now'))
        WHERE id = ? AND user_id = ? AND status IN ('active', 'revoked')`,
    ).bind(connectionId, session.user_id),
    env.cybermeters_db.prepare(
      `INSERT INTO audit_events
         (id, workspace_id, user_id, actor_type, event_type, entity_type,
          entity_id, description, metadata_json, created_at)
       SELECT ?, c.workspace_id, c.user_id, 'customer', 'mcp_oauth_grant_revoked',
              'mcp_oauth_connection', c.id, 'MCP connection revoked', NULL, datetime('now')
         FROM mcp_oauth_connections c
        WHERE c.id = ? AND c.user_id = ? AND c.status = 'revoked'
       ON CONFLICT(id) DO NOTHING`,
    ).bind(auditId, connectionId, session.user_id),
  ]);
  if (Number(committed?.[0]?.meta?.changes ?? committed?.[0]?.changes ?? 0) !== 1) {
    return mcpOAuthJson(request, { error: "not_found" }, 404, options);
  }
  // D1 status is the immediate access fence. Also remove the matching KV grant;
  // if KV is temporarily unavailable, no token can pass D1 validation.
  try {
    const oauth = server.getOAuthApi(env);
    let cursor;
    for (let page = 0; page < 10; page++) {
      const grants = await oauth.listUserGrants(session.user_id, { limit: 100, cursor });
      for (const grant of grants.items ?? []) {
        if (grant.metadata?.connectionId === connectionId) {
          await oauth.revokeGrant(grant.id, session.user_id);
        }
      }
      cursor = grants.cursor;
      if (!cursor) break;
    }
  } catch { /* D1 revocation remains authoritative. */ }
  return mcpOAuthJson(request, { revoked: true }, 200, options);
}

/** Route only exact OAuth paths from the API Worker; unrelated paths return null. */
export async function handleMcpOAuthRequest(request, env, ctx, options = {}) {
  const url = new URL(request.url);
  const path = url.pathname;
  const owned = path === "/authorize" ||
    path === "/.well-known/oauth-authorization-server" ||
    path === "/oauth/token" || path === "/oauth/register" ||
    path === "/api/mcp/oauth/browser-session" ||
    path === "/api/mcp/oauth/connections" || path.startsWith("/api/mcp/oauth/connections/");
  if (!owned) return null;
  let effective;
  try { effective = config(env, options); }
  catch { return plain("MCP OAuth is not configured", 503); }
  const { issuer } = effective;
  if (env?.MCP_CUSTOMER_OAUTH_ENABLED !== "true" || !env?.OAUTH_KV ||
      !env?.cybermeters_db || !validRequestOrigin(request, issuer)) {
    return plain("MCP OAuth is not configured", 503);
  }
  try {
    if (path === "/api/mcp/oauth/browser-session") {
      return bridgeMcpOAuthBrowserSession(request, env, effective);
    }
    const server = createMcpOAuthAuthorizationServer(env, effective);
    if (path === "/authorize") return await processAuthorize(request, env, server, effective);
    if (path === "/api/mcp/oauth/connections" || path.startsWith("/api/mcp/oauth/connections/")) {
      return await processConnections(request, env, server, effective);
    }
    if (path === "/oauth/register") {
      if (env.MCP_OAUTH_DCR_ENABLED !== "true") return plain("Not found", 404);
      if (request.method === "POST" && await readBoundedMcpOAuthBody(request.clone(), 8192) === null) {
        return plain("Registration request too large", 413);
      }
    }
    if (path === "/oauth/token") {
      if (request.method !== "POST") return plain("Method not allowed", 405);
      const limited = await claimMcpOAuthTokenBudget(request, env, effective);
      if (limited) return plain(limited.status === 429
        ? "Too many token requests" : "Token service temporarily unavailable", limited.status);
      if (request.headers.get("Content-Type")?.split(";")[0] !==
          "application/x-www-form-urlencoded" ||
          Number(request.headers.get("Content-Length") || 0) > 4096) {
        return plain("Invalid token request", 400);
      }
      const boundedBody = await readBoundedMcpOAuthBody(request, 4096);
      if (boundedBody === null) return plain("Invalid token request", 400);
      const headers = new Headers(request.headers);
      headers.delete("Content-Length");
      headers.delete("Transfer-Encoding");
      request = new Request(request.url, { method: "POST", headers, body: boundedBody });
    }
    return await server.fetch(request, env, ctx);
  } catch (error) {
    if (error instanceof AuthorizationError && error.redirectTo) {
      return new Response(null, { status: 302, headers: { ...NO_STORE, Location: error.redirectTo } });
    }
    if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
      return plain("Invalid authorization request", 400);
    }
    console.error(JSON.stringify({ event: "mcp_oauth_unavailable", path }));
    return plain("Authorization temporarily unavailable", 503);
  }
}
