import {
  AuthorizationError, CimdFetchError, OAuthAuthorizationServer, OAuthError,
} from "@cloudflare/workers-oauth-provider";
import { hashToken } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import {
  admitMcpOAuthToken, canGrantMcpPortfolio, isMcpOAuthClientAllowed, mcpCimdEnabled,
  listMcpOAuthConnections,
  listMcpOAuthConsentWorkspaces,
  MCP_OAUTH_APP_ORIGIN, MCP_OAUTH_ISSUER, MCP_OAUTH_RESOURCE,
  resolveMcpOAuthConfig, sameMcpOAuthAuthorizationRequest,
  validMcpOAuthAuthorizationRequest,
} from "./mcp-oauth-admission.js";
import {
  bridgeMcpOAuthBrowserSession, claimMcpOAuthBrowserSession,
  claimMcpOAuthStartIpBudget, claimMcpOAuthStartGlobalBudget,
  claimMcpOAuthTokenBudget, mcpOAuthGlobalBudgetSaturated,
  clearMcpOAuthBrowserSession, completeMcpOAuthBrowserSession, MCP_OAUTH_COMPLETED_INTENT,
  createMcpOAuthIntent, expireMcpOAuthBrowserCookie, mcpOAuthCorsHeaders,
  mcpOAuthJson, readBoundedMcpOAuthBody, readMcpOAuthBrowserSession, readMcpOAuthIntent,
  requireMcpWebSession,
} from "./mcp-oauth-browser.js";
import { applyMcpDcrDefaults, evaluateMcpDcrRegistration } from "./mcp-oauth-dcr.js";
import { drainRevokedMcpOAuthGrantBacklog } from "./mcp-oauth-purge.js";

const CONNECTION_RE = /^mcpconn_[a-f0-9-]{36}$/;
const MAX_PORTFOLIO_SELECTION = 50;
const SDK_REFRESH_TOKEN = /^([A-Za-z0-9_-]{1,128}):([A-Za-z0-9_-]{16}):[A-Za-z0-9_-]{32}$/;
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

// The SDK resolves URL-shaped client IDs by fetching their CIMD document.
// Check every place it could derive such an ID before handing the request to
// the SDK. The DCR callback does not run for CIMD clients.
function isAllowedAuthorizationClient(url, env) {
  const ids = url.searchParams.getAll("client_id");
  return ids.length === 1 && isMcpOAuthClientAllowed(env, ids[0]);
}

function assertionIssuer(assertion) {
  if (typeof assertion !== "string" || assertion.length > 8192) return null;
  const parts = assertion.split(".");
  if (parts.length !== 3 || parts.some((part) => !part || !/^[A-Za-z0-9_-]+$/.test(part))) return null;
  try {
    const decodePart = (part) => {
      const bytes = Uint8Array.from(atob(part.replace(/-/g, "+").replace(/_/g, "/")),
        (character) => character.charCodeAt(0));
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    };
    const header = decodePart(parts[0]);
    const claims = decodePart(parts[1]);
    // The SDK parses all three compact-JWS parts before looking up the client.
    atob(parts[2].replace(/-/g, "+").replace(/_/g, "/"));
    if (!header || typeof header !== "object" || Array.isArray(header) ||
        !claims || typeof claims !== "object" || Array.isArray(claims)) return null;
    return typeof claims.iss === "string" ? claims.iss : null;
  } catch { return null; }
}

function isAllowedTokenClient(request, body, env) {
  const form = new URLSearchParams(body);
  const ids = form.getAll("client_id");
  if (ids.length > 1) return false;
  const authorization = request.headers.get("Authorization") ?? "";
  const schemeEnd = authorization.search(/[ \t]/);
  const isBasic = (schemeEnd === -1 ? authorization :
    authorization.slice(0, schemeEnd)).toLowerCase() === "basic";
  if (isBasic) {
    if (schemeEnd === -1) return false;
    const encoded = authorization.slice(schemeEnd).trim();
    if (!encoded || /[ \t]/.test(encoded)) return false;
    try {
      const credentials = atob(encoded);
      const colon = credentials.indexOf(":");
      if (colon === -1) return false;
      ids.push(decodeURIComponent(credentials.slice(0, colon).replace(/\+/g, " ")));
    } catch { return false; }
  }
  const assertions = form.getAll("client_assertion");
  if (assertions.length > 1) return false;
  for (const assertion of assertions) {
    const issuer = assertionIssuer(assertion);
    if (!issuer) return false;
    ids.push(issuer);
  }
  // Never hand a token request to the SDK with an unidentified client. In
  // particular, the SDK can derive a CIMD URL from an assertion without a
  // client_id and fetch it before signature verification.
  return ids.length > 0 && ids.every((id) => id === ids[0]) &&
    isMcpOAuthClientAllowed(env, ids[0]);
}

async function exactRegisteredRedirect(oauth, clientId, redirectUri) {
  if (typeof clientId !== "string" || typeof redirectUri !== "string" ||
      redirectUri.length > 500) return false;
  const client = await oauth.lookupClient(clientId);
  return Array.isArray(client?.redirectUris) && client.redirectUris.includes(redirectUri);
}

export function createMcpOAuthAuthorizationServer(env, options = {}) {
  const { issuer, resource } = config(env, options);
  return new OAuthAuthorizationServer({
    issuer, resources: [resource],
    scopesSupported: ["mcp:read", "portfolio:read", "offline_access"],
    clientIdMetadataDocumentEnabled: mcpCimdEnabled(env),
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
      if (input.grantType === "authorization_code") {
        if (typeof input.grantId !== "string" || !/^[A-Za-z0-9_-]{16}$/.test(input.grantId)) {
          throw new OAuthError("invalid_grant", { description: "Authorization unavailable" });
        }
        const bound = await input.env.cybermeters_db.prepare(
          `UPDATE mcp_oauth_connections SET oauth_grant_id = ?
            WHERE id = ? AND user_id = ? AND status = 'active'
              AND (oauth_grant_id IS NULL OR oauth_grant_id = ?)`,
        ).bind(input.grantId, input.props.connectionId, input.userId, input.grantId).run();
        if (Number(bound?.meta?.changes ?? bound?.changes ?? 0) !== 1) {
          throw new OAuthError("invalid_grant", { description: "Authorization unavailable" });
        }
      }
    },
  });
}

/** Claim only after the SDK has successfully rotated a refresh token. D1's
 * unique hash key detects concurrent or later reuse; a repeat revokes the
 * entire connection. Raw credentials never leave this request. */
export async function claimMcpOAuthRefreshUse(env, rawToken) {
  const match = SDK_REFRESH_TOKEN.exec(rawToken ?? "");
  if (!match || !env?.cybermeters_db) return false;
  const [, userId, grantId] = match;
  const connection = await env.cybermeters_db.prepare(
    `SELECT id, workspace_id, status FROM mcp_oauth_connections
      WHERE user_id = ? AND oauth_grant_id = ? LIMIT 1`,
  ).bind(userId, grantId).first();
  if (!connection || connection.status !== "active") return false;
  const tokenHash = await hashToken(rawToken);
  const claimed = await env.cybermeters_db.prepare(
    `INSERT OR IGNORE INTO mcp_oauth_refresh_uses(token_hash, connection_id)
      VALUES (?, ?)`,
  ).bind(tokenHash, connection.id).run();
  if (Number(claimed?.meta?.changes ?? claimed?.changes ?? 0) === 1) return true;
  await revokeReusedRefreshConnection(env, connection.id, userId, connection.workspace_id);
  return false;
}

async function revokeReusedRefreshConnection(env, connectionId, userId, workspaceId) {
  await env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_connections SET status = 'revoked',
      revoked_at = COALESCE(revoked_at, datetime('now'))
      WHERE id = ? AND status = 'active'`,
  ).bind(connectionId).run();
  const audited = await createAuditEvent(env, {
    workspace_id: workspaceId, user_id: userId,
    event_type: "mcp_oauth_refresh_reused", entity_type: "mcp_oauth_connection",
    entity_id: connectionId, description: "MCP refresh token reused; connection revoked",
    metadata: { connection_id: connectionId }, required: true,
    active_workspace_required: false,
  });
  if (audited !== true) throw new Error("mcp_audit_unavailable");
}

/** The provider rejects an older rotated token once a newer replacement has
 * itself been used. Only a hash already claimed after a successful refresh can
 * trigger family revocation; arbitrary invalid tokens cannot name a grant. */
export async function revokeKnownMcpOAuthRefreshReplay(env, rawToken) {
  if (!SDK_REFRESH_TOKEN.test(rawToken ?? "") || !env?.cybermeters_db) return false;
  const tokenHash = await hashToken(rawToken);
  const known = await env.cybermeters_db.prepare(
    `SELECT c.id, c.user_id, c.workspace_id, c.status
       FROM mcp_oauth_refresh_uses used
       JOIN mcp_oauth_connections c ON c.id = used.connection_id
      WHERE used.token_hash = ? LIMIT 1`,
  ).bind(tokenHash).first();
  if (!known) return false;
  if (known.status === "active") {
    await revokeReusedRefreshConnection(env, known.id, known.user_id, known.workspace_id);
  }
  return true;
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
    ? '<option value="portfolio">Selected workspaces (portfolio read)</option>' : "";
  const portfolioChoices = portfolioOption
    ? `<fieldset><legend>For portfolio access, choose up to ${MAX_PORTFOLIO_SELECTION} customer workspaces. None are selected by default.</legend>${workspaces.map((row) =>
      `<label><input type="checkbox" name="selected_workspace_id" value="${escapeHtml(row.id)}"> ${escapeHtml(row.name)} (${escapeHtml(row.role)})</label><br>`).join("")}</fieldset>` : "";
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
<p>The connected app can receive workspace names, domains, security findings and evidence, scan and case status, and report summaries within your approved access. The app or its provider may retain data it receives under its own terms and settings.</p>
<p>Revoking this connection stops future CyberMeters reads, but cannot delete data already sent to the app. Review the app before allowing access.</p>
<form method="post" action="/authorize?intent=${encodeURIComponent(intent)}">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<label for="context">CyberMeters access</label><select id="context" name="context" required>${placeholder}${workspaceOptions}${portfolioOption}</select>
${portfolioChoices}
<p>Requested scopes: ${escapeHtml(requestedScope.join(", "))}. Granted scopes: mcp:read${portfolioOption ? "; portfolio:read only when you choose a portfolio set" : ""}${requestedScope.includes("offline_access") ? "; offline_access for refresh" : ""}.</p>
<p><button type="submit" name="decision" value="approve">Allow</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button></p></form></main></body></html>`;
}

function consentHeaders(headers, redirectUri) {
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Security-Policy", `default-src 'none'; form-action 'self' ${new URL(redirectUri).origin}; frame-ancestors 'none'; base-uri 'none'`);
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  // Keep the intent URL off cross-origin requests while preserving Origin on the same-origin consent POST.
  headers.set("Referrer-Policy", "same-origin");
  return headers;
}

async function processAuthorize(request, env, server, options) {
  const { issuer, resource, appOrigin } = config(env, options);
  const oauth = server.getOAuthApi(env);
  const url = new URL(request.url);
  const intentOpaque = url.searchParams.get("intent");
  if (request.method === "GET" && !intentOpaque) {
    if (request.url.length > 4096) return plain("Invalid authorization request");
    if (!isAllowedAuthorizationClient(url, env)) return plain("Invalid authorization request");
    if (await mcpOAuthGlobalBudgetSaturated(env, "mcp_authorize_start", 8, 60) ||
        !(await claimMcpOAuthStartIpBudget(request, env, options))) {
      return plain("Authorization temporarily unavailable", 503);
    }
    const parsed = await oauth.parseAuthRequest(request);
    if (!validMcpOAuthAuthorizationRequest(parsed, resource)) return plain("Invalid authorization request");
    if (!(await exactRegisteredRedirect(oauth, parsed.clientId, parsed.redirectUri))) {
      return plain("Invalid authorization request");
    }
    if (!(await claimMcpOAuthStartGlobalBudget(env))) {
      return plain("Authorization temporarily unavailable", 503);
    }
    await oauth.describeConsent(parsed); // Verify CIMD before persisting any intent.
    const intent = await createMcpOAuthIntent(request, env, { ...options, budgetClaimed: true });
    if (!intent) return plain("Authorization temporarily unavailable", 503);
    return new Response(null, { status: 302, headers: {
      // The one-time intent rides in the fragment: never sent to a server or to
      // page analytics, and cleared from the address bar by the app on load.
      ...NO_STORE, Location: `${appOrigin}/mcp/connect#intent=${intent}`,
      "Referrer-Policy": "no-referrer",
    } });
  }
  if (!intentOpaque || !["GET", "POST"].includes(request.method)) return plain("Invalid authorization request");
  const intent = await readMcpOAuthIntent(env, intentOpaque, { includeCompleted: true });
  const original = intent && authorizeUrlFromIntent(intent, issuer);
  if (!intent || !original) return missingIntentResponse(intent);
  if (!isAllowedAuthorizationClient(original, env)) return plain("Invalid authorization request");
  const browser = await readMcpOAuthBrowserSession(request, env, intent.id_hash);
  if (!browser) return plain("Authorization session expired", 401);
  const originalRequest = new Request(original.toString(), { method: "GET" });
  const parsed = await oauth.parseAuthRequest(originalRequest);
  if (!validMcpOAuthAuthorizationRequest(parsed, resource)) return plain("Invalid authorization request");
  if (!(await exactRegisteredRedirect(oauth, parsed.clientId, parsed.redirectUri))) {
    return plain("Invalid authorization request");
  }
  const workspaces = await listMcpOAuthConsentWorkspaces(env, browser.user_id);
  if (!workspaces) return plain("CyberMeters access unavailable", 403);
  const portfolioAvailable = parsed.scope.includes("portfolio:read") &&
    workspaces.length > 1 && await canGrantMcpPortfolio(env, browser.user_id);
  if (request.method === "GET") {
    const details = await oauth.describeConsent(parsed);
    const consent = await oauth.beginConsent(parsed);
    return new Response(consentPage(details, consent.handle, intentOpaque,
      workspaces, portfolioAvailable, parsed.scope), { headers: consentHeaders(consent.headers, parsed.redirectUri) });
  }

  if (request.headers.get("Origin") !== issuer ||
      request.headers.get("Content-Type")?.split(";")[0] !== "application/x-www-form-urlencoded") {
    return plain("Invalid authorization request", 403);
  }
  const formText = await readBoundedMcpOAuthBody(request, 16_384);
  if (formText === null) return plain("Invalid authorization request", 400);
  const form = new URLSearchParams(formText);
  if (["handle", "decision"].some((name) => form.getAll(name).length !== 1) ||
      form.getAll("context").length > 1 ||
      [...form.keys()].some((name) => !["handle", "decision", "context", "selected_workspace_id"].includes(name))) {
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
  const selectedWorkspaceIds = form.getAll("selected_workspace_id");
  if (portfolioRead ? selectedWorkspaceIds.length < 1 ||
      selectedWorkspaceIds.length > MAX_PORTFOLIO_SELECTION ||
      new Set(selectedWorkspaceIds).size !== selectedWorkspaceIds.length ||
      selectedWorkspaceIds.some((id) => !workspaces.some((row) => row.id === id))
    : selectedWorkspaceIds.length !== 0) {
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
  const connectionInsert = env.cybermeters_db.prepare(
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
    browser.user_id, browser.user_id);
  const selectedInsert = portfolioRead ? env.cybermeters_db.prepare(
    `INSERT INTO mcp_oauth_connection_workspaces(connection_id, workspace_id)
      VALUES ${selectedWorkspaceIds.map(() => "(?, ?)").join(", ")}`,
  ).bind(...selectedWorkspaceIds.flatMap((id) => [connectionId, id])) : null;
  const results = portfolioRead
    ? await env.cybermeters_db.batch([connectionInsert, selectedInsert])
    : [await connectionInsert.run()];
  const insert = results?.[0];
  if (Number(insert?.meta?.changes ?? insert?.changes ?? 0) !== 1) return plain("CyberMeters access unavailable", 403);
  if (portfolioRead && Number(results?.[1]?.meta?.changes ?? results?.[1]?.changes ?? 0) !==
      selectedWorkspaceIds.length) return plain("CyberMeters access unavailable", 403);
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
        scopes: scope, portfolio_read: portfolioRead,
        selected_workspace_count: selectedWorkspaceIds.length,
        selected_workspace_ids: selectedWorkspaceIds },
      required: true, active_workspace_required: Boolean(workspaceId),
    });
    if (audit !== true) throw new Error("mcp_audit_unavailable");
    await completeMcpOAuthBrowserSession(env, intent.id_hash);
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

async function processConnections(request, env, options) {
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
  // The revoke trigger also marks KV cleanup pending. D1 includes that trigger
  // update in meta.changes, so a successful one-row revoke may report 2.
  if (Number(committed?.[0]?.meta?.changes ?? committed?.[0]?.changes ?? 0) < 1) {
    return mcpOAuthJson(request, { error: "not_found" }, 404, options);
  }
  // D1 rejects the token immediately. The migration's durable queue removes
  // provider KV state in bounded chunks, including after a transient outage.
  await drainRevokedMcpOAuthGrantBacklog(env).catch(() => {});
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
    let refreshCredential = null;
    if (path === "/api/mcp/oauth/browser-session") {
      return bridgeMcpOAuthBrowserSession(request, env, effective);
    }
    const server = createMcpOAuthAuthorizationServer(env, effective);
    if (path === "/authorize") return await processAuthorize(request, env, server, effective);
    if (path === "/api/mcp/oauth/connections" || path.startsWith("/api/mcp/oauth/connections/")) {
      return await processConnections(request, env, effective);
    }
    if (path === "/oauth/register") {
      if (env.MCP_OAUTH_DCR_ENABLED !== "true") return plain("Not found", 404);
      if (request.method === "POST") {
        const registrationBody = await readBoundedMcpOAuthBody(request.clone(), 8192);
        if (registrationBody === null) return plain("Registration request too large", 413);
        // RFC 7591 defaults go in before the library reads the body: it would
        // otherwise register a missing auth method as a secret-holding client.
        let parsed;
        try { parsed = JSON.parse(registrationBody); } catch { parsed = undefined; }
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const headers = new Headers(request.headers);
          headers.delete("Content-Length");
          headers.delete("Transfer-Encoding");
          request = new Request(request.url, { method: "POST", headers,
            body: JSON.stringify(applyMcpDcrDefaults(parsed)) });
        }
      }
    }
    if (path === "/oauth/token") {
      if (request.method !== "POST") return plain("Method not allowed", 405);
      if (request.headers.get("Content-Type")?.split(";")[0] !==
          "application/x-www-form-urlencoded" ||
          Number(request.headers.get("Content-Length") || 0) > 4096) {
        return plain("Invalid token request", 400);
      }
      const boundedBody = await readBoundedMcpOAuthBody(request, 4096);
      if (boundedBody === null) return plain("Invalid token request", 400);
      if (!isAllowedTokenClient(request, boundedBody, env)) return plain("Invalid client", 401);
      const form = new URLSearchParams(boundedBody);
      if (form.getAll("grant_type").length === 0 && form.has("token")) {
        if (form.getAll("token").length !== 1 ||
            !SDK_REFRESH_TOKEN.test(form.get("token") ?? "")) {
          return plain("Invalid token request", 400);
        }
      } else if (form.getAll("grant_type").length !== 1) {
        return plain("Invalid token request", 400);
      } else if (form.get("grant_type") === "authorization_code") {
        const code = form.get("code");
        const verifier = form.get("code_verifier");
        if (form.getAll("client_id").length !== 1 ||
            form.getAll("redirect_uri").length !== 1 ||
            form.getAll("code").length !== 1 ||
            form.getAll("code_verifier").length !== 1 ||
            typeof code !== "string" || code.length < 1 || code.length > 1024 ||
            typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
            !(await exactRegisteredRedirect(server.getOAuthApi(env),
              form.get("client_id"), form.get("redirect_uri")))) {
          return plain("Invalid token request", 400);
        }
      } else if (form.get("grant_type") === "refresh_token") {
        if (form.getAll("refresh_token").length !== 1 ||
            !SDK_REFRESH_TOKEN.test(form.get("refresh_token") ?? "")) {
          return mcpOAuthJson(request, { error: "invalid_grant" }, 400, options);
        }
        refreshCredential = form.get("refresh_token");
      } else return plain("Invalid token request", 400);
      const limited = await claimMcpOAuthTokenBudget(request, env, effective);
      if (limited) return plain(limited.status === 429
        ? "Too many token requests" : "Token service temporarily unavailable", limited.status);
      const headers = new Headers(request.headers);
      headers.delete("Content-Length");
      headers.delete("Transfer-Encoding");
      request = new Request(request.url, { method: "POST", headers, body: boundedBody });
    }
    const response = await server.fetch(request, env, ctx);
    if (refreshCredential !== null && response.status === 200) {
      // A malformed success must never bypass the single-use ledger.
      const issued = await response.clone().json();
      if (typeof issued?.access_token !== "string" ||
          typeof issued?.refresh_token !== "string") {
        throw new Error("mcp_oauth_invalid_refresh_result");
      }
      if (!(await claimMcpOAuthRefreshUse(env, refreshCredential))) {
        return mcpOAuthJson(request, { error: "invalid_grant" }, 400, options);
      }
    } else if (refreshCredential !== null && response.status === 400) {
      // The provider's wire error deliberately omits refresh_token_mismatch.
      // An already redeemed hash proves replay even after its grace period.
      if (await revokeKnownMcpOAuthRefreshReplay(env, refreshCredential)) {
        return mcpOAuthJson(request, { error: "invalid_grant" }, 400, options);
      }
    }
    return response;
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

function missingIntentResponse(intent) {
  return intent?.authorization_url === MCP_OAUTH_COMPLETED_INTENT
    ? plain("This connection was already authorised. Return to your app.", 200)
    : plain("Authorization expired", 400);
}
