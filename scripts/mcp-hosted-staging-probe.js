#!/usr/bin/env node
// End-to-end proof against the isolated, synthetic MCP staging deployment.
// This script performs remote writes (login, DCR, OAuth consent and audit), so
// it requires the exact --run-hosted-staging argument. Never pass real users.

import { createHash, randomBytes, randomInt } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MCP_STAGING_IDENTITIES } from "./generate-mcp-staging-fixture.js";
import { runGeminiSyntheticMcpProbe } from "./mcp-gemini-api-staging-probe.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const API = "https://api-staging.cybermeters.com";
const APP = "https://app-staging.cybermeters.com";
const MCP = "https://mcp-staging.cybermeters.com";
const RESOURCE = `${MCP}/mcp`;
const CREDENTIALS = path.join(root, "local/mcp-staging-fixture-credentials.json");
const REUSABLE_CLIENT = path.join(root, "local/mcp-staging-reusable-client.json");
const REQUEST_TIMEOUT_MS = 12_000;
const MAX_RESPONSE_BYTES = 96 * 1024;
const OPAQUE = /^[A-Za-z0-9_-]{43}$/;
const CONNECTION = /^mcpconn_[a-f0-9-]{36}$/;
const API_PATHS = new Set([
  "/health", "/ready", "/api/auth/login", "/api/auth/me",
  "/api/auth/logout", "/api/auth/signup", "/api/free-scan", "/api/workspaces",
  "/api/billing/plans", "/.well-known/oauth-authorization-server",
  "/oauth/register", "/oauth/token", "/api/mcp/oauth/browser-session",
  "/api/mcp/oauth/connections",
]);
export const EXPECTED_TOOL_NAMES = Object.freeze([
  "cybermeters_list_workspaces", "cybermeters_get_workspace_summary",
  "cybermeters_get_workspace_posture", "cybermeters_list_recent_scans",
  "cybermeters_get_scan_status", "cybermeters_list_managed_cases",
  "cybermeters_get_managed_case",
  "cybermeters_list_domains", "cybermeters_list_findings",
  "cybermeters_explain_finding", "cybermeters_get_tls_posture",
  "cybermeters_get_email_posture", "cybermeters_get_report_summary",
  "cybermeters_get_portfolio_summary",
]);
const EXPECTED_TOOLS = new Set(EXPECTED_TOOL_NAMES);
const RELIABILITY_READ_ROUNDS = 5;
const SAFE_DISCOVERY_ERRORS = new Set([
  "mcp_not_configured", "mcp_rate_limited", "invalid_bearer", "invalid_token",
  "insufficient_scope", "access_denied", "request_denied", "invalid_request",
  "mcp_protocol_error", "mcp_response_too_large", "unsupported_media_type",
]);
const SAFE_JSONRPC_ERRORS = new Set([-32700, -32600, -32601, -32602, -32603, -32000]);

class HostedFailure extends Error {}
function check(condition, message) {
  if (!condition) throw new HostedFailure(message);
}

/** Defense in depth: no fetched URL can be supplied by a server or CLI to a
 * production host, a loopback callback, or any third-party domain. */
export function isAllowedHostedStagingUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.hash) return false;
    if (url.origin === API) {
      if (url.pathname === "/authorize") return true;
      if (url.pathname === "/api/mcp/oauth/connections" && url.search) {
        return url.searchParams.size === 1 &&
          /^(0|[1-9][0-9]{0,5})$/.test(url.searchParams.get("offset") ?? "");
      }
      return !url.search && (
        API_PATHS.has(url.pathname) ||
        /^\/api\/mcp\/oauth\/connections\/mcpconn_[a-f0-9-]{36}$/.test(url.pathname));
    }
    if (url.origin === APP) return !url.search && url.pathname === "/mcp/connect";
    if (url.origin === MCP) return !url.search &&
      ["/mcp", "/.well-known/oauth-protected-resource/mcp"].includes(url.pathname);
    return false;
  } catch { return false; }
}

function readSyntheticCredentials() {
  const local = path.join(root, "local");
  check(/^local\/$/m.test(fs.readFileSync(path.join(root, ".gitignore"), "utf8")),
    "Synthetic credential directory is not ignored by Git");
  check(fs.realpathSync(local) === local, "Ignored local fixture directory is not canonical");
  const stat = fs.lstatSync(CREDENTIALS);
  check(stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0 &&
    fs.realpathSync(CREDENTIALS) === CREDENTIALS,
  "Synthetic credential file must be a private, regular ignored file");
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(CREDENTIALS, "utf8")); }
  catch { throw new HostedFailure("Cannot read synthetic staging credentials"); }
  check(parsed?.kind === "synthetic-mcp-staging-only" &&
    Array.isArray(parsed.accounts) && parsed.accounts.length === 2,
  "Synthetic staging credential format is invalid");
  for (const [index, account] of parsed.accounts.entries()) {
    check(account?.email === MCP_STAGING_IDENTITIES[index].email &&
      typeof account.password === "string" && account.password.length >= 40 &&
      /^[A-Za-z0-9_-]+$/.test(account.password),
    "Synthetic staging credential identity is invalid");
  }
  check(parsed.accounts[0].password !== parsed.accounts[1].password,
    "Synthetic staging account passwords must differ");
  return parsed.accounts;
}

export function isReusableSyntheticClientRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["callback", "clientId"]) ||
      typeof value.clientId !== "string" || !/^[A-Za-z0-9_-]{16}$/.test(value.clientId) ||
      typeof value.callback !== "string" || value.callback.length > 80) return false;
  try {
    const callback = new URL(value.callback);
    const port = Number(callback.port);
    return callback.protocol === "http:" && callback.hostname === "127.0.0.1" &&
      port >= 49152 && port <= 65535 && callback.pathname === "/callback" &&
      !callback.username && !callback.password && !callback.search && !callback.hash &&
      callback.toString() === value.callback;
  } catch { return false; }
}

function readReusableSyntheticClient() {
  const local = path.join(root, "local");
  check(/^local\/$/m.test(fs.readFileSync(path.join(root, ".gitignore"), "utf8")) &&
    fs.realpathSync(local) === local,
  "Reusable synthetic client directory must be canonical and ignored by Git");
  let stat;
  try { stat = fs.lstatSync(REUSABLE_CLIENT); }
  catch { throw new HostedFailure("Reusable synthetic client file is missing or unreadable"); }
  check(stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0 &&
    fs.realpathSync(REUSABLE_CLIENT) === REUSABLE_CLIENT,
  "Reusable synthetic client file must be private, regular and ignored");
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(REUSABLE_CLIENT, "utf8")); }
  catch { throw new HostedFailure("Cannot read reusable synthetic client file"); }
  check(isReusableSyntheticClientRecord(parsed),
    "Reusable synthetic client must have one opaque ID and exact loopback callback");
  return parsed;
}

async function hostedFetch(value, init = {}) {
  check(isAllowedHostedStagingUrl(value), "Refused an address outside the exact staging allowlist");
  // Every redirect is reviewed before it is used; no token or credential can
  // follow a Location header automatically.
  return fetch(value, { ...init, redirect: "manual", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
}

async function boundedText(response, label) {
  check(response.body, `${label}: empty response`);
  const reader = response.body.getReader();
  const pieces = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new HostedFailure(`${label}: oversized response`);
      }
      pieces.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of pieces) { bytes.set(part, offset); offset += part.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new HostedFailure(`${label}: invalid response encoding`); }
}

async function boundedJson(response, label) {
  const raw = await boundedText(response, label);
  try { return JSON.parse(raw); }
  catch { throw new HostedFailure(`${label}: invalid JSON`); }
}

function status(response, expected, label) {
  check(response.status === expected, `${label}: HTTP ${response.status}; expected ${expected}`);
}

function locationUrl(response, label) {
  const value = response.headers.get("Location");
  check(typeof value === "string" && value.length <= 8192,
    `${label}: missing or oversized redirect`);
  try { return new URL(value, API); }
  catch { throw new HostedFailure(`${label}: invalid redirect`); }
}

function setCookie(response, prefix, label) {
  const listed = response.headers.getSetCookie?.();
  const headers = listed?.length ? listed :
    [response.headers.get("Set-Cookie")].filter(Boolean);
  const matches = headers.filter((value) => value.startsWith(prefix));
  const cookie = matches[0]?.split(";", 1)[0];
  check(matches.length === 1 && cookie?.length <= 768 &&
    /^[A-Za-z0-9_-]+=[A-Za-z0-9_-]+$/.test(cookie) &&
    /;\s*Secure(?:;|$)/i.test(matches[0]) &&
    /;\s*HttpOnly(?:;|$)/i.test(matches[0]) &&
    /;\s*Path=\/(?:;|$)/i.test(matches[0]) &&
    !/;\s*Domain=/i.test(matches[0]),
  `${label}: expected exactly one secure OAuth cookie`);
  return cookie;
}

async function preflight() {
  const health = await hostedFetch(`${API}/health`);
  status(health, 200, "Staging health");
  const healthBody = await boundedJson(health, "Staging health");
  check(healthBody.service === "cybermeters-scan-api" && healthBody.maintenance === true,
    "Staging API must remain in maintenance mode");
  const ready = await hostedFetch(`${API}/ready`);
  status(ready, 200, "Staging readiness");
  const readyBody = await boundedJson(ready, "Staging readiness");
  check(readyBody.checks?.d1 === true && readyBody.checks?.r2 === true,
    "Dedicated staging storage is not ready");

  // These requests must be stopped before route body handling. No account or
  // scan can be created by this probe, even if maintenance is accidentally off.
  for (const [method, pathname] of [
    ["POST", "/api/auth/signup"], ["POST", "/api/free-scan"],
    ["GET", "/api/workspaces"], ["GET", "/api/billing/plans"],
  ]) {
    const response = await hostedFetch(`${API}${pathname}`, { method });
    status(response, 503, `Maintenance fence ${method} ${pathname}`);
    const body = await boundedJson(response, "Maintenance fence");
    check(body.code === "maintenance", `Maintenance fence ${method} ${pathname} is not active`);
  }

  const app = await hostedFetch(`${APP}/mcp/connect`);
  status(app, 200, "Staging app");
  const csp = app.headers.get("Content-Security-Policy") ?? "";
  check(csp.includes("connect-src 'self' https://api-staging.cybermeters.com ") &&
    !csp.includes("https://api.cybermeters.com"),
  "Staging app CSP does not point at the staging API");

  const metadata = await hostedFetch(`${API}/.well-known/oauth-authorization-server`);
  status(metadata, 200, "OAuth metadata");
  const oauth = await boundedJson(metadata, "OAuth metadata");
  check(oauth.issuer === API && oauth.authorization_endpoint === `${API}/authorize` &&
    oauth.token_endpoint === `${API}/oauth/token` &&
    oauth.registration_endpoint === `${API}/oauth/register`,
  "OAuth metadata does not name the exact staging endpoints");
  const resource = await hostedFetch(`${MCP}/.well-known/oauth-protected-resource/mcp`);
  status(resource, 200, "MCP resource metadata");
  const advertised = await boundedJson(resource, "MCP resource metadata");
  check(advertised.resource === RESOURCE &&
    JSON.stringify(advertised.authorization_servers) === JSON.stringify([API]),
  "MCP resource metadata does not name the exact staging issuer");
}

async function login(account) {
  const response = await hostedFetch(`${API}/api/auth/login`, {
    method: "POST", headers: { Origin: APP, "Content-Type": "application/json" },
    body: JSON.stringify({ email: account.email, password: account.password }),
  });
  status(response, 200, "Synthetic staging login");
  const value = await boundedJson(response, "Synthetic staging login");
  check(value.user?.email === account.email && /^[a-f0-9]{64}$/.test(value.token ?? ""),
    "Synthetic staging login returned an unexpected identity or session");
  const session = value.token;
  const me = await hostedFetch(`${API}/api/auth/me`, {
    headers: { Origin: APP, Authorization: `Bearer ${session}` },
  });
  status(me, 200, "Synthetic staging session");
  check((await boundedJson(me, "Synthetic staging session")).email === account.email,
    "Synthetic staging session identity changed");
  return session;
}

async function registerClient(callback) {
  const response = await hostedFetch(`${API}/oauth/register`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_name: "CyberMeters hosted staging proof",
      redirect_uris: [callback], grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"], token_endpoint_auth_method: "none" }),
  });
  status(response, 201, "Staging DCR");
  const value = await boundedJson(response, "Staging DCR");
  check(typeof value.client_id === "string" && value.client_id.length > 8 &&
    value.client_id.length <= 2048,
  "Staging DCR did not issue a client ID");
  return value.client_id;
}

async function authorize({ identity, session, clientId, callback }) {
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(24).toString("base64url");
  const authorizeUrl = new URL(`${API}/authorize`);
  for (const [key, value] of Object.entries({ response_type: "code", client_id: clientId,
    redirect_uri: callback, scope: "mcp:read offline_access", state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256", resource: RESOURCE })) authorizeUrl.searchParams.set(key, value);
  const started = await hostedFetch(authorizeUrl);
  status(started, 302, "Staging authorization start");
  const appRedirect = locationUrl(started, "Staging authorization start");
  check(appRedirect.origin === APP && appRedirect.pathname === "/mcp/connect" &&
    appRedirect.searchParams.size === 1 &&
    OPAQUE.test(appRedirect.searchParams.get("intent") ?? ""),
  "Authorization did not lead to the exact staging app intent");
  const intent = appRedirect.searchParams.get("intent");

  const bridge = await hostedFetch(`${API}/api/mcp/oauth/browser-session`, {
    method: "POST", headers: { Origin: APP, Authorization: `Bearer ${session}`,
      "Content-Type": "application/json" },
    body: JSON.stringify({ intent }),
  });
  status(bridge, 200, "Staging browser session bridge");
  const bridgeCookie = setCookie(bridge, "__Host-cm-mcp-auth=", "Staging browser bridge");
  const bridgeBody = await boundedJson(bridge, "Staging browser bridge");
  const continueUrl = new URL(bridgeBody.continue_url);
  check(continueUrl.origin === API && continueUrl.pathname === "/authorize" &&
    continueUrl.searchParams.size === 1 && continueUrl.searchParams.get("intent") === intent,
  "Browser bridge returned an unexpected continuation URL");

  const consent = await hostedFetch(continueUrl, { headers: { Cookie: bridgeCookie } });
  status(consent, 200, "Staging consent page");
  const consentCookie = setCookie(consent, "__Host-cm-mcp-oauth-", "Staging consent page");
  const html = await boundedText(consent, "Staging consent page");
  const options = [...html.matchAll(/<option value="([A-Za-z0-9_-]+)">/g)]
    .map((match) => match[1]);
  check(JSON.stringify(options) === JSON.stringify([identity.workspaceId]),
    "Consent displayed a workspace outside the synthetic account");
  const handle = /<input type="hidden" name="handle" value="([A-Za-z0-9_-]+)">/.exec(html)?.[1];
  check(typeof handle === "string" && handle.length >= 16 && handle.length <= 512,
    "Consent handle is absent or malformed");

  const approved = await hostedFetch(continueUrl, {
    method: "POST", headers: { Origin: API,
      Cookie: `${bridgeCookie}; ${consentCookie}`,
      "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ handle, decision: "approve", context: identity.workspaceId }),
  });
  status(approved, 302, "Staging consent approval");
  const redirect = locationUrl(approved, "Staging consent approval");
  const callbackUrl = new URL(callback);
  check(redirect.origin === callbackUrl.origin && redirect.pathname === callbackUrl.pathname &&
    redirect.searchParams.get("state") === state &&
    redirect.searchParams.get("iss") === API &&
    typeof redirect.searchParams.get("code") === "string" &&
    redirect.searchParams.get("code").length >= 16 &&
    !redirect.searchParams.has("error"),
  "Consent did not return a valid code to the loopback callback");

  const token = await hostedFetch(`${API}/oauth/token`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: redirect.searchParams.get("code"), client_id: clientId,
      redirect_uri: callback, code_verifier: verifier, resource: RESOURCE }),
  });
  status(token, 200, "Staging OAuth token exchange");
  const grant = await boundedJson(token, "Staging OAuth token exchange");
  check(typeof grant.access_token === "string" && grant.access_token.length >= 32 &&
    typeof grant.refresh_token === "string" && grant.refresh_token.length >= 32 &&
    String(grant.scope).split(" ").includes("mcp:read") &&
    !String(grant.scope).split(" ").includes("portfolio:read"),
  "OAuth token lacks the narrowed read-only grant");
  return grant.access_token;
}

let rpcId = 0;
async function mcpCall(token, method, params = {}) {
  const response = await hostedFetch(RESOURCE, {
    method: "POST", headers: { Authorization: `Bearer ${token}`,
      "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  const raw = await boundedText(response, "Staging MCP response");
  const data = response.headers.get("Content-Type")?.includes("text/event-stream")
    ? raw.split(/\r?\n/).find((line) => line.startsWith("data: "))?.slice(6)
    : raw;
  let value;
  try { value = data ? JSON.parse(data) : null; }
  catch { throw new HostedFailure("Staging MCP returned an invalid protocol response"); }
  return { status: response.status, value };
}

function toolResult(reply, label) {
  // Diagnostics contain only fixed protocol fields. Never echo a remote tool
  // result, bearer, workspace name, or response body into a CI/local log.
  const safeFailure = reply.value?.result?.content?.[0]?.text === "mcp_read_unavailable"
    ? "mcp_read_unavailable" : "unknown";
  check(reply.status === 200 && reply.value?.result?.isError !== true &&
    reply.value?.result?.content?.[0]?.type === "text",
  `${label}: MCP read failed (HTTP ${reply.status}; tool_error=${reply.value?.result?.isError === true}; code=${safeFailure})`);
  try { return JSON.parse(reply.value.result.content[0].text); }
  catch { throw new HostedFailure(`${label}: invalid projected MCP data`); }
}

/** Report only protocol categories, never a remote error message or tool data. */
export function describeMcpDiscoveryFailure(reply) {
  const status = Number.isInteger(reply?.status) && reply.status >= 100 && reply.status <= 599
    ? reply.status : "unknown";
  const error = reply?.value?.error;
  let code = "unknown";
  if (typeof error === "string" && SAFE_DISCOVERY_ERRORS.has(error)) code = error;
  else if (error && typeof error === "object" &&
    SAFE_JSONRPC_ERRORS.has(error.code)) code = `jsonrpc_${error.code}`;
  return `HTTP ${status}; code=${code}`;
}

/** Repeat only exact read-only calls. Every result is checked before the next
 * request; a failure exits without a retry and the caller still cleans up. */
export async function proveSequentialMcpReads({ token, identity, rounds = 1, call = mcpCall }) {
  check(rounds === 1 || rounds === RELIABILITY_READ_ROUNDS,
    "Invalid hosted MCP reliability round count");
  for (let round = 1; round <= rounds; round++) {
    const label = `round ${round}/${rounds}`;
    const discovered = await call(token, "tools/list");
    check(discovered.status === 200 && Array.isArray(discovered.value?.result?.tools),
      `MCP tool discovery failed (${label}; ${describeMcpDiscoveryFailure(discovered)})`);
    const names = discovered.value.result.tools.map((tool) => tool.name);
    check(names.length === EXPECTED_TOOLS.size &&
      names.every((name) => EXPECTED_TOOLS.has(name)),
    `MCP tool discovery includes an unexpected capability (${label})`);
    const listed = toolResult(await call(token, "tools/call",
      { name: "cybermeters_list_workspaces", arguments: {} }), `Workspace list (${label})`);
    check(Array.isArray(listed.workspaces) && listed.workspaces.length === 1 &&
      listed.workspaces[0].workspace_id === identity.workspaceId &&
      listed.workspaces[0].display_name === identity.workspaceName,
    `MCP workspace list escaped its synthetic tenant (${label})`);
  }
}

async function proveTwoTenantReads(tokens, { reliabilityProbe = false } = {}) {
  for (const [index, token] of tokens.entries()) {
    const identity = MCP_STAGING_IDENTITIES[index];
    await proveSequentialMcpReads({ token, identity,
      rounds: reliabilityProbe ? RELIABILITY_READ_ROUNDS : 1 });
    const summary = toolResult(await mcpCall(token, "tools/call",
      { name: "cybermeters_get_workspace_summary",
        arguments: { workspace_id: identity.workspaceId } }), "Workspace summary");
    check(summary.workspace_id === identity.workspaceId && summary.domain_count === 0 &&
      summary.open_case_count === 0,
    "MCP workspace summary contains non-synthetic data");
    const other = MCP_STAGING_IDENTITIES[1 - index];
    const denied = await mcpCall(token, "tools/call",
      { name: "cybermeters_get_workspace_summary",
        arguments: { workspace_id: other.workspaceId } });
    check(denied.status === 403 &&
      !JSON.stringify(denied.value).includes(other.workspaceName) &&
      !JSON.stringify(denied.value).includes(other.workspaceId),
    "Cross-tenant MCP read was not denied without data leakage");
  }
}

async function cleanup(sessions, clientId, tokens) {
  const failures = [];
  for (const [index, session] of sessions.entries()) {
    if (!session) continue;
    if (clientId) {
      try {
        let offset = 0;
        let complete = false;
        const connectionIds = [];
        for (let page = 0; page < 10; page++) {
          const list = await hostedFetch(`${API}/api/mcp/oauth/connections?offset=${offset}`, {
            headers: { Origin: APP, Authorization: `Bearer ${session}` },
          });
          status(list, 200, "Staging connection cleanup list");
          const result = await boundedJson(list, "Staging connection cleanup list");
          check(Array.isArray(result.connections), "Staging connection cleanup list is invalid");
          for (const connection of result.connections.filter((item) => item.client_id === clientId)) {
            check(CONNECTION.test(connection.id), "Staging cleanup connection ID is invalid");
            connectionIds.push(connection.id);
          }
          if (result.next_offset === null) { complete = true; break; }
          check(Number.isInteger(result.next_offset) && result.next_offset > offset &&
            result.next_offset <= 100_000,
          "Staging connection cleanup cursor is invalid");
          offset = result.next_offset;
        }
        check(complete, "Staging connection cleanup exceeded its page bound");
        for (const id of new Set(connectionIds)) {
          const revoked = await hostedFetch(`${API}/api/mcp/oauth/connections/${id}`, {
            method: "DELETE", headers: { Origin: APP, Authorization: `Bearer ${session}` },
          });
          status(revoked, 200, "Staging connection revocation");
        }
        if (tokens[index]) {
          const after = await mcpCall(tokens[index], "tools/call",
            { name: "cybermeters_list_workspaces", arguments: {} });
          check(after.status === 401, "Revoked MCP token still has read access");
        }
      } catch { failures.push(`account ${index + 1} connection revocation`); }
    }
    try {
      const logout = await hostedFetch(`${API}/api/auth/logout`, {
        method: "POST", headers: { Origin: APP, Authorization: `Bearer ${session}` },
      });
      status(logout, 200, "Synthetic staging logout");
      check((await boundedJson(logout, "Synthetic staging logout")).success === true,
        "Synthetic staging logout was not acknowledged");
    } catch { failures.push(`account ${index + 1} logout`); }
  }
  return failures;
}

async function runHostedStaging({ geminiApiProbe = false, reuseSyntheticClient = false,
  reliabilityProbe = false } = {}) {
  if (geminiApiProbe) {
    check(typeof process.env.GEMINI_API_KEY === "string" &&
      process.env.GEMINI_API_KEY.length >= 20,
    "Gemini API probe needs a locally configured GEMINI_API_KEY");
  }
  const accounts = readSyntheticCredentials();
  // Validate the opt-in client file before any remote health check or login.
  const reused = reuseSyntheticClient ? readReusableSyntheticClient() : null;
  const sessions = [null, null];
  const tokens = [null, null];
  let clientId = null;
  let proofFailure = null;
  try {
    await preflight();
    for (const [index, account] of accounts.entries()) sessions[index] = await login(account);
    const callback = reused?.callback ?? `http://127.0.0.1:${randomInt(49152, 65536)}/callback`;
    clientId = reused?.clientId ?? await registerClient(callback);
    for (const [index, identity] of MCP_STAGING_IDENTITIES.entries()) {
      tokens[index] = await authorize({ identity, session: sessions[index], clientId, callback });
    }
    await proveTwoTenantReads(tokens, { reliabilityProbe });
    if (geminiApiProbe) {
      const result = await runGeminiSyntheticMcpProbe({
        apiKey: process.env.GEMINI_API_KEY,
        accessToken: tokens[0],
      });
      check(result.workspaceId === MCP_STAGING_IDENTITIES[0].workspaceId &&
        result.toolCalls === 1,
      "Gemini API did not return one fixture-A MCP read");
    }
  } catch (error) { proofFailure = error; }
  finally {
    const cleanupFailures = await cleanup(sessions, clientId, tokens);
    if (cleanupFailures.length) {
      throw new HostedFailure(`Cleanup needs attention: ${cleanupFailures.join(", ")}`);
    }
  }
  if (proofFailure) throw proofFailure;
  console.log(`PASS hosted synthetic staging: ${reuseSyntheticClient ? "existing DCR client" : "DCR"}, PKCE consent, two isolated MCP tenants${reliabilityProbe ? ", five sequential discovery and workspace reads per tenant" : ""}, cross-tenant denial, revocation and logout.`);
  if (geminiApiProbe) console.log("PASS Gemini API synthetic MCP read: one fixture-A workspace, no fixture-B data.");
}

export function parseHostedStagingFlags(args) {
  if (!Array.isArray(args) || args[0] !== "--run-hosted-staging" || args.length > 4) return null;
  const optional = args.slice(1);
  if (new Set(optional).size !== optional.length || optional.some((flag) =>
    !["--gemini-api-probe", "--reuse-synthetic-client", "--reliability-probe"].includes(flag))) return null;
  return { geminiApiProbe: optional.includes("--gemini-api-probe"),
    reuseSyntheticClient: optional.includes("--reuse-synthetic-client"),
    reliabilityProbe: optional.includes("--reliability-probe") };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = parseHostedStagingFlags(process.argv.slice(2));
  if (!options) {
    console.error("Refused: this remote test requires the exact --run-hosted-staging argument, with optional --gemini-api-probe, --reuse-synthetic-client and --reliability-probe.");
    process.exitCode = 2;
  } else {
    runHostedStaging(options).catch((error) => {
      const safeGeminiError = error instanceof Error &&
        /^Gemini synthetic MCP probe: (?:invalid API key|refused a non-fixture-A OAuth access token|unexpected MCP result shape|interaction did not complete with steps|expected exactly one successful workspace-list MCP call|MCP result did not prove fixture-A-only access|empty Google response|Google response exceeded size limit|Google response was not valid JSON|Google request failed or timed out|Google returned HTTP [1-5][0-9]{2})$/.test(error.message);
      console.error(error instanceof HostedFailure || safeGeminiError
        ? `FAIL hosted staging: ${error.message}`
        : "FAIL hosted staging: unexpected local or runtime failure; sensitive details were not printed.");
      process.exitCode = 1;
    });
  }
}
