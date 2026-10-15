import { hashToken } from "../lib/auth-crypto.js";
import { consumeApiRateLimit, rateLimitScopeId } from "../lib/rate-limit.js";
import { listMcpOAuthConsentWorkspaces, MCP_OAUTH_APP_ORIGIN } from "./mcp-oauth-admission.js";

const OPAQUE_RE = /^[A-Za-z0-9_-]{43}$/;
const COOKIE_NAME = "__Host-cm-mcp-auth";
const INTENT_SECONDS = 10 * 60;
const MAX_AUTH_URL = 4096;

function randomOpaque() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function response(body, status, headers = {}) {
  return new Response(body, {
    status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers },
  });
}

/** Read a small request body without trusting Content-Length or a stalled stream. */
export async function readBoundedMcpOAuthBody(request, maxBytes, deadlineMs = 10_000) {
  if (!request.body || !Number.isInteger(maxBytes) || maxBytes < 1 ||
      !Number.isInteger(deadlineMs) || deadlineMs < 1) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true }), deadlineMs);
  });
  try {
    while (true) {
      const result = await Promise.race([reader.read(), deadline]);
      if (result.timedOut) {
        void reader.cancel().catch(() => {});
        return null;
      }
      const { done, value } = result;
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        void reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch { return null; }
  finally { clearTimeout(timer); }
}

function appOrigin(options) { return options.appOrigin ?? MCP_OAUTH_APP_ORIGIN; }

export function mcpOAuthCorsHeaders(request, options = {}) {
  if (request.headers.get("Origin") !== appOrigin(options)) return null;
  return {
    "Access-Control-Allow-Origin": appOrigin(options),
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "300",
    Vary: "Origin",
  };
}

export function mcpOAuthJson(request, value, status = 200, options = {}) {
  const cors = mcpOAuthCorsHeaders(request, options);
  return response(JSON.stringify(value), status, {
    "Content-Type": "application/json; charset=utf-8", ...(cors ?? {}),
  });
}

export async function requireMcpWebSession(request, env) {
  const bearer = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.get("Authorization") ?? "");
  if (!bearer || !env?.cybermeters_db) return null;
  const tokenHash = await hashToken(bearer[1]);
  const session = await env.cybermeters_db.prepare(
    `SELECT s.id AS session_id, s.user_id, u.status, u.email_verified
      FROM user_sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND unixepoch(s.expires_at) > unixepoch('now')
        AND NOT EXISTS (SELECT 1 FROM deletion_requests d
           WHERE d.request_type = 'account' AND d.user_id = u.id
             AND d.status NOT IN ('completed','cancelled'))
      LIMIT 1`,
  ).bind(tokenHash).first();
  return session?.status === "active" && Number(session.email_verified) === 1 ? session : null;
}

async function claimIpBudget(request, env, action, limit, seconds, options) {
  const ip = request.headers.get("CF-Connecting-IP") ?? options.testClientIp;
  if (!ip || ip.length > 64) return false;
  const id = await rateLimitScopeId("mcp_oauth_ip", ip);
  return !(await consumeApiRateLimit(env,
    [{ scope: "mcp_oauth_ip", scope_id: id }], action, limit, seconds,
    { atomic: true, failClosed: true }));
}

export async function claimMcpOAuthStartBudget(request, env, options = {}) {
  return claimIpBudget(request, env, "mcp_authorize_start", 30, 60, options);
}

export async function claimMcpOAuthTokenBudget(request, env, options = {}) {
  const ip = request.headers.get("CF-Connecting-IP") ?? options.testClientIp;
  if (!ip || ip.length > 64) return { status: 503 };
  const id = await rateLimitScopeId("mcp_oauth_ip", ip);
  return consumeApiRateLimit(env,
    [{ scope: "mcp_oauth_ip", scope_id: id }], "mcp_token_exchange", 60, 60,
    { atomic: true, failClosed: true });
}

/** Bounded retention sweep; child rows must be removed before their intents. */
export async function purgeExpiredMcpOAuthBrowserRows(env, limit = 100) {
  if (!env?.cybermeters_db || !Number.isInteger(limit) || limit < 1 || limit > 500) {
    throw new Error("mcp_oauth_cleanup_unavailable");
  }
  const sessions = await env.cybermeters_db.prepare(
    `DELETE FROM mcp_oauth_browser_sessions WHERE cookie_hash IN (
       SELECT cookie_hash FROM mcp_oauth_browser_sessions
        WHERE unixepoch(expires_at) <= unixepoch('now')
        ORDER BY expires_at LIMIT ?)`,
  ).bind(limit).run();
  const intents = await env.cybermeters_db.prepare(
    `DELETE FROM mcp_oauth_login_intents WHERE id_hash IN (
       SELECT i.id_hash FROM mcp_oauth_login_intents i
        WHERE unixepoch(i.expires_at) <= unixepoch('now')
          AND NOT EXISTS (SELECT 1 FROM mcp_oauth_browser_sessions b
                           WHERE b.intent_hash = i.id_hash)
        ORDER BY i.expires_at LIMIT ?)`,
  ).bind(limit).run();
  if (!sessions?.meta || !intents?.meta) throw new Error("mcp_oauth_cleanup_unavailable");
  return { sessions: Number(sessions.meta.changes), intents: Number(intents.meta.changes) };
}

/** Persist a validated authorization request behind a random, short-lived URL handle. */
export async function createMcpOAuthIntent(request, env, options = {}) {
  if (!env?.cybermeters_db || request.url.length > MAX_AUTH_URL ||
      (!options.budgetClaimed && !(await claimMcpOAuthStartBudget(request, env, options)))) {
    return null;
  }
  await purgeExpiredMcpOAuthBrowserRows(env);
  const opaque = randomOpaque();
  const idHash = await hashToken(opaque);
  await env.cybermeters_db.prepare(
    `INSERT INTO mcp_oauth_login_intents(id_hash, authorization_url, expires_at)
     VALUES (?, ?, datetime('now', '+10 minutes'))`,
  ).bind(idHash, request.url).run();
  return opaque;
}

export async function readMcpOAuthIntent(env, opaque) {
  if (!env?.cybermeters_db || typeof opaque !== "string" || !OPAQUE_RE.test(opaque)) return null;
  const idHash = await hashToken(opaque);
  const row = await env.cybermeters_db.prepare(
    `SELECT id_hash, authorization_url FROM mcp_oauth_login_intents
      WHERE id_hash = ? AND unixepoch(expires_at) > unixepoch('now') LIMIT 1`,
  ).bind(idHash).first();
  return row?.authorization_url && row.authorization_url.length <= MAX_AUTH_URL ? row : null;
}

function cookieValue(request) {
  const values = (request.headers.get("Cookie") ?? "").split(";").map((item) => item.trim())
    .filter((item) => item.startsWith(`${COOKIE_NAME}=`));
  if (values.length !== 1) return null;
  const value = values[0].slice(COOKIE_NAME.length + 1);
  return OPAQUE_RE.test(value) ? value : null;
}

/** Browser cookie is bound to one intent and to a still-live web session. */
export async function readMcpOAuthBrowserSession(request, env, intentHash) {
  const value = cookieValue(request);
  if (!value || !intentHash || !env?.cybermeters_db) return null;
  const hash = await hashToken(value);
  const row = await env.cybermeters_db.prepare(
    `SELECT b.user_id, b.web_session_id FROM mcp_oauth_browser_sessions b
       JOIN user_sessions s ON s.id = b.web_session_id AND s.user_id = b.user_id
       JOIN users u ON u.id = b.user_id
      WHERE b.cookie_hash = ? AND b.intent_hash = ? AND b.consumed_at IS NULL
        AND unixepoch(b.expires_at) > unixepoch('now')
        AND unixepoch(s.expires_at) > unixepoch('now')
        AND u.status = 'active' AND u.email_verified = 1 LIMIT 1`,
  ).bind(hash, intentHash).first();
  return row ?? null;
}

/** Atomic one-time claim around the library's KV consent transaction. */
export async function claimMcpOAuthBrowserSession(request, env, intentHash, userId) {
  const value = cookieValue(request);
  if (!value || !intentHash || !userId) return false;
  const hash = await hashToken(value);
  const claimed = await env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_browser_sessions SET consumed_at = datetime('now')
      WHERE cookie_hash = ? AND intent_hash = ? AND user_id = ?
        AND consumed_at IS NULL AND unixepoch(expires_at) > unixepoch('now')
        AND EXISTS (
          SELECT 1 FROM user_sessions s JOIN users u ON u.id = s.user_id
           WHERE s.id = mcp_oauth_browser_sessions.web_session_id
             AND s.user_id = mcp_oauth_browser_sessions.user_id
             AND unixepoch(s.expires_at) > unixepoch('now')
             AND u.status = 'active' AND u.email_verified = 1
        ) RETURNING user_id`,
  ).bind(hash, intentHash, userId).first();
  return claimed?.user_id === userId;
}

export async function clearMcpOAuthBrowserSession(env, intentHash) {
  await env.cybermeters_db.prepare(
    `DELETE FROM mcp_oauth_browser_sessions WHERE intent_hash = ?`,
  ).bind(intentHash).run();
  await env.cybermeters_db.prepare(
    `DELETE FROM mcp_oauth_login_intents WHERE id_hash = ?`,
  ).bind(intentHash).run();
}

/** Called by the app page with its existing localStorage web-session bearer. */
export async function bridgeMcpOAuthBrowserSession(request, env, options = {}) {
  const cors = mcpOAuthCorsHeaders(request, options);
  if (request.method === "OPTIONS") return cors
    ? response(null, 204, cors) : response(null, 403);
  if (request.method !== "POST" || !cors ||
      request.headers.get("Content-Type")?.split(";")[0] !== "application/json" ||
      Number(request.headers.get("Content-Length") || 0) > 512) {
    return mcpOAuthJson(request, { error: "invalid_request" }, 400, options);
  }
  const session = await requireMcpWebSession(request, env);
  if (!session) return mcpOAuthJson(request, { error: "unauthorized" }, 401, options);
  const rate = await consumeApiRateLimit(env,
    [{ scope: "mcp_oauth_user", scope_id: session.user_id }],
    "mcp_browser_bridge", 10, 600, { atomic: true, failClosed: true });
  if (rate) return mcpOAuthJson(request, { error: "temporarily_unavailable" }, rate.status, options);
  let body;
  try {
    const raw = await readBoundedMcpOAuthBody(request, 512);
    body = raw === null ? null : JSON.parse(raw);
  } catch { body = null; }
  if (!body || Object.keys(body).join() !== "intent") {
    return mcpOAuthJson(request, { error: "invalid_request" }, 400, options);
  }
  const intent = await readMcpOAuthIntent(env, body.intent);
  if (!intent || !(await listMcpOAuthConsentWorkspaces(env, session.user_id))) {
    return mcpOAuthJson(request, { error: "unavailable" }, 403, options);
  }
  const opaque = randomOpaque();
  const cookieHash = await hashToken(opaque);
  try {
    await env.cybermeters_db.prepare(
      `INSERT INTO mcp_oauth_browser_sessions
         (cookie_hash, intent_hash, user_id, web_session_id, expires_at)
       VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))`,
    ).bind(cookieHash, intent.id_hash, session.user_id, session.session_id).run();
  } catch {
    return mcpOAuthJson(request, { error: "unavailable" }, 409, options);
  }
  const headers = {
    "Content-Type": "application/json; charset=utf-8", ...cors,
    "Set-Cookie": `${COOKIE_NAME}=${opaque}; Path=/; Max-Age=${INTENT_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
  };
  return response(JSON.stringify({ continue_url: `${options.issuer ?? "https://api.cybermeters.com"}/authorize?intent=${body.intent}` }), 200, headers);
}

export function expireMcpOAuthBrowserCookie(headers) {
  headers.append("Set-Cookie", `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}
