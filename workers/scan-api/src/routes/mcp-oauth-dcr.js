import { consumeApiRateLimit, rateLimitScopeId } from "../lib/rate-limit.js";
import { mcpOAuthGlobalBudgetSaturated } from "./mcp-oauth-browser.js";

function configuredHostedRedirects(env) {
  try {
    const values = JSON.parse(env.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS ?? "[]");
    return Array.isArray(values) && values.length <= 20 &&
      values.every((uri) => typeof uri === "string" && uri.length <= 500)
      ? new Set(values) : new Set();
  } catch { return new Set(); }
}

function isSafeHostedRedirect(uri) {
  if (typeof uri !== "string" || uri.length > 500) return false;
  try {
    const url = new URL(uri);
    return url.protocol === "https:" && !url.username && !url.password && !url.hash &&
      uri === url.toString();
  } catch { return false; }
}

/** RFC 8252 loopback redirect with an ephemeral local port and bounded path. */
export function isMcpDcrLoopbackRedirect(uri) {
  if (typeof uri !== "string" || uri.length > 220) return false;
  try {
    const url = new URL(uri);
    const port = Number(url.port);
    return url.protocol === "http:" && uri === url.toString() &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) &&
      Number.isInteger(port) && port >= 1024 && port <= 65535 &&
      !url.username && !url.password && !url.hash && !url.search &&
      /^\/[A-Za-z0-9._~/-]{0,128}$/.test(url.pathname) &&
      !url.pathname.split("/").some((segment) => segment === "." || segment === "..");
  } catch { return false; }
}

/** A guarded RFC 7591 lane for clients that cannot use CIMD. */
export async function evaluateMcpDcrRegistration({ clientMetadata, request }, env, options = {}) {
  if (env?.MCP_OAUTH_DCR_ENABLED !== "true" || !env?.cybermeters_db ||
      request.method !== "POST" || request.headers.get("Content-Type")?.split(";")[0] !== "application/json") {
    return { code: "access_denied", description: "Registration unavailable", status: 403 };
  }
  const ip = request.headers.get("CF-Connecting-IP") ?? options.testClientIp;
  if (typeof ip !== "string" || !ip || ip.length > 64) {
    return { code: "temporarily_unavailable", description: "Registration unavailable", status: 503 };
  }
  if (!clientMetadata || typeof clientMetadata !== "object" || Array.isArray(clientMetadata)) {
    return { code: "invalid_client_metadata", description: "Invalid registration", status: 400 };
  }
  const body = JSON.stringify(clientMetadata);
  if (new TextEncoder().encode(body).length > 8192 ||
      Object.hasOwn(clientMetadata, "software_statement") ||
      typeof clientMetadata.client_name !== "string" ||
      clientMetadata.client_name.length < 1 || clientMetadata.client_name.length > 80 ||
      /[\x00-\x1f\x7f\p{Cf}]/u.test(clientMetadata.client_name) ||
      clientMetadata.token_endpoint_auth_method !== "none" ||
      (clientMetadata.token_endpoint_auth_methods_supported !== undefined &&
        (!Array.isArray(clientMetadata.token_endpoint_auth_methods_supported) ||
          clientMetadata.token_endpoint_auth_methods_supported.length !== 1 ||
          clientMetadata.token_endpoint_auth_methods_supported[0] !== "none")) ||
      !Array.isArray(clientMetadata.redirect_uris) ||
      clientMetadata.redirect_uris.length < 1 || clientMetadata.redirect_uris.length > 3) {
    return { code: "invalid_client_metadata", description: "Invalid registration", status: 400 };
  }
  const hosted = configuredHostedRedirects(env);
  if (clientMetadata.redirect_uris.some((uri) =>
    !isMcpDcrLoopbackRedirect(uri) && !(hosted.has(uri) && isSafeHostedRedirect(uri))) ||
      new Set(clientMetadata.redirect_uris).size !== clientMetadata.redirect_uris.length ||
      !Array.isArray(clientMetadata.grant_types) ||
      !clientMetadata.grant_types.includes("authorization_code") ||
      clientMetadata.grant_types.length > 2 ||
      new Set(clientMetadata.grant_types).size !== clientMetadata.grant_types.length ||
      clientMetadata.grant_types.some((grant) =>
        !["authorization_code", "refresh_token"].includes(grant)) ||
      !Array.isArray(clientMetadata.response_types) ||
      clientMetadata.response_types.length !== 1 ||
      clientMetadata.response_types[0] !== "code") {
    return { code: "invalid_client_metadata", description: "Invalid registration", status: 400 };
  }
  // Validate the bounded registration before charging shared capacity. A
  // malformed caller must not exhaust the budget for another client.
  if (await mcpOAuthGlobalBudgetSaturated(env, "mcp_dcr_register", 12, 3600)) {
    return { code: "temporarily_unavailable", description: "Registration unavailable", status: 429 };
  }
  const scopeId = await rateLimitScopeId("mcp_dcr", ip);
  const limited = await consumeApiRateLimit(env,
    [{ scope: "mcp_dcr_ip", scope_id: scopeId }],
    "mcp_dcr_register", 2, 3600,
    { atomic: true, failClosed: true, saturating: true });
  if (limited) return { code: "temporarily_unavailable", description: "Registration unavailable", status: limited.status };
  const globalLimited = await consumeApiRateLimit(env,
    [{ scope: "mcp_oauth_global", scope_id: "all" }],
    "mcp_dcr_register", 12, 3600,
    { atomic: true, failClosed: true, saturating: true });
  if (globalLimited) return { code: "temporarily_unavailable",
    description: "Registration unavailable", status: globalLimited.status };
  return undefined;
}
