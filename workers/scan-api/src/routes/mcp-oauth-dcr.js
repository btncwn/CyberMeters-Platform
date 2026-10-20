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

/**
 * RFC 7591 §2 defaults for a registration that leaves them out. A field the
 * client sent is kept exactly as sent, so the strict checks below still judge
 * it. A missing token_endpoint_auth_method registers a public client ("none";
 * PKCE is mandatory here) rather than RFC 7591's client_secret_basic, which
 * this lane does not issue. Applied to the request body before the OAuth
 * library reads it, because the library would otherwise default to a secret.
 */
export function applyMcpDcrDefaults(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return metadata;
  return {
    ...metadata,
    ...(metadata.grant_types === undefined ? { grant_types: ["authorization_code"] } : {}),
    ...(metadata.response_types === undefined ? { response_types: ["code"] } : {}),
    ...(metadata.token_endpoint_auth_method === undefined ? { token_endpoint_auth_method: "none" } : {}),
  };
}

// Values worth naming in a rejection log: protocol vocabulary only, never
// anything the client chose freely.
const LOGGABLE_VALUES = new Set(["none", "client_secret_basic", "client_secret_post",
  "client_secret_jwt", "private_key_jwt", "authorization_code", "refresh_token",
  "implicit", "password", "client_credentials", "code", "token", "id_token"]);

function loggable(value) {
  if (Array.isArray(value)) return value.slice(0, 4).map((item) => (LOGGABLE_VALUES.has(item) ? item : "other"));
  if (value === undefined) return "missing";
  return LOGGABLE_VALUES.has(value) ? value : "other";
}

function redirectHost(uri) {
  try { return new URL(uri).host.slice(0, 120); } catch { return "unparseable"; }
}

function onlyHostedRedirects(redirects, env) {
  const hosted = configuredHostedRedirects(env);
  return Array.isArray(redirects) && redirects.length >= 1 && redirects.length <= 3 &&
    redirects.every((uri) => hosted.has(uri) && isSafeHostedRedirect(uri));
}

// The first rule a registration breaks, or null. Kept in the original order.
function dcrMetadataRejection(clientMetadata, env) {
  if (!clientMetadata || typeof clientMetadata !== "object" || Array.isArray(clientMetadata)) {
    return { rule: "metadata_not_object" };
  }
  if (new TextEncoder().encode(JSON.stringify(clientMetadata)).length > 8192) return { rule: "body_too_large" };
  if (Object.hasOwn(clientMetadata, "software_statement")) return { rule: "software_statement_present" };
  const name = clientMetadata.client_name;
  if (typeof name !== "string" || name.length < 1 || name.length > 80 ||
      /[\x00-\x1f\x7f\p{Cf}]/u.test(name)) {
    return { rule: "client_name_invalid", field: "client_name", detail: typeof name === "string" ? `length_${name.length}` : typeof name };
  }
  // Public PKCE clients use "none". A client whose every callback is an
  // allow-listed hosted HTTPS callback may instead hold a secret sent in the
  // token request body (the Claude hosted connector registers this way); PKCE
  // stays mandatory for it too. Loopback clients never get a secret.
  const method = clientMetadata.token_endpoint_auth_method;
  if (method !== "none" &&
      !(method === "client_secret_post" && onlyHostedRedirects(clientMetadata.redirect_uris, env))) {
    return { rule: "auth_method_not_none", field: "token_endpoint_auth_method", value: loggable(method) };
  }
  const supported = clientMetadata.token_endpoint_auth_methods_supported;
  if (supported !== undefined &&
      (!Array.isArray(supported) || supported.length !== 1 || supported[0] !== method)) {
    return { rule: "auth_methods_supported_not_none", field: "token_endpoint_auth_methods_supported", value: loggable(supported) };
  }
  const redirects = clientMetadata.redirect_uris;
  if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 3) {
    return { rule: "redirect_uris_count", field: "redirect_uris", detail: Array.isArray(redirects) ? `count_${redirects.length}` : typeof redirects };
  }
  const hosted = configuredHostedRedirects(env);
  const refused = redirects.find((uri) =>
    !(env?.MCP_OAUTH_DCR_LOOPBACK_ENABLED === "true" && isMcpDcrLoopbackRedirect(uri)) &&
    !(hosted.has(uri) && isSafeHostedRedirect(uri)));
  if (refused !== undefined) return { rule: "redirect_not_allowed", field: "redirect_uris", redirect_host: redirectHost(refused) };
  if (new Set(redirects).size !== redirects.length) return { rule: "redirect_duplicate", field: "redirect_uris" };
  const grants = clientMetadata.grant_types;
  if (!Array.isArray(grants) || !grants.includes("authorization_code") || grants.length > 2 ||
      new Set(grants).size !== grants.length ||
      grants.some((grant) => !["authorization_code", "refresh_token"].includes(grant))) {
    return { rule: "grant_types_invalid", field: "grant_types", value: loggable(grants) };
  }
  const responses = clientMetadata.response_types;
  if (!Array.isArray(responses) || responses.length !== 1 || responses[0] !== "code") {
    return { rule: "response_types_invalid", field: "response_types", value: loggable(responses) };
  }
  return null;
}

// One line per refusal: which rule, which field, the redirect host. Never the
// IP, the client name or any free-form value the client sent.
function logDcrRejection(rejection, clientMetadata) {
  const firstRedirect = Array.isArray(clientMetadata?.redirect_uris) ? clientMetadata.redirect_uris[0] : undefined;
  console.warn(JSON.stringify({
    event: "mcp_dcr_rejected",
    ...rejection,
    redirect_host: rejection.redirect_host ?? (firstRedirect === undefined ? null : redirectHost(firstRedirect)),
  }));
}

/** A guarded RFC 7591 lane for clients that cannot use CIMD. */
export async function evaluateMcpDcrRegistration({ clientMetadata, request }, env, options = {}) {
  if (env?.MCP_OAUTH_DCR_ENABLED !== "true" || !env?.cybermeters_db ||
      request.method !== "POST" || request.headers.get("Content-Type")?.split(";")[0] !== "application/json") {
    logDcrRejection({ rule: "registration_unavailable" }, null);
    return { code: "access_denied", description: "Registration unavailable", status: 403 };
  }
  const ip = request.headers.get("CF-Connecting-IP") ?? options.testClientIp;
  if (typeof ip !== "string" || !ip || ip.length > 64) {
    logDcrRejection({ rule: "client_ip_unavailable" }, null);
    return { code: "temporarily_unavailable", description: "Registration unavailable", status: 503 };
  }
  const rejection = dcrMetadataRejection(clientMetadata, env);
  if (rejection) {
    logDcrRejection(rejection, clientMetadata);
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
