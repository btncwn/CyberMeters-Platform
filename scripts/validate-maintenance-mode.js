#!/usr/bin/env node
//
// Maintenance-mode regression: ordinary API routes return a clean 503 while
// /health and /ready remain reachable. The explicit staging MCP test switch
// permits only login, session validation, and logout on the staging API host.
// When off, traffic flows normally. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(workerPath).href);
const { isMaintenanceMode, isMaintenanceBypass,
  isStagingMcpAuthMaintenanceAllowed } = worker;

// ── 1. Unit: fail-safe flag parsing ──────────────────────────────────────────
for (const v of ["on", "ON", "1", "true", "True", " on "]) ok(`isMaintenanceMode("${v}") = true`, isMaintenanceMode({ MAINTENANCE_MODE: v }) === true);
for (const v of ["off", "", "0", "false", "nope", undefined, null]) ok(`isMaintenanceMode(${JSON.stringify(v)}) = false`, isMaintenanceMode({ MAINTENANCE_MODE: v }) === false);
ok("isMaintenanceMode({}) = false", isMaintenanceMode({}) === false);

// Bypass only when a token is configured AND the header matches.
const req = (h = {}) => new Request("https://app.cybermeters.com/api/x", { headers: h });
ok("bypass off when no token set", isMaintenanceBypass(req({ "X-Maintenance-Bypass": "x" }), {}) === false);
ok("bypass on with matching header", isMaintenanceBypass(req({ "X-Maintenance-Bypass": "secret" }), { MAINTENANCE_BYPASS_TOKEN: "secret" }) === true);
ok("bypass off with wrong header", isMaintenanceBypass(req({ "X-Maintenance-Bypass": "nope" }), { MAINTENANCE_BYPASS_TOKEN: "secret" }) === false);

const STAGING_API = "https://api-staging.cybermeters.com";
const STAGING_APP = "https://app-staging.cybermeters.com";
const stageRequest = (pathname, method = "GET", origin = STAGING_API) =>
  new Request(`${origin}${pathname}`, { method });
const stageAuthEnv = {
  MAINTENANCE_MODE: "on", MCP_DEPLOYMENT_TIER: "staging",
  MCP_STAGING_AUTH_TEST_ENABLED: "true",
};
for (const [method, pathname] of [
  ["POST", "/api/auth/login"], ["GET", "/api/auth/me"],
  ["POST", "/api/auth/logout"],
]) {
  ok(`staging auth: ${method} ${pathname} is allowed only with explicit gate`,
    isStagingMcpAuthMaintenanceAllowed(stageRequest(pathname, method), stageAuthEnv));
}
for (const [name, env] of [
  ["missing test flag", { ...stageAuthEnv, MCP_STAGING_AUTH_TEST_ENABLED: undefined }],
  ["disabled test flag", { ...stageAuthEnv, MCP_STAGING_AUTH_TEST_ENABLED: "false" }],
  ["nonliteral test flag", { ...stageAuthEnv, MCP_STAGING_AUTH_TEST_ENABLED: "TRUE" }],
  ["production tier", { ...stageAuthEnv, MCP_DEPLOYMENT_TIER: "production" }],
  ["missing tier", { ...stageAuthEnv, MCP_DEPLOYMENT_TIER: undefined }],
  ["maintenance off", { ...stageAuthEnv, MAINTENANCE_MODE: "off" }],
]) {
  ok(`staging auth: ${name} cannot open login`,
    !isStagingMcpAuthMaintenanceAllowed(stageRequest("/api/auth/login", "POST"), env));
}
for (const [name, request] of [
  ["production host", stageRequest("/api/auth/login", "POST", "https://api.cybermeters.com")],
  ["lookalike host", stageRequest("/api/auth/login", "POST", "https://api-staging.cybermeters.com.evil.invalid")],
  ["http staging host", stageRequest("/api/auth/login", "POST", "http://api-staging.cybermeters.com")],
  ["login GET", stageRequest("/api/auth/login")],
  ["session POST", stageRequest("/api/auth/me", "POST")],
  ["logout GET", stageRequest("/api/auth/logout")],
  ["login suffix", stageRequest("/api/auth/login/", "POST")],
  ["login query", stageRequest("/api/auth/login?next=/api/free-scan", "POST")],
  ["signup", stageRequest("/api/auth/signup", "POST")],
  ["MFA challenge", stageRequest("/api/auth/mfa/challenge", "POST")],
  ["workspace list", stageRequest("/api/workspaces")],
  ["free scan", stageRequest("/api/free-scan", "POST")],
  ["billing", stageRequest("/api/billing/plans")],
]) {
  ok(`staging auth: ${name} remains blocked`,
    !isStagingMcpAuthMaintenanceAllowed(request, stageAuthEnv));
}

// ── 2. Integration: real worker fetch under each mode ────────────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
const db = buildDb();
const baseEnv = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) },
  ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const call = async (urlPath, env, headers = {}, method = "GET", options = {}) => {
  const res = await worker.default.fetch(new Request(
    `${options.origin ?? "https://app.cybermeters.com"}${urlPath}`,
    { method, headers, ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }) },
  ), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return {
    status: res.status,
    body,
    retryAfter: res.headers.get("Retry-After"),
    acao: res.headers.get("Access-Control-Allow-Origin"),
    vary: res.headers.get("Vary"),
    cacheControl: res.headers.get("Cache-Control"),
    allowMethods: res.headers.get("Access-Control-Allow-Methods"),
  };
};

// OFF: normal traffic (protected route → 401, not maintenance).
const off = { ...baseEnv, MAINTENANCE_MODE: "off" };
const offResp = await call("/api/workspaces", off);
ok("OFF: protected route is normal 401", offResp.status === 401 && offResp.body.code !== "maintenance");
ok("OFF: /health maintenance flag is false", (await call("/health", off)).body.maintenance === false);

// ON: every API route → 503 maintenance contract.
const on = { ...baseEnv, MAINTENANCE_MODE: "on" };
const onResp = await call("/api/workspaces", on);
ok("ON: API route returns 503", onResp.status === 503);
ok("ON: 503 body code is 'maintenance'", onResp.body.code === "maintenance");
ok("ON: 503 body has customer message", typeof onResp.body.message === "string" && onResp.body.message.length > 20);
ok("ON: Retry-After header present", onResp.retryAfter === "300");

// ON: /health and /ready stay reachable (monitoring exempt).
const onHealth = await call("/health", on);
ok("ON: /health still 200", onHealth.status === 200);
ok("ON: /health reports maintenance:true", onHealth.body.maintenance === true);
const onReady = await call("/ready", on);
ok("ON: /ready still reachable (not maintenance-blocked)", onReady.status === 200 || onReady.status === 503);
ok("ON: /ready is not the maintenance contract", onReady.body.code !== "maintenance");

// ON + bypass token → passes through to normal handling.
const onBypass = { ...on, MAINTENANCE_BYPASS_TOKEN: "founder-token" };
const bypassResp = await call("/api/workspaces", onBypass, { "X-Maintenance-Bypass": "founder-token" });
ok("ON+bypass: request passes through (401, not 503)", bypassResp.status === 401 && bypassResp.body.code !== "maintenance");
const noBypass = await call("/api/workspaces", onBypass, { "X-Maintenance-Bypass": "wrong" });
ok("ON+wrong-bypass: still blocked (503)", noBypass.status === 503);

// With the switch enabled, only synthetic password auth is available. The
// login page's post-login workspace fetch is deliberately still a maintenance
// response; the login page handles that fetch failure and continues to MCP.
const stage = { ...baseEnv, ...stageAuthEnv, ALLOWED_ORIGIN: STAGING_APP };
const stageCall = (pathname, method = "GET", headers = {}, body) => call(
  pathname, stage, { Origin: STAGING_APP, ...(body === undefined ? {} :
    { "Content-Type": "application/json" }), ...headers }, method,
  { origin: STAGING_API, body },
);
for (const [method, pathname] of [
  ["POST", "/api/auth/signup"], ["POST", "/api/free-scan"],
  ["GET", "/api/workspaces"], ["GET", "/api/billing/plans"],
  ["POST", "/api/auth/mfa/challenge"], ["GET", "/api/auth/login"],
  ["POST", "/api/auth/me"], ["GET", "/api/auth/logout"],
]) {
  const result = await stageCall(pathname, method);
  ok(`staging auth integration: ${method} ${pathname} stays at maintenance 503`,
    result.status === 503 && result.body.code === "maintenance");
}
const stageUnauthenticated = await stageCall("/api/auth/me");
ok("staging auth integration: allowed session route still requires a bearer",
  stageUnauthenticated.status === 401);
const stageFlagOff = await call("/api/auth/login",
  { ...stage, MCP_STAGING_AUTH_TEST_ENABLED: "false" },
  { Origin: STAGING_APP }, "POST", { origin: STAGING_API });
ok("staging auth integration: generated default keeps login at maintenance 503",
  stageFlagOff.status === 503 && stageFlagOff.body.code === "maintenance");
const { hashPassword } = await import(pathToFileURL(path.join(root,
  "workers/scan-api/src/lib/password.js")).href);
const fixturePassword = "synthetic-staging-maintenance-password";
db.prepare(`INSERT INTO users
  (id, email, name, plan, password_hash, status, email_verified, auth_provider)
  VALUES (?, ?, ?, 'free', ?, 'active', 1, 'local')`).run(
    "user_staging_maintenance", "maintenance@example.invalid", "Synthetic Staging User",
    await hashPassword(fixturePassword),
  );
const stageLogin = await stageCall("/api/auth/login", "POST", {},
  { email: "maintenance@example.invalid", password: fixturePassword });
ok("staging auth integration: synthetic login succeeds only on staged allowlist",
  stageLogin.status === 200 && /^[a-f0-9]{64}$/.test(stageLogin.body.token ?? ""));
if (stageLogin.status === 200 && stageLogin.body.token) {
  const stageBearer = { Authorization: `Bearer ${stageLogin.body.token}` };
  const stageMe = await stageCall("/api/auth/me", "GET", stageBearer);
  ok("staging auth integration: session check returns synthetic identity",
    stageMe.status === 200 && stageMe.body.email === "maintenance@example.invalid");
  const stageLogout = await stageCall("/api/auth/logout", "POST", stageBearer);
  ok("staging auth integration: logout succeeds", stageLogout.status === 200 &&
    stageLogout.body.success === true);
  const stageRevoked = await stageCall("/api/auth/me", "GET", stageBearer);
  ok("staging auth integration: logged-out session is rejected",
    stageRevoked.status === 401);
} else {
  ok("staging auth integration: session check returns synthetic identity", false);
  ok("staging auth integration: logout succeeds", false);
  ok("staging auth integration: logged-out session is rejected", false);
}
const productionWithStageFlag = {
  ...stage, MCP_DEPLOYMENT_TIER: "production",
};
const productionLogin = await call("/api/auth/login", productionWithStageFlag,
  { Origin: STAGING_APP, "Content-Type": "application/json" }, "POST",
  { origin: "https://api.cybermeters.com", body: {
    email: "maintenance@example.invalid", password: fixturePassword,
  } });
ok("staging auth integration: production tier and hostname stay at maintenance 503",
  productionLogin.status === 503 && productionLogin.body.code === "maintenance");

// Public status-page origins may read only the public liveness/readiness
// endpoints. Authenticated API surfaces retain the existing app-only policy.
const apexHealth = await call("/health", off, { Origin: "https://cybermeters.com" });
const apexReady = await call("/ready", off, { Origin: "https://cybermeters.com" });
const wwwHealth = await call("/health", off, { Origin: "https://www.cybermeters.com" });
const wwwReady = await call("/ready", off, { Origin: "https://www.cybermeters.com" });
const appHealth = await call("/health", off, { Origin: "https://app.cybermeters.com" });
const appReady = await call("/ready", off, { Origin: "https://app.cybermeters.com" });
const hostileHealth = await call("/health", off, { Origin: "https://hostile.example" });
const hostileReady = await call("/ready", off, { Origin: "https://hostile.example" });
const marketingAuth = await call("/api/workspaces", off, { Origin: "https://cybermeters.com" });
const marketingPreflight = await call("/health", off, { Origin: "https://cybermeters.com" }, "OPTIONS");
const marketingWrite = await call("/health", off, { Origin: "https://cybermeters.com" }, "POST");

ok("CORS: cybermeters.com can read /health", apexHealth.acao === "https://cybermeters.com");
ok("CORS: cybermeters.com can read /ready", apexReady.acao === "https://cybermeters.com");
ok("CORS: www.cybermeters.com can read /health", wwwHealth.acao === "https://www.cybermeters.com");
ok("CORS: www.cybermeters.com can read /ready", wwwReady.acao === "https://www.cybermeters.com");
ok("CORS: app.cybermeters.com remains allowed",
  [appHealth, appReady].every((response) => response.acao === "https://app.cybermeters.com"));
ok("CORS: hostile origin cannot read /health", hostileHealth.acao === null);
ok("CORS: hostile origin cannot read /ready", hostileReady.acao === null);
ok("CORS: authenticated route does not allow cybermeters.com",
  marketingAuth.status === 401 && marketingAuth.acao === "https://app.cybermeters.com");
ok("CORS: status-page preflight is read-only",
  marketingPreflight.status === 204 &&
  marketingPreflight.acao === "https://cybermeters.com" &&
  marketingPreflight.allowMethods === "GET, OPTIONS");
ok("CORS: status-page origin cannot read a write to the probe path",
  marketingWrite.acao !== "https://cybermeters.com");
ok("CORS: no public-probe response uses wildcard ACAO",
  [apexHealth, apexReady, wwwHealth, wwwReady, appHealth, appReady, hostileHealth, hostileReady]
    .every((response) => response.acao !== "*"));
ok("CORS: origin-dependent public probes vary by Origin",
  [apexHealth, apexReady, wwwHealth, wwwReady, appHealth, appReady, hostileHealth, hostileReady]
    .every((response) => response.vary?.split(",").map((value) => value.trim()).includes("Origin")));
ok("CORS: public probes preserve no-store cache behaviour",
  [apexHealth, apexReady].every((response) => response.cacheControl === "no-store"));
ok("CORS: public probes preserve health/readiness response semantics",
  apexHealth.status === 200 && apexHealth.body.status === "ok" &&
  apexReady.status === 200 && apexReady.body.status === "ready" &&
  apexReady.body.checks?.d1 === true && apexReady.body.checks?.r2 === true);

console.log(`\nMaintenance mode: ${pass}/${pass + fail} passed`);
if (fail) { console.error("maintenance-mode validation FAILED"); process.exit(1); }
console.log("maintenance-mode validation passed");
