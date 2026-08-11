#!/usr/bin/env node
//
// Maintenance-mode regression: when MAINTENANCE_MODE is on, every API route must
// return a clean 503 maintenance contract, while /health and /ready stay
// reachable (monitoring) and a bypass token still gets through (founder smoke
// test). When off, traffic flows normally. Fail-safe parsing is unit-tested so a
// typo can never take the API down. Requires Node 24+ (node:sqlite). CI-blocking.
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
const { isMaintenanceMode, isMaintenanceBypass } = worker;

// ── 1. Unit: fail-safe flag parsing ──────────────────────────────────────────
for (const v of ["on", "ON", "1", "true", "True", " on "]) ok(`isMaintenanceMode("${v}") = true`, isMaintenanceMode({ MAINTENANCE_MODE: v }) === true);
for (const v of ["off", "", "0", "false", "nope", undefined, null]) ok(`isMaintenanceMode(${JSON.stringify(v)}) = false`, isMaintenanceMode({ MAINTENANCE_MODE: v }) === false);
ok("isMaintenanceMode({}) = false", isMaintenanceMode({}) === false);

// Bypass only when a token is configured AND the header matches.
const req = (h = {}) => new Request("https://app.cybermeters.com/api/x", { headers: h });
ok("bypass off when no token set", isMaintenanceBypass(req({ "X-Maintenance-Bypass": "x" }), {}) === false);
ok("bypass on with matching header", isMaintenanceBypass(req({ "X-Maintenance-Bypass": "secret" }), { MAINTENANCE_BYPASS_TOKEN: "secret" }) === true);
ok("bypass off with wrong header", isMaintenanceBypass(req({ "X-Maintenance-Bypass": "nope" }), { MAINTENANCE_BYPASS_TOKEN: "secret" }) === false);

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
const call = async (urlPath, env, headers = {}, method = "GET") => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${urlPath}`, { method, headers }), env, ctx);
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
