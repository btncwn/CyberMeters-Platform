#!/usr/bin/env node
//
// Error-contract regression: every API error response (HTTP >= 400) must carry a
// uniform, leak-free shape — { error, code, message } — with a snake_case
// machine `code`, a customer-safe human `message`, and NO internal `detail`/
// `stack`. The shape is enforced centrally by normalizeApiResponseData (the
// choke point behind the json() helper), so this guards both the helper's logic
// (unit) and that the real worker actually routes errors through it (integration).
// Requires Node 24+ (node:sqlite). Exits non-zero on any failure so CI blocks.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// Contract predicate reused by unit + integration: a well-formed error body.
const SNAKE = /^[a-z][a-z0-9_]*$/;
function assertContract(label, body, status) {
  ok(`${label}: error is a non-empty string`, typeof body.error === "string" && body.error.trim().length > 0);
  ok(`${label}: code is a snake_case machine token`, typeof body.code === "string" && SNAKE.test(body.code));
  ok(`${label}: message is a human sentence`, typeof body.message === "string" && body.message.trim().length > 0);
  ok(`${label}: no detail leaked`, !("detail" in body));
  ok(`${label}: no stack leaked`, !("stack" in body));
  // A customer-safe message must never be a bare machine token or a raw HTTP word.
  ok(`${label}: message is not a bare machine token`, !SNAKE.test(body.message.trim()));
}

// ── 1. Unit: normalizeApiResponseData (the choke point) ──────────────────────
const { normalizeApiResponseData: norm } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "util.js")).href
);

// Every status the API actually returns gets a proper code + message.
for (const status of [400, 401, 403, 404, 405, 409, 410, 413, 414, 422, 429, 500, 502, 503]) {
  const out = norm({ error: "" }, status);
  assertContract(`unit ${status}`, out, status);
}

// Success bodies pass through untouched — no code/message injected.
const success = norm({ data: { ok: true } }, 200);
ok("unit 200: passthrough, no code added", !("code" in success) && !("message" in success));
ok("unit 200: passthrough, no message added", success.data?.ok === true);

// A route's own specific message + code always win (added only when absent).
const specific = norm({ error: "Forbidden", code: "billing_owner_required", message: "Workspace owner required for billing." }, 403);
ok("unit: existing message preserved", specific.message === "Workspace owner required for billing.");
ok("unit: existing code preserved", specific.code === "billing_owner_required");

// A snake_case error IS the code; a human error string does not pollute code.
ok("unit: snake_case error becomes code", norm({ error: "plan_feature_required" }, 403).code === "plan_feature_required");
const human = norm({ error: "Invalid email or password" }, 401);
ok("unit: human error preserved verbatim", human.error === "Invalid email or password");
ok("unit: human error yields status code, not prose", human.code === "unauthorized");

// detail/stack are always stripped, even when other fields are valid.
const leaky = norm({ error: "boom", detail: "SELECT * FROM users…", stack: "at handler (index.js:42)" }, 500);
ok("unit: detail stripped", !("detail" in leaky));
ok("unit: stack stripped", !("stack" in leaky));
assertContract("unit leaky-500", leaky, 500);

// Non-object payloads pass through unchanged.
ok("unit: string body passthrough", norm("nope", 500) === "nope");
ok("unit: array body passthrough", Array.isArray(norm([1, 2], 400)));
ok("unit: null body passthrough", norm(null, 404) === null);

// ── 2. Integration: real worker routes errors through the contract ───────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; }, async exec(sql) { db.exec(sql); return { count: 0 }; } };
}

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(workerPath).href);
const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) },
  ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com", APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const call = async (method, urlPath, opts = {}) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${urlPath}`, { method, ...opts }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, body };
};

// 401 — unauthenticated request to a protected endpoint.
const unauth = await call("GET", "/api/workspaces");
ok("integration: unauth is 401", unauth.status === 401);
if (unauth.status >= 400 && typeof unauth.body === "object") assertContract("integration 401", unauth.body, unauth.status);

// 404 — unknown route falls through to the catch-all.
const notFound = await call("GET", "/api/this-route-does-not-exist-xyz");
ok("integration: unknown route is 404", notFound.status === 404);
if (notFound.status >= 400 && typeof notFound.body === "object") assertContract("integration 404", notFound.body, notFound.status);

console.log(`\nError contract: ${pass}/${pass + fail} passed`);
if (fail) { console.error("error-contract validation FAILED"); process.exit(1); }
console.log("error-contract validation passed");
