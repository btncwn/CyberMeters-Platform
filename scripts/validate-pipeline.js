#!/usr/bin/env node
//
// End-to-end request-pipeline tests: drive the worker's REAL fetch() handler
// (router → middleware → requireAuth → RBAC → D1 → Response) against a real
// in-memory SQLite seeded with the ACTUAL schema (schema.sql + migrations). This
// is the true integration layer above the leaf-function tests in
// validate-integration.js. Requires Node 24+ (node:sqlite). Exits non-zero on
// any failure so CI blocks.
//
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

// ── Load the worker's default export (the { fetch, scheduled, email } object) ──
function loadWorker() {
  const source = fs.readFileSync(workerPath, "utf8")
    .replace(/\bexport\s+default\b/, "const __workerDefault =");
  const context = {
    console,
    crypto: { randomUUID: () => webcrypto.randomUUID(), getRandomValues: (a) => webcrypto.getRandomValues(a), subtle: webcrypto.subtle },
    btoa: (s) => Buffer.from(String(s), "binary").toString("base64"),
    atob: (s) => Buffer.from(String(s), "base64").toString("binary"),
    Response, Request, URL, URLSearchParams, Headers,
    DecompressionStream, CompressionStream, Uint8Array, TextEncoder, TextDecoder,
    fetch: async () => { throw new Error("network disabled"); },
    AbortSignal: { timeout: () => undefined },
    Date, setTimeout, clearTimeout,
  };
  vm.createContext(context);
  vm.runInContext(`${source}\nthis.__worker = __workerDefault;\nthis.__hash = { hashToken, hashPassword };`, context);
  return { worker: context.__worker, hash: context.__hash };
}

// ── Real schema (best-effort: a few migrations are ordering/idempotency no-ops) ──
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

// ── D1-compatible adapter over node:sqlite ────────────────────────────────────
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeEnv(db) {
  const noR2 = { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "pipeline-test-mfa-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

// Independent HMAC-SHA256 hex — forges the Stripe-Signature the way Stripe does,
// so the webhook signature gate is tested against a real (not stubbed) signature.
async function hmacHex(secret, message) {
  const key = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

let passed = 0, failed = 0; const results = [];
function ok(name, cond) { if (cond) { passed++; results.push(`PASS ${name}`); } else { failed++; results.push(`FAIL ${name}`); } }

async function main() {
  const { worker, hash } = loadWorker();
  const db = buildDb();
  const env = makeEnv(db);

  // ── Seed: two tenants; userA is an admin member of ws1 only ──
  const pwHash = await hash.hashPassword("Sup3r-secret-pw");
  const tokenA = "session-raw-token-A";
  const tokenHashA = await hash.hashToken(tokenA);
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, 1, 0)")
    .run("userA", "a@example.com", pwHash, "Alice", "free", "active");
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, 1, 0)")
    .run("userC", "c@example.com", pwHash, "Carol", "free", "active");
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))")
    .run("sessA", "userA", tokenHashA);
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws1", "userA", "Alpha");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws2", "userC", "Bravo");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("m1", "ws1", "userA", "admin");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("m2", "ws2", "userC", "owner");

  const call = async (method, pathname, { token, body } = {}) => {
    const headers = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (body) headers["Content-Type"] = "application/json";
    const req = new Request("https://api.cybermeters.com" + pathname, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const res = await worker.fetch(req, env, ctx);
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch { /* non-JSON */ }
    if (process.env.PIPE_DEBUG) console.error(`  [${method} ${pathname}] → ${res.status}  ${text.slice(0, 160)}`);
    return { status: res.status, data, text };
  };
  const has = (r, sub) => JSON.stringify(r.data ?? r.text ?? "").includes(sub);

  // ── The pipeline actually runs (status AND body, so a pass can't be a coincidence) ──
  const health = await call("GET", "/health");
  ok("GET /health drives the real fetch() → 200 {status:ok}", health.status === 200 && health.data?.status === "ok");

  // ── Auth gate at the HTTP layer ──
  const noAuth = await call("GET", "/api/workspaces/ws1");
  ok("unauthenticated workspace request → 401 Unauthorized", noAuth.status === 401 && has(noAuth, "nauthorized"));

  const badToken = await call("GET", "/api/workspaces/ws1", { token: "not-a-real-token" });
  ok("invalid token → 401", badToken.status === 401);

  // ── Tenant isolation through the FULL pipeline (router→auth→RBAC→DB→response) ──
  const own = await call("GET", "/api/workspaces/ws1", { token: tokenA });
  ok("owner reaches OWN workspace → 200 with the real record (id ws1, name Alpha)",
    own.status === 200 && own.data?.workspace?.id === "ws1" && own.data?.workspace?.name === "Alpha");

  const foreign = await call("GET", "/api/workspaces/ws2", { token: tokenA });
  ok("CROSS-TENANT via HTTP: userA (ws1) → ws2 is FORBIDDEN (403) with no workspace data",
    foreign.status === 403 && has(foreign, "orbidden") && !has(foreign, "Bravo"));

  // ── Login / session lifecycle through the real pipeline ──
  const badLogin = await call("POST", "/api/auth/login", { body: { email: "a@example.com", password: "wrong-password" } });
  ok("login with wrong password → 401 (no token leaked)", badLogin.status === 401 && !badLogin.data?.token);

  const login = await call("POST", "/api/auth/login", { body: { email: "a@example.com", password: "Sup3r-secret-pw" } });
  const liveToken = login.data?.token;
  ok("login with correct password → 200 + a session token", login.status === 200 && typeof liveToken === "string" && liveToken.length > 20);

  const me = await call("GET", "/api/auth/me", { token: liveToken });
  ok("the issued token authenticates GET /api/auth/me → 200 (right user)", me.status === 200 && has(me, "a@example.com"));

  const logout = await call("POST", "/api/auth/logout", { token: liveToken });
  ok("POST /api/auth/logout succeeds (2xx)", logout.status >= 200 && logout.status < 300);

  const afterLogout = await call("GET", "/api/auth/me", { token: liveToken });
  ok("the session is DEAD after logout → 401 (token no longer resolves)", afterLogout.status === 401);

  // ── Stripe webhook → entitlement, through the real signature gate ──
  const secret = env.STRIPE_WEBHOOK_SECRET;
  const postWebhook = async (payload, { sign = true, ts = Math.floor(Date.now() / 1000) } = {}) => {
    const raw = JSON.stringify(payload);
    const headers = { "Content-Type": "application/json" };
    if (sign) headers["Stripe-Signature"] = `t=${ts},v1=${await hmacHex(secret, `${ts}.${raw}`)}`;
    const req = new Request("https://api.cybermeters.com/api/billing/webhook", { method: "POST", headers, body: raw });
    const res = await worker.fetch(req, env, ctx);
    const text = await res.text();
    if (process.env.PIPE_DEBUG) console.error(`  [POST /api/billing/webhook ${payload.type}] → ${res.status}  ${text.slice(0, 120)}`);
    return { status: res.status, text };
  };
  const subEvent = {
    type: "customer.subscription.created",
    data: { object: {
      id: "sub_pipeline_test", customer: "cus_pipeline_test", status: "active",
      items: { data: [] }, current_period_start: Math.floor(Date.now() / 1000),
      current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
      metadata: { user_id: "userA", workspace_id: "ws1", plan: "professional" },
    } },
  };

  // A forged/unsigned webhook must NOT be able to mutate billing.
  const unsigned = await postWebhook(subEvent, { sign: false });
  ok("webhook with NO signature is rejected (4xx, not processed)", unsigned.status >= 400 && unsigned.status < 500);

  // Wrong-secret signature = forgery. Sign the exact bytes but with the wrong key.
  const rawForged = JSON.stringify(subEvent); const tsF = Math.floor(Date.now() / 1000);
  const forgedReq = new Request("https://api.cybermeters.com/api/billing/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "Stripe-Signature": `t=${tsF},v1=${await hmacHex("whsec_WRONG", `${tsF}.${rawForged}`)}` }, body: rawForged });
  const forgedRes = await worker.fetch(forgedReq, env, ctx);
  ok("webhook with a WRONG-secret signature → 400 (forgery rejected)", forgedRes.status === 400);

  // A correctly-signed subscription event actually changes the stored entitlement.
  const signed = await postWebhook(subEvent);
  ok("correctly-signed subscription.created webhook is accepted → 2xx", signed.status >= 200 && signed.status < 300);
  const subRow = db.prepare("SELECT plan, subscription_status FROM subscriptions WHERE workspace_id = ? ORDER BY updated_at DESC LIMIT 1").get("ws1");
  if (process.env.PIPE_DEBUG) console.error("  [subscriptions ws1 row]", JSON.stringify(subRow));
  ok("ENTITLEMENT: the webhook upserted ws1's subscription to the paid plan (professional, active)",
    subRow?.plan === "professional" && String(subRow?.subscription_status).toLowerCase() === "active");

  for (const line of results) if (line.startsWith("FAIL")) console.error(line);
  console.log(`\nPipeline tests: ${passed}/${passed + failed} passed`);
  if (failed > 0) { console.error("pipeline validation FAILED"); process.exit(1); }
  console.log("pipeline validation passed");
}

main().catch((e) => { console.error("pipeline runner crashed:", e); process.exit(1); });
