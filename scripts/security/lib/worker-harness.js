// ─────────────────────────────────────────────────────────────────────────────
// worker-harness.js  (shared)
//
// Reusable scaffolding to drive the REAL Worker fetch() handler against a REAL
// in-memory SQLite (schema + migrations applied). Mirrors the setup pioneered by
// scripts/validate-tenant-isolation.js and reused by the extended two-tenant
// harness and the property-based authorization suite, so all three exercise the
// same production router — not a mock. Requires Node 24+ (node:sqlite).
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const workerPath = path.join(ROOT, "workers", "scan-api", "src", "index.js");

export async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

export function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema converges */ } };
  apply(path.join(ROOT, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(ROOT, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(ROOT, "database", "migrations", f));
  }
  return db;
}

export function makeD1(db) {
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

// R2 stub: serves a marker-bearing object for keys containing `served`, so an
// unauthorized 200 that fetched by key without an ownership check would leak it.
export function makeEnv(db, { r2MarkerKey = "served", marker = "R2-MARKER" } = {}) {
  const obj = {
    json:        async () => ({ modules: { leak_probe: marker } }),
    text:        async () => JSON.stringify({ snapshot: { snapshot_schema_version: "1" }, marker }),
    arrayBuffer: async () => new TextEncoder().encode(marker).buffer,
    body: marker,
  };
  const r2 = {
    get: async (key) => (String(key ?? "").includes(r2MarkerKey) ? obj : null),
    put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }),
  };
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: r2,
    MFA_ENCRYPTION_KEY: "tenant-test-mfa-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}

export const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

// Build an authenticated caller bound to a worker + env. Each call gets a UNIQUE
// synthetic client IP so the per-IP global rate limiter does not accumulate across
// a long run and mask the authorization logic under test (a shared IP would 429
// later cases, making them vacuous). Pass { fixedIp } to opt out.
export function makeCaller(worker, env, { debug = false, fixedIp = null } = {}) {
  let n = 0;
  return async (method, pathname, token, body) => {
    const headers = { "CF-Connecting-IP": fixedIp || `10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n++ & 255}` };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (body) headers["Content-Type"] = "application/json";
    const req = new Request("https://api.cybermeters.com" + pathname, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const res = await worker.fetch(req, env, ctx);
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch { /* non-JSON */ }
    if (debug) console.error(`  [${method} ${pathname}] ${token ? "(auth)" : "(anon)"} → ${res.status} ${text.slice(0, 120)}`);
    return { status: res.status, data, text };
  };
}

// Response helpers: a response "leaks" if it is a 2xx carrying the private marker.
export const leaks = (r, marker) => r.status < 300 && JSON.stringify(r.data ?? r.text ?? "").includes(marker);
export const denied = (r, marker) => (r.status === 401 || r.status === 403 || r.status === 404) || !leaks(r, marker);

// Seed helpers bound to a db + the worker's hashToken/hashPassword.
export async function makeSeeder(db, mod) {
  const { hashToken, hashPassword } = mod;
  const pw = await hashPassword("Sup3r-secret-pw");
  return {
    user: (id, email, name = id) =>
      db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, 'free', 'active', 1, 0)").run(id, email, pw, name),
    session: async (sid, uid, raw) =>
      db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))").run(sid, uid, await hashToken(raw)),
    workspace: (id, owner, name, deleted = false) =>
      db.prepare(`INSERT INTO workspaces (id, owner_user_id, name${deleted ? ", deleted_at" : ""}) VALUES (?, ?, ?${deleted ? ", datetime('now')" : ""})`).run(id, owner, name),
    member: (id, ws, uid, role) =>
      db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run(id, ws, uid, role),
    removeMember: (ws, uid) =>
      db.prepare("DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?").run(ws, uid),
    raw: (sql, ...a) => { try { db.prepare(sql).run(...a); } catch (e) { if (process.env.HARNESS_DEBUG) console.error("seed skip:", e.message, sql.slice(0, 60)); } },
  };
}
