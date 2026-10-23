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
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { splitStatements, isToleratedStatement } from "../../lib/migration-apply-tolerated.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const workerPath = path.join(ROOT, "workers", "scan-api", "src", "index.js");

export async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

export function buildDb() {
  const db = new DatabaseSync(":memory:");
  // F-025/F-035 (corrective) — a migration/schema apply error is TERMINAL. Migrations apply
  // STATEMENT-BY-STATEMENT so a tolerated error on one statement never skips the remainder of
  // the file (the R1 false-green). Tolerance is bound to the exact file bytes + the exact
  // failing statement (single source of truth: lib/migration-apply-tolerated); anything else
  // throws — a harness must never run its assertions on a silently-broken schema.
  db.exec(fs.readFileSync(path.join(ROOT, "database", "schema.sql"), "utf8")); // consolidated form; a real error here is terminal
  for (const f of fs.readdirSync(path.join(ROOT, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    const raw = fs.readFileSync(path.join(ROOT, "database", "migrations", f), "utf8");
    const fileSha = crypto.createHash("sha256").update(raw).digest("hex");
    for (const stmt of splitStatements(raw)) {
      try { db.exec(stmt); }
      catch (e) { if (!isToleratedStatement(f, fileSha, stmt, e.message)) throw e; }
    }
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

// Local stand-in for Stripe's API — never the network. The Worker reads every
// subscription it is told about (GET /v1/subscriptions/:id, latest invoice
// expanded); this answers from `truth`, Stripe's current view per subscription.
// A test sets truth directly (out-of-order histories: truth is the newest state)
// or calls mirror(event) before each delivery, which keeps truth equal to an
// in-order history of those events. failNext(n) answers the next n reads 500.
// Any other URL still throws "network disabled".
export function createStripeProvider() {
  const truth = new Map();
  let failures = 0, reads = 0;
  const idOf = (v) => (v && typeof v === "object" ? v.id : v) || null;
  const subIdOfInvoice = (inv) => idOf(inv?.subscription) ?? idOf(inv?.parent?.subscription_details?.subscription);
  const fetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const m = url.hostname === "api.stripe.com" && url.pathname.match(/^\/v1\/subscriptions\/([^/]+)$/);
    if (!m) throw new Error("network disabled");
    reads++;
    if (failures > 0) { failures--; return new Response(JSON.stringify({ error: { type: "api_error" } }), { status: 500 }); }
    const sub = truth.get(decodeURIComponent(m[1]));
    if (!sub) return new Response(JSON.stringify({ error: { type: "invalid_request_error" } }), { status: 404 });
    return new Response(JSON.stringify(sub), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const mirror = (event) => {
    const obj = event?.data?.object || {};
    const created = event?.created ?? Math.floor(Date.now() / 1000);
    const type = event?.type || "";
    if (type === "customer.subscription.created" || type === "customer.subscription.updated") {
      const prev = truth.get(obj.id) || {};
      truth.set(obj.id, { ...prev, ...obj, latest_invoice: obj.latest_invoice ?? prev.latest_invoice ?? null });
    } else if (type === "checkout.session.completed") {
      // A settled subscription checkout means Stripe now holds an active
      // subscription for what was bought (plan from metadata: no price yet).
      const id = idOf(obj.subscription);
      if (id && !truth.has(id) && ["paid", "no_payment_required"].includes(obj.payment_status)) {
        truth.set(id, { id, customer: idOf(obj.customer), status: "active", metadata: obj.metadata || {}, latest_invoice: null });
      }
    } else if (type === "customer.subscription.deleted") {
      truth.set(obj.id, { ...(truth.get(obj.id) || {}), ...obj, status: "canceled" });
    } else if (type === "invoice.payment_failed" || type === "invoice.payment_succeeded") {
      const id = subIdOfInvoice(obj);
      const prev = id && truth.get(id);
      if (!prev) return;
      const failed = type === "invoice.payment_failed";
      const status = prev.status === "canceled" || prev.status === "unpaid" ? prev.status
        : failed ? "past_due" : (prev.status === "past_due" ? "active" : prev.status);
      truth.set(id, { ...prev, status, latest_invoice: {
        id: obj.id || `in_${created}`, status: failed ? "open" : "paid", created,
        attempt_count: obj.attempt_count ?? 1,
      } });
    }
  };
  return {
    truth, fetch, mirror,
    set: (sub) => truth.set(sub.id, sub),
    failNext: (n = 1) => { failures = n; },
    get reads() { return reads; },
  };
}
