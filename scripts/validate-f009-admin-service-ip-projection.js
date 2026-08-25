#!/usr/bin/env node
//
// F-009 — the legacy admin-service `ip_address` must not reach a customer read
// projection. Behavioural, not source-text: a REAL R2 report is seeded WITH the
// field, the REAL worker route is called, and the response is asserted to omit
// it while still serving the service itself.
//
// Stored bytes are deliberately untouched — the seeded report still contains the
// IP. That is the point: historical integrity is preserved and the PROJECTION is
// what changed. A test that scrubbed the stored object would prove the wrong
// thing.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");
const SECRET_IP = "203.0.113.77";

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(st) { return Promise.all(st.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}
// The STORED report deliberately still carries the IP.
const REPORT = {
  scan_id: "scan1", domain: "f009.example.com",
  modules: { admin_surface_detection: { total: 1, evidence_status: "issue_detected", services: [
    { hostname: "admin.f009.example.com", product: "phpMyAdmin", category: "db-admin",
      severity: "high", risk_level: "high", confidence: "high",
      ip_address: SECRET_IP, server: "nginx", title: "phpMyAdmin login" },
  ] } },
};
function makeEnv(db) {
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: {
      get: async (k) => (String(k).includes("scan1") ? { json: async () => REPORT, text: async () => JSON.stringify(REPORT), arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(REPORT)).buffer } : null),
      put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }),
    },
    MFA_ENCRYPTION_KEY: "f009", STRIPE_WEBHOOK_SECRET: "whsec", STRIPE_SECRET_KEY: "sk_test",
    STRIPE_PRICE_MAP: "{}", ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com", APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
let passed = 0, failed = 0; const out = [];
const ok = (n, c) => { c ? (passed++, out.push(`PASS ${n}`)) : (failed++, out.push(`FAIL ${n}`)); };

async function main() {
  const mod = await loadWorker(); const worker = mod.default;
  const { hashToken, hashPassword } = mod;
  const db = buildDb(); const env = makeEnv(db);
  const pw = await hashPassword("Sup3r-secret-pw");
  const errs = [];
  const run = (sql, ...a) => { try { db.prepare(sql).run(...a); } catch (e) { errs.push(e.message); } };
  run("INSERT INTO users (id,email,password_hash,name,plan,status,email_verified,mfa_enabled) VALUES ('u1','u@a.co',?,'U','free','active',1,0)", pw);
  db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('s1','u1',?,datetime('now','+1 day'))").run(await hashToken("raw-u1"));
  run("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws1','u1','WS')");
  run("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m1','ws1','u1','owner')");
  run("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','f009.example.com')");
  run("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')");
  run("INSERT INTO scans (id,workspace_id,domain_id,domain,score,rating,status,scan_quality,created_at) VALUES ('scan1','ws1','d1','f009.example.com',70,'fair','completed','complete',datetime('now'))");

  ok(`fixture seeded without error (${errs[0] ?? "none"})`, errs.length === 0);
  ok("the STORED report still contains the IP (integrity preserved)", JSON.stringify(REPORT).includes(SECRET_IP));

  const r = await worker.fetch(new Request("https://api.test/api/workspaces/ws1/admin-surfaces", { headers: { Authorization: "Bearer raw-u1" } }), env, ctx);
  const body = await r.text();
  ok("route engaged (not a vacuous 401/403)", r.status === 200);
  ok("the admin service IS still served (not a deny-all pass)", body.includes("phpMyAdmin"));
  ok("the legacy ip_address is NOT projected", !body.includes(SECRET_IP));
  ok("no ip_address key in the projection", !/"ip_address"\s*:/.test(body));

  console.log(out.join("\n"));
  console.log(`\nF-009 admin-service ip projection: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
