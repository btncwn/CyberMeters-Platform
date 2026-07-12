#!/usr/bin/env node
//
// Exposure feed regression: drives the real worker fetch() handler against an
// in-memory SQLite schema and verifies /api/workspaces/:id/exposure/feed auth,
// enrichment, filtering and pagination. Requires Node 24+ (node:sqlite).
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
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
    MFA_ENCRYPTION_KEY: "exposure-feed-test-mfa-key",
    STRIPE_WEBHOOK_SECRET: "whsec_test",
    STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm", professional_monthly: "price_pm", business_monthly: "price_bm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test",
    RESEND_API_KEY: "",
    ADMIN_EMAILS: "",
  };
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const env = makeEnv(db);

  const tokenA = "exposure-feed-token-A";
  const tokenB = "exposure-feed-token-B";
  const tokenHashA = await mod.hashToken(tokenA);
  const tokenHashB = await mod.hashToken(tokenB);

  db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, 1, 0)")
    .run("userA", "a@example.com", "Alice", "free", "active");
  db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, 1, 0)")
    .run("userB", "b@example.com", "Bob", "free", "active");
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))")
    .run("sessA", "userA", tokenHashA);
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))")
    .run("sessB", "userB", tokenHashB);
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws1", "userA", "Alpha");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws2", "userB", "Bravo");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("memA", "ws1", "userA", "admin");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("memB", "ws2", "userB", "admin");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom1", "userA", "example.co.uk");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws1", "dom1");

  const insertEvent = db.prepare(
    `INSERT INTO asset_events
       (id, workspace_id, domain_id, asset_id, scan_id, event_type, hostname, severity, description, created_at)
     VALUES (?, 'ws1', 'dom1', null, ?, ?, ?, ?, ?, ?)`
  );
  const events = [
    ["evt_001", "scan1", "new_asset_discovered", "dev.example.co.uk", "info", "New asset", "2026-07-08T12:00:00.000Z"],
    ["evt_002", "scan1", "asset_reappeared", "api.example.co.uk", "medium", "Asset reappeared", "2026-07-08T12:01:00.000Z"],
    ["evt_003", "scan1", "certificate_expiring_soon", "example.co.uk", "critical", "Certificate expiring", "2026-07-08T12:02:00.000Z"],
    ["evt_004", "scan1", "exposed_service_resolved", "old.example.co.uk", "low", "Resolved", "2026-07-08T12:03:00.000Z"],
    ["evt_005", "scan1", "email_dmarc_policy_changed", "example.co.uk", "medium", "DMARC changed", "2026-07-08T12:04:00.000Z"],
    ["evt_006", "scan1", "dns_ip_changed", "www.example.co.uk", "high", "IP changed", "2026-07-08T12:05:00.000Z"],
    ["evt_007", "scan1", "email_spf_changed", "example.co.uk", "high", "SPF changed", "2026-07-08T12:06:00.000Z"],
    ["evt_008", "scan1", "unknown_custom_event", "mystery.example.co.uk", "critical", "Mystery", "2026-07-08T12:07:00.000Z"],
  ];
  for (const event of events) insertEvent.run(...event);

  const call = async (pathname, token = tokenA) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = new Request(`https://api.cybermeters.com${pathname}`, { method: "GET", headers });
    const res = await worker.fetch(req, env, ctx);
    let data = null; try { data = await res.json(); } catch { /* non-JSON */ }
    return { status: res.status, data };
  };

  const unauth = await call("/api/workspaces/ws1/exposure/feed", null);
  ok("unauthenticated feed request returns 401", unauth.status === 401);

  const foreign = await call("/api/workspaces/ws1/exposure/feed", tokenB);
  ok("foreign workspace feed request returns 403", foreign.status === 403);

  const feed = await call("/api/workspaces/ws1/exposure/feed");
  ok("feed request succeeds", feed.status === 200);
  ok("feed returns reverse chronological events", feed.data?.events?.[0]?.id === "evt_008" && feed.data?.events?.at(-1)?.id === "evt_001");
  ok("every feed event is enriched with category and title", feed.data?.events?.every((event) => event.category && event.title));

  const high = await call("/api/workspaces/ws1/exposure/feed?severity=high");
  ok("severity=high returns only high and critical events",
    high.data?.events?.length === 4 && high.data.events.every((event) => ["high", "critical"].includes(event.severity)));

  const email = await call("/api/workspaces/ws1/exposure/feed?category=email");
  ok("category=email returns only email events",
    email.data?.events?.length === 2 && email.data.events.every((event) => event.category === "email" && event.event_type.startsWith("email_")));

  const dnsIp = await call("/api/workspaces/ws1/exposure/feed?event_type=dns_ip_changed");
  ok("event_type=dns_ip_changed narrows to that type",
    dnsIp.data?.events?.length === 1 && dnsIp.data.events[0]?.event_type === "dns_ip_changed");

  const host = await call("/api/workspaces/ws1/exposure/feed?hostname=www.example.co.uk");
  ok("hostname filter narrows to matching hostname",
    host.data?.events?.length === 1 && host.data.events[0]?.hostname === "www.example.co.uk");

  const since = await call("/api/workspaces/ws1/exposure/feed?since=2026-07-08T12:05:00.000Z");
  ok("since filter narrows by created_at lower bound",
    since.data?.events?.length === 3 && since.data.events.at(-1)?.id === "evt_006");

  const page1 = await call("/api/workspaces/ws1/exposure/feed?limit=3");
  ok("pagination limit=3 returns 3 events", page1.data?.events?.length === 3);
  ok("pagination total is full filtered total and has_more is true",
    page1.data?.pagination?.total === 8 && page1.data?.pagination?.has_more === true);

  const page2 = await call("/api/workspaces/ws1/exposure/feed?limit=3&offset=3");
  ok("pagination offset=3 returns the next page",
    page2.data?.events?.length === 3 && page2.data.events[0]?.id === "evt_005");

  const unknown = feed.data?.events?.find((event) => event.event_type === "unknown_custom_event");
  ok("unknown event_type falls back safely to asset category", unknown?.category === "asset");
  ok("unknown event_type fallback title is title-cased", unknown?.title === "Unknown Custom Event");

  console.log(`\nExposure feed: ${pass}/${pass + fail} passed`);
  if (fail) { console.error("exposure-feed validation FAILED"); process.exit(1); }
  console.log("exposure-feed validation passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
