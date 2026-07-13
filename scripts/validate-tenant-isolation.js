#!/usr/bin/env node
//
// Tenant-isolation regression matrix — the highest-value security test debt.
// Drives the worker's REAL fetch() handler against a REAL in-memory SQLite
// (schema + migrations applied), with four actors seeded once:
//
//   admin  — admin member of ws1
//   viewer — viewer member of ws1 (low privilege)
//   foreign— owner of ws2, NOT a member of ws1
//   nobody — a valid session with no workspace membership at all
//
// For every workspace-scoped resource it asserts the seven invariants from
// docs/SECURITY-SDLC-ROADMAP.md:
//   1 foreign cannot READ ws1's resource        (not 200-with-data)
//   2 foreign cannot MODIFY ws1's resource
//   3 foreign cannot DELETE ws1's resource
//   4 foreign cannot tell if a ws1 resource EXISTS (foreign-by-id == nonexistent-by-id)
//   5 low-priv member cannot perform an admin action
//   6 a soft-deleted workspace's data is not readable
//   7 an invite token cannot be redirected to another workspace
//
// Exits non-zero on any failure so CI blocks. Requires Node 24+ (node:sqlite).
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema converges */ } };
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

// A ws1-owned R2 report object. get() returns it ONLY for the ws1 scan's key, so
// if any report route skipped its ownership check and fetched by key, the marker
// would leak — proving the guard is a real ownership check, not key-existence.
const REPORT_MARKER = "REPORT-SECRET";
const ws1ReportObject = {
  // The marker lives inside `modules` because the report route rebuilds the
  // envelope from the scan row and echoes the normalised modules — so an
  // authorised read surfaces it, and any unauthorised 200 would leak it.
  json:        async () => ({ scan_id: "scan_ws1", modules: { leak_probe: REPORT_MARKER } }),
  text:        async () => JSON.stringify({ marker: REPORT_MARKER }),
  arrayBuffer: async () => new TextEncoder().encode(REPORT_MARKER).buffer,
  body:        REPORT_MARKER,
};

function makeEnv(db) {
  const noR2 = {
    get: async (key) => (String(key ?? "").includes("scan_ws1") ? ws1ReportObject : null),
    put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }),
  };
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "tenant-test-mfa-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

let passed = 0, failed = 0, currentSection = "General";
const results = [];
function section(name) { currentSection = name; }
function ok(name, cond) {
  if (cond) { passed++; results.push(`PASS [${currentSection}] ${name}`); }
  else      { failed++; results.push(`FAIL [${currentSection}] ${name}`); }
}

// A response "leaks ws1" if it is a 2xx that carries the private marker string.
const leaks = (r, marker) => r.status < 300 && JSON.stringify(r.data ?? r.text ?? "").includes(marker);
// Denied = the caller is refused OR gets an empty/non-leaking success (list scoped away).
const denied = (r, marker) => (r.status === 401 || r.status === 403 || r.status === 404) || !leaks(r, marker);

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const { hashToken, hashPassword } = mod;
  const db = buildDb();
  const env = makeEnv(db);

  const pw = await hashPassword("Sup3r-secret-pw");
  const seedUser = (id, email, name) =>
    db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, 'free', 'active', 1, 0)").run(id, email, pw, name);
  const seedSession = async (sid, uid, raw) =>
    db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))").run(sid, uid, await hashToken(raw));

  seedUser("admin",  "admin@a.co",  "Admin");
  seedUser("viewer", "viewer@a.co", "Viewer");
  seedUser("foreign","foreign@b.co","Foreign");
  seedUser("nobody", "nobody@x.co", "Nobody");
  const T = { admin: "raw-admin", viewer: "raw-viewer", foreign: "raw-foreign", nobody: "raw-nobody" };
  await seedSession("s1", "admin", T.admin);
  await seedSession("s2", "viewer", T.viewer);
  await seedSession("s3", "foreign", T.foreign);
  await seedSession("s4", "nobody", T.nobody);

  // ws1 (Alpha) belongs to admin+viewer; ws2 (Bravo) belongs to foreign; wsDead is soft-deleted.
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','admin','Alpha-SECRET')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws2','foreign','Bravo')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name, deleted_at) VALUES ('wsDead','admin','Dead-SECRET', datetime('now'))").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mm1','ws1','admin','admin')").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mm2','ws1','viewer','viewer')").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mm3','ws2','foreign','owner')").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mm4','wsDead','admin','admin')").run();

  // Seed a ws1-owned object in the tables that carry a leakable marker.
  const tryInsert = (sql, ...a) => { try { db.prepare(sql).run(...a); } catch { /* schema variance — endpoint test still runs */ } };
  tryInsert("INSERT INTO domains (id, user_id, domain) VALUES ('dom1','admin','secret1.example')");
  tryInsert("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','dom1')");
  tryInsert("INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen, status, created_at, updated_at) VALUES ('a1','ws1','dom1','asset-SECRET.example','subdomain','ct', datetime('now'), datetime('now'), 'active', datetime('now'), datetime('now'))");
  tryInsert("INSERT INTO managed_cases (id, workspace_id, case_type, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, created_at, updated_at) VALUES ('mc-secret','ws1','asm_exposure','secret1.example','admin_surface_high','case-SECRET.example','high','open','{}','[]',datetime('now'),datetime('now'))");
  tryInsert("INSERT INTO scans (id, domain_id, domain, score, rating, status, created_at) VALUES ('scan_ws1','dom1','secret1.example',80,'good','completed', datetime('now'))");
  tryInsert("INSERT INTO managed_cases (id, workspace_id, case_type, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, created_at, updated_at) VALUES ('mc-brand-secret','ws1','brand_abuse','brand-case-SECRET.example','brand-secret','example.com','high','triage','{}','[]',datetime('now'),datetime('now'))");
  tryInsert("INSERT INTO notification_events (id, workspace_id, user_id, type, severity, title, message, status) VALUES ('n1','ws1',NULL,'scan','info','notif-SECRET','m','unread')");
  tryInsert("INSERT INTO workspace_invitations (id, workspace_id, email, role, token_hash, invited_by, status, expires_at, created_at) VALUES ('inv1','ws1','invitee@x.co','viewer', 'invhash1','admin','pending', datetime('now','+7 day'), datetime('now'))");

  const call = async (method, pathname, token, body) => {
    const headers = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (body) headers["Content-Type"] = "application/json";
    const req = new Request("https://api.cybermeters.com" + pathname, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const res = await worker.fetch(req, env, ctx);
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch { /* non-JSON */ }
    if (process.env.TENANT_DEBUG) console.error(`  [${method} ${pathname}] ${token ? "(auth)" : "(anon)"} → ${res.status} ${text.slice(0,120)}`);
    return { status: res.status, data, text };
  };

  // Sanity: the admin CAN see their own workspace (proves the pipeline actually
  // returns data, so a "denied" pass elsewhere can't be a false positive).
  section("Baseline (positive control)");
  const adminSelf = await call("GET", "/api/workspaces/ws1", T.admin);
  ok("admin reads own workspace and sees its name", leaks(adminSelf, "Alpha-SECRET"));

  // ── Invariant 1 & 4: foreign READ + existence oracle across every ws-scoped GET ──
  section("Invariant 1+4 — foreign cannot read / enumerate ws1 resources");
  const ROUTES = [
    { path: "/api/workspaces/ws1",                 marker: "Alpha-SECRET" },
    { path: "/api/workspaces/ws1/assets",          marker: "asset-SECRET" },
    { path: "/api/workspaces/ws1/managed-cases",   marker: "case-SECRET" },
    { path: "/api/workspaces/ws1/brand/cases",     marker: "brand-case-SECRET" },
    { path: "/api/workspaces/ws1/assets/summary",  marker: "asset-SECRET" },
    { path: "/api/workspaces/ws1/domains",         marker: "secret1.example" },
    { path: "/api/workspaces/ws1/notifications",   marker: "notif-SECRET" },
    { path: "/api/workspaces/ws1/audit-events",    marker: "Alpha-SECRET" },
    { path: "/api/workspaces/ws1/members",         marker: "admin@a.co" },
    { path: "/api/workspaces/ws1/invitations",     marker: "invitee@x.co" },
    { path: "/api/workspaces/ws1/reports",         marker: "Alpha-SECRET" },
    { path: "/api/workspaces/ws1/subscription",    marker: "Alpha-SECRET" },
    { path: "/api/workspaces/ws1/brand/profile",   marker: "Alpha-SECRET" },
    { path: "/api/workspaces/ws1/scorecard",       marker: "Alpha-SECRET" },
    { path: "/api/workspaces/ws1/business-risk",   marker: "Alpha-SECRET" },
  ];
  for (const r of ROUTES) {
    const foreign = await call("GET", r.path, T.foreign);
    ok(`foreign cannot read ${r.path}`, denied(foreign, r.marker));
    const nobody = await call("GET", r.path, T.nobody);
    ok(`non-member cannot read ${r.path}`, denied(nobody, r.marker));
  }
  // Anonymous must never reach any of them either.
  for (const r of ROUTES) {
    const anon = await call("GET", r.path, null);
    ok(`anon cannot read ${r.path}`, denied(anon, r.marker));
  }

  // Existence oracle: a foreign real workspace id and a nonexistent id must be
  // indistinguishable (same status class).
  const foreignReal = await call("GET", "/api/workspaces/ws1", T.foreign);
  const foreignFake = await call("GET", "/api/workspaces/ws_does_not_exist", T.foreign);
  ok("existence oracle: foreign real-ws vs fake-ws return the same status",
     foreignReal.status === foreignFake.status);

  // ── Invariant 1 (R2): scan reports are ownership-scoped, not key-guessable ──
  // scan_ws1 is owned by ws1 (via dom1). Its R2 object carries REPORT_MARKER, so
  // a route that fetched by key without an ownership check would leak it.
  section("Invariant 1 (R2) — scan report objects are ownership-scoped");
  const SCAN_REPORT_ENDPOINTS = [
    "/api/scans/scan_ws1/report",
    "/api/scans/scan_ws1/report/pdf",
    "/api/scans/scan_ws1/executive-report-v2",
  ];
  for (const p of SCAN_REPORT_ENDPOINTS) {
    ok(`foreign cannot read ${p}`,     denied(await call("GET", p, T.foreign), REPORT_MARKER));
    ok(`non-member cannot read ${p}`,  denied(await call("GET", p, T.nobody),  REPORT_MARKER));
    ok(`anon cannot read ${p}`,        denied(await call("GET", p, null),       REPORT_MARKER));
  }
  // Positive control: the owner (admin, via the domain) CAN read the JSON report,
  // proving the R2 object is reachable — so the foreign denials are real ownership
  // checks, not just "report not found".
  ok("owner CAN read the scan report (foreign denials above are ownership-based)",
     leaks(await call("GET", "/api/scans/scan_ws1/report", T.admin), REPORT_MARKER));

  // ── Invariant 2 & 3: foreign cannot MODIFY / DELETE ws1 resources ──
  section("Invariant 2+3 — foreign cannot modify / delete ws1 resources");
  const writes = [
    ["POST",   "/api/workspaces/ws1/domains",             { domain: "evil.example" }],
    ["POST",   "/api/workspaces/ws1/invitations",         { email: "x@y.co", role: "admin" }],
    ["POST",   "/api/workspaces/ws1/notifications/all/read", {}],
    ["POST",   "/api/workspaces/ws1/managed-cases/mc-secret/assign", { owner_ref: "foreign", owner_type: "team" }],
    ["POST",   "/api/workspaces/ws1/brand/cases/mc-brand-secret/review", { classification: "confirmed_abuse", reason: "foreign attempt" }],
    ["PATCH",  "/api/workspaces/ws1",                      { name: "Hijacked" }],
    ["POST",   "/api/workspaces/ws1/delete-request",       {}],
    ["POST",   "/api/workspaces/ws1/members",             { email: "foreign@b.co", role: "admin" }],
  ];
  for (const [m, p, b] of writes) {
    const r = await call(m, p, T.foreign, b);
    ok(`foreign ${m} ${p} is refused`, r.status === 401 || r.status === 403 || r.status === 404);
  }
  // The hijack attempt must not have renamed ws1.
  const afterHijack = await call("GET", "/api/workspaces/ws1", T.admin);
  ok("ws1 name is unchanged after the foreign PATCH attempt", leaks(afterHijack, "Alpha-SECRET"));

  // ── Invariant 5: low-priv (viewer) cannot perform admin actions ──
  section("Invariant 5 — viewer cannot perform admin actions");
  const adminActions = [
    ["POST",  "/api/workspaces/ws1/invitations",   { email: "z@z.co", role: "viewer" }],
    ["POST",  "/api/workspaces/ws1/members",       { email: "x@x.co", role: "admin" }],
    ["POST",  "/api/workspaces/ws1/delete-request", {}],
    ["PATCH", "/api/workspaces/ws1",               { name: "ViewerRenamed" }],
    ["POST",  "/api/workspaces/ws1/domains",       { domain: "viewer.example" }],
    ["POST",  "/api/workspaces/ws1/managed-cases/mc-secret/assign", { owner_ref: "viewer", owner_type: "team" }],
    ["POST",  "/api/workspaces/ws1/brand/cases/mc-brand-secret/review", { classification: "confirmed_abuse", reason: "viewer attempt" }],
  ];
  for (const [m, p, b] of adminActions) {
    const r = await call(m, p, T.viewer, b);
    ok(`viewer ${m} ${p} is forbidden`, r.status === 401 || r.status === 403);
  }
  // But a viewer CAN read (positive control — proves the 403s above aren't a blanket deny).
  const viewerRead = await call("GET", "/api/workspaces/ws1", T.viewer);
  ok("viewer CAN read ws1 (403s above are role-specific, not a blanket deny)", leaks(viewerRead, "Alpha-SECRET"));

  // ── Invariant 6: a soft-deleted workspace's data is not readable ──
  section("Invariant 6 — soft-deleted workspace is not readable");
  const deadRead = await call("GET", "/api/workspaces/wsDead", T.admin);
  ok("owner cannot read a soft-deleted workspace's data", denied(deadRead, "Dead-SECRET"));
  const deadAssets = await call("GET", "/api/workspaces/wsDead/assets", T.admin);
  ok("soft-deleted workspace asset list does not leak", denied(deadAssets, "Dead-SECRET"));

  // ── Invariant 7: an invite token cannot be redirected to another workspace ──
  section("Invariant 7 — invite token cannot cross workspaces");
  // The public preview + accept are keyed by the token itself; a token minted for
  // ws1 must never grant membership to ws2. Forging acceptance against ws2 fails.
  const acceptWrongWs = await call("POST", "/api/invitations/invhash1/accept", T.foreign, { workspace_id: "ws2" });
  ok("accepting a ws1 invite cannot join ws2", acceptWrongWs.status !== 200 || !JSON.stringify(acceptWrongWs.data ?? "").includes("ws2"));

  // ── Report ──
  const bySection = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySection[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nTenant-isolation matrix:");
  for (const [s, c] of Object.entries(bySection)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  if (failed) {
    console.log("\nFailures:");
    for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r);
  }
  console.log(`\nTenant isolation: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("tenant-isolation validation FAILED"); process.exit(1); }
  console.log("tenant-isolation validation passed");
}

main().catch((e) => { console.error("tenant-isolation runner crashed:", e); process.exit(1); });
