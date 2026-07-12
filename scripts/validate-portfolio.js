#!/usr/bin/env node
//
// MSP Portfolio regression (internal pentest §7/§8 + product): the portfolio
// endpoints aggregate ACROSS workspaces, so cross-MSP isolation is the critical
// invariant — MSP A must never see MSP B's customers. Also proves the per-
// customer rows carry this-week change counts, the attention ranking is correct,
// and the executive summary aggregates right. Drives the REAL worker fetch with a
// seeded session. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "portfolio-customers.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { computePortfolioCustomerRows, buildExecutiveSummary } = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => {
  const wrap = (sql, args) => ({ first: async () => db.prepare(sql).get(...args) ?? null, all: async () => ({ results: db.prepare(sql).all(...args) }), run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; } });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};

// ── Seed: MSP A (2 customers) + MSP B (1 customer) ───────────────────────────
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_a','a@example.co.uk',1)").run();
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_b','b@example.co.uk',1)").run();
for (const [ws, owner, name] of [["ws_a1", "u_a", "Acme"], ["ws_a2", "u_a", "Beta Ltd"], ["ws_b1", "u_b", "Rival Co"]]) {
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?,?)").run(ws, name, owner);
  db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?,?, 'owner')").run(ws, owner);
}
// Domains + one completed scan each (score → risk_rating).
for (const [ws, dom, domId, score] of [["ws_a1", "acme.co.uk", "d_a1", 30], ["ws_a2", "beta.co.uk", "d_a2", 92], ["ws_b1", "rival.co.uk", "d_b1", 50]]) {
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?,?)").run(ws, domId);
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, created_at) VALUES (?,?,?, 'completed', ?, datetime('now','-1 day'))").run(`sc_${ws}`, domId, dom, score);
}
// Acme (ws_a1): 1 critical finding + this-week changes (2 high, 1 info) + 1 OLD change (must not count).
db.prepare("INSERT INTO findings (id, scan_id, severity, title) VALUES ('f1','sc_ws_a1','critical','HTTPS not available')").run();
let ev = 0;
const seedEvent = (ws, sev, age) => db.prepare(`INSERT INTO asset_events (id, workspace_id, domain_id, event_type, hostname, severity, description, created_at) VALUES (?,?, 'd', 'exposed_service_detected', 'x', ?, 'd', datetime('now', ?))`).run(`e${++ev}`, ws, sev, age);
seedEvent("ws_a1", "high", "-1 day");
seedEvent("ws_a1", "high", "-2 days");
seedEvent("ws_a1", "info", "-3 days");
seedEvent("ws_a1", "critical", "-40 days"); // outside 7-day window
seedEvent("ws_b1", "high", "-1 day");        // B's change — must never appear for A

// Session for MSP A.
const TOKEN = "tok_msp_a";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKEN));

const env = { cybermeters_db: makeD1(db), cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) }, ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test" };
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const get = async (p, token) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return { status: res.status, body };
};

// ── 1. Unit: helper computes change counts + ranking ─────────────────────────
const rows = await computePortfolioCustomerRows(makeD1(db), ["ws_a1", "ws_a2"]);
const acme = rows.find((r) => r.workspace_id === "ws_a1");
const beta = rows.find((r) => r.workspace_id === "ws_a2");
ok("this-week change count excludes >7d events", acme.changes_7d === 3);
ok("this-week HIGH change count is correct", acme.changes_7d_high === 2);
ok("clean customer has zero recent changes", beta.changes_7d === 0);
ok("risk rating derives from score (Acme 30 → Critical)", acme.risk_rating === "Critical");
ok("risk rating (Beta 92 → Low)", beta.risk_rating === "Low");
ok("attention ranking puts the at-risk customer first", rows[0].workspace_id === "ws_a1");
ok("critical finding surfaced in the row", acme.critical_findings === 1);

// ── 2. Unit: executive summary aggregates ────────────────────────────────────
const exec = buildExecutiveSummary(rows);
ok("exec summary counts customers", exec.portfolio.customers === 2);
ok("exec summary risk distribution", exec.portfolio.distribution.Critical === 1 && exec.portfolio.distribution.Low === 1);
ok("exec summary sums high changes this week", exec.portfolio.high_changes_7d === 2);
ok("exec summary flags customers needing attention", exec.portfolio.customers_needing_attention >= 1);
ok("exec summary top_attention leads with the riskiest", exec.top_attention[0]?.workspace_id === "ws_a1");
ok("exec summary narrative names the lead customer", exec.executive_summary.includes("Acme"));

// ── 3. Integration: cross-MSP isolation over the REAL endpoints ──────────────
const wsResp = await get("/api/portfolio/workspaces", TOKEN);
ok("workspaces endpoint authorised (200)", wsResp.status === 200);
const ids = (wsResp.body.workspaces || []).map((w) => w.workspace_id);
ok("MSP A sees exactly their 2 customers", ids.length === 2 && ids.includes("ws_a1") && ids.includes("ws_a2"));
ok("MSP A NEVER sees MSP B's customer (isolation)", !ids.includes("ws_b1"));

const execResp = await get("/api/portfolio/executive-summary", TOKEN);
ok("exec-summary endpoint authorised (200)", execResp.status === 200);
ok("exec-summary scoped to MSP A (2 customers, not 3)", execResp.body.portfolio?.customers === 2);
ok("exec-summary excludes B's high change (2 high, not 3)", execResp.body.portfolio?.high_changes_7d === 2);

const ovResp = await get("/api/portfolio/overview", TOKEN);
ok("overview scoped to MSP A (2 workspaces)", ovResp.body.total_workspaces === 2);

// Unauthenticated is rejected.
ok("portfolio endpoints require auth (401)", (await get("/api/portfolio/workspaces")).status === 401);

console.log(`\nPortfolio: ${pass}/${pass + fail} passed`);
if (fail) { console.error("portfolio validation FAILED"); process.exit(1); }
console.log("portfolio validation passed");
