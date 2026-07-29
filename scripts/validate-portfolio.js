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
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, scan_quality, created_at) VALUES (?,?,?, 'completed', ?, 'complete', datetime('now','-1 day'))").run(`sc_${ws}`, domId, dom, score);
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

// ── Entitlement: portfolio is a Business+/MSP feature (portfolio_monitoring). ──
// MSP A is on Business (entitled → reaches all six endpoints). Everyone else has
// no subscription row → getUserPlan() = free (NOT entitled → 403 on all six).
db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end) VALUES ('sub_a','u_a','business','active', datetime('now','+30 days'))").run();

// An ordinary un-entitled (free) customer with their own workspace + session.
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_free','free@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_free','Free Co','u_free')").run();
db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ('ws_free','u_free','owner')").run();
const TOKEN_FREE = "tok_free";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_free','u_free',?, datetime('now','+1 day'))").run(await hashToken(TOKEN_FREE));

// ── Latest-scan determinism fixtures (owner u_c; tested via the unit helper with
// explicit workspace ids so MSP A's customer count stays 2). ──
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_c','c@example.co.uk',1)").run();
// (a) Historical exclusion: an OLDER completed scan carries a critical that a NEWER
//     completed scan resolved — the old critical must NOT be counted as current.
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_hist','Hist Co','u_c')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_hist','d_hist')").run();
db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, scan_quality, created_at) VALUES ('sc_hist_old','d_hist','hist.co.uk','completed',40,'complete', datetime('now','-10 days'))").run();
db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, scan_quality, created_at) VALUES ('sc_hist_new','d_hist','hist.co.uk','completed',90,'complete', datetime('now','-1 day'))").run();
db.prepare("INSERT INTO findings (id, scan_id, severity, title) VALUES ('fh_old','sc_hist_old','critical','OLD HTTPS crit (resolved)')").run();
// (b) Identical-timestamp dedup: TWO completed scans with the SAME created_at, each
//     carrying a critical — the domain must count ONCE (the deterministic winner),
//     not twice. Under the old MAX(created_at) join both matched → double count.
const DUP_TS = "2026-07-14 12:00:00";
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_dup','Dup Co','u_c')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_dup','d_dup')").run();
db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, scan_quality, created_at) VALUES ('sc_dup_a','d_dup','dup.co.uk','completed',55,'complete',?)").run(DUP_TS);
db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, scan_quality, created_at) VALUES ('sc_dup_b','d_dup','dup.co.uk','completed',55,'complete',?)").run(DUP_TS);
db.prepare("INSERT INTO findings (id, scan_id, severity, title) VALUES ('fd_a','sc_dup_a','critical','dup crit A')").run();
db.prepare("INSERT INTO findings (id, scan_id, severity, title) VALUES ('fd_b','sc_dup_b','critical','dup crit B')").run();

// ── MSP D: entitled, 2 customers onboarded, ZERO assessments ─────────────────
// The fixture #117/#118 never had on this engine. Everything above is seeded WITH a
// score, so every assertion here passed against code that fabricated an all-clear
// from an empty portfolio. An unassessed customer is the whole defect: it is the
// state an MSP is in on day one, and it is the state the old summary called safe.
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_d','d@example.co.uk',1)").run();
db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end) VALUES ('sub_d','u_d','business','active', datetime('now','+30 days'))").run();
for (const [ws, name, domId] of [["ws_d1", "Unseen Ltd", "d_d1"], ["ws_d2", "Unlooked Co", "d_d2"]]) {
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?, 'u_d')").run(ws, name);
  db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, 'u_d', 'owner')").run(ws);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?,?)").run(ws, domId);
}
const TOKEN_D = "tok_msp_d";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_d','u_d',?, datetime('now','+1 day'))").run(await hashToken(TOKEN_D));

// MSP E: entitled, 2 customers, only ONE assessed → the partial mean.
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_e','e@example.co.uk',1)").run();
db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end) VALUES ('sub_e','u_e','business','active', datetime('now','+30 days'))").run();
for (const [ws, name, domId] of [["ws_e1", "Scanned Ltd", "d_e1"], ["ws_e2", "Unscanned Co", "d_e2"]]) {
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?, 'u_e')").run(ws, name);
  db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, 'u_e', 'owner')").run(ws);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?,?)").run(ws, domId);
}
// Only ws_e1 has a completed assessment, and it is a flattering 90.
db.prepare("INSERT INTO scans (id, domain_id, domain, status, score, scan_quality, created_at) VALUES ('sc_e1','d_e1','scanned.co.uk','completed',90,'complete', datetime('now','-1 day'))").run();
const TOKEN_E = "tok_msp_e";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_e','u_e',?, datetime('now','+1 day'))").run(await hashToken(TOKEN_E));

const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: {
    get: async (key) => String(key || "").startsWith("reports/")
      ? { json: async () => ({ modules: {
        cve_intelligence: { executed: true, incomplete: false, evidence_publishable: true },
        known_exploited_vulnerabilities: { executed: true, incomplete: false, evidence_publishable: true },
        email_security_intelligence: { executed: true, incomplete: false, evidence_publishable: true },
      } }) }
      : null,
    put: async () => ({}),
    head: async () => null,
    delete: async () => ({}),
    list: async () => ({ objects: [] }),
  },
  ALLOWED_ORIGIN: "https://app.cybermeters.com",
  APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const get = async (p, token) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return { status: res.status, body };
};

// ── 1. Unit: helper computes change counts + ranking ─────────────────────────
const rows = await computePortfolioCustomerRows(
  makeD1(db),
  ["ws_a1", "ws_a2"],
  { env },
);
const acme = rows.find((r) => r.workspace_id === "ws_a1");
const beta = rows.find((r) => r.workspace_id === "ws_a2");
ok("this-week change count excludes >7d events", acme.changes_7d === 3);
ok("this-week HIGH change count is correct", acme.changes_7d_high === 2);
ok("clean customer has zero recent changes", beta.changes_7d === 0);
// M5.e-C: the rating speaks the CANONICAL band vocabulary (riskLevelForScore).
ok("risk rating derives from the canonical band (Acme 30 → high)", acme.risk_rating === "high");
ok("risk rating (Beta 92 → excellent)", beta.risk_rating === "excellent");
ok("attention ranking puts the at-risk customer first", rows[0].workspace_id === "ws_a1");
ok("critical finding surfaced in the row", acme.critical_findings === 1);

// ── 2. Unit: executive summary aggregates ────────────────────────────────────
const exec = buildExecutiveSummary(rows);
ok("exec summary counts customers", exec.portfolio.customers === 2);
ok("exec summary risk distribution (canonical buckets)", exec.portfolio.distribution.high === 1 && exec.portfolio.distribution.excellent === 1);
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

// ── 4. Entitlement gate — Business+/MSP only, on ALL SIX endpoints ────────────
const PORTFOLIO_ENDPOINTS = [
  "/api/portfolio/overview", "/api/portfolio/workspaces", "/api/portfolio/alerts",
  "/api/portfolio/trends", "/api/portfolio/risk", "/api/portfolio/executive-summary",
];
// Free/Starter/Growth (here: an un-subscribed → free user) is 403 on every endpoint.
for (const p of PORTFOLIO_ENDPOINTS) {
  const r = await get(p, TOKEN_FREE);
  ok(`un-entitled (free) user is 403 on ${p}`, r.status === 403 && r.body.feature === "portfolio_monitoring");
}
// Business/MSP (u_a) reaches every endpoint (never 403).
for (const p of PORTFOLIO_ENDPOINTS) {
  const r = await get(p, TOKEN);
  ok(`entitled MSP (Business) reaches ${p} (200, not 403)`, r.status === 200);
}

// ── 5. Latest-scan determinism (unit helper, explicit ids) ───────────────────
const histRows = await computePortfolioCustomerRows(
  makeD1(db),
  ["ws_hist"],
  { env },
);
ok("historical critical from an older scan is NOT counted as current", histRows[0].critical_findings === 0);
ok("latest completed scan drives the score (90, not the old 40)", histRows[0].latest_score === 90);
const dupRows = await computePortfolioCustomerRows(
  makeD1(db),
  ["ws_dup"],
  { env },
);
ok("identical created_at scans do NOT duplicate the domain (1 critical, not 2)", dupRows[0].critical_findings === 1);

// ── 6. Honesty: a never-scanned customer is shown, not dropped or faked ───────
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_ns','NeverScanned Co','u_c')").run();
const nsRows = await computePortfolioCustomerRows(
  makeD1(db),
  ["ws_ns"],
  { env },
);
ok("never-scanned customer is present (not dropped)", nsRows.length === 1);
ok("never-scanned → null score (honest, not a fake 0)", nsRows[0].latest_score === null && nsRows[0].risk_rating === null);
ok("never-scanned → status inactive", nsRows[0].status === "inactive");

// ── 7. Score honesty on /executive-summary (the #117/#118 contract) ───────────
// #117 and #118 fixed portfolio-risk.js (GET /api/portfolio/risk) and never touched
// portfolio-customers.js, which serves THIS route — so both defects were still live
// here, unguarded, because every fixture above happens to have a score. These drive
// the real endpoint: the bug only exists once something renders.
//
// Words that assert a risk verdict, and the all-clear itself. Deliberately matched as
// a CLASS, not as the one sentence that was there: the wording is not the invariant,
// the silence is. Re-phrasing the all-clear must not slip past this.
const VERDICT_WORDS = /\b(healthy|moderate|elevated|serious)\b/i;
const ALL_CLEAR = /\b(no customers? (currently )?need|none .* need urgent|all clear|no (customer )?(environments?|customers?) (are|is))\b/i;

const noEv = await get("/api/portfolio/executive-summary", TOKEN_D);
const noEvSummary = noEv.body.executive_summary || "";
ok("no-evidence: endpoint authorised (200)", noEv.status === 200);
ok("no-evidence: both customers are counted, not dropped", noEv.body.portfolio?.customers === 2);
ok("no-evidence: avg_score stays null (never a fabricated 0 or 100)", noEv.body.portfolio?.avg_score === null);
ok("no-evidence: state is evidence_insufficient", noEv.body.portfolio?.avg_score_state === "evidence_insufficient");
ok("no-evidence: basis discloses 0 of 2 scored", noEv.body.portfolio?.avg_score_basis?.scored_customers === 0 && noEv.body.portfolio?.avg_score_basis?.total_customers === 2);
ok("no-evidence: a reason says WHY (an unknown without a reason is a shrug)", /not available|cannot be calculated|no completed/i.test(noEv.body.portfolio?.avg_score_reason || ""));
// The two defects, asserted directly.
ok("NO-EVIDENCE NEVER YIELDS AN ALL-CLEAR (#118)", !ALL_CLEAR.test(noEvSummary));
ok("no-evidence: summary asserts no risk verdict (#117)", !VERDICT_WORDS.test(noEvSummary));
ok("no-evidence: NEVER prints —/100, null/100, undefined/100 or NaN/100", !/(—|null|undefined|NaN)\/100/.test(noEvSummary));
ok("no-evidence: summary still says why there is no score", /not available/i.test(noEvSummary));

const partial = await get("/api/portfolio/executive-summary", TOKEN_E);
const partialSummary = partial.body.executive_summary || "";
ok("partial: state is partial", partial.body.portfolio?.avg_score_state === "partial");
ok("partial: the mean is real and keeps its value (90)", partial.body.portfolio?.avg_score === 90);
ok("partial: basis discloses 1 of 2 scored", partial.body.portfolio?.avg_score_basis?.scored_customers === 1 && partial.body.portfolio?.avg_score_basis?.total_customers === 2);
// The partial mean flattering the verdict — 90 drawn from 1 of 2 customers is not a
// portfolio score, and the sentence that gets read has to say so.
ok("PARTIAL DISCLOSES ITS BASIS INLINE (#117)", /1 of 2/.test(partialSummary) && /not represented|no completed assessment/i.test(partialSummary));
// An all-clear is permitted here ONLY if it names its own blind spot.
ok("partial: any all-clear is scoped to the assessed subset",
   !ALL_CLEAR.test(partialSummary) || /not covered by this statement/i.test(partialSummary));

// Positive control: a fully-assessed portfolio MUST still be able to speak. Without
// this, withholding everything unconditionally would pass every assertion above.
const fullSummary = execResp.body.executive_summary || "";
ok("available: a fully-assessed portfolio still prints its real score", /\d+\/100/.test(fullSummary));
ok("available: state is available", execResp.body.portfolio?.avg_score_state === "available");
ok("available: does not claim a partial basis it does not have", !/not represented/i.test(fullSummary));

// Unauthenticated is rejected (before the entitlement gate).
ok("portfolio endpoints require auth (401)", (await get("/api/portfolio/workspaces")).status === 401);

console.log(`\nPortfolio: ${pass}/${pass + fail} passed`);
if (fail) { console.error("portfolio validation FAILED"); process.exit(1); }
console.log("portfolio validation passed");
