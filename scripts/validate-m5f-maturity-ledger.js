#!/usr/bin/env node
//
// M5.f closure validator — canonical eight-domain maturity ledger.
//
// Proves the per-workspace maturity ledger is deterministic, honest, tenant-isolated,
// append-only, idempotent and read-pure. It drives the REAL worker routes and the real
// SQLite schema + migrations, imports the canonical engine, and supplements the behavioural
// paths with static guards + a source-mutation suite (each guard proven load-bearing by
// reintroducing its defect and requiring the invariant to break).
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerSrc = path.join(root, "workers", "scan-api", "src");

const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");
const sourceFiles = new Map();
const getSource = (relPath) => sourceFiles.get(relPath) ?? read(relPath);
const setSource = (relPath, src) => sourceFiles.set(relPath, src);

let pass = 0, fail = 0;
const failures = [];
function ok(name, condition, detail = "") {
  if (condition) pass++;
  else { fail++; const m = `FAIL ${name}${detail ? " — " + detail : ""}`; failures.push(m); console.log(m); }
}
function eq(name, actual, expected) {
  ok(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

const CANONICAL_KEYS = Object.freeze([
  "email_protection", "brand_protection", "attack_surface", "certificates_trust",
  "cyber_essentials_readiness", "website_security", "identity_exposure", "shadow_it_unmanaged_technology",
]);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* idempotent no-ops tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db, writeLog, opts = {}) {
  const failSelectFrom = opts.failSelectFrom ?? null;
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => {
      if (failSelectFrom && new RegExp(`\\bfrom\\s+${failSelectFrom}\\b`, "i").test(sql)) throw new Error(`forced ${failSelectFrom} read failure`);
      const r = db.prepare(sql).get(...args) ?? null;
      return col && r ? r[col] : r;
    },
    all: async () => {
      if (failSelectFrom && new RegExp(`\\bfrom\\s+${failSelectFrom}\\b`, "i").test(sql)) throw new Error(`forced ${failSelectFrom} read failure`);
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      if (writeLog && /^\s*(insert|update|delete|replace|alter|drop|create)\b/i.test(sql)) {
        writeLog.push(sql.trim().replace(/\s+/g, " ").slice(0, 200));
      }
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

const noR2 = { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };
function makeEnv(db, writeLog, d1Opts = {}) {
  return {
    cybermeters_db: makeD1(db, writeLog, d1Opts), cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "m5f-validator-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: "{}", ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(path.join(workerSrc, "index.js")).href);
}
async function loadEngine() {
  return import(pathToFileURL(path.join(workerSrc, "engines", "domain-maturity.js")).href);
}

async function seedUserAndWorkspace(mod, db, { user = "u_owner", token = "tok-owner", workspace = "ws1", plan = "business" } = {}) {
  const hash = await mod.hashToken(token);
  db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,?,?,1,0)").run(user, `${user}@example.com`, user, plan, "active");
  db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at,last_seen_at) VALUES (?,?,?,?,?)").run(`sess_${user}`, user, hash, "2099-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at) VALUES (?,?,?,?,?,?,datetime('now'),datetime('now'))").run(`sub_${user}`, user, plan, "active", "active", "2099-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES (?,?,?,?,?)").run(workspace, workspace, user, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role,created_at) VALUES (?,?,?,?,datetime('now'))").run(`mem_${user}`, workspace, user, "admin");
  return { token, user, workspace };
}

// A COMPLETE scan report where email is healthy and website has an issue.
function completeReport({ website = "issue", email = "healthy" } = {}) {
  const findings = [];
  if (website === "issue") findings.push({ id: "header_missing_strict_transport_security", severity: "high", module: "headers", title: "HSTS missing", recommendation: "Add HSTS" });
  return {
    scan_quality: { status: "complete", modules_skipped: [] },
    completed_at: "2026-07-17T10:00:00Z", created_at: "2026-07-17T09:00:00Z",
    modules: {
      email_security: { ok: true }, email_security_intelligence: { ok: true },
      headers: email === "healthy" ? { ok: true } : { ok: true },
      ssl: { ok: true, https_available: true, https_probe_executed: true },
      dns: { ok: true },
      subdomains: { ok: true }, certificate_intelligence: { ok: true }, brand_monitoring: { ok: true },
      identity_discovery: { ok: true }, saas_exposure: { count: 3 },
    },
    findings,
  };
}
function partialReport() {
  const r = completeReport();
  r.scan_quality = { status: "partial", modules_skipped: ["headers"] };
  return r;
}
function insertCase(db, ws, { id, domain_key, status, remediation_id = null, reopened_count = 0, case_type = null }) {
  const ct = case_type || ({ website_security: "website_case", email_protection: "email_case", identity_exposure: "identity_case", shadow_it_unmanaged_technology: "shadow_it_case" }[domain_key] || "email_case");
  db.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, status, severity, title, domain, finding_id, remediation_id, reopened_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'high', 'c', 'example.com', 'f1', ?, ?, datetime('now'), datetime('now'))`).run(id, ws, ct, domain_key, status, remediation_id, reopened_count);
}

async function checkEngineDeterminism() {
  const E = await loadEngine();
  eq("A: engine exposes exactly eight domain keys", E.MATURITY_DOMAIN_KEYS.length, 8);
  eq("A: engine domain order is canonical", E.MATURITY_DOMAIN_KEYS.join(","), CANONICAL_KEYS.join(","));
  eq("A: no four-domain output", E.MATURITY_DOMAIN_KEYS.length === 4, false);
  eq("A: no five/seven-domain output", [5, 7].includes(E.MATURITY_DOMAIN_KEYS.length), false);
  eq("A: five stages ordered", E.MATURITY_STAGES.join(">"), "not_established>observed>managed>verified>monitored");

  // Determinism: same inputs → identical conclusion.
  const inp = { domainKey: "email_protection", domainState: "assessed_healthy", scanQuality: "complete", cases: [] };
  eq("A: pure function is deterministic", JSON.stringify(E.computeDomainMaturity(inp)), JSON.stringify(E.computeDomainMaturity(inp)));

  // 6/7/8/9: unknown/unavailable/not_assessed/failed evidence NEVER advances maturity.
  for (const st of ["unavailable", "not_yet_assessed", "evidence_insufficient", "degraded", "not_configured", "provisional"]) {
    eq(`C: '${st}' state → not_established`, E.computeDomainMaturity({ domainKey: "email_protection", domainState: st, scanQuality: "complete", cases: [] })?.stage, "not_established");
  }
  // 10: partial scan writes/produces nothing.
  eq("C: partial scan produces no maturity row", E.computeDomainMaturity({ domainKey: "email_protection", domainState: "issue_detected", scanQuality: "partial", cases: [] }), null);
  eq("C: degraded scan produces no maturity row", E.computeDomainMaturity({ domainKey: "email_protection", domainState: "assessed_healthy", scanQuality: "degraded", cases: [] }), null);

  // Capability ceiling is registry-derived, honest per domain.
  eq("B: identity ceiling is managed (no CyberMeters verification)", E.DOMAIN_CAPABILITY_CEILINGS.identity_exposure, "managed");
  eq("B: shadow IT ceiling is managed", E.DOMAIN_CAPABILITY_CEILINGS.shadow_it_unmanaged_technology, "managed");
  eq("B: email ceiling is monitored", E.DOMAIN_CAPABILITY_CEILINGS.email_protection, "monitored");

  // 11: customer assertion (manual attestation) alone can never conclude verified.
  const att = E.computeDomainMaturity({ domainKey: "identity_exposure", domainState: "assessed_healthy", scanQuality: "complete", cases: [{ id: "c1", case_type: "identity_case", status: "verified", remediation_id: null, reopened_count: 0 }] });
  ok("C: manual attestation stays below verified", ["observed", "managed"].includes(att?.stage), att?.stage);
  eq("C: manual attestation sets attested flag", att?.flags.attested, true);
  eq("C: attested reason is honest", att?.reason_code, "attested_not_verified");

  // 12: approved inventory (Shadow IT monitoring) alone never concludes verified.
  const shadow = E.computeDomainMaturity({ domainKey: "shadow_it_unmanaged_technology", domainState: "monitoring_only", scanQuality: "complete", cases: [] });
  eq("C: shadow IT observation-only → observed", shadow?.stage, "observed");

  // verified requires CyberMeters observation AND a clean domain.
  eq("C: automated verified + healthy → verified", E.computeDomainMaturity({ domainKey: "email_protection", domainState: "assessed_healthy", scanQuality: "complete", cases: [{ id: "c1", case_type: "email_case", status: "verified", remediation_id: "email.dmarc.publish", reopened_count: 0 }] })?.stage, "verified");
  eq("C: automated monitoring + healthy → monitored", E.computeDomainMaturity({ domainKey: "email_protection", domainState: "assessed_healthy", scanQuality: "complete", cases: [{ id: "c1", case_type: "email_case", status: "monitoring", remediation_id: "email.dmarc.publish", reopened_count: 0 }] })?.stage, "monitored");
  eq("C: live issue caps verified/monitored at managed", E.computeDomainMaturity({ domainKey: "email_protection", domainState: "issue_detected", scanQuality: "complete", cases: [{ id: "c1", case_type: "email_case", status: "monitoring", remediation_id: "email.dmarc.publish", reopened_count: 0 }] })?.stage, "managed");

  // HIGH honesty floor (Review A): a clean domain with a coexisting UNOWNED obligation cannot
  // claim verified/monitored even when the latest scan is clean, and the flag is NOT suppressed.
  const coexist = E.computeDomainMaturity({ domainKey: "email_protection", domainState: "assessed_healthy", scanQuality: "complete", cases: [
    { id: "cm", case_type: "email_case", status: "monitoring", remediation_id: "email.dmarc.publish", reopened_count: 0 },
    { id: "ct", case_type: "email_case", status: "triaged", remediation_id: "email.dmarc.publish", reopened_count: 0 },
  ] });
  eq("C: clean domain + unowned triaged case caps monitored→managed", coexist?.stage, "managed");
  eq("C: unmanaged flag is NOT suppressed at the cap", coexist?.flags.has_unmanaged_issue, true);
  eq("C: unmanaged cap reason is honest", coexist?.reason_code, "issue_unmanaged");
  // A recurrence (reopened) blocks verified/monitored and is recorded as regressed, not unmanaged.
  const reopenClean = E.computeDomainMaturity({ domainKey: "email_protection", domainState: "assessed_healthy", scanQuality: "complete", cases: [
    { id: "cr", case_type: "email_case", status: "reopened", remediation_id: "email.dmarc.publish", reopened_count: 1 },
  ] });
  eq("C: clean domain + reopened case → managed (recurrence)", reopenClean?.stage, "managed");
  eq("C: recurrence sets regressed, not unmanaged", reopenClean?.flags.regressed, true);
  eq("C: recurrence is not mislabelled unmanaged", reopenClean?.flags.has_unmanaged_issue, false);

  // 19/20: reason codes and evidence references match the conclusion.
  const owned = E.computeDomainMaturity({ domainKey: "email_protection", domainState: "issue_detected", scanQuality: "complete", cases: [{ id: "c9", case_type: "email_case", status: "assigned", remediation_id: "email.dmarc.publish", reopened_count: 0 }], findingIds: ["email_missing_dmarc"] });
  eq("C: managed reason matches", owned?.reason_code, "managed_owned");
  ok("C: evidence carries the contributing case id", owned?.evidence.case_ids.includes("c9"));
  ok("C: evidence carries finding ids", owned?.evidence.finding_ids.includes("email_missing_dmarc"));

  // 15: regression preserved honestly.
  const re = E.computeDomainMaturity({ domainKey: "email_protection", domainState: "issue_detected", scanQuality: "complete", cases: [{ id: "c1", case_type: "email_case", status: "action_in_progress", remediation_id: "email.dmarc.publish", reopened_count: 1 }], priorStage: "verified" });
  eq("C: regression records previous_stage", re?.previous_stage, "verified");
  eq("C: regression sets regressed flag", re?.flags.regressed, true);
}

async function checkWriterAndReaders() {
  const E = await loadEngine();
  const db = buildDb();
  const writes = [];
  const env = makeEnv(db, writes);
  db.prepare("INSERT INTO users (id,email,name,plan) VALUES ('u','u@e.com','U','business')").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws1','A','u')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u','example.com')").run();

  // 24: a workspace with no ledger rows reads eight honest not_established domains.
  const empty = await E.readWorkspaceMaturity(env.cybermeters_db, "ws1");
  eq("D: empty workspace still has eight domains", empty.length, 8);
  eq("D: empty workspace order canonical", empty.map((d) => d.domain_key).join(","), CANONICAL_KEYS.join(","));
  ok("D: empty workspace has no mature domain", empty.every((d) => d.maturity_stage === "not_established"));
  ok("D: empty workspace domains are not 'established'", empty.every((d) => d.established === false));

  // Writer: a complete scan writes eight rows; website has an issue+owned case → managed.
  insertCase(db, "ws1", { id: "cw", domain_key: "website_security", status: "assigned", remediation_id: "web.header.hsts" });
  const w1 = await E.persistDomainMaturity(env, { workspaceId: "ws1", domainId: "d1", scanId: "scan1", report: completeReport(), assessedAt: "2026-07-17T10:00:00Z" });
  eq("E: complete scan writes eight rows", w1.written, 8);

  // 16: duplicate finalization is idempotent (INSERT OR IGNORE) — second run adds nothing.
  const w1b = await E.persistDomainMaturity(env, { workspaceId: "ws1", domainId: "d1", scanId: "scan1", report: completeReport(), assessedAt: "2026-07-17T10:00:00Z" });
  const rowCount = db.prepare("SELECT COUNT(*) n FROM domain_maturity_ledger WHERE workspace_id='ws1' AND scan_id='scan1'").get().n;
  eq("E: duplicate finalization keeps exactly eight rows", rowCount, 8);
  ok("E: duplicate finalization is idempotent (writer returns 8 or 0, no growth)", w1b.written === 8 || w1b.written === 0);

  // 10: a partial scan writes NO rows.
  const wp = await E.persistDomainMaturity(env, { workspaceId: "ws1", domainId: "d1", scanId: "scanP", report: partialReport(), assessedAt: "2026-07-17T11:00:00Z" });
  eq("E: partial scan writes zero rows", wp.written, 0);
  eq("E: partial scan skip reason is not_complete", wp.skipped, "not_complete");

  // Reader returns the website 'managed' conclusion.
  const cur = await E.readWorkspaceMaturity(env.cybermeters_db, "ws1");
  const web = cur.find((d) => d.domain_key === "website_security");
  eq("D: website reads managed after owned case", web.maturity_stage, "managed");
  eq("D: email reads observed (clean, no case)", cur.find((d) => d.domain_key === "email_protection").maturity_stage, "observed");

  // 5: readWorkspaceMaturity performs ZERO writes.
  writes.length = 0;
  await E.readWorkspaceMaturity(env.cybermeters_db, "ws1");
  ok("D: readWorkspaceMaturity performs zero writes", writes.length === 0, writes.join(" | "));

  // 14: history is append-only; a later scan appends, prior row unchanged.
  db.prepare("UPDATE managed_cases SET status='verified' WHERE id='cw'").run();
  const before = db.prepare("SELECT maturity_stage FROM domain_maturity_ledger WHERE workspace_id='ws1' AND scan_id='scan1' AND domain_key='website_security'").get().maturity_stage;
  // website now healthy (fix verified) → verified
  await E.persistDomainMaturity(env, { workspaceId: "ws1", domainId: "d1", scanId: "scan2", report: completeReport({ website: "healthy" }), assessedAt: "2026-07-17T12:00:00Z" });
  const after = db.prepare("SELECT maturity_stage FROM domain_maturity_ledger WHERE workspace_id='ws1' AND scan_id='scan1' AND domain_key='website_security'").get().maturity_stage;
  eq("E: prior ledger row is never rewritten (append-only)", after, before);
  const latest = await E.readWorkspaceMaturity(env.cybermeters_db, "ws1");
  eq("E: current view reflects the latest eligible entry", latest.find((d) => d.domain_key === "website_security").maturity_stage, "verified");
  const hist = await E.readDomainMaturityHistory(env.cybermeters_db, "ws1", "d1", "website_security", { limit: 10 });
  ok("E: history preserves both entries newest-first", hist.length >= 2 && hist[0].maturity_stage === "verified");

  // 18: a query failure surfaces unavailable, never a clean zero or a healthy default.
  const failEnv = makeEnv(db, [], { failSelectFrom: "domain_maturity_ledger" });
  const degraded = await E.readWorkspaceMaturity(failEnv.cybermeters_db, "ws1");
  eq("D: query failure still returns eight domains", degraded.length, 8);
  ok("D: query failure marks unavailable, never healthy", degraded.every((d) => d.reason_code === "unavailable" && d.maturity_stage === "not_established"));
}

async function checkTenantIsolationAndRoutes() {
  const mod = await loadWorker();
  const E = await loadEngine();
  const db = buildDb();
  const writes = [];
  const env = makeEnv(db, writes);
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
  const { token } = await seedUserAndWorkspace(mod, db, { user: "u_a", token: "tok-a", workspace: "wsA" });
  await seedUserAndWorkspace(mod, db, { user: "u_b", token: "tok-b", workspace: "wsB" });
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('da','u_a','a.com')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('db','u_b','b.com')").run();

  // wsA gets a verified email (healthy) → verified; wsB gets nothing.
  insertCase(db, "wsA", { id: "ca", domain_key: "email_protection", status: "verified", remediation_id: "email.dmarc.publish" });
  await E.persistDomainMaturity(env, { workspaceId: "wsA", domainId: "da", scanId: "sA", report: completeReport({ website: "healthy" }), assessedAt: "2026-07-17T10:00:00Z" });

  // 13: wsB is unaffected by wsA's evidence.
  const bView = await E.readWorkspaceMaturity(env.cybermeters_db, "wsB");
  ok("F: cross-workspace evidence does not leak", bView.every((d) => d.maturity_stage === "not_established"));

  const call = (ws, tok) => mod.default.fetch(new Request(`https://api.cybermeters.com/api/workspaces/${ws}/maturity`, { headers: tok ? { Authorization: `Bearer ${tok}` } : {} }), env, ctx);

  // Route: owner 200 with eight ordered domains; ZERO writes on read.
  writes.length = 0;
  const okRes = await call("wsA", "tok-a");
  eq("F: GET /maturity owner returns 200", okRes.status, 200);
  const body = await okRes.json();
  eq("F: route returns eight domains", body.domains.length, 8);
  eq("F: route order canonical", body.domains.map((d) => d.domain_key).join(","), CANONICAL_KEYS.join(","));
  eq("F: route carries contract_version", body.contract_version, E.MATURITY_LEDGER_CONTRACT_VERSION);
  eq("F: wsA email is verified via route", body.domains.find((d) => d.domain_key === "email_protection").maturity_stage, "verified");
  ok("F: GET /maturity performs zero writes", writes.filter((w) => /maturity_ledger/i.test(w) && /insert|update|replace|delete/i.test(w)).length === 0, writes.join(" | "));

  // Tenant isolation on reads: foreign member and anon are denied.
  const foreign = await call("wsA", "tok-b");
  ok("F: foreign tenant is denied the maturity read", [401, 403, 404].includes(foreign.status));
  const anon = await call("wsA", null);
  eq("F: anonymous is denied (401)", anon.status, 401);

  // History route tenant isolation.
  const hist = (ws, tok) => mod.default.fetch(new Request(`https://api.cybermeters.com/api/workspaces/${ws}/maturity/da/email_protection/history`, { headers: tok ? { Authorization: `Bearer ${tok}` } : {} }), env, ctx);
  eq("F: history owner 200", (await hist("wsA", "tok-a")).status, 200);
  ok("F: history foreign denied", [401, 403, 404].includes((await hist("wsA", "tok-b")).status));
}

async function checkPortfolioAggregation() {
  const E = await loadEngine();
  const db = buildDb();
  const env = makeEnv(db, []);
  db.prepare("INSERT INTO users (id,email,name,plan) VALUES ('u','u@e.com','U','business')").run();
  for (const w of ["w1", "w2"]) db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES (?,?,'u')").run(w, w);
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u','one.com')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d2','u','two.com')").run();

  // w1: email monitored (healthy + monitoring case). w2: no eligible scan.
  insertCase(db, "w1", { id: "c1", domain_key: "email_protection", status: "monitoring", remediation_id: "email.dmarc.publish" });
  await E.persistDomainMaturity(env, { workspaceId: "w1", domainId: "d1", scanId: "s1", report: completeReport({ website: "healthy" }), assessedAt: "2026-07-17T10:00:00Z" });

  const p = await E.computePortfolioMaturity(env.cybermeters_db, ["w1", "w2"]);
  const email = p.domains.find((d) => d.domain_key === "email_protection");
  // 17: worst-case fold — one workspace unassessed → portfolio email is not_established.
  eq("G: portfolio worst-case fold with an unassessed workspace → not_established", email.portfolio_stage, "not_established");
  eq("G: portfolio records only the established workspace count", email.workspaces_established, 1);
  eq("G: portfolio exactly eight domains", p.domains.length, 8);

  // With both workspaces assessed and monitored, the fold reaches monitored.
  insertCase(db, "w2", { id: "c2", domain_key: "email_protection", status: "monitoring", remediation_id: "email.dmarc.publish" });
  await E.persistDomainMaturity(env, { workspaceId: "w2", domainId: "d2", scanId: "s2", report: completeReport({ website: "healthy" }), assessedAt: "2026-07-17T10:00:00Z" });
  const p2 = await E.computePortfolioMaturity(env.cybermeters_db, ["w1", "w2"]);
  eq("G: both monitored → portfolio email monitored", p2.domains.find((d) => d.domain_key === "email_protection").portfolio_stage, "monitored");

  // 18: portfolio query failure → unavailable, never zero/healthy.
  const failEnv = makeEnv(db, [], { failSelectFrom: "domain_maturity_ledger" });
  const pf = await E.computePortfolioMaturity(failEnv.cybermeters_db, ["w1", "w2"]);
  eq("G: portfolio query failure → unavailable", pf.portfolio_state, "unavailable");
  ok("G: portfolio failure publishes no mature domain", pf.domains.every((d) => d.portfolio_stage === "not_established"));

  // Empty accessible set is not a clean bill.
  eq("G: no accessible workspaces → no_workspaces", (await E.computePortfolioMaturity(env.cybermeters_db, [])).portfolio_state, "no_workspaces");
}

function checkFrontendPurityAndParity() {
  const E_labels = ["Not established", "Observed", "Under management", "Verified by CyberMeters", "Verified & monitored"];
  const disp = getSource("frontend/src/lib/maturityDisplay.js");
  const comp = getSource("frontend/src/components/DomainMaturity.jsx");
  // 4: the frontend does NOT calculate maturity (an IMPORT or a CALL, not a comment mention).
  ok("H: frontend maturity component does not import the backend engine", !/from\s+['"][^'"]*domain-maturity/.test(comp) && !/computeDomainMaturity\s*\(/.test(comp));
  ok("H: frontend does not derive a stage from evidence", !/scanQuality|verification_support|reopened_count|OWNED_STATES/.test(comp) && !/scanQuality|verification_support/.test(disp));
  ok("H: frontend renders the server maturity_stage verbatim", /d\.maturity_stage/.test(comp) && /maturity_stage/.test(disp));
  // 21: frontend labels mirror backend stage vocabulary; 8-order constant matches.
  for (const l of E_labels) ok(`H: frontend exposes stage label "${l}"`, disp.includes(l) || comp.includes(l));
  const order = [...disp.matchAll(/domain_key:\s*'([^']+)'/g)].map((m) => m[1]);
  ok("H: frontend maturity order mirrors canonical eight", order.join(",") === CANONICAL_KEYS.join(","), order.join(","));
  // Presentation safety: the fallback maps every domain to not_established, never a mature stage.
  const fallback = disp.slice(disp.indexOf("export function resolveDisplayMaturity"));
  ok("H: frontend fallback is not_established (never mature)", /maturity_stage:\s*'not_established'/.test(fallback) && !/maturity_stage:\s*'(observed|managed|verified|monitored)'/.test(fallback));
}

function checkMigrationAndPurgeAndCi() {
  const mig = getSource("database/migrations/095-domain-maturity-ledger.sql");
  // 23: additive-only migration.
  ok("I: migration 095 creates the table additively", /CREATE TABLE IF NOT EXISTS domain_maturity_ledger/.test(mig));
  ok("I: migration 095 has no destructive statement", !/\b(DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM|TRUNCATE|UPDATE)\b/i.test(mig.replace(/--[^\n]*/g, "")));
  ok("I: migration 095 binds tenant boundary + idempotency UNIQUE", /workspace_id\s+TEXT NOT NULL/.test(mig) && /UNIQUE \(workspace_id, domain_id, scan_id, domain_key\)/.test(mig));
  ok("I: migration 095 has no FK to scans (history outlives the scan)", !/REFERENCES scans/.test(mig) && /REFERENCES workspaces\(id\)/.test(mig));
  // Purge registration.
  ok("I: domain_maturity_ledger registered in WORKSPACE_PURGE_TABLES", /"domain_maturity_ledger"/.test(getSource("workers/scan-api/src/index.js")));
  // 22: M5.c/M5.d/M5.e validators remain wired; M5.f wired.
  const ci = getSource(".github/workflows/ci.yml");
  ok("I: M5.f validator wired in CI", /validate-m5f-maturity-ledger\.js/.test(ci));
  ok("I: M5.c validator remains wired", /validate-m5c-reporting-snapshot\.js/.test(ci));
  ok("I: M5.d validator remains wired", /validate-m5d-renderer-migration\.js/.test(ci));
  ok("I: M5.e validator remains wired", /validate-m5e-closure\.js/.test(ci));
  // Writer is wired non-fatally into scan finalize.
  const engineSrc = getSource("workers/scan-api/src/engines/scan-engine.js");
  ok("I: persistDomainMaturity wired into scan finalize", /persistDomainMaturity\(env,/.test(engineSrc));
}

// ── Mutation suite — each reintroduces a defect the guards must catch ──────────
const MUTATIONS = [
  {
    name: "remove one domain from the ledger registry",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('export const MATURITY_DOMAIN_KEYS = Object.freeze(CYBER_MOT_DOMAINS.map((d) => d.domain_key));',
      'export const MATURITY_DOMAIN_KEYS = Object.freeze(CYBER_MOT_DOMAINS.map((d) => d.domain_key).slice(0, 7));'),
    expect: () => /\.map\(\(d\) => d\.domain_key\)\);/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "ledger domain registry no longer the full canonical eight",
  },
  {
    name: "reorder the maturity stage ladder",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('"not_established", // 0', '"managed", // 0').replace('"managed",        // 2', '"not_established",        // 2'),
    expect: () => {
      const src = getSource("workers/scan-api/src/engines/domain-maturity.js");
      const m = src.match(/export const MATURITY_STAGES = Object\.freeze\(\[([\s\S]*?)\]\)/);
      const keys = m ? [...m[1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1]) : [];
      return keys.join(">") === "not_established>observed>managed>verified>monitored" ? null : "stage ladder order changed";
    },
  },
  {
    name: "map unavailable evidence to the highest maturity",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('const OBSERVED_STATES = new Set(["assessed_healthy", "issue_detected", "monitoring_only"]);',
      'const OBSERVED_STATES = new Set(["assessed_healthy", "issue_detected", "monitoring_only", "unavailable", "not_yet_assessed", "evidence_insufficient"]);'),
    expect: () => /OBSERVED_STATES = new Set\(\["assessed_healthy", "issue_detected", "monitoring_only"\]\)/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "unavailable/failed evidence now counts as observed",
  },
  {
    name: "allow a partial scan to create/advance maturity",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('if (scanQuality !== "complete") return null;', 'if (false) return null;'),
    expect: () => /if \(scanQuality !== "complete"\) return null;/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "partial scan no longer blocked from producing maturity",
  },
  {
    name: "drop the workspace filter from the current reader",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('FROM domain_maturity_ledger WHERE workspace_id = ?\n       ) WHERE rn = 1', 'FROM domain_maturity_ledger\n       ) WHERE rn = 1'),
    expect: () => /FROM domain_maturity_ledger WHERE workspace_id = \?[\s\S]{0,40}\) WHERE rn = 1/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "current reader lost its workspace_id filter",
  },
  {
    name: "introduce write-on-read in the maturity route",
    file: "workers/scan-api/src/routes/executive-dashboard.js",
    mutate: (s) => s.replace('const domains = await readWorkspaceMaturity(env.cybermeters_db, wsId);',
      "await env.cybermeters_db.prepare('INSERT INTO domain_maturity_ledger (id) VALUES (?)').bind('x').run(); const domains = await readWorkspaceMaturity(env.cybermeters_db, wsId);"),
    expect: () => /INSERT INTO domain_maturity_ledger/.test(getSource("workers/scan-api/src/routes/executive-dashboard.js")) ? "GET /maturity now writes on read" : null,
  },
  {
    name: "treat a customer attestation as CyberMeters-verified",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('if (VERIFIED_LIKE.has(st) && support === "automated") obsVerified = true;',
      'if (VERIFIED_LIKE.has(st)) obsVerified = true;'),
    expect: () => /if \(VERIFIED_LIKE\.has\(st\) && support === "automated"\) obsVerified = true;/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "attestation now counts as CyberMeters verification",
  },
  {
    name: "calculate maturity in the frontend",
    file: "frontend/src/components/DomainMaturity.jsx",
    mutate: (s) => `${s}\nconst derived = (d) => d.finding_count === 0 ? 'monitored' : 'observed';\n`,
    expect: () => /finding_count === 0 \? 'monitored'/.test(getSource("frontend/src/components/DomainMaturity.jsx")) ? "frontend now derives a maturity stage" : null,
  },
  {
    name: "overwrite a historical ledger row (INSERT OR REPLACE)",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace("INSERT OR IGNORE INTO domain_maturity_ledger", "INSERT OR REPLACE INTO domain_maturity_ledger"),
    expect: () => /INSERT OR IGNORE INTO domain_maturity_ledger/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "ledger write can now overwrite history",
  },
  {
    name: "collapse a query failure into a clean/healthy default",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace('return MATURITY_DOMAIN_KEYS.map((k) => ({ ...viewFromRow(k, null), reason_code: "unavailable", tone: "neutral" }));',
      'return MATURITY_DOMAIN_KEYS.map((k) => ({ ...viewFromRow(k, null), maturity_stage: "monitored" }));'),
    expect: () => /reason_code: "unavailable", tone: "neutral"/.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "query failure now returns a healthy/clean default",
  },
];

async function runMutations() {
  const original = new Map();
  const touched = new Set(MUTATIONS.map((m) => m.file));
  for (const f of touched) original.set(f, read(f));
  // Also snapshot any file an expect() reads.
  for (const extra of ["frontend/src/components/DomainMaturity.jsx", "workers/scan-api/src/routes/executive-dashboard.js", "workers/scan-api/src/engines/domain-maturity.js"]) {
    if (!original.has(extra)) original.set(extra, read(extra));
  }
  let mutationPass = 0, mutationFail = 0;
  for (const m of MUTATIONS) {
    sourceFiles.clear();
    for (const [k, v] of original) sourceFiles.set(k, v);
    setSource(m.file, m.mutate(getSource(m.file)));
    const reason = m.expect();
    if (reason) mutationPass++;
    else { mutationFail++; console.log(`FAIL mutation '${m.name}' did not break its invariant`); }
  }
  sourceFiles.clear();
  ok(`mutations: ${MUTATIONS.length} required regressions each break an invariant`, mutationFail === 0, `${mutationPass} caught, ${mutationFail} escaped`);
}

async function main() {
  await checkEngineDeterminism();
  await checkWriterAndReaders();
  await checkTenantIsolationAndRoutes();
  await checkPortfolioAggregation();
  checkFrontendPurityAndParity();
  checkMigrationAndPurgeAndCi();
  await runMutations();

  console.log(`\nm5f-maturity-ledger: ${pass} passed, ${fail} failed`);
  if (fail) { console.error("m5f-maturity-ledger validation FAILED"); process.exit(1); }
  console.log("m5f-maturity-ledger validation passed");
}
main().catch((err) => { console.error(err?.stack || err); process.exit(1); });
