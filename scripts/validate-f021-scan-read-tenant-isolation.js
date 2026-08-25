#!/usr/bin/env node
//
// F-021 — scan-read tenant isolation.
//
// THE DEFECT: a shared domain plus a NULL-owner scan authorised FOREIGN scan
// reads. Three distinct leaks existed:
//   1. requireScanReadAccess fell back to a workspace_domains join whenever
//      scans.workspace_id was NULL — so every co-linked tenant could read it.
//   2. GET /api/scans listed NULL-owner scans via the same fallback.
//   3. GET /api/domain/:domain/history filtered on wd.workspace_id with NO
//      condition on s.workspace_id at all — leaking ATTRIBUTED foreign scans,
//      not merely legacy NULL ones. This was the most severe of the three.
//
// NULL means the owner is UNKNOWN. It must never mean "readable by whoever
// shares the domain".
//
// Drives the REAL worker fetch() against a REAL in-memory SQLite with schema +
// migrations applied — same instrument as validate-tenant-isolation.js — with
// ONE domain deliberately linked to TWO workspaces.
//
// R2 is instrumented: every get() is counted by key, so "no R2 read is even
// ATTEMPTED" is asserted as a measured zero, not inferred from the response.
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

// Each scan's R2 object carries a marker unique to its OWNER, so any 2xx that
// echoes a foreign marker is a proven leak rather than a suspicious status code.
const MARK = { scan_ws1: "MARKER-WS1", scan_ws2: "MARKER-WS2", scan_null: "MARKER-NULL" };
const r2Gets = [];
function objFor(id) {
  const m = MARK[id];
  const report = {
    scan_id: id,
    domain: "shared-tenant.com",
    status: "completed",
    modules: {
      leak_probe: m,
      certificate_intelligence: {
        certificate_risk_level: "high",
        certificate_status: "valid",
        issuer: `ISSUER-${m}`,
        subject: "CN=shared-tenant.com",
        total_certificates_seen: 1,
        suspicious_certificate_signals: [],
      },
      saas_exposure: {
        exposures: [{
          name: `SAAS-${m}`, category: "collaboration",
          exposure_type: "saas_tenant", risk_level: "high",
          confidence: "confirmed",
        }],
      },
      cloud_storage_discovery: {
        findings: [{
          asset: `CLOUD-${m}`, provider: `PROVIDER-${m}`,
          category: "storage", service_type: "object_storage",
          evidence: m, risk_level: "high",
        }],
      },
      admin_surface_detection: {
        evidence_status: "issue_detected",
        services: [{
          hostname: `${id}.shared-tenant.com`, product: `ADMIN-${m}`,
          category: "admin_panel", severity: "critical",
          confidence: "confirmed", risk_level: "critical",
        }],
      },
    },
  };
  return {
    json:        async () => report,
    text:        async () => JSON.stringify({ snapshot: { snapshot_schema_version: "1" }, marker: m }),
    arrayBuffer: async () => new TextEncoder().encode(m).buffer,
    body:        m,
  };
}
function makeEnv(db) {
  const r2 = {
    get: async (key) => {
      const k = String(key ?? "");
      r2Gets.push(k);
      for (const id of Object.keys(MARK)) if (k.includes(id)) return objFor(id);
      return null;
    },
    put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }),
  };
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: r2,
    MFA_ENCRYPTION_KEY: "f021-mfa-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

let passed = 0, failed = 0; const results = [];
let section = "General";
function ok(name, cond) {
  if (cond) { passed++; results.push(`PASS [${section}] ${name}`); }
  else      { failed++; results.push(`FAIL [${section}] ${name}`); }
}

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const { hashToken, hashPassword } = mod;
  const db = buildDb();
  const env = makeEnv(db);

  const pw = await hashPassword("Sup3r-secret-pw");
  const seedUser = (id, email) =>
    db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, 'free', 'active', 1, 0)").run(id, email, pw, id);
  const seedSession = async (sid, uid, raw) =>
    db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))").run(sid, uid, await hashToken(raw));

  seedUser("alice", "alice@a.co"); seedUser("bob", "bob@b.co");
  const T = { alice: "raw-alice", bob: "raw-bob" };
  await seedSession("s1", "alice", T.alice);
  await seedSession("s2", "bob", T.bob);

  // Seeding errors are RECORDED, never swallowed. A fixture whose rows failed to
  // insert makes every negative assertion pass vacuously — the "confident zero"
  // failure class. Preconditions are asserted below before any contract check.
  const seedErrors = [];
  const tryRun = (sql, ...a) => {
    try { db.prepare(sql).run(...a); }
    catch (e) { seedErrors.push(`${e.message} :: ${sql.slice(0, 70)}`); }
  };
  tryRun("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','alice','Alpha')");
  tryRun("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws2','bob','Bravo')");
  tryRun("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','alice','admin')");
  tryRun("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m2','ws2','bob','owner')");

  // ── THE FIXTURE: ONE domain, TWO workspaces ────────────────────────────────
  const SHARED = "shared-tenant.com";  // must satisfy isValidDomain, or /history 400s and the scoping assertions below become vacuous
  tryRun("INSERT INTO domains (id, user_id, domain) VALUES ('dom1','alice',?)", SHARED);
  tryRun("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','dom1')");
  tryRun("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws2','dom1')"); // <- co-linked
  const seedScan = (id, ws, createdAt) =>
    tryRun(`INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, scan_quality, created_at) VALUES (?, ?, 'dom1', ?, 80, 'good', 'completed', 'complete', ?)`, id, ws, SHARED, createdAt);
  seedScan("scan_ws1", "ws1", "2026-08-25 00:00:01");
  seedScan("scan_null", null,  "2026-08-25 00:00:02");   // legacy: owner UNKNOWN, newer than ws1
  seedScan("scan_ws2", "ws2", "2026-08-25 00:00:03");   // foreign, newest for shared domain

  // ── FIXTURE PRECONDITIONS — the suite is meaningless if these fail ────────
  section = "fixture-preconditions";
  const scanRows = db.prepare("SELECT id, workspace_id FROM scans ORDER BY id").all();
  const linkRows = db.prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id='dom1' ORDER BY workspace_id").all();
  ok(`no seeding errors (${seedErrors.length ? seedErrors[0] : "none"})`, seedErrors.length === 0);
  ok("three scans seeded", scanRows.length === 3);
  ok("scan_ws1 attributed to ws1", scanRows.some(r => r.id === "scan_ws1" && r.workspace_id === "ws1"));
  ok("scan_ws2 attributed to ws2", scanRows.some(r => r.id === "scan_ws2" && r.workspace_id === "ws2"));
  ok("scan_null has NULL owner",   scanRows.some(r => r.id === "scan_null" && r.workspace_id === null));
  ok("the domain is co-linked to BOTH workspaces", linkRows.length === 2);

  const call = async (p, tok) => {
    const r = await worker.fetch(new Request(`https://api.test${p}`, { headers: { Authorization: `Bearer ${tok}` } }), env, ctx);
    const body = await r.text();
    let data; try { data = JSON.parse(body); } catch { data = null; }
    return { status: r.status, body, data };
  };
  const SURFACES = (id) => [
    [`detail`,      `/api/scans/${id}`],
    [`report`,      `/api/scans/${id}/report`],
    [`pdf`,         `/api/scans/${id}/report/pdf`],
    [`exec-v2`,     `/api/scans/${id}/executive-report-v2`],
    [`snapshot`,    `/api/scans/${id}/snapshot`],
  ];

  // ── 0. AUTH PRECONDITION ──────────────────────────────────────────────────
  // Every "denied" assertion in this suite passes trivially if the actor is not
  // authenticated at all. An unauthenticated 401 is NOT evidence of isolation.
  // Assert real sessions BEFORE asserting any denial.
  section = "auth-preconditions";
  for (const [who, tok] of [["alice", T.alice], ["bob", T.bob]]) {
    const probe = await call("/api/scans", tok);
    ok(`${who} is genuinely authenticated (not a vacuous 401)`, probe.status !== 401);
  }

  // ── 1. Direct-ID reads: exact denial + no existence or R2 oracle ───────────
  // A non-401/non-marker response is not enough: 200/404/500 could all mask a
  // broken test. Foreign, NULL-owner and nonexistent IDs must produce the exact
  // same 403 body, and denial must occur before ANY R2 access.
  for (const [name, foreignPath] of SURFACES("scan_ws2")) {
    const nullPath = SURFACES("scan_null").find(([n]) => n === name)[1];
    const missingPath = SURFACES("scan_does_not_exist").find(([n]) => n === name)[1];
    section = `direct-${name}`;

    r2Gets.length = 0;
    const missing = await call(missingPath, T.alice);
    ok(`nonexistent scan is exact 403 via ${name}`, missing.status === 403);
    ok(`ZERO total R2 access for nonexistent scan via ${name}`, r2Gets.length === 0);

    r2Gets.length = 0;
    const foreign = await call(foreignPath, T.alice);
    ok(`foreign scan is exact same 403 via ${name}`,
      foreign.status === 403 && foreign.body === missing.body);
    ok(`ZERO total R2 access for foreign scan via ${name}`, r2Gets.length === 0);

    r2Gets.length = 0;
    const legacy = await call(nullPath, T.alice);
    ok(`NULL-owner scan is exact same 403 via ${name}`,
      legacy.status === 403 && legacy.body === missing.body);
    ok(`ZERO total R2 access for NULL-owner scan via ${name}`, r2Gets.length === 0);
  }

  // ── 2. POSITIVE CONTROL — the owner still reads its own scan ──────────────
  // Without this the suite would pass by denying everything.
  section = "positive-control";
  const own = await call("/api/scans/scan_ws1", T.alice);
  ok("alice CAN read her own scan (guard is not deny-all)", own.status === 200);

  // ── 3. LIST surfaces are scoped ───────────────────────────────────────────
  section = "list";
  for (const [who, tok, mine, theirs] of [["alice", T.alice, "scan_ws1", "scan_ws2"], ["bob", T.bob, "scan_ws2", "scan_ws1"]]) {
    const l = await call("/api/scans", tok);
    ok(`${who} list contains own scan`,        String(l.body).includes(mine));
    ok(`${who} list EXCLUDES foreign scan`,   !String(l.body).includes(theirs));
    ok(`${who} list EXCLUDES NULL-owner scan`,!String(l.body).includes("scan_null"));
  }
  const lf = await call("/api/scans?workspace_id=ws1", T.alice);
  ok("workspace-filtered list contains own scan",         String(lf.body).includes("scan_ws1"));
  ok("workspace-filtered list EXCLUDES foreign scan",    !String(lf.body).includes("scan_ws2"));
  ok("workspace-filtered list EXCLUDES NULL-owner scan", !String(lf.body).includes("scan_null"));

  // ── 4. WORKSPACE AGGREGATES select only directly attributed scans ─────────
  // The foreign scan is newest and the NULL-owner scan is newer than Alice's.
  // Therefore each surface proves that recency is evaluated only AFTER direct
  // workspace attribution. Every route stays a 200 aggregate but may derive
  // exactly one R2 key: Alice's own scan.
  const AGGREGATES = [
    ["certificates",  "/api/workspaces/ws1/certificates",         "ISSUER-MARKER-WS1"],
    ["saas",          "/api/workspaces/ws1/saas-exposure",        "SAAS-MARKER-WS1"],
    ["cloud",         "/api/workspaces/ws1/cloud-assets",         "CLOUD-MARKER-WS1"],
    ["cloud-summary", "/api/workspaces/ws1/cloud-assets/summary", "PROVIDER-MARKER-WS1"],
    ["admin",         "/api/workspaces/ws1/admin-surfaces",       "ADMIN-MARKER-WS1"],
  ];
  for (const [name, p, ownMarker] of AGGREGATES) {
    section = `aggregate-${name}`;
    r2Gets.length = 0;
    const r = await call(p, T.alice);
    ok(`${name} returns its normal workspace aggregate`, r.status === 200);
    ok(`${name} includes own directly attributed scan`, String(r.body).includes(ownMarker));
    ok(`${name} excludes foreign and NULL-owner report bytes`,
      !String(r.body).includes(MARK.scan_ws2) && !String(r.body).includes(MARK.scan_null));
    ok(`${name} derives the exact one permitted R2 key`,
      r2Gets.length === 1 && r2Gets[0] === "reports/scan_ws1.json");
  }

  // ── 5. HISTORY is scoped by DIRECT attribution ────────────────────────────
  section = "history";
  const h = await call(`/api/domain/${SHARED}/history`, T.alice);
  ok("history route actually engaged (not a vacuous 400/401)", h.status === 200);
  ok("history contains own scan",         String(h.body).includes("scan_ws1"));
  ok("history EXCLUDES foreign scan",    !String(h.body).includes("scan_ws2"));
  ok("history EXCLUDES NULL-owner scan", !String(h.body).includes("scan_null"));

  console.log(results.join("\n"));
  console.log(`\nF-021 scan-read tenant isolation: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
