#!/usr/bin/env node
//
// Cyber Essentials data integrity — mutation-tested, CI-blocking.
//
// Two P1s found while re-auditing CE for canonical alerting. Both are live today
// and neither has anything to do with alerting — which is why they are fixed
// before the CE lifecycle is built on top of them.
//
//   P1-1  cyber_essentials_answers was absent from WORKSPACE_PURGE_TABLES for the
//         entire life of the table. It holds `note` (free customer text) and
//         `answered_by` (a user id), it has NO foreign key to workspaces(id) — so
//         D1 could not block the parent delete either — and the deletion email
//         tells the owner their data has been "permanently removed". Every row
//         outlived the workspace it belonged to.
//
//   P1-2  CE selected its evidence with `(s.workspace_id = ? OR wd.workspace_id = ?)`
//         joined to workspace_domains, whose PK is (workspace_id, domain_id): one
//         domain, many workspaces, by design. The OR arm matched on merely LINKING
//         the domain, so an MSP scanning hourly graded its client's readiness from
//         a scan the client never ran.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  return {
    prepare(sql) {
      const wrap = (args) => ({
        __sql: sql, __args: args,
        first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
        all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
        run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
      });
      const b = wrap([]); b.bind = (...a) => wrap(a); return b;
    },
    async batch(stmts) {
      return stmts.map((st) => ({ results: db.prepare(st.__sql).all(...(st.__args || [])), success: true, meta: {} }));
    },
  };
}

// ── P1-2. Two workspaces, ONE shared verified domain ────────────────────────
// The exact production shape: an MSP and its client both link acme.com, and the
// MSP scans far more often. This is a supported configuration —
// workspace_domains PK (workspace_id, domain_id) exists to allow it.
{
  const db = buildDb();
  const { buildCyberEssentialsReadiness } = await import(eng("ce-readiness.js"));

  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('msp','msp@example.com','msp','professional',datetime('now'))").run();
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('cli','cli@example.com','cli','professional',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsMsp','msp','MSP')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsClient','cli','Client')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain, created_at) VALUES ('d1','msp','acme.example.com',datetime('now'))").run();
  // ONE domain, BOTH workspaces — the supported configuration that made the OR arm dangerous.
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsMsp','d1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsClient','d1')").run();

  // The MSP scanned an hour ago. The client has NEVER scanned.
  db.prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, score, rating, status, scan_quality, created_at)
              VALUES ('scan_msp','d1','wsMsp','acme.example.com',30,'poor','completed','complete',datetime('now'))`).run();

  const reports = {
    "reports/scan_msp.json": {
      modules: {
        headers: { accessible: true, headers_assessed: true, values: {}, present: [], missing: ["strict-transport-security"] },
        ssl: { https_available: false, https_probe_executed: true },
        email_security: { spf: { present: false }, dmarc: { present: false }, dkim: { present: false } },
      },
    },
  };
  const fetched = [];
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: { get: async (k) => { fetched.push(k); return reports[k] ? { json: async () => reports[k] } : null; } },
  };

  const client = await buildCyberEssentialsReadiness("wsClient", env);
  eq("the client workspace, which never scanned, is NOT assessed", client?.status, "not_assessed");
  eq("...and is explicitly not assessable", client?.assessable, false);
  eq("...and invents no gaps from the MSP's scan", client?.top_gaps, []);
  ok("the MSP's report object was NEVER fetched on the client's behalf",
     !fetched.includes("reports/scan_msp.json"), JSON.stringify(fetched));
  ok("no foreign scan id leaked into the client's verdict",
     !JSON.stringify(client || {}).includes("scan_msp"));

  // The MSP itself still grades normally off its OWN scan — the fix must not
  // break the legitimate case.
  const msp = await buildCyberEssentialsReadiness("wsMsp", env);
  eq("the MSP grades from its own scan", msp?.assessable, true);
  ok("the MSP's verdict is a real grade", typeof msp?.score === "number");
  ok("the MSP's own report WAS fetched", fetched.includes("reports/scan_msp.json"));

  // Now the client runs its own scan: it must grade from ITS OWN evidence.
  db.prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, score, rating, status, scan_quality, created_at)
              VALUES ('scan_client','d1','wsClient','acme.example.com',90,'good','completed','complete',datetime('now','+1 minute'))`).run();
  reports["reports/scan_client.json"] = {
    modules: {
      headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'" }, present: ["strict-transport-security"], missing: [] },
      ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
      email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
    },
  };
  const clientOwn = await buildCyberEssentialsReadiness("wsClient", env);
  eq("once the client scans, it grades from its OWN evidence", clientOwn?.assessable, true);
  ok("the client's healthy scan is not contaminated by the MSP's failing one",
     (clientOwn?.score ?? 0) > (msp?.score ?? 100),
     `client=${clientOwn?.score} msp=${msp?.score}`);

  // A legacy scan with no workspace attribution is evidence for NOBODY.
  db.prepare("DELETE FROM scans").run();
  db.prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, score, rating, status, scan_quality, created_at)
              VALUES ('scan_legacy','d1',NULL,'acme.example.com',10,'poor','completed','complete',datetime('now'))`).run();
  reports["reports/scan_legacy.json"] = reports["reports/scan_msp.json"];
  const legacy = await buildCyberEssentialsReadiness("wsClient", env);
  eq("an unattributed legacy scan grades nobody", legacy?.status, "not_assessed");
}

// ── P1-2 (source). The OR arm must not come back ────────────────────────────
{
  const src = fs.readFileSync(srcPath("engines", "ce-readiness.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const selector = src.slice(
    src.indexOf("async function getLatestWorkspaceScanReport"),
    src.indexOf("export async function buildCyberEssentialsReadiness"),
  );
  ok("CE evidence selection has no workspace_domains fallback", !/workspace_domains/.test(selector));
  ok("CE evidence selection scopes to the workspace's own scans", /s\.workspace_id = \?/.test(selector));
  ok("CE evidence selection has no OR arm", !/OR wd\.workspace_id/.test(selector));
  ok("the separate Stage-1 count helper uses workspace_domains without joining it to scans",
     /SELECT COUNT\(\*\) AS n[\s\S]*FROM workspace_domains[\s\S]*WHERE workspace_id = \?/.test(src));
}

// ── P1-1. Purge — the table is listed, and the guard is REAL ────────────────
{
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  const mod = await import(pathToFileURL(srcPath("index.js")).href);
  const { purgeWorkspaceData, WORKSPACE_PURGE_TABLES } = mod;

  ok("cyber_essentials_answers is in the workspace purge contract",
     WORKSPACE_PURGE_TABLES.includes("cyber_essentials_answers"));

  const db = buildDb();
  const seed = (ws, q) => db.prepare(
    `INSERT INTO cyber_essentials_answers (id, workspace_id, control_key, question_key, answer, note, answered_by, updated_at)
     VALUES (?, ?, 'boundary_protection', ?, 'no', 'internal note — customer text', 'u1', datetime('now'))`,
  ).run(`ce_${ws}_${q}`, ws, q);
  for (const q of ["q1", "q2", "q3"]) { seed("wsPurge", q); seed("wsKeep", q); }

  const count = (ws) => db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE workspace_id=?").get(ws).c;
  eq("the purged workspace really had answers to lose (the test is not vacuous)", count("wsPurge"), 3);

  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => {}, list: async () => ({ objects: [] }) },
  };
  let guard = 0, res;
  do { res = await purgeWorkspaceData(env, "wsPurge"); } while (res && res.done === false && ++guard < 50);
  ok("purge completed", res?.done === true);

  eq("every CE answer for the purged workspace is gone", count("wsPurge"), 0);
  // The free-text note and the author id are the customer data the deletion email
  // promises is removed. Assert on the ROWS, not just the count.
  const leaked = db.prepare("SELECT * FROM cyber_essentials_answers WHERE workspace_id='wsPurge'").all();
  eq("no customer note survives the purge", leaked.length, 0);
  eq("the other workspace's answers all survive (no over-deletion)", count("wsKeep"), 3);
}

// ── MUTATION — would this suite catch either regression? ────────────────────
{
  // (a) Remove cyber_essentials_answers from the purge contract.
  const idxSrc = fs.readFileSync(srcPath("index.js"), "utf8");
  const mutatedIdx = idxSrc.replace(/\n\s*"cyber_essentials_answers",/, "");
  ok("MUTATION (a) applied — the table is where this suite thinks it is", mutatedIdx !== idxSrc);
  ok("MUTANT (a): the purge contract no longer lists the table",
     !/"cyber_essentials_answers"/.test(mutatedIdx.slice(mutatedIdx.indexOf("const WORKSPACE_PURGE_TABLES"), mutatedIdx.indexOf("const ACCOUNT_PURGE_TABLES"))));

  // (b) Restore the OR arm and prove the client is graded from the MSP's scan —
  // the live defect, reproduced against the real engine. Built by string surgery on
  // the real source so the mutant is the shipped code minus the fix, not a rewrite.
  const ceSrc = fs.readFileSync(srcPath("engines", "ce-readiness.js"), "utf8");
  const FIXED_PREDICATE = "         FROM scans s\n         WHERE s.status = 'completed'\n           AND s.workspace_id = ?";
  const OR_PREDICATE = "         FROM scans s\n         LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id\n         WHERE s.status = 'completed'\n           AND (s.workspace_id = ? OR wd.workspace_id = ?)";
  ok("the fixed predicate is present in the real source", ceSrc.includes(FIXED_PREDICATE));
  const mutatedCe = ceSrc
    .replace(FIXED_PREDICATE, OR_PREDICATE)
    .replace("      .bind(wsId)\n      .first();", "      .bind(wsId, wsId)\n      .first();");
  ok("MUTATION (b) applied — the predicate is where this suite thinks it is", mutatedCe !== ceSrc);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-ce-"));
  const tmp = srcPath("engines", `.ce-readiness.mutant.${path.basename(dir)}.js`);
  fs.writeFileSync(tmp, mutatedCe);
  try {
    const mutant = await import(pathToFileURL(tmp).href);
    const db = buildDb();
    db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('msp','msp@example.com','msp','professional',datetime('now'))").run();
    db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('cli','cli@example.com','cli','professional',datetime('now'))").run();
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsMsp','msp','MSP')").run();
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsClient','cli','Client')").run();
    db.prepare("INSERT INTO domains (id, user_id, domain, created_at) VALUES ('d1','msp','acme.example.com',datetime('now'))").run();
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsMsp','d1')").run();
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsClient','d1')").run();
    db.prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, score, rating, status, scan_quality, created_at)
                VALUES ('scan_msp','d1','wsMsp','acme.example.com',30,'poor','completed','complete',datetime('now'))`).run();

    const fetched = [];
    const MUTANT_REPORT = { modules: {
      headers: { accessible: true, headers_assessed: true, values: {}, present: [], missing: [] },
      ssl: { https_available: false, https_probe_executed: true },
      email_security: { spf: { present: false }, dmarc: { present: false }, dkim: { present: false } },
    } };
    const env = {
      cybermeters_db: makeD1(db),
      cybermeters_reports: { get: async (k) => { fetched.push(k); return { json: async () => MUTANT_REPORT }; } },
    };
    const client = await mutant.buildCyberEssentialsReadiness("wsClient", env);
    ok("MUTANT (b): the client — which never scanned — IS graded, from the MSP's scan",
       client?.assessable === true && client?.status !== "not_assessed", `status=${client?.status}`);
    ok("MUTANT (b): the MSP's report object IS fetched on the client's behalf — the leak, reproduced",
       fetched.includes("reports/scan_msp.json"), JSON.stringify(fetched));
  } finally {
    fs.rmSync(tmp, { force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log(`\nce-data-integrity: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("ce-data-integrity validation FAILED"); process.exit(1); }
console.log("ce-data-integrity validation passed");
