#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-https-observation-deadline-lifecycle.js  (CI-blocking)
//
// PR-A1 — two proofs the PR-A suite was missing entirely.
//
// D. DEADLINE FALLBACK. When the SSL module is deadline-deferred it never ran, so
//    it observed nothing. Before PR-A the fallback hard-coded `https_available:
//    false`, which scoring.js reads as positive evidence of absence and turns into
//    the CRITICAL "HTTPS Not Available" finding — a second, independent path to the
//    same false claim. PR-A fixed it to null/not_assessed but NOTHING guarded it:
//    reverting the fix left all 253 harnesses green. This is that guard.
//
// L. LIFECYCLE NON-PROGRESSION. An incomplete scan must not advance an open SSL
//    condition or its managed case toward verified/resolved. This asserts the
//    CANONICAL partial/incomplete scan-quality contract already defers the
//    transition — no SSL-specific bypass is added to lifecycle code, and no
//    lifecycle policy changes here.
//
// Real runScanEngine, real D1 (schema + migrations), real R2 shim. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engUrl = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;
const { runScanEngine, buildScanQuality } = await import(engUrl("scan-engine.js"));
const { moduleCompletionGate } = await import(engUrl("asm-cases.js"));

const NOW = "2026-07-28T13:00:00.000Z";
const NOW_MS = Date.parse(NOW);

// PINNED — a dropped assertion or mutant hard-fails even if everything else passes.
const EXPECTED_MUTANTS = 3;

let passed = 0, failed = 0, killed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch { /* schema/migration overlap */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const stmt = (sql, args = []) => ({
    __sql: sql, bind: (...b) => stmt(sql, b),
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } }; },
  });
  return {
    prepare: (s) => stmt(s),
    batch: async (l) => { const o = []; db.exec("BEGIN"); try { for (const s of l) o.push(/^\s*select/i.test(s.__sql) ? await s.all() : await s.run()); db.exec("COMMIT"); return o; } catch (e) { db.exec("ROLLBACK"); throw e; } },
    exec: async (s) => { db.exec(s); return { count: 0, duration: 0 }; },
  };
}
function makeR2(store) {
  return {
    get: async (k) => { const b = store.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store.set(String(k), String(b)); return {}; },
    delete: async (k) => { store.delete(String(k)); return {}; },
    head: async () => null, list: async () => ({ objects: [] }),
  };
}
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

// ═══════════════════════════════════════════════════════════════════════════
// D — DEADLINE FALLBACK
// ═══════════════════════════════════════════════════════════════════════════
// SCAN_DEADLINE_MS=0 makes every deadline-gated module take its fallback path, so
// the SSL module is genuinely deadline-deferred rather than simulated.
async function deadlineTrace(seedLifecycle = false) {
  const db = buildDb(); const store = new Map();
  const env = {
    cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "0", APP_VERSION: "pra1-deadline",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','o@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','PR-A1',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
              VALUES ('scan-dl','ws','dom','example.com','running',NULL,?)`).run(NOW);

  if (seedLifecycle) seedOpenSslCondition(db);

  const prevFetch = globalThis.fetch, prevErr = console.error;
  globalThis.fetch = async () => new Response("<html></html>", { status: 200, headers: { "content-type": "text/html", server: "nginx" } });
  console.error = () => {};
  try {
    await runScanEngine("scan-dl", "dom", "ws", "example.com", env,
      { now: () => NOW_MS, executionContext: "queue", trigger: "manual" });
  } catch { /* finalization is asserted from D1, not from a throw */ }
  finally { globalThis.fetch = prevFetch; console.error = prevErr; }

  const raw = store.get("reports/scan-dl.json");
  const report = raw ? JSON.parse(raw) : null;
  return {
    db, report,
    ssl: report?.modules?.ssl || {},
    quality: db.prepare("SELECT scan_quality FROM scans WHERE id='scan-dl'").get()?.scan_quality ?? null,
    findings: db.prepare("SELECT title FROM findings WHERE scan_id='scan-dl'").all().map((r) => r.title),
    domains: Object.fromEntries(db.prepare("SELECT domain_key, state, coverage, summary FROM cyber_mot_domain_states WHERE scan_id='scan-dl'").all().map((r) => [r.domain_key, r])),
  };
}

console.log("── D. deadline-deferred SSL module ──");
const d = await deadlineTrace();
ok("D: a report was produced (the scan finalized honestly)", d.report !== null);
ok("D: https_available === null", d.ssl.https_available === null, JSON.stringify(d.ssl.https_available));
ok("D: https_probe_executed === false (the probe never ran)", d.ssl.https_probe_executed === false);
ok("D: observation state/reason is the not_assessed / deadline equivalent",
  d.ssl.https_observation_state === "not_assessed" && d.ssl.https_observation_reason === "deadline_deferred",
  JSON.stringify({ s: d.ssl.https_observation_state, r: d.ssl.https_observation_reason }));
ok("D: SSL module carries canonical incompleteness",
  d.ssl.incomplete === true && d.ssl.incomplete_reason === "https_probe_not_executed",
  JSON.stringify({ i: d.ssl.incomplete, r: d.ssl.incomplete_reason }));
ok("D: scan_quality is partial in D1", d.quality === "partial", String(d.quality));
ok("D: SSL is listed in canonical incompleteness metadata",
  (d.report?.scan_quality?.modules_skipped || []).includes("ssl"),
  JSON.stringify(d.report?.scan_quality));
ok("D: NO \"HTTPS Not Available\" finding", !d.findings.includes("HTTPS Not Available"), d.findings.join(" | "));
{
  const ws = d.domains.website_security || {};
  const ct = d.domains.certificates_trust || {};
  const ce = d.domains.cyber_essentials_readiness || {};
  ok("D: website_security is NOT a healthy verdict", ws.state !== "assessed_healthy" && ws.coverage !== "complete", JSON.stringify(ws));
  ok("D: certificates_trust is NOT a healthy verdict", ct.state !== "assessed_healthy" && ct.coverage !== "complete", JSON.stringify(ct));
  ok("D: Cyber Essentials is unknown/insufficient, never a readiness GAP",
    ["customer_input_required", "evidence_insufficient", "not_yet_assessed", "provisional"].includes(ce.state) && ce.coverage !== "complete",
    JSON.stringify(ce));
}

// ═══════════════════════════════════════════════════════════════════════════
// L — LIFECYCLE / CASE NON-PROGRESSION
// ═══════════════════════════════════════════════════════════════════════════
// An OPEN ssl condition + linked managed case whose ordinary prerequisites would
// allow a later verification. The scan below is incomplete, so the canonical gate
// must defer — no resolution event, no verification, no case close.
function seedOpenSslCondition(db) {
  db.prepare(`INSERT INTO website_security_conditions
      (id, workspace_id, domain_id, domain, condition_key, observed_severity, observed_title,
       detecting_module, monitoring_status, monitoring_reason, recurrence_type, recurrence_band,
       first_seen_at, last_seen_at, last_changed_at, last_scan_id, last_scan_quality,
       linked_case_id, created_at, updated_at)
     VALUES ('wsc-fix','ws','dom','example.com','ssl_not_available','critical','HTTPS Not Available',
       'ssl','observed','observed_in_scan','transport_not_available','critical',
       datetime('now','-3 days'), datetime('now','-1 day'), datetime('now','-3 days'),
       'scan-old','complete','mc-fix', datetime('now','-3 days'), datetime('now','-1 day'))`).run();
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity,
       status, evidence_json, recommended_actions_json, created_at, updated_at)
     VALUES ('mc-fix','ws','website_case','website_security','example.com','ssl_not_available','example.com','critical',
       'awaiting_verification','{}','[]', datetime('now','-3 days'), datetime('now','-1 day'))`).run();
}

console.log("\n── L. lifecycle / case non-progression on an incomplete scan ──");
const l = await deadlineTrace(true);
const before = { condition: "observed", case: "awaiting_verification" };
const condAfter = l.db.prepare("SELECT monitoring_status, recurrence_type, last_scan_quality FROM website_security_conditions WHERE id='wsc-fix'").get() || {};
const caseAfter = l.db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-fix'").get() || {};
const events = l.db.prepare("SELECT event_type FROM website_security_events WHERE record_id='wsc-fix'").all().map((r) => r.event_type);
console.log(`   BEFORE  condition=${before.condition}  case=${before.case}`);
console.log(`   AFTER   condition=${condAfter.monitoring_status}  case=${caseAfter.status}  events=[${events.join(", ")}]`);
ok("L: NO condition_resolved event was emitted", !events.includes("condition_resolved"), events.join(","));
ok("L: the case did NOT enter verification_requested/verifying/resolved/verified",
  !["verification_requested", "verifying", "resolved", "verified"].includes(caseAfter.status),
  String(caseAfter.status));
ok("L: the case was NOT verified (verified_at still null)", caseAfter.verified_at == null, String(caseAfter.verified_at));
ok("L: the case remains where it was (awaiting_verification)", caseAfter.status === "awaiting_verification", String(caseAfter.status));
ok("L: the condition did NOT progress to no_longer_observed",
  condAfter.monitoring_status !== "no_longer_observed", String(condAfter.monitoring_status));
// The canonical gate is what defers it — asserted directly, so the proof does not
// rest on the branch it happened to be called from.
ok("L: the CANONICAL gate refuses verification on a partial scan (no SSL bypass)",
  moduleCompletionGate({ ssl: { incomplete: true } }, { status: "partial", modules_skipped: ["ssl"] }).canVerify("ssl") === false);
ok("L: the canonical gate ALSO refuses when the scan is complete but SSL self-reports incomplete",
  moduleCompletionGate({ ssl: { incomplete: true } }, { status: "complete", modules_skipped: [] }).canVerify("ssl") === false);
ok("L: the same canonical gate ALLOWS verification on a complete scan (positive control)",
  moduleCompletionGate({ ssl: {} }, { status: "complete", modules_skipped: [] }).canVerify("ssl") === true);

// ═══════════════════════════════════════════════════════════════════════════
// M — MUTATIONS (anchor-guarded, pinned)
// ═══════════════════════════════════════════════════════════════════════════
console.log("\n── M. mutation proof ──");
let seq = 0;
async function withMutant({ target, from, to }, run) {
  const original = fs.readFileSync(target, "utf8");
  const mutated = original.replace(from, to);
  if (mutated === original) return { applied: false };
  const name = `.${path.basename(target, ".js")}.mutant.${process.pid}.${++seq}.js`;
  const file = path.join(path.dirname(target), name);
  fs.writeFileSync(file, mutated);
  try { return { applied: true, result: await run(await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`)) }; }
  finally { fs.rmSync(file, { force: true }); }
}
const SCAN_ENGINE = path.join(root, "workers/scan-api/src/engines/scan-engine.js");
const MUTATIONS = [
  {
    name: "M-D1 the former hard-coded `https_available: false` deadline fallback is restored",
    target: SCAN_ENGINE,
    from: 'https_available: null, https_probe_executed: false, https_observation_state: "not_assessed", https_observation_reason: "deadline_deferred", https_observation_completeness: "not_assessed", https_origin_status: null, https_endpoint_observations: [], incomplete: true, incomplete_reason: "https_probe_not_executed", source: "tls_probe"',
    to: 'https_available: false, source: "tls_probe"',
    // A deferred module would again assert positive evidence of absence.
    check: (mod) => {
      const q = mod.buildScanQuality({ ssl: { https_available: false, source: "tls_probe" } });
      return q.status !== "partial" || !(q.modules_skipped || []).includes("ssl");
    },
  },
  {
    name: "M-D2 the deadline fallback keeps null but DROPS canonical incompleteness",
    target: SCAN_ENGINE,
    from: 'https_endpoint_observations: [], incomplete: true, incomplete_reason: "https_probe_not_executed", source: "tls_probe"',
    to: 'https_endpoint_observations: [], source: "tls_probe"',
    check: (mod) => {
      const q = mod.buildScanQuality({ ssl: { https_available: null, source: "tls_probe" } });
      return !(q.modules_skipped || []).includes("ssl");
    },
  },
  {
    name: "M-D3 buildScanQuality stops honouring the canonical module-incompleteness contract",
    target: SCAN_ENGINE,
    from: "    .filter(([, value]) => value?.incomplete === true)",
    to: "      .filter(() => false)",
    check: (mod) => {
      const q = mod.buildScanQuality({ ssl: { incomplete: true, incomplete_reason: "https_origin_not_observed" } });
      return q.status !== "partial";
    },
  },
];
for (const m of MUTATIONS) {
  const r = await withMutant(m, (mod) => m.check(mod));
  ok(`${m.name} :: mutation APPLIED (anchor matches the product source)`, r.applied,
    "anchor not found — this mutation tests NOTHING");
  if (!r.applied) continue;
  if (r.result === true) killed += 1;
  ok(`${m.name} :: defect REAPPEARS when mutated`, r.result === true);
}
ok(`mutants killed: ${killed}/${EXPECTED_MUTANTS} (pinned)`, killed === EXPECTED_MUTANTS,
  `expected exactly ${EXPECTED_MUTANTS}, killed ${killed}`);
ok(`mutation table length is pinned at ${EXPECTED_MUTANTS}`, MUTATIONS.length === EXPECTED_MUTANTS);
const strays = fs.readdirSync(path.join(root, "workers/scan-api/src/engines")).filter((f) => f.includes(".mutant."));
ok("no mutant file left behind", strays.length === 0, strays.join(", "));

console.log(`\nhttps-observation deadline+lifecycle: ${passed}/${passed + failed} passed; ${killed}/${EXPECTED_MUTANTS} mutants killed`);
if (failed) { console.error("https-observation-deadline-lifecycle validation FAILED"); process.exit(1); }
console.log("https-observation-deadline-lifecycle validation passed");
