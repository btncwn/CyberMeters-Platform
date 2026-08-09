#!/usr/bin/env node
// RWS.5 — Option A + H-A focused contract. Node 24+.
//
// This gate drives the real resolver, Website lifecycle/case factory, remediation
// registry and history comparator. It deliberately uses the repository schema in an
// in-memory D1-compatible harness so tenant, soft-delete and immutable-legacy-case
// behaviour are executable claims rather than source-string assertions.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...parts) => path.join(root, "workers", "scan-api", "src", ...parts);
const eng = (name) => pathToFileURL(src("engines", name)).href;

if (process.env.RWS5_EXPECT_MUTATED_FILE || process.env.RWS5_EXPECT_MUTATED_SHA256) {
  const relative = process.env.RWS5_EXPECT_MUTATED_FILE || "";
  const target = path.join(root, ...relative.split("/"));
  const bytes = fs.readFileSync(target);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  if (digest !== process.env.RWS5_EXPECT_MUTATED_SHA256) {
    throw new Error(`RWS5 mutation setup mismatch for ${relative}`);
  }
  await import(`${pathToFileURL(target).href}?mutation_sha=${digest}`);
  console.log(`LOADED_MUTATED_MODULE_URL=${pathToFileURL(target).href}`);
  console.log(`LOADED_MUTATED_MODULE_SHA256=${digest}`);
}

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const COOKIE_IDS = Object.freeze([
  "dse_cookie_no_secure",
  "dse_cookie_no_httponly",
  "dse_cookie_no_samesite",
]);
const UNRELATED_DSE = Object.freeze([
  "dse_missing_caa",
  "dse_caa_no_issuers",
  "dse_hsts_short_maxage",
  "dse_hsts_not_preload_eligible",
]);

let cookieContract = null;
try { cookieContract = await import(eng("cookie-observation.js")); } catch { /* fail-first */ }
const domains = await import(eng("cyber-mot-domains.js"));
const history = await import(eng("cyber-mot-state-history.js"));
const lifecycle = await import(eng("website-security-lifecycle.js"));
const websiteCases = await import(eng("website-security-cases.js"));
const remediation = await import(eng("remediation-registry.js"));
const asmCases = await import(eng("asm-cases.js"));
const managedVerification = await import(eng("managed-verification.js"));

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (filename) => {
    try { db.exec(fs.readFileSync(filename, "utf8")); } catch { /* schema already includes additive migrations */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations")).filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return {
    prepare(sql) {
      const direct = wrap(sql, []);
      direct.bind = (...args) => wrap(sql, args);
      return direct;
    },
  };
}

function seed(db) {
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','one@example.test','One','business',datetime('now'))").run();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u2','two@example.test','Two','business',datetime('now'))").run();
  for (const [workspace, owner] of [["ws1", "u1"], ["ws2", "u2"]]) {
    db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(workspace, owner, workspace);
    db.prepare(`INSERT OR IGNORE INTO alert_activation
      (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
      VALUES (?,?,'website_security','2020-01-01T00:00:00Z',0,datetime('now'))`).run(`act_${workspace}`, workspace);
  }
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','shared.example.test')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d2','u2','shared.example.test')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws2','d2')").run();
}

function cookieEvidence({ found = 1, insecure = 0, noHttpOnly = 0, noSameSite = 0, error = null } = {}) {
  return {
    caa: { present: true, records: [], issuers: ["example"], error: null },
    hsts: { present: true, max_age: 31_536_000, preload_eligible: true, error: null },
    cookies: {
      found,
      cookies: Array.from({ length: found }, (_, i) => ({ name: `c${i}` })),
      insecure_count: insecure,
      no_httponly: noHttpOnly,
      no_samesite: noSameSite,
      error,
    },
    source: "dns_headers_analysis",
    error: null,
  };
}

function context(enrich, { quality = "complete", moduleError = null } = {}) {
  const value = moduleError ? { ...enrich, error: moduleError } : enrich;
  return {
    modules: { domain_security_enrichment: value, headers: { values: {} }, ssl: { available: true } },
    scanQuality: { status: quality, modules_skipped: quality === "partial" ? ["domain_security_enrichment"] : [] },
  };
}

const finding = (id) => ({
  id,
  finding_type: "finding",
  module: "domain_security_enrichment",
  severity: id === "dse_cookie_no_secure" ? "high" : id === "dse_cookie_no_httponly" ? "medium" : "low",
  title: id,
  description: id,
  recommendation: "Set the canonical cookie attributes.",
  affected_hosts: ["shared.example.test"],
});

async function baseline(env, workspace = "ws1", domainId = "d1") {
  return lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: workspace,
    domain_id: domainId,
    domain: "shared.example.test",
    scan_id: `${workspace}-baseline`,
    findings: [],
    ...context(cookieEvidence({ found: 0 })),
  });
}

async function evaluate(env, {
  workspace = "ws1", domainId = "d1", scanId = "scan-1", findings = [],
  enrich = cookieEvidence(), quality = "complete", moduleError = null,
} = {}) {
  return lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: workspace,
    domain_id: domainId,
    domain: "shared.example.test",
    scan_id: scanId,
    findings,
    ...context(enrich, { quality, moduleError }),
  });
}

function condition(db, workspace, id) {
  return db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id=? AND condition_key=?").get(workspace, id) || null;
}

function cases(db, workspace) {
  return db.prepare("SELECT * FROM managed_cases WHERE workspace_id=? ORDER BY rowid").all(workspace);
}

// 1. One neutral canonical observation contract.
ok("shared cookie observation module loads", Boolean(cookieContract));
eq("cookie registry is exact", cookieContract?.COOKIE_FINDING_TYPES, COOKIE_IDS);
if (cookieContract) {
  for (const id of COOKIE_IDS) {
    const defect = id === "dse_cookie_no_secure" ? { insecure: 1 }
      : id === "dse_cookie_no_httponly" ? { noHttpOnly: 1 }
      : { noSameSite: 1 };
    eq(`${id}: found>0 defective is present`, cookieContract.evaluateCookieObservation(id, cookieEvidence(defect), { moduleComplete: true })?.state, "present");
    eq(`${id}: found>0 compliant is clear`, cookieContract.evaluateCookieObservation(id, cookieEvidence(), { moduleComplete: true })?.state, "clear");
    const none = cookieContract.evaluateCookieObservation(id, cookieEvidence({ found: 0 }), { moduleComplete: true });
    eq(`${id}: found===0 is deferred`, none?.state, "deferred");
    eq(`${id}: found===0 reason is exact`, none?.reason, "no_cookies_observed");
    eq(`${id}: incomplete module is deferred`, cookieContract.evaluateCookieObservation(id, cookieEvidence(defect), { moduleComplete: false })?.state, "deferred");
    eq(`${id}: unusable cookies are deferred`, cookieContract.evaluateCookieObservation(id, cookieEvidence({ ...defect, error: "failed" }), { moduleComplete: true })?.state, "deferred");
  }
}

// 2. Projection has one owner and preserves every unrelated dse_* mapping.
const attack = domains.CYBER_MOT_DOMAINS.find((entry) => entry.domain_key === "attack_surface");
const website = domains.CYBER_MOT_DOMAINS.find((entry) => entry.domain_key === "website_security");
for (const id of COOKIE_IDS) {
  eq(`${id}: Attack Surface no longer owns`, attack?.match({ id }), false);
  eq(`${id}: Website Security owns`, website?.match({ id }), true);
  eq(`${id}: generic ASM creation excludes`, asmCases.isAsmManagedFinding(finding(id)), false);
  eq(`${id}: managed verification ownership is Website Security`, managedVerification.managedVerificationDomainKey(id), "website_security");
}
for (const id of UNRELATED_DSE) {
  eq(`${id}: Attack Surface ownership preserved`, attack?.match({ id }), true);
  eq(`${id}: not dual-owned by Website Security`, website?.match({ id }), false);
  eq(`${id}: generic ASM creation remains enabled`, asmCases.isAsmManagedFinding({ id, module: "domain_security_enrichment" }), true);
  eq(`${id}: managed verification ownership remains Attack Surface`, managedVerification.managedVerificationDomainKey(id), "attack_surface");
}

const report = {
  scan_id: "scan-projection",
  completed_at: "2026-08-09T12:00:00Z",
  scan_quality: { status: "complete", modules_skipped: [] },
  modules: {
    subdomains: { subdomains: [] }, dns: { records: [] }, headers: { values: {} },
    ssl: { available: true }, domain_security_enrichment: cookieEvidence({ insecure: 1 }),
  },
  findings: [finding("dse_cookie_no_secure")],
};
const projected = domains.resolveCyberMotDomainStates(report);
const projectedAttack = projected.find((entry) => entry.domain_key === "attack_surface");
const projectedWebsite = projected.find((entry) => entry.domain_key === "website_security");
eq("cookie is absent from Attack Surface count", projectedAttack?.finding_count, 0);
eq("cookie appears once in Website Security count", projectedWebsite?.finding_count, 1);
eq("cookie is counted exactly once across all eight domains", projected.reduce((sum, entry) => sum + entry.finding_count, 0), 1);

// 3. One canonical remediation identity, already Website-owned.
const cookieEntries = remediation.REMEDIATION_REGISTRY.filter((entry) =>
  entry.finding_types?.some((id) => COOKIE_IDS.includes(id)));
eq("one remediation entry covers cookies", cookieEntries.length, 1);
eq("cookie remediation identity remains web.cookie.flags", cookieEntries[0]?.remediation_id, "web.cookie.flags");
eq("cookie remediation remains Website-owned", cookieEntries[0]?.domain_key, "website_security");
eq("one entry covers exactly all three cookie ids", [...(cookieEntries[0]?.finding_types || [])].sort(), [...COOKIE_IDS].sort());

// 4. Lifecycle spec/case ownership/alert domain and low SameSite preservation.
for (const id of COOKIE_IDS) {
  const spec = lifecycle.websiteConditionSpec(id);
  ok(`${id}: Website lifecycle spec exists`, Boolean(spec));
  eq(`${id}: detecting module is domain_security_enrichment`, spec?.module, "domain_security_enrichment");
  eq(`${id}: recurrence reuses the canonical Website case path`, websiteCases.WEBSITE_CASE_RECURRENCES.has(spec?.recurrence), true);
}

{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env);
  await evaluate(env, {
    findings: [finding("dse_cookie_no_samesite")],
    enrich: cookieEvidence({ noSameSite: 1 }),
  });
  const row = condition(db, "ws1", "dse_cookie_no_samesite");
  const allCases = cases(db, "ws1");
  ok("low-severity SameSite condition is retained by managed lifecycle", Boolean(row));
  eq("exactly one managed case opens", allCases.length, 1);
  eq("new cookie case type is website_case", allCases[0]?.case_type, "website_case");
  eq("new cookie case domain is Website Security", allCases[0]?.domain_key, "website_security");
  eq("new cookie case keeps the one remediation", allCases[0]?.remediation_id, "web.cookie.flags");
  eq("condition links to its single case", row?.linked_case_id, allCases[0]?.id);
  const alertDomains = db.prepare("SELECT domain_key FROM notification_events WHERE workspace_id='ws1'").all().map((entry) => entry.domain_key);
  ok("new cookie alert is Website Security", alertDomains.includes("website_security"), JSON.stringify(alertDomains));
  ok("no Attack Surface cookie alert is emitted", !alertDomains.includes("attack_surface"), JSON.stringify(alertDomains));

  await evaluate(env, {
    scanId: "scan-defect-repeat",
    findings: [finding("dse_cookie_no_samesite")],
    enrich: cookieEvidence({ noSameSite: 1 }),
  });
  eq("found>0 defective remains observed", condition(db, "ws1", "dse_cookie_no_samesite")?.monitoring_status, "observed");
  eq("unchanged defect creates no second case", cases(db, "ws1").length, 1);
}

// 5. Conclusive clear can verify; zero cookies and incomplete/error evidence cannot.
async function verificationScenario({ name, enrich, quality = "complete", moduleError = null, wantStatus, wantUnknown, wantCase }) {
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env);
  await evaluate(env, { findings: [finding("dse_cookie_no_secure")], enrich: cookieEvidence({ insecure: 1 }) });
  const row = condition(db, "ws1", "dse_cookie_no_secure");
  if (!row?.linked_case_id) {
    ok(`${name}: prerequisite cookie condition exists`, false);
    eq(`${name}: condition state`, row?.monitoring_status, wantStatus);
    eq(`${name}: unknown reason`, row?.unknown_reason ?? null, wantUnknown ?? null);
    eq(`${name}: case state`, null, wantCase);
    return { db, next: row, kase: null };
  }
  db.prepare("UPDATE managed_cases SET status='awaiting_verification' WHERE id=?").run(row?.linked_case_id);
  await evaluate(env, { scanId: `scan-${name}`, findings: [], enrich, quality, moduleError });
  const next = condition(db, "ws1", "dse_cookie_no_secure");
  const kase = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(row?.linked_case_id);
  eq(`${name}: condition state`, next?.monitoring_status, wantStatus);
  eq(`${name}: unknown reason`, next?.unknown_reason ?? null, wantUnknown ?? null);
  eq(`${name}: case state`, kase?.status, wantCase);
  return { db, next, kase };
}

await verificationScenario({
  name: "compliant", enrich: cookieEvidence(),
  wantStatus: "no_longer_observed", wantUnknown: null, wantCase: "verified",
});
const none = await verificationScenario({
  name: "no-cookies", enrich: cookieEvidence({ found: 0 }),
  wantStatus: "unknown", wantUnknown: "no_cookies_observed", wantCase: "awaiting_verification",
});
eq("found===0 writes no condition_resolved event",
  none.next
    ? none.db.prepare("SELECT COUNT(*) AS n FROM website_security_events WHERE record_id=? AND event_type='condition_resolved'").get(none.next.id).n
    : null,
  0);
await verificationScenario({
  name: "partial", enrich: cookieEvidence(), quality: "partial",
  wantStatus: "unknown", wantUnknown: "scan_partial", wantCase: "awaiting_verification",
});
await verificationScenario({
  name: "module-error", enrich: cookieEvidence(), moduleError: "enrichment failed",
  wantStatus: "unknown", wantUnknown: "module_not_assessed", wantCase: "awaiting_verification",
});

// The historical full-scan ASM verifier must not translate the ownership exclusion
// into finding absence. It consumes the same contract before deciding.
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  db.prepare(`INSERT INTO managed_cases
    (id,workspace_id,case_type,domain_key,domain,finding_id,source_finding_type,asset_ref,severity,status,evidence_json,created_at,updated_at)
    VALUES ('legacy-awaiting','ws1','asm_exposure','attack_surface','shared.example.test','dse_cookie_no_secure',
      'dse_cookie_no_secure','shared.example.test','high','verification_requested',?,datetime('now'),datetime('now'))`)
    .run(JSON.stringify({ finding: finding("dse_cookie_no_secure") }));
  const result = await asmCases.verifyManagedAsmCasesForScan(
    "scan-legacy-none", "d1", "shared.example.test", [], env,
    { ...context(cookieEvidence({ found: 0 })), scanPublished: true },
  );
  eq("historical full-scan cookie verification defers zero cookies", result.deferred, 1);
  eq("historical full-scan cookie case remains awaiting verification",
    db.prepare("SELECT status FROM managed_cases WHERE id='legacy-awaiting'").get()?.status,
    "verification_requested");
  const deferred = db.prepare("SELECT detail_json FROM managed_case_events WHERE case_id='legacy-awaiting' AND action='verification_deferred' ORDER BY rowid DESC LIMIT 1").get();
  eq("historical full-scan deferral keeps no_cookies_observed reason",
    deferred ? JSON.parse(deferred.detail_json).reason : null,
    "no_cookies_observed");
}

// 6. Historical H-A compatibility: exact legacy case suppresses a new case without mutation.
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env);
  db.prepare(`INSERT INTO managed_cases
    (id,workspace_id,case_type,domain_key,domain,finding_id,source_finding_type,asset_ref,severity,status,evidence_json,created_at,updated_at)
    VALUES ('legacy-cookie','ws1','asm_exposure','attack_surface','shared.example.test','dse_cookie_no_secure',
      'dse_cookie_no_secure','shared.example.test','high','open','{"legacy":true}','2026-07-01 00:00:00','2026-07-01 00:00:00')`).run();
  db.prepare(`INSERT INTO managed_case_events
    (id,case_id,workspace_id,actor_type,action,detail_json,created_at)
    VALUES ('legacy-event','legacy-cookie','ws1','system','case_created','{"legacy":true}','2026-07-01 00:00:00')`).run();
  const caseBefore = JSON.stringify(db.prepare("SELECT * FROM managed_cases WHERE id='legacy-cookie'").get());
  const eventBefore = JSON.stringify(db.prepare("SELECT * FROM managed_case_events WHERE id='legacy-event'").get());
  await evaluate(env, {
    findings: [finding("dse_cookie_no_secure")],
    enrich: cookieEvidence({ insecure: 1 }),
  });
  const allCases = cases(db, "ws1");
  eq("historical ASM cookie case suppresses a Website duplicate", allCases.length, 1);
  eq("historical ASM case row remains byte-equivalent", JSON.stringify(db.prepare("SELECT * FROM managed_cases WHERE id='legacy-cookie'").get()), caseBefore);
  eq("historical ASM event remains byte-equivalent", JSON.stringify(db.prepare("SELECT * FROM managed_case_events WHERE id='legacy-event'").get()), eventBefore);
  eq("Website condition presents the historical case link", condition(db, "ws1", "dse_cookie_no_secure")?.linked_case_id, "legacy-cookie");
}

// 7. Resolver boundary is mechanically versioned and therefore never recovery/new risk.
ok("resolver version is mechanically bumped from 2026-07-24.4", domains.CYBER_MOT_RESOLVER_VERSION !== "2026-07-24.4");
const oldState = {
  domain_key: "attack_surface", state: "issue_detected", coverage: "complete",
  highest_severity: "high", finding_count: 1, finding_ids_json: '["dse_cookie_no_secure"]',
  scan_quality: "complete", resolver_version: "2026-07-24.4", assessed_at: "2026-08-08T00:00:00Z",
};
const newState = {
  ...oldState, state: "assessed_healthy", highest_severity: null, finding_count: 0,
  finding_ids_json: "[]", resolver_version: domains.CYBER_MOT_RESOLVER_VERSION,
  assessed_at: "2026-08-09T00:00:00Z",
};
eq("historical/new ownership boundary is not_comparable",
  history.resolveDomainTrend(newState, oldState).trend, "not_comparable");

// 8. Tenant and soft-delete boundaries through the real Website writer.
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env, "ws1", "d1");
  await baseline(env, "ws2", "d2");
  await evaluate(env, { workspace: "ws1", domainId: "d1", findings: [finding("dse_cookie_no_secure")], enrich: cookieEvidence({ insecure: 1 }) });
  eq("same hostname in foreign tenant receives no condition", condition(db, "ws2", "dse_cookie_no_secure"), null);
  eq("same hostname in foreign tenant receives no case", cases(db, "ws2").length, 0);

  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws2'").run();
  const eventCount = db.prepare("SELECT COUNT(*) AS n FROM website_security_events WHERE workspace_id='ws2'").get().n;
  await evaluate(env, { workspace: "ws2", domainId: "d2", findings: [finding("dse_cookie_no_secure")], enrich: cookieEvidence({ insecure: 1 }) });
  eq("soft-deleted workspace receives no condition", condition(db, "ws2", "dse_cookie_no_secure"), null);
  eq("soft-deleted workspace receives no case", cases(db, "ws2").length, 0);
  eq("soft-deleted workspace receives no event write", db.prepare("SELECT COUNT(*) AS n FROM website_security_events WHERE workspace_id='ws2'").get().n, eventCount);
}

// 9. No second remediation, cookie detector or verifier is introduced.
const contractSource = cookieContract ? fs.readFileSync(src("engines", "cookie-observation.js"), "utf8") : "";
const dseSource = fs.readFileSync(src("engines", "dse-findings.js"), "utf8");
const verificationSource = fs.readFileSync(src("engines", "managed-verification.js"), "utf8");
const lifecycleSource = fs.readFileSync(src("engines", "website-security-lifecycle.js"), "utf8");
eq("both Website lifecycle alert calls use the canonical Website domain constant",
  (lifecycleSource.match(/domain_key: WEBSITE_SECURITY_DOMAIN_KEY/g) || []).length, 2);
ok("canonical cookie counters are defined only in the shared contract",
  cookieContract && [dseSource, verificationSource, lifecycleSource].every((sourceText) =>
    !/insecure_count\s*>\s*0|no_httponly\s*>\s*0|no_samesite\s*>\s*0/.test(sourceText)) &&
    /insecure_count/.test(contractSource) && /no_httponly/.test(contractSource) && /no_samesite/.test(contractSource));
ok("detection imports the shared cookie contract", /from "\.\/cookie-observation\.js"/.test(dseSource));
ok("Website lifecycle imports the shared cookie contract", /from "\.\/cookie-observation\.js"/.test(lifecycleSource));
ok("managed verification imports the shared cookie contract", /from "\.\/cookie-observation\.js"/.test(verificationSource));

console.log(`\nRWS.5 cookie ownership: ${pass}/${pass + fail} passed`);
if (fail > 0) {
  console.error("RWS.5 cookie ownership validation FAILED");
  process.exit(1);
}
console.log("RWS.5 cookie ownership validation passed");
