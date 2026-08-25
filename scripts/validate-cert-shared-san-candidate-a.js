#!/usr/bin/env node
// CERT_SHARED_SAN_COUNT Candidate A (R1+R3) behavioural contract.
// Node 24+. Deterministic local doubles only; no network or production data.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = (...parts) => path.join(root, ...parts);
const moduleUrl = (relative) => pathToFileURL(source(...relative.split("/"))).href;
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stable = (value) => JSON.stringify(value);
const clone = (value) => structuredClone(value);

const { runScanEngine } = await import(moduleUrl("workers/scan-api/src/engines/scan-engine.js"));
const { scanRoutes } = await import(moduleUrl("workers/scan-api/src/routes/scans.js"));
const { runCertificateIntelligenceModule } = await import(
  moduleUrl("workers/scan-api/src/engines/cert-intel.js"));
const { composeSnapshot } = await import(
  moduleUrl("workers/scan-api/src/engines/report-snapshot.js"));
const { buildExecutiveReportV2 } = await import(
  moduleUrl("workers/scan-api/src/engines/executive-report.js"));
const { buildScanReportPdf, buildWorkspaceExecutivePdf } = await import(
  moduleUrl("workers/scan-api/src/engines/pdf.js"));
const { buildScorecardSections } = await import(
  moduleUrl("workers/scan-api/src/engines/scorecard.js"));

let projector = null;
try {
  const candidate = await import(
    process.env.CERT_SHARED_SAN_PROJECTOR_MODULE ||
      moduleUrl("workers/scan-api/src/routes/certificate-shared-san-projection.js"));
  projector = candidate.projectCertificateSharedSanForCustomer;
} catch { /* fail-first parent has no projector */ }

const results = new Map();
const resultDetails = new Map();
function fixture(id, condition, detail = "") {
  results.set(id, Boolean(condition));
  if (!condition) resultDetails.set(id, detail);
}
function assessment(modules, domain = "example.com") {
  if (typeof projector !== "function") return null;
  return projector({
    ssl: modules.ssl,
    certificateIntelligence: modules.certificate_intelligence,
    domain,
  })?.shared_san_assessment ?? null;
}
function projectedIntelligence(modules, domain = "example.com") {
  if (typeof projector !== "function") return modules.certificate_intelligence;
  return projector({
    ssl: modules.ssl,
    certificateIntelligence: modules.certificate_intelligence,
    domain,
  });
}

function storedModules({
  version = "external-certificate-observation-v2",
  includeEvidence = true,
  raw = 0,
  crtCount = 5,
  crtError = null,
  incomplete = false,
  subject = "example.com",
  sans = ["example.com"],
  wildcard = 0,
  rawOwned = true,
  rawConfidence = 90,
} = {}) {
  const ssl = {
    cert_subject: subject,
    cert_san_names: sans,
    cert_wildcard_san_count: wildcard,
    cert_shared_san_count: raw,
    ct_sources: { crt_sh: { count: crtCount, error: crtError } },
  };
  if (includeEvidence) ssl.certificate_evidence = { schema_version: version };
  return {
    ssl,
    certificate_intelligence: {
      shared_san_count: raw,
      ownership: {
        status: raw > 0 ? "shared_certificate" : "customer_domain_certificate",
        customer_owned: rawOwned,
        confidence: rawConfidence,
      },
      ...(incomplete ? { incomplete: true, incomplete_reason: "fixture_incomplete" } : {}),
    },
  };
}

const legacy = storedModules();
const legacyProjected = projectedIntelligence(legacy);
const legacyAssessment = legacyProjected?.shared_san_assessment;
fixture("F01",
  legacyAssessment?.measurement_state === "legacy_ambiguous_zero" &&
  legacyAssessment?.assessment_state === "not_assessed" &&
  legacyAssessment?.ownership_status == null &&
  legacyAssessment?.customer_owned == null &&
  legacyAssessment?.confidence == null);

const unversioned = storedModules({ includeEvidence: false });
const unversionedAssessment = assessment(unversioned);
fixture("F02",
  unversionedAssessment?.measurement_state === "legacy_ambiguous_zero" &&
  unversionedAssessment?.assessment_state === "not_assessed" &&
  unversionedAssessment?.customer_owned == null &&
  unversionedAssessment?.confidence == null);

const legacyBefore = stable(legacy);
projectedIntelligence(legacy);
fixture("F03",
  legacyAssessment != null && stable(legacy) === legacyBefore &&
  legacyProjected?.shared_san_count === 0 &&
  legacyProjected?.ownership?.customer_owned === true &&
  legacyProjected?.ownership?.confidence === 90);

const brokenV3 = storedModules({
  version: "external-certificate-observation-v3",
  crtError: "provider unavailable",
});
const brokenAssessment = assessment(brokenV3);
fixture("F06",
  brokenAssessment?.measurement_state === "unmeasured" &&
  brokenAssessment?.assessment_state === "not_assessed" &&
  brokenAssessment?.customer_owned == null && brokenAssessment?.confidence == null);

const nullV3 = storedModules({
  version: "external-certificate-observation-v3", raw: null,
  rawOwned: null, rawConfidence: null,
});
fixture("F07", assessment(nullV3)?.measurement_state === "unmeasured");

const legacyPositive = storedModules({ raw: 2, rawOwned: false, rawConfidence: 50 });
const legacyPositiveAssessment = assessment(legacyPositive);
fixture("F08",
  legacyPositiveAssessment?.measurement_state === "legacy_measured_positive" &&
  legacyPositiveAssessment?.shared_san_count === 2 &&
  legacyPositiveAssessment?.ownership_status === "shared_certificate" &&
  legacyPositiveAssessment?.confidence === 50 &&
  legacyPositiveAssessment?.customer_owned === false);

const invalidValues = ["0", Number.NaN, -1, 0.5, Infinity, undefined];
const invalidStates = [];
for (const version of [
  "external-certificate-observation-v2",
  "external-certificate-observation-v3",
]) {
  for (const raw of invalidValues) {
    const invalid = storedModules({ version, raw: null });
    invalid.ssl.cert_shared_san_count = raw;
    invalid.certificate_intelligence.shared_san_count = raw;
    invalidStates.push(assessment(invalid)?.measurement_state);
  }
}
fixture("F09", invalidStates.length === 12 && invalidStates.every((state) => state === "unmeasured"));

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent migrations */ }
  };
  apply(source("database", "schema.sql"));
  for (const file of fs.readdirSync(source("database", "migrations"))
    .filter((name) => name.endsWith(".sql")).sort()) {
    apply(source("database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db, trace) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      trace.reads.push(sql);
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => {
      trace.reads.push(sql);
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      trace.writes.push(sql);
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes, last_row_id: Number(result.lastInsertRowid || 0) } };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => Promise.all(statements.map((entry) =>
      /^\s*select/i.test(entry.__sql) ? entry.all() : entry.run())),
  };
}

function makeR2(store, trace) {
  return {
    get: async (key) => {
      trace.gets.push(String(key));
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => {
      trace.puts.push(String(key));
      store.set(String(key), String(body));
      return {};
    },
    delete: async (key) => { trace.deletes.push(String(key)); store.delete(String(key)); return {}; },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

async function runEngineScenario({ name, domain, commonName, names, expected }) {
  const db = buildDb();
  const store = new Map();
  const trace = { reads: [], writes: [], gets: [], puts: [], deletes: [] };
  const env = {
    cybermeters_db: makeD1(db, trace),
    cybermeters_reports: makeR2(store, trace),
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "19000",
    APP_VERSION: "candidate-a-engine-fixture",
  };
  const scanId = `scan-candidate-a-${name}`;
  const domainId = `domain-candidate-a-${name}`;
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)")
    .run(`user-${name}`, `${name}@example.invalid`);
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)")
    .run(`workspace-${name}`, `Workspace ${name}`);
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)")
    .run(domainId, `user-${name}`, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)")
    .run(`workspace-${name}`, domainId);
  db.prepare(
    `INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, created_at)
     VALUES (?, ?, ?, ?, 'running', '2026-08-09T12:00:00.000Z')`,
  ).run(scanId, `workspace-${name}`, domainId, domain);

  const realFetch = globalThis.fetch;
  const realRandom = Math.random;
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.hostname === "crt.sh") {
      return jsonResponse([{
        id: `crt-${name}`,
        common_name: commonName,
        name_value: names.join("\n"),
        issuer_name: "Candidate A Fixture CA",
        not_before: "2026-08-01T00:00:00.000Z",
        not_after: "2099-08-01T00:00:00.000Z",
      }]);
    }
    if (url.hostname === "api.certspotter.com") return jsonResponse({}, 403);
    if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
      return jsonResponse({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    return new Response("<html><title>Candidate A</title></html>", {
      status: 200,
      headers: { "content-type": "text/html", server: "candidate-a-fixture" },
    });
  };
  Math.random = () => 0.123456789;
  let engineError = null;
  try {
    await runScanEngine(scanId, domainId, `workspace-${name}`, domain, env, {
      now: () => Date.parse("2026-08-09T12:00:00.000Z"),
      executionContext: "queue",
      trigger: "manual",
    });
  } catch (error) {
    engineError = error;
  } finally {
    globalThis.fetch = realFetch;
    Math.random = realRandom;
  }
  const rawBytes = store.get(`reports/${scanId}.json`) || "";
  const report = JSON.parse(rawBytes || "{}");
  const callReport = async (access = async () => true, id = scanId) => {
    const request = new Request(`https://api.cybermeters.test/api/scans/${id}/report`);
    const response = await scanRoutes({
      request,
      env,
      ctx: { waitUntil() {} },
      url: new URL(request.url),
      json: jsonResponse,
      serverError: (_scope, error) => jsonResponse({ error: String(error?.message || error) }, 500),
      corsHeaders: {},
      requireAuth: async () => ({ id: `user-${name}` }),
      requireScanReadAccess: access,
    });
    return { response, body: await response.json() };
  };
  const route = await callReport();
  return { db, store, trace, env, scanId, domainId, domain, engineError, rawBytes, report, route, callReport, expected };
}

const scenarios = [];
for (const spec of [
  {
    name: "plain", domain: "plain.example.com", commonName: "plain.example.com",
    names: ["plain.example.com", "www.plain.example.com"],
    expected: { state: "measured_zero", status: "customer_domain_certificate", confidence: 90, owned: true, count: 0 },
  },
  {
    name: "wildcard", domain: "wild.example.net", commonName: "*.wild.example.net",
    names: ["*.wild.example.net", "wild.example.net"],
    expected: { state: "measured_zero", status: "customer_domain_wildcard", confidence: 70, owned: true, count: 0 },
  },
  {
    name: "uncertain", domain: "uncertain.example.org", commonName: "unrelated.example.invalid",
    names: ["*.uncertain.example.org"],
    expected: { state: "measured_zero", status: "ownership_uncertain", confidence: 60, owned: false, count: 0 },
  },
  {
    name: "positive", domain: "positive.example.co.uk", commonName: "positive.example.co.uk",
    names: ["positive.example.co.uk", "unrelated.example.invalid"],
    expected: { state: "measured_positive", status: "shared_certificate", confidence: 50, owned: false, count: 1 },
  },
]) {
  scenarios.push(await runEngineScenario(spec));
}

const zeroScenarios = scenarios.slice(0, 3);
fixture("F04", zeroScenarios.every((scenario) => {
  const projected = scenario.route.body?.modules?.certificate_intelligence?.shared_san_assessment;
  const rawStillSame = scenario.store.get(`reports/${scenario.scanId}.json`) === scenario.rawBytes;
  return scenario.engineError == null && scenario.route.response.status === 200 && rawStillSame &&
    scenario.report.modules?.ssl?.cert_shared_san_count === 0 &&
    projected?.measurement_state === scenario.expected.state &&
    projected?.ownership_status === scenario.expected.status &&
    projected?.confidence === scenario.expected.confidence &&
    projected?.customer_owned === scenario.expected.owned &&
    projected?.shared_san_count === 0;
}));

const positive = scenarios[3];
const positiveProjected = positive.route.body?.modules?.certificate_intelligence?.shared_san_assessment;
fixture("F05",
  positive.engineError == null && positive.route.response.status === 200 &&
  positive.report.modules?.ssl?.cert_shared_san_count === 1 &&
  positiveProjected?.measurement_state === "measured_positive" &&
  positiveProjected?.ownership_status === "shared_certificate" &&
  positiveProjected?.confidence === 50 && positiveProjected?.customer_owned === false &&
  positiveProjected?.shared_san_count === 1);

const evidence = scenarios[0].report.modules?.ssl?.certificate_evidence || {};
const evidenceV2 = {
  ...evidence,
  schema_version: "external-certificate-observation-v2",
  observed_at: "<engine-observed-at>",
};
const GOLDEN_EVIDENCE_V2 = "69a96451e093f41bc0be77233dbc4a0f21a368d177710310e53bc0848b97cca4";
fixture("F10",
  evidence.schema_version === "external-certificate-observation-v3" &&
  hash(stable(evidenceV2)) === GOLDEN_EVIDENCE_V2);

function parityReport(projection = undefined) {
  const certificateIntelligence = {
    certificate_risk_level: "low",
    suspicious_certificate_signals: [],
    signal_completeness: null,
    ...(projection === undefined ? {} : { shared_san_assessment: projection }),
  };
  return {
    scan_id: "scan-golden",
    status: "completed",
    completed_at: "2026-08-09T13:00:00.000Z",
    cyber_metrics_score: 73,
    risk_level: "medium",
    findings: [],
    recommendations: [],
    modules: { certificate_intelligence: certificateIntelligence },
    scan_quality: { status: "partial", modules_skipped: ["identity_exposure"], warnings: [] },
  };
}
function parityOutputs(projection) {
  const snapshot = composeSnapshot({
    snapshotId: "snapshot-golden", workspaceId: "workspace-golden",
    domainId: "domain-golden", scanId: "scan-golden", domain: "golden.example",
    report: parityReport(projection), cyberEssentials: null, ceReadiness: null,
    caseRows: [], questionSetVersions: [], certificateLifecycleRecords: [],
    attackSurfaceLifecycleRecords: [], supersedesSnapshotId: null,
    builtAt: "2026-08-09T13:00:05.000Z",
  });
  const read = { status: "ok", snapshot, row: { id: "snapshot-golden" }, integrity: { verified: true } };
  const executive = buildExecutiveReportV2({
    scan: { id: "scan-golden", domain_id: "domain-golden", domain: "golden.example" },
    workspace: { id: "workspace-golden", name: "Golden Workspace" }, read,
  });
  const pdf = buildScanReportPdf(
    { id: "scan-golden", domain: "golden.example" }, read,
    { mode: "cybermeters", attribution: "full" }, null,
  );
  const workspacePdf = buildWorkspaceExecutivePdf({
    workspaceName: "Golden Workspace", reads: [read],
    branding: { mode: "cybermeters", attribution: "full" },
    generatedAt: "2026-08-09T13:00:05.000Z", logoImage: null,
  });
  const sections = buildScorecardSections({
    active_assets: 0, new_assets_30d: 0, asset_events_30d: 0,
    vendors_detected: 0, vendor_risk: { high: 0, medium: 0, low: 0 },
    third_party_assets: 0, saas_exposures: 0, admin_surfaces: 0,
    brand_risks: { total: 0, active: 0, high: 0 },
    critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0,
    email_security: { status: "good", description: "Golden" },
    certificate_risks: { signals: 0, risk_level: "low", days_until_expiry: 84 },
    security_posture: {}, top_recommendations: [],
  });
  const f13 = hash(stable({
    snapshot,
    executive,
    pdf: hash(pdf),
    workspace_pdf: hash(workspacePdf),
    scorecard_sections: sections,
  }));
  const f14 = hash(stable({
    overall: snapshot.overall,
    domains: snapshot.domains,
    observed_findings: snapshot.observed_findings,
    remediation_actions: snapshot.remediation_actions,
    methodology: snapshot.methodology,
    historical_scores: [{ score: 73, rating: "medium", business_risk: null }],
  }));
  return { f13, f14 };
}

const states = [
  { measurement_state: "measured_zero" },
  { measurement_state: "measured_positive" },
  { measurement_state: "legacy_ambiguous_zero" },
  { measurement_state: "legacy_measured_positive" },
  { measurement_state: "unmeasured" },
];
const parity = states.map(parityOutputs);
// D3 RE-DERIVATION: byte drift measured field-by-field against base f1af6e41 —
// methodology stamp 2026-08-23.1 -> 2026-08-24.1 (the deliberate D3 bump, its
// own assertion in validate-report-copy-live-triage), two additive
// evidence_completeness fields (phase5_evidence, skipped_score_bearing_modules)
// and a null-valued assessment.suppression_reason key. Score, band, summary,
// domains and findings byte-identical. No value changed; the goldens follow.
const GOLDEN_F13 = "d46224be662e3a9a7f58202f7ddc791e6e0be54983e1cdbcb19ba2ea7a091886";
const GOLDEN_F14 = "2ec23d5f7ea37be1703eed200f2a05001b338ac461848d07d06709485c6423bb";
fixture("F13", parity.every((row) => row.f13 === GOLDEN_F13));
fixture("F14", parity.every((row) => row.f14 === GOLDEN_F14));

function operationalDigest(db) {
  const wanted = [
    "certificate_observations", "asset_events", "managed_cases",
    "alert_occurrences", "certificate_lifecycle", "related_changes", "audit_log",
  ];
  const existing = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name));
  const rows = {};
  for (const table of wanted.filter((name) => existing.has(name))) {
    rows[table] = db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
  }
  return hash(stable(rows));
}

const isolated = scenarios[0];
const operationalBefore = operationalDigest(isolated.db);
const writesBeforeReads = isolated.trace.writes.length;
const putsBeforeReads = isolated.trace.puts.length;
isolated.db.prepare("INSERT INTO workspaces (id, name) VALUES ('workspace-foreign', 'Foreign')").run();
isolated.db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('workspace-deleted', 'Deleted', '2026-08-09T00:00:00.000Z')").run();
for (const [id, workspace] of [["scan-foreign", "workspace-foreign"], ["scan-deleted", "workspace-deleted"]]) {
  isolated.db.prepare(
    `INSERT INTO scans (id, workspace_id, domain_id, domain, status, created_at)
     VALUES (?, ?, ?, ?, 'completed', '2026-08-09T12:00:00.000Z')`,
  ).run(id, workspace, isolated.domainId, isolated.domain);
}
const same = await isolated.callReport(async (_user, id) => id === isolated.scanId);
const sameAgain = await isolated.callReport(async (_user, id) => id === isolated.scanId);
const routeGetsAfterSame = isolated.trace.gets.length;
const foreign = await isolated.callReport(async () => false, "scan-foreign");
const nonexistent = await isolated.callReport(async () => false, "scan-nonexistent");
const deleted = await isolated.callReport(async () => false, "scan-deleted");
const deniedBodiesEqual = stable(foreign.body) === stable(nonexistent.body) &&
  stable(deleted.body) === stable(nonexistent.body);
fixture("F16",
  same.response.status === 200 && sameAgain.response.status === 200 &&
  (typeof projector !== "function" ||
    (same.body?.modules?.certificate_intelligence?.shared_san_assessment != null &&
     stable(same.body?.modules?.certificate_intelligence?.shared_san_assessment) ===
       stable(sameAgain.body?.modules?.certificate_intelligence?.shared_san_assessment))) &&
  foreign.response.status === 403 && nonexistent.response.status === 403 &&
  deleted.response.status === 403 && deniedBodiesEqual &&
  isolated.trace.gets.length === routeGetsAfterSame &&
  isolated.trace.writes.length === writesBeforeReads &&
  isolated.trace.puts.length === putsBeforeReads);

const rawKeys = Object.keys(legacy.certificate_intelligence);
const projectedKeys = Object.keys(legacyProjected || {});
fixture("F17",
  (typeof projector !== "function" ||
   (projectedKeys.slice(0, rawKeys.length).join("\0") === rawKeys.join("\0") &&
    projectedKeys[rawKeys.length] === "shared_san_assessment")) &&
  stable(Object.fromEntries(rawKeys.map((key) => [key, legacyProjected?.[key]]))) ===
    stable(legacy.certificate_intelligence));

const unavailableIntel = runCertificateIntelligenceModule({
  ssl: {
    cert_san_count: null, cert_raw_san_count: null,
    cert_wildcard_san_count: null, cert_shared_san_count: null,
    ct_sources: { crt_sh: { count: 0, error: "unavailable" }, certspotter: { count: 0, error: "unavailable" } },
  },
}, "example.com");
fixture("F18",
  unavailableIntel.san_count === 0 && unavailableIntel.raw_san_count === 0 &&
  unavailableIntel.wildcard_san_count === 0 && unavailableIntel.shared_san_count === null);

function p2Guard() {
  const sslFile = source("workers", "scan-api", "src", "engines", "ssl-scan.js");
  const validator = source("scripts", "validate-item9-certificate-p2-engine-trace.js");
  const original = fs.readFileSync(sslFile, "utf8");
  const anchor = '      schema_version: "external-certificate-observation-v3",';
  if (original.split(anchor).length - 1 !== 1) return false;
  const first = spawnSync(process.execPath, [validator], { cwd: root, encoding: "utf8", timeout: 120_000 });
  if (first.status !== 0 || first.error || first.signal) return false;
  try {
    fs.writeFileSync(sslFile, original.replace(anchor,
      '      schema_version: "external-certificate-observation-v2",'));
    const second = spawnSync(process.execPath, [validator], { cwd: root, encoding: "utf8", timeout: 120_000 });
    const output = `${second.stdout || ""}\n${second.stderr || ""}`;
    return second.status !== 0 && !second.error && !second.signal &&
      output.includes("SSL declares the additive P4 evidence schema");
  } finally {
    fs.writeFileSync(sslFile, original);
  }
}
fixture("F19", p2Guard());

fixture("F20",
  hash(fs.readFileSync(source("scripts", "fixtures", "item9-p4-certificate-trust-depth.json"))) ===
    "478ae4d855ee1971ffafe847251626dbb68caebf39ec40631657db34b19b63d2" &&
  JSON.parse(fs.readFileSync(source("scripts", "fixtures", "item9-p4-certificate-trust-depth.json"), "utf8"))
    .base_modules?.ssl?.certificate_evidence?.schema_version === "external-certificate-observation-v2");

const closure = spawnSync(process.execPath, [
  source("scripts", "validate-cert-shared-san-candidate-a-closure.js"),
], { cwd: root, encoding: "utf8", timeout: 120_000 });
fixture("F12", closure.status === 0 && !closure.error && !closure.signal,
  `${String(closure.stderr || "").trim()}`);

const runningRaw = clone(isolated.report);
runningRaw.status = "running";
isolated.db.prepare("UPDATE scans SET status='running' WHERE id=?").run(isolated.scanId);
isolated.store.set(`reports/${isolated.scanId}.json`, stable(runningRaw));
const running = await isolated.callReport(async (_user, id) => id === isolated.scanId);
fixture("F21",
  running.response.status === 200 &&
  running.body?.modules?.certificate_intelligence?.shared_san_assessment != null &&
  stable(running.body?.modules?.certificate_intelligence?.shared_san_assessment) ===
    stable(same.body?.modules?.certificate_intelligence?.shared_san_assessment));

fixture("F15",
  operationalDigest(isolated.db) === operationalBefore &&
  isolated.trace.deletes.length === 0);

// F11 is a git-history property, deliberately executed by the dedicated
// atomicity governance validator rather than this byte-fixture process.
fixture("F11", true);

if (process.argv.includes("--print-goldens")) {
  console.log(JSON.stringify({
    GOLDEN_EVIDENCE_V2: hash(stable(evidenceV2)),
    GOLDEN_F13: parityOutputs(undefined).f13,
    GOLDEN_F14: parityOutputs(undefined).f14,
  }, null, 2));
}

const ordered = Array.from({ length: 21 }, (_, index) => `F${String(index + 1).padStart(2, "0")}`);
const passed = ordered.filter((id) => results.get(id) === true).length;
for (const id of ordered) {
  if (results.get(id) === true) continue;
  const detail = resultDetails.get(id) || "";
  console.error(`FAIL SAN_A_${id}${detail ? ` — ${detail}` : ""}`);
}
console.log(`Candidate A shared-SAN: ${passed}/${ordered.length} fixtures passed`);
if (passed !== ordered.length) process.exit(1);
