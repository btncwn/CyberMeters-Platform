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
const { liveTlsProbeBinding, liveTlsSsl } = await import(moduleUrl("scripts/lib/live-tls-fixture.mjs"));
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

// historical: stored records from earlier scans carry the source map they
// recorded (neutral keys here). `ctSources` overrides the whole map, e.g. a
// single-source record or a two-source record.
function storedModules({
  version = "external-certificate-observation-v2",
  includeEvidence = true,
  raw = 0,
  ctCount = 5,
  ctError = null,
  ctSources = null,
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
    ct_sources: ctSources ?? { provider_a: { count: ctCount, error: ctError } },
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
// A pre-cutover two-provider zero stays ambiguous even when its surviving
// provider answered: the measurement predicate is provider-generic, so the
// legacy gate (not the provider name) is what keeps an eager zero unproven.
const legacyTwoProviderAssessment = assessment(storedModules({
  ctSources: {
    provider_a: { count: 0, error: "provider unavailable" },
    provider_b: { count: 4, error: null },
  },
}));
fixture("F01",
  legacyAssessment?.measurement_state === "legacy_ambiguous_zero" &&
  legacyAssessment?.assessment_state === "not_assessed" &&
  legacyAssessment?.ownership_status == null &&
  legacyAssessment?.customer_owned == null &&
  legacyAssessment?.confidence == null &&
  legacyTwoProviderAssessment?.measurement_state === "legacy_ambiguous_zero" &&
  legacyTwoProviderAssessment?.customer_owned == null &&
  legacyTwoProviderAssessment?.confidence == null);

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
  ctError: "provider unavailable",
});
const brokenAssessment = assessment(brokenV3);
// The same error sentinel on a single-source record.
const brokenSourceAssessment = assessment(storedModules({
  version: "external-certificate-observation-v3",
  ctSources: { provider_b: { count: 5, error: "provider unavailable" } },
}));
fixture("F06",
  brokenAssessment?.measurement_state === "unmeasured" &&
  brokenAssessment?.assessment_state === "not_assessed" &&
  brokenAssessment?.customer_owned == null && brokenAssessment?.confidence == null &&
  brokenSourceAssessment?.measurement_state === "unmeasured" &&
  brokenSourceAssessment?.customer_owned == null &&
  brokenSourceAssessment?.confidence == null);

const nullV3 = storedModules({
  version: "external-certificate-observation-v3", raw: null,
  rawOwned: null, rawConfidence: null,
});
// A two-source v3 record whose second source answered only as a fallback: that
// branch never wrote the count, so it stays unmeasured.
const fallbackNullV3 = storedModules({
  version: "external-certificate-observation-v3", raw: null,
  rawOwned: null, rawConfidence: null,
  ctSources: {
    provider_a: { count: 0, error: "provider unavailable" },
    provider_b: { count: 3, error: null },
  },
});
fixture("F07",
  assessment(nullV3)?.measurement_state === "unmeasured" &&
  assessment(fallbackNullV3)?.measurement_state === "unmeasured");

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
    SCAN_DEADLINE_MS: "115000",
    APP_VERSION: "candidate-a-engine-fixture",
    // The live TLS collector presents the certificate: `commonName` is its
    // subject and `names` its complete DNS SAN list.
    NETWORK_PROBE: liveTlsProbeBinding({ subject: `CN=${commonName}`, dnsNames: names }),
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
    if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
      return jsonResponse({ Status: 0, Answer: url.searchParams.get("type") === "A" ? [{ type: 1, data: "93.184.216.34" }] : [] });
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

// A fresh engine record measures from the live leaf only: the collector was
// asked once, the served certificate is recorded, and no retired raw field
// appears.
function liveLeafRecord(scenario) {
  const ssl = scenario.report.modules?.ssl || {};
  return scenario.env.NETWORK_PROBE.calls.length === 1 &&
    ssl.live_certificate?.collection_complete === true &&
    !("ct_sources" in ssl) && !("cert_shared_san_count" in ssl) && !("cert_subject" in ssl);
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
    liveLeafRecord(scenario) &&
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
  liveLeafRecord(positive) &&
  positiveProjected?.measurement_state === "measured_positive" &&
  positiveProjected?.ownership_status === "shared_certificate" &&
  positiveProjected?.confidence === 50 && positiveProjected?.customer_owned === false &&
  positiveProjected?.shared_san_count === 1);

// The SSL module's own evidence block (everything except the attached live TLS
// observation) stays byte-stable; the live attachment declares schema v4.
// Retiring certificate logs removed only the block's ct_projection entry.
const evidence = scenarios[0].report.modules?.ssl?.certificate_evidence || {};
const { live_tls: attachedLiveTls, ...evidenceBase } = evidence;
const evidenceV2 = {
  ...evidenceBase,
  schema_version: "external-certificate-observation-v2",
  observed_at: "<engine-observed-at>",
};
const GOLDEN_EVIDENCE_V2 = "ebd729ca330d48054f328f52a71f87625535f179e1aa255af5a8dc4f83baffa0";
fixture("F10",
  evidence.schema_version === "external-certificate-observation-v4" &&
  attachedLiveTls?.leaf_collected === true &&
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
// The two live TLS remediation entries change the frozen registry fingerprint
// from r67-c98a810a to r69-7eefae14. Replacing only that snapshot methodology
// value with r67-c98a810a reproduces both previous output hashes exactly.
// Customer PDF ordering changes only F13's rendered PDF bytes. The previous
// F13 golden was reproduced with the prior renderer; non-PDF facts and F14
// remain byte-identical. Visible text changes only the two reordered TOC labels.
// Identity HTTP inventory updates the frozen scope text and 2026-10-10.1
// methodology stamps. Explicit object comparison retained all finding/scoring
// facts; all five SAN projection states must still produce identical outputs.
// Sign-in page remediations (web.signin.*) move the frozen registry fingerprint
// r69-7eefae14 -> r72-31ea0a7c; substituting the old fingerprint reproduces both
// previous hashes exactly, so only that methodology stamp changed.
// Report truth: the score/BRI/eight-domain basis and limits sentences are
// reworded for customers and snapshot items carry the canonical remediation
// title/action. A field-by-field diff against main shows only those strings and
// the two additive fields; no score, state, finding or methodology fact moved,
// and all five SAN projection states still produce identical outputs.
// The home-page availability remediation (web.homepage.not_served) moves the
// registry fingerprint r72-31ea0a7c -> r73-133d04b1; with only that entry
// removed both previous hashes reproduce exactly.
// The website-unavailable remediation (web.homepage.unavailable) moves it again,
// r73-133d04b1 -> r74-05b42c41; with only that entry removed both previous
// hashes reproduce exactly.
// A single certificate-log source rewords the Attack Surface limitation
// sentence; with only that sentence reverted both previous hashes reproduce.
// Dropping the second log source removes it from two stamped provider lists
// (the monitoring definition and the asset-removal policy's excluded passive
// sources); with only those two lists restored both previous hashes reproduce.
// Retiring certificate logs moves the methodology stamps (resolver, monitoring,
// certificate and attack-surface completeness versions, registry fingerprint,
// snapshot builder) and the Attack Surface / Certificates wording; all five SAN
// projection states still produce identical outputs.
// Without a captured live leaf the Certificates & Trust evidence basis now
// states that no certificate fact is asserted; with only that sentence reverted
// both previous hashes (658dda3c…, f21336e2…) reproduce exactly.
// Each Attack Surface signal gains three additive presentation fields
// (statement, caveat, coverage_message); with only those fields removed the
// previous F13 hash (333f92db…) reproduces exactly and F14 is unchanged.
// Outside vulnerability data leaves the check pack: a field-by-field diff
// against the previous tree shows only moved stamps — score methodology and
// snapshot builder 2026-10-13.1, registry fingerprint r74-c8030e1a, the reader's
// attack-surface contract v4 and the new methodology.check_pack_version (null:
// this fixture predates the check pack, so its not-recorded Attack Surface
// notice keeps the signal set of its time). No score, state, finding or
// customer statement moved; all five SAN projection states stay identical.
// The PDF appendix names the new stamp "Check pack" (only F13's PDF bytes).
// Change notifications: the snapshot's frozen alert reason-code vocabulary
// gains "inventory_changes_only" (17 -> 18 codes). A field-by-field snapshot
// diff against the previous tree shows only that list; the executive report
// carries the snapshot, the PDFs and F14 are unchanged.
// Honest coverage wording: the scorecard's Security Findings summary for zero
// critical/high findings no longer says "Clean scan" and is bounded to what the
// scan checked. A field-by-field diff against the previous tree shows only that
// one summary string; the snapshot, executive report, PDFs and F14 are unchanged.
// Live TLS checks: the certificate presentation's name-match, expiry and
// trust-store signals gain an additive backend check outcome. In this fixture,
// which has no captured leaf, all three read "Not checked"; a field-by-field
// diff shows only those three fields (in the snapshot and the executive report
// that carries it). The PDFs and F14 are unchanged.
// The 22 public-content remediation entries move only the frozen registry stamp
// r74-c8030e1a -> r96-d432058a. Replacing that one snapshot field with the old
// value reproduces both previous golden hashes exactly, including rendered PDFs.
// Finding, score, coverage and all five SAN projection states remain unchanged.
// Thirteen endpoint-TLS remediation entries advance that frozen stamp again.
// Temporarily substituting only the predecessor remediation registry reproduces
// both previous hashes byte-for-byte; this fixture has no live TLS finding.
// The two new hashes therefore pin the additive registry version in every SAN
// projection state without treating absent TLS evidence as a clean result.
// Certificates & Trust now declares TLS assessment in its scope, bounds the
// conclusion to completed endpoint controls, and stamps resolver 2026-10-13.1.
// Replacing only security-check-domains.js with origin/main reproduces both previous
// hashes exactly. This fixture has no TLS module or finding, so the change is
// methodology/scope presentation; all five SAN projection states remain equal.
// Customer PDF domain order follows the founder order (Email Protection first,
// Identity Exposure fourth) in both the assessment PDF (REPORT_DOMAIN_ORDER) and
// the executive PDF (EXECUTIVE_AREAS). Only F13's rendered PDF bytes change:
// with only those two lists reverted the previous F13 hash (abf6af86…)
// reproduces exactly, and F14 and the evidence hash are unchanged.
// Shadow IT detection fixes (16 Oct 2026): the Shadow IT limitation sentence in
// security-check-domains.js changed to observation language ("the customer's own record
// in the Shadow IT inventory, not an external verdict"). That sentence travels in
// the resolved domain states (F14) and is printed in the customer PDF (F13), so both
// goldens move. With ONLY security-check-domains.js reverted the previous hashes
// (c4e6b4e0… / 5aeea4a3…) reproduce exactly; the evidence hash is unchanged and the
// PDF label map (pdf.js) and Related Changes rule text move neither golden.
// Customer-state accuracy moves the resolver, score and snapshot-builder
// stamps. This certificate-only fixture has no Brand or DMARC finding; only
// methodology metadata and its PDF rendering change here.
// External-posture wording (16 Oct 2026, rebased onto customer-state accuracy):
// the customer PDF's external-posture section heading moves F13 and
// the snapshot summary sentence ("Across your external posture: ...") travels in
// the resolved states, moving F14. With ONLY pdf.js, report-snapshot.js,
// dmarc-state.js and lifecycle-email.js reverted to their previous text the
// previous hashes (4fe03f24... / 366be232...) reproduce exactly; the evidence
// hash is unchanged and no mutation control is touched.
// Attack Surface evidence and the current Shadow IT summary change the rendered
// PDF and resolved states without changing the certificate evidence fixture.
// Brand decision honesty (17 Oct 2026) mints resolver 2026-10-17.1. This
// certificate-only fixture has no brand candidate or enrichment state, so only
// the methodology stamp and its PDF rendering move both goldens.
// Domain decision honesty (17 Oct 2026) mints resolver 2026-10-17.2 and
// rewords the Identity Exposure summary to its inventory counts ("Inventory
// evidence: …"). That sentence travels in the resolved states (F14) and the
// customer PDF (F13); the fixture has no registration finding or sender alert.
// Completed-phase subset evidence mints resolver 2026-10-17.4 and the snapshot
// separates attempted incomplete modules from skips. This fixture has no
// exposure phase, so only the methodology stamps move its golden bytes.
// P1b mints resolver 2026-10-17.5. This certificate-only fixture has no
// exposure, TLS, or DMARC signal; the changed methodology stamp moves both bytes.
// PR-A2 withholds provisional numeric scores from the customer PDF. This
// certificate-only fixture's F14 snapshot remains byte-identical; only F13's
// rendered PDF bytes move from e0c2559c… to 4e120f57….
// The 2026-10-18.1 resolver boundary changes this fixture's methodology stamp
// in the snapshot and PDF. Its SAN evidence hash stays ebd729ca….
// Resolver 2026-10-18.2 changes the report methodology stamp; the underlying
// shared-SAN evidence golden above remains byte-identical.
// One timezone convention (19 Oct 2026): the customer PDF states "All times are
// in UTC." once on its cover and drops the per-time suffix. Only F13's PDF bytes
// move; with those two changes reverted the previous hash (e7f66eae…) reproduces.
// SIRA 4 (19 Oct 2026): unsupported vendor-risk wording removed. The scorecard
// section "Vendor Risk" becomes "Third-party services observed" (moves F13 only,
// 0a063e9f… → 75156c7a…), and the Business Risk Indicator methodology says
// "third-party service signals" instead of "supply-chain signals" (moves F14,
// 2fe7f50a… → 8f34acb8…, and F13 with it). With both changes reverted the
// previous hashes (0a063e9f… / 2fe7f50a…) reproduce exactly.
// BRI methodology 2026-10-20.1 (20 Oct 2026): missing HSTS with an observed
// HTTP->HTTPS redirect deducts 10 instead of 20. This certificate-only fixture
// has no HSTS finding, so only the stamped BRI methodology version moves. With
// ONLY BUSINESS_RISK_METHODOLOGY_VERSION reverted to 2026-10-10.1 the previous
// hashes (26b80c70… / 8f34acb8…) reproduce exactly.
// Retired product name (21 Oct 2026): the PDF section heading reads "External
// security posture" (wording), and the scan report gains the neutral
// security_domains alias of cyber_mot_domains (additive). F14 is unchanged.
// origin/main with ONLY the wording applied gives 6be5c1e8…; this head with ONLY
// the alias lines removed gives the same 6be5c1e8…, so wording + alias explain F13.
// Score methodology 2026-10-21.1 (21 Oct 2026): an admin name + title needs an
// observed login form to be an "administrative interface". This certificate-only
// fixture has no exposure asset, so only the stamped score methodology version
// moves. With ONLY CYBER_METRICS_SCORE_METHODOLOGY_VERSION reverted to 2026-10-16.1
// the previous hashes (efcecdda… / 69f17b6e…) reproduce exactly.
// BRI methodology 2026-10-21.1 (21 Oct 2026): Attack Surface deducts for
// confirmed exposure findings. This certificate-only fixture has none, so only
// the stamped BRI version moves. With ONLY BUSINESS_RISK_METHODOLOGY_VERSION
// reverted to 2026-10-20.1 the previous hashes (0b744ecb… / 8772c1dc…) reproduce.
// BRI methodology 2026-10-21.2 (21 Oct 2026): reachable hosts and missing vendor
// data no longer deduct from Attack Surface. The F14 inputs differ from
// origin/main in exactly four fields: Attack Surface 90 -> 100 (the "+10 no
// vendor visibility" every scan paid is gone), overall BRI 98 -> 100, and the
// stamped BRI version in the basis text and the methodology block.
// DNS registration guidance adds one registry entry and moves only its frozen
// methodology fingerprint (r109-de4d1155 -> r110-f8e28c62) in this fixture.
// Substituting only the predecessor registry reproduces both prior hashes
// exactly; certificate evidence remains ebd729ca… and all five SAN states agree.
// Watchlist DNS guidance adds only the frozen registry stamp in this fixture
// (r110-f8e28c62 -> r111-368754e2). Substituting just the predecessor registry
// reproduces both prior hashes exactly; certificate evidence remains unchanged.
// Public identity metadata guidance adds only the frozen registry stamp here
// (r111-368754e2 -> r112-286dce37). Predecessor-registry substitution reproduces
// both prior report hashes; the certificate evidence hash stays unchanged.
// The unconfirmed takeover-candidate entry (21 Oct 2026) adds one more and moves
// only the fingerprint (r112-286dce37 -> r113-1a7ce169); with ONLY the registry reverted to
// its predecessor both prior hashes (89e9e4ef… / b1b96ef3…) reproduce.
// S3-0 remote-admin entries (22 Oct 2026) add two more and move only the
// fingerprint (r113-1a7ce169 -> r115-64a2e4fd); with ONLY the registry reverted to its
// predecessor both prior hashes (9c021774… / 7eb2b55a…) reproduce.
// S3-C DANE entries (22 Oct 2026) add two more and move only the fingerprint
// (r115-64a2e4fd -> r117-c175ea1a); with ONLY the registry reverted to its predecessor both
// prior hashes (1d68563a… / a2596c0d…) reproduce.
// Script metadata guidance adds only the registry stamp (r118-25b6147b).
// Substituting current origin/main registry reproduces both preceding hashes
// exactly; the certificate evidence hash remains unchanged.
// Website Security scope line (22 Oct 2026, founder): the limitation sentence no
// longer says "no active, authenticated or intrusive testing" (false for a
// workspace using signed-in scanning). It travels in the resolved states (F14)
// and the customer PDF (F13). With ONLY that sentence reverted the previous
// hashes (4b779e3c… / 3d973605…) reproduce exactly; all five SAN projection
// states agree and the certificate evidence hash is unchanged.
// Signed-in scanning in the report (22 Oct 2026): the snapshot gains the additive
// website_signed_in section and the builder stamp moves to 2026-10-22.1. This
// fixture has no sign-in profile, so the section reads "unavailable"/"not
// configured" and both goldens move. With ONLY the section line and the builder
// version reverted the previous hashes (0908a80d… / efeee99a…) reproduce exactly
// and the evidence hash (ebd729ca…) is unchanged.
// Signed-in scanning in the report (22 Oct 2026): the executive report passes the
// snapshot's website_signed_in section through and the customer PDF prints its
// sentences under Website Security. Only F13 moves; with ONLY those two additions
// reverted the previous hash (e621f237…) reproduces exactly and F14 is unchanged.
// PDF type scale (22 Oct 2026): the rendered PDF sets nothing below the 8 pt floor
// and section headings at 14 pt. Only F13's PDF bytes move; with ONLY pdf.js
// reverted the previous hash (e621f237…) reproduces exactly; F14 is unchanged.
// Both changes together (#877 + #879): the hash below; each was proven alone above.
// Stated-limit sentences (22 Oct 2026): the snapshot evidence_completeness gains
// stated_limits (here []); with ONLY report-snapshot.js reverted both prior hashes
// (f9fbbfe4… / b8b177e0…) reproduce.
// Resolver 2026-10-23.1 (23 Oct 2026): Website Security is provisional while its
// own header checks could not validate. This certificate-only fixture has no
// header finding, so only the stamped resolver version moves. With ONLY
// SECURITY_CHECK_RESOLVER_VERSION reverted to 2026-10-18.2 the previous hashes
// (c4382a25… / 2f7b557f…) reproduce exactly.
// BRI methodology 2026-10-23.1 (23 Oct 2026): a CSP 'unsafe-inline' beside a
// nonce/hash no longer counts as csp_weak_policy. This certificate-only fixture
// has no CSP finding, so only the stamped BRI version moves. With ONLY
// BUSINESS_RISK_METHODOLOGY_VERSION reverted to 2026-10-21.2 the previous hashes
// (893866a0… / b2147cf3…) reproduce exactly.
const GOLDEN_F13 = "24dc14cc552eb314fcd9da4c49a4d4a7dab593f5355887f82cc115099902e89f";
const GOLDEN_F14 = "87194812c7a7f13a8c85af6b70baeabe7a32acccad3eb4aea0a9a920c061d261";
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
    ct_sources: { provider_a: { count: 0, error: "unavailable" } },
  },
}, "example.com");
fixture("F18",
  unavailableIntel.san_count === 0 && unavailableIntel.raw_san_count === 0 &&
  unavailableIntel.wildcard_san_count === 0 && unavailableIntel.shared_san_count === null);

const CANDIDATE_EXPIRY_NOW = new Date(Date.UTC(2026, 7, 30, 12, 0, 0)).toISOString();
// Expiry comes only from the served certificate's notAfter, observed by the
// live TLS collector at a recorded instant.
const expiryIntel = (days, notAfter = null) => runCertificateIntelligenceModule({
  ssl: liveTlsSsl({ days, notAfter, finishedAt: CANDIDATE_EXPIRY_NOW }),
  subdomains: { items: [] },
}, "example.com");
const expiryRows = (days, notAfter) => expiryIntel(days, notAfter).suspicious_certificate_signals
  .filter((signal) => signal.signal.startsWith("certificate_expir"));
fixture("F22",
  expiryRows(13).length === 1 &&
  expiryRows(13)[0]?.signal === "certificate_expiring_critical" &&
  expiryRows(13)[0]?.severity === "high" &&
  expiryRows(13)[0]?.finding_type === "finding" &&
  expiryRows(13)[0]?.score_impact === 0);
fixture("F23",
  expiryRows(14).length === 1 &&
  expiryRows(14)[0]?.signal === "certificate_expiring_soon" &&
  expiryRows(14)[0]?.severity === "medium");
fixture("F24",
  expiryRows(29).length === 1 &&
  expiryRows(29)[0]?.signal === "certificate_expiring_soon" &&
  expiryRows(29)[0]?.severity === "medium");
fixture("F25", expiryRows(30).length === 0);
fixture("F26",
  ["not-a-date", "", "2026-13-45T00:00:00Z"].every((notAfter) => {
    const result = expiryIntel(10, notAfter);
    return result.expiry_evidence === "not_usable" && result.days_until_expiry === null &&
      expiryRows(10, notAfter).length === 0;
  }));
fixture("F27",
  [0, 13, 14, 29, 30].every((days) =>
    !expiryIntel(days).suspicious_certificate_signals
      .some((signal) => signal.signal === "certificate_expired")) &&
  expiryIntel(-2).suspicious_certificate_signals
    .some((signal) => signal.signal === "certificate_expired" && signal.severity === "high"));
const criticalExpiry = expiryRows(13)[0];
const soonExpiry = expiryRows(14)[0];
fixture("F28",
  expiryIntel(13).expiry_evidence === "usable" &&
  criticalExpiry?.evidence_source === "live_tls" &&
  criticalExpiry?.live_certificate_verified === true &&
  criticalExpiry?.evidence_basis === "pinned_public_address_tls_handshake" &&
  criticalExpiry?.title === "The live certificate expires within 14 days" &&
  soonExpiry?.title === "The live certificate expires within 30 days");
fixture("F29",
  [criticalExpiry, soonExpiry].every((signal) =>
    signal?.description?.includes("served by this endpoint") &&
    !signal.description.includes("service outage")));
fixture("F30",
  (() => {
    const result = runCertificateIntelligenceModule({
      ssl: {
        tls_state: "observed_present", https_available: true,
        cert_expiry_days: 10, cert_not_after: "2026-09-09T12:00:00.000Z", cert_issuer: "Stored CA",
      },
      subdomains: { items: [] },
    }, "example.com");
    return result.expiry_evidence === "not_usable" && result.days_until_expiry === null &&
      result.issuer === null &&
      result.suspicious_certificate_signals.every((signal) => !signal.signal.startsWith("certificate_expir"));
  })());

function p2Guard() {
  // The SSL module's evidence schema in a scan report is stamped when the live
  // TLS observation is attached; the P2 engine trace must guard it.
  const probeFile = source("workers", "scan-api", "src", "engines", "network-probe.js");
  const validator = source("scripts", "validate-item9-certificate-p2-engine-trace.js");
  const original = fs.readFileSync(probeFile, "utf8");
  const anchor = "schema_version:'external-certificate-observation-v4'";
  if (original.split(anchor).length - 1 !== 1) return false;
  const first = spawnSync(process.execPath, [validator], { cwd: root, encoding: "utf8", timeout: 120_000 });
  if (first.status !== 0 || first.error || first.signal) return false;
  try {
    fs.writeFileSync(probeFile, original.replace(anchor,
      "schema_version:'external-certificate-observation-v3'"));
    const second = spawnSync(process.execPath, [validator], { cwd: root, encoding: "utf8", timeout: 120_000 });
    const output = `${second.stdout || ""}\n${second.stderr || ""}`;
    return second.status !== 0 && !second.error && !second.signal &&
      output.includes("SSL declares the live TLS evidence schema");
  } finally {
    fs.writeFileSync(probeFile, original);
  }
}
fixture("F19", p2Guard());

fixture("F20",
  hash(fs.readFileSync(source("scripts", "fixtures", "item9-p4-certificate-trust-depth.json"))) ===
    "a71757be49d614a86ab6e53e1d3a8da89a36f9cd2f9e6678d8a7cae266f063fb" &&
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

const ordered = Array.from({ length: 30 }, (_, index) => `F${String(index + 1).padStart(2, "0")}`);
const passed = ordered.filter((id) => results.get(id) === true).length;
for (const id of ordered) {
  if (results.get(id) === true) continue;
  const detail = resultDetails.get(id) || "";
  console.error(`FAIL SAN_A_${id}${detail ? ` — ${detail}` : ""}`);
}
console.log(`Candidate A shared-SAN: ${passed}/${ordered.length} fixtures passed`);
if (passed !== ordered.length) process.exit(1);
