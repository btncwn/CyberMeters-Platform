#!/usr/bin/env node
// Historical Phase-5 customer-read P1: immutable snapshot + customer projection.
// Node 24+ (node:sqlite). CI-blocking, network-free and write-free outside its
// in-memory fixtures.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (name) => import(pathToFileURL(path.join(
  root, "workers/scan-api/src/engines", name,
)).href);
const route = (name) => import(pathToFileURL(path.join(
  root, "workers/scan-api/src/routes", name,
)).href);

const {
  PHASE5_EVIDENCE_MODULES,
  projectPhase5EvidenceForCustomer,
  projectPhase5RiskIntelligenceForCustomer,
  projectPhase5SnapshotForCustomer,
  resolvePhase5EvidenceContract,
} = await eng("phase5-evidence.js");
const {
  readScanReportSnapshot,
  snapshotSha256Hex,
} = await eng("report-snapshot.js");
const { buildExecutiveReportV2 } = await eng("executive-report.js");
const { buildScanReportPdf, buildWorkspaceExecutivePdf } = await eng("pdf.js");
const { buildScorecardData } = await eng("scorecard.js");
const { computePortfolioDomainRows } = await eng("portfolio-domains.js");
const { getCurrentPosturePresentation } = await eng("current-posture.js");
const { runHistoricalModule } = await eng("historical-scan.js");
const { scanRoutes } = await route("scans.js");
const { executiveDashboardRoutes } = await route("executive-dashboard.js");
const { CYBER_MOT_DOMAIN_KEYS } = await eng("cyber-mot-state-history.js");

const healthyMonitoringStates = {
  version: "signal-monitoring-state-v1",
  signals: Object.fromEntries([
    "dns",
    "certificate_transparency",
    "website_security",
    "email_protection",
    "attack_surface",
    "technology_visibility",
    "vulnerability_intelligence",
    "registration_data",
  ].map((signal) => [signal, {
    state: "monitoring_healthy",
    message: `${signal} checks completed normally in this run.`,
    evidence: { modules: [], incomplete_modules: [], providers: {} },
  }])),
};

const completedCve = (overrides = {}) => ({
  technologies_checked: ["nginx"],
  lookup_statuses: { nginx: "completed" },
  results: { nginx: [] },
  total_cves: 0,
  critical_count: 0,
  high_count: 0,
  source: "nvd_api",
  ...overrides,
});
const completedKev = (overrides = {}) => ({
  matches: [],
  checked: 100,
  matched: 0,
  source: "cisa_kev",
  ...overrides,
});
const completedEmail = (overrides = {}) => ({
  mta_sts: { configured: true },
  tls_rpt: { configured: true },
  email_security_score: 100,
  rating: "excellent",
  business_email_risk: "Low",
  findings: [],
  ...overrides,
});
const deferred = (base) => ({
  ...base,
  executed: false,
  incomplete: true,
  outcome: "deadline_exceeded",
  reason: "scan_deadline_exhausted",
});
const completedModules = () => ({
  cve_intelligence: completedCve(),
  known_exploited_vulnerabilities: completedKev(),
  email_security_intelligence: completedEmail(),
});

function snapshotFor({ scanId, workspaceId, domainId, domain, findings = [] }) {
  return {
    snapshot: {
      snapshot_id: `snap-${scanId}`,
      snapshot_schema_version: "1",
      status: "completed",
      workspace_id: workspaceId,
      domain_id: domainId,
      scan_id: scanId,
      domain,
      as_of: "2026-07-20T10:00:00.000Z",
      scan_started_at: "2026-07-20T09:59:40.000Z",
      scan_completed_at: "2026-07-20T10:00:00.000Z",
      built_at: "2026-07-20T10:00:01.000Z",
      provenance: "scan_finalize",
    },
    methodology: {},
    overall: {
      cyber_metrics_score: 100,
      score_band: "excellent",
      assessment: {
        raw_score: 100,
        display_score: 100,
        display_rating: "excellent",
        quality: "complete",
        provisional: false,
        authoritative: true,
        comparable: true,
        message: null,
      },
      summary: "No critical or high-severity issues detected.",
      business_risk_indicator: {
        band: "Low",
        explanation: "No critical or high-severity issues detected.",
        provisional: false,
        internal_metrics: { score: 100, categories: {}, top_business_risks: [] },
      },
      evidence_completeness: {
        scan_quality: "complete",
        assessment_quality: "complete",
      },
      not_fully_assessed: [],
    },
    monitoring_states: healthyMonitoringStates,
    domains: [],
    observed_findings: findings,
    observations: [],
    remediation_actions: [],
    unmapped_finding_types: [],
    source_artifacts: { scan_report_r2_key: `reports/${scanId}.json` },
    limitations: [],
  };
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { meta: { changes: result.changes } };
    },
    __sql: sql,
    __args: args,
  });
  return {
    prepare(sql) {
      const base = wrap(sql, []);
      base.bind = (...args) => wrap(sql, args);
      return base;
    },
    async batch(statements) {
      const out = [];
      for (const statement of statements) {
        out.push(/^\s*(select|with)\b/i.test(statement.__sql)
          ? await statement.all()
          : await statement.run());
      }
      return out;
    },
  };
}

async function fixtureEnvironment() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* migration ordering */ }
  };
  apply(path.join(root, "database/schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database/migrations"))
    .filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");

  db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('usr-hist','hist@example.test',1)").run();
  db.prepare(`INSERT INTO subscriptions
    (id, owner_user_id, plan, subscription_status, current_period_end)
    VALUES ('sub-hist','usr-hist','professional','active',datetime('now','+30 days'))`).run();

  const store = new Map();
  const d1 = makeD1(db);
  const env = {
    cybermeters_db: d1,
    cybermeters_reports: {
      get: async (key) => {
        if (!store.has(key)) return null;
        const body = store.get(key);
        return {
          text: async () => body,
          json: async () => JSON.parse(body),
          arrayBuffer: async () => new TextEncoder().encode(body).buffer,
        };
      },
    },
  };

  let stateId = 0;
  async function addFixture({
    name,
    modules,
    scanQuality,
    findings = [],
    createdAt,
  }) {
    const workspaceId = `ws-${name}`;
    const domainId = `dom-${name}`;
    const scanId = `scan-${name}`;
    const domain = `${name}.example`;
    db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES (?,?,?)")
      .run(workspaceId, name, "usr-hist");
    db.prepare("INSERT INTO workspace_members (workspace_id,user_id,role) VALUES (?,?,'owner')")
      .run(workspaceId, "usr-hist");
    db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)")
      .run(domainId, "usr-hist", domain);
    db.prepare(`INSERT INTO workspace_domains
      (workspace_id,domain_id,verification_status) VALUES (?,?,'verified')`)
      .run(workspaceId, domainId);
    db.prepare(`INSERT INTO scans
      (id,domain_id,domain,workspace_id,status,score,rating,scan_quality,created_at)
      VALUES (?,?,?,?,'completed',100,'excellent',?,?)`)
      .run(scanId, domainId, domain, workspaceId, scanQuality, createdAt);

    const report = {
      scan_id: scanId,
      domain,
      status: "completed",
      cyber_metrics_score: 100,
      risk_level: "excellent",
      scan_quality: { status: scanQuality },
      monitoring_states: healthyMonitoringStates,
      completed_at: "2026-07-20T10:00:00.000Z",
      findings,
      recommendations: [],
      modules: {
        ...modules,
        risk_intelligence: {
          overall_risk_level: "Low",
          narrative: "No critical or high-severity issues detected.",
          finding_counts: {
            critical: 0,
            high: findings.filter((finding) => finding.severity === "high").length,
            medium: 0,
            low: 0,
          },
          risk_categories: findings.length
            ? { "Web Security": findings }
            : {},
          enriched_findings: findings,
        },
        remediation_plan: {
          summary: { p1_count: 0, p2_count: 0, p3_count: 0 },
          immediate_actions: [],
          short_term_actions: [],
          strategic_actions: [],
        },
      },
    };
    const snapshot = snapshotFor({
      scanId, workspaceId, domainId, domain, findings,
    });
    const snapshotRaw = JSON.stringify(snapshot);
    const checksum = await snapshotSha256Hex(snapshotRaw);
    const snapshotKey = `reports/snapshots/${scanId}.json`;
    store.set(`reports/${scanId}.json`, JSON.stringify(report));
    store.set(snapshotKey, snapshotRaw);
    db.prepare(`INSERT INTO scan_report_snapshots
      (id,workspace_id,domain_id,scan_id,status,r2_key,checksum_sha256,
       size_bytes,snapshot_schema_version,resolver_version,scan_quality,
       assessed_at,created_at,completed_at)
      VALUES (?,?,?,?, 'completed',?,?,?,?,?,?,?, ?,?)`)
      .run(
        `snap-${scanId}`, workspaceId, domainId, scanId, snapshotKey, checksum,
        new TextEncoder().encode(snapshotRaw).length, "1", "fixture",
        scanQuality, "2026-07-20T10:00:00.000Z",
        "2026-07-20T10:00:01.000Z", "2026-07-20T10:00:01.000Z",
      );

    for (const domainKey of CYBER_MOT_DOMAIN_KEYS) {
      db.prepare(`INSERT INTO cyber_mot_domain_states
        (id,workspace_id,domain_id,scan_id,domain_key,state,coverage,summary,
         finding_count,evidence_count,finding_ids_json,scan_quality,resolver_version,assessed_at)
        VALUES (?,?,?,?,?,'assessed_healthy','complete',
          'Assessed — no material issue observed.',0,1,'[]',?,'fixture',?)`)
        .run(
          `state-${++stateId}`, workspaceId, domainId, scanId, domainKey,
          scanQuality, "2026-07-20T10:00:00.000Z",
        );
    }
    return {
      workspaceId, domainId, scanId, domain, report, snapshot, snapshotRaw, checksum,
    };
  }

  const sibling = {
    id: "trusted-sibling",
    module: "headers",
    severity: "high",
    title: "Trustworthy sibling header finding",
    description: "Observed by a completed sibling module.",
  };
  const incomplete = await addFixture({
    name: "incomplete",
    modules: {
      ...completedModules(),
      cve_intelligence: deferred(completedCve()),
    },
    scanQuality: "partial",
    findings: [sibling],
    createdAt: "2026-07-20T10:00:00.000Z",
  });
  const missing = await addFixture({
    name: "missing",
    modules: {
      known_exploited_vulnerabilities: completedKev(),
      email_security_intelligence: completedEmail(),
    },
    scanQuality: "complete",
    createdAt: "2026-07-21T10:00:00.000Z",
  });
  const zero = await addFixture({
    name: "zero",
    modules: completedModules(),
    scanQuality: "complete",
    createdAt: "2026-07-22T10:00:00.000Z",
  });
  const positive = await addFixture({
    name: "positive",
    modules: {
      ...completedModules(),
      cve_intelligence: completedCve({
        total_cves: 1,
        critical_count: 1,
        results: { nginx: [{ id: "CVE-2099-0001", severity: "CRITICAL" }] },
      }),
      known_exploited_vulnerabilities: deferred(completedKev()),
    },
    scanQuality: "partial",
    findings: [{
      id: "CVE-2099-0001",
      module: "cve_intelligence",
      severity: "critical",
      title: "Observed CVE finding",
      description: "A completed CVE provider returned this finding.",
    }, sibling],
    createdAt: "2026-07-23T10:00:00.000Z",
  });

  return { db, env, store, incomplete, missing, zero, positive };
}

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});
const routeContext = (env, pathname) => {
  const request = new Request(`https://api.cybermeters.test${pathname}`);
  return {
    request,
    env,
    ctx: { waitUntil() {} },
    url: new URL(request.url),
    json,
    serverError: (_scope, error) => json({ error: String(error?.message || error) }, 500),
    corsHeaders: {},
    requireAuth: async () => ({ id: "usr-hist" }),
    requireWorkspaceRole: async () => ({ role: "owner" }),
    requireScanReadAccess: async () => true,
    getAccessibleWorkspaceIds: async () => [
      "ws-incomplete", "ws-missing", "ws-zero", "ws-positive",
    ],
  };
};
async function scanApi(env, pathname) {
  const response = await scanRoutes(routeContext(env, pathname));
  const type = response.headers.get("content-type") || "";
  return {
    status: response.status,
    body: type.includes("application/json") ? await response.json() : null,
    response,
  };
}

async function child(mode) {
  if (mode === "frontend") {
    try {
      execFileSync("npm", [
        "run", "test", "--", "--run",
        "src/pages/__tests__/IntelligencePage.phase5Historical.test.jsx",
        "src/lib/__tests__/phase5EvidencePresentation.test.js",
      ], {
        cwd: path.join(root, "frontend"),
        stdio: "pipe",
        timeout: 120_000,
      });
      return { passed: true };
    } catch {
      return { passed: false };
    }
  }
  if (mode === "risk") {
    const modules = { ...completedModules(), cve_intelligence: deferred(completedCve()) };
    const evidence = resolvePhase5EvidenceContract(modules);
    return projectPhase5RiskIntelligenceForCustomer({
      overall_risk_level: "Low",
      narrative: "No critical or high-severity issues detected.",
    }, evidence);
  }
  const fx = await fixtureEnvironment();
  if (mode === "report") {
    return (await scanApi(fx.env, `/api/scans/${fx.incomplete.scanId}/report`)).body;
  }
  if (mode === "snapshot") {
    return (await scanApi(fx.env, `/api/scans/${fx.incomplete.scanId}/snapshot`)).body;
  }
  if (mode === "executive") {
    const read = await readScanReportSnapshot(fx.env, fx.incomplete.scanId, { repair: false });
    return buildExecutiveReportV2({
      scan: { id: fx.incomplete.scanId, domain: fx.incomplete.domain },
      read,
    });
  }
  throw new Error(`unknown child mode ${mode}`);
}

const childArg = process.argv.find((arg) => arg.startsWith("--child="));
if (childArg) {
  process.stdout.write(JSON.stringify(await child(childArg.slice(8))));
  process.exit(0);
}

let passed = 0;
let failed = 0;
let assertions = 0;
const ok = (name, condition, detail = "") => {
  assertions += 1;
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, wanted) =>
  ok(name, got === wanted, `got ${JSON.stringify(got)} wanted ${JSON.stringify(wanted)}`);

console.log("── A. immutable snapshot and customer-route projection ──");
const fx = await fixtureEnvironment();
const incompleteRead = await readScanReportSnapshot(
  fx.env, fx.incomplete.scanId, { repair: false },
);
eq("A1 integrity-gated snapshot read succeeds", incompleteRead.status, "ok");
eq("A2 stored snapshot raw bytes remain byte-identical", incompleteRead.raw, fx.incomplete.snapshotRaw);
eq("A3 stored bytes still match the D1 checksum",
  await snapshotSha256Hex(incompleteRead.raw), fx.incomplete.checksum);
eq("A4 immutable snapshot retains frozen score", incompleteRead.snapshot.overall.cyber_metrics_score, 100);
eq("A5 customer snapshot withholds frozen score", incompleteRead.customerSnapshot.overall.cyber_metrics_score, null);
eq("A6 customer snapshot withholds frozen excellent band", incompleteRead.customerSnapshot.overall.score_band, null);
eq("A7 customer snapshot withholds frozen Low risk",
  incompleteRead.customerSnapshot.overall.business_risk_indicator.band, null);
eq("A8 customer snapshot withholds clean summary", incompleteRead.customerSnapshot.overall.summary, null);

const snapshotApi = await scanApi(fx.env, `/api/scans/${fx.incomplete.scanId}/snapshot`);
const reportApi = await scanApi(fx.env, `/api/scans/${fx.incomplete.scanId}/report`);
const scanListApi = await scanApi(
  fx.env,
  `/api/scans?workspace_id=${fx.incomplete.workspaceId}`,
);
const scanDetailApi = await scanApi(fx.env, `/api/scans/${fx.incomplete.scanId}`);
eq("A9 verbatim snapshot endpoint succeeds", snapshotApi.status, 200);
eq("A10 endpoint snapshot reserialises to exact stored bytes",
  JSON.stringify(snapshotApi.body.snapshot), fx.incomplete.snapshotRaw);
eq("A11 endpoint checksum remains the stored-byte checksum",
  snapshotApi.body.integrity.checksum_sha256, fx.incomplete.checksum);
eq("A12 customer report withholds numeric score", reportApi.body.cyber_metrics_score, null);
eq("A13 customer report withholds excellent rating", reportApi.body.risk_level, null);
eq("A14 customer report withholds derived Low risk",
  reportApi.body.modules.risk_intelligence.overall_risk_level, null);
eq("A15 customer report withholds clean narrative",
  reportApi.body.modules.risk_intelligence.narrative, null);
ok("A16 customer report states the assessment is incomplete",
  reportApi.body.assessment?.authoritative === false &&
  /incomplete/i.test(reportApi.body.assessment?.message || ""));
ok("A17 trustworthy sibling finding remains visible",
  reportApi.body.findings.some((finding) => finding.id === "trusted-sibling"));
eq("A18 scan-list D1 score is withheld by report evidence",
  scanListApi.body.scans[0]?.score, null);
eq("A19 scan-list D1 rating is withheld by report evidence",
  scanListApi.body.scans[0]?.rating, null);
eq("A20 scan-detail D1 score is withheld by report evidence",
  scanDetailApi.body.scan?.score, null);
eq("A21 scan-detail D1 rating is withheld by report evidence",
  scanDetailApi.body.scan?.rating, null);

console.log("── B. missing legacy, completed-zero and positive controls ──");
const missingApi = await scanApi(fx.env, `/api/scans/${fx.missing.scanId}/report`);
const missingCve = missingApi.body.modules.cve_intelligence;
ok("B1 missing CVE is an explicit unavailable placeholder",
  missingCve?.evidence_publishable === false &&
  missingCve?.executed === false &&
  missingCve?.outcome === "unavailable");
eq("B2 missing legacy module cannot publish score", missingApi.body.cyber_metrics_score, null);
eq("B3 missing legacy module cannot publish rating", missingApi.body.risk_level, null);

const zeroApi = await scanApi(fx.env, `/api/scans/${fx.zero.scanId}/report`);
eq("B4 completed-zero retains legitimate score 100", zeroApi.body.cyber_metrics_score, 100);
eq("B5 completed-zero retains legitimate excellent", zeroApi.body.risk_level, "excellent");
eq("B6 completed-zero retains legitimate Low",
  zeroApi.body.modules.risk_intelligence.overall_risk_level, "Low");
ok("B7 completed-zero retains legitimate clean narrative",
  /No critical or high-severity issues detected/.test(
    zeroApi.body.modules.risk_intelligence.narrative,
  ));

const positiveApi = await scanApi(fx.env, `/api/scans/${fx.positive.scanId}/report`);
eq("B8 incomplete sibling evidence still withholds overall score",
  positiveApi.body.cyber_metrics_score, null);
ok("B9 completed positive CVE finding remains visible",
  positiveApi.body.findings.some((finding) => finding.id === "CVE-2099-0001"));
ok("B10 trustworthy sibling finding remains visible with positive CVE",
  positiveApi.body.findings.some((finding) => finding.id === "trusted-sibling"));

console.log("── C. executive, PDF, posture, scorecard, dashboard and portfolio ──");
const executiveApi = await scanApi(
  fx.env, `/api/scans/${fx.incomplete.scanId}/executive-report-v2`,
);
eq("C1 executive report withholds score", executiveApi.body.cyber_metrics_score.value, null);
eq("C2 executive report withholds excellent rating", executiveApi.body.cyber_metrics_score.rating, null);
eq("C3 executive report withholds Low BRI", executiveApi.body.business_risk_indicator.band, null);
eq("C4 executive report withholds clean summary", executiveApi.body.executive_summary.summary, null);

const pdfText = new TextDecoder("latin1").decode(buildScanReportPdf(
  { id: fx.incomplete.scanId, domain: fx.incomplete.domain },
  incompleteRead,
));
ok("C5 PDF does not expose frozen 100/excellent/Low clean conclusion",
  !pdfText.includes("100 / 100") &&
  !pdfText.includes("assessment band: excellent") &&
  !pdfText.includes("No material findings were observed in this assessment."));
ok("C6 PDF states incomplete assessment", pdfText.includes("results may be incomplete"));
ok("C7 PDF retains trustworthy sibling finding",
  pdfText.includes("Trustworthy sibling header finding"));
const workspacePdfText = new TextDecoder("latin1").decode(
  buildWorkspaceExecutivePdf({
    workspaceName: "Historical Workspace",
    reads: [incompleteRead],
    generatedAt: "2026-07-29T12:00:00.000Z",
  }),
);
ok("C8 workspace PDF withholds frozen score and clean copy",
  !workspacePdfText.includes("100 / 100") &&
  !workspacePdfText.includes("No material findings were observed in this assessment."));
ok("C9 workspace PDF retains incomplete disclosure",
  workspacePdfText.includes("results may be incomplete"));

const incompletePosture = await getCurrentPosturePresentation(
  fx.env, { workspaceId: fx.incomplete.workspaceId },
);
eq("C10 incomplete historical evidence cannot establish current posture",
  incompletePosture.authoritative, null);
const zeroPosture = await getCurrentPosturePresentation(
  fx.env, { workspaceId: fx.zero.workspaceId },
);
eq("C11 completed-zero still establishes score 100",
  zeroPosture.authoritative?.display_score, 100);
eq("C12 completed-zero still establishes excellent",
  zeroPosture.authoritative?.display_rating, "excellent");

const scorecard = await buildScorecardData(fx.incomplete.workspaceId, fx.env);
eq("C13 scorecard withholds frozen security score", scorecard.security_score, null);
ok("C14 scorecard does not publish no-critical/high clean copy",
  !scorecard.executive_summary.good.some((line) =>
    /No critical or high-severity findings/.test(line)));
ok("C15 scorecard publishes existing incomplete message",
  scorecard.executive_summary.attention_required.some((line) =>
    /incomplete/i.test(line || "")));

const dashboardResponse = await executiveDashboardRoutes(
  routeContext(fx.env, `/api/workspaces/${fx.incomplete.workspaceId}/executive-dashboard`),
);
const dashboard = await dashboardResponse.json();
eq("C16 executive dashboard headline withholds score", dashboard.summary?.security_score, null);
eq("C17 executive dashboard headline withholds rating", dashboard.summary?.risk_level, null);
ok("C18 executive dashboard trend withholds frozen score",
  dashboard.score_trend?.every((point) => point.score == null));

const portfolioRows = await computePortfolioDomainRows(
  fx.env.cybermeters_db,
  [fx.incomplete.workspaceId, fx.zero.workspaceId],
  { env: fx.env },
);
const incompletePortfolio = portfolioRows.find(
  (row) => row.workspace_id === fx.incomplete.workspaceId,
);
const zeroPortfolio = portfolioRows.find(
  (row) => row.workspace_id === fx.zero.workspaceId,
);
eq("C19 portfolio domain withholds incomplete score", incompletePortfolio?.overall_score, null);
eq("C20 portfolio domain withholds incomplete rating", incompletePortfolio?.overall_rating, null);
eq("C21 portfolio completed-zero retains 100", zeroPortfolio?.overall_score, 100);
eq("C22 portfolio completed-zero retains excellent", zeroPortfolio?.overall_rating, "excellent");

const historical = await runHistoricalModule(
  "new-scan",
  fx.missing.domain,
  88,
  [],
  { subdomains: { items: [] }, subdomain_takeover: { risks: [] }, asset_exposure: { assets: [] } },
  fx.env,
  fx.missing.workspaceId,
);
eq("C23 missing legacy Phase-5 cannot anchor historical score", historical.previous_score, null);
eq("C24 missing legacy Phase-5 cannot produce score delta", historical.score_change, null);

console.log("── D. sanitised read-only attribution reducer ──");
const attributionRows = [
  ...Array.from({ length: 16 }, () => ({
    modules: {
      ...completedModules(),
      cve_intelligence: deferred(completedCve()),
    },
  })),
  ...Array.from({ length: 29 }, () => ({
    modules: {
      ...completedModules(),
      cve_intelligence: {
        ...completedCve(),
        executed: false,
        incomplete: true,
        outcome: "unavailable",
      },
    },
  })),
  ...Array.from({ length: 12 }, () => ({ modules: completedModules() })),
];
const attributionDir = fs.mkdtempSync(path.join(os.tmpdir(), "phase5-attribution-"));
const attributionInput = path.join(attributionDir, "sanitised.json");
try {
  fs.writeFileSync(attributionInput, JSON.stringify(attributionRows));
  const attribution = JSON.parse(String(execFileSync(process.execPath, [
    path.join(root, "scripts/analyze-phase5-historical-attribution.js"),
    `--input=${attributionInput}`,
    `--verify=${path.join(root, "scripts/fixtures/phase5-historical-attribution-aggregate.json")}`,
  ], { cwd: root })));
  eq("D1 aggregate-only attribution population is reproducible", attribution.population, 57);
  ok("D2 aggregate buckets reproduce the recorded read-only result",
    attribution.phase5_deadline_exceeded === 16 &&
    attribution.phase5_incomplete_without_deadline === 29 &&
    attribution.phase5_fully_completed === 12 &&
    attribution.unattributable_from_historical_contract === 0);
  const extractorSource = fs.readFileSync(path.join(
    root,
    "scripts/extract-phase5-historical-attribution.js",
  ), "utf8");
  ok("D3 committed extractor pins the 57+1 overflow-detection bound",
    /MAX_CANDIDATES = 57/.test(extractorSource) &&
    /LIMIT \$\{MAX_CANDIDATES \+ 1\}/.test(extractorSource));
  ok("D4 committed extractor contains reads only",
    /"d1",\s*"execute"/.test(extractorSource) &&
    /"r2",\s*"object",\s*"get"/.test(extractorSource) &&
    !/"r2",\s*"object",\s*"(put|delete)"/.test(extractorSource) &&
    !/\b(INSERT|UPDATE|DELETE|REPLACE)\b/.test(extractorSource));
} finally {
  fs.rmSync(attributionDir, { recursive: true, force: true });
}

console.log("── E. pinned anchor-guarded mutations (fresh processes) ──");
const PHASE5 = path.join(root, "workers/scan-api/src/engines/phase5-evidence.js");
const SCANS = path.join(root, "workers/scan-api/src/routes/scans.js");
const EXECUTIVE = path.join(root, "workers/scan-api/src/engines/executive-report.js");
const PORTFOLIO_ROUTE = path.join(root, "workers/scan-api/src/routes/portfolio.js");
const INTELLIGENCE = path.join(root, "frontend/src/pages/IntelligencePage.jsx");
const FRONTEND_PRESENTATION = path.join(root, "frontend/src/lib/phase5EvidencePresentation.js");

async function withMutant(edits, run) {
  const originals = new Map();
  try {
    for (const edit of edits) {
      const source = fs.readFileSync(edit.target, "utf8");
      originals.set(edit.target, source);
      const count = source.split(edit.from).length - 1;
      if (count !== 1) return { applied: false, reason: `anchor x${count}` };
      fs.writeFileSync(edit.target, source.replace(edit.from, edit.to));
    }
    return { applied: true, result: await run() };
  } finally {
    for (const [target, source] of originals) fs.writeFileSync(target, source);
  }
}
const runChild = (mode) => JSON.parse(String(execFileSync(
  process.execPath,
  [fileURLToPath(import.meta.url), `--child=${mode}`],
  { cwd: root, timeout: 180_000, maxBuffer: 32 * 1024 * 1024 },
)));
const validatorRejects = (script) => {
  try {
    execFileSync(process.execPath, [path.join(root, "scripts", script)], {
      cwd: root,
      timeout: 180_000,
      stdio: "pipe",
    });
    return false;
  } catch {
    return true;
  }
};
const mutations = [
  {
    name: "M1 IntelligencePage restores stale D1 score/rating",
    edits: [{
      target: INTELLIGENCE,
      from: "  const assessmentPresentation = canonicalAssessmentPresentation(assessment)\n",
      to: `  const assessmentPresentation = canonicalAssessmentPresentation({
    ...assessment,
    display_score: assessment?.display_score ?? storedScanObj?.score ?? null,
    display_rating: assessment?.display_rating ?? storedScanObj?.rating ?? null,
  })
`,
    }],
    survived: () => runChild("frontend").passed === false,
  },
  {
    name: "M2 customer report republishes frozen snapshot score/risk",
    edits: [{
      target: SCANS,
      from: "        const snap = read.customerSnapshot ?? read.snapshot;\n",
      to: "        const snap = read.snapshot;\n",
    }],
    survived: () => {
      const value = runChild("report");
      return value.cyber_metrics_score === 100 && value.risk_level === "excellent";
    },
  },
  {
    name: "M3 historical risk Low/clean narrative restored",
    edits: [{
      target: PHASE5,
      from: "  if (evidence?.complete === true) return riskIntelligence;\n",
      to: "  if (true) return riskIntelligence;\n",
    }],
    survived: () => {
      const value = runChild("risk");
      return value.overall_risk_level === "Low" && value.narrative != null;
    },
  },
  {
    name: "M4 frontend evidence_publishable !== false restored",
    edits: [{
      target: FRONTEND_PRESENTATION,
      from: "  return moduleResult?.evidence_publishable === true\n",
      to: "  return moduleResult?.evidence_publishable !== false\n",
    }],
    survived: () => runChild("frontend").passed === false,
  },
  {
    name: "M5 missing Phase-5 count restored to zero",
    edits: [{
      target: FRONTEND_PRESENTATION,
      from: "  return Number.isFinite(value) ? value : null\n",
      to: "  return Number.isFinite(value) ? value : 0\n",
    }],
    survived: () => runChild("frontend").passed === false,
  },
  {
    name: "M6 masking moves into verbatim checksum endpoint",
    edits: [{
      target: SCANS,
      from: "          snapshot: read.snapshot,\n",
      to: "          snapshot: read.customerSnapshot,\n",
    }],
    survived: () => {
      const value = runChild("snapshot");
      return value.snapshot?.overall?.cyber_metrics_score == null;
    },
  },
  {
    name: "M7 executive non-Intelligence consumer loses masking",
    edits: [{
      target: EXECUTIVE,
      from: "  const snap = read.customerSnapshot ?? read.snapshot;\n",
      to: "  const snap = read.snapshot;\n",
    }],
    survived: () => runChild("executive").cyber_metrics_score?.value === 100,
  },
  {
    name: "M8 portfolio detail drops canonical env projection",
    edits: [{
      target: PORTFOLIO_ROUTE,
      from: `          const rows = await computePortfolioDomainRows(
            env.cybermeters_db,
            [wsId],
            { env },
          );
`,
      to: `          const rows = await computePortfolioDomainRows(
            env.cybermeters_db,
            [wsId],
          );
`,
    }],
    survived: () =>
      validatorRejects("validate-msp-portfolio-domains.js"),
  },
];
const EXPECTED_MUTANTS = 8;
let killed = 0;
for (const mutation of mutations) {
  const result = await withMutant(mutation.edits, mutation.survived);
  if (!result.applied) {
    failed += 1;
    console.error(`FAIL ${mutation.name} — ${result.reason}`);
  } else if (result.result === true) {
    killed += 1;
    console.log(`KILLED ${mutation.name}`);
  } else {
    failed += 1;
    console.error(`FAIL ${mutation.name} — mutant survived`);
  }
}
ok(`E1 all ${EXPECTED_MUTANTS} pinned mutants killed`,
  killed === EXPECTED_MUTANTS, `${killed}/${EXPECTED_MUTANTS}`);

const EXPECTED_ASSERTIONS = 60;
if (assertions !== EXPECTED_ASSERTIONS) {
  failed += 1;
  console.error(`FAIL assertion pin — expected ${EXPECTED_ASSERTIONS}, executed ${assertions}`);
}
console.log(
  `\n${passed} passed, ${failed} failed, ` +
  `${assertions}/${EXPECTED_ASSERTIONS} assertions, ` +
  `${killed}/${EXPECTED_MUTANTS} mutants killed`,
);
process.exit(failed ? 1 : 0);
