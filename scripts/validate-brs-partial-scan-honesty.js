#!/usr/bin/env node
// Business Risk Score partial-scan honesty: deterministic producer, projection,
// sibling-consumer, report and PDF contract proofs.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...parts) => path.join(root, "workers", "scan-api", "src", ...parts);
const {
  computeAndPersistWorkspaceBrs,
  readWorkspaceBrsAssessment,
  resolveWorkspaceBrsProjection,
  WORKSPACE_BRS_BASIS_CONTRACT,
} = await import(pathToFileURL(src("engines", "business-risk.js")).href);
const { computePortfolioRisk } = await import(pathToFileURL(src("engines", "portfolio-risk.js")).href);
const { computeSupplyChainIntelligence } = await import(pathToFileURL(src("engines", "supply-chain.js")).href);
const { composeSnapshot } = await import(pathToFileURL(src("engines", "report-snapshot.js")).href);
const { buildExecutiveReportV2 } = await import(pathToFileURL(src("engines", "executive-report.js")).href);
const { buildScanReportPdf } = await import(pathToFileURL(src("engines", "pdf.js")).href);

const EXPECTED_ASSERTIONS = 47;
let passed = 0;
let failed = 0;
const only = String(process.env.BRS_ASSERT_ONLY || "");
const check = (name, condition, detail = "") => {
  if (only && !name.includes(only)) return;
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  check(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent overlap */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const name of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((entry) => entry.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", name));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function d1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
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
  return { prepare: (sql) => statement(sql) };
}

const db = buildDb();
const reports = new Map();
const env = {
  cybermeters_db: d1(db),
  cybermeters_reports: {
    get: async (key) => reports.has(key) ? { json: async () => JSON.parse(reports.get(key)) } : null,
  },
};
db.prepare("INSERT INTO users (id,email) VALUES ('user','founder@example.com')").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws','Founder Workspace','user')").run();
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom','user','example.com')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws','dom')").run();
db.prepare(`
  INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at)
  VALUES ('scan-complete','ws','dom','example.com','completed','complete',70,'medium','2026-07-28T09:00:00.000Z')
`).run();
reports.set("reports/scan-complete.json", JSON.stringify({
  scan_id: "scan-complete",
  scan_quality: { status: "complete" },
  modules: {
    cve_intelligence: {
      technologies_checked: ["nginx"],
      lookup_statuses: { nginx: { status: "complete" } },
      results: { nginx: [] },
      total_cves: 0,
      critical_count: 0,
      high_count: 0,
      source: "nvd_api",
      cve_coverage: "complete",
    },
    known_exploited_vulnerabilities: {},
    email_security_intelligence: {},
  },
  findings: [
    { id: "ssl_no_certificate", type: "ssl_no_certificate", finding_type: "finding", severity: "high" },
    { id: "email_missing_dmarc", type: "email_missing_dmarc", finding_type: "finding", severity: "high" },
    { id: "header_missing_content_security_policy", type: "header_missing_content_security_policy", finding_type: "finding", severity: "medium" },
  ],
}));

const complete = await computeAndPersistWorkspaceBrs(env, "ws", {
  scanId: "scan-complete",
  scanQuality: "complete",
  assessedAt: "2026-07-28T09:01:00.000Z",
});
eq("complete expected score", complete.score, 70);
eq("complete expected band", complete.risk_band, "medium");
eq("complete expected grade", complete.grade, "B");
eq("complete persists", complete.persisted, true);
eq("complete exact basis id", complete.basis_scan.scan_id, "scan-complete");
eq("complete canonical basis quality", complete.basis_scan.scan_quality, "complete");
eq("complete basis contract", complete.basis_contract, WORKSPACE_BRS_BASIS_CONTRACT);
eq("complete current row count", db.prepare("SELECT COUNT(*) n FROM workspace_brs_scores WHERE workspace_id='ws'").get().n, 1);
eq("complete history row count", db.prepare("SELECT COUNT(*) n FROM workspace_brs_score_history WHERE workspace_id='ws'").get().n, 1);

const canonicalBeforePartial = db.prepare(
  "SELECT score,risk_band,calculated_at,payload_json FROM workspace_brs_scores WHERE workspace_id='ws'"
).get();
db.prepare(`
  INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at)
  VALUES ('scan-partial','ws','dom','example.com','completed','partial',95,'low','2026-07-28T10:00:00.000Z')
`).run();
reports.set("reports/scan-partial.json", JSON.stringify({
  scan_id: "scan-partial", scan_quality: { status: "partial" }, findings: [],
}));
const partial = await computeAndPersistWorkspaceBrs(env, "ws", {
  scanId: "scan-partial",
  scanQuality: "partial",
  assessedAt: "2026-07-28T10:01:00.000Z",
});
eq("partial decision is not persisted", partial.persisted, false);
eq("partial does not overwrite canonical row",
  JSON.stringify(db.prepare("SELECT score,risk_band,calculated_at,payload_json FROM workspace_brs_scores WHERE workspace_id='ws'").get()),
  JSON.stringify(canonicalBeforePartial));
eq("partial does not append canonical history",
  db.prepare("SELECT COUNT(*) n FROM workspace_brs_score_history WHERE workspace_id='ws'").get().n, 1);

const staleProjection = await readWorkspaceBrsAssessment(env, "ws");
eq("latest partial state", staleProjection.state, "latest_incomplete");
eq("latest partial current score unavailable", staleProjection.score, null);
eq("latest partial current grade unavailable", staleProjection.grade, null);
eq("latest partial current scan id", staleProjection.current_assessment.scan_id, "scan-partial");
eq("latest partial current quality", staleProjection.current_assessment.scan_quality, "partial");
eq("latest partial last complete score explicit", staleProjection.last_complete_assessment.score, 70);
eq("latest partial last complete historical", staleProjection.last_complete_assessment.historical, true);
eq("latest partial last complete stale", staleProjection.last_complete_assessment.stale, true);
eq("latest partial keeps distinct basis id", staleProjection.last_complete_assessment.basis_scan.scan_id, "scan-complete");
check("latest and basis scan ids are not conflated",
  staleProjection.current_assessment.scan_id !== staleProjection.last_complete_assessment.basis_scan.scan_id);

const rowBeforeOldRecompute = JSON.stringify(db.prepare(
  "SELECT score,risk_band,calculated_at,payload_json FROM workspace_brs_scores WHERE workspace_id='ws'"
).get());
const oldRecompute = await computeAndPersistWorkspaceBrs(env, "ws", {
  scanId: "scan-current-missing",
  scanQuality: "complete",
  assessedAt: "2026-07-28T11:00:00.000Z",
});
eq("missing exact current basis cannot silently choose older complete", oldRecompute.persisted, false);
eq("missing current basis preserves row", JSON.stringify(db.prepare(
  "SELECT score,risk_band,calculated_at,payload_json FROM workspace_brs_scores WHERE workspace_id='ws'"
).get()), rowBeforeOldRecompute);

db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('partial-only','Partial Only','user')").run();
db.prepare(`
  INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at)
  VALUES ('partial-only-scan','partial-only','dom','example.com','completed','partial',100,'low','2026-07-28T12:00:00.000Z')
`).run();
const partialOnly = await readWorkspaceBrsAssessment(env, "partial-only");
eq("partial-only state is incomplete", partialOnly.state, "latest_incomplete");
eq("partial-only score unavailable never A", partialOnly.score, null);
eq("partial-only grade unavailable never A", partialOnly.grade, null);
eq("partial-only has no last complete", partialOnly.last_complete_assessment, null);

db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('no-report','No Report','user')").run();
db.prepare(`
  INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at)
  VALUES ('no-report-scan','no-report','dom','example.com','completed','complete',100,'low','2026-07-28T13:00:00.000Z')
`).run();
const noReport = await computeAndPersistWorkspaceBrs(env, "no-report", {
  scanId: "no-report-scan", scanQuality: "complete", assessedAt: "2026-07-28T13:01:00.000Z",
});
eq("complete metadata without durable complete report is not publishable", noReport.persisted, false);
eq("unpublishable complete report writes no canonical row",
  db.prepare("SELECT COUNT(*) n FROM workspace_brs_scores WHERE workspace_id='no-report'").get().n, 0);

db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('legacy','Legacy','user')").run();
db.prepare(`
  INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at)
  VALUES ('legacy-scan','legacy','dom','example.com','completed',NULL,95,'low','2026-07-28T08:00:00.000Z')
`).run();
db.prepare(`
  INSERT INTO workspace_brs_scores (workspace_id,score,risk_band,calculated_at,payload_json)
  VALUES ('legacy',95,'low','2026-07-28T08:01:00.000Z','{"score":95,"grade":"A","latest_scan":{"scan_id":"legacy-scan"}}')
`).run();
const legacy = await readWorkspaceBrsAssessment(env, "legacy");
eq("legacy unproven basis fails honest", legacy.state, "basis_unproven");
eq("legacy stored numeric is masked", legacy.score, null);
eq("legacy stored A is masked", legacy.grade, null);

const directLegacy = resolveWorkspaceBrsProjection({
  storedRow: { workspace_id: "legacy", score: 95, risk_band: "low", payload_json: '{"score":95,"grade":"A"}' },
  latestScan: { scan_id: "legacy-scan", workspace_id: "legacy", status: "completed", scan_quality: "complete" },
  basisScan: null,
});
eq("unavailable cannot convert to healthy numeric", directLegacy.score, null);
eq("unavailable cannot convert to A", directLegacy.grade, null);

db.prepare(`
  INSERT INTO workspace_vendors
    (id,workspace_id,vendor_name,category,source,confidence,risk_level,status,source_module,first_seen,last_seen,created_at,updated_at)
  VALUES ('vendor','ws','Example Vendor','cloud','scan','high','high','active','vendor_risk',
          '2026-07-28T09:00:00.000Z','2026-07-28T10:00:00.000Z',
          '2026-07-28T09:00:00.000Z','2026-07-28T10:00:00.000Z')
`).run();
const supply = await computeSupplyChainIntelligence("ws", env);
eq("sibling consumer masks stale BRS input", supply.brs_score, null);
eq("sibling consumer publishes BRS incompleteness", supply.brs_state, "latest_incomplete");
eq("trustworthy sibling vendor evidence remains represented", supply.vendor_summary.active, 1);
check("incomplete BRS cannot become a downstream numeric composite",
  supply.supply_chain_score_state === "incomplete" && supply.supply_chain_score === null);

const portfolio = await computePortfolioRisk(["ws"], env);
eq("portfolio does not expose stale BRS as current", portfolio.portfolio_score, null);
eq("portfolio ranking carries latest incomplete state", portfolio.risk_rankings[0].brs_state, "latest_incomplete");
eq("portfolio ranking retains explicit historical evidence",
  portfolio.risk_rankings[0].last_complete_assessment.basis_scan.scan_id, "scan-complete");

const partialReport = {
  scan_id: "scan-partial",
  domain_id: "dom",
  domain: "example.com",
  status: "completed",
  cyber_metrics_score: 95,
  risk_level: "low",
  started_at: "2026-07-28T10:00:00.000Z",
  completed_at: "2026-07-28T10:01:00.000Z",
  scan_quality: { status: "partial", incomplete_modules: ["ssl"] },
  findings: [],
  modules: {},
};
const snapshot = composeSnapshot({
  snapshotId: "snapshot",
  workspaceId: "ws",
  domainId: "dom",
  scanId: "scan-partial",
  domain: "example.com",
  report: partialReport,
  cyberEssentials: null,
  ceReadiness: null,
  caseRows: [],
  questionSetVersions: [],
  supersedesSnapshotId: null,
  builtAt: "2026-07-28T10:02:00.000Z",
});
eq("snapshot partial BRS indicator has no band", snapshot.overall.business_risk_indicator.band, null);
eq("snapshot partial BRS indicator is provisional", snapshot.overall.business_risk_indicator.provisional, true);
const executive = buildExecutiveReportV2({
  scan: { id: "scan-partial", domain_id: "dom", domain: "example.com" },
  workspace: { id: "ws", name: "Founder Workspace" },
  read: { snapshot, row: { id: "snapshot" }, integrity: { verified: true }, dmarcPolicy: null },
});
eq("Executive Report partial BRS band parity", executive.business_risk_indicator.band, null);
check("Executive Report explains non-authoritative partial evidence",
  /not authoritative/i.test(executive.business_risk_indicator.explanation || ""));
const pdfText = new TextDecoder("latin1").decode(buildScanReportPdf(
  { id: "scan-partial", domain_id: "dom", domain: "example.com" },
  { snapshot, row: { id: "snapshot" }, integrity: { verified: true }, dmarcPolicy: null },
));
check("PDF wording preserves non-authoritative partial state",
  /Business Risk Indicator: NOT AUTHORITATIVE/.test(pdfText));

if (!only && passed + failed !== EXPECTED_ASSERTIONS) {
  failed += 1;
  console.error(`FAIL pinned assertion count — got ${passed + failed - 1} want ${EXPECTED_ASSERTIONS}`);
}
console.log(`BRS partial-scan honesty: ${passed}/${passed + failed} assertions passed`);
if (failed > 0 || (!only && passed !== EXPECTED_ASSERTIONS)) process.exit(1);
console.log("BRS partial-scan honesty passed");
