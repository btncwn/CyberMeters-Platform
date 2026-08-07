#!/usr/bin/env node
// Phase-5 historical evidence adapter: high-cardinality fan-out and fail-closed
// aggregate contract. Network-free; drives the real customer projection,
// aggregate resolver and Business Risk customer resolver.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines",
  name,
)).href;
const {
  PHASE5_EVIDENCE_READ_CONCURRENCY,
  PHASE5_EVIDENCE_READ_LIMIT,
  phase5EvidenceReadCoverage,
  projectPhase5ScanRowsForCustomer,
  resolvePhase5CustomerAggregate,
} = await import(engine("phase5-evidence.js"));
const {
  WORKSPACE_BRS_BASIS_CONTRACT,
  WORKSPACE_BRS_STATES,
  resolveWorkspaceBrsProjection,
} = await import(engine("business-risk.js"));

let assertions = 0;
let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  assertions += 1;
  if (condition) {
    passed += 1;
  } else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const completedModules = {
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
  known_exploited_vulnerabilities: {
    matches: [],
    checked: 0,
    matched: 0,
  },
  email_security_intelligence: {
    mta_sts: { configured: true },
    tls_rpt: { configured: true },
    findings: [],
  },
};

let activeReads = 0;
let maximumActiveReads = 0;
const requestedScanIds = [];
const env = {
  cybermeters_reports: {
    get: async (key) => {
      const scanId = key.replace(/^reports\//, "").replace(/\.json$/, "");
      requestedScanIds.push(scanId);
      activeReads += 1;
      maximumActiveReads = Math.max(maximumActiveReads, activeReads);
      await new Promise((resolve) => setImmediate(resolve));
      activeReads -= 1;
      if (scanId === "scan-5") throw new Error("bounded fixture read failure");
      return {
        json: async () => ({ modules: structuredClone(completedModules) }),
      };
    },
  },
};

// 1,200 rows but only 150 unique scan IDs. This proves both the fixed read cap
// and ID deduplication while recreating the cardinality that previously started
// 1,200 simultaneous R2 promises.
const inputRows = Array.from({ length: 1200 }, (_, index) => ({
  id: `scan-${index % 150}`,
  scan_id: `scan-${index % 150}`,
  workspace_id: `workspace-${index % 150}`,
  status: "completed",
  scan_quality: "complete",
  score: 100,
  rating: "excellent",
  created_at: "2026-07-29T12:00:00.000Z",
}));
const projected = await projectPhase5ScanRowsForCustomer(env, inputRows);
const coverage = phase5EvidenceReadCoverage(projected);

ok("A1 fixed evidence-read concurrency is pinned at 8",
  PHASE5_EVIDENCE_READ_CONCURRENCY === 8);
ok("A2 fixed total evidence-read bound is pinned at 100",
  PHASE5_EVIDENCE_READ_LIMIT === 100);
ok("A3 1,200 rows issue only 100 R2 reads",
  requestedScanIds.length === 100, String(requestedScanIds.length));
ok("A4 scan-ID deduplication issues one read per attempted identity",
  new Set(requestedScanIds).size === requestedScanIds.length);
ok("A5 observed concurrency never exceeds the fixed bound",
  maximumActiveReads <= PHASE5_EVIDENCE_READ_CONCURRENCY,
  String(maximumActiveReads));
ok("A6 fixture reaches the bound rather than testing serial execution",
  maximumActiveReads === PHASE5_EVIDENCE_READ_CONCURRENCY,
  String(maximumActiveReads));
ok("A7 coverage records all 1,200 input rows", coverage.row_count === 1200);
ok("A8 coverage records 150 unique scan identities",
  coverage.unique_scan_count === 150);
ok("A9 coverage records exactly 100 attempted reads",
  coverage.reads_attempted === 100);
ok("A10 coverage records the injected unavailable read",
  coverage.reads_unavailable === 1);
ok("A11 coverage records 50 bounded-out identities",
  coverage.bounded_out_scan_count === 50);
ok("A12 aggregate coverage is explicitly partial and truncated",
  coverage.complete === false &&
  coverage.truncated === true &&
  coverage.reason === "evidence_read_bound_exceeded");

const verifiedRow = projected.find((row) => row.scan_id === "scan-0");
const failedReadRow = projected.find((row) => row.scan_id === "scan-5");
const boundedRow = projected.find((row) => row.scan_id === "scan-149");
ok("B1 verified completed-zero retains 100/excellent",
  verifiedRow.score === 100 && verifiedRow.rating === "excellent");
ok("B2 failed R2 read fails closed",
  failedReadRow.score === null &&
  failedReadRow.rating === null &&
  failedReadRow.phase5_evidence_read.state === "unavailable");
ok("B3 bounded-out row fails closed",
  boundedRow.score === null &&
  boundedRow.rating === null &&
  boundedRow.phase5_evidence_read.state === "bounded_out");
ok("B4 bounded-out row carries an honest incomplete assessment",
  boundedRow.scan_quality === "partial" &&
  boundedRow.assessment?.authoritative === false);

const aggregate = resolvePhase5CustomerAggregate(projected);
ok("C1 incomplete high-cardinality aggregate excludes unassessed rows and states its denominator",
  aggregate.score === 100 &&
  aggregate.scores.length === 792 &&
  aggregate.evidence_coverage.assessed_row_count === 792 &&
  aggregate.evidence_coverage.incomplete_row_count === 408);
ok("C2 aggregate discloses partial/truncated evidence",
  aggregate.complete === false &&
  aggregate.evidence_coverage.truncated === true &&
  aggregate.evidence_coverage.assessment_complete === false);
const trendAggregate = resolvePhase5CustomerAggregate([
  verifiedRow,
  boundedRow,
]);
ok("C3 bounded-out trend point is excluded from a denominator-qualified average",
  trendAggregate.score === 100 &&
  trendAggregate.scores.length === 1 &&
  trendAggregate.evidence_coverage.complete === false &&
  trendAggregate.evidence_coverage.assessed_row_count === 1 &&
  trendAggregate.evidence_coverage.incomplete_row_count === 1);
ok("C4 bounded-out evidence cannot retain a healthy rating",
  boundedRow.rating === null);

const storedBRS = {
  workspace_id: boundedRow.workspace_id,
  score: 100,
  risk_band: "Low",
  calculated_at: "2026-07-29T12:00:00.000Z",
  payload_json: JSON.stringify({
    basis_contract: WORKSPACE_BRS_BASIS_CONTRACT,
    score: 100,
    risk_band: "Low",
    basis_scan: {
      scan_id: boundedRow.scan_id,
      scan_quality: "complete",
      assessed_at: "2026-07-29T12:00:00.000Z",
    },
  }),
};
const brs = resolveWorkspaceBrsProjection({
  storedRow: storedBRS,
  latestScan: boundedRow,
  basisScan: boundedRow,
});
ok("D1 bounded-out evidence cannot establish BRS",
  brs.score === null && brs.risk_band === null);
ok("D2 BRS has an explicit non-assessed state",
  brs.state === WORKSPACE_BRS_STATES.BASIS_UNPROVEN ||
  brs.state === WORKSPACE_BRS_STATES.LATEST_INCOMPLETE);
ok("D3 BRS publishes an explicit incomplete/unproven reason",
  typeof brs.state_reason === "string" && brs.state_reason.length > 0);

const absentStore = await projectPhase5ScanRowsForCustomer(null, [
  {
    id: "unverified",
    status: "completed",
    scan_quality: "complete",
    score: 100,
    rating: "excellent",
  },
]);
ok("E1 missing evidence store never falls back to raw D1 score/rating",
  absentStore[0].score === null && absentStore[0].rating === null);

const EXPECTED_ASSERTIONS = 24;
if (assertions !== EXPECTED_ASSERTIONS) {
  failed += 1;
  console.error(
    `FAIL assertion pin — expected ${EXPECTED_ASSERTIONS}, executed ${assertions}`,
  );
}
console.log(
  `\nPhase-5 evidence read bounds: ${passed}/${assertions} assertions passed`,
);
if (failed) process.exit(1);
