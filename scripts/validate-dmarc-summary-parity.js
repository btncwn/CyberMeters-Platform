#!/usr/bin/env node
// Pre-Item11 DMARC summary / technical evidence parity.
//
// The frozen-production-derived fixture contains only the load-bearing contradiction:
// a valid exact-domain p=none record and complete policy conclusion coexist
// with stale failed/skipped lookup markers. Real domains, scan ids, reporting
// destinations and unrelated report evidence are deliberately excluded.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (name) => pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", name,
)).href;

const stateModule = await import(engineUrl("dmarc-state.js"));
const emailModule = await import(engineUrl("email-scan.js"));
const domainModule = await import(engineUrl("cyber-mot-domains.js"));
const presentationModule = await import(engineUrl("dmarcbis-presentation.js"));
const contractModule = await import(engineUrl("dmarcbis-contract.js"));
const snapshotModule = await import(engineUrl("report-snapshot.js"));
const parserModule = await import(engineUrl("dmarcbis-parser.js"));
const idnaModule = await import(engineUrl("dmarcbis-idna.js"));

let passed = 0;
let failed = 0;
function verdict(id, condition, detail = "") {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}

const json = (value) => JSON.stringify(value);

function policyEvidence({
  policy = null,
  record = policy ? `v=DMARC1; p=${policy}` : null,
  observationState = policy ? "present_valid" : "absent",
  recordValidity = policy ? "valid" : "not_applicable",
  policySourceKind = policy ? "exact" : "none",
  policyCompleteness = "complete",
  coreCompleteness = "complete",
  providerState = "available",
  monitoringState = "monitoring_healthy",
  staleMarker = false,
} = {}) {
  const candidates = record == null ? [] : [{ value: record }];
  const lookupPath = [{
    question: {
      ordinal: 1,
      name: "_dmarc.fixture.example",
      type: "TXT",
      purpose: "policy_tree_walk",
      resolver: "primary",
    },
    outcome: candidates.length ? "success" : "nxdomain",
    logically_used: true,
    record_set: {
      candidates,
      selected: policy && recordValidity.startsWith("valid")
        ? { p: { normalized: policy } }
        : null,
    },
  }];
  if (staleMarker) {
    lookupPath.push({
      question: {
        ordinal: 2,
        name: "_dmarc.example",
        type: "TXT",
        purpose: "organisational_domain_discovery",
        resolver: "secondary",
      },
      outcome: "provider_timeout",
      skipped: true,
      logically_used: false,
    });
  }
  return {
    schema: "dmarc-policy.v2",
    methodology_version: "rfc9989-treewalk-v1",
    parser_version: parserModule.DMARCBIS_PARSER_VERSION,
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    author_domain: "fixture.example",
    submitted_domain: "fixture.example",
    observed_at: "2026-08-12T12:00:00.000Z",
    observation_state: observationState,
    record_validity: recordValidity,
    raw_records: record == null ? [] : [{ raw: record }],
    parsed_tags: policy == null ? [] : [
      { name: "p", raw_value: policy, normalized: policy },
    ],
    lookup_path: lookupPath,
    organisational_domain: "fixture.example",
    organisational_domain_provenance: policy
      ? "highest_valid_record"
      : "fallback_initial_target",
    organisational_domain_completeness:
      coreCompleteness === "complete" ? "complete" : "incomplete",
    policy_source_domain: policy ? "fixture.example" : null,
    policy_source_kind: policySourceKind,
    source_record: record == null ? null : { raw: record },
    domain_existence: "not_required",
    existence_completeness: "not_applicable",
    declared_policy: policy,
    effective_requested_policy: policy,
    testing_adjustment: policy ? "none" : "not_applicable",
    effective_policy_tag: policy ? "p" : null,
    inheritance_reason: policy ? "exact_p" : "none",
    p: policy == null
      ? null
      : { present: true, raw: policy, normalized: policy, valid: true },
    sp: null,
    np: null,
    t: null,
    psd: null,
    legacy_pct: {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: [],
    ruf_destinations: [],
    policy_completeness: policyCompleteness,
    corroboration_state: staleMarker ? "unavailable" : "not_applicable",
    rua_authorisation_completeness: "not_applicable",
    external_rua_authorisation: {
      rua_authorisation_completeness: "not_applicable",
      assessment_reason: "not_applicable",
      destinations: [],
    },
    monitoring_state: monitoringState,
    provider_state: providerState,
    receiver_enforcement_observed: false,
    core_completeness: coreCompleteness,
    outcome: coreCompleteness === "complete" ? "available" : "unavailable",
    evidence_grade: {
      grade: policyCompleteness === "complete" ? "L3" : "L0",
      source_type: "normative_protocol",
      basis: "Frozen RFC 9989 DNS policy evidence.",
      limits: ["Receiver handling is not observed."],
      repeat_confirmed: false,
    },
  };
}

function emailFixture() {
  return {
    spf: { present: true, record: "v=spf1 -all" },
    dkim: { present: true, selector: "selector1" },
    spf_detail: { raw: "v=spf1 -all", valid: true, record_count: 1 },
    dkim_detail: { status: "detected", selector: "selector1" },
    bimi_readiness: { record_found: false, blockers: [], warnings: [] },
    remediation_actions: [],
  };
}

function projectEmail(evidence) {
  const email = emailFixture();
  // The focused projection fixture excludes remediation rebuilding; that path
  // has its own validators and is outside this corrective.
  Object.defineProperty(email, "dmarc_policy_evidence", {
    value: {}, enumerable: false, configurable: true,
  });
  return emailModule.applyDmarcbisEmailCompatibilityProjection(
    "fixture.example",
    email,
    evidence,
  );
}

function reportWithEmail(emailSecurity) {
  return {
    scan_id: "scan-fixture",
    status: "completed",
    completed_at: "2026-08-12T12:00:01.000Z",
    findings: [],
    scan_quality: { status: "complete", modules_skipped: [] },
    monitoring_states: { version: "signal-monitoring-state-v1", signals: {} },
    modules: {
      email_security: emailSecurity,
      email_security_intelligence: {},
    },
  };
}

const contradictoryPolicy = policyEvidence({
  policy: "none",
  coreCompleteness: "incomplete",
  providerState: "historical_lookup_failed",
  monitoringState: "monitoring_degraded",
  staleMarker: true,
});
const contradictoryPolicyBytes = json(contradictoryPolicy);
const contradictoryPolicyEmail = projectEmail(contradictoryPolicy);
const contradictoryPolicyState = contradictoryPolicyEmail.dmarc_state;
verdict("DMARC-PARITY-VALID-NONE-STALE",
  contradictoryPolicyState?.canonical_evidence_state === "observed_policy" &&
  contradictoryPolicyState?.enforcement_level === "monitoring" &&
  contradictoryPolicyState?.policy === "none");
verdict("DMARC-PARITY-PNONE-NOT-HEALTHY",
  contradictoryPolicyState?.enforcement_level === "monitoring" &&
  contradictoryPolicyState?.enforcement_level !== "reject_enforced");

const contradictoryPolicyDomain = domainModule.resolveCyberMotDomainStates(
  reportWithEmail(contradictoryPolicyEmail),
).find((entry) => entry.domain_key === "email_protection");
verdict("DMARC-PARITY-SUMMARY-CANONICAL",
  contradictoryPolicyDomain?.state === "issue_detected" &&
  /no-action|p=none|monitoring/i.test(contradictoryPolicyDomain?.summary || "") &&
  !/could not be observed|lookup did not complete/i.test(contradictoryPolicyDomain?.summary || ""));

const contradictoryPolicyPresentation = presentationModule.buildDmarcPolicyPresentation({
  status: "current",
  evidence: contradictoryPolicy,
});
verdict("DMARC-PARITY-TECHNICAL-CANONICAL",
  contradictoryPolicyPresentation?.canonical_assessment?.canonical_evidence_state ===
    contradictoryPolicyState?.canonical_evidence_state &&
  contradictoryPolicyPresentation?.canonical_assessment?.policy ===
    contradictoryPolicyState?.policy);
verdict("DMARC-PARITY-RAW-EVIDENCE-IMMUTABLE",
  json(contradictoryPolicy) === contradictoryPolicyBytes);

for (const [policy, level] of [
  ["quarantine", "quarantine_enforced"],
  ["reject", "reject_enforced"],
]) {
  const state = projectEmail(policyEvidence({ policy })).dmarc_state;
  verdict(`DMARC-PARITY-${policy.toUpperCase()}-VALID`,
    state?.canonical_evidence_state === "observed_policy" &&
    state?.policy === policy && state?.enforcement_level === level);
}

const absentState = projectEmail(policyEvidence()).dmarc_state;
verdict("DMARC-PARITY-ABSENT-DISTINCT",
  absentState?.canonical_evidence_state === "absent" &&
  absentState?.enforcement_level === "no_record");

const unavailableState = projectEmail(policyEvidence({
  observationState: "unavailable",
  recordValidity: "indeterminate",
  policySourceKind: "unknown",
  policyCompleteness: "unavailable",
  coreCompleteness: "unavailable",
  providerState: "provider_timeout",
  monitoringState: "monitoring_degraded",
})).dmarc_state;
verdict("DMARC-PARITY-UNAVAILABLE-DISTINCT",
  unavailableState?.canonical_evidence_state === "unavailable" &&
  unavailableState?.enforcement_level === "not_observed");

const incompleteState = projectEmail(policyEvidence({
  observationState: "incomplete_oversized",
  recordValidity: "indeterminate",
  policySourceKind: "unknown",
  policyCompleteness: "incomplete",
  coreCompleteness: "incomplete",
  providerState: "response_limit",
  monitoringState: "monitoring_degraded",
})).dmarc_state;
verdict("DMARC-PARITY-INCOMPLETE-DISTINCT",
  incompleteState?.canonical_evidence_state === "incomplete" &&
  incompleteState?.enforcement_level === "not_observed");

const notAssessedState = projectEmail(null).dmarc_state;
verdict("DMARC-PARITY-NOT-ASSESSED-DISTINCT",
  notAssessedState?.canonical_evidence_state === "not_assessed" &&
  notAssessedState?.enforcement_level === "not_yet_assessed");

const malformedState = projectEmail(policyEvidence({
  record: "v=DMARC1; p=bogus",
  observationState: "present_invalid",
  recordValidity: "invalid",
  policySourceKind: "none",
  policyCompleteness: "complete",
  coreCompleteness: "complete",
})).dmarc_state;
verdict("DMARC-PARITY-MALFORMED-DISTINCT",
  malformedState?.canonical_evidence_state === "malformed" &&
  malformedState?.enforcement_level === "invalid_record");

const unrelatedBefore = json({
  spf: emailFixture().spf,
  dkim: emailFixture().dkim,
});
const unrelatedProjected = projectEmail(contradictoryPolicy);
verdict("DMARC-PARITY-SPF-DKIM-UNCHANGED", json({
  spf: unrelatedProjected.spf,
  dkim: unrelatedProjected.dkim,
}) === unrelatedBefore && json({
  spf: stateModule.projectDmarcReportForCustomer(
    reportWithEmail(emailFixture()), contradictoryPolicy,
  ).modules.email_security.spf,
  dkim: stateModule.projectDmarcReportForCustomer(
    reportWithEmail(emailFixture()), contradictoryPolicy,
  ).modules.email_security.dkim,
}) === unrelatedBefore);

const legacyReportWithoutPolicyEvidence = reportWithEmail(emailFixture());
verdict("DMARC-PARITY-NO-POLICY-EVIDENCE-NOOP",
  stateModule.projectDmarcReportForCustomer(
    legacyReportWithoutPolicyEvidence,
    null,
  ) === legacyReportWithoutPolicyEvidence);

const composed = snapshotModule.composeSnapshot({
  snapshotId: "snap-compose",
  workspaceId: "ws-compose",
  domainId: "dom-compose",
  scanId: "scan-compose",
  domain: "fixture.example",
  report: reportWithEmail(emailFixture()),
  dmarcPolicyEvidence: contradictoryPolicy,
  cyberEssentials: { status: "not_assessed" },
  ceReadiness: null,
  caseRows: [],
  questionSetVersions: [],
  certificateLifecycleRecords: null,
  attackSurfaceLifecycleRecords: null,
  supersedesSnapshotId: null,
  builtAt: "2026-08-12T12:00:02.000Z",
});
const composedEmailDomain = composed.domains.find(
  (entry) => entry.domain_key === "email_protection",
);
verdict("DMARC-PARITY-COMPOSED-SUMMARY",
  composedEmailDomain?.state === "issue_detected" &&
  /no-action|p=none|monitoring/i.test(composedEmailDomain?.summary || "") &&
  !/could not be observed|lookup did not complete/i.test(
    composedEmailDomain?.summary || "",
  ));

const snapshotFixture = {
  overall: {
    summary: "Across the eight Cyber MOT domains: 0 assessed healthy, 0 with issues detected, and 8 needing further evidence, customer input or monitoring.",
    not_fully_assessed: [{
      domain_key: "email_protection",
      state: "evidence_insufficient",
      reason: "DMARC lookup did not complete.",
    }],
  },
  domains: [{
    domain_key: "email_protection",
    display_name: "Email Protection",
    state: "evidence_insufficient",
    coverage: "degraded",
    summary: "DMARC could not be observed this scan (the DNS lookup did not complete) — not enough to assess.",
    finding_count: 0,
    finding_ids: [],
    highest_severity: null,
    recommendation_count: 0,
  }],
};
const projectedSnapshot = typeof stateModule.projectDmarcSnapshotForCustomer === "function"
  ? stateModule.projectDmarcSnapshotForCustomer(
      snapshotFixture,
      contradictoryPolicy,
    )
  : snapshotFixture;
const projectedEmailDomain = projectedSnapshot.domains?.[0];
verdict("DMARC-PARITY-SNAPSHOT-SUMMARY-TECHNICAL-PARITY",
  projectedEmailDomain?.canonical_dmarc_assessment?.canonical_evidence_state ===
    contradictoryPolicyPresentation?.canonical_assessment
      ?.canonical_evidence_state &&
  projectedEmailDomain?.state === "issue_detected" &&
  !/could not be observed|lookup did not complete/i.test(projectedEmailDomain?.summary || ""));
verdict("DMARC-PARITY-OVERALL-SUMMARY-PARITY",
  /1 with issues detected/.test(projectedSnapshot.overall?.summary || "") &&
  !(projectedSnapshot.overall?.not_fully_assessed || []).some(
    (entry) => entry.domain_key === "email_protection",
  ));
verdict("DMARC-PARITY-SNAPSHOT-INPUT-IMMUTABLE",
  snapshotFixture.domains[0].state === "evidence_insufficient" &&
  /lookup did not complete/i.test(snapshotFixture.domains[0].summary));

const unrelatedIssueSummary = "Two unrelated SPF or DKIM issues were detected.";
const issueSnapshot = stateModule.projectDmarcSnapshotForCustomer({
  domains: [{
    domain_key: "email_protection",
    state: "issue_detected",
    coverage: "complete",
    summary: unrelatedIssueSummary,
    state_reason: unrelatedIssueSummary,
  }],
}, contradictoryPolicy);
verdict("DMARC-PARITY-UNRELATED-EMAIL-SUMMARY-UNCHANGED",
  issueSnapshot.domains?.[0]?.summary === unrelatedIssueSummary &&
  issueSnapshot.domains?.[0]?.state_reason === unrelatedIssueSummary &&
  issueSnapshot.domains?.[0]?.canonical_dmarc_assessment
    ?.canonical_evidence_state === "observed_policy");

function makeD1(db) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => ({ success: true, meta: db.prepare(sql).run(...args) }),
  });
  return { prepare: (sql) => statement(sql) };
}

function makeR2(store) {
  return {
    get: async (key) => {
      const value = store.get(String(key));
      return value == null ? null : {
        text: async () => value,
        json: async () => JSON.parse(value),
      };
    },
  };
}

async function sealedEvidence(policy) {
  const base = policyEvidence({ policy });
  return contractModule.sealDmarcPolicyEvidence({
    ...base,
    idna_profile: idnaModule.DMARCBIS_IDNA_PROFILE,
  });
}

const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
  CREATE TABLE scan_report_snapshots (
    id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, scan_id TEXT,
    status TEXT, r2_key TEXT, checksum_sha256 TEXT,
    snapshot_schema_version TEXT, assessed_at TEXT, created_at TEXT,
    branding_json TEXT, related_changes_json TEXT,
    supersedes_snapshot_id TEXT
  );
`);
db.prepare("INSERT INTO workspaces (id, deleted_at) VALUES ('ws-a', NULL), ('ws-b', NULL), ('ws-dead', '2026-08-12T00:00:00.000Z')").run();
const store = new Map();
async function seedSnapshot({ id, workspace, scan, policy, assessedAt }) {
  const evidence = await sealedEvidence(policy);
  const body = JSON.stringify({
    snapshot: { snapshot_schema_version: "1" },
    protocol_evidence: { dmarc: evidence },
    domains: [{
      domain_key: "email_protection",
      state: "evidence_insufficient",
      coverage: "degraded",
      summary: "DMARC could not be observed this scan (the DNS lookup did not complete) — not enough to assess.",
    }],
  });
  const key = `fixture/${id}.json`;
  store.set(key, body);
  db.prepare(`INSERT INTO scan_report_snapshots
    (id, workspace_id, domain_id, scan_id, status, r2_key, checksum_sha256,
     snapshot_schema_version, assessed_at, created_at)
    VALUES (?, ?, 'dom-shared', ?, 'completed', ?, ?, '1', ?, ?)`)
    .run(id, workspace, scan, key,
      await snapshotModule.snapshotSha256Hex(body), assessedAt, assessedAt);
  return body;
}
const wsABody = await seedSnapshot({
  id: "snap-a", workspace: "ws-a", scan: "scan-a", policy: "none",
  assessedAt: "2026-08-12T12:00:00.000Z",
});
await seedSnapshot({
  id: "snap-b", workspace: "ws-b", scan: "scan-b", policy: "reject",
  assessedAt: "2026-08-12T12:01:00.000Z",
});
await seedSnapshot({
  id: "snap-dead", workspace: "ws-dead", scan: "scan-dead", policy: "quarantine",
  assessedAt: "2026-08-12T12:02:00.000Z",
});
const env = { cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store) };
const wsARead = await snapshotModule.readLatestDomainDmarcPolicyEvidence(
  env, "ws-a", "dom-shared",
);
const wsARawRead = await snapshotModule.readScanReportSnapshot(env, "scan-a", {
  repair: false,
  allowReconstruction: false,
  includeSuccessor: false,
});
const deadRead = await snapshotModule.readLatestDomainDmarcPolicyEvidence(
  env, "ws-dead", "dom-shared",
);
verdict("DMARC-PARITY-TENANT-ISOLATION",
  wsARead?.evidence?.effective_requested_policy === "none");
verdict("DMARC-PARITY-SOFT-DELETE-ISOLATION",
  deadRead?.status === "not_available");
verdict("DMARC-PARITY-HISTORICAL-RAW-BYTES",
  store.get("fixture/snap-a.json") === wsABody);
verdict("DMARC-PARITY-HISTORICAL-READ-RAW",
  wsARawRead.raw === wsABody &&
  JSON.stringify(wsARawRead.snapshot) === wsABody &&
  wsARawRead.customerSnapshot?.domains?.[0]?.state === "issue_detected");

const sourceGuards = {
  snapshot: fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/report-snapshot.js",
  ), "utf8"),
  presentation: fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/dmarcbis-presentation.js",
  ), "utf8"),
  pdf: fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/pdf.js",
  ), "utf8"),
};
verdict("DMARC-PARITY-SUMMARY-WIRING",
  sourceGuards.snapshot.includes("projectDmarcSnapshotForCustomer") &&
  sourceGuards.snapshot.includes("projectDmarcReportForCustomer"));
verdict("DMARC-PARITY-TECHNICAL-WIRING",
  sourceGuards.presentation.includes("deriveDmarcStateFromPolicyEvidence") &&
  sourceGuards.presentation.includes("canonical_assessment"));
verdict("DMARC-PARITY-NO-PDF-PATCH",
  !sourceGuards.pdf.includes("DMARC-PARITY") &&
  !sourceGuards.pdf.includes("projectDmarcSnapshotForCustomer"));

console.log(`\nDMARC summary parity fixtures: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
console.log("DMARC summary parity validation passed");
