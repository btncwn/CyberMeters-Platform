#!/usr/bin/env node
// Focused customer-state fixtures. All DNS and storage inputs are local.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", name)).href;
const { runEmailModule, applyDmarcbisEmailCompatibilityProjection } = await import(engine("email-scan.js"));
const { resolveCyberMotDomainStates } = await import(engine("cyber-mot-domains.js"));
const { composeSnapshot } = await import(engine("report-snapshot.js"));
const { computeScore } = await import(engine("scoring.js"));
const { projectPhase5ScanRowsForCustomer } = await import(engine("phase5-evidence.js"));
const { runVendorRelationshipModule } = await import(engine("vendor-relationship.js"));
const { upsertVendorRelationships } = await import(engine("scan-engine.js"));
const {
  projectUnvalidatedBrandReportForCustomer,
  projectUnvalidatedBrandSnapshotForCustomer,
} = await import(engine("brand-candidate-presentation.js"));

let passed = 0;
let failed = 0;
function check(name, condition, detail = "") {
  if (condition) passed++;
  else { failed++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}
const roundTrip = (value) => JSON.parse(JSON.stringify(value));
const domainState = (report, key) => resolveCyberMotDomainStates(report)
  .find((entry) => entry.domain_key === key)?.state;
const reportWith = (modules, findings = []) => ({
  scan_id: "fixture-scan", completed_at: "2026-10-16T00:00:00.000Z",
  scan_quality: { status: "complete", modules_skipped: [] }, findings, modules,
});
function snapshot(report) {
  return composeSnapshot({
    snapshotId: "fixture-snapshot", workspaceId: "fixture-workspace",
    domainId: "fixture-domain", scanId: "fixture-scan", domain: "fixture.example",
    report, cyberEssentials: { status: "not_assessed" }, ceReadiness: null,
    caseRows: [], questionSetVersions: [], supersedesSnapshotId: null,
    builtAt: "2026-10-16T00:00:01.000Z",
  });
}

// The cache supplies every DNS answer without issuing a request.
const emptyAnswer = { Status: 0, Answer: [] };
const quarantineAnswer = { Status: 0, Answer: [{ type: 16, data: "v=DMARC1; p=quarantine" }] };
const cache = {
  get: (key) => key.includes("_dmarc.fixture.example") ? quarantineAnswer : emptyAnswer,
  set: () => {},
};
const liveEmail = await runEmailModule("fixture.example", { cache });
const liveReport = reportWith({ email_security: liveEmail });
const storedReport = roundTrip(liveReport);
check("CM-P1-003 quarantine producer decision", liveEmail.dmarc_state?.enforcement_level === "quarantine_enforced");
check("CM-P1-003 decision survives JSON storage", storedReport.modules.email_security.dmarc_state?.enforcement_level === "quarantine_enforced");
check("CM-P1-003 live dashboard issue", domainState(liveReport, "email_protection") === "issue_detected");
check("CM-P1-003 stored dashboard issue", domainState(storedReport, "email_protection") === "issue_detected");
check("CM-P1-003 stored snapshot issue", snapshot(storedReport).domains.find((entry) => entry.domain_key === "email_protection")?.state === "issue_detected");

const projectedEmail = applyDmarcbisEmailCompatibilityProjection("fixture.example", {
  spf: {}, dkim: {},
}, {
  core_completeness: "complete",
  lookup_path: [{ question: { ordinal: 1, resolver: "primary", purpose: "policy_tree_walk" },
    record_set: { candidates: [{ value: "v=DMARC1; p=quarantine" }], selected: { p: { normalized: "quarantine" } } } }],
});
check("CM-P1-003 projected decision survives JSON storage",
  roundTrip(projectedEmail).dmarc_state?.enforcement_level === "quarantine_enforced");
const legacyReport = reportWith({ email_security: { dmarc: { present: true, policy: "quarantine" } } });
check("CM-P1-003 legacy missing decision is insufficient",
  domainState(legacyReport, "email_protection") === "evidence_insufficient");
check("CM-P1-003 legacy snapshot is insufficient",
  snapshot(legacyReport).domains.find((entry) => entry.domain_key === "email_protection")?.state === "evidence_insufficient");

const candidate = {
  candidate_domain: "fixture-login.example", variant_type: "prefix_keyword",
  risk_level: "high", risk_reasons: ["similar_name"], confidence: 40,
};
const unvalidated = { candidates_validated: false, domains: [candidate], error: null };
const provisionalReport = reportWith({ brand_monitoring: unvalidated });
const unvalidatedFindings = computeScore({ brand_monitoring: unvalidated }, "fixture.example").findings;
check("CM-P1-006 unvalidated candidate is not a scored threat",
  !unvalidatedFindings.some((finding) => /^brand_/.test(finding.id || "")));
check("CM-P1-006 dashboard marks watchlist provisional",
  domainState(provisionalReport, "brand_protection") === "provisional" &&
  /candidate|watchlist/i.test(resolveCyberMotDomainStates(provisionalReport)
    .find((entry) => entry.domain_key === "brand_protection")?.summary || ""));
check("CM-P1-006 stored snapshot stays provisional",
  snapshot(roundTrip(provisionalReport)).domains.find((entry) => entry.domain_key === "brand_protection")?.state === "provisional");
const legacyCandidateFinding = { id: "brand_lookalike_detected", module: "brand_monitoring", finding_type: "finding", severity: "high" };
check("CM-P1-006 old candidate finding cannot assert threat",
  domainState(reportWith({ brand_monitoring: unvalidated }, [legacyCandidateFinding]), "brand_protection") === "provisional");
const oldCandidateReport = reportWith({ brand_monitoring: unvalidated }, [legacyCandidateFinding]);
const unknownCandidateReport = reportWith({ brand_monitoring: { domains: [candidate] } }, [legacyCandidateFinding]);
check("CM-P1-006 missing candidate validation is insufficient",
  domainState(unknownCandidateReport, "brand_protection") === "evidence_insufficient");
oldCandidateReport.cyber_metrics_score = 70;
oldCandidateReport.risk_level = "moderate";
oldCandidateReport.monitoring_states = {
  version: "signal-monitoring-state-v3",
  signals: Object.fromEntries([
    "dns", "website_security", "email_protection", "attack_surface", "technology_visibility",
  ].map((name) => [name, { state: "monitoring_healthy", message: "Check completed.",
    evidence: { modules: [], incomplete_modules: [], providers: {} } }])),
};
const cleanScoreReport = {
  ...oldCandidateReport,
  findings: [],
  modules: { brand_monitoring: { candidates_validated: true, domains: [] } },
};
check("CM-P1-006 score fixture otherwise permits an authoritative score",
  snapshot(cleanScoreReport).overall.cyber_metrics_score === 70);
const presentedCandidate = projectUnvalidatedBrandReportForCustomer(oldCandidateReport);
check("CM-P1-006 raw report candidate presented as observation",
  presentedCandidate.findings[0]?.finding_type === "observation" &&
  presentedCandidate.findings[0]?.severity === "info" &&
  /watchlist/i.test(presentedCandidate.findings[0]?.title || "") &&
  oldCandidateReport.findings[0]?.finding_type === "finding");
check("CM-P1-006 old report without validation decision is an observation",
  projectUnvalidatedBrandReportForCustomer(unknownCandidateReport).findings[0]?.finding_type === "observation");
const newCandidateSnapshot = snapshot(oldCandidateReport);
check("CM-P1-006 new snapshot has no candidate threat or action",
  !newCandidateSnapshot.observed_findings.some((item) => /^brand_/.test(item.finding_id || "")) &&
  !newCandidateSnapshot.remediation_actions.some((item) => item.domain_keys?.includes("brand_protection")) &&
  newCandidateSnapshot.observations.some((item) => /^brand_/.test(item.finding_id || "")));
check("CM-P1-006 new snapshot withholds old candidate score",
  newCandidateSnapshot.overall.cyber_metrics_score === null &&
  newCandidateSnapshot.overall.business_risk_indicator.band === null);
const frozenLegacySnapshot = {
  domains: [{ domain_key: "brand_protection", state: "issue_detected", finding_count: 1 }],
  observed_findings: [{ finding_id: "brand_lookalike_detected", domain_keys: ["brand_protection"],
    finding_type: "finding", title: "Threat", severity: "high", remediation_id: "brand.lookalike.review" }],
  observations: [],
  remediation_actions: [{ remediation_id: "brand.lookalike.review", domain_keys: ["brand_protection"],
    finding_ids: ["brand_lookalike_detected"], priority: "high" }],
  overall: { summary: "One issue detected.", cyber_metrics_score: 70, score_band: "moderate",
    assessment: { display_score: 70, display_rating: "moderate", authoritative: true },
    business_risk_indicator: { band: "moderate", provisional: false } },
};
const originalLegacyBytes = JSON.stringify(frozenLegacySnapshot);
const presentedSnapshot = projectUnvalidatedBrandSnapshotForCustomer(frozenLegacySnapshot, oldCandidateReport);
check("CM-P1-006 frozen snapshot candidate demoted without changing raw bytes",
  presentedSnapshot.domains[0]?.state === "provisional" &&
  presentedSnapshot.observed_findings.length === 0 &&
  presentedSnapshot.observations[0]?.severity === "info" &&
  presentedSnapshot.remediation_actions.length === 0 &&
  presentedSnapshot.overall.cyber_metrics_score === null &&
  presentedSnapshot.overall.assessment?.state === "not_established" &&
  JSON.stringify(frozenLegacySnapshot) === originalLegacyBytes);
const missingSourceSnapshot = projectUnvalidatedBrandSnapshotForCustomer(frozenLegacySnapshot, null);
check("CM-P1-006 unavailable source cannot publish old candidate threat",
  missingSourceSnapshot.domains[0]?.state === "evidence_insufficient" &&
  missingSourceSnapshot.observed_findings.length === 0 &&
  missingSourceSnapshot.remediation_actions.length === 0 &&
  missingSourceSnapshot.overall.cyber_metrics_score === null &&
  missingSourceSnapshot.overall.assessment?.state === "not_established");
for (const incompleteSource of [{}, { modules: {} }, { modules: { brand_monitoring: {} } }]) {
  const projected = projectUnvalidatedBrandSnapshotForCustomer(frozenLegacySnapshot, incompleteSource);
  check("CM-P1-006 incomplete source cannot publish old candidate threat",
    projected.domains[0]?.state === "evidence_insufficient" &&
    projected.observed_findings.length === 0 && projected.remediation_actions.length === 0 &&
    projected.overall.cyber_metrics_score === null);
}
const publishableModules = {
  cve_intelligence: { technologies_checked: ["fixture"], lookup_statuses: { fixture: { status: "complete" } },
    results: { fixture: [] }, total_cves: 0, critical_count: 0, high_count: 0, source: "fixture", cve_coverage: "complete" },
  known_exploited_vulnerabilities: { matches: [], checked: 0, matched: 0 },
  email_security_intelligence: { mta_sts: { configured: true }, tls_rpt: { configured: true }, findings: [] },
};
const historicalRow = { id: "fixture-scan", status: "completed", scan_quality: "complete", score: 70, rating: "moderate" };
async function historicalCustomerRow(source) {
  const [row] = await projectPhase5ScanRowsForCustomer({ cybermeters_reports: {
    get: async () => ({ json: async () => ({ ...source, modules: { ...publishableModules, ...source.modules } }) }),
  } }, [historicalRow]);
  return row;
}
const historicalClean = await historicalCustomerRow(cleanScoreReport);
const historicalCandidate = await historicalCustomerRow(oldCandidateReport);
const historicalUnknown = await historicalCustomerRow(unknownCandidateReport);
check("CM-P1-006 complete historical row can publish score",
  historicalClean.score === 70 && historicalClean.rating === "moderate");
check("CM-P1-006 historical candidate score withheld across scan rows",
  historicalCandidate.score === null && historicalCandidate.rating === null &&
  historicalCandidate.assessment?.display_score === null &&
  historicalCandidate.assessment?.state === "not_established" &&
  historicalCandidate.phase5_evidence?.brand_score_unreliable === true);
check("CM-P1-006 historical row without validation withholds score",
  historicalUnknown.score === null && historicalUnknown.rating === null &&
  historicalUnknown.phase5_evidence?.brand_score_unreliable === true);
check("CM-P1-006 validated high-risk candidate still surfaces",
  domainState(reportWith({ brand_monitoring: { ...unvalidated, candidates_validated: true } }, [legacyCandidateFinding]), "brand_protection") === "issue_detected");
check("CM-P1-006 failed candidate module is evidence insufficient",
  domainState(reportWith({ brand_monitoring: { ...unvalidated, domains: [], error: "analysis failed" } }), "brand_protection") === "evidence_insufficient");

const completeInputs = {
  headers: { values: {} }, technology_detection: { external_scripts: [] },
  subdomain_takeover: { risks: [] }, asset_exposure: { assets: [] }, dns_bruteforce: { items: [] },
};
const fixtureSignature = [{
  name: "Fixture Service", category: "saas", risk_level: "low",
  signals: [{ source: "cname", test: (hostname) => hostname === "alias.fixture.example" }],
}];
const observedAlias = runVendorRelationshipModule({
  ...completeInputs,
  subdomain_takeover: { risks: [], cname_observations: [{ host: "www.fixture.example", cname: "alias.fixture.example" }] },
}, fixtureSignature);
check("Shadow IT takeover CNAME observation preserves supplier detection",
  observedAlias.inputs_complete === true && observedAlias.vendors[0]?.name === "Fixture Service" &&
  observedAlias.vendors[0]?.confidence === "high" && observedAlias.vendors[0]?.source_signals?.includes("cname"));
const chainedAlias = runVendorRelationshipModule({
  ...completeInputs,
  dns_bruteforce: { items: [{ hostname: "www.fixture.example", dns: {
    cname_chain: [{ name: "www.fixture.example", target: "alias.fixture.example" }],
  } }] },
}, fixtureSignature);
check("Shadow IT discovered DNS CNAME chain preserves supplier detection",
  chainedAlias.inputs_complete === true && chainedAlias.vendors[0]?.name === "Fixture Service" &&
  chainedAlias.vendors[0]?.confidence === "high");
async function retirementAfter(modules) {
  const relationship = runVendorRelationshipModule(modules);
  let status = "active";
  const db = { prepare: (sql) => ({ bind: () => ({
    all: async () => ({ results: [{ workspace_id: "fixture-workspace" }] }),
    run: async () => { if (sql.includes("SET status = 'inactive'")) status = "inactive"; return { success: true }; },
  }) }) };
  await upsertVendorRelationships("fixture-domain", relationship, { cybermeters_db: db });
  return { status, relationship };
}
for (const name of ["subdomain_takeover", "asset_exposure", "dns_bruteforce"]) {
  const missing = { ...completeInputs }; delete missing[name];
  const absent = await retirementAfter(missing);
  const errored = await retirementAfter({ ...completeInputs, [name]: { error: "read failed" } });
  const incomplete = await retirementAfter({ ...completeInputs, [name]: { incomplete: true } });
  check(`Shadow IT ${name} absent preserves CNAME supplier`, absent.relationship.inputs_complete === false && absent.status === "active");
  check(`Shadow IT ${name} error preserves CNAME supplier`, errored.relationship.inputs_complete === false && errored.status === "active");
  check(`Shadow IT ${name} incomplete preserves CNAME supplier`, incomplete.relationship.inputs_complete === false && incomplete.status === "active");
}
const clean = await retirementAfter(completeInputs);
check("Shadow IT complete empty evidence retires absent supplier",
  clean.relationship.inputs_complete === true && clean.status === "inactive");
for (const [name, partial] of [
  ["dns_bruteforce", { items: [], not_asked: 1 }],
  ["dns_bruteforce", { items: [], lookup_failed: 1 }],
  ["asset_exposure", { assets: [], probe_coverage: { cap_reached: true, dropped_count: 1 } }],
]) {
  const result = await retirementAfter({ ...completeInputs, [name]: partial });
  check(`Shadow IT ${name} partial coverage preserves CNAME supplier`,
    result.relationship.inputs_complete === false && result.status === "active");
}

console.log(`Launch state accuracy fixtures: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
