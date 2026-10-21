#!/usr/bin/env node
// Focused customer-state fixtures. All DNS and storage inputs are local.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", name)).href;
const { runEmailModule, applyDmarcbisEmailCompatibilityProjection } = await import(engine("email-scan.js"));
const { resolveSecurityCheckDomainStates, SECURITY_CHECK_DOMAINS } = await import(engine("security-check-domains.js"));
const { composeSnapshot } = await import(engine("report-snapshot.js"));
const { computeScore } = await import(engine("scoring.js"));
const { projectPhase5ScanRowsForCustomer } = await import(engine("phase5-evidence.js"));
const { runVendorRelationshipModule } = await import(engine("vendor-relationship.js"));
const { upsertVendorRelationships } = await import(engine("scan-engine.js"));
const { upsertBrandAssets } = await import(engine("asset-persistence.js"));
const {
  projectUnvalidatedBrandReportForCustomer,
  projectUnvalidatedBrandSnapshotForCustomer,
} = await import(engine("brand-candidate-presentation.js"));
const {
  deriveBrandValidation, loadBrandValidationState, brandCandidateIsLive,
  selectBrandValidationAssetsSql, selectBrandOpenAbuseCasesSql,
} = await import(engine("brand-validation-state.js"));
import fs from "node:fs";
const { whoisReportFindings } = await import(engine("whois-scan.js"));
const { loadUnauthorisedSendingSourceAlerts, spfUnauthorisedDedupePrefix } = await import(engine("spf-corroboration.js"));
const { resolveRemediation } = await import(engine("remediation-registry.js"));

let passed = 0;
let failed = 0;
function check(name, condition, detail = "") {
  if (condition) passed++;
  else { failed++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}
const roundTrip = (value) => JSON.parse(JSON.stringify(value));
const domainState = (report, key) => resolveSecurityCheckDomainStates(report)
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
  /candidate|watchlist/i.test(resolveSecurityCheckDomainStates(provisionalReport)
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

// ── CM-P1-007: the Brand decision reads the enrichment state ─────────────────
// The scan module is pure and marks candidates unvalidated; the hourly DNS and
// daily HTTPS enrichment live in workspace_brand_assets. The scan must read
// that state back into its decision: a resolving high-risk candidate or an open
// confirmed-abuse case is a finding, an unchecked candidate is never a finding
// and never inactive, and unfinished checks never read as a clean watchlist.
const enrichmentAt = "2026-10-17T00:00:00.000Z";
const generated = {
  brand: "fixture", total_candidates_generated: 3, candidates_validated: false, source: "typosquat_analysis", error: null,
  risk_summary: { critical: 1, high: 1, medium: 1, low: 0 },
  domains: [
    { candidate_domain: "fixture-login.example", variant_type: "prefix_keyword", risk_level: "high", risk_reasons: ["login keyword"], confidence: 40, validation_quality: "weak" },
    { candidate_domain: "fixtvre.example", variant_type: "substitution", risk_level: "critical", risk_reasons: ["one character"], confidence: 40, validation_quality: "weak" },
    { candidate_domain: "fixture.co", variant_type: "tld_variation", risk_level: "medium", risk_reasons: ["other TLD"], confidence: 40, validation_quality: "weak" },
  ],
};
const brandFindingsOf = (mod) => computeScore({ brand_monitoring: mod }, "fixture.example").findings
  .filter((finding) => /^brand_/.test(finding.id || ""));
const brandEntry = (mod, findings = []) => resolveSecurityCheckDomainStates(reportWith({ brand_monitoring: mod }, findings))
  .find((entry) => entry.domain_key === "brand_protection");
const row = (candidate_domain, dns_resolves, extra = {}) => ({
  candidate_domain, dns_resolves, https_available: null, classification: "unreviewed", risk_level: "high", status: "unverified",
  last_checked_at: dns_resolves === null ? null : enrichmentAt, ...extra,
});

const unchecked3 = deriveBrandValidation(generated, { assetRows: [row("fixture-login.example", null)], caseRows: [], checkedAt: enrichmentAt });
check("CM-P1-007 unchecked watchlist stays unvalidated",
  unchecked3.candidates_validated === false && unchecked3.validation?.state === "unchecked" &&
  unchecked3.validation.unchecked === 3 && unchecked3.validation.checked === 0 &&
  unchecked3.domains.every((c) => c.dns_resolves === null && c.enrichment_status === "unchecked") &&
  brandFindingsOf(unchecked3).length === 0);
const uncheckedEntry = brandEntry(roundTrip(unchecked3));
check("CM-P1-007 unchecked watchlist reads provisional, never inactive or healthy",
  uncheckedEntry?.state === "provisional" && uncheckedEntry.coverage === "partial" &&
  /none has a DNS result/.test(uncheckedEntry.summary) && !/inactive/i.test(uncheckedEntry.summary));

const liveRows = [
  row("fixture-login.example", 1, { https_available: 1 }),
  row("fixtvre.example", 0),
  row("fixture.co", 1),
];
const live = deriveBrandValidation(generated, { assetRows: liveRows, caseRows: [], checkedAt: enrichmentAt });
check("CM-P1-007 enrichment state is merged per candidate",
  live.candidates_validated === true && live.validation.state === "complete" &&
  live.validation.checked === 3 && live.validation.unchecked === 0 &&
  live.validation.active === 2 && live.validation.active_high_risk === 1 && live.validation.https_served === 1 &&
  live.domains[0].dns_resolves === 1 && live.domains[0].https_available === 1 && live.domains[0].enrichment_status === "active" &&
  live.domains[1].dns_resolves === 0 && live.domains[1].enrichment_status === "inactive" &&
  live.domains[0].last_checked_at === enrichmentAt);
const liveFindings = brandFindingsOf(live);
check("CM-P1-007 live high-risk candidate is a scored finding",
  liveFindings.length === 1 && liveFindings[0].id === "brand_lookalike_detected" &&
  liveFindings[0].finding_type === "finding" && liveFindings[0].severity === "high" &&
  liveFindings[0].evidence.some((item) => item.label === "DNS Resolves" && /^yes/.test(item.value)) &&
  liveFindings[0].evidence.some((item) => item.label === "HTTPS" && item.value === "served") &&
  /own DNS probe resolved it/.test(liveFindings[0].description) &&
  !/(phishing|malicious|attacker|compromise)/i.test(`${liveFindings[0].title} ${liveFindings[0].description}`));
check("CM-P1-007 inactive critical candidate is not a finding",
  !liveFindings.some((finding) => /fixtvre/.test(finding.title)) && !brandCandidateIsLive(live.domains[1]));
const liveBrandReport = roundTrip(reportWith({ brand_monitoring: live }, liveFindings));
const liveEntry = brandEntry(liveBrandReport.modules.brand_monitoring, liveBrandReport.findings);
check("CM-P1-007 live candidate turns the card to issue_detected",
  liveEntry?.state === "issue_detected" && liveEntry.coverage === "complete" && liveEntry.finding_count === 1 &&
  /1 high-risk lookalike resolving in DNS/.test(liveEntry.summary));
const liveSnapshot = snapshot({ ...liveBrandReport, cyber_metrics_score: 70, risk_level: "moderate", monitoring_states: oldCandidateReport.monitoring_states });
check("CM-P1-007 snapshot carries the validated finding and its score",
  liveSnapshot.domains.find((entry) => entry.domain_key === "brand_protection")?.state === "issue_detected" &&
  liveSnapshot.observed_findings.some((item) => item.finding_id === "brand_lookalike_detected" && item.finding_type === "finding") &&
  liveSnapshot.overall.cyber_metrics_score === 70);

const partial = deriveBrandValidation(generated, { assetRows: [row("fixtvre.example", 0)], caseRows: [], checkedAt: enrichmentAt });
const partialEntry = brandEntry(roundTrip(partial), brandFindingsOf(partial));
check("CM-P1-007 partially validated watchlist stays provisional",
  partial.candidates_validated === true && partial.validation.state === "partial" && partial.validation.unchecked === 2 &&
  brandFindingsOf(partial).length === 0 &&
  partialEntry?.state === "provisional" && partialEntry.coverage === "partial" &&
  /2 of 3 lookalike candidates still await DNS validation; 1 checked/.test(partialEntry.summary));

const allInactive = deriveBrandValidation(generated, {
  assetRows: [row("fixture-login.example", 0), row("fixtvre.example", 0), row("fixture.co", 0)], caseRows: [], checkedAt: enrichmentAt,
});
const allInactiveReport = roundTrip({ ...reportWith({ brand_monitoring: allInactive }), monitoring_states: oldCandidateReport.monitoring_states });
check("CM-P1-007 fully checked inactive watchlist can read healthy",
  allInactive.validation.state === "complete" && brandFindingsOf(allInactive).length === 0 &&
  domainState(allInactiveReport, "brand_protection") === "assessed_healthy");

const closed = deriveBrandValidation(generated, {
  assetRows: [row("fixture-login.example", 1, { classification: "false_positive" }), row("fixtvre.example", 0), row("fixture.co", 0)],
  caseRows: [], checkedAt: enrichmentAt,
});
check("CM-P1-007 customer-closed live candidate is not a finding",
  closed.validation.closed_by_customer === 1 && closed.validation.active_high_risk === 0 &&
  brandFindingsOf(closed).length === 0 && !brandCandidateIsLive(closed.domains[0]));

const caseRow = { id: "case_fixture", candidate_domain: "fixture-login.example", severity: "high", status: "confirmed_abuse" };
const withCase = deriveBrandValidation(generated, { assetRows: [], caseRows: [caseRow], checkedAt: enrichmentAt });
const caseFindings = brandFindingsOf(withCase);
check("CM-P1-007 open confirmed-abuse case is a finding",
  withCase.candidates_validated === true && withCase.validation.open_abuse_cases === 1 &&
  withCase.domains[0].open_abuse_case?.case_id === "case_fixture" &&
  caseFindings.length === 1 && /Confirmed brand abuse under management/.test(caseFindings[0].title) &&
  caseFindings[0].evidence.some((item) => item.label === "Managed Case" && item.value === "case_fixture") &&
  /registrar or provider actions it/.test(caseFindings[0].description));
const caseEntry = brandEntry(roundTrip(withCase), caseFindings);
check("CM-P1-007 open case turns the card to issue_detected even with unchecked candidates",
  caseEntry?.state === "issue_detected" && caseEntry.coverage === "partial" &&
  /1 open confirmed-abuse case/.test(caseEntry.summary) && /3 candidates still awaiting DNS validation/.test(caseEntry.summary));
const triageOnly = deriveBrandValidation(generated, { assetRows: [], caseRows: [{ ...caseRow, status: "triage" }], checkedAt: enrichmentAt });
const resolvedOnly = deriveBrandValidation(generated, { assetRows: [], caseRows: [{ ...caseRow, status: "resolved" }], checkedAt: enrichmentAt });
check("CM-P1-007 unconfirmed or resolved case is not a finding",
  triageOnly.candidates_validated === false && resolvedOnly.candidates_validated === false &&
  brandFindingsOf(triageOnly).length === 0 && brandFindingsOf(resolvedOnly).length === 0);
const orphanCase = deriveBrandValidation(generated, { assetRows: [], caseRows: [{ ...caseRow, candidate_domain: "older-fixture.example" }], checkedAt: enrichmentAt });
check("CM-P1-007 open case for an older candidate still counts",
  orphanCase.domains.length === 4 && orphanCase.validation.open_abuse_cases === 1 &&
  brandFindingsOf(orphanCase).some((finding) => /older-fixture\.example/.test(finding.title)));

const persistedBinds = [];
const persistenceDb = { prepare: (sql) => ({ bind: (...args) => {
  persistedBinds.push(args);
  return {
    all: async () => ({ results: /FROM workspace_domains wd/.test(sql) ? [{ workspace_id: "ws_fixture", domain: "fixture.example" }] : [] }),
    first: async () => null,
    run: async () => ({ meta: { changes: 1 } }),
  };
} }) };
await upsertBrandAssets("dom_fixture", orphanCase, { cybermeters_db: persistenceDb });
const persistedCandidates = new Set(persistedBinds.flat().filter((value) => typeof value === "string" && /\.example$/.test(value)));
check("CM-P1-007 case-only entries are never re-persisted as generated candidates",
  orphanCase.domains[3]?.generated_this_scan === false &&
  persistedCandidates.has("fixture-login.example") && !persistedCandidates.has("older-fixture.example"));

const unavailable = deriveBrandValidation(generated, { checkedAt: enrichmentAt, unavailable: true, reason: "enrichment_state_read_failed" });
const unavailableEntry = brandEntry(roundTrip(unavailable));
check("CM-P1-007 unreadable enrichment state fails closed",
  unavailable.candidates_validated === false && unavailable.validation.state === "unavailable" &&
  brandFindingsOf(unavailable).length === 0 &&
  unavailableEntry?.state === "provisional" && /could not be read/.test(unavailableEntry.summary));
const failedModule = deriveBrandValidation({ ...generated, error: "analysis failed" }, { assetRows: liveRows, checkedAt: enrichmentAt });
check("CM-P1-007 failed candidate generation never becomes validated",
  failedModule.candidates_validated === false && failedModule.validation.state === "unavailable");

function mockBrandDb({ assets = [], cases = [], throwOn = null } = {}) {
  const calls = [];
  return { calls, prepare: (sql) => ({ bind: (...args) => ({ all: async () => {
    calls.push({ sql, args });
    const isCases = /FROM managed_cases/.test(sql);
    if (throwOn === "any" || (throwOn === "cases" && isCases)) throw new Error("D1 unavailable");
    return { results: isCases ? cases : assets };
  } }) }) };
}
const db = mockBrandDb({ assets: liveRows, cases: [caseRow] });
const loaded = await loadBrandValidationState({ cybermeters_db: db }, { workspaceId: "ws_fixture", domain: "fixture.example", brandModule: generated, now: enrichmentAt });
check("CM-P1-007 scan-time read merges rows and cases through one derivation",
  JSON.stringify(loaded) === JSON.stringify(deriveBrandValidation(generated, { assetRows: liveRows, caseRows: [caseRow], checkedAt: enrichmentAt })));
check("CM-P1-007 enrichment reads are tenant-scoped and bounded",
  db.calls.length === 2 &&
  db.calls.every((call) => /w\.deleted_at IS NULL/.test(call.sql) && /LIMIT \d+/.test(call.sql) && call.args.includes("ws_fixture") && call.args.includes("fixture.example")) &&
  /workspace_id = \?/.test(selectBrandValidationAssetsSql()) && /c\.workspace_id = \?/.test(selectBrandOpenAbuseCasesSql()) &&
  /case_type = 'brand_abuse'/.test(selectBrandOpenAbuseCasesSql()) && /'confirmed_abuse'/.test(selectBrandOpenAbuseCasesSql()) &&
  !/'triage'|'resolved'|'closed'|'false_positive'/.test(selectBrandOpenAbuseCasesSql()));
const loadFailed = await loadBrandValidationState({ cybermeters_db: mockBrandDb({ throwOn: "any" }) }, { workspaceId: "ws_fixture", domain: "fixture.example", brandModule: generated, now: enrichmentAt });
const loadNoDb = await loadBrandValidationState({}, { workspaceId: "ws_fixture", domain: "fixture.example", brandModule: generated, now: enrichmentAt });
const loadNoWorkspace = await loadBrandValidationState({ cybermeters_db: db }, { workspaceId: null, domain: "fixture.example", brandModule: generated, now: enrichmentAt });
check("CM-P1-007 read failure, missing database and missing workspace all fail closed",
  [loadFailed, loadNoDb, loadNoWorkspace].every((mod) => mod.candidates_validated === false && mod.validation?.state === "unavailable") &&
  loadFailed.validation.reason === "enrichment_state_read_failed" && loadNoDb.validation.reason === "database_unavailable" &&
  loadNoWorkspace.validation.reason === "no_workspace_context");

const legacyValidated = { candidates_validated: true, domains: [{ candidate_domain: "legacy-login.example", variant_type: "prefix_keyword", risk_level: "high", risk_reasons: ["legacy"] }] };
check("CM-P1-007 legacy validated module without DNS fields still scores",
  brandFindingsOf(legacyValidated).length === 1 && brandEntry(legacyValidated, brandFindingsOf(legacyValidated))?.state === "issue_detected");

const scanEngineSource = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/scan-engine.js"), "utf8");
const mergeAt = scanEngineSource.indexOf("modules.brand_monitoring = await loadBrandValidationState(env, {");
const scoreAt = scanEngineSource.indexOf("computeScore(modules, domain)");
check("CM-P1-007 scan merges enrichment state before scoring and before the report freezes",
  mergeAt > 0 && scoreAt > mergeAt &&
  /import \{ loadBrandValidationState \} from "\.\/brand-validation-state\.js";/.test(scanEngineSource) &&
  /workspaceId, domain, brandModule: modules\.brand_monitoring,/.test(scanEngineSource));

// ── CM-P1-008: Identity Exposure publishes its inventory counts ──────────────
// The state stays evidence-insufficient (compromise and sign-in controls are not
// evaluated); the summary states what was observed and evidence_count is the
// real inventory count rather than the number of modules present.
const identityModule = {
  detected: true, total: 5, provider_count: 2, portal_count: 3,
  provider_relationship_count: 2, surface_candidate_count: 2, reachability_evaluated_count: 1, reachable_surface_count: 1,
  password_form_count: 0, high_risk_count: 1, providers: [], portals: [], source: "identity_discovery", error: null,
};
const identityOf = (mod) => resolveSecurityCheckDomainStates(reportWith({ identity_discovery: mod })).find((entry) => entry.domain_key === "identity_exposure");
const identityEntry = identityOf(identityModule);
check("CM-P1-008 identity inventory counts reach the summary without changing the state",
  identityEntry?.state === "evidence_insufficient" && identityEntry.evidence_count === 5 &&
  /2 provider relationships, 3 possible identity-facing hostnames, 1 endpoint measured \(1 reachable\)/.test(identityEntry.summary) &&
  /classified as 2 provider relationships, 2 hostname candidates, 1 measured surface\./.test(identityEntry.summary) &&
  /were not evaluated/.test(identityEntry.summary) && identityEntry.finding_count === 0);
const emptyIdentity = identityOf({});
check("CM-P1-008 empty identity inventory reports zero evidence honestly",
  emptyIdentity?.state === "evidence_insufficient" && emptyIdentity.evidence_count === 0 &&
  /no provider relationship or identity-facing hostname was observed/.test(emptyIdentity.summary) && /not evaluated/.test(emptyIdentity.summary));
const malformedIdentity = identityOf({ provider_count: "2", portal_count: -1, total: "5" });
check("CM-P1-008 non-numeric identity counts are omitted, never fabricated",
  malformedIdentity?.evidence_count === 0 && !/provider relationship[s]?,/.test(malformedIdentity.summary) &&
  /no provider relationship or identity-facing hostname was observed/.test(malformedIdentity.summary));

// ── CM-P1-009: registration expiry findings are Attack Surface issues ─────────
const whoisAnswered = {
  source: "rdap", optional: true, domain: "fixture.example", registrar: "Fixture Registrar",
  expiration_date: "2026-10-01T00:00:00Z", days_until_expiry: 15, error: null, registries_asked: [],
  findings: [
    { id: "whois_expiry_critical", title: "Domain expires within 30 days", severity: "high", score_impact: 0, module: "whois_intelligence", recommendation: "Renew the domain." },
    { id: "whois_new_domain", title: "Recently registered domain", severity: "low", score_impact: 0, module: "whois_intelligence" },
    { id: "whois_registrar_info", title: "Registrar identified", severity: "informational", score_impact: 0, module: "whois_intelligence" },
  ],
};
const whoisFindings = whoisReportFindings(whoisAnswered);
// Downstream checks use the produced finding when present; a mutant that
// produces none still reports its own named failure and lets the suite finish.
const whoisExpiry = whoisFindings[0] ?? { id: "whois_expiry_critical", severity: "high", finding_type: "finding", score_impact: 0, module: "whois_intelligence" };
check("CM-P1-009 only the expiry finding reaches the report, with finding authority and no score weight",
  whoisFindings.length === 1 && whoisFindings[0].id === "whois_expiry_critical" && whoisFindings[0].finding_type === "finding" &&
  whoisFindings[0].score_impact === 0 && whoisFindings[0].module === "whois_intelligence" &&
  whoisFindings[0].evidence.some((item) => item.label === "Expiration Date" && item.value === "2026-10-01T00:00:00Z") &&
  whoisFindings[0].evidence.some((item) => item.label === "Source" && /RDAP/.test(item.value)));
check("CM-P1-009 unavailable, deferred or errored registries add nothing",
  [{ ...whoisAnswered, unavailable: true }, { ...whoisAnswered, incomplete: true }, { ...whoisAnswered, error: "lookup failed" },
    { ...whoisAnswered, outcome: "deadline_exceeded" }, { ...whoisAnswered, findings: [] }, null, undefined]
    .every((mod) => whoisReportFindings(mod).length === 0));
const attackSurfaceOf = (findings) => resolveSecurityCheckDomainStates(reportWith({ subdomains: { count: 1 }, dns: {}, whois_intelligence: whoisAnswered }, findings))
  .find((entry) => entry.domain_key === "attack_surface");
const expiring = attackSurfaceOf(whoisFindings);
check("CM-P1-009 expiring registration turns Attack Surface to issue_detected",
  expiring?.state === "issue_detected" && expiring.highest_severity === "high" && expiring.finding_count === 1 &&
  JSON.stringify(expiring.finding_ids) === JSON.stringify(["whois_expiry_critical"]));
const expired = attackSurfaceOf([{ ...whoisExpiry, id: "whois_domain_expired", title: "Domain has expired" }]);
const warning = attackSurfaceOf([{ ...whoisExpiry, id: "whois_expiry_warning", severity: "medium" }]);
check("CM-P1-009 expired registration is high; the 90-day warning is medium",
  expired?.state === "issue_detected" && expired.highest_severity === "high" &&
  warning?.state === "issue_detected" && warning.highest_severity === "medium");
check("CM-P1-009 registration finding belongs to exactly one domain",
  JSON.stringify(SECURITY_CHECK_DOMAINS.filter((d) => d.match(whoisExpiry)).map((d) => d.domain_key)) === JSON.stringify(["attack_surface"]));
const observationOnly = attackSurfaceOf([{ id: "whois_new_domain", finding_type: "observation", severity: "low", score_impact: 0, module: "whois_intelligence" }]);
check("CM-P1-009 registration observations never own the Attack Surface state",
  observationOnly?.state !== "issue_detected" && observationOnly.finding_count === 0);
check("CM-P1-009 expiry findings resolve to the registration remediation",
  ["whois_domain_expired", "whois_expiry_critical", "whois_expiry_warning"].every((id) =>
    resolveRemediation({ finding_type: id, domain_key: "attack_surface" })?.remediation_id === "asm.domain.expiry"));
const whoisSnapshot = snapshot(roundTrip(reportWith({ subdomains: { count: 1 }, dns: {}, whois_intelligence: whoisAnswered }, whoisFindings)));
check("CM-P1-009 snapshot grades registration evidence as registry data and carries the issue",
  whoisSnapshot.domains.find((entry) => entry.domain_key === "attack_surface")?.state === "issue_detected" &&
  whoisSnapshot.observed_findings.some((item) => item.finding_id === "whois_expiry_critical") &&
  JSON.stringify(whoisSnapshot).includes("Registration data (RDAP)"));
const whoisSource = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/whois-scan.js"), "utf8");
check("CM-P1-009 scan appends registration findings to the one report array with explicit authority",
  scanEngineSource.includes("for (const f of whoisReportFindings(modules.whois_intelligence)) {") &&
  ["whois_domain_expired", "whois_expiry_critical", "whois_expiry_warning"].every((id) =>
    new RegExp(`id:\\s+"${id}",\\n\\s+finding_type:\\s+"finding",`).test(whoisSource)) &&
  ["whois_new_domain", "whois_registrar_info"].every((id) =>
    new RegExp(`id:\\s+"${id}",\\n\\s+finding_type:\\s+"observation",`).test(whoisSource)));

// ── CM-P1-010: an open unauthorised-sending-source alert is not silent ────────
function mockAlertDb(rows, { fail = false } = {}) {
  const calls = [];
  return { calls, prepare: (sql) => ({ bind: (...args) => ({ all: async () => {
    calls.push({ sql, args });
    if (fail) throw new Error("D1 unavailable");
    return { results: rows };
  } }) }) };
}
const tierMeta = (tier) => JSON.stringify({ corroboration_tier: tier });
const alertRows = [
  { dedupe_key: "spf_unauthorised:fixture.example:203.0.113.5", severity: "medium", created_at: "2026-10-16T12:00:00Z", metadata_json: tierMeta("unauthorised_confirmed") },
  { dedupe_key: "spf_unauthorised:fixture.example:198.51.100.7", severity: "low", created_at: "2026-10-10T12:00:00Z", metadata_json: tierMeta("fail_comparison_unavailable") },
  { dedupe_key: "spf_unauthorised:fixture.example:203.0.113.5", severity: "low", created_at: "2026-10-01T12:00:00Z", metadata_json: tierMeta("fail_comparison_unavailable") },
];
const alertDb = mockAlertDb(alertRows);
const senderAlerts = await loadUnauthorisedSendingSourceAlerts({ cybermeters_db: alertDb }, { workspaceId: "ws_fixture", domain: "Fixture.example", now: enrichmentAt });
const alertPrefix = spfUnauthorisedDedupePrefix("Fixture.example");
check("CM-P1-010 sender alerts are read per source, tenant-scoped, within the corroboration window",
  senderAlerts.state === "read" && senderAlerts.count === 2 &&
  JSON.stringify(senderAlerts.source_ips) === JSON.stringify(["203.0.113.5", "198.51.100.7"]) &&
  senderAlerts.latest_at === "2026-10-16T12:00:00Z" && senderAlerts.highest_severity === "medium" && senderAlerts.window_days === 30 &&
  senderAlerts.outside_authorisation === 1 && senderAlerts.comparison_unavailable === 1 &&
  alertDb.calls.length === 1 && JSON.stringify(alertDb.calls[0].args) === JSON.stringify(["ws_fixture", alertPrefix.length, "spf_unauthorised:fixture.example:"]) &&
  /w\.deleted_at IS NULL/.test(alertDb.calls[0].sql) && /n\.type = 'email_spf_unauthorised_source'/.test(alertDb.calls[0].sql) &&
  /datetime\('now', '-30 days'\)/.test(alertDb.calls[0].sql) && /LIMIT \d+/.test(alertDb.calls[0].sql));
const healthyEmail = { dmarc_state: { enforcement_level: "reject_enforced" } };
const emailEntryOf = (emailModule) => resolveSecurityCheckDomainStates(reportWith({ email_security: emailModule })).find((entry) => entry.domain_key === "email_protection");
const emailBaseline = emailEntryOf(healthyEmail);
const emailWithAlert = emailEntryOf({ ...healthyEmail, unauthorised_sending_sources: senderAlerts });
check("CM-P1-010 healthy decision is unchanged but coverage and summary name the open alert",
  emailBaseline?.state === "assessed_healthy" && emailBaseline.coverage === "complete" &&
  emailWithAlert?.state === "assessed_healthy" && emailWithAlert.coverage === "partial" && emailWithAlert.finding_count === 0 &&
  /2 sending sources reported SPF failure for this domain in DMARC aggregate reports in the last 30 days \(1 outside your resolved SPF authorisation; 1 where that comparison was unavailable\)/.test(emailWithAlert.summary) &&
  /does not change the published-record conclusion/.test(emailWithAlert.summary) &&
  emailWithAlert.summary.startsWith(emailBaseline.summary));
const uncomparedOnly = emailEntryOf({ ...healthyEmail, unauthorised_sending_sources: { ...senderAlerts, count: 1, source_ips: ["198.51.100.7"], outside_authorisation: 0, comparison_unavailable: 1 } });
check("CM-P1-010 a source whose comparison was unavailable is never called unauthorised",
  uncomparedOnly?.state === "assessed_healthy" && uncomparedOnly.coverage === "partial" &&
  /1 sending source reported SPF failure .* \(1 where that comparison was unavailable\); the open Email Protection alert names it\./.test(uncomparedOnly.summary) &&
  !/outside your/.test(uncomparedOnly.summary));
const quarantineWithAlert = emailEntryOf({ ...roundTrip(liveEmail), unauthorised_sending_sources: { ...senderAlerts, count: 1, source_ips: ["203.0.113.5"], outside_authorisation: 1, comparison_unavailable: 0 } });
check("CM-P1-010 issue decision also carries the caveat",
  quarantineWithAlert?.state === "issue_detected" && quarantineWithAlert.coverage === "partial" &&
  /1 sending source reported SPF failure .* \(1 outside your resolved SPF authorisation\); the open Email Protection alert names it\./.test(quarantineWithAlert.summary));
const silentVariants = [
  { ...healthyEmail, unauthorised_sending_sources: { ...senderAlerts, count: 0, source_ips: [] } },
  { ...healthyEmail, unauthorised_sending_sources: { ...senderAlerts, state: "unavailable", count: null, source_ips: [] } },
  { ...healthyEmail, unauthorised_sending_sources: { ...senderAlerts, state: "unavailable", count: 3 } },
  healthyEmail,
];
check("CM-P1-010 zero alerts, an unreadable ledger and legacy reports stay as before",
  silentVariants.every((mod) => JSON.stringify(emailEntryOf(mod)) === JSON.stringify(emailBaseline)));
const alertReadFailed = await loadUnauthorisedSendingSourceAlerts({ cybermeters_db: mockAlertDb([], { fail: true }) }, { workspaceId: "ws_fixture", domain: "fixture.example", now: enrichmentAt });
const alertNoDb = await loadUnauthorisedSendingSourceAlerts({}, { workspaceId: "ws_fixture", domain: "fixture.example", now: enrichmentAt });
const alertNoWorkspace = await loadUnauthorisedSendingSourceAlerts({ cybermeters_db: alertDb }, { workspaceId: null, domain: "fixture.example", now: enrichmentAt });
check("CM-P1-010 read failure, missing database and missing workspace never fabricate an alert",
  [alertReadFailed, alertNoDb, alertNoWorkspace].every((out) => out.state === "unavailable" && out.count === null && out.source_ips.length === 0 && out.outside_authorisation === null) &&
  alertReadFailed.reason === "alert_read_failed" && alertNoDb.reason === "database_unavailable" && alertNoWorkspace.reason === "no_workspace_context");
const alertAttachAt = scanEngineSource.indexOf("modules.email_security.unauthorised_sending_sources = await loadUnauthorisedSendingSourceAlerts(env, {");
check("CM-P1-010 scan attaches the alert summary before the report freezes",
  alertAttachAt > 0 && alertAttachAt < scanEngineSource.indexOf("const report = {") &&
  /if \(!modules\.email_security\.error\) \{\n\s+modules\.email_security\.unauthorised_sending_sources/.test(scanEngineSource));
const emailSnapshot = snapshot(roundTrip(reportWith({ email_security: { ...healthyEmail, unauthorised_sending_sources: senderAlerts } })))
  .domains.find((entry) => entry.domain_key === "email_protection");
check("CM-P1-010 snapshot email domain carries the caveat with the decision unchanged",
  emailSnapshot?.state === "assessed_healthy" && emailSnapshot.coverage === "partial" && /sending sources reported SPF failure for this domain/.test(emailSnapshot.summary));

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

// ── CM-P1-011: missing HSTS is medium once an HTTP→HTTPS redirect was observed ──
{
  const hstsModules = (redirect) => ({
    dns: { resolves: true }, ssl: { https_available: true, http_redirects_to_https: redirect },
    headers: { accessible: true, final_https: true, validation_uncertain: false, status_code: 200,
      values: { "strict-transport-security": null } },
    email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  });
  const hsts = (redirect) => computeScore(hstsModules(redirect), "hsts.example.com").findings
    .find((finding) => finding.id === "header_missing_strict_transport_security");
  check("CM-P1-011 missing HSTS with an observed redirect is medium",
    hsts(true)?.severity === "medium" && hsts(true)?.score_impact === -5, JSON.stringify(hsts(true)));
  check("CM-P1-011 missing HSTS without an observed redirect stays high", hsts(false)?.severity === "high");
}

// ── CM-P1-012: the weak-CSP description states its directive once ─────────────
{
  const cspDescription = (policy) => computeScore({
    dns: { resolves: true }, ssl: { https_available: true, http_redirects_to_https: true },
    headers: { accessible: true, final_https: true, validation_uncertain: false, status_code: 200, values: {
      "strict-transport-security": "max-age=31536000; includeSubDomains", "content-security-policy": policy,
      "x-frame-options": "DENY", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
      "permissions-policy": "geolocation=()" } },
    email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  }, "csp.example.com").findings.find((finding) => finding.id === "csp_weak_policy")?.description || "";
  const script = cspDescription("default-src 'self'; script-src 'self' 'unsafe-inline'");
  const style = cspDescription("default-src 'self'; style-src 'self' 'unsafe-inline'");
  check("CM-P1-012 weak CSP description names the directive once",
    script.includes("in script-src") && !script.includes("CSP contains") && (script.match(/script-src/g) || []).length === 1
      && style.includes("in style-src only") && !style.includes("CSP permits") && (style.match(/style-src/g) || []).length === 1,
    `${script} | ${style}`);
}

// ── CM-P1-013: the BRI HSTS weight follows the HSTS severity policy ──────────
{
  const { deriveScanBusinessRisk, BUSINESS_RISK_METHODOLOGY_VERSION } = await import(engine("business-risk.js"));
  const websiteTrust = (redirect) => {
    const modules = {
      dns: { resolves: true }, ssl: { https_available: true, http_redirects_to_https: redirect },
      headers: { accessible: true, final_https: true, validation_uncertain: false, status_code: 200, values: {
        "strict-transport-security": null, "content-security-policy": "default-src 'self'", "x-frame-options": "DENY",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()" } },
      email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
    };
    const findings = computeScore(modules, "bri-hsts.example.com").findings;
    return deriveScanBusinessRisk({ findings, modules }).categories.website_trust.score;
  };
  check("CM-P1-013 missing HSTS with an observed redirect deducts 10 from Website Trust", websiteTrust(true) === 90,
    `website_trust=${websiteTrust(true)}`);
  check("CM-P1-013 missing HSTS without an observed redirect deducts 20", websiteTrust(false) === 80,
    `website_trust=${websiteTrust(false)}`);
  check("BRI methodology stamp is current (2026-10-21.2)", BUSINESS_RISK_METHODOLOGY_VERSION === "2026-10-21.2");

  // Attack Surface reads confirmed exposure findings (21 Oct 2026). With three or
  // more reachable hosts the reachable-host deduction is capped, so before this a
  // newly exposed management tool or login-protected admin interface moved nothing.
  const reachable = (extra = []) => ({ checked: 4, reachable: 4, assets: [
    { host: "www.bri-asm.example.com", status: 200, reachable: true, title: "Home", tech: [] },
    { host: "api.bri-asm.example.com", status: 404, reachable: true, title: null, tech: [] },
    { host: "app.bri-asm.example.com", status: 200, reachable: true, title: "App", tech: [] },
    ...extra,
  ], source: "http_probe" });
  const attack = (assets) => {
    const modules = { dns: { resolves: true }, ssl: { https_available: true, http_redirects_to_https: true },
      subdomains: { wildcard_dns: false, items: assets.assets.map((a) => a.host) }, asset_exposure: assets };
    const findings = computeScore(modules, "bri-asm.example.com").findings;
    return { score: deriveScanBusinessRisk({ findings, modules }).categories.attack_surface_exposure.score,
      ids: new Set(findings.map((f) => f.id)) };
  };
  const baseline = attack(reachable());
  const adminNoForm = attack(reachable([{ host: "admin.bri-asm.example.com", status: 200, reachable: true, title: "Admin test page", tech: [],
    authentication_observation: { schema_version: "identity_http.v1", password_form_observed: null } }]));
  const adminWithForm = attack(reachable([{ host: "admin.bri-asm.example.com", status: 200, reachable: true, title: "Admin login", tech: [],
    authentication_observation: { schema_version: "identity_http.v1", password_form_observed: true } }]));
  const tool = attack(reachable([{ host: "ci.bri-asm.example.com", status: 200, reachable: true, title: "Dashboard [Jenkins]", tech: ["Jenkins"] }]));
  // BRI 2026-10-21.2: reachable hosts are inventory and missing vendor data is
  // not a risk, so a clean domain with public hosts and no finding scores 100.
  check("BRI attack surface: reachable hosts and no finding cost nothing (100)", baseline.score === 100, `baseline=${baseline.score}`);
  check("BRI attack surface: an admin name/title with no login form deducts nothing beyond the capped host count",
    adminNoForm.score === baseline.score, `baseline=${baseline.score} adminNoForm=${adminNoForm.score}`);
  check("BRI attack surface: a confirmed admin interface (login form) deducts 10",
    adminWithForm.ids.has("asset_exposure_admin_interface") && adminWithForm.score === baseline.score - 10,
    `baseline=${baseline.score} adminWithForm=${adminWithForm.score}`);
  check("BRI attack surface: an exposed management tool deducts 15",
    tool.ids.has("asset_exposure_sensitive_tool") && tool.score === baseline.score - 15,
    `baseline=${baseline.score} tool=${tool.score} ids=${[...tool.ids].join(",")}`);
  // Mutant: drop the confirmed-exposure deductions; the category must then stop
  // moving for a confirmed admin interface (the pre-21-Oct-2026 behaviour).
  {
    const fsm = await import("node:fs"), osm = await import("node:os"), pm = await import("node:path");
    const { fileURLToPath: f2p, pathToFileURL: p2u } = await import("node:url");
    const file = f2p(engine("business-risk.js"));
    const source = fsm.readFileSync(file, "utf8");
    const anchor = '  if (findingIds.has("asset_exposure_sensitive_tool")) attackDed += 15;\n  if (findingIds.has("asset_exposure_admin_interface")) attackDed += 10;\n';
    check("BRI mutant anchor present exactly once", source.split(anchor).length === 2);
    const dir = fsm.mkdtempSync(pm.join(osm.tmpdir(), "bri-mutant-"));
    try {
      const mutated = source.replace(anchor, "")
        .replace(/from "(\.\.?\/[^"]+)"/g, (_, rel) => `from ${JSON.stringify(p2u(pm.resolve(pm.dirname(file), rel)).href)}`);
      fsm.writeFileSync(pm.join(dir, "bri.mjs"), mutated);
      const mutant = await import(p2u(pm.join(dir, "bri.mjs")).href);
      const modules = { dns: { resolves: true }, ssl: { https_available: true, http_redirects_to_https: true },
        subdomains: { wildcard_dns: false, items: [] }, asset_exposure: reachable([{ host: "admin.bri-asm.example.com", status: 200, reachable: true,
          title: "Admin login", tech: [], authentication_observation: { schema_version: "identity_http.v1", password_form_observed: true } }]) };
      const findings = computeScore(modules, "bri-asm.example.com").findings;
      check("MUTANT without the confirmed-exposure deductions leaves Attack Surface unmoved (caught)",
        mutant.deriveScanBusinessRisk({ findings, modules }).categories.attack_surface_exposure.score === baseline.score);
    } finally { fsm.rmSync(dir, { recursive: true, force: true }); }
  }
  const { readFileSync } = await import("node:fs");
  const engineSource = readFileSync(new URL(engine("scan-engine.js")), "utf8");
  check("CM-P1-013 the scan-engine BRS passes the HSTS finding's severity",
    engineSource.includes("hstsMissingSeverity:   hstsMissingSeverity(findings.filter(isActionableFinding)),"));
}

console.log(`Launch state accuracy fixtures: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
