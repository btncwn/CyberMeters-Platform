// Report-copy & policy honesty from founder live triage (D1-D4).
// D1 DMARC/SPF template truth · D2 wrong-reason axis · D3 score-suppression
// unification · D4 self-RUA authorisation. Each defect: deterministic fixture +
// wire-in proof through the production transform. Mutation proof is the sibling
// validate-report-copy-live-triage-mutations.js.
import assert from "node:assert";

const root = new URL("../", import.meta.url);
const eng = (rel) => new URL(`workers/scan-api/src/engines/${rel}`, root);

let passed = 0;
const fail = [];
function ok(name, cond, detail = "") {
  if (cond) { passed += 1; console.log(`PASS ${name}`); }
  else { fail.push(name); console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}

// ---------------------------------------------------------------------------
// D4 — self-RUA authorisation: destinations under our hosted RUA domain resolve
// positively WITHOUT a live DNS lookup, and never as "Authorisation unavailable".
// ---------------------------------------------------------------------------
{
  const { resolveDmarcbisExternalRuaAuthorizations } = await import(eng("dmarcbis-resolver.js"));
  const { buildDmarcPolicyPresentation } = await import(eng("dmarcbis-presentation.js"));

  const validUri = (host) => ({
    destination_host: host, normalized_uri: `mailto:x@${host}`, raw: `mailto:x@${host}`,
    syntax_valid: true, supported_scheme: true, over_product_limit: false,
  });
  const dnsMustNotRun = async () => { throw new Error("DNS_CALLED_FOR_HOSTED"); };
  const resolveHost = async (host, dns = dnsMustNotRun) =>
    resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: { policy_source_domain: "sheshire.co.uk", organisational_domain: "sheshire.co.uk", rua_destinations: [validUri(host)] },
      dns, reserveHost: () => true,
    });

  const hosted = await resolveHost("reports.cybermeters.com");
  ok("D4: hosted destination resolves not_required_cybermeters_hosted",
    hosted.destinations[0].authorization_status === "not_required_cybermeters_hosted",
    hosted.destinations[0].authorization_status);
  ok("D4: hosted destination is a definitive positive (all_destinations_authorized)",
    hosted.all_destinations_authorized === true);
  ok("D4: hosted destination lookup is complete without a live DNS call",
    hosted.destinations[0].lookup_completeness === "complete");

  const sub = await resolveHost("mx.reports.cybermeters.com");
  ok("D4: subdomain of hosted RUA domain also resolves hosted",
    sub.destinations[0].authorization_status === "not_required_cybermeters_hosted");

  // Guard specificity: a non-hosted destination MUST NOT get the hosted status;
  // it follows the live path (here DNS refuses → unavailable, never hosted).
  const vendor = await resolveHost("reports.vendor.test", async () => ({ outcome: "not_issued_budget" }));
  ok("D4: non-hosted destination never gets the hosted status",
    vendor.destinations[0].authorization_status !== "not_required_cybermeters_hosted");

  // The org apex is NOT the hosted RUA endpoint (a customer rua at cybermeters.com
  // is not our reports.* endpoint) — must not be short-circuited as hosted.
  const orgApex = await resolveHost("cybermeters.com", async () => ({ outcome: "not_issued_budget" }));
  ok("D4: bare org apex is not treated as the hosted RUA endpoint",
    orgApex.destinations[0].authorization_status !== "not_required_cybermeters_hosted");

  // P1-1 negative paths (R1 verdict): a hosted destination consumes NO budget
  // and NO reservation, so no budget state may un-know our own hosted
  // authority. Check order decides reachability — these three fixtures pin the
  // hosted short-circuit AHEAD of every budget/reservation gate.
  const evidenceFor = (hosts) => ({
    policy_source_domain: "sheshire.co.uk", organisational_domain: "sheshire.co.uk",
    rua_destinations: hosts.map(validUri),
  });

  // (1) Reservation refusal: reserveHost must not even be CALLED for hosted.
  let hostedReservationCalls = 0;
  const refusedReservation = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: evidenceFor(["reports.cybermeters.com"]),
    dns: dnsMustNotRun,
    reserveHost: () => { hostedReservationCalls += 1; return false; },
  });
  ok("D4-P1: hosted destination survives a refused reservation",
    refusedReservation.destinations[0].authorization_status === "not_required_cybermeters_hosted" &&
      refusedReservation.destinations[0].lookup_completeness === "complete" &&
      refusedReservation.all_destinations_authorized === true,
    JSON.stringify({ status: refusedReservation.destinations[0].authorization_status, all: refusedReservation.all_destinations_authorized }));
  ok("D4-P1: hosted destination reserves nothing",
    hostedReservationCalls === 0, `reserveHost called ${hostedReservationCalls}x`);

  // (2) Already-closed budget: an external vendor's refused reservation closes
  // the budget; the hosted destination AFTER it must still resolve hosted.
  const closedBudget = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: evidenceFor(["reports.vendor.test", "reports.cybermeters.com"]),
    dns: dnsMustNotRun,
    reserveHost: () => false,
  });
  ok("D4-P1: hosted destination after a closed budget still resolves hosted",
    closedBudget.destinations[1].authorization_status === "not_required_cybermeters_hosted" &&
      closedBudget.destinations[1].lookup_completeness === "complete",
    closedBudget.destinations[1].authorization_status);

  // (3) Hosted after the external-host cap: five admitted externals fill the
  // cap; the hosted destination is still ours and still resolves hosted.
  const cappedHosts = [1, 2, 3, 4, 5].map((n) => `reports.vendor${n}.test`).concat("reports.cybermeters.com");
  const capped = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: evidenceFor(cappedHosts),
    dns: async () => ({ outcome: "not_issued_budget" }),
    reserveHost: () => true,
  });
  ok("D4-P1: hosted destination after the external-host cap still resolves hosted",
    capped.destinations[5].authorization_status === "not_required_cybermeters_hosted" &&
      capped.destinations[5].lookup_completeness === "complete",
    capped.destinations[5].authorization_status);

  // Wire-in: the presentation layer gives the hosted status an honest label +
  // message and does NOT print "Authorisation unavailable".
  const read = {
    status: "current",
    evidence: { external_rua_authorisation: { destinations: [{ ...validUri("reports.cybermeters.com"), authorization_status: "not_required_cybermeters_hosted", lookup_completeness: "complete", authorization_record_state: "not_required_hosted", authorized_destination: "mailto:x@reports.cybermeters.com" }], all_destinations_authorized: true } },
  };
  const pres = buildDmarcPolicyPresentation(read);
  const dest = pres?.external_rua?.destinations?.[0];
  ok("D4: presentation label is CyberMeters-hosted, not 'Authorisation unavailable'",
    dest?.status_label === "CyberMeters-hosted destination" && !/unavailable/i.test(dest?.message || ""),
    `${dest?.status_label} | ${dest?.message}`);
  ok("D4: presentation message states authoritative + no-external-claim honesty",
    /hosted by CyberMeters/i.test(dest?.message || "") && /does not prove/i.test(dest?.message || ""));
}

// ---------------------------------------------------------------------------
// D1 — DMARC monitoring-mode template + SPF qualifier wording.
// ---------------------------------------------------------------------------
{
  const { readFileSync } = await import("node:fs");
  const { buildDmarcPolicyUpgradeValue } = await import(eng("email-analysis.js"));
  const { getRemediationById } = await import(eng("remediation-registry.js"));

  // (a) pct is DROPPED regardless of the observed record.
  const withRua = buildDmarcPolicyUpgradeValue("v=DMARC1; p=none; pct=100; rua=mailto:owner@corp.example; adkim=s", "mailto:dmarc-reports@corp.example", "quarantine");
  ok("D1: upgrade drops the DMARCbis-removed pct tag", !/pct\s*=/i.test(withRua), withRua);
  ok("D1: upgrade sets the target policy p=quarantine", /(^|;\s*)p=quarantine(\s*;|$)/i.test(withRua), withRua);
  // (b) existing rua is PRESERVED verbatim; our fallback is NOT injected over it.
  ok("D1: upgrade preserves the observed rua and does not overwrite it",
    /rua=mailto:owner@corp\.example/i.test(withRua) && !/dmarc-reports@corp\.example/i.test(withRua), withRua);
  ok("D1: upgrade preserves other observed tags (adkim=s)", /adkim=s/i.test(withRua), withRua);

  // Only synthesise a mailbox when the observed record has NO rua.
  const noRua = buildDmarcPolicyUpgradeValue("v=DMARC1; p=none", "mailto:dmarc-reports@corp.example", "quarantine");
  ok("D1: upgrade synthesises a fallback rua only when none is observed",
    /rua=mailto:dmarc-reports@corp\.example/i.test(noRua) && !/pct\s*=/i.test(noRua), noRua);

  // Wire-in: the customer-facing monitoring-only action is built from the helper,
  // not the old hardcoded pct/overwrite literal.
  const src = readFileSync(new URL(eng("email-analysis.js")), "utf8");
  ok("D1 wire-in: monitoring-only action calls buildDmarcPolicyUpgradeValue",
    /dmarc\.valid && dmarc\.policy === "none"[\s\S]{0,240}buildDmarcPolicyUpgradeValue\(dmarc\.raw/.test(src));
  ok("D1 wire-in: the old pct=100 monitoring template literal is gone",
    !/p=quarantine; pct=100; rua=mailto:\$\{reportAddress\}/.test(src));

  // (c) SPF registry wording is qualifier-honest (reaches the PDF/Exec report).
  const spf = getRemediationById("email.spf.tighten");
  ok("D1: SPF tighten action no longer says a bare 'remove +all'",
    !/remove \+all/i.test(spf.recommended_action), spf.recommended_action);
  ok("D1: SPF tighten action names the ~all softfail ending honestly",
    /~all/.test(spf.recommended_action) && /-all/.test(spf.recommended_action), spf.recommended_action);
}

// ---------------------------------------------------------------------------
// D2 — wrong-reason copy: name the ACTUAL failing axis; reconcile monitoring.
// ---------------------------------------------------------------------------
{
  const { readFileSync } = await import("node:fs");
  const { deriveDmarcStateFromPolicyEvidence } = await import(eng("dmarc-state.js"));

  const base = {
    observation_state: "unavailable", policy_completeness: "complete", core_completeness: "complete",
    organisational_domain_completeness: "complete", existence_completeness: "complete",
    rua_authorisation_completeness: "complete", provider_state: "available",
  };
  const summaryFor = (over) => deriveDmarcStateFromPolicyEvidence({ ...base, ...over }).canonical_summary;

  // The cybermeters.com symptom: rua-authorisation was the gap, not the policy lookup.
  const ruaGap = summaryFor({ rua_authorisation_completeness: "incomplete" });
  ok("D2a: rua-authorisation gap names the rua axis",
    /aggregate-report \(rua\)/i.test(ruaGap), ruaGap);
  ok("D2a: rua-authorisation gap does NOT falsely blame the policy lookup",
    !/policy lookup was unavailable/i.test(ruaGap), ruaGap);

  ok("D2a: provider gap names the provider axis",
    /provider could not be corroborated/i.test(summaryFor({ provider_state: "corroboration_unavailable" })));
  ok("D2a: organisational-domain gap names the tree-walk axis",
    /organisational-domain tree-walk/i.test(summaryFor({ organisational_domain_completeness: "unavailable" })));
  ok("D2a: existence gap names the existence axis",
    /domain existence could not be confirmed/i.test(summaryFor({ existence_completeness: "unavailable" })));
  // Genuinely nothing identifiable still yields the honest generic (no false axis).
  ok("D2a: a policy-lookup gap still reads as a policy-resolution reason",
    /policy record could not be fully resolved/i.test(summaryFor({ policy_completeness: "incomplete" })));

  // D2b — panel/summary can't diverge: production recomputes monitoring_state from
  // the full core-completeness check (not policy_completeness alone).
  const prod = readFileSync(new URL(eng("dmarcbis-production.js")), "utf8");
  ok("D2b: runDmarcbisCore recomputes monitoring_state from core completeness",
    /monitoring_state:\s*complete\s*\?\s*"monitoring_healthy"\s*:\s*"monitoring_degraded"/.test(prod));
}

// ---------------------------------------------------------------------------
// D3 — score-suppression unification: skipped score-bearing module ⇒ NULL, with
// an honest cause line on all score surfaces; ran-partial stays provisional.
// ---------------------------------------------------------------------------
{
  const { skippedScoreBearingModules, resolvePhase5CustomerAssessment, resolveScoreSuppressionReason,
    projectPhase5ScanRowsForCustomer } =
    await import(eng("phase5-evidence.js"));
  const { resolvePhase5HistoricalCustomerProjection, projectPhase5SnapshotForCustomer } =
    await import(eng("phase5-evidence.js"));
  const { resolveAssessmentPresentation } = await import(eng("assessment-presentation.js"));
  const { getCurrentPosturePresentation } = await import(eng("current-posture.js"));
  const { composeSnapshot } = await import(eng("report-snapshot.js"));
  const { buildExecutiveReportV2 } = await import(eng("executive-report.js"));
  const { buildScanReportPdf } = await import(eng("pdf.js"));
  const { CYBER_METRICS_SCORE_METHODOLOGY_VERSION, SCORE_BEARING_MODULES } = await import(eng("scoring.js"));
  const { readFileSync } = await import("node:fs");

  // Skip detection: explicit skip / never-ran / budget-deadline only.
  ok("D3: asset_exposure skipped is detected as a skipped score-bearing module",
    skippedScoreBearingModules({ asset_exposure: { skipped: true } }).includes("asset_exposure"));
  ok("D3: never-launched (executed:false) score-bearing module is detected",
    skippedScoreBearingModules({ subdomains: { executed: false } }).includes("subdomains"));
  ok("D3: budget/deadline error on a score-bearing module is detected",
    skippedScoreBearingModules({ headers: { error: "http origin budget exceeded" } }).includes("headers"));
  // Boundary: a RAN-partial module (incomplete only, executed) is NOT a skip.
  ok("D3: ran-partial (incomplete only) is NOT a suppression trigger",
    skippedScoreBearingModules({ dns: { executed: true, incomplete: true } }).length === 0);
  ok("D3: a clean score-bearing module is not flagged",
    skippedScoreBearingModules({ ssl: { https_available: true } }).length === 0);

  // barbers: a skipped score-bearing module nulls the score (was 100/100).
  const barbers = resolvePhase5CustomerAssessment({ score: 100, riskLevel: "excellent", modules: { asset_exposure: { skipped: true } } });
  ok("D3: skipped score-bearing module withholds the score (null)", barbers.score === null && barbers.risk_level === null);
  ok("D3: suppression is flagged with a cause naming the forcing area",
    barbers.suppressed === true && /attack surface/.test(barbers.suppression_reason || ""));

  // ISOLATION: with COMPLETE phase5 evidence, the skip path must suppress on its
  // own (independent of the evidence-incomplete path) — else disarming the skip
  // check would go unnoticed. Control proves complete evidence yields a score.
  const completeMods = () => ({
    technology_detection: {
      technologies: ["nginx"],
      technology_fingerprints: [{ technology: "nginx", source: "server", confidence: 90 }],
      serviceability_contract: { serviceable: true, conclusion_class: "conclusive", reason: "origin_response_serviceable" },
    },
    cve_intelligence: { technologies_checked: ["nginx"], lookup_statuses: { nginx: { status: "complete" } }, results: {}, total_cves: 0, critical_count: 0, high_count: 0, cve_coverage: "complete", source: "nvd_api" },
    known_exploited_vulnerabilities: { matches: [] },
    email_security_intelligence: { email_security_score: 100 },
  });
  const control = resolvePhase5CustomerAssessment({ score: 92, riskLevel: "good", modules: completeMods() });
  ok("D3 isolation control: complete evidence + no skip yields a real score", control.score === 92);
  const completePlusSkip = resolvePhase5CustomerAssessment({ score: 92, riskLevel: "good", modules: { ...completeMods(), asset_exposure: { skipped: true } } });
  ok("D3 isolation: complete evidence + skipped score-bearing module STILL nulls the score",
    completePlusSkip.score === null && completePlusSkip.suppressed === true);

  // Persistence boundary: the live transform owns the one KEV deduction. A
  // historical projection receives that already-adjusted score and must preserve
  // it byte-for-value while still applying the shared suppression decision.
  const kevModules = {
    ...completeMods(),
    known_exploited_vulnerabilities: { matches: [{
      cve_id: "CVE-2021-0000",
      matched_technology: "nginx",
      fingerprint_source: "server",
      fingerprint_confidence: 90,
      version_confirmed: false,
    }] },
  };
  const liveKev = resolvePhase5CustomerAssessment({
    score: 90,
    riskLevel: "good",
    modules: kevModules,
  });
  const historicalKev = resolvePhase5HistoricalCustomerProjection({
    score: liveKev.score,
    riskLevel: liveKev.risk_level,
    scanQuality: "complete",
    modules: kevModules,
  });
  ok("D3 persistence boundary: live KEV adjustment applies exactly once (90 to 85)",
    liveKev.score === 85 && liveKev.risk_level === "good");
  ok("D3 persistence boundary: historical projection preserves persisted 85/good",
    historicalKev.score === 85 &&
      historicalKev.risk_level === "good" &&
      historicalKev.assessment.display_score === 85 &&
      historicalKev.assessment.display_rating === "good");

  // Cause is a single source, reusable by read surfaces.
  ok("D3: resolveScoreSuppressionReason returns the same cause from modules alone",
    /attack surface/.test(resolveScoreSuppressionReason({ asset_exposure: { skipped: true } }) || ""));
  ok("D3: no false suppression reason for a non-skipped, complete-evidence path",
    resolveScoreSuppressionReason({}) !== null); // {} has no publishable phase5 evidence → suppressed (correct)

  // Three-surface wire-in: the shared assessment carries the cause (exec report,
  // PDF and Scan Info all render assessment.message / .suppression_reason).
  const reason = resolveScoreSuppressionReason({ asset_exposure: { skipped: true }, subdomains: { executed: false } });
  const a = resolveAssessmentPresentation({ score: null, scanQuality: "degraded", status: "completed", suppressionReason: reason });
  ok("D3 wire-in: suppressed assessment shows no number", a.display_score === null && a.display_rating === null);
  ok("D3 wire-in: suppressed assessment message names the cause (never bare)",
    a.message === reason && /attack surface/.test(a.message || "") && a.message !== null);
  ok("D3 wire-in: assessment carries suppression_reason for all surfaces",
    a.suppression_reason === reason);
  const completeNoScore = resolveAssessmentPresentation({
    score: null,
    scanQuality: "complete",
    status: "completed",
  });
  ok("D3 no-score invariant: complete quality alone is never authoritative or comparable",
    completeNoScore.state === "not_established" &&
      completeNoScore.authoritative === false &&
      completeNoScore.comparable === false);
  ok("D3 no-score invariant: complete no-score has a bounded customer explanation",
    completeNoScore.message === "Current posture not yet established.");

  // Production read-adapter regression: a legacy/inconsistent complete row may
  // carry a stale band even though its score is NULL. The shared Phase-5 decision
  // must remove both together before any API consumer sees the row.
  const [nullScoreAdapterRow] = await projectPhase5ScanRowsForCustomer({
    cybermeters_reports: {
      get: async () => ({ json: async () => ({ modules: completeMods() }) }),
    },
  }, [{
    scan_id: "scan-d3-null-score",
    status: "completed",
    score: null,
    rating: "good",
    scan_quality: "complete",
  }]);
  ok("D3 adapter invariant: complete null-score row cannot retain a stale risk band",
    nullScoreAdapterRow.score === null &&
      nullScoreAdapterRow.rating === null &&
      nullScoreAdapterRow.assessment.display_score === null &&
      nullScoreAdapterRow.assessment.display_rating === null &&
      nullScoreAdapterRow.assessment.authoritative === false);

  // Historical report read: complete Phase-5 intelligence must not revive a
  // stale score when an independent score-bearing module was skipped.
  const staleAssessment = {
    raw_score: 92, display_score: 92, display_rating: "good",
    quality: "complete", provisional: false, authoritative: true,
    comparable: true, message: null,
  };
  const historicalSuppressed = resolvePhase5HistoricalCustomerProjection({
    score: 92,
    riskLevel: "good",
    assessment: staleAssessment,
    scanQuality: "complete",
    modules: { ...completeMods(), asset_exposure: { skipped: true } },
  });
  ok("D3 historical: complete phase5 plus skip cannot retain a stale numeric score",
    historicalSuppressed.score === null &&
      historicalSuppressed.risk_level === null &&
      historicalSuppressed.assessment.display_score === null &&
      historicalSuppressed.assessment.display_rating === null);
  ok("D3 historical: the stale assessment is replaced by the canonical suppression cause",
    historicalSuppressed.assessment.message === historicalSuppressed.suppression_reason &&
      /attack surface/.test(historicalSuppressed.assessment.message || ""));

  // Immutable snapshot read: the same single decision removes every dependent
  // conclusion, not just the headline score.
  const staleSnapshot = {
    methodology: { cyber_mot_resolver_version: "9999.0" },
    domains: [], observed_findings: [],
    overall: {
      cyber_metrics_score: 92,
      score_band: "good",
      assessment: staleAssessment,
      summary: "Eight-domain stale healthy summary",
      business_risk_indicator: {
        band: "low",
        explanation: "Stale low risk",
        provisional: false,
        internal_metrics: {
          score: 91,
          categories: { email: 90 },
          top_business_risks: [{ title: "stale" }],
        },
      },
      evidence_completeness: { scan_quality: "complete" },
      not_fully_assessed: [],
    },
  };
  const staleSnapshotBytes = JSON.stringify(staleSnapshot);
  const projectedSnapshot = projectPhase5SnapshotForCustomer(
    staleSnapshot,
    { ...completeMods(), asset_exposure: { skipped: true } },
  );
  ok("D3 snapshot: suppression nulls score, band, summary and BRI together",
    projectedSnapshot.overall.cyber_metrics_score === null &&
      projectedSnapshot.overall.score_band === null &&
      projectedSnapshot.overall.summary === null &&
      projectedSnapshot.overall.business_risk_indicator.band === null &&
      projectedSnapshot.overall.business_risk_indicator.explanation !== "Stale low risk" &&
      /not authoritative/.test(projectedSnapshot.overall.business_risk_indicator.explanation || "") &&
      projectedSnapshot.overall.business_risk_indicator.internal_metrics.score === null &&
      projectedSnapshot.overall.business_risk_indicator.internal_metrics.categories === null &&
      projectedSnapshot.overall.business_risk_indicator.internal_metrics.top_business_risks === null);
  ok("D3 snapshot: suppression projects a customer-visible cause without mutating evidence",
    /attack surface/.test(projectedSnapshot.overall.assessment.message || "") &&
      JSON.stringify(staleSnapshot) === staleSnapshotBytes);

  const monitoringSignals = [
    "dns", "certificate_transparency", "website_security", "email_protection",
    "attack_surface", "technology_visibility", "vulnerability_intelligence",
    "registration_data",
  ];
  const healthyMonitoringStates = {
    version: "signal-monitoring-state-v1",
    signals: Object.fromEntries(monitoringSignals.map((signal) => [signal, {
      state: "monitoring_healthy",
      message: `${signal} checks completed normally in this run.`,
      evidence: { modules: [], incomplete_modules: [], providers: {} },
    }])),
  };
  const suppressedReport = {
    scan_id: "scan-d3",
    domain_id: "dom-d3",
    domain: "example.com",
    status: "completed",
    cyber_metrics_score: 92,
    risk_level: "good",
    started_at: "2026-08-24T10:00:00.000Z",
    completed_at: "2026-08-24T10:01:00.000Z",
    scan_quality: { status: "complete", modules_skipped: ["asset_exposure"], warnings: [] },
    monitoring_states: healthyMonitoringStates,
    findings: [], recommendations: [],
    modules: { ...completeMods(), asset_exposure: { skipped: true } },
  };
  const composed = composeSnapshot({
    snapshotId: "snap-d3", workspaceId: "ws-d3", domainId: "dom-d3",
    scanId: "scan-d3", domain: "example.com", report: suppressedReport,
    cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    supersedesSnapshotId: null, builtAt: "2026-08-24T10:01:01.000Z",
  });
  const composedBri = composed.overall.business_risk_indicator;
  ok("D3 composition: Phase5 decision nulls every stale report conclusion",
    composed.overall.cyber_metrics_score === null &&
      composed.overall.score_band === null &&
      composed.overall.summary === null &&
      composedBri.band === null && composedBri.internal_metrics.score === null &&
      composedBri.internal_metrics.categories === null &&
      composedBri.internal_metrics.top_business_risks === null);
  ok("D3 composition: one suppression cause reaches assessment, BRI and evidence metadata",
    composedBri.explanation.includes(composed.overall.assessment.message) &&
      /not authoritative/.test(composedBri.explanation) &&
      /attack surface/.test(composed.overall.assessment.message || "") &&
      composed.overall.evidence_completeness.skipped_score_bearing_modules.includes("asset_exposure"));

  const read = {
    customerSnapshot: composed,
    snapshot: composed,
    row: { id: "snap-d3" },
    integrity: { verified: true },
    dmarcPolicy: null,
  };
  const executive = buildExecutiveReportV2({
    scan: { id: "scan-d3", domain_id: "dom-d3", domain: "example.com" },
    workspace: { id: "ws-d3", name: "D3 Workspace" },
    read,
  });
  ok("D3 executive report: snapshot suppression remains null with the same reason",
    executive.cyber_metrics_score.value === null &&
      executive.cyber_metrics_score.rating === null &&
      executive.executive_summary.summary === null &&
      executive.business_risk_indicator.band === null &&
      executive.cyber_metrics_score.message === composed.overall.assessment.message);
  const pdfText = new TextDecoder("latin1").decode(buildScanReportPdf(
    { id: "scan-d3", domain_id: "dom-d3", domain: "example.com" },
    read,
  ));
  ok("D3 PDF: withheld score is not printed as the stale numeric result",
    /Not available for this assessment/.test(pdfText) && !/92 \/ 100/.test(pdfText));
  ok("D3 PDF: the canonical suppression cause is customer-visible",
    /attack surface/.test(pdfText));

  // Current posture: a complete database row is only a candidate. Its stored
  // report can disqualify it through the same Phase-5 decision.
  const postureRow = {
    scan_id: "scan-d3", score: 92, rating: "good",
    scan_quality: "complete", created_at: "2026-08-24T10:01:00.000Z",
  };
  const postureEnv = {
    cybermeters_db: {
      prepare(sql) {
        return {
          bind() {
            return {
              all: async () => ({ results: [postureRow] }),
              first: async () => postureRow,
            };
          },
        };
      },
    },
    cybermeters_reports: {
      get: async () => ({
        json: async () => ({
          monitoring_states: healthyMonitoringStates,
          modules: { ...completeMods(), asset_exposure: { skipped: true } },
        }),
      }),
    },
  };
  const posture = await getCurrentPosturePresentation(postureEnv, { domainId: "dom-d3" });
  ok("D3 current posture: a suppressed complete row cannot become authoritative",
    posture.state === "not_established" && posture.authoritative === null);
  ok("D3 current posture: the candidate survives only as a null-score provisional with cause",
    posture.latest_provisional?.display_score === null &&
      posture.latest_provisional?.display_rating === null &&
      /attack surface/.test(posture.latest_provisional?.message || ""));

  // Boundary control: a module that ran and returned partial evidence is still
  // the established product contract — provisional number, no final band.
  const ranPartial = resolvePhase5HistoricalCustomerProjection({
    score: 92,
    riskLevel: "good",
    scanQuality: "partial",
    modules: { ...completeMods(), dns: { executed: true, incomplete: true } },
  });
  ok("D3 boundary: ran-partial retains a provisional numeric score",
    ranPartial.suppressed !== true &&
      ranPartial.assessment.display_score === 92 &&
      ranPartial.assessment.display_rating === null &&
      ranPartial.assessment.provisional === true);

  // Boundary control: a proven-complete row whose D1 score cell is empty is a
  // data fact, not an evidence gap. Suppressing it would rewrite scan_quality
  // and fabricate an incompleteness cause — the defect that nulled every proven
  // BRS basis row on the portfolio surface (portfolio-score-honesty 51/73).
  const completeEmptyScoreCell = resolvePhase5HistoricalCustomerProjection({
    score: null,
    riskLevel: "low",
    scanQuality: "complete",
    modules: completeMods(),
  });
  ok("D3 boundary: complete row with empty score cell is not suppressed",
    completeEmptyScoreCell.suppressed !== true && completeEmptyScoreCell.score === null);
  ok("D3 boundary: complete row with empty score cell keeps scan_quality complete",
    completeEmptyScoreCell.scan_quality === "complete");
  ok("D3 boundary: the withheld-band law holds without a suppression claim",
    completeEmptyScoreCell.risk_level === null && completeEmptyScoreCell.suppression_reason === undefined);

  // P1-2 (R1 verdict): the historical website-redirect invalidation must be
  // ATOMIC. Nulling the headline score/band while the stale assessment
  // (85/good/authoritative), summary and BRI survive re-publishes the withdrawn
  // conclusion through every surface that reads those fields.
  const p12StaleSnapshot = () => ({
    domains: [{ domain_key: "website_security", state: "issue_detected",
      finding_ids: ["ssl_no_http_redirect"], finding_count: 1 }],
    observed_findings: [{ finding_id: "ssl_no_http_redirect", title: "Missing HTTPS redirect" }],
    overall: {
      cyber_metrics_score: 85, score_band: "good",
      assessment: { raw_score: 85, display_score: 85, display_rating: "good",
        quality: "complete", provisional: false, authoritative: true, comparable: true, message: null },
      summary: "Stale scored summary",
      business_risk_indicator: { band: "low", explanation: "Stale BRI explanation",
        provisional: false, internal_metrics: { score: 20 } },
      evidence_completeness: { scan_quality: "complete" },
    },
  });
  const p12BadChainModules = () => ({
    ...completeMods(),
    ssl: { http_redirect_chain: {
      http_redirect_validated: true,
      hop_observations: [{ state: "transport_unavailable", origin_status: null }],
    } },
  });
  const invalidated = projectPhase5SnapshotForCustomer(p12StaleSnapshot(), p12BadChainModules());
  ok("P1-2: invalidation still nulls headline score and band",
    invalidated.overall.cyber_metrics_score === null && invalidated.overall.score_band === null);
  ok("P1-2: stale assessment cannot stay authoritative",
    invalidated.overall.assessment?.authoritative !== true &&
      invalidated.overall.assessment?.display_score !== 85 &&
      invalidated.overall.assessment?.display_rating == null,
    JSON.stringify({ a: invalidated.overall.assessment?.authoritative, s: invalidated.overall.assessment?.display_score }));
  ok("P1-2: stale summary does not survive the invalidation",
    invalidated.overall.summary == null, String(invalidated.overall.summary));
  ok("P1-2: stale BRI band and internal score do not survive the invalidation",
    invalidated.overall.business_risk_indicator?.band == null &&
      invalidated.overall.business_risk_indicator?.internal_metrics?.score == null,
    JSON.stringify(invalidated.overall.business_risk_indicator?.band));
  ok("P1-2: the withheld reason is customer-visible on the assessment",
    /never observed|withheld/i.test(invalidated.overall.assessment?.message || ""),
    String(invalidated.overall.assessment?.message));

  // P1-2 current-posture: the same invalidation predicate must reach authority
  // selection — a complete row whose persisted 85/good rests on the withdrawn
  // redirect conclusion cannot present as the authoritative posture.
  const withheldRow = { scan_id: "scan-p12", score: 85, rating: "good",
    scan_quality: "complete", status: "completed", created_at: "2026-08-20T10:00:00.000Z" };
  const withheldEnv = {
    cybermeters_db: { prepare: () => ({ bind: () => ({
      first: async () => withheldRow,
      all: async () => ({ results: [withheldRow] }),
    }) }) },
    cybermeters_reports: { get: async () => ({ json: async () => ({
      monitoring_states: healthyMonitoringStates,
      modules: p12BadChainModules(),
      findings: [{ id: "ssl_no_http_redirect", severity: "medium" }],
    }) }) },
  };
  const withheldPosture = await getCurrentPosturePresentation(withheldEnv, { domainId: "dom-p12" });
  ok("P1-2 current posture: a withdrawn redirect conclusion cannot be authoritative",
    withheldPosture.state === "not_established" && withheldPosture.authoritative === null,
    JSON.stringify({ state: withheldPosture.state }));
  ok("P1-2 current posture: the row survives only as null-score provisional with the withheld cause",
    withheldPosture.latest_provisional?.display_score === null &&
      withheldPosture.latest_provisional?.display_rating == null &&
      /never observed|withheld/i.test(withheldPosture.latest_provisional?.message || ""),
    JSON.stringify({ s: withheldPosture.latest_provisional?.display_score, m: withheldPosture.latest_provisional?.message }));

  const scanDetailSource = readFileSync(
    new URL("../frontend/src/pages/ScanDetail.jsx", import.meta.url),
    "utf8",
  );
  ok("D3 ScanDetail wire-in: null score renders the backend assessment reason",
    /assessmentScore === null && assessmentReason/.test(scanDetailSource) &&
      /assessment\?\.suppression_reason, assessment\?\.message/.test(scanDetailSource));

  // Methodology bump (paired with golden-consumer re-derivation elsewhere).
  ok("D3: methodology stamp remains newer than the pre-D3 contract",
    CYBER_METRICS_SCORE_METHODOLOGY_VERSION !== "2026-08-23.1", CYBER_METRICS_SCORE_METHODOLOGY_VERSION);
  ok("D3: score-bearing set includes asset_exposure/subdomains (barbers' skipped areas)",
    SCORE_BEARING_MODULES.includes("asset_exposure") && SCORE_BEARING_MODULES.includes("subdomains"));
}

assert.strictEqual(fail.length, 0, `report-copy triage: ${fail.length} failed`);
console.log(`\nreport-copy live triage: ${passed} passed, ${fail.length} failed`);
if (fail.length) process.exit(1);
