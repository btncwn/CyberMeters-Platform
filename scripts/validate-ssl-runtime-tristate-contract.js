#!/usr/bin/env node
// SSL runtime tri-state + customer projection semantic contract.
// Node 24+. Supports fresh copied-engine mutation children via
// SSL_TRISTATE_ENGINE_SRC and emits a machine-readable exact failure set.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENGINE_SRC = process.env.SSL_TRISTATE_ENGINE_SRC
  ? path.resolve(process.env.SSL_TRISTATE_ENGINE_SRC)
  : path.join(ROOT, "workers", "scan-api", "src");
const eng = (file) => pathToFileURL(path.join(ENGINE_SRC, "engines", file)).href;
const EXPECTED_ASSERTIONS = 182;

const tlsModule = await import(eng("tls-evidence.js"));
const { computeScore } = await import(eng("scoring.js"));
const { computeSecurityPosture } = await import(eng("posture-scoring.js"));
const { runCertificateIntelligenceModule } = await import(eng("cert-intel.js"));
const { deriveCertificateSignalCompletenessFromModules } = await import(
  eng("certificate-signal-completeness.js")
);
const { resolveConfidence } = await import(eng("confidence.js"));
const { resolveCustomerAlertPresentation } = await import(eng("customer-alert-presentation.js"));
const { resolveCyberMotDomainStates } = await import(eng("cyber-mot-domains.js"));
const { deriveScanBusinessRisk } = await import(eng("business-risk.js"));
const { projectPhase5EvidenceForCustomer, projectPhase5SnapshotForCustomer } = await import(
  eng("phase5-evidence.js")
);
const { buildExecutiveReportV2 } = await import(eng("executive-report.js"));
const { buildScanReportPdf } = await import(eng("pdf.js"));

console.log(`LOADED_TLS_MODULE_URL=${eng("tls-evidence.js")}`);

const results = [];
function check(id, condition, detail = "") {
  const passed = Boolean(condition);
  results.push({ id, passed });
  if (!passed) console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
}
function equal(id, actual, expected) {
  check(id, JSON.stringify(actual) === JSON.stringify(expected),
    `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`);
}

const DOMAIN = "tri-state.example";
const observedPresent = (status = 200) => ({
  tls_state: "observed_present",
  tls_state_reason: "origin_response_over_tls",
  https_available: true,
  https_probe_executed: true,
  https_observation_state: "origin_response",
  https_observation_reason: "origin_response",
  https_observation_completeness: "observed",
  https_origin_status: status,
  http_redirects_to_https: true,
  http_redirect_chain: {
    observation_state: "origin_response",
    observation_completeness: "observed",
    http_redirect_validated: true,
  },
  certificate_evidence: {
    schema_version: "external-certificate-observation-v2",
    observed_at: "2026-08-09T12:00:00.000Z",
    active_service: {
      observation_state: "origin_response",
      observation_reason: "origin_response",
      origin_status: status,
      endpoint_context: DOMAIN,
    },
  },
});
const positivelyAbsent = () => ({
  tls_state: "positively_absent",
  tls_state_reason: "approved_active_tls_positive_absence",
  https_available: false,
  https_probe_executed: true,
  http_redirects_to_https: true,
  certificate_evidence: { observed_at: "2026-08-09T12:00:05.000Z" },
  tls_positive_absence_evidence: {
    state: "positively_absent",
    execution: "completed",
    source_type: "approved_active_tls_collector",
    collector: "semantic_contract_fixture",
    collector_version: "1",
    endpoint: `https://${DOMAIN}`,
    assessed_domain: DOMAIN,
    observed_at: "2026-08-09T12:00:00.000Z",
    absence_outcome: "tls_service_absent",
    evidence_grade: "positive_absence",
  },
});
const positivelyAbsentEnvelope = (overrides) => {
  const base = positivelyAbsent();
  return {
    ...base,
    tls_positive_absence_evidence: {
      ...base.tls_positive_absence_evidence,
      ...overrides,
    },
  };
};
const withoutEnvelopeKey = (key) => {
  const base = positivelyAbsent();
  delete base.tls_positive_absence_evidence[key];
  return base;
};
const unavailable = Object.freeze({
  missing: {},
  null: { https_available: null, https_probe_executed: false },
  bare_false: { https_available: false, https_probe_executed: true },
  legacy_false: { https_available: false },
  synthetic_false: { https_available: false, https_probe_executed: true, source: "fixture" },
  edge_false: {
    https_available: false,
    https_probe_executed: true,
    https_observation_state: "cloudflare_edge_error",
    https_observation_reason: "cloudflare_edge_error",
    incomplete: true,
  },
  timeout: {
    https_available: null,
    https_probe_executed: false,
    https_observation_state: "transport_unavailable",
    https_observation_reason: "timeout",
    incomplete: true,
  },
  deadline: {
    executed: false,
    outcome: "deadline_exceeded",
    https_available: null,
    https_probe_executed: false,
    incomplete: true,
  },
  invalid_positive_source: {
    ...positivelyAbsent(),
    tls_positive_absence_evidence: {
      ...positivelyAbsent().tls_positive_absence_evidence,
      source_type: "unknown_collector",
    },
  },
  incomplete_positive: {
    ...positivelyAbsent(),
    tls_positive_absence_evidence: {
      ...positivelyAbsent().tls_positive_absence_evidence,
      execution: "timed_out",
    },
  },
  // Contradictory top-level carrier state must dominate a valid envelope: a
  // failed, unexecuted, deadline-hit or incomplete probe can never prove absence.
  contradicted_error: { ...positivelyAbsent(), error: "connect_failure" },
  contradicted_not_executed: { ...positivelyAbsent(), executed: false },
  contradicted_deadline: { ...positivelyAbsent(), outcome: "deadline_exceeded" },
  contradicted_incomplete: { ...positivelyAbsent(), incomplete: true },
  contradicted_incomplete_reason: { ...positivelyAbsent(), incomplete_reason: "scan_budget_exhausted" },
  // Merely parseable timestamps are not canonical positive evidence.
  ts_offset: positivelyAbsentEnvelope({ observed_at: "2026-08-09T13:00:00.000+01:00" }),
  ts_missing_millis: positivelyAbsentEnvelope({ observed_at: "2026-08-09T12:00:00Z" }),
  ts_lowercase: positivelyAbsentEnvelope({ observed_at: "2026-08-09t12:00:00.000z" }),
  ts_hour_24: positivelyAbsentEnvelope({ observed_at: "2026-08-09T24:00:00.000Z" }),
  // Timeliness relative to the carrier's own reference observation.
  ts_future: positivelyAbsentEnvelope({ observed_at: "2026-08-09T12:10:00.000Z" }),
  ts_stale: positivelyAbsentEnvelope({ observed_at: "2026-08-09T11:00:00.000Z" }),
  ts_no_reference: (() => { const base = positivelyAbsent(); delete base.certificate_evidence; return base; })(),
  // Assessed-domain binding: HTTPS syntax alone is not target identity.
  envelope_domain_mismatch: positivelyAbsentEnvelope({ endpoint: "https://unrelated.example" }),
  missing_assessed_domain: withoutEnvelopeKey("assessed_domain"),
  carrier_domain_mismatch: { ...positivelyAbsent(), assessed_domain: "other.example" },
});

const baseModules = (ssl) => ({
  dns: { resolves: true, has_mx: false },
  ssl,
  headers: {
    accessible: true,
    headers_assessed: true,
    final_https: true,
    validation_uncertain: false,
    status_code: 200,
    values: {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin",
      "permissions-policy": "geolocation=()",
    },
  },
  email_security: { applicability: { applicable: false } },
  subdomains: {
    items: [],
    sources: {
      crt_sh: { count: 1, error: null },
      certspotter: { count: 1, error: null },
    },
  },
});
const scoreFor = (ssl) => computeScore(baseModules(ssl), DOMAIN);

// Resolver truth table, including genuine origin 5xx.
equal("resolver.present.200", tlsModule.resolveTlsRuntimeState(observedPresent(200)).state, "observed_present");
equal("resolver.present.503", tlsModule.resolveTlsRuntimeState(observedPresent(503)).state, "observed_present");
equal("resolver.positive_absence", tlsModule.resolveTlsRuntimeState(positivelyAbsent()).state, "positively_absent");
for (const [name, ssl] of Object.entries(unavailable)) {
  equal(`resolver.unavailable.${name}`, tlsModule.resolveTlsRuntimeState(ssl).state, "unavailable");
}
check("resolver.positive_absence.source_bound",
  tlsModule.resolveTlsRuntimeState(positivelyAbsent()).evidence?.collector === "semantic_contract_fixture");
// Call-site strictness: where the true assessed domain is in scope it binds too.
equal("resolver.positive_absence.context_match",
  tlsModule.resolveTlsRuntimeState(positivelyAbsent(), { assessedDomain: DOMAIN }).state, "positively_absent");
equal("resolver.unavailable.context_mismatch",
  tlsModule.resolveTlsRuntimeState(positivelyAbsent(), { assessedDomain: "other.example" }).state, "unavailable");

// Scoring and remediation: every unavailable form is neutral; future positive is live.
for (const [name, ssl] of Object.entries(unavailable)) {
  const result = scoreFor(ssl);
  check(`score.unavailable.${name}.no_finding`,
    !result.findings.some((finding) => finding.id === "ssl_not_available"));
  check(`score.unavailable.${name}.no_action`,
    !result.recommendations.some((item) => /TLS Certificate|Enable HTTPS with a valid certificate/i.test(item.title)));
}
const presentScore = scoreFor(observedPresent());
const absentScore = scoreFor(positivelyAbsent());
for (const [name, ssl] of Object.entries(unavailable)) {
  equal(`score.unavailable.${name}.no_penalty`, scoreFor(ssl).score, presentScore.score);
}
check("score.present.no_absence_finding", !presentScore.findings.some((finding) => finding.id === "ssl_not_available"));
check("score.positive_absence.finding", absentScore.findings.some((finding) => finding.id === "ssl_not_available"));
check("score.positive_absence.action", absentScore.recommendations.some((item) => item.title === "Enable HTTPS with a valid certificate"));
equal("score.positive_absence.impact", presentScore.score - absentScore.score, 25);
const positiveFinding = absentScore.findings.find((finding) => finding.id === "ssl_not_available");
check("score.positive_absence.provenance", positiveFinding?.evidence?.tls_positive_absence_evidence?.collector === "semantic_contract_fixture");

// Executive posture uses the same decision.
const scorecard = {
  certificate_risks: { risk_level: null, days_until_expiry: null },
  brand_risks: { high: 0, medium: 0 },
  new_assets_30d: 0,
  last_scanned_domain: DOMAIN,
  vendor_risk: { high: 0, medium: 0 },
  third_party_assets: 0,
  saas_exposures: 0,
  admin_surfaces: 0,
};
const postureFor = (ssl) => computeSecurityPosture(scorecard, { modules: baseModules(ssl) });
const unavailablePosture = postureFor(unavailable.bare_false).ssl_certificates;
const positivePosture = postureFor(positivelyAbsent()).ssl_certificates;
check("posture.unavailable.no_reason", !unavailablePosture.reasons.some((value) => /unencrypted/i.test(value)));
check("posture.unavailable.no_action", !unavailablePosture.remediations.some((value) => value.remediation_id === "cert.tls.install"));
equal("posture.positive_absence.score_delta", unavailablePosture.score - positivePosture.score, 40);
check("posture.positive_absence.action", positivePosture.remediations.some((value) => value.remediation_id === "cert.tls.install"));

// Certificate intelligence, active-service completeness and ownership/confidence.
const certModules = (ssl) => ({
  ...baseModules({
    ...ssl,
    cert_issuer: "Fixture CA",
    cert_subject: DOMAIN,
    cert_san_names: [DOMAIN],
    cert_san_count: 1,
    cert_raw_san_count: 1,
    cert_shared_san_count: 0,
    cert_wildcard_san_count: 0,
    ct_sources: { crt_sh: { count: 1, error: null }, certspotter: { count: 1, error: null } },
  }),
});
const ciUnavailable = runCertificateIntelligenceModule(certModules(unavailable.bare_false), DOMAIN, {
  observedAt: "2026-08-09T12:00:00.000Z", engineVersion: "contract",
});
const ciPresent = runCertificateIntelligenceModule(certModules(observedPresent()), DOMAIN, {
  observedAt: "2026-08-09T12:00:00.000Z", engineVersion: "contract",
});
const ciAbsent = runCertificateIntelligenceModule(certModules(positivelyAbsent()), DOMAIN, {
  observedAt: "2026-08-09T12:00:00.000Z", engineVersion: "contract",
});
equal("cert.unavailable.status", ciUnavailable.certificate_status, "unknown");
equal("cert.unavailable.risk", ciUnavailable.certificate_risk_level, "low");
check("cert.unavailable.no_no_https", !ciUnavailable.suspicious_certificate_signals.some((signal) => signal.signal === "no_https"));
equal("cert.unavailable.ownership", ciUnavailable.ownership.status, "unknown");
equal("cert.unavailable.ownership_confidence", ciUnavailable.ownership.confidence, null);
equal("cert.unavailable.active_service", ciUnavailable.signal_completeness.signals.active_service.observation, "unknown");
equal("cert.unavailable.active_service_value", ciUnavailable.signal_completeness.signals.active_service.value, null);
equal("cert.present.status", ciPresent.certificate_status, "valid");
equal("cert.present.active_service", ciPresent.signal_completeness.signals.active_service.observation, "present");
equal("cert.positive_absence.status", ciAbsent.certificate_status, "unavailable");
equal("cert.positive_absence.risk", ciAbsent.certificate_risk_level, "critical");
check("cert.positive_absence.signal", ciAbsent.suspicious_certificate_signals.some((signal) => signal.signal === "no_https"));
equal("cert.positive_absence.active_service", ciAbsent.signal_completeness.signals.active_service.observation, "absent");
equal("cert.positive_absence.active_service_value", ciAbsent.signal_completeness.signals.active_service.value, false);
const directIncomplete = deriveCertificateSignalCompletenessFromModules({ modules: certModules(unavailable.bare_false) });
equal("completeness.direct_unavailable", directIncomplete.signals.active_service.completeness_state, "evidence_incomplete");

equal("confidence.legacy_false_demoted", resolveConfidence({ id: "ssl_not_available", confidence: 90 }), null);
equal("confidence.positive_absence_supported", resolveConfidence(positiveFinding ?? {}), 90);

// Alert/email presentation never converts unavailable into the install claim.
const canonicalAlert = {
  title: "Enable HTTPS with a valid certificate",
  what_changed: "A completed HTTPS/TLS assessment positively identified a defect.",
  recommended_action: "Install a publicly trusted TLS certificate.",
  remediation_id: "cert.tls.install",
};
const alertFor = (ssl) => resolveCustomerAlertPresentation({
  domain_key: "website_security",
  recurrence: "transport_not_available",
  finding_type: "ssl_not_available",
  module_evidence: ssl,
  canonical: canonicalAlert,
});
equal("alert.unavailable.state", alertFor(unavailable.bare_false).presentation_state, "observation_unavailable");
equal("alert.unavailable.remediation", alertFor(unavailable.bare_false).remediation_id, null);
check("alert.unavailable.neutral_action", /run another assessment/i.test(alertFor(unavailable.bare_false).recommended_action));
equal("alert.present.conflict", alertFor(observedPresent()).presentation_state, "evidence_conflict");
equal("alert.positive_absence.state", alertFor(positivelyAbsent()).presentation_state, "positively_observed_certificate_defect");
equal("alert.positive_absence.remediation", alertFor(positivelyAbsent()).remediation_id, "cert.tls.install");

// Canonical domains and URL profile remain explicitly unknown, never healthy/critical.
const domainFor = (ssl, findings) => resolveCyberMotDomainStates({
  modules: { ...baseModules(ssl), certificate_intelligence: runCertificateIntelligenceModule(baseModules(ssl), DOMAIN) },
  findings,
  scan_quality: { status: "complete", modules_skipped: [] },
  completed_at: "2026-08-09T12:00:00.000Z",
}).find((row) => row.domain_key === "website_security");
equal("domain.unavailable.state", domainFor(unavailable.bare_false, [{ id: "ssl_not_available", severity: "critical", module: "ssl" }]).state, "evidence_insufficient");
equal("domain.unavailable.findings", domainFor(unavailable.bare_false, [{ id: "ssl_not_available", severity: "critical", module: "ssl" }]).finding_count, 0);
equal("domain.positive_absence.state", domainFor(positivelyAbsent(), absentScore.findings).state, "issue_detected");
equal("domain.positive_absence.severity", domainFor(positivelyAbsent(), absentScore.findings).highest_severity, "critical");
// Immutable R2 projection: source bytes unchanged, customer bytes fail closed.
const historicalReport = {
  scan_id: "scan-legacy",
  domain: DOMAIN,
  cyber_metrics_score: 75,
  risk_level: "good",
  modules: {
    ...certModules(unavailable.bare_false),
    certificate_intelligence: {
      ...ciUnavailable,
      certificate_status: "unavailable",
      certificate_risk_level: "critical",
      ownership: { status: "customer_domain_certificate", confidence: 90, customer_owned: true },
      suspicious_certificate_signals: [{ signal: "no_https", severity: "high" }],
    },
  },
  findings: [{ id: "ssl_not_available", severity: "critical", module: "ssl", confidence: 90 }],
  recommendations: [{ module: "ssl", title: "Enable HTTPS with a valid certificate" }],
};
const rawReportBytes = JSON.stringify(historicalReport);
const projectedModules = projectPhase5EvidenceForCustomer(historicalReport.modules);
const projectedReport = tlsModule.projectTlsReportForCustomer(historicalReport);
equal("report.raw_immutable", JSON.stringify(historicalReport), rawReportBytes);
equal("report.unavailable.explicit_state", projectedReport.modules.ssl.tls_state, "unavailable");
check("report.unavailable.null_key_retained", Object.hasOwn(projectedReport.modules.ssl, "https_available") && projectedReport.modules.ssl.https_available === null);
equal("report.unavailable.findings", projectedReport.findings, []);
equal("report.unavailable.actions", projectedReport.recommendations, []);
equal("report.unavailable.cert_status", projectedModules.certificate_intelligence.certificate_status, "unknown");
equal("report.unavailable.cert_ownership", projectedModules.certificate_intelligence.ownership.confidence, null);
equal("report.unavailable.cert_signal", projectedModules.certificate_intelligence.suspicious_certificate_signals, []);
const positiveReport = tlsModule.projectTlsReportForCustomer({
  ...historicalReport,
  modules: { ...historicalReport.modules, ssl: positivelyAbsent() },
});
equal("report.positive_absence.finding_retained", positiveReport.findings.length, 1);
equal("report.positive_absence.action_retained", positiveReport.recommendations.length, 1);

const historicalSnapshot = {
  snapshot: { snapshot_id: "snap-legacy", scan_id: "scan-legacy", domain: DOMAIN, built_at: "2026-08-09T12:00:00.000Z" },
  overall: {
    cyber_metrics_score: 75,
    score_band: "good",
    summary: "Good",
    assessment: { status: "assessed", quality: "complete" },
    business_risk_indicator: { band: "high", explanation: "TLS absent", internal_metrics: { score: 40 } },
    evidence_completeness: { scan_quality: "complete" },
  },
  domains: [{ domain_key: "website_security", state: "issue_detected", coverage: "complete", summary: "1 issue", finding_count: 1, finding_ids: ["ssl_not_available"], highest_severity: "critical" }],
  observed_findings: [{ finding_id: "ssl_not_available", domain_keys: ["website_security"], severity: "critical", title: "HTTPS Not Available", remediation_id: "cert.tls.install" }],
  observations: [],
  remediation_actions: [{ remediation_id: "cert.tls.install", title: "Enable HTTPS with a valid certificate", action: "Install", finding_ids: ["ssl_not_available"] }],
  monitoring_states: null,
};
const rawSnapshotBytes = JSON.stringify(historicalSnapshot);
const customerSnapshot = projectPhase5SnapshotForCustomer(historicalSnapshot, historicalReport.modules);
equal("snapshot.raw_immutable", JSON.stringify(historicalSnapshot), rawSnapshotBytes);
equal("snapshot.unavailable.findings", customerSnapshot.observed_findings, []);
equal("snapshot.unavailable.actions", customerSnapshot.remediation_actions, []);
equal("snapshot.unavailable.domain", customerSnapshot.domains[0].state, "evidence_insufficient");
equal("snapshot.unavailable.score", customerSnapshot.overall.cyber_metrics_score, null);
const positiveSnapshot = projectPhase5SnapshotForCustomer(historicalSnapshot, { ...historicalReport.modules, ssl: positivelyAbsent() });
equal("snapshot.positive_absence.finding_retained", positiveSnapshot.observed_findings.length, 1);
const executive = buildExecutiveReportV2({
  scan: { id: "scan-legacy", domain: DOMAIN },
  read: { snapshot: historicalSnapshot, customerSnapshot, row: { id: "snap-legacy" }, integrity: { verified: true } },
});
equal("executive.unavailable.findings", executive.observed_findings, []);
equal("executive.unavailable.actions", executive.remediation_actions, []);
equal("executive.unavailable.score", executive.cyber_metrics_score.value, null);
let pdfText = "";
try {
  pdfText = Buffer.from(buildScanReportPdf({ id: "scan-legacy", domain: DOMAIN }, {
    snapshot: historicalSnapshot,
    customerSnapshot,
    row: { id: "snap-legacy" },
    integrity: { verified: true },
  })).toString("latin1");
} catch (error) {
  pdfText = `PDF_ERROR:${error.message}`;
}
check("pdf.unavailable.rendered", pdfText.startsWith("%PDF"), pdfText.slice(0, 120));
check("pdf.unavailable.no_tls_install", !/Enable HTTPS with a valid certificate|HTTPS Not Available/.test(pdfText));

const legacyBri = deriveScanBusinessRisk(historicalReport);
check("business_risk.unavailable.no_tls_penalty", !legacyBri.top_business_risks.some((risk) => /SSL|TLS|certificate/i.test(risk.title)));

// One mechanically checkable consumer inventory; no current producer may emit
// the reserved positive state or claim an approved collector exists.
const consumerFiles = [
  "scoring.js", "posture-scoring.js", "ce-readiness.js", "cert-intel.js",
  "certificate-signal-completeness.js", "confidence.js", "customer-alert-presentation.js",
  "website-security-lifecycle.js", "cyber-mot-domains.js", "business-risk.js",
  "phase5-evidence.js", "report-snapshot.js", "scan-engine.js",
];
for (const file of consumerFiles) {
  const source = fs.readFileSync(path.join(ENGINE_SRC, "engines", file), "utf8");
  check(`inventory.${file}`, /tls-evidence\.js/.test(source), "canonical resolver import missing");
}
const scansRoute = fs.readFileSync(path.join(ENGINE_SRC, "routes", "scans.js"), "utf8");
check("inventory.route.report_projection", /projectTlsReportForCustomer\(raw\)/.test(scansRoute));
check("inventory.route.snapshot_projection", /read\.customerSnapshot \?\? read\.snapshot/.test(scansRoute));
const sslProducer = fs.readFileSync(path.join(ENGINE_SRC, "engines", "ssl-scan.js"), "utf8");
check("producer.current_never_positive_absence", !/TLS_RUNTIME_STATES\.POSITIVELY_ABSENT/.test(sslProducer));
check("producer.current_emits_present_unavailable", /TLS_RUNTIME_STATES\.OBSERVED_PRESENT/.test(sslProducer) && /TLS_RUNTIME_STATES\.UNAVAILABLE/.test(sslProducer));

const countBeforeInterlock = results.length;
check("harness.expected_assertion_count", countBeforeInterlock + 1 === EXPECTED_ASSERTIONS,
  `got ${countBeforeInterlock + 1} want ${EXPECTED_ASSERTIONS}`);
const summary = {
  module_url: eng("tls-evidence.js"),
  passed: results.filter((row) => row.passed).map((row) => row.id),
  failed: results.filter((row) => !row.passed).map((row) => row.id),
  total: results.length,
};
console.log(`SSL_TRISTATE_RESULT=${JSON.stringify(summary)}`);
console.log(`\nSSL runtime tri-state contract: ${summary.passed.length}/${summary.total} passed`);
if (summary.failed.length) process.exit(1);
