#!/usr/bin/env node
//
// Item 8 PR-C — focused customer-surface contract.
// Proves candidate lifecycle completeness, fail-honest scored finding copy and
// canonical snapshot/PDF parity for an evidence-corroborated IDN lookalike.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (file) => pathToFileURL(
  path.join(root, "workers", "scan-api", "src", "engines", file),
).href;
const { brandCandidateToApi } = await import(eng("brand-protection.js"));
const { computeScore } = await import(eng("scoring.js"));
const { composeSnapshot } = await import(eng("report-snapshot.js"));
const { buildScanReportPdf } = await import(eng("pdf.js"));
const { portfolioBrandAlertPresentation } = await import(pathToFileURL(
  path.join(root, "workers", "scan-api", "src", "routes", "portfolio.js"),
).href);

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else {
    fail++;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

const profile = {
  id: "bp1",
  brand_name: "Apple",
  primary_domain: "apple.com",
};
const candidate = brandCandidateToApi({
  id: "bra-idn",
  workspace_id: "ws1",
  domain: "apple.com",
  candidate_domain: "xn--pple-43d.com",
  variant_type: "homoglyph_idn",
  dns_resolves: 1,
  https_available: 0,
  mx_present: null,
  status: "active",
  classification: "unreviewed",
  first_seen: "2026-07-20T10:00:00.000Z",
  last_seen: "2026-07-26T10:00:00.000Z",
  last_checked_at: "2026-07-26T10:01:00.000Z",
  evidence_json: JSON.stringify([
    { signal: "ct_observed", value: true },
    { signal: "idn_visual_confusable", value: true },
  ]),
}, profile);

eq("candidate exposes canonical A-label", candidate.candidate_domain, "xn--pple-43d.com");
eq("candidate exposes safe Unicode display form", candidate.unicode_domain, "аpple.com");
eq("candidate lifecycle preserves first seen", candidate.lifecycle.first_seen_at, "2026-07-20T10:00:00.000Z");
eq("candidate lifecycle reports active evidence state", candidate.lifecycle.observation_state, "active");
eq("candidate lifecycle keeps DNS/HTTPS/MX completeness separate",
  candidate.lifecycle.evidence_completeness,
  { dns: true, https: true, mx: false });
ok("HTTP-inactive does not erase positive DNS activity",
  candidate.dns_active === true && candidate.https_active === false);
const portfolioCopy = portfolioBrandAlertPresentation({
  candidate_domain: candidate.candidate_domain,
  variant_type: candidate.variant_type,
  evidence_json: JSON.stringify(candidate.evidence),
});
ok("MSP portfolio identifies the IDN signal without calling it a typosquat",
  portfolioCopy.title === "IDN lookalike: xn--pple-43d.com" &&
  !/typosquat/i.test(portfolioCopy.description));
ok("MSP portfolio keeps the not-proof-of-abuse boundary",
  /not proof of abuse/i.test(portfolioCopy.description));

const scored = computeScore({
  brand_monitoring: {
    domains: [{
      candidate_domain: candidate.candidate_domain,
      unicode_domain: candidate.unicode_domain,
      variant_type: "homoglyph_idn",
      risk_level: "high",
      risk_reasons: ["visually confusable IDN", "DNS active", "seen in certificate log"],
      confidence: 80,
      validation_quality: "strong",
    }],
  },
}, "apple.com");
const finding = scored.findings.find((item) => item.id === "brand_homoglyph_detected");
ok("corroborated IDN candidate becomes the canonical Brand homograph finding", Boolean(finding));
ok("finding names the visually confusable IDN signal", /Visually confusable IDN lookalike/.test(finding?.title || ""));
ok("finding says lookalike is not proof of abuse", /not proof of abuse/i.test(finding?.description || ""));
ok("finding never claims confirmed phishing or maliciousness",
  !/(confirmed phishing|malicious|compromise|attacker)/i.test(
    `${finding?.title || ""} ${finding?.description || ""}`,
  ));
ok("finding retains both A-label and Unicode evidence",
  finding?.evidence?.some((item) => item.label === "Candidate Domain" &&
    item.value === "xn--pple-43d.com") &&
  finding?.evidence?.some((item) => item.label === "Unicode Display Form" &&
    item.value === "аpple.com"));

const modules = {
  dns: { has_mx: true },
  email_security: { spf: null },
  headers: {},
  ssl: {},
  subdomains: { count: 1 },
  certificate_intelligence: { total_certificates: 1 },
  brand_monitoring: { domains: [] },
  identity_discovery: { high_risk_count: 0 },
  technology_detection: { count: 0 },
  saas_exposure: { count: 0 },
  third_party_assets: { count: 0 },
  vendor_relationships: { high_confidence: 0 },
  whois_intelligence: {},
};
const monitoringSignals = [
  "dns", "certificate_transparency", "website_security", "email_protection",
  "attack_surface", "technology_visibility", "vulnerability_intelligence",
  "registration_data",
];
const report = {
  scan_id: "scan-idn",
  domain_id: "dom-idn",
  domain: "apple.com",
  status: "completed",
  cyber_metrics_score: scored.score,
  risk_level: "moderate",
  completed_at: "2026-07-26T10:05:00.000Z",
  findings: [finding],
  recommendations: [],
  scan_quality: { status: "complete", modules_skipped: [], warnings: [] },
  monitoring_states: {
    version: "signal-monitoring-state-v1",
    signals: Object.fromEntries(monitoringSignals.map((signal) => [signal, {
      state: "monitoring_healthy",
      message: `${signal} checks completed normally in this run.`,
      evidence: { modules: [], incomplete_modules: [], providers: {} },
    }])),
  },
  modules,
};
const snapshot = composeSnapshot({
  snapshotId: "snap-idn",
  workspaceId: "ws1",
  domainId: "dom-idn",
  scanId: "scan-idn",
  domain: "apple.com",
  report,
  cyberEssentials: { status: "not_assessed" },
  ceReadiness: null,
  caseRows: [{
    id: "case-idn",
    workspace_id: "ws1",
    case_type: "brand_abuse",
    domain_key: "brand_protection",
    domain: "xn--pple-43d.com",
    finding_id: "bp1:xn--pple-43d.com",
    remediation_id: "brand.lookalike.review",
    severity: "high",
    status: "confirmed_abuse",
    reopened_count: 1,
  }],
  questionSetVersions: [],
  supersedesSnapshotId: null,
  builtAt: "2026-07-26T10:05:01.000Z",
});
const snapshotFinding = snapshot.observed_findings.find(
  (item) => item.finding_id === "brand_homoglyph_detected",
);
ok("canonical snapshot attributes the IDN finding to Brand Protection",
  snapshotFinding?.domain_keys?.includes("brand_protection"));
ok("canonical snapshot preserves fail-honest finding wording",
  /not proof of abuse/i.test(snapshotFinding?.explanation || ""));
ok("canonical snapshot preserves Brand managed-workflow recurrence state",
  snapshot.domains.find((item) => item.domain_key === "brand_protection")
    ?.managed_workflow?.statuses?.confirmed_abuse === 1);

const pdf = buildScanReportPdf(
  { domain: "apple.com" },
  { snapshot, dmarcPolicy: null },
);
const pdfText = Buffer.from(pdf).toString("latin1");
ok("assessment PDF renders the canonical IDN finding title",
  pdfText.includes("Visually confusable IDN lookalike observed"));
ok("assessment PDF renders the not-proof-of-abuse boundary",
  pdfText.includes("not proof of abuse"));

console.log(`\nBrand IDN PR-C customer surface: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand IDN PR-C customer-surface validation passed");
