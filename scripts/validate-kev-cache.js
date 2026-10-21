#!/usr/bin/env node
//
// Outside vulnerability data is not part of a scan.
//
// This validator used to prove the CISA KEV catalogue cache. Scans no longer
// read outside vulnerability databases, exploited-vulnerability catalogues or
// exploit-likelihood scores (workers/scan-api/src/engines/check-pack.js), so it
// now proves that absence:
//   • no Worker source names an outside vulnerability-data service or the
//     retired catalogue cache, and the module that fetched them is gone;
//   • the two modules a scan still records say so in a fixed shape, with the
//     check-pack version and the customer statement from the pack;
//   • that shape is complete evidence with nothing to publish: it never
//     withholds a score, never raises a finding and never reads as an outage;
//   • a stored scan that did use outside data keeps its recorded meaning.
// The runtime audit (a real scan with outside egress refused) lives in
// scripts/lab/lab-checks.mjs, run by validate-own-observation-discovery.js.
//
// CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(root, "workers", "scan-api", "src");
const eng = (f) => import(pathToFileURL(path.join(src, "engines", f)).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── 1. No Worker source reaches outside vulnerability data ──────────────────
function sourceFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "node_modules" ? [] : sourceFiles(full);
    return /\.(m?js)$/.test(entry.name) ? [full] : [];
  });
}
const files = sourceFiles(src);
ok("the Worker source tree was read", files.length > 50, String(files.length));
const OUTSIDE_VULNERABILITY_DATA = [
  /services\.nvd\.nist\.gov/i,
  /api\.first\.org/i,
  /known_exploited_vulnerabilities\.json/i,
  /cisa\.gov\/sites\/default\/files\/feeds/i,
  /api\.osv\.dev/i,
  /cache\/cisa-kev\.json/i,
];
const hits = files.flatMap((file) => {
  const text = fs.readFileSync(file, "utf8");
  return OUTSIDE_VULNERABILITY_DATA
    .filter((pattern) => pattern.test(text))
    .map((pattern) => `${path.relative(root, file)} ~ ${pattern}`);
});
eq("no Worker source names an outside vulnerability-data service or the retired catalogue cache", hits.join("; "), "");
ok("the module that fetched outside vulnerability data is gone",
  !fs.existsSync(path.join(src, "engines", "vuln-intel.js")));
const engineSrc = fs.readFileSync(path.join(src, "engines", "scan-engine.js"), "utf8");
ok("the scan engine records both modules as not part of the check pack",
  /modules\.cve_intelligence = moduleNotInCheckPack\("vulnerability_database_matching"/.test(engineSrc) &&
  /modules\.known_exploited_vulnerabilities = moduleNotInCheckPack\("exploited_vulnerability_data"/.test(engineSrc));
ok("outbound accounting no longer waits for modules that never launch",
  !/required:\s*\[[^\]]*"cve_intelligence"/.test(engineSrc) && !/required:\s*\[[^\]]*"known_exploited_vulnerabilities"/.test(engineSrc));

// ── 2. The stated shape ──────────────────────────────────────────────────────
const {
  CHECK_PACK_VERSION,
  NOT_IN_CHECK_PACK,
  OUTSIDE_SOURCES,
  checkPackSummary,
  isNotInCheckPack,
  moduleNotInCheckPack,
} = await eng("check-pack.js");
const cve = moduleNotInCheckPack("vulnerability_database_matching", "outside_vulnerability_data_not_used");
const kev = moduleNotInCheckPack("exploited_vulnerability_data", "outside_vulnerability_data_not_used");
for (const [name, value] of [["vulnerability matching", cve], ["exploited-vulnerability data", kev]]) {
  ok(`${name}: recorded as not part of the check pack, never as executed`,
    value.executed === false && value.outcome === "not_in_check_pack" && isNotInCheckPack(value));
  eq(`${name}: stamped with the check-pack version`, value.check_pack_version, CHECK_PACK_VERSION);
  ok(`${name}: carries the customer statement from the pack`,
    value.customer_message === NOT_IN_CHECK_PACK.find((item) => item.id === value.source)?.statement &&
      typeof value.customer_message === "string" && value.customer_message.length > 20);
  ok(`${name}: raises no finding and claims no error or incompleteness`,
    Array.isArray(value.findings) && value.findings.length === 0 && !value.error && value.incomplete !== true);
}
const summary = checkPackSummary();
ok("the report summary lists what is not in the pack",
  summary.not_in_check_pack.includes("vulnerability_database_matching") &&
    summary.not_in_check_pack.includes("exploited_vulnerability_data"));
ok("the only outside services named are DNS resolution (required) and registry RDAP (optional)",
  JSON.stringify(OUTSIDE_SOURCES.map(({ id, required }) => [id, required])) ===
    JSON.stringify([["public_dns_resolver", true], ["registry_rdap", false]]));

// ── 3. Complete evidence, nothing to publish ─────────────────────────────────
const {
  projectPhase5EvidenceForCustomer,
  resolvePhase5CustomerAssessment,
  resolvePhase5EvidenceContract,
  resolvePhase5HistoricalCustomerProjection,
  resolveScoreSuppressionReason,
} = await eng("phase5-evidence.js");
const email = { email_security_score: 70, findings: [] };
const current = { cve_intelligence: cve, known_exploited_vulnerabilities: kev, email_security_intelligence: email };
const contract = resolvePhase5EvidenceContract(current);
ok("the phase-5 evidence contract is complete with both modules outside the pack",
  contract.complete === true && contract.incomplete_modules.length === 0, JSON.stringify(contract));
ok("nothing from either module is publishable", contract.publishable.cve === false && contract.publishable.kev === false);
eq("no score is withheld for them", resolveScoreSuppressionReason(current), null);
const assessed = resolvePhase5CustomerAssessment({ score: 82, riskLevel: "good", modules: current });
ok("the computed score and its canonical band pass through unchanged",
  assessed.score === 82 && assessed.risk_level === "good" && assessed.suppressed !== true, JSON.stringify(assessed));
const projected = projectPhase5EvidenceForCustomer(current);
ok("the customer projection keeps the statement and states no outage",
  projected.cve_intelligence.customer_message === cve.customer_message &&
    projected.cve_intelligence.evidence_publishable === false &&
    !/could not|unavailable|incomplete/i.test(projected.cve_intelligence.customer_message));

// ── 4. Stored scans keep their recorded meaning ──────────────────────────────
const historicalKev = {
  source: "cisa_kev", catalogue_source: "r2_cache", checked: 1200, matched: 1,
  matches: [{ cve_id: "CVE-2099-10001", matched_technology: "nginx" }],
  score_impact_applied: -5,
};
const historicalCve = { cve_coverage: "complete", technologies_checked: ["nginx"], lookup_statuses: { nginx: { status: "complete" } }, results: { nginx: [] }, total_cves: 0 };
const stored = { cve_intelligence: historicalCve, known_exploited_vulnerabilities: historicalKev, email_security_intelligence: email };
const storedRead = resolvePhase5HistoricalCustomerProjection({
  score: 60, riskLevel: "moderate", scanQuality: "complete", modules: stored,
});
ok("a stored score finalised with an exploited-vulnerability deduction is read back exactly",
  storedRead.score === 60 && storedRead.risk_level === "moderate" && storedRead.persisted_score_already_adjusted === true,
  JSON.stringify(storedRead));
const storedProjection = projectPhase5EvidenceForCustomer(stored);
ok("a stored exploited-vulnerability result stays publishable as recorded",
  storedProjection.known_exploited_vulnerabilities.evidence_publishable === true &&
    storedProjection.known_exploited_vulnerabilities.matches.length === 1);
const missing = resolvePhase5EvidenceContract({ email_security_intelligence: email });
ok("a stored scan with no vulnerability modules recorded still fails closed, as before",
  missing.complete === false && missing.incomplete_modules.includes("cve_intelligence"));

// ── 5. The score owner holds no outside-data arithmetic ──────────────────────
const scoring = await eng("scoring.js");
ok("the score owner no longer exports an exploited-vulnerability deduction",
  !("computeKevCveDeduction" in scoring) && !("applyKevCveDeduction" in scoring) && !("KEV_CVE_SCORE_WEIGHTS" in scoring));
eq("the score methodology stamp records the change", scoring.CYBER_METRICS_SCORE_METHODOLOGY_VERSION, "2026-10-21.1");

// ── 6. Registration data (registry RDAP) is optional ─────────────────────────
// The one outside service a scan still asks besides DNS. A registry that does
// not answer leaves the registration notes out and nothing more: no error, no
// request URL in the result, and no effect on whether the scan completed.
const { REGISTRATION_DATA_OPTIONAL, runWhoisModule } = await eng("whois-scan.js");
const { buildScanQuality } = await eng("scan-engine.js");
const { markDeadlineDeferred } = await eng("scan-budget.js");
const realFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new TypeError("network refused"); };
let unanswered;
try { unanswered = await runWhoisModule("example.co.uk"); } finally { globalThis.fetch = realFetch; }
ok("an unanswered registry is reported unavailable and optional, never as an error",
  unanswered.optional === true && unanswered.outcome === "unavailable" && !unanswered.error &&
    unanswered.reason === "registry_not_answering", JSON.stringify(unanswered));
ok("the result names each registry service asked and how it answered",
  JSON.stringify(unanswered.registries_asked) ===
    JSON.stringify([{ registry: "rdap.nominet.uk", outcome: "no_response" }, { registry: "rdap.org", outcome: "no_response" }]),
  JSON.stringify(unanswered.registries_asked));
ok("no request URL or raw network error is kept", !/https?:\/\/|network refused/.test(JSON.stringify(unanswered)));
const coreModules = {
  dns: { resolves: true }, ssl: {}, headers: {}, email_security: {}, dmarc_core: {},
};
const withUnanswered = buildScanQuality({ ...coreModules, whois_intelligence: unanswered });
const withDeferred = buildScanQuality({ ...coreModules, whois_intelligence: markDeadlineDeferred({ ...REGISTRATION_DATA_OPTIONAL }) });
ok("an unanswered or deferred registry never makes the scan incomplete",
  [withUnanswered, withDeferred].every((graded) =>
    !graded.modules_skipped.includes("whois_intelligence") &&
      !graded.modules_incomplete.some((entry) => entry.module === "whois_intelligence") &&
      graded.warnings.length === 0),
  JSON.stringify([withUnanswered, withDeferred]));
const storedLegacy = buildScanQuality({ ...coreModules, whois_intelligence: { error: "All RDAP providers failed: operation timed out" } });
ok("a stored result from before registration data was optional keeps its recorded grading",
  storedLegacy.modules_skipped.includes("whois_intelligence"), JSON.stringify(storedLegacy));

console.log(`outside vulnerability data: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
