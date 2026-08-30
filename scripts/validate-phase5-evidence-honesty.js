#!/usr/bin/env node
// Phase-5 False-Healthy P1 — CI-blocking customer-output and mutation proof.
//
// The faithful trace delegates to validate-email-deadline-evidence's real
// runScanEngine harness. Its deferred-intel fixture uses Queue context, completes
// CVE + KEV, and holds only Email Intelligence past its independent bounded cap.
// This proves a slow sibling cannot erase fulfilled Phase-5 evidence. There is no
// global-deadline manipulation, production access or external network access.
//
// Canonical implementation base (origin/main after PR #350):
// 9f2014994ecd3e57c6ec2cf64da2cbac4dec904a
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const selfPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(selfPath), "..");
const engineDir = path.join(root, "workers/scan-api/src/engines");
const engineUrl = (name) => pathToFileURL(path.join(engineDir, name)).href;
const { runRiskModule } = await import(engineUrl("asset-intel.js"));
const {
  projectPhase5EvidenceForCustomer,
  resolvePhase5CustomerAssessment,
  resolvePhase5EvidenceContract,
} = await import(engineUrl("phase5-evidence.js"));
const { resolveAssessmentPresentation } =
  await import(engineUrl("assessment-presentation.js"));
const { markDeadlineDeferred } = await import(engineUrl("scan-budget.js"));
const { moduleCompletionGate } = await import(engineUrl("asm-cases.js"));
const { isPhase5EvidenceAvailable } = await import(
  pathToFileURL(
    path.join(root, "frontend/src/lib/phase5EvidencePresentation.js"),
  ).href
);

const EMAIL_VALIDATOR = path.join(
  root,
  "scripts/validate-email-deadline-evidence.js",
);
const EXPECTED_MUTANTS = 8;
const EXPECTED_ASSERTIONS = 45;
const PHASE5_KEYS = [
  "cve_intelligence",
  "known_exploited_vulnerabilities",
  "email_security_intelligence",
];

const completedCve = (overrides = {}) => ({
  technologies_checked: ["nginx"],
  lookup_statuses: { nginx: { status: "complete" } },
  results: { nginx: [] },
  total_cves: 0,
  critical_count: 0,
  high_count: 0,
  source: "nvd_api",
  cve_coverage: "complete",
  ...overrides,
});
const completedKev = (overrides = {}) => ({
  matches: [],
  checked: 100,
  matched: 0,
  source: "cisa_kev",
  catalogue_source: "origin",
  catalogue_stale: false,
  ...overrides,
});
const completedEmailIntel = (overrides = {}) => ({
  domain: "example.com",
  spf: { status: "PASS" },
  dkim: { status: "VERIFIED" },
  dmarc: { status: "ENFORCED" },
  mta_sts: { configured: true },
  tls_rpt: { configured: true },
  starttls: { observed: true },
  email_security_score: 100,
  email_score_breakdown: { status: "EXCELLENT" },
  rating: "excellent",
  business_email_risk: "Low",
  strengths: [],
  findings: [],
  business_impacts: [],
  ...overrides,
});
const deferred = (shape) => markDeadlineDeferred(shape);
const completedTechnology = () => ({
  technologies: ["nginx"],
  technology_fingerprints: [{ technology: "nginx", source: "server", confidence: 90 }],
  serviceability_contract: {
    serviceable: true,
    conclusion_class: "conclusive",
    reason: "origin_response_serviceable",
  },
});
const completeModules = () => ({
  technology_detection: completedTechnology(),
  cve_intelligence: completedCve(),
  known_exploited_vulnerabilities: completedKev(),
  email_security_intelligence: completedEmailIntel(),
});
const fallbackModules = () => ({
  technology_detection: completedTechnology(),
  cve_intelligence: deferred(completedCve()),
  known_exploited_vulnerabilities: deferred(completedKev()),
  email_security_intelligence: deferred(completedEmailIntel()),
});
const probe = (modules, findings = []) => {
  // Production order: the single score owner stamps the exact charged KEV
  // evidence before risk-intelligence builds the canonical customer finding.
  const customer = resolvePhase5CustomerAssessment({
    score: 100,
    riskLevel: "excellent",
    modules,
  });
  return {
    customer,
    risk: runRiskModule(findings, modules),
    projected: projectPhase5EvidenceForCustomer(modules),
  };
};

function runEngineChild() {
  return JSON.parse(
    String(
      execFileSync(
        process.execPath,
        [EMAIL_VALIDATOR, "--child=deferred-intel"],
        {
          cwd: root,
          timeout: 180_000,
          maxBuffer: 32 * 1024 * 1024,
        },
      ),
    ),
  );
}

const childArg = process.argv.find((arg) => arg.startsWith("--child="));
if (childArg) {
  const mode = childArg.slice("--child=".length);
  let output;
  if (mode === "engine") {
    const engine = runEngineChild();
    output = {
      score: engine.score,
      riskLevel: engine.riskLevel,
      overall: engine.risk?.overall_risk_level ?? null,
      narrative: engine.risk?.narrative ?? null,
      hasMtaStsDetail: engine.hasMtaStsDetail,
    };
  } else if (mode === "frontend-deferred") {
    output = {
      available: isPhase5EvidenceAvailable(undefined),
    };
  } else {
    const modules = completeModules();
    if (mode === "cve-deferred") {
      modules.cve_intelligence = deferred(completedCve());
    } else if (mode === "kev-deferred") {
      modules.known_exploited_vulnerabilities = deferred(completedKev());
    }
    const findings = mode === "sibling"
      ? [{
          id: "trusted_sibling",
          title: "Trustworthy sibling finding",
          severity: "high",
          category: "Web Security",
          module: "headers",
          description: "Completed header evidence.",
        }]
      : [];
    output = probe(modules, findings);
  }
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

let passed = 0;
let failed = 0;
let assertions = 0;
let killed = 0;
const ok = (name, condition, detail = "") => {
  assertions += 1;
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

console.log("── A. real runScanEngine independent durable Phase-5 trace ──");
const engine = runEngineChild();
const projectedEngine = projectPhase5EvidenceForCustomer({
  cve_intelligence: engine.cve,
  known_exploited_vulnerabilities: engine.kev,
  email_security_intelligence: engine.intel,
});
const presentation = resolveAssessmentPresentation({
  score: engine.score,
  scanQuality: engine.reportQuality,
  status: engine.dbStatus,
  coverage: engine.scanQuality,
});
ok("A1 no exception escaped", engine.escaped == null, String(engine.escaped));
ok("A2 scan completed terminally", engine.dbStatus === "completed");
ok("A3 scan quality remains partial",
  engine.quality === "partial" && engine.reportQuality === "partial");
ok("A4 only Email Intelligence and its derived risk consumer are incomplete",
  engine.scanQuality?.modules_skipped?.includes("email_security_intelligence") &&
    !engine.scanQuality?.modules_skipped?.includes("cve_intelligence") &&
    !engine.scanQuality?.modules_skipped?.includes("known_exploited_vulnerabilities") &&
    engine.scanQuality.modules_skipped.every((key) =>
      ["email_security_intelligence", "risk_intelligence", "remediation_plan"].includes(key)),
  JSON.stringify(engine.scanQuality?.modules_skipped));
ok("A5 completed CVE sibling remains canonical publishable evidence",
  engine.cve?.executed !== false && engine.cve?.outcome !== "deadline_exceeded" &&
    projectedEngine.cve_intelligence.evidence_publishable === true);
ok("A6 completed KEV sibling remains canonical publishable evidence",
  engine.kev?.executed !== false && engine.kev?.outcome !== "deadline_exceeded" &&
    projectedEngine.known_exploited_vulnerabilities.evidence_publishable === true);
ok("A7 email-intelligence fallback is canonical non-publishable evidence",
  engine.intel?.executed === false && engine.intel?.incomplete === true &&
    engine.intel?.outcome === "deadline_exceeded" &&
    projectedEngine.email_security_intelligence.evidence_publishable === false);
ok("A8 runRiskModule publishes no Low", engine.risk?.overall_risk_level == null);
ok("A9 no no-critical/high narrative is published",
  engine.risk?.narrative == null &&
    !JSON.stringify(engine.risk).includes(
      "No critical or high-severity issues detected"));
ok("A10 report publishes no numeric 100", engine.score == null);
ok("A11 report publishes no excellent band", engine.riskLevel == null);
ok("A12 presentation is explicitly incomplete and scoreless",
  presentation.quality === "partial" && presentation.provisional === true &&
    presentation.display_score == null &&
    /incomplete/i.test(presentation.message || ""),
  JSON.stringify(presentation));
ok("A13 primary email does not gain fabricated MTA-STS/TLS-RPT detail",
  !Object.prototype.hasOwnProperty.call(engine.email || {}, "mta_sts_detail") &&
    !Object.prototype.hasOwnProperty.call(engine.email || {}, "tls_rpt_detail"));
ok("A14 completed primary email evidence remains visible",
  engine.email?.executed !== false && engine.email?.spf?.present === true &&
    engine.email?.dmarc?.present === true);
ok("A15 completed DNS/SSL/header siblings remain visible",
  engine.dns?.resolves === true && engine.ssl != null && engine.headers != null);
ok("A16 completed technology sibling remains visible", engine.technology != null);
ok("A17 risk is incomplete while trustworthy remediation remains available",
  engine.risk?.incomplete === true &&
    engine.remediation?.incomplete !== true &&
    engine.remediation?.summary?.total > 0);

console.log("\n── B. isolated producer-to-consumer fixtures ──");
{
  const modules = fallbackModules();
  const result = probe(modules);
  const contract = resolvePhase5EvidenceContract(modules);
  ok("B1 all-three fallback contract is incomplete", !contract.complete);
  ok("B2 all three module keys are identified", contract.incomplete_modules.length === 3);
  ok("B3 all-three fallback withholds Low/excellent/100 and narrative",
    result.risk.overall_risk_level == null &&
      result.risk.narrative == null &&
      result.customer.score == null &&
      result.customer.risk_level == null);
}
{
  const modules = completeModules();
  modules.cve_intelligence = deferred(completedCve());
  const result = probe(modules);
  ok("B4 CVE-only deferral is recognised",
    result.customer.evidence.publishable.cve === false);
  ok("B5 completed KEV sibling remains publishable",
    result.customer.evidence.publishable.kev === true);
  ok("B6 CVE-only deferral withholds Low/excellent/100",
    result.risk.overall_risk_level == null &&
      result.customer.score == null && result.customer.risk_level == null);
}
{
  const modules = completeModules();
  modules.known_exploited_vulnerabilities = deferred(completedKev());
  const result = probe(modules);
  ok("B7 KEV-only deferral is recognised",
    result.customer.evidence.publishable.kev === false);
  ok("B8 completed CVE sibling remains publishable",
    result.customer.evidence.publishable.cve === true);
  ok("B9 KEV-only deferral withholds Low/excellent/100",
    result.risk.overall_risk_level == null &&
      result.customer.score == null && result.customer.risk_level == null);
}
{
  const modules = completeModules();
  modules.email_security_intelligence = deferred(completedEmailIntel());
  const result = probe(modules);
  ok("B10 email-intelligence-only deferral is recognised",
    result.customer.evidence.publishable.email === false);
  ok("B11 completed CVE/KEV siblings remain publishable",
    result.customer.evidence.publishable.cve &&
      result.customer.evidence.publishable.kev);
  ok("B12 customer projection marks email intelligence unavailable",
    result.projected.email_security_intelligence.evidence_publishable === false);
  ok("B13 email-intelligence-only deferral withholds excellent/100",
    result.customer.score == null && result.customer.risk_level == null);
}
{
  const result = probe(completeModules());
  ok("B14 genuine completed-zero contract is complete",
    result.customer.evidence.complete);
  ok("B15 genuine completed-zero retains legitimate Low",
    result.risk.overall_risk_level === "Low");
  ok("B16 genuine completed-zero retains legitimate excellent/100",
    result.customer.score === 100 &&
      result.customer.risk_level === "excellent");
  ok("B17 genuine completed-zero retains legitimate no-issues narrative",
    /No critical or high-severity issues detected/.test(result.risk.narrative));
}
{
  const modules = completeModules();
  modules.cve_intelligence = completedCve({
    total_cves: 1,
    critical_count: 1,
    results: { nginx: [{
      cve_id: "CVE-2099-0001",
      severity: "CRITICAL",
      description: "Positive fixture.",
    }] },
  });
  modules.known_exploited_vulnerabilities = completedKev({
    matched: 1,
    matches: [{
      cve_id: "CVE-2099-0001",
      vulnerability_name: "Positive fixture",
      matched_technology: "nginx",
      fingerprint_source: "server",
      fingerprint_confidence: 90,
      version_confirmed: false,
    }],
  });
  const result = probe(modules);
  ok("B18 completed positive CVE finding remains publishable",
    result.risk.enriched_findings.some(
      (finding) => finding.id === "cve_high_severity_detected"));
  ok("B19 completed positive KEV finding remains publishable",
    result.risk.enriched_findings.some(
      (finding) => finding.id === "kev_active_exploitation"));
  ok("B20 version-blind CVE stays informational while bounded KEV produces Moderate",
    result.risk.overall_risk_level === "Moderate" &&
      result.risk.enriched_findings.find(
        (finding) => finding.id === "cve_high_severity_detected")?.severity === "informational");
}
{
  const sibling = {
    id: "trusted_sibling",
    title: "Trustworthy sibling finding",
    severity: "high",
    category: "Web Security",
    module: "headers",
    description: "Completed header evidence.",
  };
  const result = probe(fallbackModules(), [sibling]);
  ok("B21 trustworthy sibling finding remains visible",
    result.risk.enriched_findings.some((finding) => finding.id === sibling.id));
  ok("B22 trustworthy sibling category remains visible",
    Object.values(result.risk.risk_categories).some((category) =>
      category.some((finding) => finding.id === sibling.id)));
  ok("B23 incomplete Phase-5 still prevents an overall conclusion",
    result.risk.overall_risk_level == null);
}
{
  const gate = moduleCompletionGate(fallbackModules(), {
    status: "partial",
    modules_skipped: PHASE5_KEYS,
  });
  ok("B24 CVE lifecycle verification cannot progress",
    gate.canVerify("cve_intelligence") === false);
  ok("B25 KEV lifecycle verification cannot progress",
    gate.canVerify("known_exploited_vulnerabilities") === false);
  ok("B26 completed evidence remains eligible (positive control)",
    moduleCompletionGate(completeModules(), {
      status: "complete",
      modules_skipped: [],
    }).canVerify("cve_intelligence") === true);
  ok("B27 frontend customer resolver refuses backend-marked evidence",
    isPhase5EvidenceAvailable({
      evidence_publishable: false,
      mta_sts: { configured: false },
      tls_rpt: { configured: false },
    }) === false);
}

console.log("\n── M. pinned anchor-guarded mutations in fresh processes ──");
const ASSET_INTEL = path.join(engineDir, "asset-intel.js");
const PHASE5 = path.join(engineDir, "phase5-evidence.js");
const SCAN_ENGINE = path.join(engineDir, "scan-engine.js");
const FRONTEND_PRESENTATION = path.join(
  root,
  "frontend/src/lib/phase5EvidencePresentation.js",
);
function runChild(mode) {
  return JSON.parse(String(execFileSync(process.execPath, [
    selfPath, `--child=${mode}`,
  ], {
    cwd: root,
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
  })));
}
async function withMutant(edits, run) {
  const originals = new Map();
  for (const { target, from, to } of edits) {
    const original = originals.get(target) ?? fs.readFileSync(target, "utf8");
    if (!originals.has(target)) originals.set(target, original);
    const current = fs.readFileSync(target, "utf8");
    const count = current.split(from).length - 1;
    if (count !== 1) {
      return { applied: false, reason: `anchor x${count} in ${path.basename(target)}` };
    }
    fs.writeFileSync(target, current.replace(from, to));
  }
  try {
    return { applied: true, result: await run() };
  } finally {
    for (const [target, source] of originals) fs.writeFileSync(target, source);
  }
}
const MUTATIONS = [
  {
    name: "M1 fallback zeroes treated as assessed Low",
    edits: [{
      target: ASSET_INTEL,
      from: "  if (!phase5Evidence.complete) {\n",
      to: "  if (false) {\n",
    }],
    check: () => runChild("engine").overall != null,
  },
  {
    name: "M2 incomplete CVE alone is omitted from the Phase-5 completeness gate",
    edits: [{
      target: PHASE5,
      from: "    .filter(([name]) => !completeByModule[name])\n",
      to: "    .filter(([name]) => name !== \"cve\" && !completeByModule[name])\n",
    }],
    check: () => {
      const result = runChild("cve-deferred");
      return result.customer.score != null &&
        result.customer.risk_level != null;
    },
  },
  {
    name: "M3 incomplete CVE publishes excellent/100",
    edits: [{
      target: PHASE5,
      from: "  if (skippedScored.length > 0 || (suppressOnEvidenceGaps && !evidence.complete)) {",
      to: "  if (skippedScored.length > 0) {",
    }],
    check: () => {
      const result = runChild("cve-deferred");
      return result.customer.score === 100 &&
        result.customer.risk_level === "excellent";
    },
  },
  {
    name: "M4 incomplete KEV publishes excellent/100",
    edits: [{
      target: PHASE5,
      from: "  if (skippedScored.length > 0 || (suppressOnEvidenceGaps && !evidence.complete)) {",
      to: "  if (skippedScored.length > 0) {",
    }],
    check: () => {
      const result = runChild("kev-deferred");
      return result.customer.score === 100 &&
        result.customer.risk_level === "excellent";
    },
  },
  {
    name: "M5 frontend accepts missing legacy Phase-5 evidence",
    edits: [{
      target: FRONTEND_PRESENTATION,
      from: "  return moduleResult?.evidence_publishable === true\n",
      to: "  return moduleResult?.evidence_publishable !== false\n",
    }],
    check: () => {
      const result = runChild("frontend-deferred");
      return result.available === true;
    },
  },
  {
    name: "M6 engine projects deferred email transport absence",
    edits: [{
      target: SCAN_ENGINE,
      from: "    const emailIntelUsable =\n      isPublishableModuleEvidence(modules.email_security_intelligence) && emailApplicability.applicable;",
      to: "    const emailIntelUsable =\n      !modules.email_security_intelligence.error && !modules.email_security_intelligence.skipped && emailApplicability.applicable;",
    }],
    check: () => runChild("engine").hasMtaStsDetail === true,
  },
  {
    name: "M7 completed measured-zero control is suppressed",
    edits: [{
      target: PHASE5,
      from: "    cve: cveEvidence.negative_complete,\n",
      to: "    cve: false,\n",
    }],
    check: () => {
      const result = runChild("complete");
      return result.customer.score == null &&
        result.risk.overall_risk_level == null;
    },
  },
  {
    name: "M8 trustworthy sibling finding is lost",
    edits: [{
      target: ASSET_INTEL,
      from: "  const enrichedFindings = [];\n  const customerFindings = [];\n\n  for (const f of findings) {\n",
      to: "  const enrichedFindings = [];\n  const customerFindings = [];\n\n  for (const f of []) {\n",
    }],
    check: () => !runChild("sibling").risk.enriched_findings.some(
      (finding) => finding.id === "trusted_sibling"),
  },
];
for (const mutation of MUTATIONS) {
  const result = await withMutant(
    mutation.edits,
    async () => mutation.check(),
  );
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
ok(`M8 all ${EXPECTED_MUTANTS} pinned mutants killed`,
  killed === EXPECTED_MUTANTS, `${killed}/${EXPECTED_MUTANTS}`);
if (assertions !== EXPECTED_ASSERTIONS) {
  failed += 1;
  console.error(
    `FAIL assertion pin — expected ${EXPECTED_ASSERTIONS}, executed ${assertions}`,
  );
}
console.log(
  `\n${passed} passed, ${failed} failed, ` +
    `${assertions}/${EXPECTED_ASSERTIONS} assertions, ` +
    `${killed}/${EXPECTED_MUTANTS} mutants killed`,
);
process.exit(failed ? 1 : 0);
