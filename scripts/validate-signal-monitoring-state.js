#!/usr/bin/env node
//
// Item 5 / PR-5.4: canonical within-scan per-signal monitoring states and
// customer wording. Proves all four states from CyberMeters' own module
// evidence (no third-party provider participates),
// module-incomplete attribution, PR-5.1 coarse fallback, complete-copy stability,
// backend report exposure, and four executable mutation directions. CI-blocking.
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const worker = path.join(root, "workers", "scan-api", "src");
const statePath = path.join(worker, "engines", "signal-monitoring-state.js");
const presentationPath = path.join(worker, "engines", "assessment-presentation.js");
const mutation = process.argv.find((arg) => arg.startsWith("--mutation="))?.split("=")[1] ?? null;

async function loadStateModule() {
  if (mutation !== "collapse-states" && mutation !== "ignore-module-outcome" &&
      mutation !== "partial-unavailable-reads-healthy") {
    return import(pathToFileURL(statePath).href);
  }

  const source = fs.readFileSync(statePath, "utf8");
  // ignore-module-outcome: an unavailable module outcome reads as healthy.
  // partial-unavailable-reads-healthy: a signal with some unavailable modules
  // is no longer degraded.
  const mutated = mutation === "collapse-states"
    ? source
      .replace('MONITORING_DEGRADED: "monitoring_degraded"', 'MONITORING_DEGRADED: "monitoring_healthy"')
      .replace('SIGNAL_UNAVAILABLE:  "signal_unavailable"', 'SIGNAL_UNAVAILABLE:  "monitoring_healthy"')
      .replace('EVIDENCE_INCOMPLETE: "evidence_incomplete"', 'EVIDENCE_INCOMPLETE: "monitoring_healthy"')
    : mutation === "ignore-module-outcome"
      ? source.replace(
        'if (value.outcome === "unavailable" || value.unavailable === true) {',
        "if (false) {"
      )
      : source.replace("    unavailable > 0 ||\n", "");
  if (mutated === source) throw new Error(`state mutation target missing: ${mutation}`);
  return import(`data:text/javascript;base64,${Buffer.from(mutated).toString("base64")}#${mutation}`);
}

async function loadPresentationModule() {
  if (mutation !== "present-degraded-as-healthy") {
    return import(pathToFileURL(presentationPath).href);
  }

  // data: modules cannot resolve relative specifiers, so BOTH real relative
  // imports are rewritten to absolute file URLs (the REAL scoring bindings —
  // CYBER_METRICS_SCORE_METHODOLOGY_VERSION + riskLevelForScore — stay intact);
  // each rewrite is a must-fail anchor: a silent no-op replace previously left
  // a relative "./scoring.js" import in the data: module, so the child died at
  // load with empty stdout and the kill was rejected (hosted run 31653951557).
  const scoringAbs = `import {\n  CYBER_METRICS_SCORE_METHODOLOGY_VERSION,\n  riskLevelForScore,\n} from "${pathToFileURL(path.join(worker, "engines", "scoring.js")).href}";`;
  const raw = fs.readFileSync(presentationPath, "utf8");
  const withScoring = raw.replace('import {\n  CYBER_METRICS_SCORE_METHODOLOGY_VERSION,\n  riskLevelForScore,\n} from "./scoring.js";', scoringAbs);
  if (withScoring === raw) throw new Error("presentation scoring import anchor missing");
  const source = withScoring.replace('from "./signal-monitoring-state.js";', `from "${pathToFileURL(statePath).href}";`);
  if (source === withScoring) throw new Error("presentation monitoring import anchor missing");
  const mutated = source.replace('entry?.state !== "monitoring_healthy"', "false");
  if (mutated === source) throw new Error("presentation mutation target missing");
  return import(`data:text/javascript;base64,${Buffer.from(mutated).toString("base64")}#${mutation}`);
}

const stateModel = await loadStateModule();
const presentation = await loadPresentationModule();
const {
  SIGNAL_MONITORING_DEFINITIONS,
  SIGNAL_MONITORING_STATES,
  SIGNAL_MONITORING_WORDING,
  deriveSignalMonitoringStates, normalizeSignalMonitoringStates, requiredMonitoringSignals,
} = stateModel;
const { buildScanCompletionPresentation, resolveAssessmentPresentation } = presentation;

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const provider = (outcome) => ({
  outcome,
  attempts: 1,
  latency_ms: 25,
  final_error: outcome === "available" ? null : "provider unavailable",
});

function completeModules() {
  return {
    dns: {},
    subdomains: {},
    ssl: { https_probe_executed: true },
    headers: {},
    email_security: {},
    dmarc_core: { core_completeness: "complete", outcome: "available" },
    email_security_intelligence: {},
    dns_bruteforce: {},
    subdomain_takeover: {},
    asset_exposure: {},
    cloud_storage_discovery: {},
    technology_detection: {},
    cve_intelligence: {},
    known_exploited_vulnerabilities: {},
    whois_intelligence: {},
  };
}

const completeQuality = {
  status: "complete",
  warnings: [],
  modules_skipped: [],
};
const derive = (overrides = {}) => deriveSignalMonitoringStates({
  modules: overrides.modules ?? completeModules(),
  scanQuality: overrides.scanQuality ?? completeQuality,
});

// ── Vocabulary and canonical wording coverage ───────────────────────────────
{
  const states = Object.values(SIGNAL_MONITORING_STATES);
  eq("the canonical model exposes four distinct states", new Set(states).size, 4);
  for (const expected of [
    "monitoring_healthy",
    "monitoring_degraded",
    "signal_unavailable",
    "evidence_incomplete",
  ]) {
    ok(`canonical state exists: ${expected}`, states.includes(expected));
  }
  for (const signal of Object.keys(SIGNAL_MONITORING_DEFINITIONS)) {
    const wording = SIGNAL_MONITORING_WORDING[signal];
    ok(`${signal}: one canonical wording map exists`, wording && typeof wording === "object");
    for (const state of [
      "monitoring_healthy",
      "monitoring_degraded",
      "signal_unavailable",
      "evidence_incomplete",
    ]) {
      ok(`${signal}/${state}: signal-specific wording is non-empty`,
        typeof wording?.[state] === "string" && wording[state].length > 20);
    }
  }
}

// ── Required state fixtures ─────────────────────────────────────────────────
// Every signal is CyberMeters' own observation. A signal is degraded when some
// of its modules report an unavailable or degraded outcome, unavailable when all
// of them do, and no third-party provider participates in any state.
const degradedModules = completeModules();
degradedModules.dmarc_core = { core_completeness: "complete", outcome: "unavailable" };
const degradedEmail = derive({ modules: degradedModules });
{
  const email = degradedEmail.signals.email_protection;
  eq("one of three email modules unavailable → email_protection monitoring_degraded",
    email.state, "monitoring_degraded");
  ok("degraded email carries email-specific wording",
    email.message.includes("email protection") &&
      email.message.includes("could not fully verify"));
  ok("degraded email never reads healthy",
    email.state !== "monitoring_healthy" && !/completed normally/i.test(email.message));
  ok("degraded email evidence names its modules and no provider",
    JSON.stringify(email.evidence.modules) ===
      JSON.stringify(["email_security", "dmarc_core", "email_security_intelligence"]) &&
      !("providers" in email.evidence));
}

const unavailableModules = completeModules();
unavailableModules.whois_intelligence = { outcome: "unavailable" };
const unavailableRegistration = derive({ modules: unavailableModules });
{
  const registration = unavailableRegistration.signals.registration_data;
  eq("every registration module unavailable → registration_data signal_unavailable",
    registration.state, "signal_unavailable");
  ok("unavailable registration wording is explicit and never healthy",
    /unavailable/i.test(registration.message) && !/completed normally/i.test(registration.message));
}

// No signal depends on a third-party data provider, and the resolver ignores
// any provider health it is handed.
{
  ok("no signal declares a provider dependency",
    Object.values(SIGNAL_MONITORING_DEFINITIONS).every((definition) =>
      !("providers" in definition)));
  ok("no signal is named for an external log source",
    !Object.keys(SIGNAL_MONITORING_DEFINITIONS).some((name) => /transparency|provider/i.test(name)));
  const withHealth = deriveSignalMonitoringStates({
    modules: completeModules(),
    scanQuality: completeQuality,
    providerHealth: { unrelated: provider("unavailable") },
  });
  ok("provider health handed to the resolver changes nothing",
    Object.values(withHealth.signals).every((entry) => entry.state === "monitoring_healthy"));
}

const incompleteModules = completeModules();
incompleteModules.asset_exposure = {
  incomplete: true,
  executed: false,
  outcome: "deadline_exceeded",
};
const incompleteAttackSurface = derive({
  modules: incompleteModules,
  scanQuality: {
    status: "partial",
    warnings: ["Module incomplete: asset_exposure"],
    modules_skipped: ["asset_exposure"],
  },
});
{
  const attackSurface = incompleteAttackSurface.signals.attack_surface;
  eq("incomplete module → its signal evidence_incomplete",
    attackSurface.state, "evidence_incomplete");
  ok("incomplete signal identifies the responsible module",
    attackSurface.evidence.incomplete_modules.includes("asset_exposure"));
  ok("incomplete signal wording is specific and never healthy",
    /attack-surface checks did not complete/i.test(attackSurface.message) &&
      !/completed normally/i.test(attackSurface.message));
}

const allComplete = derive();
{
  eq("complete derivation stamps every configured signal exactly once",
    Object.keys(allComplete.signals).length,
    Object.keys(SIGNAL_MONITORING_DEFINITIONS).length);
  ok("all complete evidence → every signal monitoring_healthy",
    Object.values(allComplete.signals).every((entry) =>
      entry.state === "monitoring_healthy"
    ));
  ok("canonical state output is versioned",
    allComplete.version === "signal-monitoring-state-v3");
}

// A module that left no evidence is evidence-incomplete, never a false healthy.
{
  const missingModules = completeModules();
  delete missingModules.whois_intelligence;
  const missing = derive({ modules: missingModules }).signals.registration_data;
  eq("missing module evidence fails closed", missing.state, "evidence_incomplete");
}

// ── Scan-completion presentation ────────────────────────────────────────────
{
  const complete = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "complete",
    monitoringStates: allComplete,
  });
  eq("all-healthy complete audit copy stays byte-identical",
    complete.description,
    "Scan completed for example.com — score 95, risk excellent");
  eq("all-healthy complete notification copy stays byte-identical",
    complete.message,
    "Score: 95 · excellent risk");
  eq("all-healthy complete copy has no disclosure", complete.disclosure, null);

  const degraded = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "complete",
    monitoringStates: degradedEmail,
  });
  ok("attributable degraded email upgrades completion copy",
    degraded.message.includes(
      "We could not fully verify email protection data in this run. Other checks completed normally."
    ));
  ok("degraded monitoring coverage-caps score/rating semantics",
    degraded.quality === "degraded" &&
      degraded.message.startsWith("Score: 95 (provisional)") &&
      !degraded.message.includes("excellent risk"));
  ok("degraded monitoring never presents as an unqualified healthy completion",
    degraded.disclosure != null && !/monitoring healthy/i.test(degraded.message));

  const degradedQuality = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "degraded",
    monitoringStates: degradedEmail,
  });
  ok("degraded-quality scan uses the attributable email wording",
    degradedQuality.message.includes(
      "We could not fully verify email protection data in this run."
    ));
  ok("degraded-quality score remains provisional",
    degradedQuality.message.includes("Score: 95 (provisional)") &&
      !degradedQuality.message.includes("excellent"));

  const unavailable = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "complete",
    monitoringStates: unavailableRegistration,
  });
  // Registration data is optional: a registry that did not answer is stated on
  // its own signal and never caveats the scan's required checks.
  eq("an unanswered registry leaves a complete scan's completion copy unqualified",
    unavailable.message, "Score: 95 · excellent risk");
  ok("an unanswered registry adds no completion disclosure and keeps the scan complete",
    unavailable.disclosure == null && unavailable.complete === true);
  ok("the registration signal still states its own unavailability",
    unavailableRegistration.signals.registration_data.message === "Domain-registration data was unavailable in this run.");

  const partialSpecific = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "partial",
    monitoringStates: incompleteAttackSurface,
  });
  ok("partial attributable scan uses signal-specific wording",
    partialSpecific.message.includes("Attack-surface checks did not complete in this run."));
  ok("partial attributable score remains provisional",
    partialSpecific.message.includes("Score: 95 (provisional)"));
  ok("partial attributable copy suppresses the unqualified band",
    !partialSpecific.message.includes("excellent"));

  const partialUnattributed = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "partial",
    monitoringStates: allComplete,
  });
  ok("unattributed partial scan retains PR-5.1 coarse fallback",
    partialUnattributed.disclosure.startsWith(
      "Partial scan — some checks did not complete this run"
    ));
}

// ── Production wiring and additive output ──────────────────────────────────
{
  const engine = fs.readFileSync(path.join(worker, "engines", "scan-engine.js"), "utf8");
  const routes = fs.readFileSync(path.join(worker, "routes", "scans.js"), "utf8");
  const events = fs.readFileSync(path.join(worker, "lib", "events.js"), "utf8");

  ok("scan engine imports the canonical state resolver",
    /import \{ deriveSignalMonitoringStates \} from "\.\/signal-monitoring-state\.js";/.test(engine));
  ok("scan engine derives states from modules and scan quality only",
    /deriveSignalMonitoringStates\(\{\s*modules,\s*scanQuality,\s*\}\)/.test(engine));
  ok("completed R2 report exposes canonical monitoring_states",
    /monitoring_states:\s+monitoringStates/.test(engine));
  ok("completed diagnostics carry no provider snapshot",
    !/providerHealth/.test(engine));
  ok("atomic audit completion presentation receives canonical monitoring states",
    /monitoring_states:\s*report\?\.monitoring_states\s*\?\?\s*null/.test(engine) &&
      /scanCompletionAuditStatement\(env,\s*latch\.completion\)/.test(engine) &&
      /const completion = buildScanCompletionPresentation\(\{\s*domain,\s*score,\s*riskLevel: risk_level,\s*scanQuality: scan_quality,\s*monitoringStates: monitoring_states,\s*\}\);/.test(events));
  ok("in-app completion presentation receives canonical monitoring states",
    /createNotificationsForDomain\([\s\S]{0,240}scanQuality\?\.status,\s*monitoringStates,\s*\)/.test(engine) &&
      /buildScanCompletionPresentation\(\{[\s\S]{0,180}monitoringStates,[\s\S]{0,30}\}\)/.test(events));
  eq("authenticated report API exposes monitoring_states in both lifecycle branches",
    (routes.match(/monitoring_states:\s*(?:snap\.monitoring_states \?\? )?raw\.monitoring_states \?\? null/g) || []).length,
    2);
  ok("no migration 100 was created",
    !fs.existsSync(path.join(root, "database", "migrations", "100-signal-monitoring-state.sql")));
}

// ── v3: outside vulnerability data gone, registration data optional ────────
{
  ok("no signal reads outside vulnerability data (check-pack.js)",
    !("vulnerability_intelligence" in SIGNAL_MONITORING_DEFINITIONS) &&
      !("vulnerability_intelligence" in allComplete.signals));
  ok("registration data is reported as optional, never required",
    SIGNAL_MONITORING_DEFINITIONS.registration_data?.optional === true &&
      allComplete.signals.registration_data?.optional === true &&
      !requiredMonitoringSignals(allComplete).includes("registration_data"));
}

// A stored v2 payload is read against the signals it was recorded with, so a
// historical scan whose vulnerability-intelligence evidence was incomplete
// reads exactly as it did: required, and coverage-limiting.
{
  const legacy = {
    version: "signal-monitoring-state-v2",
    signals: Object.fromEntries([
      "dns", "website_security", "email_protection", "attack_surface",
      "technology_visibility", "vulnerability_intelligence", "registration_data",
    ].map((signal) => [signal, {
      state: signal === "vulnerability_intelligence" ? "evidence_incomplete" : "monitoring_healthy",
      message: `${signal} message`,
      evidence: { modules: [], incomplete_modules: [] },
    }])),
  };
  const normalised = normalizeSignalMonitoringStates(legacy);
  ok("a v2 payload keeps its vulnerability-intelligence signal",
    normalised.signals.vulnerability_intelligence?.state === "evidence_incomplete");
  ok("a v2 payload keeps every signal required, registration data included",
    requiredMonitoringSignals(legacy).includes("vulnerability_intelligence") &&
      requiredMonitoringSignals(legacy).includes("registration_data"));
  const legacyAssessment = resolveAssessmentPresentation({
    score: 90, scanQuality: "complete", status: "completed", monitoringStates: legacy,
  });
  ok("a v2 scan with incomplete vulnerability evidence stays coverage-limited",
    legacyAssessment.provisional === true && legacyAssessment.authoritative === false);
}

// Each named mutation must make the same behavioural contract red.
if (!mutation) {
  for (const [name, expectedFailure] of [
    ["collapse-states", "FAIL the canonical model exposes four distinct states"],
    ["ignore-module-outcome",
      "FAIL every registration module unavailable → registration_data signal_unavailable"],
    ["partial-unavailable-reads-healthy",
      "FAIL one of three email modules unavailable → email_protection monitoring_degraded"],
    ["present-degraded-as-healthy", "FAIL attributable degraded email upgrades completion copy"],
  ]) {
    const run = spawnSync(process.execPath, [scriptPath, `--mutation=${name}`], {
      cwd: root,
      encoding: "utf8",
    });
    ok(`mutation ${name} makes the validator RED`,
      run.status !== 0 && run.stdout.includes(expectedFailure),
      `status=${run.status} stdout=${JSON.stringify(run.stdout.slice(0, 300))}`);
  }
}

console.log(`\nsignal-monitoring-state: ${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.error("signal-monitoring-state validation FAILED");
  process.exit(1);
}
console.log("signal-monitoring-state validation passed");
