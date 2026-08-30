#!/usr/bin/env node
//
// Item 5 / PR-5.4: canonical within-scan per-signal monitoring states and
// customer wording. Proves all four states, CT provider fallback semantics,
// module-incomplete attribution, PR-5.1 coarse fallback, complete-copy stability,
// backend report exposure, and three executable mutation directions. CI-blocking.
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
  if (mutation !== "collapse-states" && mutation !== "drop-ct-attribution") {
    return import(pathToFileURL(statePath).href);
  }

  const source = fs.readFileSync(statePath, "utf8");
  const mutated = mutation === "collapse-states"
    ? source
      .replace('MONITORING_DEGRADED: "monitoring_degraded"', 'MONITORING_DEGRADED: "monitoring_healthy"')
      .replace('SIGNAL_UNAVAILABLE:  "signal_unavailable"', 'SIGNAL_UNAVAILABLE:  "monitoring_healthy"')
      .replace('EVIDENCE_INCOMPLETE: "evidence_incomplete"', 'EVIDENCE_INCOMPLETE: "monitoring_healthy"')
    : source.replace(
      'providers: Object.freeze(["crt_sh", "certspotter"]),',
      "providers: Object.freeze([]),"
    );
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
  deriveSignalMonitoringStates,
} = stateModel;
const { buildScanCompletionPresentation } = presentation;

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
const fullProviderHealth = {
  crt_sh: provider("available"),
  certspotter: provider("available"),
};
const derive = (overrides = {}) => deriveSignalMonitoringStates({
  modules: overrides.modules ?? completeModules(),
  scanQuality: overrides.scanQuality ?? completeQuality,
  providerHealth: overrides.providerHealth ?? fullProviderHealth,
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
const degradedCt = derive({
  providerHealth: {
    crt_sh: provider("unavailable"),
    certspotter: provider("available"),
  },
});
{
  const ct = degradedCt.signals.certificate_transparency;
  eq("crt.sh unavailable + CertSpotter available → CT monitoring_degraded",
    ct.state, "monitoring_degraded");
  ok("degraded CT carries CT-specific wording",
    ct.message.includes("certificate transparency") &&
      ct.message.includes("could not fully verify"));
  ok("degraded CT never reads healthy",
    ct.state !== "monitoring_healthy" && !/completed normally/i.test(ct.message));
  eq("degraded CT exposes crt.sh unavailable evidence",
    ct.evidence.providers.crt_sh, "unavailable");
  eq("degraded CT exposes fallback available evidence",
    ct.evidence.providers.certspotter, "available");
}

const unavailableCt = derive({
  providerHealth: {
    crt_sh: provider("unavailable"),
  },
});
{
  const ct = unavailableCt.signals.certificate_transparency;
  eq("provider unavailable + no fallback evidence → signal_unavailable",
    ct.state, "signal_unavailable");
  ok("unavailable CT wording is explicit and never healthy",
    /unavailable/i.test(ct.message) && !/completed normally/i.test(ct.message));
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
    allComplete.version === "signal-monitoring-state-v1");
}

// Missing provider telemetry is evidence-incomplete, never a false healthy.
{
  const missing = derive({ providerHealth: {} }).signals.certificate_transparency;
  eq("missing CT telemetry fails closed", missing.state, "evidence_incomplete");
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
    monitoringStates: degradedCt,
  });
  ok("attributable degraded CT upgrades completion copy",
    degraded.message.includes(
      "We could not fully verify certificate transparency data in this run. Other checks completed normally."
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
    monitoringStates: degradedCt,
  });
  ok("degraded-quality scan uses the attributable CT wording",
    degradedQuality.message.includes(
      "We could not fully verify certificate transparency data in this run."
    ));
  ok("degraded-quality score remains provisional",
    degradedQuality.message.includes("Score: 95 (provisional)") &&
      !degradedQuality.message.includes("excellent"));

  const unavailable = buildScanCompletionPresentation({
    domain: "example.com",
    score: 95,
    riskLevel: "excellent",
    scanQuality: "complete",
    monitoringStates: unavailableCt,
  });
  ok("signal-unavailable completion copy names the unavailable signal",
    unavailable.message.includes("Certificate transparency data was unavailable in this run."));
  ok("signal-unavailable completion copy never reads healthy",
    unavailable.disclosure != null &&
      !unavailable.disclosure.includes("Certificate transparency checks completed normally"));

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
  ok("scan engine derives states from modules, scan quality and CT provider health",
    /deriveSignalMonitoringStates\(\{\s*modules,\s*scanQuality,\s*providerHealth,\s*\}\)/.test(engine));
  ok("completed R2 report exposes canonical monitoring_states",
    /monitoring_states:\s+monitoringStates/.test(engine));
  ok("completed diagnostics reuse the identical provider snapshot",
    /const providerHealth = ctCache\.healthSnapshot\(\);[\s\S]{0,800}providerHealth,\s*\}\);/.test(engine));
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

// Each named mutation must make the same behavioural contract red.
if (!mutation) {
  for (const [name, expectedFailure] of [
    ["collapse-states", "FAIL the canonical model exposes four distinct states"],
    ["drop-ct-attribution", "FAIL crt.sh unavailable + CertSpotter available"],
    ["present-degraded-as-healthy", "FAIL attributable degraded CT upgrades completion copy"],
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
