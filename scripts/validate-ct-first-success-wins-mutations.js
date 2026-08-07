#!/usr/bin/env node
// CT-R2 PR-3 fresh-process semantic mutation runner.
// Expected ordered FAIL sets were frozen in
// docs/CT-R2-PR-3-MUTATION-CONTRACT.md before runtime implementation/execution.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(root, "scripts/validate-ct-first-success-wins.js");
const targets = Object.freeze({
  orchestrator: [path.join(engines, "ct-first-success.js"), "CT_PR3_ORCHESTRATOR_MODULE_URL"],
  cache: [path.join(engines, "ct-provider-cache.js"), "CT_PR3_CACHE_MODULE_URL"],
  ssl: [path.join(engines, "ssl-scan.js"), "CT_PR3_SSL_MODULE_URL"],
  subdomains: [path.join(engines, "subdomains-scan.js"), "CT_PR3_SUBDOMAINS_MODULE_URL"],
  asset: [path.join(engines, "asset-inventory.js"), "CT_PR3_ASSET_MODULE_URL"],
  scanEngine: [path.join(engines, "scan-engine.js"), "CT_PR3_SCAN_ENGINE_MODULE_URL"],
});

const EXPECTED = Object.freeze([
  ["M1", ["M1_ONE_SUCCESS_RETAINS_DEGRADATION"]],
  ["M2", ["M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE"]],
  ["M3", ["M3_SCAN_QUALITY_REMAINS_PARTIAL"]],
  ["M4", ["M4_FIRST_FAILURE_CANNOT_WIN"]],
  ["M5", ["M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL"]],
  ["M6", ["M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT"]],
  ["M7", ["M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY"]],
  ["M8", ["M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL"]],
  ["M9", ["M9_DEGRADATION_WORDING_REMAINS_EXPLICIT"]],
  ["M10", ["M10_SUCCESSFUL_EMPTY_STAYS_MEASURED"]],
  ["M11", ["M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED"]],
]);

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const once = (source, from, to, label) => {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
};
const target = (name, mutate) => ({ name, mutate });
const mutationTargets = Object.freeze({
  M1: [target("subdomains", (source) => once(source,
    '? { incomplete: true, incomplete_reason: "ct_source_degraded" }',
    '? { incomplete_reason: "ct_source_degraded" }', "M1"))],
  M2: [target("asset", (source) => once(source,
    `  if (sources.crt_sh?.error) return false;       // a CT source errored → partial coverage
  if (sources.certspotter?.error) return false;`,
    `  if (sources.crt_sh?.error && sources.certspotter?.error) return false;`, "M2"))],
  M3: [target("scanEngine", (source) => once(source,
    ".filter(([, value]) => value?.incomplete === true)",
    '.filter(([name, value]) => value?.incomplete === true && name !== "subdomains")', "M3"))],
  M4: [target("orchestrator", (source) => once(source,
    '      if (result?.status === "available") {',
    '      if (result?.status === "available" || settledCount === 1) {', "M4"))],
  M5: [target("cache", (source) => once(source,
    '    record.state = "released_budget_exhausted";\n    record.physicalAttemptState = physicalStateOf(record.entry);',
    '    record.state = "released_budget_exhausted";\n    record.entry.controller.abort("consumer_release");\n    record.physicalAttemptState = physicalStateOf(record.entry);', "M5"))],
  M6: [
    target("orchestrator", (source) => once(source,
      "  return Object.freeze({ ...result });",
      "  return result;", "M6 orchestrator")),
    target("cache", (source) => once(source,
      `          record.customerEvidenceDisposition = succeeded
            ? (firstSuccessRelease
              ? "late_success_excluded_after_first_success"
              : "late_success_excluded_after_consumer_release")
            : (firstSuccessRelease
              ? "late_failure_after_first_success"
              : "late_failure_after_consumer_release");`,
      `          record.customerEvidenceDisposition = succeeded
            ? (firstSuccessRelease
              ? "late_success_excluded_after_first_success"
              : "late_success_excluded_after_consumer_release")
            : (firstSuccessRelease
              ? "late_failure_after_first_success"
              : "late_failure_after_consumer_release");
          Object.assign(record.releasedResult, result);`, "M6 cache")),
  ],
  M7: [target("cache", (source) => once(source,
    '    status: "unavailable",\n    data: null,',
    '    status: "available",\n    data: [],', "M7"))],
  M8: [target("ssl", (source) => once(source,
    "  let cert_shared_san_count = null;",
    "  let cert_shared_san_count = 0;", "M8"))],
  M9: [target("cache", (source) => once(source,
    '  "CyberMeters released this module after another Certificate Transparency provider succeeded; this provider result was still in flight and was excluded from the immutable module output.";',
    '  "";', "M9"))],
  M10: [target("orchestrator", (source) => once(source,
    '      if (result?.status === "available") {',
    '      if (result?.status === "available" && result.data.length > 0) {', "M10"))],
  M11: [target("orchestrator", (source) => once(source,
    "    const includedTerminalProviders = PROVIDERS.filter((provider) => terminalResults.has(provider));",
    "    const includedTerminalProviders = winner ? [winner] : PROVIDERS.filter((provider) => terminalResults.has(provider));", "M11"))],
});

let sequence = 0;
let killed = 0;
let controls = 0;
let failures = 0;
const active = new Set();
const fail = (message) => { failures += 1; console.error(`FAIL ${message}`); };
function fingerprint() {
  const child = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: root,
    encoding: "utf8",
  });
  if (child.error || child.signal || child.status !== 0) {
    throw new Error(`cannot fingerprint worktree: ${child.error?.message || child.stderr}`);
  }
  return hash(child.stdout);
}
const initialFingerprint = fingerprint();
function cleanup() {
  for (const file of active) {
    try { fs.rmSync(file, { force: true }); } catch { /* best effort */ }
  }
  active.clear();
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanup();
    console.error(`FAIL mutation suite interrupted by ${signal}`);
    process.exit(2);
  });
}

function failureIds(output) {
  return String(output || "").split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function execute(name, definitions, expected, { control = false, wrongCase = null } = {}) {
  sequence += 1;
  const originals = definitions.map((definition) => {
    const [sourcePath, envName] = targets[definition.name];
    const bytes = fs.readFileSync(sourcePath);
    return { ...definition, sourcePath, envName, bytes, originalHash: hash(bytes) };
  });
  const env = {};
  try {
    for (const [index, definition] of originals.entries()) {
      const extension = path.extname(definition.sourcePath);
      const mutantPath = path.join(path.dirname(definition.sourcePath),
        `.${path.basename(definition.sourcePath, extension)}.ctpr3-mutant.${process.pid}.${sequence}.${index}${extension}`);
      const source = definition.bytes.toString("utf8");
      const mutated = definition.mutate(source);
      if (mutated === source) throw new Error(`${name}: mutation did not change source`);
      fs.writeFileSync(mutantPath, mutated);
      active.add(mutantPath);
      env[definition.envName] = pathToFileURL(mutantPath).href;
    }
    const mutationCase = wrongCase || name;
    const child = spawnSync(process.execPath, [validator, `--mutation-case=${mutationCase}`], {
      cwd: root,
      encoding: "utf8",
      timeout: 60_000,
      env: { ...process.env, ...env },
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actual = failureIds(output);
    const failureLines = String(child.stdout || "").split(/\r?\n/)
      .filter((line) => line.startsWith("FAIL "));
    const summary = String(child.stdout || "").match(/CT-R2 PR-3 first-success: (\d+)\/(\d+) assertions passed/);
    const normalSemanticKill = child.error == null && child.signal == null
      && child.status === 1 && summary != null && Number(summary[2]) === 1
      && JSON.stringify(actual) === JSON.stringify(expected)
      && failureLines.every((line) => line.endsWith(" — predicate returned false"));
    if (!control && normalSemanticKill) {
      killed += 1;
      console.log(`PASS ${name} exact FAIL set ${JSON.stringify(actual)}`);
    } else if (control && !normalSemanticKill) {
      controls += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(`${name}: ${control ? "invalid kill accepted" : "wrong semantic failure"}`
        + `\nexpected=${JSON.stringify(expected)}\nactual=${JSON.stringify(actual)}`
        + `\nstatus=${child.status} signal=${child.signal} error=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`);
    }
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
  } finally {
    cleanup();
    for (const original of originals) {
      if (hash(fs.readFileSync(original.sourcePath)) !== original.originalHash) {
        fail(`${name}: target bytes changed: ${path.relative(root, original.sourcePath)}`);
      }
    }
    if (fingerprint() !== initialFingerprint) fail(`${name}: worktree fingerprint changed`);
  }
}

for (const [name, expected] of EXPECTED) {
  execute(name, mutationTargets[name], expected);
}

execute("SYNTAX_FAILURE_REJECTED", [target("orchestrator", (source) => `${source}\nnot valid JavaScript !\n`)],
  ["M4_FIRST_FAILURE_CANNOT_WIN"], { control: true, wrongCase: "M4" });
execute("LOAD_FAILURE_REJECTED", [target("ssl", (source) => once(source,
  'from "./ct-first-success.js";', 'from "./missing-ct-first-success.js";', "load control"))],
  ["M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL"], { control: true, wrongCase: "M8" });
execute("WRONG_REASON_REJECTED", [target("orchestrator", mutationTargets.M4[0].mutate)],
  ["M10_SUCCESSFUL_EMPTY_STAYS_MEASURED"], { control: true, wrongCase: "M4" });

console.log(`CT-R2 PR-3 mutations: ${killed}/${EXPECTED.length} killed; ${controls}/3 controls passed`);
if (failures > 0 || killed !== EXPECTED.length || controls !== 3) process.exit(1);
console.log("CT-R2 PR-3 mutation validation passed");
