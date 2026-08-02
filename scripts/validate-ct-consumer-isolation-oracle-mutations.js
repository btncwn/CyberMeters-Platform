#!/usr/bin/env node
// CT-R2 PR-2A.1 immutable fresh-process mutation map.
//
// Every semantic mutant and its exact contract-ID failure set is predeclared in
// this oracle-only file. Multi-file mutants model the complete forbidden path
// where both the cache and publisher admit a late result. Target bytes and the
// complete worktree fingerprint must be unchanged after every run/interruption.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(root, "scripts/validate-ct-consumer-isolation-oracle.js");
const cachePath = path.join(engines, "ct-provider-cache.js");
const overlapPath = path.join(engines, "ct-provider-overlap.js");
const budgetPath = path.join(engines, "scan-budget.js");
const reservedPath = path.join(engines, "reserved-scan.js");
const analyzerPath = path.join(root, "scripts/analyze-ct-provider-telemetry.js");
const EXPECTED_CONTRACTS = 22;
const EXPECTED_MUTANTS = 17;
const EXPECTED_CONTROLS = 2;

let sequence = 0;
let killed = 0;
let controlsPassed = 0;
let failures = 0;
const activeMutantPaths = new Set();

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => {
  failures += 1;
  console.error(`FAIL ${message}`);
};
function gitStatusFingerprint() {
  const child = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: root,
    encoding: "utf8",
  });
  if (child.error || child.signal || child.status !== 0) {
    throw new Error(`cannot fingerprint worktree: ${child.error?.message || child.stderr}`);
  }
  return hash(child.stdout);
}
const initialWorktreeFingerprint = gitStatusFingerprint();
function cleanup() {
  for (const mutantPath of activeMutantPaths) {
    try { fs.rmSync(mutantPath, { force: true }); } catch { /* best effort */ }
  }
  activeMutantPaths.clear();
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanup();
    console.error(`FAIL oracle mutation suite interrupted by ${signal}`);
    process.exit(2);
  });
}
function replaceExactlyOnce(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}
function contractFailures(output) {
  return String(output || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5));
}
function runCase({ name, targets, expectedFailures, expectHarnessRejection = false }) {
  sequence += 1;
  const originals = targets.map((target) => {
    const bytes = fs.readFileSync(target.sourcePath);
    return { ...target, bytes, originalHash: hash(bytes) };
  });
  const mutantEnv = {};
  try {
    for (const [index, target] of originals.entries()) {
      const extension = path.extname(target.sourcePath) || ".js";
      const base = path.basename(target.sourcePath, extension);
      const mutantPath = path.join(
        path.dirname(target.sourcePath),
        `.${base}.ct-immutable-oracle-mutant.${process.pid}.${sequence}.${index}${extension}`,
      );
      fs.writeFileSync(mutantPath, target.mutate(target.bytes.toString("utf8")));
      activeMutantPaths.add(mutantPath);
      mutantEnv[target.envName] = pathToFileURL(mutantPath).href;
    }
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      timeout: 20_000,
      env: { ...process.env, ...mutantEnv },
    });
    const combined = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = contractFailures(combined);
    const summary = String(child.stdout || "").match(
      /CT isolation oracle: (\d+)\/(\d+) contracts passed/,
    );
    const exactSet = JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalAssertionExit = child.error == null
      && child.signal == null
      && child.status === 1
      && summary != null
      && Number(summary[2]) === EXPECTED_CONTRACTS
      && Number(summary[1]) + expectedFailures.length === EXPECTED_CONTRACTS;
    if (!expectHarnessRejection && normalAssertionExit && exactSet) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else if (expectHarnessRejection && !(normalAssertionExit && exactSet)) {
      controlsPassed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: ${expectHarnessRejection ? "invalid failure accepted" : "wrong semantic failure"}`
        + `\nexpected=${JSON.stringify(expectedFailures)}`
        + `\nactual=${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} error=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
  } finally {
    cleanup();
    for (const target of originals) {
      if (hash(fs.readFileSync(target.sourcePath)) !== target.originalHash) {
        fail(`${name}: target bytes changed: ${path.relative(root, target.sourcePath)}`);
      }
    }
    if (gitStatusFingerprint() !== initialWorktreeFingerprint) {
      fail(`${name}: worktree fingerprint changed`);
    }
  }
}
const target = (sourcePath, envName, mutate) => ({ sourcePath, envName, mutate });

const physicalPoisonFailures = [
  "SSL_RELEASE_IS_CONSUMER_ONLY",
  "SIBLING_LATE_SUCCESS_RECEIVED",
  "CT_R1_LATE_SUCCESS_IS_OK",
  "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
];

runCase({
  name: "restore first-consumer signal capture",
  expectedFailures: physicalPoisonFailures,
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `      const entry = physicalEntry(normalizedDomain, provider, config);
      if (!module) return entry.promise;`,
    `      const entry = physicalEntry(normalizedDomain, provider, config);
      if (consumerSignal && !entry.firstConsumerSignalCaptured) {
        entry.firstConsumerSignalCaptured = true;
        consumerSignal.addEventListener("abort", () => entry.controller.abort("first_consumer_release"), { once: true });
      }
      if (!module) return entry.promise;`,
    "first-consumer signal boundary",
  ))],
});

runCase({
  name: "allow SSL release to abort shared physical work",
  expectedFailures: physicalPoisonFailures,
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    record.state = "released_budget_exhausted";
    record.physicalAttemptState = physicalStateOf(record.entry);`,
    `    record.state = "released_budget_exhausted";
    record.entry?.controller?.abort("consumer_release");
    record.physicalAttemptState = physicalStateOf(record.entry);`,
    "SSL physical abort",
  ))],
});

runCase({
  name: "report consumer release as provider failure",
  expectedFailures: [
    "RELEASED_CONSUMER_REJECTS_LATE_RESULT",
    "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
  ],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    record.state = "released_budget_exhausted";
    record.physicalAttemptState = physicalStateOf(record.entry);
    record.resultCount = null;
    record.error = null;`,
    `    record.state = "received_failure";
    record.physicalAttemptState = "terminal_failure";
    record.resultCount = null;
    record.error = "module deadline exceeded";`,
    "consumer release classification",
  ))],
});

runCase({
  name: "accept late result into released consumer state",
  expectedFailures: [
    "RELEASED_CONSUMER_REJECTS_LATE_RESULT",
    "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
  ],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `        if (record.state !== "waiting") return;
        const succeeded = result?.status === "available";`,
    `        if (!["waiting", "released_budget_exhausted"].includes(record.state)) return;
        const succeeded = result?.status === "available";`,
    "released consumer settlement guard",
  ))],
});

runCase({
  name: "allow late result to replace released SSL output",
  expectedFailures: [
    "RELEASED_CONSUMER_REJECTS_LATE_RESULT",
    "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
    "RELEASED_OUTPUT_IMMUTABLE",
  ],
  targets: [
    target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
      source,
      `        if (record.state !== "waiting") return;
        const succeeded = result?.status === "available";`,
      `        if (!["waiting", "released_budget_exhausted"].includes(record.state)) return;
        const succeeded = result?.status === "available";`,
      "late cache settlement",
    )),
    target(reservedPath, "CT_ORACLE_RESERVED_MODULE_URL", (source) => replaceExactlyOnce(
      source,
      `  if (winner.error) throw winner.error;
  return winner.value;`,
      `  if (winner.error) throw winner.error;
  if (winner.boundary && module === "ssl" && !signal?.aborted) {
    const late = await work;
    if (late.error) throw late.error;
    return late.value;
  }
  return winner.value;`,
      "late output publication",
    )),
  ],
});

runCase({
  name: "classify abort-before-release as in-flight",
  expectedFailures: ["ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT"],
  targets: [target(overlapPath, "CT_ORACLE_OVERLAP_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `          started && globalDeadlineBeforeRelease
            ? "terminal_platform_deadline_abort"`,
    `          false && started && globalDeadlineBeforeRelease
            ? "terminal_platform_deadline_abort"`,
    "abort-before-release precedence",
  ))],
});

runCase({
  name: "erase structured global deadline owner",
  expectedFailures: ["STRUCTURED_GLOBAL_DEADLINE_PROVENANCE"],
  targets: [target(budgetPath, "CT_ORACLE_BUDGET_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `      aborted: true,
      owner: "scan_global_deadline",`,
    `      aborted: true,
      owner: "unknown",`,
    "structured deadline owner",
  ))],
});

runCase({
  name: "allow late observe to mutate frozen overlap",
  expectedFailures: ["FROZEN_OVERLAP_REJECTS_LATE_OBSERVE"],
  targets: [target(overlapPath, "CT_ORACLE_OVERLAP_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    observe(provider, settled, domain) {
      if (consumerReleased || !PROVIDERS.includes(provider)) return;`,
    `    observe(provider, settled, domain) {
      if (!PROVIDERS.includes(provider)) return;`,
    "late observe guard",
  ))],
});

runCase({
  name: "duplicate physical provider request",
  expectedFailures: [
    "SHARED_PHYSICAL_REQUEST_ONE",
    "CT_R1_LATE_SUCCESS_IS_OK",
  ],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    if (entries.has(key)) return entries.get(key);`,
    `    if (false && entries.has(key)) return entries.get(key);`,
    "physical request cache",
  ))],
});

runCase({
  name: "lose global deadline cancellation",
  expectedFailures: [
    "GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK",
    "CT_R1_GLOBAL_DEADLINE_CAUSE",
  ],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    else signal?.addEventListener?.("abort", abortFromGlobalDeadline, { once: true });`,
    `    else void signal;`,
    "global cancellation listener",
  ))],
});

runCase({
  name: "consumer release overwrites physical state",
  expectedFailures: [
    "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
  ],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    record.physicalAttemptState = physicalStateOf(record.entry);`,
    `    record.entry.state = "terminal_failure";
    record.physicalAttemptState = "terminal_failure";`,
    "consumer/physical separation",
  ))],
});

runCase({
  name: "confuse consumer wait with physical outcome",
  expectedFailures: ["CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL"],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `        record.state = succeeded ? "received_success" : "received_failure";`,
    `        record.state = result?.physical_attempt_state ? "received_success" : "received_failure";`,
    "consumer wait outcome",
  ))],
});

runCase({
  name: "collapse successful-empty into unavailable",
  expectedFailures: ["SUCCESSFUL_EMPTY_IS_ZERO"],
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `        status: "available",
        data,
        error: null,`,
    `        status: data.length > 0 ? "available" : "unavailable",
        data,
        error: data.length > 0 ? null : "empty response treated as unavailable",`,
    "successful empty",
  ))],
});

runCase({
  name: "restore acceptance-only source-set v1",
  expectedFailures: ["SOURCE_SET_VERSION_IS_V2"],
  targets: [target(overlapPath, "CT_ORACLE_OVERLAP_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = "ct-provider-overlap/2";`,
    `export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = "ct-provider-overlap/1";`,
    "source-set version",
  ))],
});

runCase({
  name: "admit PA plus in-flight as a canonical pair",
  expectedFailures: ["PA_IF_UNREACHABLE_ON_SHARED_SIGNAL"],
  targets: [target(overlapPath, "CT_ORACLE_OVERLAP_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `  "terminal_platform_deadline_abort|terminal_platform_deadline_abort": "censored_platform_deadline_abort",`,
    `  "in_flight_at_consumer_release|terminal_platform_deadline_abort": "censored_platform_deadline_abort",
  "terminal_platform_deadline_abort|terminal_platform_deadline_abort": "censored_platform_deadline_abort",`,
    "PA plus in-flight canonical pair",
  ))],
});

runCase({
  name: "omit reserved consumer release boundary",
  expectedFailures: [
    "RELEASED_OUTPUT_IMMUTABLE",
    "RESERVED_PATH_USES_ISOLATED_BOUNDARY",
  ],
  targets: [target(reservedPath, "CT_ORACLE_RESERVED_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `    ctCache.releaseConsumer?.(domain, module, cause);`,
    `    void ctCache;`,
    "reserved consumer release boundary",
  ))],
});

runCase({
  name: "filter platform attempts by completeness impact before counting",
  expectedFailures: ["ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION"],
  targets: [target(analyzerPath, "CT_ORACLE_ANALYZER_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `  const attemptRows = rows.filter((row) => row.provider && row.outcome);`,
    `  const attemptRows = rows.filter((row) =>
    row.provider && row.outcome && Number(row.completeness_impact) === 1
  );`,
    "attempt population ordering",
  ))],
});

runCase({
  name: "harness rejects syntax/import failure",
  expectedFailures: ["SHARED_PHYSICAL_REQUEST_ONE"],
  expectHarnessRejection: true,
  targets: [target(cachePath, "CT_ORACLE_CACHE_MODULE_URL", (source) =>
    `${source}\nthis is not valid JavaScript {{{\n`)],
});
runCase({
  name: "harness rejects wrong contract-ID set",
  expectedFailures: ["WRONG_REASON_MUST_NOT_PASS"],
  expectHarnessRejection: true,
  targets: [target(overlapPath, "CT_ORACLE_OVERLAP_MODULE_URL", (source) => replaceExactlyOnce(
    source,
    `export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = "ct-provider-overlap/2";`,
    `export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = "ct-provider-overlap/1";`,
    "wrong-set control",
  ))],
});

cleanup();
if (sequence !== EXPECTED_MUTANTS + EXPECTED_CONTROLS) {
  fail(`defined ${sequence} cases, expected ${EXPECTED_MUTANTS + EXPECTED_CONTROLS}`);
}
if (killed !== EXPECTED_MUTANTS) fail(`killed ${killed}/${EXPECTED_MUTANTS} mutants`);
if (controlsPassed !== EXPECTED_CONTROLS) fail(`passed ${controlsPassed}/${EXPECTED_CONTROLS} controls`);
if (gitStatusFingerprint() !== initialWorktreeFingerprint) {
  fail("suite exit worktree fingerprint changed");
}
console.log(
  `CT immutable isolation oracle mutations: ${killed}/${EXPECTED_MUTANTS} mutants killed; `
  + `${controlsPassed}/${EXPECTED_CONTROLS} controls passed`,
);
process.exit(failures === 0 ? 0 : 1);
