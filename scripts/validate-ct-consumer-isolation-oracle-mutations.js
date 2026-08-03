#!/usr/bin/env node
// CT-R2 PR-2A.1 fresh-process semantic mutation runner.
//
// The exact ordered FAIL set for every semantic mutant comes only from the
// pre-execution classification record. All target bytes and the complete
// worktree fingerprint must be restored after each run and on interruption.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  CT_ISOLATION_ASSERTIONS,
  CT_ISOLATION_HARNESS_CONTROLS,
  CT_ISOLATION_SEMANTIC_MUTANTS,
} from "./ct-consumer-isolation-old-runtime-classification.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(root, "scripts/validate-ct-consumer-isolation-oracle.js");
const paths = Object.freeze({
  cache: path.join(engines, "ct-provider-cache.js"),
  overlap: path.join(engines, "ct-provider-overlap.js"),
  budget: path.join(engines, "scan-budget.js"),
  reserved: path.join(engines, "reserved-scan.js"),
  ssl: path.join(engines, "ssl-scan.js"),
  subdomains: path.join(engines, "subdomains-scan.js"),
  analyzer: path.join(root, "scripts/analyze-ct-provider-telemetry.js"),
  inventory: path.join(root, "scripts/derive-ct-provider-source-consumer-inventory.js"),
});
const envNames = Object.freeze({
  cache: "CT_ORACLE_CACHE_MODULE_URL",
  overlap: "CT_ORACLE_OVERLAP_MODULE_URL",
  budget: "CT_ORACLE_BUDGET_MODULE_URL",
  reserved: "CT_ORACLE_RESERVED_MODULE_URL",
  ssl: "CT_ORACLE_SSL_MODULE_URL",
  subdomains: "CT_ORACLE_SUBDOMAINS_MODULE_URL",
  analyzer: "CT_ORACLE_ANALYZER_MODULE_URL",
  inventory: "CT_ORACLE_INVENTORY_MODULE_URL",
});
const mutantById = new Map(CT_ISOLATION_SEMANTIC_MUTANTS.map((entry) => [
  entry.mutant_id, entry,
]));
if (mutantById.size !== CT_ISOLATION_SEMANTIC_MUTANTS.length) {
  throw new Error("Duplicate semantic mutant ID");
}

let sequence = 0;
let killed = 0;
let controlsPassed = 0;
let failures = 0;
const registered = new Set();
const activeMutantPaths = new Set();
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => { failures += 1; console.error(`FAIL ${message}`); };
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
function replaceExactly(source, from, to, expectedCount, label) {
  const count = source.split(from).length - 1;
  if (count !== expectedCount) {
    throw new Error(`${label}: anchor count ${count}, expected ${expectedCount}`);
  }
  return source.split(from).join(to);
}
const once = (source, from, to, label) => replaceExactly(source, from, to, 1, label);
const target = (key, mutate) => ({ sourcePath: paths[key], envName: envNames[key], mutate });
function contractFailures(output) {
  return String(output || "").split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5));
}

function runCase({ name, targets, expectedFailures, expectHarnessRejection = false }) {
  sequence += 1;
  const originals = targets.map((entry) => {
    const bytes = fs.readFileSync(entry.sourcePath);
    return { ...entry, bytes, originalHash: hash(bytes) };
  });
  const mutantEnv = {};
  try {
    for (const [index, entry] of originals.entries()) {
      const extension = path.extname(entry.sourcePath) || ".js";
      const base = path.basename(entry.sourcePath, extension);
      const mutantPath = path.join(
        path.dirname(entry.sourcePath),
        `.${base}.ct2a1-mutant.${process.pid}.${sequence}.${index}${extension}`,
      );
      fs.writeFileSync(mutantPath, entry.mutate(entry.bytes.toString("utf8")));
      activeMutantPaths.add(mutantPath);
      mutantEnv[entry.envName] = pathToFileURL(mutantPath).href;
    }
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      timeout: 60_000,
      env: { ...process.env, ...mutantEnv },
    });
    const actualFailures = contractFailures(`${child.stdout || ""}\n${child.stderr || ""}`);
    const summary = String(child.stdout || "").match(/CT isolation oracle: (\d+)\/(\d+) contracts passed/);
    const exactSet = JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalAssertionExit = child.error == null && child.signal == null
      && child.status === 1 && summary != null
      && Number(summary[2]) === CT_ISOLATION_ASSERTIONS.length
      && Number(summary[1]) + expectedFailures.length === CT_ISOLATION_ASSERTIONS.length;
    if (!expectHarnessRejection && normalAssertionExit && exactSet) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else if (expectHarnessRejection && !(normalAssertionExit && exactSet)) {
      controlsPassed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(`${name}: ${expectHarnessRejection ? "invalid failure accepted" : "wrong semantic failure"}`
        + `\nexpected=${JSON.stringify(expectedFailures)}`
        + `\nactual=${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} error=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`);
    }
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
  } finally {
    cleanup();
    for (const entry of originals) {
      if (hash(fs.readFileSync(entry.sourcePath)) !== entry.originalHash) {
        fail(`${name}: target bytes changed: ${path.relative(root, entry.sourcePath)}`);
      }
    }
    if (gitStatusFingerprint() !== initialWorktreeFingerprint) {
      fail(`${name}: worktree fingerprint changed`);
    }
  }
}

function semantic(mutantId, targets) {
  const declaration = mutantById.get(mutantId);
  if (!declaration) throw new Error(`Unregistered semantic mutant ${mutantId}`);
  if (registered.has(mutantId)) throw new Error(`Duplicate mutation case ${mutantId}`);
  registered.add(mutantId);
  runCase({
    name: mutantId,
    targets,
    expectedFailures: [...declaration.expected_failure_ids],
  });
}

semantic("DUPLICATE_PHYSICAL_REQUEST", [target("cache", (source) => once(
  source,
  "    if (entries.has(key)) return entries.get(key);",
  "    if (false && entries.has(key)) return entries.get(key);",
  "physical request cache",
))]);
semantic("RESTORE_FIRST_CONSUMER_SIGNAL_CAPTURE", [target("cache", (source) => once(
  source,
  "      const entry = physicalEntry(normalizedDomain, provider, config);\n      if (!module) return entry.promise;",
  `      const entry = physicalEntry(normalizedDomain, provider, config);
      if (consumerSignal && !entry.firstConsumerSignalCaptured) {
        entry.firstConsumerSignalCaptured = true;
        consumerSignal.addEventListener("abort", () => entry.controller.abort("first_consumer_release"), { once: true });
      }
      if (!module) return entry.promise;`,
  "first-consumer capture",
))]);
semantic("ACCEPT_LATE_RESULT_FOR_RELEASED_CONSUMER", [target("cache", (source) => once(
  source,
  "        if (record.state !== \"waiting\") return;\n        const succeeded = result?.status === \"available\";",
  "        if (![\"waiting\", \"released_budget_exhausted\"].includes(record.state)) return;\n        const succeeded = result?.status === \"available\";",
  "released-consumer settlement guard",
))]);
semantic("ALLOW_LATE_RESERVED_PUBLICATION", [
  target("cache", (source) => once(
    source,
    "        if (record.state !== \"waiting\") return;\n        const succeeded = result?.status === \"available\";",
    "        if (![\"waiting\", \"released_budget_exhausted\"].includes(record.state)) return;\n        const succeeded = result?.status === \"available\";",
    "late cache settlement",
  )),
  target("reserved", (source) => once(
    source,
    "  if (winner.error) throw winner.error;\n  return winner.value;",
    "  if (winner.error) throw winner.error;\n  if (winner.boundary) return (await work).value;\n  return winner.value;",
    "reserved publication latch",
  )),
]);
semantic("COLLAPSE_SUCCESSFUL_EMPTY", [target("cache", (source) => once(
  source,
  "        status: \"available\",\n        data,\n        error: null,",
  "        status: data.length > 0 ? \"available\" : \"unavailable\",\n        data: data.length > 0 ? data : null,\n        error: data.length > 0 ? null : \"empty unavailable\",",
  "successful empty",
))]);
semantic("ERASE_GENUINE_PROVIDER_FAILURE", [target("cache", (source) => once(
  source,
  "      result: unavailable(provider, domain, `HTTP ${response?.status ?? \"unknown\"}`),",
  "      result: withPhysicalAttemptState({ provider, domain, status: \"available\", data: [], error: null }, \"terminal_success\"),",
  "genuine HTTP failure",
))]);
semantic("ERASE_STRUCTURED_DEADLINE_OWNER", [target("budget", (source) => once(
  source,
  "      aborted: true,\n      owner: \"scan_global_deadline\",",
  "      aborted: true,\n      owner: \"unknown\",",
  "structured deadline owner",
))]);
semantic("LOSE_GLOBAL_DEADLINE_CANCELLATION", [target("cache", (source) => once(
  source,
  "    else signal?.addEventListener?.(\"abort\", abortFromGlobalDeadline, { once: true });",
  "    else void signal;",
  "global cancellation listener",
))]);
semantic("CONFUSE_CONSUMER_AND_PHYSICAL_STATE", [target("cache", (source) => {
  let mutated = once(
    source,
    "    record.physicalAttemptState = physicalStateOf(record.entry);",
    "    record.physicalAttemptState = record.state;",
    "released consumer physical state",
  );
  mutated = once(
    mutated,
    "        record.physicalAttemptState = result?.physical_attempt_state\n          || (succeeded ? \"terminal_success\" : \"terminal_failure\");",
    "        record.physicalAttemptState = record.state;",
    "settled consumer physical state",
  );
  return mutated;
})]);
semantic("COLLAPSE_STATE_MACHINE_TYPES", [target("cache", (source) => once(
  source,
  "export const CT_PROVIDER_CONSUMER_WAIT_STATES = Object.freeze([",
  "export const CT_PROVIDER_CONSUMER_WAIT_STATES = Object.freeze([\n  \"terminal_success\",",
  "consumer vocabulary separation",
))]);
semantic("ABORT_BEFORE_RELEASE_AS_IN_FLIGHT", [target("overlap", (source) => once(
  source,
  "          started && globalDeadlineBeforeRelease\n            ? \"terminal_platform_deadline_abort\"",
  "          false && started && globalDeadlineBeforeRelease\n            ? \"terminal_platform_deadline_abort\"",
  "abort-before-release ordering",
))]);
semantic("RELEASE_BEFORE_ABORT_AS_PLATFORM_ABORT", [target("overlap", (source) => once(
  source,
  "      const globalDeadlineBeforeRelease = global_deadline?.aborted === true",
  "      const globalDeadlineBeforeRelease = true || global_deadline?.aborted === true",
  "release-before-abort ordering",
))]);
semantic("ALLOW_LATE_OVERLAP_OBSERVE", [target("overlap", (source) => once(
  source,
  "    observe(provider, settled, domain) {\n      if (consumerReleased || !PROVIDERS.includes(provider)) return;",
  "    observe(provider, settled, domain) {\n      if (!PROVIDERS.includes(provider)) return;",
  "late overlap observe",
))]);
semantic("ADMIT_PA_IF_SHARED_SIGNAL", [target("overlap", (source) => once(
  source,
  "  \"terminal_platform_deadline_abort|terminal_platform_deadline_abort\": \"censored_platform_deadline_abort\",",
  "  \"in_flight_at_consumer_release|terminal_platform_deadline_abort\": \"censored_platform_deadline_abort\",\n  \"terminal_platform_deadline_abort|terminal_platform_deadline_abort\": \"censored_platform_deadline_abort\",",
  "PA plus IF pair",
))]);
semantic("COLLAPSE_PERSISTENCE_OUTCOME", [target("overlap", (source) => once(
  source,
  "  if (!measurement) return {\n    status: \"not_attempted_empty\",\n    persistence_outcome: \"not_attempted_empty\",\n  };",
  "  if (!measurement) return { status: \"persistence_failed\", persistence_outcome: \"persistence_failed\" };",
  "empty persistence outcome",
))]);
semantic("TYPO_PLATFORM_ABORT_WORDING", [target("cache", (source) => once(
  source,
  "CyberMeters did not observe the provider result within the scan's global execution window.",
  "CyberMeters did not observe the provider result within the scan global execution window.",
  "exact customer wording",
))]);
semantic("PLATFORM_ABORT_AS_PROVIDER_UNAVAILABLE", [target("cache", (source) => once(
  source,
  "CyberMeters did not observe the provider result within the scan's global execution window.",
  "The provider was unavailable.",
  "provider-unavailable wording",
))]);
semantic("LEAK_LIFECYCLE_INTO_SOURCE_OBJECT", [target("ssl", (source) => once(
  source,
  "    error: result?.status === \"unavailable\" ? result.error : null,",
  `    error: result?.status === "unavailable" ? result.error : null,
    ...(result?.status === "unavailable" || result?.data?.length > 0
      ? { physical_attempt_state: result?.physical_attempt_state || null }
      : {}),`,
  "customer source shape",
))]);
semantic("DRIFT_SSL_PLATFORM_WORDING", [target("ssl", (source) => once(
  source,
  "    error: result?.status === \"unavailable\" ? result.error : null,",
  "    error: result?.status === \"unavailable\" && result.error?.includes(\"global execution window\") ? \"SSL deadline\" : (result?.status === \"unavailable\" ? result.error : null),",
  "SSL-only wording",
))]);
semantic("DRIFT_RESERVED_PLATFORM_WORDING", [target("reserved", (source) => once(
  source,
  "CyberMeters did not observe the provider result within the scan's global execution window.",
  "Reserved scan deadline exceeded.",
  "reserved wording",
))]);
semantic("IGNORE_SENTINEL_ERROR_PRECEDENCE", [target("inventory", (source) => once(
  source,
  "    unsafe_count_decision_detected: unsafe.unsafe_decision_consumers.length > 0,",
  "    unsafe_count_decision_detected: false,",
  "sentinel detector calibration",
))]);
semantic("RESTORE_SOURCE_SET_V1", [target("overlap", (source) => once(
  source,
  "export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = \"ct-provider-overlap/2\";",
  "export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = \"ct-provider-overlap/1\";",
  "source-set version",
))]);
semantic("ALLOW_V1_DECISION_ROWS", [target("analyzer", (source) => once(
  source,
  "row.source_set_version === \"ct-provider-overlap/2\"",
  "[\"ct-provider-overlap/1\", \"ct-provider-overlap/2\"].includes(row.source_set_version)",
  "v1 decision quarantine",
))]);
semantic("PIN_INVENTORY_BEFORE_RUNTIME", [target("inventory", (source) => once(
  source,
  "  final_runtime_count: null,",
  "  final_runtime_count: 1,",
  "premature inventory pin",
))]);
semantic("OMIT_PLATFORM_ABORT_VOCABULARY", [
  target("cache", (source) => once(
    source,
    "  \"platform_deadline_abort\",",
    "  \"network_error\", // platform value omitted",
    "CT-R1 platform vocabulary",
  )),
  target("overlap", (source) => once(
    source,
    "  \"terminal_platform_deadline_abort\",",
    "  \"terminal_failure\", // platform value omitted",
    "overlap platform vocabulary",
  )),
]);
semantic("FILTER_ATTEMPTS_BY_IMPACT_FIRST", [target("analyzer", (source) => once(
  source,
  "  const attemptRows = rows.filter((row) => row.provider && row.outcome);",
  "  const attemptRows = rows.filter((row) => row.provider && row.outcome && Number(row.completeness_impact) === 1);",
  "attempt population ordering",
))]);
semantic("OMIT_RESERVED_CONSUMER_BOUNDARY", [target("reserved", (source) => once(
  source,
  "    ctCache.releaseConsumer?.(domain, module, cause);",
  "    void ctCache;",
  "reserved consumer release boundary",
))]);
semantic("SPLIT_CT_R1_OVERLAP_PROVENANCE", [target("cache", (source) => {
  let mutated = once(
    source,
    "      const provenance = readGlobalDeadlineProvenance();",
    "      const provenance = null;",
    "shared CT-R1/overlap provenance read",
  );
  mutated = once(
    mutated,
    "      controller.abort(provenance || signal?.reason || \"scan_deadline_exhausted\");",
    "      controller.abort(\"scan_deadline_exhausted\");",
    "shared CT-R1/overlap abort reason",
  );
  return mutated;
})]);
semantic("REPORT_CONSUMER_RELEASE_AS_PROVIDER_FAILURE", [target("cache", (source) => once(
  source,
  "    record.state = \"released_budget_exhausted\";\n    record.physicalAttemptState = physicalStateOf(record.entry);",
  "    record.state = \"received_failure\";\n    record.physicalAttemptState = \"terminal_failure\";",
  "consumer release classification",
))]);

if (registered.size !== mutantById.size
  || [...mutantById.keys()].some((mutantId) => !registered.has(mutantId))) {
  fail(`semantic mutant registration mismatch: ${registered.size}/${mutantById.size}`);
}

runCase({
  name: CT_ISOLATION_HARNESS_CONTROLS[0],
  expectedFailures: ["SHARED_PHYSICAL_REQUEST_ONE"],
  expectHarnessRejection: true,
  targets: [target("cache", (source) => `${source}\nthis is not valid JavaScript {{{\n`)],
});
runCase({
  name: CT_ISOLATION_HARNESS_CONTROLS[1],
  expectedFailures: ["WRONG_REASON_MUST_NOT_PASS"],
  expectHarnessRejection: true,
  targets: [target("overlap", (source) => once(
    source,
    "export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = \"ct-provider-overlap/2\";",
    "export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = \"ct-provider-overlap/1\";",
    "wrong-reason control",
  ))],
});

cleanup();
if (sequence !== CT_ISOLATION_SEMANTIC_MUTANTS.length + CT_ISOLATION_HARNESS_CONTROLS.length) {
  fail(`defined ${sequence} cases, expected ${CT_ISOLATION_SEMANTIC_MUTANTS.length + CT_ISOLATION_HARNESS_CONTROLS.length}`);
}
if (killed !== CT_ISOLATION_SEMANTIC_MUTANTS.length) {
  fail(`killed ${killed}/${CT_ISOLATION_SEMANTIC_MUTANTS.length} mutants`);
}
if (controlsPassed !== CT_ISOLATION_HARNESS_CONTROLS.length) {
  fail(`passed ${controlsPassed}/${CT_ISOLATION_HARNESS_CONTROLS.length} controls`);
}
if (gitStatusFingerprint() !== initialWorktreeFingerprint) {
  fail("suite exit worktree fingerprint changed");
}
console.log(
  `CT2A1 immutable oracle mutations: ${killed}/${CT_ISOLATION_SEMANTIC_MUTANTS.length} mutants killed; `
  + `${controlsPassed}/${CT_ISOLATION_HARNESS_CONTROLS.length} controls passed`,
);
process.exit(failures === 0 ? 0 : 1);
