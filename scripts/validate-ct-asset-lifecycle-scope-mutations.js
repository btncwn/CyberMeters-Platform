#!/usr/bin/env node
// PR-2B-1 pinned fresh-process mutation proof.
//
// A semantic kill counts only when the fixture reaches its normal 41-contract
// summary, exits 1, and returns the exact ordered predeclared FAIL set. Syntax,
// import and wrong-reason failures are rejected controls. Target bytes and the
// complete worktree fingerprint must remain unchanged.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const lifecycleSourcePath = path.join(
  root, "workers/scan-api/src/engines/attack-surface-lifecycle.js",
);
const shadowSourcePath = path.join(
  root, "workers/scan-api/src/engines/shadow-it-inventory.js",
);
const validator = path.join(root, "scripts/validate-ct-asset-lifecycle-scope.js");
const ASSERTION_TOTAL = 41;
const returnBlock = `  return {
    dns_resolution: { state, reason },
    http_https_service: { state, reason },
  };`;
const semanticMutants = Object.freeze([
  {
    id: "REMOVE_CT_SCOPE_GATE",
    from: "      const scopeSignals = ctDiscoveryScopeSignals(asset, subdomainDiscovery);",
    to: "      const scopeSignals = null;",
    expectedFailures: [
      "DEGRADED_EXPLICIT_INCOMPLETE",
      "DEGRADED_QUALIFYING_CLOCK_PRESERVED",
      "DEGRADED_ROWS_NEVER_QUALIFY",
      "DEGRADED_NO_RESET_OF_REMOVED_STATE",
      "DEGRADED_NO_REOPEN_EVENT",
      "DEADLINE_EXPLICIT_NOT_ASSESSED",
      "DEADLINE_NO_ABSENCE_STATE",
      "SEQUENCE_THIRD_ASSESSABLE_CONFIRMS",
    ],
  },
  {
    id: "ADVANCE_CLOCK_DURING_DEGRADED_SCOPE",
    from: returnBlock,
    to: `  return {
    dns_resolution: { state: "absent", reason },
    http_https_service: { state: "not_observed", reason },
  };`,
    expectedFailures: [
      "DEGRADED_EXPLICIT_INCOMPLETE",
      "DEGRADED_QUALIFYING_CLOCK_PRESERVED",
      "DEGRADED_ROWS_NEVER_QUALIFY",
      "DEADLINE_EXPLICIT_NOT_ASSESSED",
      "DEADLINE_NO_ABSENCE_STATE",
      "SEQUENCE_DEGRADED_DOES_NOT_RESET_CLOCK",
      "SEQUENCE_NEXT_HEALTHY_RESUMES_AT_TWO",
      "SEQUENCE_NOT_PREMATURELY_REMOVED",
      "SEQUENCE_DEGRADED_ROW_NEVER_QUALIFIES",
    ],
  },
  {
    id: "RESET_CLOCK_DURING_DEGRADED_SCOPE",
    from: returnBlock,
    to: `  return {
    dns_resolution: { state: "observed", reason },
    http_https_service: { state: "observed", reason },
  };`,
    expectedFailures: [
      "DEGRADED_EXPLICIT_INCOMPLETE",
      "DEGRADED_NO_ABSENCE_PROGRESS",
      "DEGRADED_NO_RESET_OF_REMOVED_STATE",
      "DEGRADED_NO_REOPEN_EVENT",
      "DEADLINE_EXPLICIT_NOT_ASSESSED",
      "DEADLINE_NO_ABSENCE_STATE",
      "SEQUENCE_THIRD_ASSESSABLE_CONFIRMS",
    ],
  },
  {
    id: "ALLOW_SHADOW_CT_PRESENCE_DURING_DEGRADED_SCOPE",
    sourcePath: shadowSourcePath,
    envKey: "PR2B1_SHADOW_MODULE_URL",
    from: '    if (deferCtAssetEvidence && r.source === "certificate_transparency") {',
    to: "    if (false) {",
    expectedFailures: [
      "SHADOW_DEGRADED_NO_LAST_SEEN_REFRESH",
      "SHADOW_DEGRADED_NO_REAPPEARANCE",
      "SHADOW_DEGRADED_NO_CASE_REOPEN",
      "SHADOW_HEALTHY_RESUMES_REAPPEARANCE",
    ],
  },
  {
    id: "ALLOW_SHADOW_CT_ABSENCE_DURING_DEGRADED_SCOPE",
    sourcePath: shadowSourcePath,
    envKey: "PR2B1_SHADOW_MODULE_URL",
    from: `    if (deferredKeys?.has(it.canonical_technology_key) &&
        !seenKeys?.has(it.canonical_technology_key)) continue;`,
    to: "    if (false) continue;",
    expectedFailures: [
      "SHADOW_DEGRADED_NO_DISAPPEARANCE",
      "SHADOW_DEGRADED_NO_DISAPPEARANCE_EVENT",
    ],
  },
  {
    id: "OVER_DEFER_SHADOW_INDEPENDENT_SOURCE",
    sourcePath: shadowSourcePath,
    envKey: "PR2B1_SHADOW_MODULE_URL",
    from: `    if (deferredKeys?.has(it.canonical_technology_key) &&
        !seenKeys?.has(it.canonical_technology_key)) continue;`,
    to: "    if (deferredKeys?.has(it.canonical_technology_key)) continue;",
    expectedFailures: [
      "SHADOW_INDEPENDENT_SOURCE_REMAINS_ASSESSABLE",
      "SHADOW_INDEPENDENT_PHASE2_TRANSITION_RECORDED",
      "SHADOW_INDEPENDENT_PHASE2_CASE_CREATED",
    ],
  },
]);

let sequence = 0;
let killed = 0;
let controlsPassed = 0;
let failures = 0;
const activeMutants = new Set();
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
function fail(message) {
  failures += 1;
  console.error(`FAIL ${message}`);
}
function worktreeFingerprint() {
  const child = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: root,
    encoding: "utf8",
  });
  if (child.error || child.signal || child.status !== 0) {
    throw new Error(`cannot fingerprint worktree: ${child.error?.message || child.stderr}`);
  }
  return hash(child.stdout);
}
const initialFingerprint = worktreeFingerprint();
function cleanup() {
  for (const mutantPath of activeMutants) {
    try { fs.rmSync(mutantPath, { force: true }); } catch { /* best effort */ }
  }
  activeMutants.clear();
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanup();
    console.error(`FAIL mutation suite interrupted by ${signal}`);
    process.exit(2);
  });
}
function replaceExactly(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}
function failureIds(output) {
  return String(output || "").split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}
function executeMutant(id, mutate, {
  sourcePath = lifecycleSourcePath,
  envKey = "PR2B1_LIFECYCLE_MODULE_URL",
} = {}) {
  sequence += 1;
  const originalBytes = fs.readFileSync(sourcePath);
  const originalHash = hash(originalBytes);
  const mutantPath = path.join(
    path.dirname(sourcePath),
    `.${path.basename(sourcePath, ".js")}.pr2b1-mutant.${process.pid}.${sequence}.js`,
  );
  try {
    const mutated = mutate(originalBytes.toString("utf8"));
    if (mutated === originalBytes.toString("utf8")) {
      throw new Error(`${id}: mutation did not change source`);
    }
    fs.writeFileSync(mutantPath, mutated);
    activeMutants.add(mutantPath);
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      timeout: 60_000,
      env: {
        ...process.env,
        [envKey]: pathToFileURL(mutantPath).href,
      },
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = failureIds(output);
    const summary = String(child.stdout || "").match(
      /PR-2B-1 CT asset lifecycle scope: (\d+)\/(\d+) contracts passed/,
    );
    const normalAssertionExit = child.error == null && child.signal == null &&
      child.status === 1 && summary != null &&
      Number(summary[2]) === ASSERTION_TOTAL &&
      Number(summary[1]) + actualFailures.length === ASSERTION_TOTAL;
    return { child, output, actualFailures, normalAssertionExit };
  } finally {
    cleanup();
    if (hash(fs.readFileSync(sourcePath)) !== originalHash) {
      fail(`${id}: target bytes changed`);
    }
    if (worktreeFingerprint() !== initialFingerprint) {
      fail(`${id}: worktree fingerprint changed`);
    }
  }
}

for (const mutant of semanticMutants) {
  try {
    const result = executeMutant(mutant.id, (source) =>
      replaceExactly(source, mutant.from, mutant.to, mutant.id), mutant);
    const exact = JSON.stringify(result.actualFailures) ===
      JSON.stringify(mutant.expectedFailures);
    if (result.normalAssertionExit && exact) {
      killed += 1;
      console.log(`PASS ${mutant.id} exact FAIL set ${JSON.stringify(result.actualFailures)}`);
    } else {
      fail(`${mutant.id} was not killed for the exact reason; normal=${result.normalAssertionExit} actual=${JSON.stringify(result.actualFailures)} expected=${JSON.stringify(mutant.expectedFailures)}`);
    }
  } catch (error) {
    fail(`${mutant.id} runner error: ${error.message}`);
  }
}

try {
  const syntax = executeMutant("SYNTAX_ERROR_CONTROL", (source) => `${source}\nnot valid javascript !!!\n`);
  if (!syntax.normalAssertionExit) {
    controlsPassed += 1;
    console.log("PASS SYNTAX_ERROR_CONTROL rejected non-assertion kill");
  } else fail("SYNTAX_ERROR_CONTROL unexpectedly reached normal assertion exit");
} catch (error) {
  fail(`SYNTAX_ERROR_CONTROL runner error: ${error.message}`);
}

try {
  const importFailure = executeMutant("IMPORT_ERROR_CONTROL", (source) =>
    replaceExactly(
      source,
      'from "./hostnames.js";',
      'from "./pr2b1-missing-hostnames.js";',
      "IMPORT_ERROR_CONTROL",
    ));
  if (!importFailure.normalAssertionExit) {
    controlsPassed += 1;
    console.log("PASS IMPORT_ERROR_CONTROL rejected non-assertion kill");
  } else fail("IMPORT_ERROR_CONTROL unexpectedly reached normal assertion exit");
} catch (error) {
  fail(`IMPORT_ERROR_CONTROL runner error: ${error.message}`);
}

try {
  const control = semanticMutants[0];
  const wrongReason = executeMutant("WRONG_REASON_CONTROL", (source) =>
    replaceExactly(source, control.from, control.to, "WRONG_REASON_CONTROL"));
  const wronglyAccepted = wrongReason.normalAssertionExit &&
    JSON.stringify(wrongReason.actualFailures) === JSON.stringify(["WRONG_REASON"]);
  if (!wronglyAccepted) {
    controlsPassed += 1;
    console.log("PASS WRONG_REASON_CONTROL rejected non-pinned FAIL set");
  } else fail("WRONG_REASON_CONTROL accepted an unrelated FAIL set");
} catch (error) {
  fail(`WRONG_REASON_CONTROL runner error: ${error.message}`);
}

cleanup();
console.log(`\nPR-2B-1 CT asset lifecycle mutations: ${killed}/${semanticMutants.length} semantic mutants killed`);
console.log(`PR-2B-1 mutation controls: ${controlsPassed}/3 rejected`);
if (failures || killed !== semanticMutants.length || controlsPassed !== 3) process.exit(1);
console.log("PR-2B-1 CT asset lifecycle mutation validation passed");
