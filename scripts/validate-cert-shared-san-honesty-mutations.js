#!/usr/bin/env node
// PR-2A.2 pinned fresh-process mutation proof.
//
// Each semantic mutant is an exact source transform over a temporary sibling of
// the real runtime module. A kill counts only when the validator reaches its
// normal assertion summary, exits 1, and returns the exact ordered predeclared
// FAIL set. Syntax, load and wrong-reason failures are explicit negative controls.
// Target bytes and the complete worktree fingerprint must remain unchanged.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(root, "scripts/validate-cert-shared-san-honesty.js");
const ASSERTION_TOTAL = 39;
const targets = Object.freeze({
  ssl: {
    sourcePath: path.join(engines, "ssl-scan.js"),
    envName: "PR2A2_SSL_MODULE_URL",
  },
  certIntel: {
    sourcePath: path.join(engines, "cert-intel.js"),
    envName: "PR2A2_CERT_INTEL_MODULE_URL",
  },
});

const semanticMutants = Object.freeze([
  {
    id: "FABRICATE_SHARED_SAN_INITIAL_ZERO",
    target: "ssl",
    from: "  let cert_shared_san_count = null;",
    to: "  let cert_shared_san_count = 0;",
    expectedFailures: [
      "CS_ONLY_SSL_SHARED_SAN_NULL",
      "BLACKOUT_SSL_SHARED_SAN_NULL",
    ],
  },
  {
    id: "DERIVE_OWNERSHIP_FROM_UNMEASURED_COUNT",
    target: "certIntel",
    from: `  const sharedSanMeasured = Boolean(
    crtShSource &&
    crtShSource.error == null &&
    Number.isInteger(crtShSource.count) &&
    crtShSource.count > 0 &&
    Number.isInteger(rawSharedSanCount) &&
    rawSharedSanCount >= 0
  );
  const sharedSanCount = sharedSanMeasured ? rawSharedSanCount : null;`,
    to: `  const sharedSanMeasured = true;
  const sharedSanCount = Number(rawSharedSanCount || 0);`,
    expectedFailures: [
      "CS_ONLY_MODULE_SHARED_SAN_NULL",
      "CS_ONLY_OWNERSHIP_UNKNOWN",
      "CS_ONLY_OWNERSHIP_NOT_ASSESSED",
      "CS_ONLY_OWNERSHIP_REASON",
      "CS_ONLY_CUSTOMER_OWNED_NULL",
      "CS_ONLY_CONFIDENCE_NULL",
      "CS_ONLY_NO_CONFIDENCE_90",
      "CS_ONLY_BRITISH_NOT_ASSESSED_WORDING",
      "BLACKOUT_MODULE_SHARED_SAN_NULL",
      "BLACKOUT_OWNERSHIP_UNKNOWN",
      "SENTINEL_ERROR_DOMINATES_ZERO",
      "SENTINEL_ERROR_BLOCKS_CUSTOMER_OWNED",
      "SENTINEL_ERROR_BLOCKS_CONFIDENCE",
      "MISSING_SOURCE_DOMINATES_ZERO",
    ],
  },
]);

let sequence = 0;
let semanticKilled = 0;
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
function executeMutant({ id, target, mutate }) {
  sequence += 1;
  const config = targets[target];
  const originalBytes = fs.readFileSync(config.sourcePath);
  const originalHash = hash(originalBytes);
  const extension = path.extname(config.sourcePath);
  const base = path.basename(config.sourcePath, extension);
  const mutantPath = path.join(
    path.dirname(config.sourcePath),
    `.${base}.pr2a2-mutant.${process.pid}.${sequence}${extension}`,
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
      env: { ...process.env, [config.envName]: pathToFileURL(mutantPath).href },
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = failureIds(output);
    const summary = String(child.stdout || "").match(
      /PR-2A\.2 shared-SAN honesty: (\d+)\/(\d+) contracts passed/,
    );
    const normalAssertionExit = child.error == null && child.signal == null &&
      child.status === 1 && summary != null &&
      Number(summary[2]) === ASSERTION_TOTAL &&
      Number(summary[1]) + actualFailures.length === ASSERTION_TOTAL;
    return { child, output, actualFailures, normalAssertionExit };
  } finally {
    cleanup();
    if (hash(fs.readFileSync(config.sourcePath)) !== originalHash) {
      fail(`${id}: target bytes changed: ${path.relative(root, config.sourcePath)}`);
    }
    if (worktreeFingerprint() !== initialFingerprint) {
      fail(`${id}: worktree fingerprint changed`);
    }
  }
}

for (const mutant of semanticMutants) {
  try {
    const result = executeMutant({
      id: mutant.id,
      target: mutant.target,
      mutate: (source) => replaceExactly(
        source,
        mutant.from,
        mutant.to,
        mutant.id,
      ),
    });
    const exactFailures = JSON.stringify(result.actualFailures) ===
      JSON.stringify(mutant.expectedFailures);
    if (result.normalAssertionExit && exactFailures) {
      semanticKilled += 1;
      console.log(`PASS ${mutant.id} exact FAIL set ${JSON.stringify(result.actualFailures)}`);
    } else {
      fail(`${mutant.id}: wrong semantic failure\n` +
        `expected=${JSON.stringify(mutant.expectedFailures)}\n` +
        `actual=${JSON.stringify(result.actualFailures)}\n` +
        `status=${result.child.status} signal=${result.child.signal} error=${result.child.error?.message || "none"}\n` +
        `stdout:\n${String(result.child.stdout || "").trim()}\n` +
        `stderr:\n${String(result.child.stderr || "").trim()}`);
    }
  } catch (error) {
    fail(`${mutant.id}: ${error?.message || error}`);
  }
}

// Negative control 1: a syntax failure is not a semantic kill.
try {
  const result = executeMutant({
    id: "SYNTAX_FAILURE_REJECTED",
    target: "ssl",
    mutate: (source) => `${source}\nthis is not valid JavaScript !\n`,
  });
  if (!result.normalAssertionExit && result.actualFailures.length === 0) {
    controlsPassed += 1;
    console.log("PASS SYNTAX_FAILURE_REJECTED");
  } else {
    fail("SYNTAX_FAILURE_REJECTED: invalid failure looked like a semantic kill");
  }
} catch (error) {
  fail(`SYNTAX_FAILURE_REJECTED: ${error?.message || error}`);
}

// Negative control 2: an import/load failure is not a semantic kill.
try {
  const result = executeMutant({
    id: "LOAD_FAILURE_REJECTED",
    target: "certIntel",
    mutate: (source) => replaceExactly(
      source,
      `from "./hostnames.js";`,
      `from "./missing-pr2a2-hostnames.js";`,
      "LOAD_FAILURE_REJECTED",
    ),
  });
  if (!result.normalAssertionExit && result.actualFailures.length === 0) {
    controlsPassed += 1;
    console.log("PASS LOAD_FAILURE_REJECTED");
  } else {
    fail("LOAD_FAILURE_REJECTED: invalid failure looked like a semantic kill");
  }
} catch (error) {
  fail(`LOAD_FAILURE_REJECTED: ${error?.message || error}`);
}

// Negative control 3: a real assertion failure for the wrong contract is not an
// accepted kill for the fabricated-initial-zero mutant.
try {
  const expected = semanticMutants[0].expectedFailures;
  const result = executeMutant({
    id: "WRONG_REASON_FAILURE_REJECTED",
    target: "ssl",
    mutate: (source) => replaceExactly(
      source,
      "          cert_subject   = domain;",
      "          cert_subject   = \"wrong-reason.example\";",
      "WRONG_REASON_FAILURE_REJECTED",
    ),
  });
  const differsFromPinnedReason = JSON.stringify(result.actualFailures) !== JSON.stringify(expected);
  if (result.normalAssertionExit && result.actualFailures.length > 0 && differsFromPinnedReason) {
    controlsPassed += 1;
    console.log(`PASS WRONG_REASON_FAILURE_REJECTED actual FAIL set ${JSON.stringify(result.actualFailures)}`);
  } else {
    fail("WRONG_REASON_FAILURE_REJECTED: wrong assertion reason was accepted");
  }
} catch (error) {
  fail(`WRONG_REASON_FAILURE_REJECTED: ${error?.message || error}`);
}

cleanup();
console.log(
  `PR-2A.2 shared-SAN mutations: ${semanticKilled}/${semanticMutants.length} semantic mutants killed; ` +
  `${controlsPassed}/3 invalid-kill controls rejected`,
);
if (failures > 0 || semanticKilled !== semanticMutants.length || controlsPassed !== 3) {
  console.error("PR-2A.2 shared-SAN mutation validation FAILED");
  process.exit(1);
}
console.log("PR-2A.2 shared-SAN mutation validation passed");
