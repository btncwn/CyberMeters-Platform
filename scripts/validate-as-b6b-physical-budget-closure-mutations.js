#!/usr/bin/env node
//
// Mutation adequacy for the focused AS-B6b closure oracle.
//
// Mutants are applied only to disposable source copies. A mutant counts as killed
// only when the validator exits normally through its assertion summary and names
// the expected failed contract; syntax/import crashes are never accepted as kills.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRoot = path.join(root, "workers", "scan-api");
const validatorName = "validate-as-b6b-physical-budget-closure.js";
const validatorPath = path.join(root, "scripts", validatorName);
const completionPattern = /AS-B6b physical-budget closure: \d+ passed, [1-9]\d* failed/;

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const candidateFiles = [
  path.join(workerRoot, "src", "engines", "scan-budget.js"),
  path.join(workerRoot, "src", "engines", "reserved-probe.js"),
  path.join(workerRoot, "src", "engines", "reserved-scan.js"),
  path.join(workerRoot, "src", "engines", "scan-engine.js"),
  validatorPath,
];
const candidateHashes = new Map(candidateFiles.map((file) => [file, sha256(file)]));

function makeSandbox() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "asb6b-mutant-"));
  const sandbox = path.join(tempRoot, "repo");
  const sandboxWorker = path.join(sandbox, "workers", "scan-api");
  const sandboxScripts = path.join(sandbox, "scripts");
  fs.mkdirSync(sandboxWorker, { recursive: true });
  fs.mkdirSync(sandboxScripts, { recursive: true });
  fs.cpSync(path.join(workerRoot, "src"), path.join(sandboxWorker, "src"), { recursive: true });
  fs.cpSync(path.join(root, "shared"), path.join(sandbox, "shared"), { recursive: true });
  fs.copyFileSync(path.join(workerRoot, "package.json"), path.join(sandboxWorker, "package.json"));
  fs.copyFileSync(validatorPath, path.join(sandboxScripts, validatorName));
  fs.symlinkSync(path.join(workerRoot, "node_modules"), path.join(sandboxWorker, "node_modules"), "dir");
  return { tempRoot, sandbox };
}

function replaceExactlyOnce(file, before, after) {
  const source = fs.readFileSync(file, "utf8");
  const occurrences = source.split(before).length - 1;
  if (occurrences !== 1) {
    throw new Error(`mutation anchor count ${occurrences}, expected 1: ${before}`);
  }
  fs.writeFileSync(file, source.replace(before, after));
}

function runValidator(sandbox) {
  return spawnSync(process.execPath, [path.join(sandbox, "scripts", validatorName)], {
    cwd: sandbox,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, ASB6B_MUTANT_MODE: "1" },
  });
}

const mutants = [
  {
    name: "counter-removal",
    file: path.join("workers", "scan-api", "src", "engines", "scan-budget.js"),
    before: "      recordAttempt: () => this.recordAttempt(key),",
    after: "      recordAttempt: () => {},",
    expected: "ASB6B_COUNTER_RECONCILES_PHYSICAL",
  },
  {
    name: "boundary-off-by-one",
    file: path.join("workers", "scan-api", "src", "engines", "scan-budget.js"),
    before: "    if (this.issued >= this.limit) this.deny(category);",
    after: "    if (this.issued > this.limit) this.deny(category);",
    expected: "ASB6B_BOUNDARY_50_ISSUED_51_DENIED",
  },
  {
    name: "fallback-uncharged",
    file: path.join("workers", "scan-api", "src", "engines", "reserved-probe.js"),
    before: "      activeAccounting?.recordAttempt?.();",
    after: "      if (new URL(current).protocol !== \"http:\") activeAccounting?.recordAttempt?.();",
    expected: "ASB6B_FALLBACK_INTERNAL_EQUALS_PHYSICAL",
  },
];

let failures = 0;
let killed = 0;
let baselineSandbox = null;
try {
  baselineSandbox = makeSandbox();
  const baseline = runValidator(baselineSandbox.sandbox);
  const baselineGreen = baseline.status === 0
    && baseline.signal == null
    && !/^FAIL /m.test(baseline.stdout || "");
  if (baselineGreen) {
    console.log("PASS ASB6B_MUTATION_BASELINE_GREEN");
  } else {
    failures += 1;
    console.log(`FAIL ASB6B_MUTATION_BASELINE_GREEN — status=${baseline.status}, signal=${baseline.signal}`);
    console.log((baseline.stdout || "") + (baseline.stderr || ""));
  }
} finally {
  if (baselineSandbox) fs.rmSync(baselineSandbox.tempRoot, { recursive: true, force: true });
}

for (const mutant of mutants) {
  let mutantSandbox = null;
  try {
    mutantSandbox = makeSandbox();
    replaceExactlyOnce(
      path.join(mutantSandbox.sandbox, mutant.file),
      mutant.before,
      mutant.after,
    );
    const result = runValidator(mutantSandbox.sandbox);
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const namedFailure = new RegExp(`^FAIL ${mutant.expected}(?:\\s|—|$)`, "m").test(output);
    const cleanAssertionExit = result.status === 1
      && result.signal == null
      && completionPattern.test(output)
      && !/SyntaxError|ERR_MODULE_NOT_FOUND|uncaught exception/i.test(output);
    if (namedFailure && cleanAssertionExit) {
      killed += 1;
      console.log(`PASS ASB6B_MUTANT_${mutant.name.toUpperCase().replaceAll("-", "_")} — killed by ${mutant.expected}`);
    } else {
      failures += 1;
      console.log(`FAIL ASB6B_MUTANT_${mutant.name.toUpperCase().replaceAll("-", "_")} — status=${result.status}, signal=${result.signal}, expected=${mutant.expected}`);
      console.log(output);
    }
  } catch (error) {
    failures += 1;
    console.log(`FAIL ASB6B_MUTANT_${mutant.name.toUpperCase().replaceAll("-", "_")} — harness error: ${error?.stack || error}`);
  } finally {
    if (mutantSandbox) fs.rmSync(mutantSandbox.tempRoot, { recursive: true, force: true });
  }
}

const candidateUnchanged = candidateFiles.every((file) => sha256(file) === candidateHashes.get(file));
if (candidateUnchanged) {
  console.log("PASS ASB6B_MUTANTS_DID_NOT_TOUCH_CANDIDATE");
} else {
  failures += 1;
  console.log("FAIL ASB6B_MUTANTS_DID_NOT_TOUCH_CANDIDATE");
}

console.log(`AS-B6b mutation adequacy: ${killed}/${mutants.length} named mutants killed; ${failures} harness failures`);
if (failures > 0) process.exit(1);
