#!/usr/bin/env node
// Mutation adequacy for the AS-B6 reserved deadline/cancellation closure.
// Mutants live only in disposable copies; syntax/import crashes and timeouts do
// not count as kills.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRoot = path.join(root, "workers", "scan-api");
const validatorName = "validate-as-b6-reserved-deadline-safety.js";
const validatorPath = path.join(root, "scripts", validatorName);
const completionPattern = /AS-B6 reserved deadline safety: \d+ passed, [1-9]\d* failed/;

const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const protectedFiles = [
  path.join(workerRoot, "src", "engines", "scan-budget.js"),
  path.join(workerRoot, "src", "engines", "reserved-probe.js"),
  path.join(workerRoot, "src", "engines", "reserved-scan.js"),
  path.join(workerRoot, "src", "engines", "scan-engine.js"),
  validatorPath,
];
const protectedHashes = new Map(protectedFiles.map((file) => [file, sha256(file)]));

function makeSandbox() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "asb6-reserved-mutant-"));
  const sandbox = path.join(tmp, "repo");
  const sandboxWorker = path.join(sandbox, "workers", "scan-api");
  const sandboxScripts = path.join(sandbox, "scripts");
  fs.mkdirSync(sandboxWorker, { recursive: true });
  fs.mkdirSync(sandboxScripts, { recursive: true });
  fs.cpSync(path.join(workerRoot, "src"), path.join(sandboxWorker, "src"), { recursive: true });
  fs.cpSync(path.join(root, "shared"), path.join(sandbox, "shared"), { recursive: true });
  fs.copyFileSync(path.join(workerRoot, "package.json"), path.join(sandboxWorker, "package.json"));
  fs.copyFileSync(validatorPath, path.join(sandboxScripts, validatorName));
  fs.symlinkSync(path.join(workerRoot, "node_modules"), path.join(sandboxWorker, "node_modules"), "dir");
  return { tmp, sandbox };
}

function replaceExactlyOnce(file, before, after) {
  const source = fs.readFileSync(file, "utf8");
  const count = source.split(before).length - 1;
  if (count !== 1) throw new Error(`anchor count=${count}, expected=1: ${before}`);
  fs.writeFileSync(file, source.replace(before, after));
}

function runValidator(sandbox) {
  return spawnSync(process.execPath, [path.join(sandbox, "scripts", validatorName)], {
    cwd: sandbox,
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 8 * 1024 * 1024,
  });
}

const mutants = [
  {
    id: "ASB6R-M-DEADLINE-ARM-REMOVED",
    file: "workers/scan-api/src/engines/scan-engine.js",
    before: "    if (!durableInvocation && reservedMode) deadline.arm();",
    after: "    if (!durableInvocation && reservedMode) void deadline;",
    expected: "ASB6R_ENGINE_WIRES_DEADLINE_ARM",
  },
  {
    id: "ASB6R-M-GET-SIGNAL-REMOVED",
    file: "workers/scan-api/src/engines/reserved-probe.js",
    before: "          signal: combineSignals(opts?.signal, activeAccounting?.signal, AbortSignal.timeout(timeoutMs)),",
    after: "          signal: combineSignals(opts?.signal, AbortSignal.timeout(timeoutMs)),",
    expected: "ASB6R_SIGNAL_REMOVAL_INFLIGHT_GET_ABORTED",
  },
  {
    id: "ASB6R-M-GET-ACCOUNTING-REMOVED",
    file: "workers/scan-api/src/engines/reserved-probe.js",
    before: "      activeAccounting?.recordAttempt?.();",
    after: "      void activeAccounting;",
    expected: "ASB6R_ACCOUNTING_REMOVAL_GET_COUNTED",
  },
  {
    id: "ASB6R-M-LATE-WORK-GUARD-REMOVED",
    file: "workers/scan-api/src/engines/scan-budget.js",
    before: "      recordAttempt: () => { assertNotCancelled(); return this.recordAttempt(key); },",
    after: "      recordAttempt: () => this.recordAttempt(key),",
    expected: "ASB6R_LATE_WORK_AFTER_DEADLINE_REFUSED",
  },
  {
    id: "ASB6R-M-SSL-PREABORT-CT-SHAPE-REMOVED",
    file: "workers/scan-api/src/engines/reserved-scan.js",
    before: "    ct_sources: {\n      crt_sh: { count: 0, error },",
    after: "    ct_sources_removed: {\n      crt_sh: { count: 0, error },",
    expected: "ASB6R_PREABORT_CT_PLATFORM_WORDING_PRESERVED",
  },
  {
    id: "ASB6R-M-SUBDOMAINS-PREABORT-CT-SHAPE-REMOVED",
    file: "workers/scan-api/src/engines/reserved-scan.js",
    before: "    sensitive: [],\n    sources: {\n      crt_sh: { count: 0, error },",
    after: "    sensitive: [],\n    sources_removed: {\n      crt_sh: { count: 0, error },",
    expected: "ASB6R_PREABORT_CT_PLATFORM_WORDING_PRESERVED",
  },
];

let failures = 0;
let killed = 0;
let baseline = null;
try {
  baseline = makeSandbox();
  const result = runValidator(baseline.sandbox);
  const green = result.status === 0 && result.signal == null && !/^FAIL /m.test(result.stdout || "");
  if (green) console.log("PASS ASB6R_MUTATION_BASELINE_GREEN");
  else {
    failures += 1;
    console.log(`FAIL ASB6R_MUTATION_BASELINE_GREEN — status=${result.status} signal=${result.signal}`);
    console.log(`${result.stdout || ""}${result.stderr || ""}`);
  }
} finally {
  if (baseline) fs.rmSync(baseline.tmp, { recursive: true, force: true });
}

for (const mutant of mutants) {
  let fixture = null;
  try {
    fixture = makeSandbox();
    replaceExactlyOnce(path.join(fixture.sandbox, mutant.file), mutant.before, mutant.after);
    const result = runValidator(fixture.sandbox);
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const named = new RegExp(`^FAIL ${mutant.expected}(?:\\s|—|$)`, "m").test(output);
    const clean = result.status === 1
      && result.signal == null
      && completionPattern.test(output)
      && !/SyntaxError|ERR_MODULE_NOT_FOUND|uncaught exception/i.test(output);
    if (named && clean) {
      killed += 1;
      console.log(`PASS ${mutant.id} — killed by ${mutant.expected}`);
    } else {
      failures += 1;
      console.log(`FAIL ${mutant.id} — status=${result.status} signal=${result.signal} expected=${mutant.expected}`);
      console.log(output);
    }
  } catch (error) {
    failures += 1;
    console.log(`FAIL ${mutant.id} — ${error?.stack || error}`);
  } finally {
    if (fixture) fs.rmSync(fixture.tmp, { recursive: true, force: true });
  }
}

const unchanged = protectedFiles.every((file) => sha256(file) === protectedHashes.get(file));
if (unchanged) console.log("PASS ASB6R_MUTANTS_DID_NOT_TOUCH_CANDIDATE");
else {
  failures += 1;
  console.log("FAIL ASB6R_MUTANTS_DID_NOT_TOUCH_CANDIDATE");
}

console.log(`AS-B6 reserved mutation adequacy: ${killed}/${mutants.length} named mutants killed; ${failures} harness failures`);
if (failures > 0) process.exit(1);
