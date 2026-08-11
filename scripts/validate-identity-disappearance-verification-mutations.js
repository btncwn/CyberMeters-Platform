#!/usr/bin/env node
// Identity disappearance verification honesty — strict fresh-process mutation proof.
//
// A semantic mutant is killed only by the exact expected FAIL-name set through
// the owning validator's normal summary/exit path. Syntax, load, runtime, spawn,
// signal, timeout, and wrong-reason failures are rejected. Mutants are isolated
// beside the source for valid relative imports; target bytes and the complete
// worktree status fingerprint must be unchanged after every run and at exit.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = path.join(root, "workers/scan-api/src/engines/identity-lifecycle.js");
const validator = path.join(root, "scripts/validate-identity-exposure-lifecycle.js");
const EXPECTED_ASSERTIONS = 105;
const EXPECTED_MUTANTS = 3;
const EXPECTED_CONTROLS = 2;

let sequence = 0;
let killed = 0;
let controlsPassed = 0;
let failures = 0;
let activeMutantPath = null;

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => {
  failures += 1;
  console.error(`FAIL ${message}`);
};

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
const originalSourceHash = hash(fs.readFileSync(sourcePath));

function cleanup() {
  if (!activeMutantPath) return;
  try { fs.rmSync(activeMutantPath, { force: true }); } catch { /* best effort */ }
  activeMutantPath = null;
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanup();
    console.error(`FAIL mutation suite interrupted by ${signal}; revalidate worktree cleanliness`);
    process.exit(2);
  });
}

function replaceExactlyOnce(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}

function failNames(output) {
  return String(output || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function runCase({ name, expectedFailures, mutate, expectHarnessRejection = false }) {
  sequence += 1;
  let mutated;
  try {
    mutated = mutate(fs.readFileSync(sourcePath, "utf8"));
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
    return;
  }

  activeMutantPath = path.join(
    path.dirname(sourcePath),
    `.identity-lifecycle.disappearance-mutant.${process.pid}.${sequence}.js`,
  );
  fs.writeFileSync(activeMutantPath, mutated);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      timeout: 20_000,
      env: {
        ...process.env,
        IDENTITY_LIFECYCLE_MODULE_URL: pathToFileURL(activeMutantPath).href,
      },
    });
    const combined = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = failNames(combined);
    const summary = String(child.stdout || "").match(/(\d+) passed, (\d+) failed/);
    const exactSet = JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalAssertionExit = child.error == null
      && child.signal == null
      && child.status === 1
      && summary != null
      && Number(summary[1]) === EXPECTED_ASSERTIONS - expectedFailures.length
      && Number(summary[2]) === expectedFailures.length;

    if (!expectHarnessRejection && normalAssertionExit && exactSet) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else if (expectHarnessRejection && !(normalAssertionExit && exactSet)) {
      controlsPassed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: ${expectHarnessRejection ? "invalid failure was accepted" : (child.status === 0 ? "mutant survived" : "mutant failed for the wrong reason")}`
        + `\nexpected failures: ${JSON.stringify(expectedFailures)}`
        + `\nactual failures: ${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } finally {
    cleanup();
    if (hash(fs.readFileSync(sourcePath)) !== originalSourceHash) {
      fail(`${name}: target bytes changed`);
    }
    if (worktreeFingerprint() !== initialFingerprint) {
      fail(`${name}: worktree fingerprint changed after cleanup`);
    }
  }
}

runCase({
  name: "age across the disappearance window restores false verification",
  expectedFailures: [
    "surface_removed full-window absence is never verified",
    "absence predating the customer removal action stays inconclusive",
    "unknown customer-action time cannot verify disappearance",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `else if (age != null && age >= IDENTITY_DISAPPEARANCE_WINDOW_DAYS) { verification_result = "inconclusive"; actual_outcome = "absent_across_window"; }`,
    `else if (age != null && age >= IDENTITY_DISAPPEARANCE_WINDOW_DAYS) { verification_result = "verified"; actual_outcome = "absent_across_window"; }`,
    "full-window disappearance result",
  ),
});

runCase({
  name: "supported material-change verification is suppressed",
  expectedFailures: [
    "a change AFTER the customer's action DOES verify it",
    "and says why",
    "a SQLite-format action time still verifies a genuinely later change",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    const changedAfterAction = !!(rec.last_changed_at && customer_action_at)`,
    `    const changedAfterAction = false && !!(rec.last_changed_at && customer_action_at)`,
    "supported material-change gate",
  ),
});

runCase({
  name: "still-observed removal failure collapses to inconclusive",
  expectedFailures: [
    "stale last_seen with observed state is still-observed failure",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `if (observedNow) { verification_result = "failed"; actual_outcome = "still_observed"; }`,
    `if (observedNow) { verification_result = "inconclusive"; actual_outcome = "still_observed"; }`,
    "still-observed failure",
  ),
});

runCase({
  name: "harness rejects syntax/load failure",
  expectedFailures: ["surface_removed full-window absence is never verified"],
  expectHarnessRejection: true,
  mutate: (source) => `${source}\nthis is not valid JavaScript {{{\n`,
});

runCase({
  name: "harness rejects wrong exact FAIL-name set",
  expectedFailures: ["wrong reason that must never be accepted"],
  expectHarnessRejection: true,
  mutate: (source) => replaceExactlyOnce(
    source,
    `if (observedNow) { verification_result = "failed"; actual_outcome = "still_observed"; }`,
    `if (observedNow) { verification_result = "inconclusive"; actual_outcome = "still_observed"; }`,
    "wrong-set control",
  ),
});

cleanup();
if (hash(fs.readFileSync(sourcePath)) !== originalSourceHash) fail("suite exit target bytes changed");
if (worktreeFingerprint() !== initialFingerprint) fail("suite exit worktree fingerprint changed");
if (killed !== EXPECTED_MUTANTS) fail(`killed ${killed}/${EXPECTED_MUTANTS} semantic mutants`);
if (controlsPassed !== EXPECTED_CONTROLS) fail(`passed ${controlsPassed}/${EXPECTED_CONTROLS} harness controls`);

console.log(
  `Identity disappearance verification mutations: ${killed}/${EXPECTED_MUTANTS} mutants killed; `
  + `${controlsPassed}/${EXPECTED_CONTROLS} harness controls passed`,
);
if (failures > 0) process.exit(1);
process.exit(0);
