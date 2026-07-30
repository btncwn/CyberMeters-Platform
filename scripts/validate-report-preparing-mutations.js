#!/usr/bin/env node
//
// A1 report_preparing strict fresh-process mutation proof.
//
// Each carrier mutant is an adjacent temporary copy of the production module.
// The full route/resolver validator runs in a fresh Node process, while its
// direct resolver/frontend imports point at that mutated production copy. A kill
// counts only for the exact expected assertion list and the normal validator
// summary/exit contract.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-report-preparing.js");
const EXPECTED_MUTANTS = 4;
const EXPECTED_VALIDATOR_ASSERTIONS = 38;

let defined = 0;
let killed = 0;
let failures = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL ${message}`);
}

function replaceExactlyOnce(source, from, to, label) {
  const occurrences = source.split(from).length - 1;
  if (occurrences !== 1) {
    throw new Error(`${label}: anchor count ${occurrences}, expected 1`);
  }
  return source.replace(from, to);
}

function assertionFailures(stdout) {
  return String(stdout || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function runMutant({
  name,
  relativeSource,
  moduleEnv,
  expectedFailures,
  mutate,
}) {
  defined += 1;
  const sourcePath = path.join(root, relativeSource);
  const source = fs.readFileSync(sourcePath, "utf8");
  const parsed = path.parse(sourcePath);
  const mutantPath = path.join(
    parsed.dir,
    `.${parsed.name}.a1-mutant.${process.pid}.${defined}${parsed.ext}`,
  );

  let mutated;
  try {
    mutated = mutate(source);
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
    return;
  }

  fs.writeFileSync(mutantPath, mutated);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        [moduleEnv]: pathToFileURL(mutantPath).href,
      },
    });
    const actualFailures = assertionFailures(child.stdout);
    const summary = String(child.stdout || "").match(
      /report-preparing: (\d+) passed, (\d+) failed/,
    );
    const exactFailureList =
      JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalValidatorFailure =
      child.error == null &&
      child.signal == null &&
      child.status === 1 &&
      String(child.stderr || "").trim() === "" &&
      summary != null &&
      Number(summary[2]) === expectedFailures.length &&
      Number(summary[1]) + Number(summary[2]) === EXPECTED_VALIDATOR_ASSERTIONS;

    if (normalValidatorFailure && exactFailureList) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: mutant ${child.status === 0 ? "survived" : "failed for the wrong reason"}`
        + `\nexpected failures: ${JSON.stringify(expectedFailures)}`
        + `\nactual failures: ${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

runMutant({
  name: "completed lifecycle restored as report-ready without evidence",
  relativeSource: "workers/scan-api/src/engines/report-availability.js",
  moduleEnv: "REPORT_PREPARING_RESOLVER_MODULE_URL",
  expectedFailures: [
    "resolver gives terminal integrity errors precedence over preparing",
    "completed status alone never becomes report_ready",
    "failed repair limit is an explicit terminal report error",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "  const before = await snapshotAttemptState(env, scan.id);",
    `  return {
    availability: { status: "report_ready", retryable: false },
    read: null,
  };
  const before = await snapshotAttemptState(env, scan.id);`,
    "completed requires authoritative report evidence",
  ),
});

runMutant({
  name: "terminal snapshot integrity error converted to report_preparing",
  relativeSource: "workers/scan-api/src/engines/report-availability.js",
  moduleEnv: "REPORT_PREPARING_RESOLVER_MODULE_URL",
  expectedFailures: [
    "resolver gives terminal integrity errors precedence over preparing",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `  if (read.status === "integrity_error" || read.status === "unsupported_schema_version") {
    return terminalState(
      "report_integrity_error",
      "The report is unavailable because its integrity could not be verified.",
      read.reason ?? read.status,
      { manual_retry_available: false },
    );
  }`,
    `  if (read.status === "integrity_error" || read.status === "unsupported_schema_version") {
    return {
      availability: {
        status: "report_preparing",
        code: "report_preparing",
        message: REPORT_PREPARING_MESSAGE,
        retryable: true,
      },
      read,
    };
  }`,
    "integrity errors outrank preparation",
  ),
});

runMutant({
  name: "legitimate report_preparing presentation branch bypassed",
  relativeSource: "frontend/src/lib/reportAvailability.js",
  moduleEnv: "REPORT_PREPARING_FRONTEND_MODULE_URL",
  expectedFailures: [
    "frontend recognises only explicit retryable report_preparing",
    "legitimate preparing state has dedicated non-error presentation",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "  return availability?.status === 'report_preparing' && availability?.retryable === true",
    "  return false",
    "explicit report_preparing presentation branch",
  ),
});

runMutant({
  name: "bounded preparation polling permits an extra indefinite step",
  relativeSource: "frontend/src/lib/reportAvailability.js",
  moduleEnv: "REPORT_PREPARING_FRONTEND_MODULE_URL",
  expectedFailures: [
    "preparation polling stops at the configured bound",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "attempt >= REPORT_PREPARING_MAX_ATTEMPTS",
    "attempt > REPORT_PREPARING_MAX_ATTEMPTS",
    "finite preparation polling bound",
  ),
});

if (defined !== EXPECTED_MUTANTS) {
  fail(`pinned mutant count — defined ${defined}, expected ${EXPECTED_MUTANTS}`);
}
if (killed !== EXPECTED_MUTANTS) {
  fail(`mutation score — killed ${killed}/${EXPECTED_MUTANTS}`);
}

console.log(`\nreport-preparing mutations: ${killed}/${EXPECTED_MUTANTS} killed`);
process.exit(failures > 0 ? 1 : 0);
