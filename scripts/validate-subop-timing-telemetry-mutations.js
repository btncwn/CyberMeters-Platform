#!/usr/bin/env node
//
// Track B load-bearing mutation proof.
//
// Each production-source mutant is written as a temporary adjacent module and
// the complete sub-operation telemetry validator is launched in a fresh Node
// process against that module. A mutant counts as killed only when the child
// completes through the validator's normal exit path with the exact expected
// failure set: no syntax/import/runtime stderr, no signal, no extra assertion
// failure, and a matching validator summary. Anchor counts and the total mutant
// count are pinned so deletion or source drift cannot silently turn this suite
// into a no-op.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const validator = path.join(root, "scripts", "validate-subop-timing-telemetry.js");
const EXPECTED_MUTANTS = 5;
const EXPECTED_VALIDATOR_ASSERTIONS = 76;

let mutantsKilled = 0;
let failures = 0;
let sequence = 0;

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

function failureNames(stdout) {
  return String(stdout || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function runMutant({ name, sourceName, moduleEnv, expectedFailures, mutate }) {
  sequence += 1;
  const sourcePath = path.join(engines, sourceName);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutantPath = path.join(
    engines,
    `.${sourceName.replace(/\.js$/, "")}.subop-mutant.${process.pid}.${sequence}.js`,
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
    const actualFailures = failureNames(child.stdout);
    const summary = String(child.stdout || "").match(
      /subop-timing-telemetry: (\d+) passed, (\d+) failed/,
    );
    const exactFailureSet = JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalValidatorExit = child.error == null
      && child.signal == null
      && child.status === 1
      && String(child.stderr || "").trim() === ""
      && summary != null
      && Number(summary[2]) === expectedFailures.length
      && Number(summary[1]) + Number(summary[2]) === EXPECTED_VALIDATOR_ASSERTIONS;
    const killedForExpectedReason = normalValidatorExit && exactFailureSet;
    if (killedForExpectedReason) {
      mutantsKilled += 1;
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
  name: "unguarded telemetry finish changes module behaviour",
  sourceName: "ssl-scan.js",
  moduleEnv: "SUBOP_TIMING_SSL_MODULE_URL",
  expectedFailures: ["ssl result identical with THROWING collector"],
  mutate: (source) => replaceExactlyOnce(
    source,
    `  const subOpFinish = (token, res) => {
    try {
      opts.subOps?.finish?.(token, {
        outcome: res ? "ok" : (opts.signal?.aborted === true ? "aborted" : "unavailable"),
        aborted: !res && opts.signal?.aborted === true,
      });
    } catch { /* observational only */ }
  };`,
    `  const subOpFinish = (token, res) => {
    opts.subOps?.finish?.(token, {
      outcome: res ? "ok" : (opts.signal?.aborted === true ? "aborted" : "unavailable"),
      aborted: !res && opts.signal?.aborted === true,
    });
  };`,
    "guarded ssl finish",
  ),
});

runMutant({
  name: "aborted collector completion reclassified as ok",
  sourceName: "scan-budget.js",
  moduleEnv: "SUBOP_TIMING_SCAN_BUDGET_MODULE_URL",
  expectedFailures: [
    "aborted flag wins over outcome",
    "in-flight bare probe attributed as aborted",
    "in-flight headers GET attributed as aborted",
    "CT lookup in flight at cap attributed as aborted",
    "bare probe in flight with CT attributed as aborted",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `        if (entry.aborted) entry.outcome = "aborted";`,
    `        if (entry.aborted) entry.outcome = "ok";`,
    "aborted outcome precedence",
  ),
});

runMutant({
  name: "post-cap ssl operations open telemetry rows",
  sourceName: "ssl-scan.js",
  moduleEnv: "SUBOP_TIMING_SSL_MODULE_URL",
  expectedFailures: [
    "NO row for the post-cap www probe",
    "NO row for the post-cap redirect hop 1",
    "NO row for CT-abort post-cap www probe",
    "NO row for CT-abort post-cap redirect hop 1",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `      if (opts.signal?.aborted === true) return null;
      return opts.subOps?.begin?.("ssl", name) ?? null;`,
    `      return opts.subOps?.begin?.("ssl", name) ?? null;`,
    "ssl post-cap begin gate",
  ),
});

runMutant({
  name: "ct_lookup structured resolve classified unconditionally ok",
  sourceName: "ssl-scan.js",
  moduleEnv: "SUBOP_TIMING_SSL_MODULE_URL",
  expectedFailures: ["ct_lookup honest when every provider failed"],
  mutate: (source) => replaceExactlyOnce(
    source,
    `          opts.subOps?.finish?.(ctSubOp, { outcome: anyOk ? "ok" : "unavailable" });`,
    `          opts.subOps?.finish?.(ctSubOp, { outcome: "ok" });`,
    "ct_lookup evidence classification",
  ),
});

runMutant({
  name: "bounded batch regresses to awaited per-row writes",
  sourceName: "scan-engine.js",
  moduleEnv: "SUBOP_TIMING_SCAN_ENGINE_MODULE_URL",
  expectedFailures: [
    "exactly ONE batch call for all rows",
    "still exactly one batch call",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    await env.cybermeters_db.batch(statements);`,
    `    for (const statement of statements) await statement.run();`,
    "single D1 batch",
  ),
});

if (sequence !== EXPECTED_MUTANTS) {
  fail(`pinned mutant count — defined ${sequence}, expected ${EXPECTED_MUTANTS}`);
}
if (mutantsKilled !== EXPECTED_MUTANTS) {
  fail(`mutation score — killed ${mutantsKilled}/${EXPECTED_MUTANTS}`);
}

console.log(`\nsubop-timing-telemetry mutations: ${mutantsKilled}/${EXPECTED_MUTANTS} killed`);
process.exit(failures > 0 ? 1 : 0);
