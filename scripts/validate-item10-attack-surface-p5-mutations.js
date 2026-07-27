#!/usr/bin/env node
// Item 10 P5 — load-bearing source mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(
  root,
  "scripts/validate-item10-attack-surface-p5-customer-parity.js",
);
const paths = {
  presentation: path.join(
    engines,
    "attack-surface-customer-presentation.js",
  ),
  executive: path.join(engines, "executive-report.js"),
};
const sources = Object.fromEntries(Object.entries(paths).map(([key, file]) => [
  key,
  fs.readFileSync(file, "utf8"),
]));
const EXPECTED_MUTANTS = 6;
const EXPECTED_ASSERTIONS = EXPECTED_MUTANTS * 2;
let mutantsKilled = 0;
let mutantFailures = 0;
let assertionsPassed = 0;
let assertionFailures = 0;
let sequence = 0;

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function mutateRequired(source, from, to, label) {
  const mutated = source.replace(from, to);
  assert(`${label}: anchor guard`, mutated !== source, "mutated === original");
  return mutated;
}

function runMutant(name, {
  mutatePresentation = (source) => source,
  mutateExecutive = (source) => source,
}) {
  sequence += 1;
  const presentationName =
    `.attack-surface-customer-presentation.item10-p5-mutant.${process.pid}.${sequence}.js`;
  const executiveName =
    `.executive-report.item10-p5-mutant.${process.pid}.${sequence}.js`;
  const presentationFile = path.join(engines, presentationName);
  const executiveFile = path.join(engines, executiveName);
  const presentation = mutatePresentation(sources.presentation);
  const executive = mutateExecutive(sources.executive);
  fs.writeFileSync(presentationFile, presentation);
  fs.writeFileSync(executiveFile, executive);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_P5_PRESENTATION_MODULE_URL:
          pathToFileURL(presentationFile).href,
        ITEM10_P5_EXECUTIVE_MODULE_URL:
          pathToFileURL(executiveFile).href,
      },
    });
    const killed = child.status !== 0;
    assert(`${name}: suite turns red`, killed,
      killed ? "" : "validator exited zero");
    if (killed) mutantsKilled += 1;
    else {
      mutantFailures += 1;
      console.error(`FAIL ${name}: mutant survived`);
    }
  } finally {
    fs.rmSync(presentationFile, { force: true });
    fs.rmSync(executiveFile, { force: true });
  }
}

runMutant("unavailable renders as healthy", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `  unavailable: "Evidence unavailable",`,
    `  unavailable: "Healthy",`,
    "unavailable wording",
  ),
});

runMutant("not_observed renders as removed", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `  not_observed: "Not observed in this scan",`,
    `  not_observed: "Removed",`,
    "not_observed wording",
  ),
});

runMutant("Executive Report bypasses the shared projection", {
  mutateExecutive: (source) => mutateRequired(
    source,
    `    attack_surface_assurance: attackSurfaceAssuranceFromSnapshot(snap),`,
    `    attack_surface_assurance: {
      schema: "parallel-asm-presentation",
      status: "current",
      signals: {},
    },`,
    "Executive Report projection call",
  ),
});

runMutant("pre-P5 historical snapshot is upgraded from an unfrozen field", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `  return buildAttackSurfaceCustomerPresentation({
    absenceReason: reason,`,
    `  return buildAttackSurfaceCustomerPresentation({
    signalCompleteness:
      snapshot?.modules?.attack_surface_signal_completeness || null,
    absenceReason: reason,`,
    "historical snapshot boundary",
  ),
});

runMutant("migration-102 absence renders healthy", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `    status: recorded ? "recorded" : "not_recorded",
    records: projected,
    customer_message: recorded`,
    `    status: recorded ? "recorded" : "healthy",
    records: projected,
    customer_message: recorded`,
    "migration-102 absence status",
  ),
});

runMutant("signal model-version stamp is dropped", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `      signal_completeness: signalRecorded
        ? (canonical.model_version || null)
        : null,`,
    `      signal_completeness: null,`,
    "signal model-version stamp",
  ),
});

console.log(
  `Item 10 P5 customer parity mutations: ${mutantsKilled}/${EXPECTED_MUTANTS} mutants killed; ` +
  `${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
if (
  mutantsKilled !== EXPECTED_MUTANTS ||
  mutantFailures > 0 ||
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
