#!/usr/bin/env node
// Canonical ASM alert email-label coverage mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const sourceFile = path.join(engines, "asset-alerts.js");
const validator = path.join(
  root,
  "scripts/validate-asset-alert-email-labels.js",
);
const source = fs.readFileSync(sourceFile, "utf8");
const EXPECTED_MUTANTS = 1;
const EXPECTED_ASSERTIONS = 2;
let mutantsKilled = 0;
let mutantFailures = 0;
let assertionsPassed = 0;
let assertionFailures = 0;

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function mutateRequired(input, from, to, label) {
  const mutated = input.replace(from, to);
  assert(`${label}: anchor guard`, mutated !== input, "mutated === original");
  return mutated;
}

const mutantSource = mutateRequired(
  source,
  `  admin_surface_detected: "Admin surfaces observed",\n`,
  "",
  "canonical admin-surface email label",
);
const mutantFile = path.join(
  engines,
  `.asset-alerts.labels-mutant.${process.pid}.js`,
);
fs.writeFileSync(mutantFile, mutantSource);
try {
  const child = spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      ASSET_ALERT_LABELS_MODULE_URL: pathToFileURL(mutantFile).href,
    },
  });
  const killed = child.status !== 0;
  assert(
    "removed canonical label turns the suite red",
    killed,
    killed ? "" : "validator exited zero",
  );
  if (killed) mutantsKilled += 1;
  else {
    mutantFailures += 1;
    console.error("FAIL removed canonical label mutant survived");
  }
} finally {
  fs.rmSync(mutantFile, { force: true });
}

console.log(
  `Asset alert email label mutations: ` +
  `${mutantsKilled}/${EXPECTED_MUTANTS} mutants killed; ` +
  `${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
if (
  mutantsKilled !== EXPECTED_MUTANTS ||
  mutantFailures > 0 ||
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
