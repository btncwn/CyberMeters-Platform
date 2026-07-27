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
const EXPECTED_MUTANTS = 2;
const EXPECTED_ASSERTIONS = 4;
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

const labelMutantSource = mutateRequired(
  source,
  `  admin_surface_detected: "Admin surfaces observed",\n`,
  "",
  "canonical admin-surface email label",
);
const labelMutantFile = path.join(
  engines,
  `.asset-alerts.labels-mutant.${process.pid}.js`,
);
fs.writeFileSync(labelMutantFile, labelMutantSource);
try {
  const child = spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      ASSET_ALERT_LABELS_MODULE_URL: pathToFileURL(labelMutantFile).href,
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
  fs.rmSync(labelMutantFile, { force: true });
}

const subjectMutantSource = mutateRequired(
  source,
  `  const takeoverCount = counts.takeover_risk_detected || 0;
  const newAssetCount = counts.new_asset_discovered || 0;
  const adminSurfaceCount = counts.admin_surface_detected || 0;
  const subject = takeoverCount > 0
    ? \`🚨 CyberMeters: Takeover risk on \${domain}\`
    : newAssetCount > 0 && adminSurfaceCount > 0
    ? \`⚠ CyberMeters: Asset changes observed on \${domain}\`
    : adminSurfaceCount > 0
    ? \`⚠ CyberMeters: Admin surfaces observed on \${domain}\`
    : newAssetCount > 0
    ? \`⚠ CyberMeters: New assets observed on \${domain}\`
    : \`CyberMeters: Asset changes on \${domain}\`;`,
    `  const subject = severity === "critical"
    ? \`🚨 CyberMeters: Takeover risk on \${domain}\`
    : severity === "high"
    ? \`⚠ CyberMeters: New assets detected on \${domain}\`
    : \`CyberMeters: Asset changes on \${domain}\`;`,
  "canonical-count-backed subject selection",
);
const subjectMutantFile = path.join(
  engines,
  `.asset-alerts.subject-mutant.${process.pid}.js`,
);
fs.writeFileSync(subjectMutantFile, subjectMutantSource);
try {
  const child = spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      ASSET_ALERT_LABELS_MODULE_URL: pathToFileURL(subjectMutantFile).href,
    },
  });
  const killed = child.status !== 0;
  assert(
    "severity-only high-subject selection turns the suite red",
    killed,
    killed ? "" : "validator exited zero",
  );
  if (killed) mutantsKilled += 1;
  else {
    mutantFailures += 1;
    console.error("FAIL severity-only high-subject mutant survived");
  }
} finally {
  fs.rmSync(subjectMutantFile, { force: true });
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
