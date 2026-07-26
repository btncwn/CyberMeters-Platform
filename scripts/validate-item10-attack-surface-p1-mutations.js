#!/usr/bin/env node
//
// Every mutation reintroduces an Item 10 evidence-honesty or removal-threshold
// defect and must make the deterministic P1 validator fail.
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-item10-attack-surface-p1.js");
const mutations = [
  "collapse-siblings",
  "unavailable-as-absent",
  "cve-zero-is-clean",
  "one-scan-removes",
  "drop-spacing",
  "drop-window",
  "either-source-removes",
  "ct-advances-removal",
  "unavailable-advances",
  "observed-keeps-counter",
];

let pass = 0;
let fail = 0;
for (const mutation of mutations) {
  const result = spawnSync(
    process.execPath,
    [validator, `--mutation=${mutation}`],
    { cwd: root, encoding: "utf8" }
  );
  if (result.status !== 0) {
    pass++;
  } else {
    fail++;
    console.log(`FAIL ${mutation}: mutant survived`);
  }
}

console.log(`\nItem 10 P1 mutations: ${pass}/${pass + fail} killed`);
if (fail > 0) {
  console.error("Item 10 P1 mutation validation FAILED");
  process.exit(1);
}
console.log("Item 10 P1 mutation validation passed");
