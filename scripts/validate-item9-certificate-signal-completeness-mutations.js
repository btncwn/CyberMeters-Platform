#!/usr/bin/env node
//
// Item 9 P1 load-bearing mutations. Each source mutation reintroduces one honesty
// defect and must make the deterministic pure-model suite fail.
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const validator = path.join(
  root,
  "scripts",
  "validate-item9-certificate-signal-completeness.js"
);
const mutations = [
  "collapse-siblings",
  "unavailable-as-absent",
  "ct-promotes-live-leaf",
  "history-promotes-parallel-set",
  "drop-grade-contract",
  "trust-without-store",
  "publish-without-provenance",
  "allow-identical-parallel-identities",
  "unbound-parallel-window",
  "ct-zero-becomes-wildcard",
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

console.log(`\nItem 9 certificate mutations: ${pass}/${pass + fail} killed`);
if (fail > 0) {
  console.error("Item 9 certificate signal mutation validation FAILED");
  process.exit(1);
}
console.log("Item 9 certificate signal mutation validation passed");
