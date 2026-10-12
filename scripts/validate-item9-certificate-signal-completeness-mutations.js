#!/usr/bin/env node
//
// Item 9 P1 load-bearing mutations. Each source mutation reintroduces one honesty
// defect and must make the deterministic pure-model suite fail on an assertion:
// a mutant that crashes or never reaches the summary is not a kill.
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
  "stored-fields-fill-issuer",
  "history-promotes-parallel-set",
  "drop-grade-contract",
  "trust-without-store",
  "publish-without-provenance",
  "allow-identical-parallel-identities",
  "unbound-parallel-window",
  "wildcard-without-leaf",
];

let pass = 0;
let fail = 0;
for (const mutation of mutations) {
  const result = spawnSync(
    process.execPath,
    [validator, `--mutation=${mutation}`],
    { cwd: root, encoding: "utf8" }
  );
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  const semantic = result.status === 1 &&
    /^FAIL /m.test(result.stdout || "") &&
    /Item 9 certificate signal completeness: \d+\/\d+ assertions passed/.test(output) &&
    !/SyntaxError|ERR_MODULE_NOT_FOUND|mutation anchor missing|unresolved relative import/.test(output);
  if (semantic) {
    pass++;
  } else {
    fail++;
    console.log(`FAIL ${mutation}: mutant survived or was not a semantic kill (status=${result.status})`);
    console.log(output.slice(0, 600));
  }
}

console.log(`\nItem 9 certificate mutations: ${pass}/${pass + fail} killed`);
if (fail > 0) {
  console.error("Item 9 certificate signal mutation validation FAILED");
  process.exit(1);
}
console.log("Item 9 certificate signal mutation validation passed");
