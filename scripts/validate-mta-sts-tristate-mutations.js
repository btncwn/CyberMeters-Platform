#!/usr/bin/env node
// Real source mutations for the MTA-STS tri-state contract.  Each mutant is
// applied in this process, then the contract validator is executed in a fresh
// child process so ESM caching cannot turn an assertion-only test green.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const target = path.join(root, "workers/scan-api/src/engines/email-intel.js");
const original = fs.readFileSync(target, "utf8");
const run = () => spawnSync(process.execPath, [path.join(root, "scripts/validate-mta-sts-tristate.js")], { cwd: root, encoding: "utf8" });
const mutants = [
  {
    id: "MTA-M1-admission-widening",
    from: '  const state = coherent ? rawState : "unavailable";',
    to:   '  const state = rawState;',
    mustContain: "200-valid-policy: score admission",
  },
  {
    id: "MTA-M2-404-equals-5xx",
    from: '      result.observation_state = "definitive_absent";\n      result.reason = "well_known_404";',
    to:   '      result.observation_state = "unavailable";\n      result.reason = "well_known_404";',
    mustContain: "404-served: observation state",
  },
];
let passed = 0;
for (const m of mutants) {
  const mutated = original.replace(m.from, m.to);
  if (mutated === original) throw new Error(`FAIL ${m.id}: anchor missing`);
  fs.writeFileSync(target, mutated);
  try {
    const result = run();
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    const killed = result.status !== 0 && output.includes(m.mustContain);
    if (!killed) throw new Error(`FAIL ${m.id}: exit=${result.status}\n${output}`);
    passed += 1;
    console.log(`PASS ${m.id}: killed by named assertion`);
  } finally {
    fs.writeFileSync(target, original);
  }
}
console.log(`mta-sts-tristate real mutations: ${passed}/${mutants.length} killed`);
