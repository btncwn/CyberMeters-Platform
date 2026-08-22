#!/usr/bin/env node
// Real source mutations for the MTA-STS tri-state contract.  Each mutant is
// applied in this process, then the contract validator is executed in a fresh
// child process so ESM caching cannot turn an assertion-only test green.
// Mutants name their target file: the admission gate lives in email-analysis.js
// (the boundary module) and the producer + wired consumers in email-intel.js.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const FILES = {
  intel: path.join(root, "workers/scan-api/src/engines/email-intel.js"),
  analysis: path.join(root, "workers/scan-api/src/engines/email-analysis.js"),
};
const originals = Object.fromEntries(
  Object.entries(FILES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]),
);
const run = () => spawnSync(process.execPath, [path.join(root, "scripts/validate-mta-sts-tristate.js")], { cwd: root, encoding: "utf8" });
const mutants = [
  {
    // Deleting the gate's coherence demotion must go RED on a PRODUCTION-path
    // assertion (forged evidence reaching a real consumer output), not only on
    // the gate's own unit assertions.
    id: "MTA-M1-admission-widening",
    file: "analysis",
    from: '  const state = coherent ? rawState : "unavailable";',
    to:   '  const state = rawState;',
    mustContain: "FAIL forged-present: production score fail-closed",
  },
  {
    id: "MTA-M2-404-equals-5xx",
    file: "intel",
    from: '      result.observation_state = "definitive_absent";\n      result.reason = "well_known_404";',
    to:   '      result.observation_state = "unavailable";\n      result.reason = "well_known_404";',
    mustContain: "FAIL 404-served: observation state",
  },
  {
    // Survivor mutant, named: the catch block loses its shaped serviceability —
    // the exact LV-01 reintroduction. Must die on the shape assertion.
    id: "MTA-M3-catch-serviceability-null",
    file: "intel",
    from: `    result.serviceability = classifyServiceability({
      state: FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE,
      origin_status: null,
    });`,
    to:   `    result.serviceability = null;`,
    mustContain: "FAIL timeout: serviceability shape",
  },
  {
    // Survivor mutant, named: the catch block claims an enabled policy while the
    // evidence is unavailable. Must die on the enabled-coherence assertion.
    id: "MTA-M4-enabled-true-retention",
    file: "intel",
    from: '    result.enabled = false;\n    result.observation_state = "unavailable";',
    to:   '    result.enabled = true;\n    result.observation_state = "unavailable";',
    mustContain: "FAIL timeout: enabled coherence",
  },
  {
    // Wire-in regression: the score consumer falls back to the bare token,
    // bypassing the admission gate. Forged evidence then scores — a
    // production-path assertion must go red.
    id: "MTA-M5-score-raw-token-regression",
    file: "intel",
    from: '  if (mtaAdmission.score_admitted && mtaSts.policy_mode === "enforce") mtaScore = W.mta_sts;\n  else if (mtaAdmission.score_admitted) mtaScore = Math.round(W.mta_sts * 0.6);',
    to:   '  if (mtaSts.observation_state === "present" && mtaSts.policy_mode === "enforce") mtaScore = W.mta_sts;\n  else if (mtaSts.observation_state === "present") mtaScore = Math.round(W.mta_sts * 0.6);',
    mustContain: "FAIL forged-present: production score fail-closed",
  },
];
let passed = 0;
for (const m of mutants) {
  const target = FILES[m.file];
  const original = originals[m.file];
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
for (const [key, file] of Object.entries(FILES)) {
  if (fs.readFileSync(file, "utf8") !== originals[key]) throw new Error(`FAIL restore: ${file}`);
}
console.log(`mta-sts-tristate real mutations: ${passed}/${mutants.length} killed`);
