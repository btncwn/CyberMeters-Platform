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
  {
    // The denominator markers are load-bearing: deleting them from the
    // customer-visible breakdown goes red on the orchestrator pin.
    id: "MTA-M6-breakdown-marker-deletion",
    file: "intel",
    from: '      unmeasured:      scoreResult.unmeasured,\n      measured_weight: scoreResult.measured_weight,\n',
    to:   '',
    mustContain: "FAIL orchestrator breakdown carries denominator markers",
  },
  {
    // ADV-2b, exact: enabled pre-set BEFORE the body read AND the catch reset
    // removed — a body-read failure then retains enabled=true. Dies on the
    // body-read-failure enabled-coherence assertion.
    id: "MTA-M7-ADV-2b-enabled-preset-retention",
    file: "intel",
    edits: [
      {
        from: '    const text = await res.text();\n    result.enabled = true;',
        to:   '    result.enabled = true;\n    const text = await res.text();',
      },
      {
        from: '    result.enabled = false;\n    result.observation_state = "unavailable";',
        to:   '    result.observation_state = "unavailable";',
      },
    ],
    mustContain: "FAIL body-read-failure: enabled coherence",
  },
  {
    // Binding-rule reintroduction: the gate falls back to a private
    // `serviceable === true` predicate, weaker than the canonical authority
    // (conclusion_class ignored). Dies on the conclusive-class probe.
    id: "MTA-M8-private-eligibility-predicate",
    file: "analysis",
    from: '  const coherent = rawState === "present"\n    ? status === 200 && reason === "origin_response" && maySupportHealthyConclusion(serviceability)\n    : rawState === "definitive_absent"\n      ? status === 404 && reason === "well_known_404" && mayGroundAbsence(serviceability)',
    to:   '  const privateServiceable = serviceability?.serviceable === true;\n  const coherent = rawState === "present"\n    ? status === 200 && reason === "origin_response" && privateServiceable\n    : rawState === "definitive_absent"\n      ? status === 404 && reason === "well_known_404" && privateServiceable',
    mustContain: "FAIL conclusive-class gate: serviceable-true non-conclusive present is not admitted",
  },
];
let passed = 0;
for (const m of mutants) {
  const target = FILES[m.file];
  const original = originals[m.file];
  let mutated = original;
  for (const edit of (m.edits || [{ from: m.from, to: m.to }])) {
    const next = mutated.replace(edit.from, edit.to);
    if (next === mutated) throw new Error(`FAIL ${m.id}: anchor missing`);
    mutated = next;
  }
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
