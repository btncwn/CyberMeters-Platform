#!/usr/bin/env node
// Load-bearing mutation proof for Free-Scan False-Healthy P1.
// Each source mutation reintroduces one founder-pinned defect. The ordinary
// contract assertion must fail for every mutant, proving the gate would go RED.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const sourcePath = path.join(engines, "free-scan-evidence.js");
const original = fs.readFileSync(sourcePath, "utf8");
let sequence = 0;
let pass = 0;
let fail = 0;
let mutantsKilled = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};

async function loadMutant(name, from, to) {
  const mutated = original.replace(from, to);
  ok(`${name}: mutation anchor applied`, mutated !== original);
  if (mutated === original) return null;
  const mutantPath = path.join(
    engines,
    `.free-scan-evidence.mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    return await import(`${pathToFileURL(mutantPath).href}?mutation=${sequence}`);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

function zeroFindingSettlements(overrides = {}) {
  return {
    dns: { status: "fulfilled", value: {} },
    ssl: { status: "fulfilled", value: {} },
    headers: { status: "fulfilled", value: {} },
    email_security: {
      status: "fulfilled",
      value: {
        spf_evidence_status: "observed",
        dkim_evidence_status: "observed",
        dmarc_state: { evidence_status: "observed" },
      },
    },
    ...overrides,
  };
}

{
  const mutant = await loadMutant(
    "M1 health derived from a failed probe",
    "  if (findingsCount > 0) return FREE_SCAN_PREVIEW_STATES.ISSUES_OBSERVED;",
    `  if (moduleEvidence.some((entry) => entry.state === FREE_SCAN_MODULE_STATES.FAILED)) {
    return FREE_SCAN_PREVIEW_STATES.NO_ISSUES_OBSERVED;
  }
  if (findingsCount > 0) return FREE_SCAN_PREVIEW_STATES.ISSUES_OBSERVED;`,
  );
  if (mutant) {
    const evidence = mutant.buildFreeScanEvidence(zeroFindingSettlements({
      ssl: { status: "rejected", reason: new Error("timeout") },
    }));
    const state = mutant.resolveFreeScanPreviewState({
      findingsCount: 0,
      coverage: evidence.evidence_coverage,
      moduleEvidence: evidence.module_evidence,
    });
    const ordinaryContractPassed =
      evidence.module_evidence.find((entry) => entry.module === "ssl")?.state === "failed" &&
      state === "evidence_incomplete";
    const killed = !ordinaryContractPassed;
    ok("M1 makes failed-probe honesty contract RED", killed);
    if (killed) mutantsKilled += 1;
  }
}

{
  const mutant = await loadMutant(
    "M2 total_findings zero used alone",
    "if (findingsCount === 0 && coverage?.complete === true && allModulesCompleted) {",
    "if (findingsCount === 0) {",
  );
  if (mutant) {
    const evidence = mutant.buildFreeScanEvidence(zeroFindingSettlements({
      ssl: { status: "rejected", reason: new Error("timeout") },
    }));
    const state = mutant.resolveFreeScanPreviewState({
      findingsCount: 0,
      coverage: evidence.evidence_coverage,
      moduleEvidence: evidence.module_evidence,
    });
    const ordinaryContractPassed = state === "evidence_incomplete";
    const killed = !ordinaryContractPassed;
    ok("M2 makes zero-findings evidence gate RED", killed);
    if (killed) mutantsKilled += 1;
  }
}

{
  const mutant = await loadMutant(
    "M3 hard-coded modules_scanned",
    `  return moduleEvidence
    .filter((entry) => entry.state === FREE_SCAN_MODULE_STATES.COMPLETED)
    .map((entry) => entry.module);`,
    `  return ["dns", "ssl", "headers", "email_security"];`,
  );
  if (mutant) {
    const evidence = mutant.buildFreeScanEvidence(zeroFindingSettlements({
      ssl: { status: "rejected", reason: new Error("timeout") },
    }));
    const ordinaryContractPassed = !evidence.modules_scanned.includes("ssl");
    const killed = !ordinaryContractPassed;
    ok("M3 makes derived-module-list contract RED", killed);
    if (killed) mutantsKilled += 1;
  }
}

{
  const mutant = await loadMutant(
    "M4 unavailable collapsed into failed",
    "    return FREE_SCAN_MODULE_STATES.UNAVAILABLE;",
    "    return FREE_SCAN_MODULE_STATES.FAILED;",
  );
  if (mutant) {
    const evidence = mutant.buildFreeScanEvidence(zeroFindingSettlements({
      ssl: { status: "fulfilled", value: { unavailable: true } },
    }));
    const ordinaryContractPassed =
      evidence.module_evidence.find((entry) => entry.module === "ssl")?.state === "unavailable";
    const killed = !ordinaryContractPassed;
    ok("M4 makes distinct-state contract RED", killed);
    if (killed) mutantsKilled += 1;
  }
}

console.log(
  `\nFree-scan false-healthy mutations: ${mutantsKilled}/4 mutants killed; ` +
  `${pass}/${pass + fail} assertions passed`,
);
if (fail || mutantsKilled !== 4) process.exit(1);
console.log("Free-scan false-healthy mutation proof passed");
