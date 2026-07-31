#!/usr/bin/env node
// PDF-DMARC-OBJECT-RENDERING — strict anchor-guarded mutation proof.
//
// Each mutant reintroduces one exact contract-breaking behaviour in the real
// renderer (workers/scan-api/src/engines/pdf.js) and must be killed by the
// focused validator IN A FRESH NODE CHILD PROCESS for its exact target
// assertions — no wrong-reason kill is accepted:
//   - the anchor must match exactly once (zero or multiple matches is fatal);
//   - the child must exit 1 with no spawn error and no signal;
//   - the set of FAIL assertion names must equal the pinned expected set —
//     an extra unexpected FAIL line, a SyntaxError, or a module-load failure
//     does not count as a kill;
//   - the validator summary must be present and its assertion total must
//     match the validator's own pinned count;
//   - survivor or mutant-count drift exits non-zero;
//   - the mutated file is restored even on failure.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const pdfFile = path.join(root, "workers", "scan-api", "src", "engines", "pdf.js");
const validator = path.join(root, "scripts", "validate-pdf-dmarc-record-rendering.js");

const EXPECTED_MUTANTS = 2;
const VALIDATOR_ASSERTIONS = 20;
const SUMMARY_PREFIX = "PDF-DMARC record rendering:";

const replaceExactlyOnce = (source, anchor, replacement, label) => {
  const first = source.indexOf(anchor);
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor must exist exactly once`);
  }
  const mutated = source.slice(0, first) + replacement + source.slice(first + anchor.length);
  if (mutated === source) throw new Error(`${label}: mutated === original`);
  return mutated;
};

// FAIL lines print as "FAIL <name>" or "FAIL <name> — <detail>"; compare names.
const failNames = (output) => output
  .split("\n")
  .filter((line) => line.startsWith("FAIL "))
  .map((line) => line.slice(5).split(" — ")[0].trim())
  .sort();

const summaryTotals = (output) => {
  const line = output.split("\n").find((l) => l.startsWith(SUMMARY_PREFIX));
  if (!line) return null;
  const match = line.match(/(\d+) passed, (\d+) failed/);
  if (!match) return null;
  return { pass: Number(match[1]), fail: Number(match[2]), line };
};

const runValidator = () => spawnSync(process.execPath, [validator], {
  cwd: root,
  encoding: "utf8",
  timeout: 120_000,
});

const mutants = [
  {
    // The exact production defect: the raw DNS answer object is selected
    // before the canonical value string and String() prints "[object Object]".
    name: "raw object selected before canonical value",
    anchor:
      `  if (typeof record?.value === "string" && record.value.trim()) return record.value;
  if (typeof record?.raw === "string" && record.raw.trim()) return record.raw;
  return null;`,
    replacement:
      "  return String(record?.raw ?? record?.value ?? record);",
    expectedFailures: [
      "A: canonical record value renders",
      "A: no object marker",
      "C: no object marker",
      "D: no object marker",
      "D: record-data heading absent when nothing is printable",
      "E: no object marker",
      "E: printable record renders exactly once",
      "global: zero object markers across all rendered PDFs",
    ].sort(),
  },
  {
    // Restores unconditional heading rendering: the "Observed DMARC record
    // data" heading appears even when no record is customer-printable.
    name: "heading renders with zero printable records",
    anchor: "  if (printableRecords.length) {",
    replacement: "  if (appendix.raw_records.length) {",
    expectedFailures: [
      "D: record-data heading absent when nothing is printable",
    ],
  },
];

// Baseline: the validator must be green on unmutated source, or every "kill"
// below would be meaningless.
const baseline = runValidator();
const baselineTotals = summaryTotals(`${baseline.stdout || ""}\n${baseline.stderr || ""}`);
if (baseline.error || baseline.signal !== null || baseline.status !== 0 ||
    !baselineTotals || baselineTotals.pass !== VALIDATOR_ASSERTIONS || baselineTotals.fail !== 0) {
  console.error("FAIL baseline validator run is not green on unmutated source");
  console.error(`${baseline.stdout || ""}\n${baseline.stderr || ""}`.trim());
  process.exit(1);
}
console.log(`PASS baseline validator green (${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS})`);

const original = fs.readFileSync(pdfFile, "utf8");
let killed = 0;
try {
  for (const mutant of mutants) {
    const mutated = replaceExactlyOnce(original, mutant.anchor, mutant.replacement, mutant.name);
    fs.writeFileSync(pdfFile, mutated);
    try {
      const child = runValidator();
      const output = `${child.stdout || ""}\n${child.stderr || ""}`;
      const totals = summaryTotals(output);
      const got = failNames(output);
      const want = [...mutant.expectedFailures].sort();
      const problems = [];
      if (child.error) problems.push(`spawn error: ${child.error.message}`);
      if (child.signal !== null) problems.push(`signal: ${child.signal}`);
      if (child.status !== 1) problems.push(`exit status ${child.status}, want 1`);
      if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module/.test(output)) {
        problems.push("child failed to load, not a behavioural kill");
      }
      if (!totals) {
        problems.push("validator summary missing");
      } else if (totals.pass + totals.fail !== VALIDATOR_ASSERTIONS) {
        problems.push(`assertion total ${totals.pass + totals.fail}, want ${VALIDATOR_ASSERTIONS}`);
      }
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        problems.push(`FAIL set mismatch — got [${got.join(" | ")}] want [${want.join(" | ")}]`);
      }
      if (problems.length) {
        console.error(`FAIL mutant "${mutant.name}" escaped or was killed for the wrong reason`);
        for (const problem of problems) console.error(`  - ${problem}`);
        console.error(output.trim());
      } else {
        killed += 1;
        console.log(`PASS mutant "${mutant.name}" killed by exactly: ${want.join(" | ")}`);
      }
    } finally {
      fs.writeFileSync(pdfFile, original);
    }
  }
} finally {
  fs.writeFileSync(pdfFile, original);
}

if (fs.readFileSync(pdfFile, "utf8") !== original) {
  console.error("FAIL pdf.js was not restored to its original content");
  process.exit(1);
}
if (mutants.length !== EXPECTED_MUTANTS) {
  console.error(`FAIL pinned mutant count — got ${mutants.length} want ${EXPECTED_MUTANTS}`);
  process.exit(1);
}
if (killed !== EXPECTED_MUTANTS) {
  console.error(`PDF-DMARC mutations FAILED: ${killed}/${EXPECTED_MUTANTS} killed for the intended reason`);
  process.exit(1);
}
console.log(`PDF-DMARC mutations passed: ${killed}/${EXPECTED_MUTANTS} killed, each for its exact pinned assertion set`);
