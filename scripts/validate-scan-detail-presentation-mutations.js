#!/usr/bin/env node
// Track A A2+A3 — strict fresh-process mutation proof.
//
// Every mutant changes the real production ScanDetail source, runs the focused
// AST+UI validator in a fresh process, and is accepted only when it exits exactly
// 1 for its exact pinned FAIL-name set. Source bytes and the complete intended
// working-tree diff are restored and SHA-256 checked after the suite.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetRel = "frontend/src/pages/ScanDetail.jsx";
const targetFile = path.join(root, targetRel);
const validator = path.join(root, "scripts", "validate-scan-detail-presentation.js");

const EXPECTED_MUTANTS = 6;
const VALIDATOR_ASSERTIONS = 16;
const SUMMARY_PREFIX = "ScanDetail presentation:";

const AST_RAW = "AST: raw scan.rating cannot feed ScanDetail presentation";
const AST_CANONICAL = "AST: canonical assessment.display_rating feeds band presentation";
const AST_GATE = "AST: comparison claims require changes.comparable === true";
const AST_POSITIVE = "AST: comparable=true score and change path remains reachable";
const UI_A = "UI: A: partial canonical null rating hides the raw good band";
const UI_B = "UI: B: partial non-comparable history hides every relative claim and explains why";
const UI_C_MISSING = "UI: C: missing comparable fails closed";
const UI_C_NULL = "UI: C: null comparable fails closed";
const UI_C_UNKNOWN = "UI: C: unknown comparable fails closed";
const UI_D = "UI: D: complete canonical good rating and comparable history retain positive behavior";
const UI_F = "UI: F: missing canonical assessment never falls back to the raw rating";
const UI_G = "UI: G: observed partial finding stays visible without becoming a new-change claim";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const runGit = (args, encoding = "utf8") => {
  const result = spawnSync("git", args, { cwd: root, encoding });
  if (result.error || result.signal !== null || result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.error?.message || result.stderr || result.signal || result.status}`);
  }
  return result.stdout;
};
const workingTreeFingerprint = () => {
  const status = runGit(["status", "--porcelain=v1", "--untracked-files=all"]);
  const diff = runGit(["diff", "--binary", "--no-ext-diff", "HEAD", "--", "."]);
  const untrackedRaw = runGit(["ls-files", "--others", "--exclude-standard", "-z"], "buffer");
  const untracked = untrackedRaw.toString("utf8").split("\0").filter(Boolean).sort().map((rel) => {
    const bytes = fs.readFileSync(path.join(root, rel));
    return `${rel}\0${sha256(bytes)}`;
  }).join("\n");
  return { status, diff, untracked, hash: sha256(`${status}\0${diff}\0${untracked}`) };
};
const replaceExactlyOnce = (source, anchor, replacement, label) => {
  const first = source.indexOf(anchor);
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor must exist exactly once`);
  }
  const mutated = source.slice(0, first) + replacement + source.slice(first + anchor.length);
  if (mutated === source) throw new Error(`${label}: mutated === original`);
  return mutated;
};
const runValidator = () => spawnSync(process.execPath, [validator], {
  cwd: root,
  encoding: "utf8",
  timeout: 180_000,
});
const failNames = (output) => output
  .split("\n")
  .filter((line) => line.startsWith("FAIL "))
  .map((line) => line.slice(5).split(" — ")[0].trim())
  .sort();
const summaryTotals = (output) => {
  const line = output.split("\n").find((candidate) => candidate.startsWith(SUMMARY_PREFIX));
  if (!line) return null;
  const match = line.match(/(\d+) passed, (\d+) failed \((\d+) total\)/);
  if (!match) return null;
  return { pass: Number(match[1]), fail: Number(match[2]), total: Number(match[3]), line };
};

const ratingAnchor = "  const assessmentRating = assessment?.display_rating ?? null";
const comparableAnchor = "  if (changes.comparable !== true) {";
const deltaAnchor = "  const delta = changes.score_change";
const mutants = [
  {
    name: "raw scan.rating restores the provisional band bypass",
    anchor: ratingAnchor,
    replacement: "  const assessmentRating = scan?.rating ?? assessment?.display_rating ?? null",
    expectedFailures: [AST_RAW, UI_A, UI_F],
  },
  {
    name: "ChangesPanel comparable gate is removed",
    anchor: comparableAnchor,
    replacement: "  if (false) {",
    expectedFailures: [AST_GATE, UI_B, UI_C_MISSING, UI_C_NULL, UI_C_UNKNOWN, UI_G],
  },
  {
    name: "missing and unknown comparable are accepted",
    anchor: comparableAnchor,
    replacement: "  if (changes.comparable === false) {",
    expectedFailures: [AST_GATE, UI_C_MISSING, UI_C_NULL, UI_C_UNKNOWN],
  },
  {
    name: "complete canonical Good band is over-suppressed",
    anchor: ratingAnchor,
    replacement: "  const assessmentRating = null",
    expectedFailures: [AST_CANONICAL, UI_D],
  },
  {
    name: "comparable true positive path is over-suppressed",
    anchor: deltaAnchor,
    replacement: "  if (changes.comparable === true) return null\n\n  const delta = changes.score_change",
    expectedFailures: [AST_POSITIVE, UI_D],
  },
  {
    name: "computed raw rating bypass evades token-only guards",
    anchor: ratingAnchor,
    replacement: "  const assessmentRating = scan?.[\"rating\"] ?? assessment?.display_rating ?? null",
    expectedFailures: [AST_RAW, UI_A, UI_F],
  },
];

const original = fs.readFileSync(targetFile);
const beforeTargetSha = sha256(original);
const beforeTree = workingTreeFingerprint();
let killed = 0;
let suiteFailures = 0;

try {
  if (mutants.length !== EXPECTED_MUTANTS) {
    throw new Error(`pinned mutant count drift: got ${mutants.length}, want ${EXPECTED_MUTANTS}`);
  }

  const baseline = runValidator();
  const baselineOutput = `${baseline.stdout || ""}\n${baseline.stderr || ""}`;
  const baselineTotals = summaryTotals(baselineOutput);
  if (
    baseline.error || baseline.signal !== null || baseline.status !== 0 ||
    !baselineTotals || baselineTotals.pass !== VALIDATOR_ASSERTIONS ||
    baselineTotals.fail !== 0 || baselineTotals.total !== VALIDATOR_ASSERTIONS
  ) {
    throw new Error(`baseline validator is not ${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS} green\n${baselineOutput.trim()}`);
  }
  console.log(`PASS baseline validator green (${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS})`);

  for (const mutant of mutants) {
    const mutated = replaceExactlyOnce(original.toString("utf8"), mutant.anchor, mutant.replacement, mutant.name);
    fs.writeFileSync(targetFile, mutated);
    try {
      const child = runValidator();
      const output = `${child.stdout || ""}\n${child.stderr || ""}`;
      const totals = summaryTotals(output);
      const got = failNames(output);
      const want = [...mutant.expectedFailures].sort();
      const problems = [];
      if (child.error) problems.push(`spawn error: ${child.error.message}`);
      if (child.signal !== null) problems.push(`signal: ${child.signal}`);
      if (child.status !== 1) problems.push(`exit status ${child.status}, want exactly 1`);
      if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|Failed to load url|Transform failed/.test(output)) {
        problems.push("child failed to parse/import/load; not a behavioural kill");
      }
      if (!totals) {
        problems.push("validator summary missing");
      } else {
        if (totals.total !== VALIDATOR_ASSERTIONS) {
          problems.push(`assertion total ${totals.total}, want ${VALIDATOR_ASSERTIONS}`);
        }
        if (totals.fail !== want.length || totals.pass !== VALIDATOR_ASSERTIONS - want.length) {
          problems.push(`summary ${totals.pass} pass/${totals.fail} fail does not match pinned FAIL count ${want.length}`);
        }
      }
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        problems.push(`FAIL set mismatch — got [${got.join(" | ")}] want [${want.join(" | ")}]`);
      }

      if (problems.length) {
        suiteFailures += 1;
        console.error(`FAIL mutant "${mutant.name}" escaped or died for the wrong reason`);
        for (const problem of problems) console.error(`  - ${problem}`);
        console.error(output.trim());
      } else {
        killed += 1;
        console.log(`PASS mutant "${mutant.name}" killed by exactly: ${want.join(" | ")}`);
      }
    } finally {
      fs.writeFileSync(targetFile, original);
    }
  }
} catch (error) {
  suiteFailures += 1;
  console.error(`FAIL mutation suite setup/baseline — ${error.message}`);
} finally {
  fs.writeFileSync(targetFile, original);
}

const afterTarget = fs.readFileSync(targetFile);
const afterTargetSha = sha256(afterTarget);
let afterTree = null;
try {
  afterTree = workingTreeFingerprint();
} catch (error) {
  suiteFailures += 1;
  console.error(`FAIL post-suite working-tree fingerprint — ${error.message}`);
}
if (afterTargetSha !== beforeTargetSha || !afterTarget.equals(original)) {
  suiteFailures += 1;
  console.error(`FAIL production source SHA-256 changed: before=${beforeTargetSha} after=${afterTargetSha}`);
} else {
  console.log(`PASS production source SHA-256 restored exactly (${afterTargetSha})`);
}
if (!afterTree || afterTree.hash !== beforeTree.hash || afterTree.status !== beforeTree.status ||
    afterTree.diff !== beforeTree.diff || afterTree.untracked !== beforeTree.untracked) {
  suiteFailures += 1;
  console.error(`FAIL working-tree diff changed: before=${beforeTree.hash} after=${afterTree?.hash || "unavailable"}`);
} else {
  console.log(`PASS working-tree diff restored exactly (${afterTree.hash})`);
}

if (killed !== EXPECTED_MUTANTS || suiteFailures > 0) {
  console.error(`ScanDetail presentation mutations FAILED: ${killed}/${EXPECTED_MUTANTS} exact kills; suite failures=${suiteFailures}`);
  process.exit(1);
}
console.log(`ScanDetail presentation mutations passed: ${killed}/${EXPECTED_MUTANTS} killed with exact FAIL sets, exit 1, no signal/load/syntax/wrong-reason kill`);
