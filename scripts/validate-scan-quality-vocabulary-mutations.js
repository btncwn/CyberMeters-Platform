#!/usr/bin/env node
// CT-R2 PR-1 — strict fresh-process mutation proof for the vocabulary inventory.
//
// Each mutant edits a real governed source, starts a fresh validator process and
// is accepted only for one exact FAIL name. Parse/import/load failures and any
// wrong-reason kill are rejected. All bytes and the complete worktree fingerprint
// are restored before exit.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-scan-quality-vocabulary-inventory.js");
const runtimeTargetRel = "workers/scan-api/src/engines/asm-cases.js";
const commentTargetRel = "frontend/src/pages/Dashboard.jsx";
const sqlTargetRel = "workers/scan-api/src/engines/business-risk.js";
const EXPECTED_MUTANTS = 8;
const VALIDATOR_ASSERTIONS = 7;
const EXPECTED_ASSERTIONS = 29;
const SUMMARY_PREFIX = "Scan-quality vocabulary inventory:";
const RUNTIME_FAILURE = "runtime: semantic scan-quality comparison inventory is exact";
const SQL_FAILURE = "SQL: runtime scan-quality predicate inventory is exact";
const CLASSIFICATION_FAILURE = "classification: no scan-quality gate is unclassified or uses an unknown status";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const runGit = (args, encoding = "utf8") => {
  const result = spawnSync("git", args, { cwd: root, encoding });
  if (result.error || result.signal !== null || result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.error?.message || result.stderr || result.signal || result.status}`);
  }
  return result.stdout;
};
const worktreeFingerprint = () => {
  const status = runGit(["status", "--porcelain=v1", "--untracked-files=all"]);
  const diff = runGit(["diff", "--binary", "--no-ext-diff", "HEAD", "--", "."]);
  const untrackedRaw = runGit(["ls-files", "--others", "--exclude-standard", "-z"], "buffer");
  const untracked = untrackedRaw.toString("utf8").split("\0").filter(Boolean).sort().map((relative) =>
    `${relative}\0${sha256(fs.readFileSync(path.join(root, relative)))}`).join("\n");
  return sha256(`${status}\0${diff}\0${untracked}`);
};
const replaceExactlyOnce = (source, anchor, replacement, name) => {
  const first = source.indexOf(anchor);
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${name}: mutation anchor must exist exactly once`);
  }
  return source.slice(0, first) + replacement + source.slice(first + anchor.length);
};
const appendMutation = (source, addition) => `${source.trimEnd()}\n\n${addition}\n`;
const runValidator = () => spawnSync(process.execPath, [validator], {
  cwd: root,
  encoding: "utf8",
  timeout: 180_000,
});
const failNames = (output) => output.split("\n")
  .filter((line) => line.startsWith("FAIL "))
  .map((line) => line.slice(5).split(" — ")[0].trim())
  .filter((name) => name !== "pinned assertion count")
  .sort();
const summaryTotals = (output) => {
  const line = output.split("\n").find((candidate) => candidate.startsWith(SUMMARY_PREFIX));
  if (!line) return null;
  const match = line.match(/(\d+) passed, (\d+) failed \((\d+) total\)/);
  return match ? { pass: Number(match[1]), fail: Number(match[2]), total: Number(match[3]) } : null;
};

const mutations = [
  {
    name: "await-less scan_quality member access adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `// CT-R2 mutation: deliberately no await.
const ctR2AwaitlessRow = Promise.resolve({ scan_quality: "complete" });
export const ctR2AwaitlessGate = ctR2AwaitlessRow.scan_quality === "complete";`),
    expectedFailure: RUNTIME_FAILURE,
  },
  {
    name: "local alias propagation adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2AliasCarrier = { scan_quality: "complete" };
const ctR2AliasedQuality = ctR2AliasCarrier.scan_quality;
export const ctR2AliasGate = ctR2AliasedQuality === "complete";`),
    expectedFailure: RUNTIME_FAILURE,
  },
  {
    name: "computed scan_quality access adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2ComputedCarrier = { scan_quality: "complete" };
export const ctR2ComputedGate = ctR2ComputedCarrier["scan_quality"] === "complete";`),
    expectedFailure: RUNTIME_FAILURE,
  },
  {
    name: "destructured scan_quality alias adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2DestructuredCarrier = { scan_quality: "complete" };
const { scan_quality: ctR2DestructuredQuality } = ctR2DestructuredCarrier;
export const ctR2DestructuredGate = ctR2DestructuredQuality === "complete";`),
    expectedFailure: RUNTIME_FAILURE,
  },
  {
    name: "new partial-only gate is rejected",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2PartialCarrier = { scan_quality: "partial" };
export const ctR2PartialOnlyGate = ctR2PartialCarrier.scan_quality === "partial";`),
    expectedFailure: RUNTIME_FAILURE,
  },
  {
    name: "unknown scan-quality status gate fails closed",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2UnknownCarrier = { scan_quality: "provider_degraded" };
export const ctR2UnknownStatusGate = ctR2UnknownCarrier.scan_quality === "provider_degraded";`),
    expectedFailure: CLASSIFICATION_FAILURE,
  },
  {
    name: "comment and string cannot impersonate a removed caller",
    file: commentTargetRel,
    mutate: (source) => replaceExactlyOnce(
      source,
      "  const authoritative = completed.find(s => s.scan_quality === 'complete') || null",
      `  // const authoritative = completed.find(s => s.scan_quality === 'complete') || null
  void "completed.find(s => s.scan_quality === 'complete')"
  const authoritative = null`,
      "comment and string cannot impersonate a removed caller",
    ),
    expectedFailure: RUNTIME_FAILURE,
  },
  {
    name: "reversed SQL predicate variation adds an unreviewed query site",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source,
      `export const CT_R2_MUTANT_SQL = "SELECT id FROM scans s WHERE ( 'complete' = s.scan_quality )";`),
    expectedFailure: SQL_FAILURE,
  },
];

let assertionsPassed = 0;
let assertionsFailed = 0;
const assertion = (name, condition, detail = "") => {
  if (condition) {
    assertionsPassed += 1;
    console.log(`PASS ${name}`);
  } else {
    assertionsFailed += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const targetFiles = [...new Set(mutations.map((mutation) => mutation.file))];
const originals = new Map(targetFiles.map((relative) => [
  relative, fs.readFileSync(path.join(root, relative)),
]));
const beforeTree = worktreeFingerprint();
let killed = 0;

try {
  const baseline = runValidator();
  const baselineOutput = `${baseline.stdout || ""}\n${baseline.stderr || ""}`;
  const baselineTotals = summaryTotals(baselineOutput);
  assertion(
    `baseline validator is ${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS} green`,
    !baseline.error && baseline.signal === null && baseline.status === 0 &&
      baselineTotals?.pass === VALIDATOR_ASSERTIONS && baselineTotals.fail === 0 &&
      baselineTotals.total === VALIDATOR_ASSERTIONS,
    baselineOutput.trim(),
  );

  for (const mutation of mutations) {
    const target = path.join(root, mutation.file);
    const original = originals.get(mutation.file);
    const originalText = original.toString("utf8");
    let mutated = originalText;
    try {
      mutated = mutation.mutate(originalText);
      assertion(`${mutation.name}: mutation applied`, mutated !== originalText);
      fs.writeFileSync(target, mutated);

      const child = runValidator();
      const output = `${child.stdout || ""}\n${child.stderr || ""}`;
      const totals = summaryTotals(output);
      const gotFailures = failNames(output);
      const expectedFailures = [mutation.expectedFailure].sort();
      const problems = [];
      if (child.error) problems.push(`spawn error ${child.error.message}`);
      if (child.signal !== null) problems.push(`signal ${child.signal}`);
      if (child.status !== 1) problems.push(`exit ${child.status}, want exactly 1`);
      if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|Transform failed/.test(output)) {
        problems.push("parse/import/load failure is not an inventory kill");
      }
      if (!totals) problems.push("validator summary missing");
      else {
        if (totals.total !== VALIDATOR_ASSERTIONS) problems.push(`assertions ${totals.total}, want ${VALIDATOR_ASSERTIONS}`);
        if (totals.fail !== 1 || totals.pass !== VALIDATOR_ASSERTIONS - 1) {
          problems.push(`summary ${totals.pass}/${totals.fail}, want ${VALIDATOR_ASSERTIONS - 1}/1`);
        }
      }
      if (JSON.stringify(gotFailures) !== JSON.stringify(expectedFailures)) {
        problems.push(`FAIL set [${gotFailures.join(" | ")}] want [${expectedFailures.join(" | ")}]`);
      }
      const exactKill = problems.length === 0;
      assertion(`${mutation.name}: killed only by target assertion`, exactKill, problems.join("; "));
      if (exactKill) killed += 1;
    } catch (error) {
      assertion(`${mutation.name}: killed only by target assertion`, false, error.message);
    } finally {
      fs.writeFileSync(target, original);
      assertion(
        `${mutation.name}: target bytes restored`,
        sha256(fs.readFileSync(target)) === sha256(original),
      );
    }
  }
} finally {
  for (const [relative, bytes] of originals) fs.writeFileSync(path.join(root, relative), bytes);
}

assertion("all target files restored", targetFiles.every((relative) =>
  sha256(fs.readFileSync(path.join(root, relative))) === sha256(originals.get(relative))));
assertion("complete worktree fingerprint restored", worktreeFingerprint() === beforeTree);
assertion(`mutants killed ${killed}/${EXPECTED_MUTANTS}`, killed === EXPECTED_MUTANTS);
assertion("mutant table count is pinned", mutations.length === EXPECTED_MUTANTS);

const assertionTotal = assertionsPassed + assertionsFailed;
console.log(`\nScan-quality vocabulary mutations: mutants ${killed}/${EXPECTED_MUTANTS}; assertions ${assertionsPassed}/${assertionTotal}`);
if (assertionTotal !== EXPECTED_ASSERTIONS) {
  console.error(`FAIL pinned mutation assertion count — got ${assertionTotal}, want ${EXPECTED_ASSERTIONS}`);
  process.exit(1);
}
if (assertionsFailed > 0 || killed !== EXPECTED_MUTANTS) process.exit(1);
console.log("Scan-quality vocabulary mutation proof passed");
