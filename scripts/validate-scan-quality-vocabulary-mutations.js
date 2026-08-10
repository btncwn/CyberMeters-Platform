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
const EXPECTED_MUTANTS = 21;
const VALIDATOR_ASSERTIONS = 10;
const EXPECTED_ASSERTIONS = 70;
const SUMMARY_PREFIX = "Scan-quality vocabulary inventory:";
const RUNTIME_FAILURE = "runtime: semantic scan-quality comparison inventory is exact";
const SQL_FAILURE = "SQL: runtime scan-quality predicate inventory is exact";
const DIRECT_RUNTIME_FAILURE = "primary: runtime canonical direct-read inventory is exact";
const SQL_READ_FAILURE = "SQL: direct read/projection inventory is exact";
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
  const untracked = untrackedRaw.toString("utf8").split("\0").filter(Boolean).sort()
    .filter((relative) => fs.statSync(path.join(root, relative)).isFile())
    .map((relative) => `${relative}\0${sha256(fs.readFileSync(path.join(root, relative)))}`)
    .join("\n");
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
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "local alias propagation adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2AliasCarrier = { scan_quality: "complete" };
const ctR2AliasedQuality = ctR2AliasCarrier.scan_quality;
export const ctR2AliasGate = ctR2AliasedQuality === "complete";`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "computed scan_quality access adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2ComputedCarrier = { scan_quality: "complete" };
export const ctR2ComputedGate = ctR2ComputedCarrier["scan_quality"] === "complete";`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "destructured scan_quality alias adds an unreviewed gate",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2DestructuredCarrier = { scan_quality: "complete" };
const { scan_quality: ctR2DestructuredQuality } = ctR2DestructuredCarrier;
export const ctR2DestructuredGate = ctR2DestructuredQuality === "complete";`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "new partial-only gate is rejected",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2PartialCarrier = { scan_quality: "partial" };
export const ctR2PartialOnlyGate = ctR2PartialCarrier.scan_quality === "partial";`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "unknown scan-quality status gate fails closed",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2UnknownCarrier = { scan_quality: "provider_degraded" };
export const ctR2UnknownStatusGate = ctR2UnknownCarrier.scan_quality === "provider_degraded";`),
    expectedFailures: [CLASSIFICATION_FAILURE, DIRECT_RUNTIME_FAILURE],
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
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "reversed SQL predicate variation adds an unreviewed query site",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source,
      `export const CT_R2_MUTANT_SQL = "SELECT id FROM scans s WHERE ( 'complete' = s.scan_quality )";`),
    expectedFailure: SQL_FAILURE,
  },
  {
    name: "B1 renamed SQL fragment adds an unreviewed query site",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source, `export const ctR2RenamedFragmentGate = (db) => {
  const COMPLETE_FILTER = "SELECT id FROM scans WHERE scan_quality = 'complete'";
  return db.prepare(COMPLETE_FILTER).first();
};`),
    expectedFailure: SQL_FAILURE,
  },
  {
    name: "B2 arbitrary object property carries scan_quality taint",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2ArbitraryCarrierRow = { scan_quality: "partial" };
const ctR2ArbitraryCarrier = { q: ctR2ArbitraryCarrierRow.scan_quality };
export const ctR2ArbitraryPropertyGate = ctR2ArbitraryCarrier.q === "partial";`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "B3 wrapped SQL predicate is inventory-visible",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source, `export const ctR2WrappedSqlGate = (db) =>
  db.prepare("SELECT id FROM scans WHERE LOWER(scan_quality) = 'complete' OR TRIM(scan_quality) = 'partial' OR COALESCE(scan_quality, 'partial') = 'complete'").first();`),
    expectedFailure: SQL_FAILURE,
  },
  {
    name: "B4 array laundering carries scan_quality taint",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2ArrayCarrierRow = { scan_quality: "partial" };
const ctR2ArrayCarrier = [ctR2ArrayCarrierRow.scan_quality];
export const ctR2ArrayLaunderingGate = ctR2ArrayCarrier[0] === "partial";`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "B5 Map laundering carries scan_quality taint",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2MapCarrierRow = { scan_quality: "complete" };
const ctR2MapCarrier = new Map();
ctR2MapCarrier.set("quality", ctR2MapCarrierRow.scan_quality);
export const ctR2MapLaunderingGate = [...ctR2MapCarrier.values()].filter((v) => v === "complete");`),
    expectedFailures: [RUNTIME_FAILURE, DIRECT_RUNTIME_FAILURE],
  },
  {
    name: "A comparison-free dot read is pinned by the primary direct-read inventory",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2DirectDotProject = (row) => ({ quality: row.scan_quality });`),
    expectedFailure: DIRECT_RUNTIME_FAILURE,
  },
  {
    name: "B static computed read is pinned by the primary direct-read inventory",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2DirectKey = "scan_quality";
const ctR2DirectComputedProject = (row) => row[ctR2DirectKey];`),
    expectedFailure: DIRECT_RUNTIME_FAILURE,
  },
  {
    name: "C destructuring read is pinned by the primary direct-read inventory",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2DirectDestructure = (row) => {
  const { scan_quality: quality } = row;
  return quality;
};`),
    expectedFailure: DIRECT_RUNTIME_FAILURE,
  },
  {
    name: "D SQL projection read is pinned without changing predicate count",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source, `export const ctR2ProjectionSql = "SELECT scan_quality FROM scans LIMIT 1";`),
    expectedFailure: SQL_READ_FAILURE,
  },
  {
    name: "E split static array.join SQL is pinned by read and predicate inventories",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source, `export const ctR2JoinedSql = (db) => {
  const parts = ["SELECT id FROM scans WHERE ", "scan_", "quality", " = ", "'complete'"];
  return db.prepare(parts.join("")).first();
};`),
    expectedFailure: SQL_FAILURE,
  },
  {
    name: "P1-1 symbol-scoped computed key is pinned",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `const ctR2Key = "scan_quality";
export const ctR2SymbolRead = (row) => row[ctR2Key];
{ const ctR2Key = "not_quality"; void ctR2Key; }`),
    expectedFailure: DIRECT_RUNTIME_FAILURE,
  },
  {
    name: "P1-2 bare SQL projection fragment is pinned",
    file: sqlTargetRel,
    mutate: (source) => appendMutation(source, `export const CT_R2_BARE_PROJECTION = "s.id, s.scan_quality, s.created_at";`),
    expectedFailure: SQL_READ_FAILURE,
  },
  {
    name: "P2 write-only direct access remains a negative control",
    file: runtimeTargetRel,
    mutate: (source) => appendMutation(source, `export const ctR2WriteOnly = (row) => { row.scan_quality = "partial"; };`),
    expectedFailures: [],
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
let negativeControlsGreen = 0;

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
      const expectedFailures = [...(mutation.expectedFailures || [mutation.expectedFailure])].sort();
      const problems = [];
      if (child.error) problems.push(`spawn error ${child.error.message}`);
      if (child.signal !== null) problems.push(`signal ${child.signal}`);
      const expectedExit = expectedFailures.length === 0 ? 0 : 1;
      if (child.status !== expectedExit) problems.push(`exit ${child.status}, want exactly ${expectedExit}`);
      if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|Transform failed/.test(output)) {
        problems.push("parse/import/load failure is not an inventory kill");
      }
      if (!totals) problems.push("validator summary missing");
      else {
        if (totals.total !== VALIDATOR_ASSERTIONS) problems.push(`assertions ${totals.total}, want ${VALIDATOR_ASSERTIONS}`);
        if (totals.fail !== expectedFailures.length || totals.pass !== VALIDATOR_ASSERTIONS - expectedFailures.length) {
          problems.push(`summary ${totals.pass}/${totals.fail}, want ${VALIDATOR_ASSERTIONS - expectedFailures.length}/${expectedFailures.length}`);
        }
      }
      if (JSON.stringify(gotFailures) !== JSON.stringify(expectedFailures)) {
        problems.push(`FAIL set [${gotFailures.join(" | ")}] want [${expectedFailures.join(" | ")}]`);
      }
      const exactKill = problems.length === 0;
      assertion(`${mutation.name}: killed only by target assertion`, exactKill, problems.join("; "));
      if (exactKill) {
        if (expectedFailures.length === 0) negativeControlsGreen += 1;
        else killed += 1;
      }
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
assertion("killing mutants killed 20/20", killed === 20);
assertion("negative controls green 1/1", negativeControlsGreen === 1);
assertion("governed cases validated 21/21", killed + negativeControlsGreen === 21);
assertion("mutant table count is pinned", mutations.length === 21);

const assertionTotal = assertionsPassed + assertionsFailed;
console.log(`\nScan-quality vocabulary mutations: killing ${killed}/20; negative controls ${negativeControlsGreen}/1; cases ${killed + negativeControlsGreen}/21; assertions ${assertionsPassed}/${assertionTotal}`);
if (assertionTotal !== EXPECTED_ASSERTIONS) {
  console.error(`FAIL pinned mutation assertion count — got ${assertionTotal}, want ${EXPECTED_ASSERTIONS}`);
  process.exit(1);
}
if (assertionsFailed > 0 || killed !== 20 || negativeControlsGreen !== 1) process.exit(1);
console.log("Scan-quality vocabulary mutation proof passed");
