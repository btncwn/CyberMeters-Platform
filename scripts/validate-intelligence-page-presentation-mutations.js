#!/usr/bin/env node
// TRACK-A3 — strict fresh-process mutation proof for IntelligencePage.
//
// Every mutant edits the real production source serially, invokes the combined
// AST+React validator in a fresh process, and counts only an exact behavioral
// FAIL set with exit 1. Parse/import/spawn/signal failures are never kills.
// Source bytes and the entire intended working-tree fingerprint are restored.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetRel = "frontend/src/pages/IntelligencePage.jsx";
const targetFile = path.join(root, targetRel);
const validator = path.join(root, "scripts", "validate-intelligence-page-presentation.js");

const EXPECTED_MUTANTS = 9;
const EXPECTED_LEGACY_SURVIVORS = 2;
const VALIDATOR_ASSERTIONS = 27;
const SUMMARY_PREFIX = "IntelligencePage presentation:";

const AST_INVENTORY = "AST: assessment-critical field inventory is pinned across the local closure";
const AST_RAW_RATING = "AST: raw stored scan.rating cannot feed IntelligencePage or child helpers";
const AST_RAW_SCORE = "AST: raw stored scan.score cannot feed IntelligencePage or child helpers";
const AST_RATING = "AST: canonical display_rating reaches bandMeta label metadata and is never printed raw";
const AST_SCORE = "AST: only finite canonical display_score reaches both score renderers";
const AST_PROVISIONAL = "AST: provisional score requires canonical provisional === true and explicit customer copy";
const AST_REASON = "AST: non-comparable reason is backend-verbatim priority with no frontend cause inference";
const AST_GATE = "AST: all historical claims require changes.comparable === true";
const AST_POSITIVE = "AST: comparable=true score/change/unchanged positive path remains reachable";
const UI_A = "UI: A: partial raw excellent/99 with null canonical rating and score fails closed";
const UI_B = "UI: B: partial canonical provisional score remains visible with an explicit label";
const UI_C = "UI: C: complete authoritative canonical good assessment remains visible";
const UI_E = "UI: E: comparable false suppresses every historical claim";
const UI_F1 = "UI: F1: null comparable fails closed";
const UI_F2 = "UI: F2: missing comparable fails closed";
const UI_F3 = "UI: F3: unknown comparable fails closed";
const UI_G = "UI: G: backend non-comparable message is rendered verbatim without frontend causality";
const UI_H = "UI: H: positive observed finding remains visible without a new or resolved claim";
const UI_I = "UI: I: missing canonical assessment never falls back to raw report or stored values";
const UI_J = "UI: J: unknown rating and non-finite canonical score fail closed";

const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
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
  const untracked = untrackedRaw.toString("utf8").split("\0").filter(Boolean).sort().map(rel => {
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
  if (mutated === source) throw new Error(`${label}: mutated source is unchanged`);
  return mutated;
};
const runValidator = () => spawnSync(process.execPath, [validator], {
  cwd: root,
  encoding: "utf8",
  timeout: 180_000,
});
const failNames = output => output.split("\n")
  .filter(line => line.startsWith("FAIL "))
  .map(line => line.slice(5).split(" — ")[0].trim())
  .sort();
const summaryTotals = output => {
  const line = output.split("\n").find(candidate => candidate.startsWith(SUMMARY_PREFIX));
  const match = line?.match(/(\d+) passed, (\d+) failed \((\d+) total\)/);
  return match ? { pass: Number(match[1]), fail: Number(match[2]), total: Number(match[3]) } : null;
};

const presentationAnchor = "  const assessmentPresentation = canonicalAssessmentPresentation(assessment)";
const bandAnchor = "  const band = bandMeta(assessment?.display_rating)";
const scoreAnchor = `  const score = Number.isFinite(assessment?.display_score)
    ? assessment.display_score
    : null`;
const comparableAnchor = "  if (changes.comparable !== true) {";
const positiveAnchor = "  const previousScore = Number.isFinite(changes.previous_score) ? changes.previous_score : null";
const contextScoreAnchor = `              <span className="text-gray-500">
                {assessmentPresentation.provisional && assessmentPresentation.score != null ? 'Provisional score ' : 'Score '}
                {assessmentPresentation.score ?? '—'}/100
              </span>`;
const reasonAnchor = `function nonComparableReason(assessment, scanQuality) {
  if (typeof assessment?.message === 'string' && assessment.message.trim()) {
    return assessment.message
  }

  const warning = Array.isArray(scanQuality?.warnings)
    ? scanQuality.warnings.find(item => typeof item === 'string' && item.trim())
    : null
  if (warning) return warning

  return 'Historical changes are unavailable because this assessment is not explicitly comparable.'
}`;

const mutants = [
  {
    name: "raw stored rating fallback restores an internal enum",
    anchor: presentationAnchor,
    replacement: `  const assessmentPresentation = canonicalAssessmentPresentation({
    ...assessment,
    display_rating: assessment?.display_rating ?? storedScanObj?.rating ?? null,
  })`,
    expectedFailures: [AST_INVENTORY, AST_RAW_RATING, AST_RATING, UI_A, UI_B, UI_I],
  },
  {
    name: "destructured raw stored score bypass replaces canonical context score",
    anchor: presentationAnchor,
    replacement: `  const { score: storedScore } = storedScanObj ?? {}
  const assessmentPresentation = {
    ...canonicalAssessmentPresentation(assessment),
    score: Number.isFinite(storedScore) ? storedScore : null,
  }`,
    expectedFailures: [AST_INVENTORY, AST_RAW_SCORE, UI_A, UI_B, UI_C, UI_I, UI_J],
  },
  {
    name: "explicit comparable gate is removed",
    anchor: comparableAnchor,
    replacement: "  if (false) {",
    expectedFailures: [AST_INVENTORY, AST_GATE, UI_E, UI_F1, UI_F2, UI_F3, UI_G, UI_H],
  },
  {
    name: "frontend skipped-module inference overrides backend reason",
    anchor: reasonAnchor,
    replacement: `function nonComparableReason(assessment, scanQuality) {
  const skipped = Array.isArray(scanQuality?.modules_skipped)
    ? scanQuality.modules_skipped.filter(Boolean)
    : []
  if (skipped.length) return skipped[0] + ' caused this comparison to be unavailable.'
  if (typeof assessment?.message === 'string' && assessment.message.trim()) return assessment.message
  return 'Comparison unavailable.'
}`,
    expectedFailures: [AST_INVENTORY, AST_REASON, UI_G],
  },
  {
    name: "canonical complete band positive control is suppressed",
    anchor: bandAnchor,
    replacement: "  const band = bandMeta(null)",
    expectedFailures: [AST_INVENTORY, AST_RATING, UI_C],
  },
  {
    name: "canonical provisional numeric score is suppressed",
    anchor: scoreAnchor,
    replacement: `  const score = assessment?.provisional === true
    ? null
    : Number.isFinite(assessment?.display_score)
      ? assessment.display_score
      : null`,
    expectedFailures: [AST_INVENTORY, AST_PROVISIONAL, UI_B],
  },
  {
    name: "computed raw rating bypass defeats the legacy token guard",
    anchor: presentationAnchor,
    replacement: `  const assessmentPresentation = canonicalAssessmentPresentation({
    ...assessment,
    display_rating: assessment?.display_rating ?? storedScanObj?.["rating"] ?? null,
  })`,
    legacyGuardSurvivor: true,
    expectedFailures: [AST_INVENTORY, AST_RAW_RATING, AST_RATING, UI_A, UI_B, UI_I],
  },
  {
    name: "arrow JSX helper launders a computed raw score",
    edits: [
      {
        anchor: presentationAnchor,
        replacement: `  const RawScore = ({ row }) => <span>{row["score"]}/100</span>
${presentationAnchor}`,
      },
      {
        anchor: contextScoreAnchor,
        replacement: `${contextScoreAnchor}
              <RawScore row={storedScanObj} />`,
      },
    ],
    legacyGuardSurvivor: true,
    expectedFailures: [AST_INVENTORY, AST_RAW_SCORE, UI_A, UI_B, UI_C, UI_I, UI_J],
  },
  {
    name: "function-expression helper launders a direct raw score argument",
    anchor: presentationAnchor,
    replacement: `  const rawStoredScore = function (row) { return row?.["score"] }
  const assessmentPresentation = {
    ...canonicalAssessmentPresentation(assessment),
    score: rawStoredScore(storedScanObj),
  }`,
    expectedFailures: [AST_INVENTORY, AST_RAW_SCORE, UI_A, UI_B, UI_C, UI_I, UI_J],
  },
];

// This models the old loose guard class: it only noticed the literal dot token.
// The computed-property mutant must pass it, then die specifically in the AST guard.
const legacyLooseGuard = source =>
  !source.includes("storedScanObj?.rating") && !source.includes("scan?.rating") &&
  !source.includes("storedScanObj?.score") && !source.includes("scan?.score");

const original = fs.readFileSync(targetFile);
const originalText = original.toString("utf8");
const beforeTargetSha = sha256(original);
const beforeTree = workingTreeFingerprint();
let killed = 0;
let legacySurvivors = 0;
let suiteFailures = 0;

try {
  if (mutants.length !== EXPECTED_MUTANTS) {
    throw new Error(`pinned mutant count drift: got ${mutants.length}, want ${EXPECTED_MUTANTS}`);
  }

  const baseline = runValidator();
  const baselineOutput = `${baseline.stdout || ""}\n${baseline.stderr || ""}`;
  const baselineTotals = summaryTotals(baselineOutput);
  if (baseline.error || baseline.signal !== null || baseline.status !== 0 ||
      !baselineTotals || baselineTotals.pass !== VALIDATOR_ASSERTIONS || baselineTotals.fail !== 0 ||
      baselineTotals.total !== VALIDATOR_ASSERTIONS) {
    throw new Error(`baseline validator is not ${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS} green\n${baselineOutput.trim()}`);
  }
  console.log(`PASS baseline validator green (${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS})`);

  for (const mutant of mutants) {
    const edits = mutant.edits ?? [{ anchor: mutant.anchor, replacement: mutant.replacement }];
    let mutated = originalText;
    edits.forEach((edit, index) => {
      mutated = replaceExactlyOnce(mutated, edit.anchor, edit.replacement, `${mutant.name} edit ${index + 1}`);
    });
    if (mutant.legacyGuardSurvivor) {
      if (legacyLooseGuard(mutated)) {
        legacySurvivors += 1;
        console.log(`PASS legacy loose guard would accept mutant "${mutant.name}"`);
      } else {
        suiteFailures += 1;
        console.error(`FAIL legacy loose guard unexpectedly rejected mutant "${mutant.name}"`);
      }
    }

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
        problems.push("child parse/import/load failure is not a behavioral kill");
      }
      if (!totals) {
        problems.push("validator summary missing");
      } else {
        if (totals.total !== VALIDATOR_ASSERTIONS) problems.push(`assertion total ${totals.total}, want ${VALIDATOR_ASSERTIONS}`);
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
  console.error(`FAIL working-tree fingerprint changed: before=${beforeTree.hash} after=${afterTree?.hash || "unavailable"}`);
} else {
  console.log(`PASS working-tree fingerprint restored exactly (${afterTree.hash})`);
}
if (legacySurvivors !== EXPECTED_LEGACY_SURVIVORS) {
  suiteFailures += 1;
  console.error(`FAIL legacy-survivor proof count ${legacySurvivors}, want ${EXPECTED_LEGACY_SURVIVORS}`);
} else {
  console.log(`PASS legacy-survivor proof pinned (${legacySurvivors}/${EXPECTED_LEGACY_SURVIVORS})`);
}

if (killed !== EXPECTED_MUTANTS || suiteFailures > 0) {
  console.error(`IntelligencePage presentation mutations FAILED: ${killed}/${EXPECTED_MUTANTS} exact kills; suite failures=${suiteFailures}`);
  process.exit(1);
}
console.log(`IntelligencePage presentation mutations passed: ${killed}/${EXPECTED_MUTANTS} exact kills; no wrong-reason/load/syntax/spawn failures; zero artifacts`);
