#!/usr/bin/env node
//
// RCE.5 — mutation runner for the CE declaration drift guard. CI-blocking.
//
// A guard is only worth its CI minute if breaking the thing it protects makes it
// go red FOR THE RIGHT REASON. Each mutant below reintroduces exactly one defect
// and pins the exact set of guards that must fail. A mutant dying outside its
// frozen set is a HARNESS DEFECT, not a kill.
//
// UNIT 1 ONLY. `RCE5_M03` (the lib footprint sentence) is deliberately absent —
// it lands with RCE.5 Unit 2 alongside `RCE5_G3`.
//
// ── The compound mutant, and why it exists ──────────────────────────────────
// `RCE5_M05` cannot be killed on its own. Replacing the guard's runtime
// CE_QUESTIONS derivation with a hard-coded list THAT MATCHES CURRENT TRUTH
// leaves every assertion passing, so there is no failure to observe. The defect
// is only visible once the runtime truth MOVES. So M05 is compound:
//
//   control  M04 alone            → the guard MUST go red   (proves the probe is live)
//   compound M05 ∘ M04            → the guard MUST stay green
//
// and the KILL is recorded when the expected failure DOES NOT OCCUR. This is the
// inverse of every other mutant here and is labelled `expectGuardGreen` so a
// naive reader cannot score it backwards.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const rel = (...p) => path.join(root, ...p);
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const readRaw = (f) => fs.readFileSync(rel(f));
const readText = (f) => fs.readFileSync(rel(f), "utf8");

const GUARD = "scripts/validate-ce-declaration-drift.js";
const CASES = "workers/scan-api/src/engines/cyber-essentials-cases.js";
const DOC = "docs/cyber-essentials-readiness.md";
const QUESTIONS = "shared/cyber-essentials-questions.js";   // ⚠ IN the email closure

let pass = 0, fail = 0;
const lines = [];
const ok = (name, cond, detail = "") => {
  if (cond) { pass++; lines.push(`ok   ${name}`); }
  else { fail++; lines.push(`FAIL ${name}${detail ? ` -- ${detail}` : ""}`); }
};

// Run the guard in a FRESH process and return { exitCode, guards } where `guards`
// is the set of guard ids that emitted at least one FAIL.
function runGuard() {
  let stdout = "", code = 0;
  try {
    stdout = execFileSync(process.execPath, [rel(GUARD)], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    stdout = `${e.stdout || ""}${e.stderr || ""}`;
    code = typeof e.status === "number" ? e.status : 1;
  }
  const reachedSummary = /ce-declaration-drift: \d+ passed, \d+ failed/.test(stdout);
  const guards = new Set(
    [...stdout.matchAll(/^FAIL \[([A-Z0-9_]+)\]/gm)].map((m) => m[1]),
  );
  return { code, guards, reachedSummary, stdout };
}

const setEq = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

// ── Mutant definitions ───────────────────────────────────────────────────────
// `edits` is a list of { file, from, to }. Every `from` MUST occur exactly once.
const MUTANTS = [
  {
    id: "RCE5_M01", unit: 1, expect: ["RCE5_G1"],
    why: "the declared count word must track the live `partial` count",
    edits: [{ file: CASES, from: "declares only TWO", to: "declares only THREE" }],
  },
  {
    id: "RCE5_M02", unit: 1, expect: ["RCE5_G2"],
    why: "each declared coverage token must equal the live value",
    edits: [{ file: CASES,
      from: '//   patch_management_readiness  external_coverage "none"     → questionnaire-only',
      to:   '//   patch_management_readiness  external_coverage "partial"  → assessable' }],
  },
  {
    id: "RCE5_M04", unit: 1, expect: ["RCE5_G1", "RCE5_G2"], inClosure: true,
    why: "a reclassification without a declaration update must be caught",
    edits: [{ file: QUESTIONS,
      from: 'control_key: "patch_management_readiness",\n    external_coverage: "none",',
      to:   'control_key: "patch_management_readiness",\n    external_coverage: "partial",' }],
  },
  {
    id: "RCE5_M06", unit: 1, expect: ["RCE5_G4"],
    why: "an executable change must not hide behind a comment corrective",
    edits: [{ file: CASES,
      from: 'export const CE_CASE_TYPE = "cyber_essentials_case";',
      to:   'const __rce5_m06_probe = 1;\nexport const CE_CASE_TYPE = "cyber_essentials_case";' }],
  },
  {
    id: "RCE5_M07", unit: 1, expect: ["RCE5_G5"],
    why: "a withdrawn proxy must not return as a current claim",
    edits: [{ file: CASES,
      from: "// ── THE PARTIAL CEILING ──",
      to:   "// patch_management_readiness is scored from certificate expiry as a proxy signal.\n// ── THE PARTIAL CEILING ──" }],
  },
  {
    id: "RCE5_M08", unit: 1, expect: ["RCE5_G2"],
    why: "B-4 — `.key` yields undefined identifiers while the 2/3 aggregate still looks right",
    edits: [{ file: GUARD,
      from: "  key: c.control_key,                       // control_key — NEVER `.key`",
      to:   "  key: c.key," }],
  },
  {
    id: "RCE5_M09", unit: 1, expect: ["RCE5_G5"],
    why: "proves G5's expanded document scope is live, not decorative",
    edits: [{ file: DOC,
      from: "## Grades",
      to:   "User Access Control is derived from SPF and DMARC as proxy signals.\n\n## Grades" }],
  },
  {
    id: "RCE5_M10", unit: 1, expect: ["RCE5_G5"],
    why: "\"historical\" must not become a generic bypass — non-allowlisted phrasing must still fail",
    edits: [{ file: DOC,
      from: "## Grades",
      to:   "Historically speaking, Malware Protection is based on email authentication evidence.\n\n## Grades" }],
  },
];

// ── Apply / restore with exact-byte restoration proof ────────────────────────
function applyEdits(edits) {
  const originals = new Map();
  for (const e of edits) {
    if (!originals.has(e.file)) originals.set(e.file, readRaw(e.file));
    const text = readText(e.file);
    const occurrences = text.split(e.from).length - 1;
    if (occurrences !== 1) {
      // Restore anything already applied before aborting this mutant.
      for (const [f, buf] of originals) fs.writeFileSync(rel(f), buf);
      return { originals: null, anchorError: `${e.file}: anchor occurs ${occurrences}× (must be exactly 1)` };
    }
    fs.writeFileSync(rel(e.file), text.replace(e.from, e.to));
  }
  return { originals, anchorError: null };
}
function restore(originals) {
  const report = [];
  for (const [f, buf] of originals) {
    fs.writeFileSync(rel(f), buf);
    report.push({ file: f, restored: sha256(readRaw(f)) === sha256(buf) });
  }
  return report;
}

// ── Baseline: the guard must be GREEN before any mutation ───────────────────
const baselineHashes = new Map(
  [GUARD, CASES, DOC, QUESTIONS].map((f) => [f, sha256(readRaw(f))]),
);
const baseline = runGuard();
ok("baseline: the drift guard is green before any mutation",
   baseline.code === 0 && baseline.guards.size === 0,
   `exit ${baseline.code}, failing guards [${[...baseline.guards].join(", ")}]`);
if (baseline.code !== 0) {
  console.log(lines.join("\n"));
  console.error("\nce-declaration-drift-mutations: refusing to run against a non-green baseline");
  process.exit(1);
}

// ── Ordinary mutants ─────────────────────────────────────────────────────────
for (const m of MUTANTS) {
  const { originals, anchorError } = applyEdits(m.edits);
  if (anchorError) { ok(`${m.id}: anchor is exact`, false, anchorError); continue; }
  ok(`${m.id}: anchor is exact and mutated bytes differ`, true);

  const run = runGuard();
  const expected = new Set(m.expect);

  ok(`${m.id}: validator reached its normal summary (not a crash/timeout)`, run.reachedSummary,
     run.stdout.slice(-200));
  ok(`${m.id}: exit code is exactly 1`, run.code === 1, `got ${run.code}`);
  ok(`${m.id}: exact guard FAIL set is {${m.expect.join(", ")}} — ${m.why}`,
     setEq(run.guards, expected),
     `expected [${[...expected].join(", ")}], observed [${[...run.guards].sort().join(", ")}]`);

  const restored = restore(originals);
  ok(`${m.id}: every target byte restored exactly`,
     restored.every((r) => r.restored),
     restored.filter((r) => !r.restored).map((r) => r.file).join(", "));
  if (m.inClosure) {
    ok(`${m.id}: IN-CLOSURE source restored before any closure measurement`,
       sha256(readRaw(QUESTIONS)) === baselineHashes.get(QUESTIONS));
  }
}

// ── RCE5_M05 — compound, semantic kill by ABSENCE ───────────────────────────
{
  const m04 = MUTANTS.find((m) => m.id === "RCE5_M04");

  // Step 1 — CONTROL. M04 alone must make the guard red. If it does not, the probe
  // is dead and the compound result below would be meaningless.
  const c = applyEdits(m04.edits);
  const controlRun = c.anchorError ? null : runGuard();
  ok("RCE5_M05 control: M04 alone makes the guard RED (probe is live)",
     controlRun !== null && controlRun.code === 1 &&
       setEq(controlRun.guards, new Set(["RCE5_G1", "RCE5_G2"])),
     c.anchorError || `exit ${controlRun?.code}, guards [${[...(controlRun?.guards ?? [])].join(", ")}]`);
  if (c.originals) restore(c.originals);

  // Step 2 — COMPOUND. Weaken the guard so its expectation is a hard-coded literal
  // rather than a runtime derivation, then seed the same defect.
  const weaken = {
    file: GUARD,
    from: "const livePartial = liveControls.filter((c) => c.coverage === \"partial\").map((c) => c.key);",
    to: "const livePartial = [\"boundary_protection\", \"secure_configuration\"]; // M05: hard-coded, no longer observes runtime",
  };
  const comp = applyEdits([weaken, ...m04.edits]);
  if (comp.anchorError) {
    ok("RCE5_M05: compound anchors are exact", false, comp.anchorError);
  } else {
    ok("RCE5_M05: compound anchors are exact", true);
    const run = runGuard();
    // THE KILL IS INVERTED: a weakened guard stays GREEN under a seeded defect.
    const weakenedStaysGreen = run.reachedSummary && !run.guards.has("RCE5_G1");
    ok("RCE5_M05 (expectGuardGreen): a hard-coded guard FAILS TO FAIL under M04 — kill by absence",
       weakenedStaysGreen,
       `exit ${run.code}, guards [${[...run.guards].sort().join(", ")}] — G1 should NOT be failing`);
    const restored = restore(comp.originals);
    ok("RCE5_M05: every target byte restored exactly",
       restored.every((r) => r.restored));
  }
}

// ── Final restoration proof — never freeze while a mutant is applied ────────
const drift = [...baselineHashes.entries()]
  .filter(([f, h]) => sha256(readRaw(f)) !== h)
  .map(([f]) => f);
ok("worktree fingerprint restored: every mutated file is byte-identical to baseline",
   drift.length === 0, drift.join(", "));

const final = runGuard();
ok("post-mutation: the drift guard is green again", final.code === 0 && final.guards.size === 0,
   `exit ${final.code}`);

console.log(lines.join("\n"));
console.log(`\nce-declaration-drift-mutations: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("ce-declaration-drift-mutations validation FAILED"); process.exit(1); }
console.log("ce-declaration-drift-mutations validation passed");
