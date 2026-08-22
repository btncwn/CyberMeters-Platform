#!/usr/bin/env node
//
// BL-1 — MUTATION PROOF. Node 24+.
//
// DISPOSABLE WORKTREE ONLY. Every mutation is applied inside a throwaway `git
// worktree`, never the checkout you are standing in. A mutation harness that edits
// the live tree can leave a mutant behind if it dies mid-run, and any measurement
// taken while it runs reads a mutated source — both have bitten this repository
// before. The worktree is removed in `finally`.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };

const VALIDATOR = "scripts/validate-bl1-shadow-it-first-observation.js";

// [id, file, find, replace, mustFailAssertion]
const MUTANTS = [
  // THE CORE CLAIM: remove the occurrence emit -> the digest goes silent again.
  ["BL1-M1-first-observation-reader-returns-nothing",
    "workers/scan-api/src/engines/weekly-digest.js",
    "    return { count: deduped.length, items: deduped, evaluated: true };",
    "    return { count: 0, items: [], evaluated: true };",
    "BL1_P1_DIGEST_RENDERS_THE_SECTION"],
  // Drop the `created` filter -> every re-observation re-surfaces as "newly observed".
  ["BL1-M2-created-filter-dropped",
    "workers/scan-api/src/engines/weekly-digest.js",
    "            AND json_extract(e.detail_json, '$.created') = 1\n",
    "",
    "BL1_P2_TECHNOLOGY_NAMED_EXACTLY_ONCE"],
  // Drop the unreviewed filter -> a REVIEWED technology is called "not yet reviewed".
  ["BL1-M3-unreviewed-filter-dropped",
    "workers/scan-api/src/engines/weekly-digest.js",
    "            AND i.classification = 'unreviewed'\n",
    "",
    "BL1_P3_REVIEWED_TECH_IS_NOT_NEWLY_OBSERVED"],
  // Drop workspace scoping -> cross-tenant leak.
  ["BL1-M4-workspace-scope-dropped",
    "workers/scan-api/src/engines/weekly-digest.js",
    "          WHERE e.workspace_id = ?\n            AND i.workspace_id = ?\n",
    "          WHERE (e.workspace_id = ? OR 1=1)\n            AND (i.workspace_id = ? OR 1=1)\n",
    "BL1_P4_FOREIGN_TECH_ABSENT_FROM_MY_DIGEST"],
  // The wrapper is what carries the section onto the quiet-week branch.
  ["BL1-M5-section-not-appended-to-every-branch",
    "workers/scan-api/src/engines/weekly-digest.js",
    "  return withFirstObservations(email, changes, origin, workspaceId);",
    "  return email;",
    "BL1_P1_SECTION_SURVIVES_A_ZERO_CHANGE_WEEK"],
  // Fail-open on an unreadable window would invent "no new technology this week".
  ["BL1-M6-unreadable-window-reports-zero",
    "workers/scan-api/src/engines/weekly-digest.js",
    "    return { count: null, items: [], evaluated: false };",
    "    return { count: 0, items: [], evaluated: true };",
    "BL1_FAILCLOSED_UNREADABLE_WINDOW_IS_NOT_EVALUATED"],
  // The in-app indicator must not disagree with the digest.
  ["BL1-M7-indicator-ignores-classification",
    "workers/scan-api/src/engines/shadow-it-inventory.js",
    "                CASE WHEN i.classification = 'unreviewed'",
    "                CASE WHEN 1 = 1",
    "BL1_P4_INDICATOR_CLEAR_FOR_REVIEWED"],
];

// Cosmetic edits that MUST survive — a suite that dies on a comment proves nothing.
const CONTROLS = [
  ["C1-comment-wording", "workers/scan-api/src/engines/weekly-digest.js",
    "// BL-1 — first-observation surfacing.", "// BL-1 first-observation surfacing (canonical)."],
];

function withWorktree(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bl1-mutation-"));
  const wt = path.join(dir, "wt");
  const add = spawnSync("git", ["-C", root, "worktree", "add", "--detach", "-f", wt, "HEAD"],
    { encoding: "utf8" });
  if (add.status !== 0) throw new Error(`worktree add failed: ${add.stderr || add.stdout}`);
  try {
    // The engine import graph needs installed deps; link rather than reinstall.
    const src = path.join(root, "workers", "scan-api", "node_modules");
    if (fs.existsSync(src)) {
      try { fs.symlinkSync(src, path.join(wt, "workers", "scan-api", "node_modules"), "dir"); } catch { /* already linked */ }
    }
    return fn(wt);
  } finally {
    spawnSync("git", ["-C", root, "worktree", "remove", "--force", wt], { encoding: "utf8" });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function runIn(wt) {
  const r = spawnSync(process.execPath, [path.join(wt, VALIDATOR)], { cwd: wt, encoding: "utf8", timeout: 600000 });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  return { failed: new Set([...out.matchAll(/^FAIL ([A-Z0-9_]+)/gm)].map((m) => m[1])), code: r.status, out };
}

withWorktree((wt) => {
  // Baseline: the copy must be GREEN before any mutant, or every kill is meaningless.
  const base = runIn(wt);
  ok("BL1_MUT_BASELINE_IS_GREEN", base.code === 0 && base.failed.size === 0,
     `code=${base.code} failed=[${[...base.failed].join(",")}]`);

  for (const [id, rel, find, replace, mustFail] of [...MUTANTS, ...CONTROLS.map((c) => [...c, null])]) {
    const target = path.join(wt, rel);
    const original = fs.readFileSync(target, "utf8");
    if (original.split(find).length - 1 !== 1) {
      ok(`${id}: anchor is unique`, false, "anchor missing or ambiguous — this mutation tests NOTHING");
      continue;
    }
    fs.writeFileSync(target, original.replace(find, replace));
    try {
      const r = runIn(wt);
      if (mustFail === null) {
        ok(`${id}: cosmetic change SURVIVES`, r.code === 0 && r.failed.size === 0,
           `code=${r.code} failed=[${[...r.failed].join(",")}]`);
      } else {
        ok(`${id}: killed by ${mustFail}`, r.failed.has(mustFail),
           `code=${r.code} failed=[${[...r.failed].join(",")}]`);
      }
    } finally { fs.writeFileSync(target, original); }
  }
});

console.log(`\nBL-1 mutation proof: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("BL-1 mutation proof FAILED"); process.exit(1); }
console.log("BL-1 mutation proof passed");
