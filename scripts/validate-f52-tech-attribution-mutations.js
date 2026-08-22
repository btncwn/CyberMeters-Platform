#!/usr/bin/env node
//
// F-52 / P1.2-C successor — MUTATION PROOF. Node 24+.
//
// DISPOSABLE WORKTREE ONLY — never the live checkout. A harness that mutates the tree
// it stands in can leave a mutant behind when it dies; one such leftover was committed
// in this repository and falsified a re-pin rationale before being caught.
//
// ANCHORS ARE TEXTUALLY DISTINCT by design. A duplicated anchor silently disarmed
// `validate-weekly-digest-truth`'s M5 while the suite stayed green, so each anchor
// below must be UNIQUE in its file and the harness reports "tests NOTHING" if it is not.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = "scripts/validate-f52-tech-attribution.js";
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };

// [id, file, find, replace, mustFailSubstring]
const MUTANTS = [
  // MUTANT C — collapse the origin-error token into the transport token. The two are
  // different customer stories: an origin that ANSWERED without serving, versus an
  // origin that never answered. Before the token pin, this survived both committed
  // validators because only truthiness was asserted.
  ["F52-MC-reason-token-collapsed",
    "workers/scan-api/src/engines/tech-scan.js",
    'serviceability.reason === "origin_error_no_serviceable_response"\n        ? "origin_error_no_serviceable_response" : "origin_not_observed",',
    '"origin_not_observed",',
    "incomplete reason is exactly origin_error_no_serviceable_response"],
  // FLOOR SWAP — the honesty boundary reverted to the MOVING current version. This is
  // the confirmed defect: an honest 2026-08-12.1 snapshot gets rewritten to
  // evidence_insufficient and told the customer it was never evaluated.
  ["F52-MF-floor-swapped-to-moving-version",
    "workers/scan-api/src/engines/phase5-evidence.js",
    "snapshot?.methodology?.cyber_mot_resolver_version, FIRST_HONEST_RESOLVER_VERSION);",
    "snapshot?.methodology?.cyber_mot_resolver_version);",
    "F52_FLOOR_HONEST_PREDECESSOR_STAYS_HEALTHY"],
  // The floor constant itself must be load-bearing, not decorative.
  ["F52-MF2-floor-constant-set-to-current",
    "workers/scan-api/src/engines/cyber-mot-domains.js",
    'export const FIRST_HONEST_RESOLVER_VERSION = "2026-08-12.1";',
    "export const FIRST_HONEST_RESOLVER_VERSION = CYBER_MOT_RESOLVER_VERSION;",
    // ok() THROWS on the first failure, so the run stops at the earliest bar the
    // mutant breaks. Naming a later one would be a kill this suite never reports.
    "honest floor is a fixed constant, not the moving current version"],
];

// Cosmetic edits that MUST survive — a suite that dies on a comment proves nothing.
const CONTROLS = [
  ["C1-comment-wording", "workers/scan-api/src/engines/cyber-mot-domains.js",
    "// THE HONESTY BOUNDARY IS A FIXED FLOOR, NOT A MOVING ONE.",
    "// The honesty boundary is a fixed floor, not a moving one."],
];

function withWorktree(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "f52-mutation-"));
  const wt = path.join(dir, "wt");
  const add = spawnSync("git", ["-C", root, "worktree", "add", "--detach", "-f", wt, "HEAD"], { encoding: "utf8" });
  if (add.status !== 0) throw new Error(`worktree add failed: ${add.stderr || add.stdout}`);
  try {
    const src = path.join(root, "workers", "scan-api", "node_modules");
    if (fs.existsSync(src)) {
      try { fs.symlinkSync(src, path.join(wt, "workers", "scan-api", "node_modules"), "dir"); } catch { /* linked */ }
    }
    return fn(wt);
  } finally {
    spawnSync("git", ["-C", root, "worktree", "remove", "--force", wt], { encoding: "utf8" });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const runIn = (wt) => {
  const r = spawnSync(process.execPath, [path.join(wt, VALIDATOR)], { cwd: wt, encoding: "utf8", timeout: 300000 });
  return { out: `${r.stdout || ""}${r.stderr || ""}`, code: r.status };
};

withWorktree((wt) => {
  const base = runIn(wt);
  ok("F52_MUT_BASELINE_IS_GREEN", base.code === 0, `code=${base.code}`);
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
      if (mustFail === null) ok(`${id}: cosmetic change SURVIVES`, r.code === 0, `code=${r.code}`);
      else ok(`${id}: killed by "${mustFail}"`, r.code !== 0 && r.out.includes(mustFail),
              `code=${r.code} tail=${r.out.trim().split("\n").slice(-2).join(" | ").slice(0, 160)}`);
    } finally { fs.writeFileSync(target, original); }
  }
});

console.log(`\nf52-tech-attribution mutations: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("f52 mutation proof FAILED"); process.exit(1); }
console.log("f52 mutation proof passed");
