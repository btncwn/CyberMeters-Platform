#!/usr/bin/env node
//
// P1.2-E — MUTATION PROOF. Node 24+. DISPOSABLE WORKTREE ONLY.
//
// Never the live checkout: a harness that mutates the tree it stands in can leave a
// mutant behind when it dies, and one such leftover was committed in this repository
// and falsified a re-pin rationale before being caught. Anchors are textually
// distinct — a duplicated anchor once silently disarmed a mutant while the suite
// stayed green, so uniqueness is asserted before mutating.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = "scripts/validate-p12e-historical-read-compat.js";
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };

const MUTANTS = [
  // (a) THE PROJECTION REMOVED — stored pre-P1.1 conclusions read at face value again.
  ["P12E-M1-projection-removed",
    "workers/scan-api/src/engines/phase5-evidence.js",
    "  const websiteSnapshot = projectWebsiteRedirectSnapshotForCustomer(identitySnapshot, modules);",
    "  const websiteSnapshot = identitySnapshot;",
    "P12E_COMPOSITE_CHAIN_APPLIES_THE_PROJECTION"],
  // The serviceability gate itself must be load-bearing, not decorative.
  ["P12E-M2-serviceability-gate-inverted",
    "workers/scan-api/src/engines/phase5-evidence.js",
    // Anchor re-derived after the P1-2 refactor moved the serviceability gate
    // into websiteRedirectConclusionWithheld (return snapshot -> return false).
    // The mutant is the SAME inversion: unknown serviceability stops being
    // neutral and falls through toward masking.
    "  if (serviceability.serviceable !== false) return false;",
    "  if (serviceability.serviceable === true) return false;",
    "P12E_NEUTRAL_UNKNOWN_SERVICEABILITY_OUT_OF_RANGE_STATE_UNCHANGED"],
  // FAIL-NEUTRAL turned into FAIL-MASKING: an unreadable chain would start masking
  // honest rows — the #424 defect in the opposite direction.
  ["P12E-M3-neutral-becomes-masking",
    "workers/scan-api/src/engines/phase5-evidence.js",
    "  const chain = modules?.ssl?.http_redirect_chain;",
    "  const chain = modules?.ssl?.http_redirect_chain ?? { http_redirect_validated: true,\n    hop_observations: [{ state: \"origin_response\", origin_status: 503 }] };",
    "P12E_NEUTRAL_MODULES_ABSENT_STATE_UNCHANGED"],
  // (b) THE INVERTED CASE from the P1.2-E map: the CLOSED historical enumeration
  // widened to include a live version, masking rows that are not legacy at all.
  ["P12E-M4-closed-enumeration-extended",
    "workers/scan-api/src/engines/finding-identity.js",
    '  "2026-07-24.4",\n]);',
    '  "2026-07-24.4",\n  "2026-08-22.1",\n]);',
    "P12E_ENUM_CURRENT_VERSION_IS_NOT_MASKED_AS_LEGACY"],
];

const CONTROLS = [
  ["C1-comment-wording", "workers/scan-api/src/engines/phase5-evidence.js",
    " * THE CLASS. Before P1.1, `ssl-scan.js` set `http_redirect_validated` from TRANSPORT",
    " * The class. Before P1.1, `ssl-scan.js` set `http_redirect_validated` from transport"],
];

function withWorktree(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p12e-mutation-"));
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
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  return { failed: new Set([...out.matchAll(/^FAIL ([A-Z0-9_]+)/gm)].map((m) => m[1])), code: r.status };
};

withWorktree((wt) => {
  const base = runIn(wt);
  ok("P12E_MUT_BASELINE_IS_GREEN", base.code === 0 && base.failed.size === 0,
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
      if (mustFail === null) ok(`${id}: cosmetic change SURVIVES`, r.code === 0 && r.failed.size === 0,
        `failed=[${[...r.failed].join(",")}]`);
      else ok(`${id}: killed by ${mustFail}`, r.failed.has(mustFail),
        `code=${r.code} failed=[${[...r.failed].join(",")}]`);
    } finally { fs.writeFileSync(target, original); }
  }
});

console.log(`\nP1.2-E mutation proof: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("P1.2-E mutation proof FAILED"); process.exit(1); }
console.log("P1.2-E mutation proof passed");
