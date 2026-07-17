#!/usr/bin/env node
//
// CI governance — every branch gets the same safety coverage. CI-blocking.
//
// Written after PR #89 sat with NO validate/sast run at all. The cause was not the
// trigger config (it is a bare `pull_request:`, which matches every branch) — the PR
// was CONFLICTING, and GitHub cannot run pull_request workflows on a PR whose merge
// commit it cannot compute. Cloudflare Pages still reported green because it builds
// the branch head directly, so the PR *looked* checked while the entire gate was
// absent.
//
// Two lessons, both encoded here:
//   1. A branch-name filter on `pull_request` would silently give fix/*, docs/* or
//      chore/* different safety coverage from feat/*. If one is ever added, it must be
//      a deliberate, reviewed act — not something that drifts in.
//   2. Cloudflare Pages is NOT a release gate. It proves a frontend build, not the
//      validators, and it reports on conflicting PRs where CI cannot run.
//
// This asserts the workflow's TRIGGER SHAPE, not its assertions. It must never be
// used to weaken a check — only to keep coverage uniform.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ciPath = path.join(root, ".github", "workflows", "ci.yml");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const src = fs.readFileSync(ciPath, "utf8");
const header = src.slice(0, src.indexOf("\njobs:"));   // the `on:` block only

// ── 1. The workflow exists and is the gate ───────────────────────────────────
ok("ci.yml exists on this branch", fs.existsSync(ciPath));
ok("ci.yml defines the validate job", /^\s{2}validate:/m.test(src));
ok("ci.yml defines the sast job", /^\s{2}sast:/m.test(src));

// ── 2. pull_request must match EVERY branch ──────────────────────────────────
ok("ci runs on pull_request", /^\s*pull_request:/m.test(header));

// A `branches:`/`branches-ignore:` filter under pull_request would mean some branch
// prefixes get the full gate and others get nothing — the exact silent asymmetry this
// test exists to prevent. If one is ever genuinely wanted, this test must be updated
// deliberately, with the intent stated.
const prBlock = (() => {
  const m = header.match(/^\s*pull_request:\s*\n((?:\s{4,}.*\n|\s*\n)*)/m);
  return m ? m[1] : "";
})();
ok("pull_request has NO branches filter (fix/*, docs/*, chore/* get the same gate as feat/*)",
   !/^\s*branches(-ignore)?:/m.test(prBlock),
   `pull_request block was: ${JSON.stringify(prBlock.trim())}`);
ok("pull_request has NO paths filter (a path filter silently skips the gate for some diffs)",
   !/^\s*paths(-ignore)?:/m.test(prBlock));

// ── 3. push protection for the release branch ────────────────────────────────
ok("ci runs on push to main", /push:\s*\n\s*branches:\s*\[\s*main\s*\]/.test(header));

// ── 4. The gate is the validators, not the Pages preview ─────────────────────
// Cloudflare Pages is a deploy preview. It reports on conflicting PRs where CI cannot
// run, so treating it as the gate means a PR can look green with zero validation.
ok("the CI workflow runs the validator suite", /node scripts\/validate-/.test(src));
const validators = [...new Set([...src.matchAll(/node (scripts\/validate-[a-z0-9-]+\.js)/g)].map((m) => m[1]))];
ok("CI wires a substantial validator suite", validators.length >= 80, `found ${validators.length}`);

// Every validator wired in CI must actually exist, or the step is a silent no-op.
const missing = validators.filter((v) => !fs.existsSync(path.join(root, v)));
ok("every validator referenced by CI exists on disk", missing.length === 0, `missing: ${missing.join(", ")}`);

// And every alert validator in scripts/ must be wired into CI — a validator that
// exists but is never run is worse than none: it reads as coverage and provides none.
const alertValidators = fs.readdirSync(path.join(root, "scripts"))
  .filter((f) => /^validate-(alert|managed-alerts)/.test(f));
const unwired = alertValidators.filter((f) => !validators.includes(`scripts/${f}`));
ok("every alert validator on disk is wired into CI", unwired.length === 0, `unwired: ${unwired.join(", ")}`);

// Reciprocal guard for the M5 final-closure gate. validate-m5-closure.js asserts the whole
// M5 validator suite (and ci-governance itself) stay wired; a self-guard cannot catch the
// deletion of its OWN step, so this generic governance guard — which runs as a separate step
// — asserts the closure is wired. The two mutually guard each other: dropping either step is
// caught by the other, so neither the M5 gate nor this governance check can be silently lost.
ok("the M5 final-closure guard is wired as an uncommented run step",
   /^\s*run:\s*node scripts\/validate-m5-closure\.js\s*$/m.test(src),
   "validate-m5-closure.js must run in ci.yml");

console.log(`\nci-governance: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("ci-governance validation FAILED"); process.exit(1); }
console.log("ci-governance validation passed");
