#!/usr/bin/env node
//
// CI governance — every branch starts the gate; only the versioned, fail-closed
// safe-docs policy may skip individually proven heavy steps. CI-blocking.
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
// Trigger assertions keep the workflow present on every PR. The YAML-AST policy
// assertions at the end additionally prove step reachability: all mandatory steps
// are unconditional, and only the exact versioned heavy-step skip-list may carry
// the one canonical fail-closed condition.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest } from "./ci-safe-docs-only-lib.js";
import {
  ARM2_TIMEZONE_VALIDATOR_RUN,
  ARM2_TIMEZONE_VALIDATOR_STEP,
  EXPECTED_JOB_IDS,
  F004_MATRIX_JOB_ID,
  TIMEZONE_VALIDATOR_RUN,
  TIMEZONE_VALIDATOR_STEP,
  VALIDATOR_SHARD_JOB_IDS,
  evaluateWorkflowPolicy,
  executableValidatorWiring,
  parseWorkflowAst,
} from "./ci-workflow-policy.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ciPath = path.join(root, ".github", "workflows", "ci.yml");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const src = fs.readFileSync(ciPath, "utf8");
const header = src.slice(0, src.indexOf("\njobs:"));   // the `on:` block only

// ── 1. The workflow exists and is the gate ───────────────────────────────────
ok("ci.yml exists on this branch", fs.existsSync(ciPath));
ok("ci.yml defines the CI scope job", /^\s{2}ci_scope:/m.test(src));
for (const jobId of VALIDATOR_SHARD_JOB_IDS) {
  ok(`ci.yml defines shard ${jobId}`, new RegExp(`^\\s{2}${jobId}:`, "m").test(src));
}
ok("ci.yml defines the hosted F004 recovery mutation matrix",
   new RegExp(`^\\s{2}${F004_MATRIX_JOB_ID}:`, "m").test(src));
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
const parsedWorkflow = parseWorkflowAst(src);
const executable = parsedWorkflow.workflow
  ? executableValidatorWiring(parsedWorkflow.workflow)
  : {
      validators: [],
      plainValidators: [],
      problems: parsedWorkflow.parseErrors,
      nonValidatorCarrierProblems: [],
    };
const validators = [...new Set(executable.validators)];
const executableWiringProblems = [
  ...executable.problems,
  ...executable.nonValidatorCarrierProblems,
];
ok("the CI workflow runs the validator suite", validators.length > 0);
ok("CI wires a substantial validator suite", validators.length >= 80, `found ${validators.length}`);
ok("validator and non-validator carrier wiring uses only exact executable AST run mappings",
   executableWiringProblems.length === 0, executableWiringProblems.join(" | "));

const shardSteps = VALIDATOR_SHARD_JOB_IDS.flatMap(
  (jobId) => parsedWorkflow.workflow?.jobs?.[jobId]?.steps || [],
);
const alertTimezoneSteps = shardSteps.filter(
  (step) => step?.name === TIMEZONE_VALIDATOR_STEP,
);
ok(
  "Alert watermark timezone carrier is exact, unique, blocking, and report-cx-owned",
  alertTimezoneSteps.length === 1 &&
    alertTimezoneSteps[0].run === TIMEZONE_VALIDATOR_RUN &&
    (parsedWorkflow.workflow?.jobs?.validate_report_cx?.steps || []).includes(alertTimezoneSteps[0]) &&
    !Object.prototype.hasOwnProperty.call(alertTimezoneSteps[0], "if") &&
    !Object.prototype.hasOwnProperty.call(alertTimezoneSteps[0], "continue-on-error"),
);

const arm2TimezoneSteps = shardSteps.filter(
  (step) => step?.name === ARM2_TIMEZONE_VALIDATOR_STEP,
);
ok(
  "Arm2/writer timezone carrier is exact, unique, blocking, report-cx-owned, and spans UTC/London/+14",
  arm2TimezoneSteps.length === 1 &&
    arm2TimezoneSteps[0].run === ARM2_TIMEZONE_VALIDATOR_RUN &&
    (parsedWorkflow.workflow?.jobs?.validate_report_cx?.steps || []).includes(arm2TimezoneSteps[0]) &&
    !Object.prototype.hasOwnProperty.call(arm2TimezoneSteps[0], "if") &&
    !Object.prototype.hasOwnProperty.call(arm2TimezoneSteps[0], "continue-on-error"),
);

function arm2CarrierMutationIsRejected(from, to) {
  const mutatedSource = src.replace(from, to);
  if (mutatedSource === src) return false;
  const mutatedWorkflow = parseWorkflowAst(mutatedSource);
  if (!mutatedWorkflow.workflow) return false;
  return executableValidatorWiring(mutatedWorkflow.workflow).problems.some(
    (problem) => problem.startsWith(`${ARM2_TIMEZONE_VALIDATOR_STEP}:`),
  );
}
ok(
  "Arm2 timezone carrier negative control rejects loss of the +14 zone",
  arm2CarrierMutationIsRejected(" UTC Europe/London Etc/GMT-14;", " UTC Europe/London;"),
);
ok(
  "Arm2 timezone carrier negative control rejects a substituted validator",
  arm2CarrierMutationIsRejected(
    "TZ=$tz node scripts/validate-item10-attack-surface-p5-arm2.js",
    "TZ=$tz node scripts/validate-item10-attack-surface-p5-customer-parity.js",
  ),
);
ok(
  "Arm2 timezone carrier negative control rejects loss of writer replay coverage",
  arm2CarrierMutationIsRejected(
    "    TZ=$tz node scripts/validate-item10-attack-surface-p2-integration.js\n",
    "",
  ),
);

// Every validator wired in CI must actually exist, or the step is a silent no-op.
const missing = validators.filter((v) => !fs.existsSync(path.join(root, v)));
ok("every validator referenced by CI exists on disk", missing.length === 0, `missing: ${missing.join(", ")}`);

// And every alert validator in scripts/ must be wired into CI — a validator that
// exists but is never run is worse than none: it reads as coverage and provides none.
const alertValidators = fs.readdirSync(path.join(root, "scripts"))
  .filter((f) => /^validate-(alert|managed-alerts)/.test(f));
const unwired = alertValidators.filter((f) => !validators.includes(`scripts/${f}`));
ok("every alert validator on disk is wired into CI", unwired.length === 0, `unwired: ${unwired.join(", ")}`);

// ── 5. No orphan validators — every scripts/validate-*.js runs in CI or is exempted ──
// H1 validator recovery (July 2026): nine critical validators (A1/A2/A3 evidence-status,
// B scorecard, cert standing-condition dedupe, three ADR-003 DMARC guards, UC3 case
// transitions) existed on disk but were wired into neither CI nor any pipeline, so the
// contracts they protect could have regressed under green CI. The alert-only guard above
// caught this class for alerts alone; this generalises it. A validator not run is worse
// than none — it reads as coverage and provides none. Every scripts/validate-*.js must
// appear as a CI run step, or carry an explicit exemption here with a stated reason
// (ops/backfill one-offs; scripts/load and scripts/security helpers are out of scope by
// directory). Adding a validator without wiring or exempting it fails this check.
const EXEMPT_VALIDATORS = new Map([
  // ["validate-example.js", "why this deliberately does not run in CI"],
]);
const allValidatorScripts = fs.readdirSync(path.join(root, "scripts"))
  .filter((f) => /^validate-[a-z0-9-]+\.js$/.test(f));
const orphans = allValidatorScripts
  .filter((f) => !validators.includes(`scripts/${f}`) && !EXEMPT_VALIDATORS.has(f));
ok("every scripts/validate-*.js is wired into CI or explicitly exempted with a reason",
   orphans.length === 0,
   `unwired (add a ci.yml run step, or an EXEMPT_VALIDATORS entry stating why): ${orphans.join(", ")}`);

// Exemptions must stay honest: an entry for a file that no longer exists, or for one
// that IS wired, is stale and must be removed so the list never rots into noise.
const staleExemptions = [...EXEMPT_VALIDATORS.keys()]
  .filter((f) => !allValidatorScripts.includes(f) || validators.includes(`scripts/${f}`));
ok("no stale validator exemption (missing file, or exempted yet actually wired)",
   staleExemptions.length === 0, `stale: ${staleExemptions.join(", ")}`);

// No accidental duplicate plain steps: each validator gets ONE `run: node scripts/…`
// step. Deliberate re-runs (e.g. the TZ-matrix loop) use a multiline block and are
// not counted here, so they stay possible without weakening this check.
const dupSteps = [...new Set(executable.plainValidators
  .filter((v, i) => executable.plainValidators.indexOf(v) !== i))];
ok("no validator is wired as a plain run step more than once",
   dupSteps.length === 0, `duplicated: ${dupSteps.join(", ")}`);

// Reciprocal guard for the M5 final-closure gate. validate-m5-closure.js asserts the whole
// M5 validator suite (and ci-governance itself) stay wired; a self-guard cannot catch the
// deletion of its OWN step, so this generic governance guard — which runs as a separate step
// — asserts the closure is wired. The two mutually guard each other: dropping either step is
// caught by the other, so neither the M5 gate nor this governance check can be silently lost.
ok("the M5 final-closure guard is wired as an uncommented run step",
   /^\s*run:\s*node scripts\/validate-m5-closure\.js\s*$/m.test(src),
   "validate-m5-closure.js must run in ci.yml");

ok(
  "the workflow exposes only the exact sharded gate job IDs",
  parsedWorkflow.workflow &&
    JSON.stringify(Object.keys(parsedWorkflow.workflow.jobs).sort()) === JSON.stringify([...EXPECTED_JOB_IDS].sort()),
  `got ${Object.keys(parsedWorkflow.workflow?.jobs || {}).join(", ")}`,
);

// ── 6. Step reachability and conditional-skip governance (V1) ────────────────
// Text presence alone is not wiring: `if: false` can leave a validator visible
// in YAML and permanently unreachable. Parse the YAML AST and permit a condition
// only on the exact versioned heavy-step allowlist, with one canonical fail-closed
// expression. Mandatory/always-run steps must have no `if` key at all.
const manifest = loadManifest(root);
for (const check of evaluateWorkflowPolicy({ workflowSource: src, manifest, repoRoot: root })) {
  ok(`conditional governance: ${check.name}`, check.passed, check.detail);
}

console.log(`\nci-governance: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("ci-governance validation FAILED"); process.exit(1); }
console.log("ci-governance validation passed");
