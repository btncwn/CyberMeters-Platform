#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRequire = createRequire(path.join(root, "workers", "scan-api", "package.json"));
const { parseDocument, isMap, isSeq } = workerRequire("yaml");

export const CANONICAL_SKIP_CONDITION = "${{ steps.ci_scope.outputs.decision != 'SAFE_DOCS_ONLY' }}";
export const EXPECTED_CLASSIFIER_RUN_SHA256 = "e49f164ef02bd9d4f7dead6a939dd81d55297df4fd3f90a2f57548697efcf062";
export const EXPECTED_EXECUTABLE_VALIDATOR_COUNT = 327;
export const EXPECTED_EXECUTABLE_VALIDATOR_SHA256 = "6758f2020fb9eab39c067494242ae2b92062f3c094f8e3c9a69395af0123109a";

export const EXPECTED_SKIP_IDS = Object.freeze([
  "frontend-test-coverage",
  "intelligence-presentation-mutations",
  "m5a-ce-cases",
  "m5b-remaining-reconciliation",
  "scan-detail-presentation-mutations",
  "scan-quality-vocabulary-inventory",
  "scan-quality-vocabulary-mutations",
]);

export const REQUIRED_ALWAYS_RUN = Object.freeze([
  "Classify CI change scope (fail closed)",
  "Secret scan (tracked files)",
  "Validate dependency install-script governance (deny-by-default / exact allowlist / must-fail controls)",
  "Validate safe docs-only CI classifier and conditional-step governance",
  "Full-repo assurance — entry-point inventory (drift + auth-coverage gate)",
  "Full-repo assurance — tenant-isolation invariant matrix (table classification + harness cross-ref)",
  "Validate M5.a Website Security managed cases + verification vocabulary",
  "Validate M5 closure (full M5 gate wired + append-only idempotency locked)",
  "Validate CI governance (trigger / reachability / anti-orphan)",
  "Validate date-rot governance (future-dated fixtures require a frozen clock or an explicit allowlist reason)",
  "Validate commercial canonicalisation (one direction / no stale price ladder / CE + MSP honesty)",
  "Validate frontend env contract (.env.example ⟷ import.meta.env / /api shape / no secret)",
  "Validate CAPABILITIES.md drift",
]);

const sameSet = (left, right) => {
  const a = [...left].sort();
  const b = [...right].sort();
  return JSON.stringify(a) === JSON.stringify(b);
};

const assertion = (name, passed, detail = "") => ({ name, passed: Boolean(passed), detail });
const hasOwn = (value, key) => value != null && Object.prototype.hasOwnProperty.call(value, key);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

const TIMEZONE_VALIDATOR_STEP = "Validate alert watermark is timezone-independent (non-UTC runners)";
const TIMEZONE_VALIDATOR_RUN = `for tz in Europe/London America/Los_Angeles Asia/Kolkata; do
  echo "── TZ=$tz ──"
  TZ=$tz node scripts/validate-alert-b1-canonical-cases.js
done
`;
export const ARM2_TIMEZONE_VALIDATOR_STEP =
  "Validate Item 10 P5 Arm 2 and writer lifecycle timestamps across UTC and non-UTC runners";
export const ARM2_TIMEZONE_VALIDATOR_RUN = `for tz in UTC Europe/London Etc/GMT-14; do
  echo "── TZ=$tz ──"
  TZ=$tz node scripts/validate-item10-attack-surface-p5-arm2.js
  TZ=$tz node scripts/validate-item10-attack-surface-p2-integration.js
done
`;
const EXPECTED_CLASSIFIER_OUTPUT_WRITES = Object.freeze([
  ["decision", "UNKNOWN_FAIL_CLOSED"],
  ["effective_mode", "RUN_ALL"],
  ["safe_docs_only", "false"],
  ["expected_net_savings_seconds", "0"],
  ["decision", "UNKNOWN_FAIL_CLOSED"],
  ["effective_mode", "RUN_ALL"],
  ["safe_docs_only", "false"],
  ["expected_net_savings_seconds", "0"],
]);

function classifierOutputContract(run) {
  if (typeof run !== "string") return false;
  const writes = [...run.matchAll(/^\s*echo "([a-z_]+)=([^"\n]*)"\s*$/gm)]
    .map((match) => [match[1], match[2]]);
  const firstDefault = run.indexOf('echo "decision=UNKNOWN_FAIL_CLOSED"');
  const invocation = run.indexOf("if ! node scripts/classify-ci-change.js");
  const secondDefault = run.indexOf('echo "decision=UNKNOWN_FAIL_CLOSED"', firstDefault + 1);
  return JSON.stringify(writes) === JSON.stringify(EXPECTED_CLASSIFIER_OUTPUT_WRITES) &&
    (run.match(/} >> "\$GITHUB_OUTPUT"/g) || []).length === 2 &&
    (run.match(/node scripts\/classify-ci-change\.js/g) || []).length === 1 &&
    !run.includes("decision=SAFE_DOCS_ONLY") &&
    firstDefault >= 0 && invocation > firstDefault && secondDefault > invocation;
}

export function executableValidatorWiring(workflow) {
  const steps = Array.isArray(workflow?.jobs?.validate?.steps)
    ? workflow.jobs.validate.steps
    : [];
  const validators = [];
  const plainValidators = [];
  const problems = [];
  for (const step of steps) {
    if (typeof step?.run !== "string" || !step.run.includes("scripts/validate-")) continue;
    const plain = step.run.match(/^(?:node|\/usr\/bin\/env node) (scripts\/validate-[a-z0-9-]+\.js)$/);
    if (plain) {
      validators.push(plain[1]);
      plainValidators.push(plain[1]);
      continue;
    }
    if (step.name === TIMEZONE_VALIDATOR_STEP && step.run === TIMEZONE_VALIDATOR_RUN) {
      validators.push("scripts/validate-alert-b1-canonical-cases.js");
      continue;
    }
    if (
      step.name === ARM2_TIMEZONE_VALIDATOR_STEP &&
      step.run === ARM2_TIMEZONE_VALIDATOR_RUN
    ) {
      validators.push("scripts/validate-item10-attack-surface-p5-arm2.js");
      validators.push("scripts/validate-item10-attack-surface-p2-integration.js");
      continue;
    }
    problems.push(`${step.name || "unnamed step"}: unsupported validator command carrier`);
  }
  return { validators, plainValidators, problems };
}

export function parseWorkflowAst(source) {
  const document = parseDocument(source, {
    schema: "core",
    uniqueKeys: true,
    prettyErrors: true,
  });
  const parseErrors = document.errors.map((error) => error.message);
  const root = document.contents;
  if (parseErrors.length || !isMap(root)) return { document, workflow: null, parseErrors };
  const jobsNode = document.getIn(["jobs"], true);
  const validateStepsNode = document.getIn(["jobs", "validate", "steps"], true);
  const sastStepsNode = document.getIn(["jobs", "sast", "steps"], true);
  if (!isMap(jobsNode) || !isSeq(validateStepsNode) || !isSeq(sastStepsNode)) {
    return { document, workflow: null, parseErrors: [...parseErrors, "jobs/validate.steps/sast.steps shape is invalid"] };
  }
  return { document, workflow: document.toJS({ maxAliasCount: 0 }), parseErrors };
}

export function evaluateWorkflowPolicy({ workflowSource, manifest, repoRoot = root }) {
  const results = [];
  const skipIds = (manifest.skipped_heavy_steps || []).map((step) => step.id);
  const alwaysNames = manifest.always_run || [];
  const skipNames = new Set((manifest.skipped_heavy_steps || []).map((step) => step.name));
  const requiredAlways = new Set(REQUIRED_ALWAYS_RUN);

  const idsPinned = sameSet(skipIds, EXPECTED_SKIP_IDS) && skipIds.length === new Set(skipIds).size;
  const alwaysPinned = sameSet(alwaysNames, REQUIRED_ALWAYS_RUN) && alwaysNames.length === new Set(alwaysNames).size;
  const disjoint = [...skipNames].every((name) => !requiredAlways.has(name));
  results.push(assertion("manifest: skip-list identities are exact and pinned", idsPinned));
  results.push(assertion("manifest: always-run identities are exact and pinned", alwaysPinned));
  results.push(assertion("manifest: always-run steps cannot enter the skip-list", disjoint));

  // Invalid authoritative identities are a load-bearing policy failure. Do not
  // cascade it into misleading workflow-wiring failures; mutation tests pin the
  // single intended FAIL name.
  if (!idsPinned || !alwaysPinned || !disjoint) return results;

  const parsed = parseWorkflowAst(workflowSource);
  results.push(assertion(
    "YAML AST: workflow parses uniquely with validate and sast step sequences",
    parsed.parseErrors.length === 0 && Boolean(parsed.workflow),
    parsed.parseErrors.join(" | "),
  ));
  if (!parsed.workflow) return results;

  const validateJob = parsed.workflow.jobs?.validate;
  const sastJob = parsed.workflow.jobs?.sast;
  const steps = Array.isArray(validateJob?.steps) ? validateJob.steps : [];
  const sastSteps = Array.isArray(sastJob?.steps) ? sastJob.steps : [];
  const byName = new Map();
  for (const step of steps) {
    if (!byName.has(step?.name)) byName.set(step?.name, []);
    byName.get(step?.name).push(step);
  }

  const nonManifestConditionals = steps.filter((step) =>
    hasOwn(step, "if") && !skipNames.has(step.name) && !requiredAlways.has(step.name));
  results.push(assertion(
    "conditions: only versioned skip-list steps may be conditional",
    nonManifestConditionals.length === 0,
    nonManifestConditionals.map((step) => step.name).join(", "),
  ));

  const wrongCanonical = steps.filter((step) =>
    skipNames.has(step?.name) && step.if !== CANONICAL_SKIP_CONDITION);
  results.push(assertion(
    "conditions: every skip-list step uses the exact canonical fail-closed expression",
    wrongCanonical.length === 0,
    wrongCanonical.map((step) => `${step.name}: ${JSON.stringify(step.if)}`).join(" | "),
  ));

  const wiringProblems = [];
  for (const expected of manifest.skipped_heavy_steps) {
    const found = byName.get(expected.name) || [];
    if (found.length !== 1) {
      wiringProblems.push(`${expected.name}: count ${found.length}`);
      continue;
    }
    const actual = found[0];
    const actualDirectory = actual["working-directory"] || ".";
    if (actual.run !== expected.command) wiringProblems.push(`${expected.name}: command drift`);
    if (actualDirectory !== expected.working_directory) wiringProblems.push(`${expected.name}: working-directory drift`);
  }
  results.push(assertion(
    "wiring: every skip-list step has one exact name/command/working-directory mapping",
    wiringProblems.length === 0,
    wiringProblems.join(" | "),
  ));

  const alwaysProblems = [];
  for (const name of REQUIRED_ALWAYS_RUN) {
    const found = byName.get(name) || [];
    if (found.length !== 1) alwaysProblems.push(`${name}: count ${found.length}`);
    else if (hasOwn(found[0], "if")) alwaysProblems.push(`${name}: conditional ${JSON.stringify(found[0].if)}`);
  }
  results.push(assertion(
    "always-run: mandatory steps are present exactly once and unconditional",
    alwaysProblems.length === 0,
    alwaysProblems.join(" | "),
  ));

  const classifier = (byName.get("Classify CI change scope (fail closed)") || [])[0];
  results.push(assertion(
    "classifier wiring: complete step is exact and fail-closed",
    classifier?.id === "ci_scope" &&
      typeof classifier?.run === "string" &&
      sha256(classifier.run) === EXPECTED_CLASSIFIER_RUN_SHA256 &&
      classifierOutputContract(classifier.run) &&
      classifier.run.includes("decision=UNKNOWN_FAIL_CLOSED") &&
      classifier.run.includes("effective_mode=RUN_ALL") &&
      (classifier.run.match(/decision=UNKNOWN_FAIL_CLOSED/g) || []).length === 2 &&
      (classifier.run.match(/effective_mode=RUN_ALL/g) || []).length === 2 &&
      classifier.run.includes("node scripts/classify-ci-change.js") &&
      classifier.run.includes("if ! node"),
  ));

  const executable = executableValidatorWiring(parsed.workflow);
  const allValidators = fs.readdirSync(path.join(repoRoot, "scripts"))
    .filter((filename) => /^validate-[a-z0-9-]+\.js$/.test(filename));
  const missing = executable.validators
    .filter((filename) => !fs.existsSync(path.join(repoRoot, filename)));
  const orphans = allValidators
    .filter((filename) => !executable.validators.includes(`scripts/${filename}`));
  const duplicates = [...new Set(executable.plainValidators
    .filter((filename, index) => executable.plainValidators.indexOf(filename) !== index))];
  const uniqueValidators = [...new Set(executable.validators)].sort();
  const validatorFingerprint = sha256(uniqueValidators.join("\n"));
  results.push(assertion(
    "anti-orphan: every validator is an exact executable AST run mapping",
    executable.problems.length === 0 && missing.length === 0 && orphans.length === 0 &&
      duplicates.length === 0 &&
      uniqueValidators.length === EXPECTED_EXECUTABLE_VALIDATOR_COUNT &&
      validatorFingerprint === EXPECTED_EXECUTABLE_VALIDATOR_SHA256,
    [
      ...executable.problems,
      missing.length ? `missing: ${missing.join(", ")}` : "",
      orphans.length ? `orphans: ${orphans.join(", ")}` : "",
      duplicates.length ? `duplicates: ${duplicates.join(", ")}` : "",
      uniqueValidators.length !== EXPECTED_EXECUTABLE_VALIDATOR_COUNT
        ? `count ${uniqueValidators.length}, want ${EXPECTED_EXECUTABLE_VALIDATOR_COUNT}` : "",
      validatorFingerprint !== EXPECTED_EXECUTABLE_VALIDATOR_SHA256
        ? `fingerprint ${validatorFingerprint}` : "",
    ].filter(Boolean).join(" | "),
  ));

  results.push(assertion(
    "jobs: validate and sast jobs are unconditional",
    sameSet(Object.keys(parsed.workflow.jobs || {}), ["validate", "sast"]) &&
      !hasOwn(validateJob, "if") && !hasOwn(sastJob, "if"),
  ));
  results.push(assertion(
    "SAST: every step remains unconditional",
    sastSteps.length > 0 && sastSteps.every((step) => !hasOwn(step, "if")),
  ));
  const nonBlocking = [validateJob, sastJob, ...steps, ...sastSteps]
    .filter((item) => hasOwn(item, "continue-on-error"));
  results.push(assertion(
    "reachability: validate/sast jobs and every step remain blocking",
    nonBlocking.length === 0,
    nonBlocking.map((item) => item?.name || "job").join(", "),
  ));

  return results;
}
