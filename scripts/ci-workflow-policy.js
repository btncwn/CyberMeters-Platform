#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRequire = createRequire(path.join(root, "workers", "scan-api", "package.json"));
const { parseDocument, isMap, isSeq } = workerRequire("yaml");

export const CANONICAL_SKIP_CONDITION = "${{ needs.ci_scope.outputs.decision != 'SAFE_DOCS_ONLY' }}";
export const EXPECTED_CLASSIFIER_RUN_SHA256 = "e49f164ef02bd9d4f7dead6a939dd81d55297df4fd3f90a2f57548697efcf062";
export const EXPECTED_EXECUTABLE_VALIDATOR_COUNT = 376;
export const EXPECTED_EXECUTABLE_VALIDATOR_SHA256 = "8dcdeab643dbd1be7f82864ea21891dab14b838911dad057dc5ee7828a42f8aa";
export const EXPECTED_SHARD_ASSIGNMENT_SHA256 = "5cebcfe26763635212dcc9ba7a215d2db6c365ad28b15f463b8f727f0c7e8694";

export const VALIDATOR_SHARD_JOB_IDS = Object.freeze([
  "validate_runtime_security",
  "validate_report_cx",
  "validate_data_migrations",
  "validate_frontend_build",
  "validate_integration_assurance",
]);

export const EXPECTED_JOB_IDS = Object.freeze([
  "ci_scope",
  ...VALIDATOR_SHARD_JOB_IDS,
  "validate",
  "sast",
]);

export const EXPECTED_SHARD_COUNTS = Object.freeze({
  validate_runtime_security: 89,
  validate_report_cx: 90,
  validate_data_migrations: 91,
  validate_frontend_build: 86,
  validate_integration_assurance: 20,
});

export const EXPECTED_NON_VALIDATOR_CARRIERS = Object.freeze([
  Object.freeze({
    jobId: "validate_runtime_security",
    name: "Validate Identity truth-projection semantic mutations",
    run: "node scripts/mutate-identity-truth-projection.js",
  }),
  Object.freeze({
    jobId: "validate_report_cx",
    name: "Validate Identity producer truth semantic mutations",
    run: "node scripts/mutate-identity-producer-truth.js",
  }),
  Object.freeze({
    jobId: "validate_frontend_build",
    name: "Validate Identity canonical substrate semantic mutations",
    run: "node scripts/mutate-identity-substrate-idempotence.js",
  }),
  Object.freeze({
    jobId: "validate_integration_assurance",
    name: "Validate CT-R2 PR-2A.1 provider-source consumer inventory pin",
    run: "node scripts/derive-ct-provider-source-consumer-inventory.js --pin docs/CT-R2-PR-2A1-PROVIDER-SOURCE-INVENTORY.json",
  }),
]);

const EXPECTED_SHARD_NAMES = Object.freeze({
  validate_runtime_security: "validate / runtime-security",
  validate_report_cx: "validate / report-cx",
  validate_data_migrations: "validate / data-migrations",
  validate_frontend_build: "validate / frontend-build",
  validate_integration_assurance: "validate / integration-assurance",
});

const EXPECTED_CI_SCOPE_OUTPUTS = Object.freeze({
  decision: "${{ steps.ci_scope.outputs.decision }}",
  effective_mode: "${{ steps.ci_scope.outputs.effective_mode }}",
  safe_docs_only: "${{ steps.ci_scope.outputs.safe_docs_only }}",
  expected_net_savings_seconds: "${{ steps.ci_scope.outputs.expected_net_savings_seconds }}",
});

const EXPECTED_AGGREGATOR_ENV = Object.freeze({
  CI_SCOPE_RESULT: "${{ needs.ci_scope.result }}",
  RUNTIME_SECURITY_RESULT: "${{ needs.validate_runtime_security.result }}",
  REPORT_CX_RESULT: "${{ needs.validate_report_cx.result }}",
  DATA_MIGRATIONS_RESULT: "${{ needs.validate_data_migrations.result }}",
  FRONTEND_BUILD_RESULT: "${{ needs.validate_frontend_build.result }}",
  INTEGRATION_ASSURANCE_RESULT: "${{ needs.validate_integration_assurance.result }}",
});

const EXPECTED_AGGREGATOR_RUN_SHA256 = "7fe206ec156396129fbd2e5d8a6703d497239b5a4151d623857363f3a6280075";
const EXPECTED_SAST_JOB_SHA256 = "48cf38fc15e61660e593fcd7e69bde5b35bc3d7d8a953599af0fe997b3ae3910";

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

const sameSet = (left, right) =>
  JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());

const canonicalJsonValue = (value) => {
  if (Array.isArray(value)) return value.map(canonicalJsonValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJsonValue(value[key])]));
  }
  return value;
};
const stableJson = (value) => JSON.stringify(canonicalJsonValue(value));
const assertion = (name, passed, detail = "") => ({ name, passed: Boolean(passed), detail });
const hasOwn = (value, key) => value != null && Object.prototype.hasOwnProperty.call(value, key);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export const TIMEZONE_VALIDATOR_STEP =
  "Validate alert watermark is timezone-independent (non-UTC runners)";
export const TIMEZONE_VALIDATOR_RUN =
  "for tz in Europe/London America/Los_Angeles Asia/Kolkata; do\n" +
  "  echo \"── TZ=$tz ──\"\n" +
  "  TZ=$tz node scripts/validate-alert-b1-canonical-cases.js\n" +
  "done\n";
export const ARM2_TIMEZONE_VALIDATOR_STEP =
  "Validate Item 10 P5 Arm 2 and writer lifecycle timestamps across UTC and non-UTC runners";
export const ARM2_TIMEZONE_VALIDATOR_RUN =
  "for tz in UTC Europe/London Etc/GMT-14; do\n" +
  "  echo \"── TZ=$tz ──\"\n" +
  "  TZ=$tz node scripts/validate-item10-attack-surface-p5-arm2.js\n" +
  "  TZ=$tz node scripts/validate-item10-attack-surface-p2-integration.js\n" +
  "done\n";

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
  const firstDefault = run.indexOf("echo \"decision=UNKNOWN_FAIL_CLOSED\"");
  const invocation = run.indexOf("if ! node scripts/classify-ci-change.js");
  const secondDefault = run.indexOf("echo \"decision=UNKNOWN_FAIL_CLOSED\"", firstDefault + 1);
  return JSON.stringify(writes) === JSON.stringify(EXPECTED_CLASSIFIER_OUTPUT_WRITES) &&
    (run.match(/} >> "\$GITHUB_OUTPUT"/g) || []).length === 2 &&
    (run.match(/node scripts\/classify-ci-change\.js/g) || []).length === 1 &&
    !run.includes("decision=SAFE_DOCS_ONLY") &&
    firstDefault >= 0 && invocation > firstDefault && secondDefault > invocation;
}

function expectedCheckoutStep() {
  return {
    name: "Checkout",
    uses: "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    with: { "fetch-depth": 0 },
  };
}

function expectedNodeStep() {
  return {
    name: "Set up Node",
    uses: "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    with: {
      "node-version": "24",
      cache: "npm",
      "cache-dependency-path": "workers/scan-api/package-lock.json\nfrontend/package-lock.json\n",
    },
  };
}

function expectedInstallSteps() {
  return [
    {
      name: "Install worker dependencies (governed lifecycle scripts)",
      run: "node scripts/install-governed-dependencies.js --root workers/scan-api",
    },
    {
      name: "Install frontend dependencies (governed lifecycle scripts)",
      run: "node scripts/install-governed-dependencies.js --root frontend",
    },
  ];
}

function aggregatorSuccessOnlyContract(run) {
  return typeof run === "string" &&
    sha256(run) === EXPECTED_AGGREGATOR_RUN_SHA256 &&
    run.includes("if [ \"$result\" != \"success\" ]; then failed=1; fi") &&
    run.includes("if [ \"$failed\" -ne 0 ]; then") &&
    run.includes("exit 1") &&
    !/cancelled|skipped/.test(run);
}

export function executableValidatorWiring(workflow) {
  const validators = [];
  const plainValidators = [];
  const assignments = [];
  const problems = [];
  const carrierCounts = new Map([
    [TIMEZONE_VALIDATOR_STEP, 0],
    [ARM2_TIMEZONE_VALIDATOR_STEP, 0],
  ]);

  for (const jobId of VALIDATOR_SHARD_JOB_IDS) {
    const steps = workflow?.jobs?.[jobId]?.steps;
    if (!Array.isArray(steps)) {
      problems.push(jobId + ": missing step sequence");
      continue;
    }
    for (const step of steps) {
      if (typeof step?.run !== "string" || !step.run.includes("scripts/validate-")) continue;
      const plain = step.run.match(/^(?:node|\/usr\/bin\/env node) (scripts\/validate-[a-z0-9-]+\.js)$/);
      if (plain) {
        validators.push(plain[1]);
        plainValidators.push(plain[1]);
        assignments.push({ jobId, path: plain[1] });
        continue;
      }
      if (
        jobId === "validate_report_cx" &&
        step.name === TIMEZONE_VALIDATOR_STEP &&
        step.run === TIMEZONE_VALIDATOR_RUN
      ) {
        validators.push("scripts/validate-alert-b1-canonical-cases.js");
        carrierCounts.set(TIMEZONE_VALIDATOR_STEP, carrierCounts.get(TIMEZONE_VALIDATOR_STEP) + 1);
        continue;
      }
      if (
        jobId === "validate_report_cx" &&
        step.name === ARM2_TIMEZONE_VALIDATOR_STEP &&
        step.run === ARM2_TIMEZONE_VALIDATOR_RUN
      ) {
        validators.push("scripts/validate-item10-attack-surface-p5-arm2.js");
        validators.push("scripts/validate-item10-attack-surface-p2-integration.js");
        carrierCounts.set(ARM2_TIMEZONE_VALIDATOR_STEP, carrierCounts.get(ARM2_TIMEZONE_VALIDATOR_STEP) + 1);
        continue;
      }
      problems.push(jobId + "/" + (step.name || "unnamed step") + ": unsupported validator command carrier");
    }
  }

  for (const jobId of ["ci_scope", "validate", "sast"]) {
    for (const step of workflow?.jobs?.[jobId]?.steps || []) {
      if (typeof step?.run === "string" && step.run.includes("scripts/validate-")) {
        problems.push(jobId + "/" + (step.name || "unnamed step") + ": validator outside an approved shard");
      }
    }
  }
  for (const [name, count] of carrierCounts) {
    if (count !== 1) problems.push(name + ": carrier count " + count + ", want 1 in validate_report_cx");
  }

  const observedNonValidatorCarriers = [];
  for (const jobId of VALIDATOR_SHARD_JOB_IDS) {
    for (const step of workflow?.jobs?.[jobId]?.steps || []) {
      if (typeof step?.run !== "string") continue;
      const plainNodeScript = step.run.match(/^node (scripts\/[a-z0-9-]+\.js)(?: .+)?$/);
      if (!plainNodeScript || plainNodeScript[1].startsWith("scripts/validate-") ||
          plainNodeScript[1] === "scripts/install-governed-dependencies.js") continue;
      observedNonValidatorCarriers.push({
        jobId,
        name: step.name,
        run: step.run,
        conditional: hasOwn(step, "if"),
        nonBlocking: hasOwn(step, "continue-on-error"),
      });
    }
  }
  const expectedNonValidatorCarriers = EXPECTED_NON_VALIDATOR_CARRIERS.map((carrier) => ({
    ...carrier,
    conditional: false,
    nonBlocking: false,
  }));
  const nonValidatorCarrierProblems = [];
  if (stableJson(observedNonValidatorCarriers) !== stableJson(expectedNonValidatorCarriers)) {
    nonValidatorCarrierProblems.push(
      "observed " + stableJson(observedNonValidatorCarriers) +
      "; want " + stableJson(expectedNonValidatorCarriers),
    );
  }
  return {
    validators,
    plainValidators,
    assignments,
    problems,
    carrierCounts,
    nonValidatorCarrierProblems,
  };
}

export function parseWorkflowAst(source) {
  const document = parseDocument(source, {
    schema: "core",
    uniqueKeys: true,
    prettyErrors: true,
  });
  const parseErrors = document.errors.map((error) => error.message);
  if (parseErrors.length || !isMap(document.contents)) {
    return { document, workflow: null, parseErrors };
  }
  if (!isMap(document.getIn(["jobs"], true))) parseErrors.push("jobs map is invalid");
  for (const jobId of EXPECTED_JOB_IDS) {
    if (!isSeq(document.getIn(["jobs", jobId, "steps"], true))) {
      parseErrors.push("jobs." + jobId + ".steps is invalid");
    }
  }
  return {
    document,
    workflow: parseErrors.length ? null : document.toJS({ maxAliasCount: 0 }),
    parseErrors,
  };
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
  if (!idsPinned || !alwaysPinned || !disjoint) return results;

  const parsed = parseWorkflowAst(workflowSource);
  results.push(assertion(
    "YAML AST: workflow parses uniquely with the complete sharded job graph",
    parsed.parseErrors.length === 0 && Boolean(parsed.workflow),
    parsed.parseErrors.join(" | "),
  ));
  if (!parsed.workflow) return results;

  const jobs = parsed.workflow.jobs || {};
  const ciScopeJob = jobs.ci_scope;
  const validateJob = jobs.validate;
  const sastJob = jobs.sast;
  const shardJobs = VALIDATOR_SHARD_JOB_IDS.map((jobId) => jobs[jobId]);
  const ciScopeSteps = ciScopeJob.steps || [];
  const shardSteps = VALIDATOR_SHARD_JOB_IDS.flatMap((jobId) => jobs[jobId].steps || []);
  const validationSteps = [...ciScopeSteps, ...shardSteps];
  const sastSteps = sastJob.steps || [];

  results.push(assertion(
    "jobs: exact scope + five shards + terminal validate + SAST set is pinned",
    sameSet(Object.keys(jobs), EXPECTED_JOB_IDS) && Object.keys(jobs).length === EXPECTED_JOB_IDS.length,
    Object.keys(jobs).join(", "),
  ));

  const graphProblems = [];
  if (hasOwn(ciScopeJob, "needs") || hasOwn(ciScopeJob, "if")) graphProblems.push("ci_scope is not independent/unconditional");
  if (hasOwn(sastJob, "needs") || hasOwn(sastJob, "if")) graphProblems.push("sast is not independent/unconditional");
  for (const jobId of VALIDATOR_SHARD_JOB_IDS) {
    const job = jobs[jobId];
    if (job.needs !== "ci_scope") graphProblems.push(jobId + ": needs " + JSON.stringify(job.needs));
    if (hasOwn(job, "if")) graphProblems.push(jobId + ": job-level if");
  }
  results.push(assertion(
    "job graph: ci_scope and SAST are independent; every shard depends only on ci_scope",
    graphProblems.length === 0,
    graphProblems.join(" | "),
  ));

  const bootstrapProblems = [];
  for (const jobId of VALIDATOR_SHARD_JOB_IDS) {
    const job = jobs[jobId];
    if (job.name !== EXPECTED_SHARD_NAMES[jobId]) bootstrapProblems.push(jobId + ": name drift");
    if (job["runs-on"] !== "ubuntu-latest") bootstrapProblems.push(jobId + ": runner drift");
    const expected = [expectedCheckoutStep(), expectedNodeStep(), ...expectedInstallSteps()];
    if (stableJson((job.steps || []).slice(0, 4)) !== stableJson(expected)) {
      bootstrapProblems.push(jobId + ": checkout/setup/install prefix drift");
    }
  }
  results.push(assertion(
    "shards: names, runner, full-history checkout, Node cache and both governed installs are exact",
    bootstrapProblems.length === 0,
    bootstrapProblems.join(" | "),
  ));

  results.push(assertion(
    "ci_scope: exact outputs and four-step classifier carrier are pinned",
    ciScopeJob.name === "CI scope" &&
      ciScopeJob["runs-on"] === "ubuntu-latest" &&
      stableJson(ciScopeJob.outputs) === stableJson(EXPECTED_CI_SCOPE_OUTPUTS) &&
      ciScopeSteps.length === 4 &&
      stableJson(ciScopeSteps[0]) === stableJson(expectedCheckoutStep()) &&
      stableJson(ciScopeSteps[1]) === stableJson(expectedNodeStep()) &&
      ciScopeSteps[3]?.name === "Show Node version" &&
      ciScopeSteps[3]?.run === "node --version && npm --version",
  ));

  const byName = new Map();
  for (const step of validationSteps) {
    if (!byName.has(step?.name)) byName.set(step?.name, []);
    byName.get(step?.name).push(step);
  }
  const classifier = (byName.get("Classify CI change scope (fail closed)") || [])[0];
  results.push(assertion(
    "classifier wiring: complete ci_scope step is exact and fail-closed",
    (byName.get("Classify CI change scope (fail closed)") || []).length === 1 &&
      classifier?.id === "ci_scope" &&
      typeof classifier?.run === "string" &&
      sha256(classifier.run) === EXPECTED_CLASSIFIER_RUN_SHA256 &&
      classifierOutputContract(classifier.run),
  ));

  const nonManifestConditionals = shardSteps.filter((step) =>
    hasOwn(step, "if") && !skipNames.has(step.name));
  results.push(assertion(
    "conditions: only versioned skip-list shard steps may be conditional",
    nonManifestConditionals.length === 0,
    nonManifestConditionals.map((step) => step.name).join(", "),
  ));
  const wrongCanonical = shardSteps.filter((step) =>
    skipNames.has(step?.name) && step.if !== CANONICAL_SKIP_CONDITION);
  results.push(assertion(
    "conditions: every skip-list step uses the exact cross-job fail-closed expression",
    wrongCanonical.length === 0,
    wrongCanonical.map((step) => step.name + ": " + JSON.stringify(step.if)).join(" | "),
  ));

  const wiringProblems = [];
  for (const expected of manifest.skipped_heavy_steps) {
    const found = byName.get(expected.name) || [];
    if (found.length !== 1) {
      wiringProblems.push(expected.name + ": count " + found.length);
      continue;
    }
    const actual = found[0];
    if (actual.run !== expected.command) wiringProblems.push(expected.name + ": command drift");
    if ((actual["working-directory"] || ".") !== expected.working_directory) {
      wiringProblems.push(expected.name + ": working-directory drift");
    }
  }
  results.push(assertion(
    "wiring: every skip-list step has one exact name/command/working-directory mapping",
    wiringProblems.length === 0,
    wiringProblems.join(" | "),
  ));

  const alwaysProblems = [];
  for (const name of REQUIRED_ALWAYS_RUN) {
    const found = byName.get(name) || [];
    if (found.length !== 1) alwaysProblems.push(name + ": count " + found.length);
    else if (hasOwn(found[0], "if")) alwaysProblems.push(name + ": conditional " + JSON.stringify(found[0].if));
  }
  results.push(assertion(
    "always-run: mandatory scope/shard steps are present exactly once and unconditional",
    alwaysProblems.length === 0,
    alwaysProblems.join(" | "),
  ));

  const executable = executableValidatorWiring(parsed.workflow);
  const allValidators = fs.readdirSync(path.join(repoRoot, "scripts"))
    .filter((filename) => /^validate-[a-z0-9-]+\.js$/.test(filename));
  const missing = executable.validators.filter((filename) => !fs.existsSync(path.join(repoRoot, filename)));
  const orphans = allValidators.filter((filename) => !executable.validators.includes("scripts/" + filename));
  const duplicatePlain = [...new Set(executable.plainValidators
    .filter((filename, index) => executable.plainValidators.indexOf(filename) !== index))];
  const uniqueValidators = [...new Set(executable.validators)].sort();
  const validatorFingerprint = sha256(uniqueValidators.join("\n"));
  results.push(assertion(
    "anti-orphan: five shards are the exact executable 376-validator union",
    executable.problems.length === 0 && missing.length === 0 && orphans.length === 0 &&
      duplicatePlain.length === 0 &&
      uniqueValidators.length === EXPECTED_EXECUTABLE_VALIDATOR_COUNT &&
      validatorFingerprint === EXPECTED_EXECUTABLE_VALIDATOR_SHA256,
    [
      ...executable.problems,
      missing.length ? "missing: " + missing.join(", ") : "",
      orphans.length ? "orphans: " + orphans.join(", ") : "",
      duplicatePlain.length ? "duplicates: " + duplicatePlain.join(", ") : "",
      uniqueValidators.length !== EXPECTED_EXECUTABLE_VALIDATOR_COUNT
        ? "count " + uniqueValidators.length + ", want " + EXPECTED_EXECUTABLE_VALIDATOR_COUNT : "",
      validatorFingerprint !== EXPECTED_EXECUTABLE_VALIDATOR_SHA256
        ? "fingerprint " + validatorFingerprint : "",
    ].filter(Boolean).join(" | "),
  ));

  const actualCounts = Object.fromEntries(VALIDATOR_SHARD_JOB_IDS.map((jobId) => [
    jobId,
    executable.assignments.filter((assignment) => assignment.jobId === jobId).length,
  ]));
  const assignmentFingerprint = sha256(executable.assignments
    .map((assignment) => assignment.jobId + "\t" + assignment.path)
    .sort()
    .join("\n"));
  results.push(assertion(
    "assignment: exact non-overlapping shard counts and ownership fingerprint are pinned",
    stableJson(actualCounts) === stableJson(EXPECTED_SHARD_COUNTS) &&
      assignmentFingerprint === EXPECTED_SHARD_ASSIGNMENT_SHA256,
    "counts " + stableJson(actualCounts) + "; fingerprint " + assignmentFingerprint,
  ));

  results.push(assertion(
    "timezone carriers: both exact loops remain unique, blocking and owned by report-cx",
    executable.carrierCounts.get(TIMEZONE_VALIDATOR_STEP) === 1 &&
      executable.carrierCounts.get(ARM2_TIMEZONE_VALIDATOR_STEP) === 1,
    executable.problems.filter((problem) => problem.includes("timezone") || problem.includes("Arm 2")).join(" | "),
  ));

  results.push(assertion(
    "non-validator carriers: four exact commands remain unique, blocking and shard-owned",
    executable.nonValidatorCarrierProblems.length === 0,
    executable.nonValidatorCarrierProblems.join(" | "),
  ));

  const aggregatorStep = validateJob.steps?.[0];
  results.push(assertion(
    "terminal validate: always runs, explicitly needs scope + five shards, and only success passes",
    validateJob.name === "validate" &&
      validateJob["runs-on"] === "ubuntu-latest" &&
      validateJob.if === "${{ always() }}" &&
      Array.isArray(validateJob.needs) &&
      sameSet(validateJob.needs, ["ci_scope", ...VALIDATOR_SHARD_JOB_IDS]) &&
      validateJob.needs.length === 1 + VALIDATOR_SHARD_JOB_IDS.length &&
      validateJob.steps?.length === 1 &&
      aggregatorStep?.name === "Require every validation shard to pass" &&
      stableJson(aggregatorStep?.env) === stableJson(EXPECTED_AGGREGATOR_ENV) &&
      aggregatorSuccessOnlyContract(aggregatorStep?.run) &&
      !hasOwn(aggregatorStep, "if") &&
      !hasOwn(aggregatorStep, "continue-on-error"),
  ));

  results.push(assertion(
    "SAST: semantic job contract is exact and independent",
    sha256(stableJson(sastJob)) === EXPECTED_SAST_JOB_SHA256 &&
      !hasOwn(sastJob, "needs") && !hasOwn(sastJob, "if"),
  ));
  results.push(assertion(
    "SAST: every step remains unconditional",
    sastSteps.length === 4 && sastSteps.every((step) => !hasOwn(step, "if")),
  ));

  const nonBlocking = [
    ciScopeJob,
    ...shardJobs,
    validateJob,
    sastJob,
    ...ciScopeSteps,
    ...shardSteps,
    ...(validateJob.steps || []),
    ...sastSteps,
  ].filter((item) => hasOwn(item, "continue-on-error"));
  results.push(assertion(
    "reachability: scope, shards, terminal validate, SAST and every step remain blocking",
    nonBlocking.length === 0,
    nonBlocking.map((item) => item?.name || "job").join(", "),
  ));

  return results;
}
