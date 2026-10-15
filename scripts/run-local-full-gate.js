#!/usr/bin/env node
// Run the current CI shell checks on the local worktree. GitHub checkout, cache,
// artifact upload and the terminal job-status aggregator have no local analogue;
// this runner never calls a hosted MCP endpoint or uses customer credentials.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CANONICAL_SKIP_CONDITION,
  F004_MATRIX_JOB_ID,
  F004_MATRIX_RUN,
  VALIDATOR_SHARD_JOB_IDS,
  parseWorkflowAst,
} from "./ci-workflow-policy.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflowPath = path.join(root, ".github/workflows/ci.yml");
const args = new Set(process.argv.slice(2));
const allowedArgs = new Set(["--all", "--mcp", "--plan"]);
for (const arg of args) {
  if (!allowedArgs.has(arg)) throw new Error(`Unknown argument: ${arg}`);
}
if (args.has("--all") && args.has("--mcp")) {
  throw new Error("Choose either --all or --mcp");
}
const mode = args.has("--mcp") ? "mcp" : "all";
const planOnly = args.has("--plan");

const MCP_STEPS = Object.freeze([
  ["Install MCP gateway dependencies for supply-chain inventory",
    "npm ci --prefix workers/mcp-server --ignore-scripts"],
  ["Validate MCP admission and private service contract",
    "node scripts/validate-mcp-admission.js"],
  ["Validate MCP customer service contract",
    "node scripts/validate-mcp-service.js"],
  ["Validate MCP private two-Worker runtime",
    "node scripts/validate-mcp-rpc-runtime.js"],
  ["Validate MCP OAuth resource runtime",
    "node scripts/validate-mcp-oauth-resource-runtime.js"],
  ["Validate MCP customer OAuth to gateway runtime",
    "node scripts/validate-mcp-customer-chain-runtime.js"],
  ["Validate isolated MCP staging configuration",
    "node scripts/validate-mcp-staging-config.js"],
]);

// These are hermetic, additional MCP release checks. The hosted/Gemini probes
// are deliberately excluded: they require explicit synthetic staging grants.
const MCP_LOCAL_CHECKS = Object.freeze([
  "node scripts/audit-retention-local-check.js",
  "node scripts/mcp-rate-retention-local-check.js",
  "node scripts/mcp-refresh-retention-local-check.js",
  "node scripts/mcp-staging-test-config-local-check.js",
  "node scripts/generate-mcp-staging-schema.js",
  "node scripts/mcp-staging-fixture-local-check.js",
  "node scripts/mcp-staging-fixture-import-local-check.js",
  "node --test scripts/validate-mcp-hosted-staging.test.js scripts/validate-gemini-api-mcp-staging.test.js",
  "node --test workers/scan-api/test/mcp-oauth-admission.test.js",
  "node --test workers/scan-api/test/mcp-customer-service.test.js",
  "node --test workers/scan-api/test/mcp-read.test.js",
  "node --test workers/scan-api/test/mcp-customer-status.test.js",
  "npm test --prefix workers/mcp-server",
]);

const parsed = parseWorkflowAst(readFileSync(workflowPath, "utf8"));
if (!parsed.workflow) throw new Error(`Cannot parse CI workflow: ${parsed.parseErrors.join(" | ")}`);
const workflow = parsed.workflow;
const integrationSteps = workflow.jobs?.validate_integration_assurance?.steps;
if (!Array.isArray(integrationSteps)) throw new Error("CI integration shard is missing");

const mcpSteps = MCP_STEPS.map(([name, run]) => {
  const found = integrationSteps.filter((step) => step.name === name);
  assert.equal(found.length, 1, `CI MCP step must occur exactly once: ${name}`);
  const step = found[0];
  assert.equal(step.run, run, `Local/CI MCP command drift: ${name}`);
  assert.equal(step["working-directory"], undefined, `CI MCP cwd drift: ${name}`);
  assert.equal(step.if, undefined, `CI MCP conditional drift: ${name}`);
  assert.equal(step["continue-on-error"], undefined, `CI MCP nonblocking drift: ${name}`);
  return { name, run, cwd: root };
});
const positions = mcpSteps.map((step) => integrationSteps.findIndex((item) => item.name === step.name));
for (let i = 1; i < positions.length; i++) {
  assert.equal(positions[i], positions[i - 1] + 1, "CI MCP steps must retain their exact order");
}

function checkedWorkingDirectory(step) {
  const directory = step["working-directory"] || ".";
  if (typeof directory !== "string" || path.isAbsolute(directory) ||
      directory === ".." || directory.startsWith("../") || directory.includes("\\")) {
    throw new Error(`Unsafe CI working directory: ${JSON.stringify(directory)}`);
  }
  const cwd = path.resolve(root, directory);
  if (cwd !== root && !cwd.startsWith(root + path.sep)) {
    throw new Error(`CI working directory escapes repository: ${directory}`);
  }
  return cwd;
}

function localRunStep(step, sha, extraEnv = {}) {
  if (typeof step.run !== "string" || !step.run.trim()) throw new Error("Empty CI run step");
  if (step.if !== undefined && step.if !== CANONICAL_SKIP_CONDITION) {
    throw new Error(`Unsupported CI condition on ${step.name}: ${step.if}`);
  }
  if (step["continue-on-error"] !== undefined) {
    throw new Error(`Nonblocking CI step cannot be claimed locally: ${step.name}`);
  }
  const run = step.run.replaceAll("${{ github.sha }}", sha);
  if (run.includes("${{")) throw new Error(`Unresolved GitHub expression in ${step.name}`);
  return { name: step.name, run, cwd: checkedWorkingDirectory(step), env: extraEnv };
}

function runShell(item, index, total, environment) {
  process.stdout.write(`\n[${index}/${total}] ${item.name}\n`);
  const execution = spawnSync("bash", ["-e", "-o", "pipefail", "-c", item.run], {
    cwd: item.cwd,
    env: { ...environment, ...item.env },
    stdio: "inherit",
    timeout: 900_000,
  });
  if (execution.error) throw new Error(`${item.name}: ${execution.error.message}`);
  if (execution.status !== 0) {
    throw new Error(`${item.name}: exit ${execution.status ?? execution.signal}`);
  }
}

function gitHead() {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: root, encoding: "utf8", timeout: 10_000,
  });
  if (result.status !== 0 || !/^[a-f0-9]{40}\n?$/.test(result.stdout)) {
    throw new Error("Cannot resolve the local Git HEAD for the F004 and TLS checks");
  }
  return result.stdout.trim();
}

function python312() {
  const candidates = [
    process.env.CYBERMETERS_CI_PYTHON_312,
    "python3.12",
    path.join(homedir(), ".cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3.12"),
  ].filter(Boolean);
  for (const candidate of candidates) {
    const check = spawnSync(candidate, ["--version"], { encoding: "utf8", timeout: 10_000 });
    if (check.status === 0 && /^Python 3\.12\.\d+/.test(check.stdout.trim())) return candidate;
  }
  throw new Error("CI SAST requires Python 3.12; set CYBERMETERS_CI_PYTHON_312 to its executable");
}

function fullSteps(sha) {
  const steps = [];
  for (const jobId of VALIDATOR_SHARD_JOB_IDS) {
    const job = workflow.jobs?.[jobId];
    if (!Array.isArray(job?.steps)) throw new Error(`CI shard missing: ${jobId}`);
    for (const step of job.steps) {
      if (typeof step.run === "string") {
        steps.push(localRunStep(step, sha));
      } else if (step.uses && /^(Checkout|Set up Node|Upload SBOM artifacts)$/.test(step.name)) {
        // Source is the current local worktree; runtime/cache/artifact storage are local.
      } else {
        throw new Error(`Unsupported non-shell CI step in ${jobId}: ${step.name}`);
      }
    }
  }

  const matrix = workflow.jobs?.[F004_MATRIX_JOB_ID];
  const indexes = matrix?.strategy?.matrix?.shard_index;
  assert.deepEqual(indexes, [0, 1, 2, 3, 4, 5, 6], "F004 matrix shard drift");
  const guard = matrix.steps.find((step) => step.name === "Require checkout to match exact candidate");
  if (!guard || typeof guard.run !== "string") throw new Error("F004 candidate guard is missing");
  steps.push(localRunStep(guard, sha, {
    EVENT_NAME: "push", EXPECTED_HEAD_SHA: sha, PULL_REQUEST_HEAD_SHA: "",
  }));
  const matrixStep = matrix.steps.find((step) => step.name === "Run canonical F-004 recovery mutation shard");
  assert.equal(matrixStep?.run, F004_MATRIX_RUN, "F004 matrix command drift");
  for (const index of indexes) {
    const run = matrixStep.run.replace("${{ matrix.shard_index }}", String(index));
    steps.push(localRunStep({ ...matrixStep,
      name: `${matrixStep.name} ${index + 1}/${indexes.length}`, run }, sha));
  }

  const sast = workflow.jobs?.sast;
  if (!Array.isArray(sast?.steps)) throw new Error("SAST job is missing");
  for (const step of sast.steps) {
    if (typeof step.run === "string") steps.push(localRunStep(step, sha));
    else if (step.uses && /^(Checkout|Set up Python)$/.test(step.name)) {
      // Local Python is used for the same Semgrep shell commands.
    } else throw new Error(`Unsupported non-shell SAST step: ${step.name}`);
  }
  return steps;
}

const supplemental = MCP_LOCAL_CHECKS.map((run) => ({
  name: `MCP local: ${run}`, run, cwd: root,
}));
const sha = mode === "all" ? gitHead() : null;
const steps = mode === "all" ? [...fullSteps(sha), ...supplemental] :
  [...mcpSteps, ...supplemental];

if (planOnly) {
  console.log(`Local ${mode} gate: ${steps.length} shell commands; ${mcpSteps.length} exact CI MCP steps.`);
  for (const step of mcpSteps) console.log(`${step.name}: ${step.run}`);
  console.log("Hosted MCP and Gemini API probes are separate release gates and are not run here.");
  process.exit(0);
}

if (process.versions.node.split(".")[0] !== "24") {
  throw new Error(`CI uses Node 24; run this gate with Node 24 (found ${process.version})`);
}
const environment = {
  ...process.env,
  CI: "true",
  TZ: "UTC",
  PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH || ""}`,
};
console.log(`Running local ${mode} gate on current worktree with Node ${process.version}.`);
console.log("GitHub checkout/cache/artifact actions remain CI-only; no hosted MCP probe is run.");
let temporary = null;
try {
  if (mode === "all") {
    // CI's SAST job uses setup-python 3.12. Keep pip and Semgrep writes in a
    // disposable local venv so neither user Python nor home settings are changed.
    temporary = mkdtempSync(path.join(tmpdir(), "cybermeters-local-full-gate-"));
    const venv = path.join(temporary, "python-venv");
    const setup = spawnSync(python312(), ["-m", "venv", venv], {
      cwd: root, stdio: "inherit", timeout: 120_000,
    });
    if (setup.error || setup.status !== 0) {
      throw new Error(`Cannot create local Python 3.12 venv: ${setup.error?.message || setup.status}`);
    }
    environment.VIRTUAL_ENV = venv;
    environment.PATH = `${path.join(venv, "bin")}${path.delimiter}${environment.PATH}`;
    environment.SEMGREP_LOG_FILE = path.join(temporary, "semgrep.log");
    environment.SEMGREP_SETTINGS_FILE = path.join(temporary, "semgrep-settings.yaml");
    environment.XDG_CONFIG_HOME = temporary;
    environment.PIP_CACHE_DIR = path.join(temporary, "pip-cache");
    environment.SSL_CERT_FILE = process.env.SSL_CERT_FILE || "/etc/ssl/cert.pem";
    console.log(`Python 3.12 SAST environment: ${venv}`);
  }
  for (const [index, step] of steps.entries()) runShell(step, index + 1, steps.length, environment);
  console.log(`PASS local ${mode} shell gate: ${steps.length}/${steps.length} commands.`);
} finally {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
}
