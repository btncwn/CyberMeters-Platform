#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { spawn, spawnSync } from "node:child_process";
import {
  LOCAL_GATE_DECISIONS,
  MAX_GATE_MS,
  MAX_FOCUSED_PATHS,
  PACKS,
  PACK_ORDER,
  classifyFocusedChanges,
  localFocusedGatePolicyFingerprint,
  normalizeRepoPath,
} from "./local-focused-gate-policy.js";
import {
  acquireRepositoryLock,
  installRepositoryLockSignalHandlers,
  parseInputArguments,
  parseLanePathsBuffer,
  parseNameStatusBuffer,
  repositoryLockPath,
  runLocalFocusedGate,
  scanMutationResidue,
  wholeSourceFingerprint,
} from "./run-local-focused-gate.js";

const EXPECTED_POLICY_FINGERPRINT = "4be45d639f97c53aa108f41ac75f9cb255fd17883551db957002a4954fb4702d";
const EXPECTED_ASSERTIONS = 104;
const SAFE_RECORD = Object.freeze({ status: "M", code: "M", mode: "100644", type: "blob", binary: false, valid_utf8: true });
const RUNNER_MODULE_URL = new URL("./run-local-focused-gate.js", import.meta.url).href;

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) {
    passed += 1;
    console.log(`PASS ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

function expectThrow(name, action, pattern) {
  let error = null;
  try { action(); } catch (caught) { error = caught; }
  ok(name, error && (!pattern || pattern.test(error.message)), error?.message || "did not throw");
}

function record(relative, overrides = {}) {
  return { ...SAFE_RECORD, path: relative, ...overrides };
}

function classify(paths, options = {}) {
  const records = paths.map((relative) => typeof relative === "string" ? record(relative) : relative);
  return classifyFocusedChanges({
    records,
    inputMode: options.inputMode || "worktree",
    docsClassification: options.docsClassification || null,
  });
}

function git(repo, args) {
  const child = spawnSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (child.error || child.signal !== null || child.status !== 0) {
    throw new Error(`fixture git ${args[0]} failed: ${child.stderr || child.error?.message || child.status}`);
  }
  return child.stdout.trim();
}

function write(repo, relative, contents, mode = 0o644) {
  const absolute = path.join(repo, relative);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, contents, { mode });
}

function makeRepo(files = { "scripts/validate-scan-deadline.js": "baseline\n" }) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-gate-fixture-"));
  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Focused Gate Fixture"]);
  git(repo, ["config", "user.email", "focused-gate@example.invalid"]);
  for (const [relative, contents] of Object.entries(files)) write(repo, relative, contents);
  git(repo, ["add", "--all"]);
  git(repo, ["commit", "-q", "-m", "baseline"]);
  return repo;
}

function removeRepo(repo) {
  fs.rmSync(repo, { recursive: true, force: true });
}

function successfulHooks(lockRoot, extra = {}) {
  return {
    nodeVersion: "24.9.0",
    dependenciesReady: () => true,
    executeCommand: () => ({ status: 0, signal: null, error: null, stdout: "", stderr: "" }),
    lockRoot,
    log: () => {},
    ...extra,
  };
}

function spawnCaptured(args) {
  const child = spawn(process.execPath, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  const done = new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, done, stdout: () => stdout, stderr: () => stderr };
}

async function waitUntil(predicate, timeoutMs, description) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for ${description}`);
}

function percentile(sorted, percentileValue) {
  if (!sorted.length) return 0;
  const index = Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1);
  return sorted[index];
}

function warmSafeFixtureRuns(count) {
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-gate-locks-"));
  const samples = [];
  const signatures = [];
  try {
    write(repo, "scripts/validate-scan-deadline.js", "focused change\n");
    for (let index = 0; index < count; index += 1) {
      const started = performance.now();
      const run = runLocalFocusedGate({
        argv: ["--worktree"],
        repoRoot: repo,
        hooks: successfulHooks(lockRoot),
      });
      const elapsed = performance.now() - started;
      if (run.exitCode !== 0 || run.result.decision !== LOCAL_GATE_DECISIONS.FOCUSED) {
        throw new Error(`warm fixture ${index + 1} failed: ${run.result.reason}`);
      }
      samples.push(Number(elapsed.toFixed(3)));
      signatures.push(JSON.stringify({
        paths: run.result.changed_paths,
        packs: run.result.selected_packs,
        commands: run.result.commands,
        before: run.result.source_fingerprint_before,
        after: run.result.source_fingerprint_after,
      }));
    }
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
  const sorted = [...samples].sort((left, right) => left - right);
  return {
    runs: count,
    samples_ms: samples,
    p50_ms: percentile(sorted, 50),
    p95_ms: percentile(sorted, 95),
    deterministic: new Set(signatures).size === 1,
    scope: "fixture harness only; canonical proof commands were not executed",
  };
}

const warmOnly = process.argv.find((arg) => arg.startsWith("--warm-safe-fixture-runs="));
if (warmOnly) {
  const raw = warmOnly.slice("--warm-safe-fixture-runs=".length);
  if (!/^[1-9][0-9]*$/.test(raw) || Number(raw) > 20) {
    console.error("warm fixture run count must be an integer from 1 to 20");
    process.exit(2);
  }
  try {
    console.log(JSON.stringify(warmSafeFixtureRuns(Number(raw))));
    process.exit(0);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

// Policy identity and exact order.
ok("policy semantic fingerprint is exact and pinned",
  localFocusedGatePolicyFingerprint() === EXPECTED_POLICY_FINGERPRINT,
  localFocusedGatePolicyFingerprint());
ok("pack order is exact", JSON.stringify(PACK_ORDER) === JSON.stringify([
  "runtime_evidence", "report_cx", "ci_policy", "docs_only",
]));
ok("focused path limit is 40", MAX_FOCUSED_PATHS === 40);
ok("every pack command id is globally unique",
  (() => {
    const ids = PACK_ORDER.flatMap((packId) => PACKS[packId].commands.map((item) => item.id));
    return ids.length === new Set(ids).size;
  })());
ok("no focused command invokes an installer or network client",
  PACK_ORDER.flatMap((packId) => PACKS[packId].commands).every((item) =>
    !/(?:install-governed-dependencies|npm\s+(?:ci|install)|curl|wget|wrangler\s+deploy|gh\s+)/.test(item.display)));

// Exactly three runner input modes.
ok("range input mode parses", parseInputArguments(["--range", "a".repeat(40), "b".repeat(40)]).mode === "range");
ok("whole-worktree input mode parses", parseInputArguments(["--worktree"]).mode === "worktree");
ok("lane-worktree input mode parses",
  parseInputArguments(["--worktree", "--lane-paths-file", "/tmp/lane.paths"]).mode === "lane");
for (const [name, argv] of [
  ["missing input", []],
  ["malformed range SHA", ["--range", "bad", "b".repeat(40)]],
  ["identical range SHA", ["--range", "a".repeat(40), "a".repeat(40)]],
  ["mixed input modes", ["--range", "a".repeat(40), "b".repeat(40), "--worktree"]],
  ["unknown input flag", ["--all"]],
]) {
  expectThrow(`${name} fails closed during CLI parsing`, () => parseInputArguments(argv));
}

// NUL-safe parsing and lane path validation.
ok("name-status parser retains A/M records",
  JSON.stringify(parseNameStatusBuffer(Buffer.from("A\0a.js\0M\0b.js\0"))) ===
    JSON.stringify([{ status: "A", code: "A", path: "a.js" }, { status: "M", code: "M", path: "b.js" }]));
ok("name-status parser retains rename old/new identity",
  parseNameStatusBuffer(Buffer.from("R100\0old.js\0new.js\0"))[0].old_path === "old.js");
expectThrow("truncated name-status record fails closed",
  () => parseNameStatusBuffer(Buffer.from("M\0")), /truncated/);
expectThrow("invalid UTF-8 name-status output fails closed",
  () => parseNameStatusBuffer(Buffer.from([0xff, 0])), /UTF-8/);
ok("canonical lane path file parses",
  JSON.stringify(parseLanePathsBuffer(Buffer.from("scripts/a.js\0workers/b.js\0"))) ===
    JSON.stringify(["scripts/a.js", "workers/b.js"]));
for (const [name, contents] of [
  ["empty", Buffer.alloc(0)],
  ["blank record", Buffer.from("scripts/a.js\0\0scripts/b.js\0")],
  ["duplicate", Buffer.from("scripts/a.js\0scripts/a.js\0")],
  ["absolute", Buffer.from("/tmp/a\0")],
  ["parent-relative", Buffer.from("../a\0")],
  ["backslash", Buffer.from("scripts\\a.js\0")],
  ["control character", Buffer.from("scripts/a\n.js\0")],
  ["invalid UTF-8", Buffer.from([0xff, 0])],
]) {
  expectThrow(`lane path ${name} fails closed`, () => parseLanePathsBuffer(contents));
}
ok("path normalizer accepts canonical repo paths", normalizeRepoPath("scripts/a.js") === "scripts/a.js");
ok("path normalizer rejects dot segments", normalizeRepoPath("scripts/../a.js") === null);

// Exact positive mapping and deterministic command order.
const runtime = classify(["workers/scan-api/src/engines/scan-engine.js"]);
ok("runtime path selects only runtime/evidence", runtime.decision === "FOCUSED" &&
  JSON.stringify(runtime.selected_packs) === JSON.stringify(["runtime_evidence"]));
ok("runtime command order is exact", runtime.commands.map((item) => item.id).join(",") === [
  "runtime-scan-budget-syntax", "runtime-scan-engine-syntax", "runtime-scan-deadline",
  "runtime-email-deadline", "runtime-phase5-evidence", "runtime-partial-scan",
  "runtime-scan-telemetry", "runtime-cookie-ownership", "runtime-dmarcbis-p2",
].join(","));
const report = classify(["workers/scan-api/src/engines/pdf.js"]);
ok("PDF path selects only report/CX", report.decision === "FOCUSED" && report.selected_packs[0] === "report_cx");
ok("report/CX retains focused frontend test and build",
  report.commands.some((item) => item.id === "report-frontend-focused-test") &&
  report.commands.at(-1).id === "report-frontend-build");
const ciPolicy = classify(["scripts/local-focused-gate-policy.js"]);
ok("local gate source selects only CI policy", ciPolicy.decision === "FOCUSED" && ciPolicy.selected_packs[0] === "ci_policy");
ok("CI policy pack validates the local gate last",
  ciPolicy.commands.at(-1).id === "ci-local-focused-gate");
const threePack = classify([
  "scripts/validate-scan-deadline.js",
  "workers/scan-api/src/engines/pdf.js",
  "scripts/ci-workflow-policy.js",
]);
ok("three-pack infrastructure lane remains focused", threePack.decision === "FOCUSED" &&
  JSON.stringify(threePack.selected_packs) === JSON.stringify(["runtime_evidence", "report_cx", "ci_policy"]));
ok("three-pack command order follows fixed pack order",
  threePack.commands.findIndex((item) => item.id === "runtime-scan-budget-syntax") <
  threePack.commands.findIndex((item) => item.id === "report-pdf-syntax") &&
  threePack.commands.findIndex((item) => item.id === "report-pdf-syntax") <
  threePack.commands.findIndex((item) => item.id === "ci-classifier-syntax"));
const threePackPermuted = classify([
  "scripts/ci-workflow-policy.js",
  "workers/scan-api/src/engines/pdf.js",
  "scripts/validate-scan-deadline.js",
]);
ok("identical path sets have identical pack and command order",
  JSON.stringify({ packs: threePack.selected_packs, commands: threePack.commands.map((item) => item.id) }) ===
  JSON.stringify({ packs: threePackPermuted.selected_packs, commands: threePackPermuted.commands.map((item) => item.id) }));

// Full-assurance and uncertainty negatives.
for (const [name, records, expectedDecision] of [
  ["delete", [record("scripts/validate-scan-deadline.js", { status: "D", code: "D", mode: null })], "RUN_ALL_REQUIRED"],
  ["rename", [record("scripts/validate-scan-deadline.js", { status: "R100", code: "R" })], "RUN_ALL_REQUIRED"],
  ["copy", [record("scripts/validate-scan-deadline.js", { status: "C100", code: "C" })], "RUN_ALL_REQUIRED"],
  ["type change", [record("scripts/validate-scan-deadline.js", { status: "T", code: "T" })], "RUN_ALL_REQUIRED"],
  ["conflict", [record("scripts/validate-scan-deadline.js", { status: "U", code: "U" })], "RUN_ALL_REQUIRED"],
  ["binary", [record("scripts/validate-scan-deadline.js", { binary: true })], "RUN_ALL_REQUIRED"],
  ["symlink", [record("scripts/validate-scan-deadline.js", { mode: "120000" })], "RUN_ALL_REQUIRED"],
  ["submodule", [record("scripts/validate-scan-deadline.js", { mode: "160000", type: "commit" })], "RUN_ALL_REQUIRED"],
  ["unsupported mode", [record("scripts/validate-scan-deadline.js", { mode: "100600" })], "RUN_ALL_REQUIRED"],
  ["invalid UTF-8", [record("scripts/validate-scan-deadline.js", { valid_utf8: false })], "UNKNOWN_FAIL_CLOSED"],
]) {
  const decision = classifyFocusedChanges({ records, inputMode: "worktree" });
  ok(`${name} record cannot produce focused PASS`, decision.decision === expectedDecision, decision.decision);
}
ok("duplicate changed path fails closed as uncertainty",
  classifyFocusedChanges({ records: [record("scripts/validate-scan-deadline.js"), record("scripts/validate-scan-deadline.js")], inputMode: "worktree" }).decision === "UNKNOWN_FAIL_CLOSED");
ok("empty changed inventory fails closed",
  classifyFocusedChanges({ records: [], inputMode: "worktree" }).decision === "UNKNOWN_FAIL_CLOSED");
ok("41 changed paths require full assurance",
  classifyFocusedChanges({ records: Array.from({ length: 41 }, (_, index) => record(`unknown/path-${index}.js`)), inputMode: "worktree" }).decision === "RUN_ALL_REQUIRED");
ok("unknown Worker path overrides a known focused path", classify([
  "workers/scan-api/src/engines/pdf.js",
  "workers/scan-api/src/engines/new-unknown-engine.js",
]).decision === "RUN_ALL_REQUIRED");
for (const sensitive of [
  "database/migrations/999-test.sql",
  "workers/scan-api/src/auth/session.js",
  "workers/scan-api/src/lib/tenant-isolation.js",
  "workers/scan-api/src/engines/scoring.js",
  "workers/scan-api/src/lib/remediation-registry.js",
  "scripts/deploy-production.js",
]) {
  ok(`sensitive path requires full assurance: ${sensitive}`,
    classify(["workers/scan-api/src/engines/pdf.js", sensitive]).decision === "RUN_ALL_REQUIRED");
}
ok("canonical governance path requires full assurance and ownership warning",
  (() => {
    const decision = classify(["docs/PRE-BETA-EXECUTION-BACKLOG.md"], { inputMode: "range" });
    return decision.decision === "RUN_ALL_REQUIRED" && decision.ownership_warning === true;
  })());
ok("OPERATIONS and release-checklist authorities carry the governance ownership warning",
  ["OPERATIONS.md", "docs/07-RELEASE-CHECKLIST.md"].every((relative) => {
    const decision = classify([relative], { inputMode: "range" });
    return decision.decision === "RUN_ALL_REQUIRED" && decision.ownership_warning === true;
  }));
ok("public capabilities claim requires full assurance",
  classify(["docs/CAPABILITIES.md"], { inputMode: "range" }).decision === "RUN_ALL_REQUIRED");
ok("worktree docs-only change cannot synthesize safe-docs proof",
  classify(["docs/ordinary.md"]).decision === "RUN_ALL_REQUIRED");
ok("committed safe docs select the existing classifier validator",
  (() => {
    const decision = classify(["docs/ordinary.md"], {
      inputMode: "range",
      docsClassification: { decision: "SAFE_DOCS_ONLY", reason: "fixture proof" },
    });
    return decision.decision === "FOCUSED" && decision.selected_packs[0] === "docs_only";
  })());
ok("stale committed docs evidence fails closed",
  classify(["docs/ordinary.md"], {
    inputMode: "range",
    docsClassification: { decision: "UNKNOWN_FAIL_CLOSED", reason: "stale evidence" },
  }).decision === "UNKNOWN_FAIL_CLOSED");

// Actual Git inventory, range and lane contracts in disposable repositories.
{
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  try {
    const empty = runLocalFocusedGate({ argv: ["--worktree"], repoRoot: repo, hooks: successfulHooks(lockRoot) });
    ok("empty worktree never produces focused PASS", empty.exitCode === 2 && empty.result.decision === "UNKNOWN_FAIL_CLOSED");
    const nonexistent = runLocalFocusedGate({
      argv: ["--range", "a".repeat(40), "b".repeat(40)], repoRoot: repo, hooks: successfulHooks(lockRoot),
    });
    ok("nonexistent range SHA fails closed", nonexistent.exitCode === 2 && nonexistent.result.decision === "UNKNOWN_FAIL_CLOSED");

    const base = git(repo, ["rev-parse", "HEAD"]);
    write(repo, "scripts/validate-scan-deadline.js", "range change\n");
    git(repo, ["add", "--all"]);
    git(repo, ["commit", "-q", "-m", "range change"]);
    const head = git(repo, ["rev-parse", "HEAD"]);
    const rangeRun = runLocalFocusedGate({ argv: ["--range", base, head], repoRoot: repo, hooks: successfulHooks(lockRoot) });
    ok("committed range resolves complete focused scope", rangeRun.exitCode === 0 &&
      rangeRun.result.scope_complete === true && rangeRun.result.partial_lane === false);
    ok("committed range JSON pins exact base, head and merge-base identities",
      rangeRun.result.base_sha === base && rangeRun.result.head_sha === head && rangeRun.result.merge_base === base);
    ok("local range PASS is never merge evidence", rangeRun.result.merge_gate_eligible === false);

    write(repo, "scripts/validate-scan-deadline.js", "worktree change\n");
    const whole = runLocalFocusedGate({ argv: ["--worktree"], repoRoot: repo, hooks: successfulHooks(lockRoot) });
    ok("whole-worktree focused run is complete but non-merge", whole.exitCode === 0 &&
      whole.result.scope_complete === true && whole.result.merge_gate_eligible === false);
    ok("focused JSON result carries stable whole-source fingerprints",
      /^[0-9a-f]{64}$/.test(whole.result.source_fingerprint_before) &&
      whole.result.source_fingerprint_before === whole.result.source_fingerprint_after);
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

// L3 residue sweep: exact families fail closed, remain in place and invalidate
// the sample; benign dotfiles and legitimate worktree metadata are ignored.
{
  const repo = makeRepo();
  try {
    const benignPaths = [
      "workers/scan-api/src/engines/.customer-mutation-notes.js",
      "frontend/src/components/.component.a1-mutation.1.js",
      "scripts/.mutant-guide.md",
      "database/migrations/.migration-guide.sql",
    ];
    for (const relative of benignPaths) write(repo, relative, "benign\n");
    write(repo, ".git/worktrees/legitimate/gitdir", "/tmp/legitimate-worktree/.git\n");
    ok("residue sweep avoids benign dotfiles and legitimate worktree metadata",
      scanMutationResidue(repo).length === 0, JSON.stringify(scanMutationResidue(repo)));
  } finally {
    removeRepo(repo);
  }
}

{
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  try {
    write(repo, "scripts/validate-scan-deadline.js", "focused\n");
    const residueFiles = [
      "workers/scan-api/src/engines/.headers.p5-mutant.1.1.js",
      "workers/scan-api/src/engines/cert-events.__mutant_fixture__.mjs",
      "workers/scan-api/src/engines/.subop-child-control.fixture.mjs",
      "workers/scan-api/src/routes/.route-mutant.1.js",
      "workers/scan-api/src/lib/.service-mutant.1.js",
      "frontend/src/components/.report.a1-mutant.1.js",
      "frontend/src/components/Report.a1-mutant.1.test.jsx",
      "scripts/.validator-mutant.1.js",
      "scripts/.validator.ct2a1-mutant.1.mjs",
      "database/migrations/.109-mutant-probe.sql",
      ".d1-rollback-probe-fixture.mjs",
    ];
    for (const relative of residueFiles) write(repo, relative, "residue\n");
    write(repo, ".f004-mutation-worktrees/fixture/.git", "gitdir fixture\n");
    write(repo, ".git/worktrees/f004-fixture/gitdir",
      `${path.join(repo, ".f004-mutation-worktrees", "fixture", ".git")}\n`);

    const expected = [
      ".d1-rollback-probe-fixture.mjs",
      ".f004-mutation-worktrees",
      ".git/worktrees/f004-fixture",
      ...residueFiles.filter((relative) => !relative.startsWith(".d1-")),
    ].sort((left, right) => left.localeCompare(right));
    const detected = scanMutationResidue(repo);
    ok("residue sweep detects every pinned dot/sibling/root/F004 family with exact paths",
      JSON.stringify(detected) === JSON.stringify(expected), JSON.stringify(detected));

    const beforeFingerprint = wholeSourceFingerprint(repo);
    let executed = 0;
    const run = runLocalFocusedGate({
      argv: ["--worktree"], repoRoot: repo,
      hooks: successfulHooks(lockRoot, { executeCommand: () => { executed += 1; } }),
    });
    const afterFingerprint = wholeSourceFingerprint(repo);
    ok("pre-existing residue fails before command execution",
      run.exitCode === 1 && run.result.decision === "FAILED" && executed === 0 &&
      /timing sample INVALID/.test(run.result.reason));
    ok("pre-existing residue is recorded exactly and keeps the sample invalid",
      JSON.stringify(run.result.residue_paths_before) === JSON.stringify(expected) &&
      run.result.timing_sample_valid === false && run.result.residue_checks[0]?.phase === "preflight");
    ok("pre-existing residue is never deleted or moved",
      residueFiles.every((relative) => fs.existsSync(path.join(repo, relative))) &&
      fs.existsSync(path.join(repo, ".f004-mutation-worktrees")) &&
      fs.existsSync(path.join(repo, ".git/worktrees/f004-fixture")));
    ok("failed preflight residue sweep leaves the source fingerprint unchanged",
      beforeFingerprint === afterFingerprint);
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

{
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  const created = "workers/scan-api/src/engines/.command.p4-mutant.1.1.js";
  try {
    write(repo, "scripts/validate-scan-deadline.js", "focused\n");
    let commands = 0;
    const run = runLocalFocusedGate({
      argv: ["--worktree"], repoRoot: repo,
      hooks: successfulHooks(lockRoot, {
        executeCommand: () => {
          commands += 1;
          write(repo, created, "command residue\n");
          return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
        },
      }),
    });
    ok("command-created residue stops the lane after the creating command with its exact path",
      run.exitCode === 1 && run.result.decision === "FAILED" && commands === 1 &&
      run.result.command_results[0]?.residue_paths_after?.includes(created) &&
      /timing sample INVALID/.test(run.result.reason));
    ok("command-created residue remains in place and changes the recorded source fingerprint",
      fs.existsSync(path.join(repo, created)) && run.result.timing_sample_valid === false &&
      run.result.source_fingerprint_before !== run.result.source_fingerprint_after);
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

{
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  try {
    write(repo, "scripts/validate-scan-deadline.js", "focused\n");
    const run = runLocalFocusedGate({ argv: ["--worktree"], repoRoot: repo, hooks: successfulHooks(lockRoot) });
    ok("clean focused run records empty pre/post residue sets and a valid timing sample",
      run.exitCode === 0 && run.result.timing_sample_valid === true &&
      run.result.residue_paths_before.length === 0 && run.result.residue_paths_after.length === 0 &&
      run.result.residue_checks.every((check) => check.paths.length === 0) &&
      run.result.command_results.every((command) => command.residue_paths_after.length === 0));
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

{
  const repo = makeRepo({
    "scripts/validate-scan-deadline.js": "baseline A\n",
    "scripts/validate-email-deadline-evidence.js": "baseline B\n",
  });
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  const laneFile = path.join(os.tmpdir(), `local-focused-lane-${process.pid}-${Date.now()}.nul`);
  try {
    write(repo, "scripts/validate-scan-deadline.js", "changed A\n");
    write(repo, "scripts/validate-email-deadline-evidence.js", "changed B\n");
    fs.writeFileSync(laneFile, "scripts/validate-scan-deadline.js\0");
    const lane = runLocalFocusedGate({
      argv: ["--worktree", "--lane-paths-file", laneFile], repoRoot: repo, hooks: successfulHooks(lockRoot),
    });
    ok("lane mode lists omitted concurrent paths", lane.exitCode === 0 &&
      lane.result.omitted_worktree_paths.includes("scripts/validate-email-deadline-evidence.js"));
    ok("lane PASS remains partial and non-merge", lane.result.partial_lane === true &&
      lane.result.scope_complete === false && lane.result.merge_gate_eligible === false);
    fs.writeFileSync(laneFile, "scripts/not-changed.js\0");
    const missing = runLocalFocusedGate({
      argv: ["--worktree", "--lane-paths-file", laneFile], repoRoot: repo, hooks: successfulHooks(lockRoot),
    });
    ok("lane path absent from worktree inventory fails closed",
      missing.exitCode === 2 && missing.result.decision === "UNKNOWN_FAIL_CLOSED");
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
    fs.rmSync(laneFile, { force: true });
  }
}

// Shallow and diverged range identities fail closed.
{
  const source = makeRepo();
  let shallow = null;
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  try {
    write(source, "scripts/validate-scan-deadline.js", "second\n");
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "second"]);
    shallow = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-shallow-parent-"));
    fs.rmdirSync(shallow);
    git(os.tmpdir(), ["clone", "-q", "--depth", "1", `file://${source}`, shallow]);
    const head = git(shallow, ["rev-parse", "HEAD"]);
    const shallowRun = runLocalFocusedGate({
      argv: ["--range", "a".repeat(40), head], repoRoot: shallow,
      hooks: successfulHooks(lockRoot),
    });
    ok("shallow repository fails closed", shallowRun.exitCode === 2 && /shallow/.test(shallowRun.result.reason));
  } finally {
    removeRepo(source);
    if (shallow) removeRepo(shallow);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

{
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  try {
    const common = git(repo, ["rev-parse", "HEAD"]);
    write(repo, "scripts/validate-scan-deadline.js", "main change\n");
    git(repo, ["add", "--all"]);
    git(repo, ["commit", "-q", "-m", "main"]);
    const base = git(repo, ["rev-parse", "HEAD"]);
    git(repo, ["checkout", "-q", "-b", "side", common]);
    write(repo, "scripts/validate-scan-deadline.js", "side change\n");
    git(repo, ["add", "--all"]);
    git(repo, ["commit", "-q", "-m", "side"]);
    const head = git(repo, ["rev-parse", "HEAD"]);
    const diverged = runLocalFocusedGate({ argv: ["--range", base, head], repoRoot: repo, hooks: successfulHooks(lockRoot) });
    ok("merge-base mismatch fails closed", diverged.exitCode === 2 && diverged.result.decision === "UNKNOWN_FAIL_CLOSED");
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

// Execution failure, dependency, source-integrity and lock negatives.
{
  const repo = makeRepo();
  const lockRoot = fs.mkdtempSync(path.join(os.tmpdir(), "local-focused-locks-"));
  try {
    write(repo, "scripts/validate-scan-deadline.js", "focused\n");
    let executed = 0;
    const missingDeps = runLocalFocusedGate({
      argv: ["--worktree"], repoRoot: repo,
      hooks: successfulHooks(lockRoot, { dependenciesReady: () => false, executeCommand: () => { executed += 1; } }),
    });
    ok("missing dependencies fail without auto-install or command execution",
      missingDeps.exitCode === 1 && executed === 0 && /no install was attempted/.test(missingDeps.result.reason));
    const wrongNode = runLocalFocusedGate({
      argv: ["--worktree"], repoRoot: repo,
      hooks: successfulHooks(lockRoot, { nodeVersion: "26.3.0", executeCommand: () => { executed += 1; } }),
    });
    ok("unsupported Node major fails before command execution", wrongNode.exitCode === 1 && /major 24/.test(wrongNode.result.reason));

    let budgetCommands = 0;
    let clockCalls = 0;
    const exhausted = runLocalFocusedGate({
      argv: ["--worktree"], repoRoot: repo,
      hooks: successfulHooks(lockRoot, {
        now: () => (++clockCalls === 1 ? 0 : MAX_GATE_MS + 1),
        executeCommand: () => {
          budgetCommands += 1;
          return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
        },
      }),
    });
    ok("MAX_GATE_MS exhaustion fails before the next command executes",
      exhausted.exitCode === 1 && exhausted.result.decision === "FAILED" && budgetCommands === 0 &&
      /exceeded 300000ms/.test(exhausted.result.reason));

    for (const [name, execution, reasonPattern] of [
      ["missing command", { status: null, signal: null, error: Object.assign(new Error("missing"), { code: "ENOENT" }), stdout: "", stderr: "" }, /command failed/],
      ["signal-terminated command", { status: null, signal: "SIGTERM", error: null, stdout: "", stderr: "" }, /command failed/],
      ["timed-out command", { status: null, signal: "SIGTERM", error: Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }), stdout: "", stderr: "" }, /timed out/],
      ["non-zero command", { status: 1, signal: null, error: null, stdout: "", stderr: "fixture failure" }, /command failed/],
    ]) {
      const run = runLocalFocusedGate({
        argv: ["--worktree"], repoRoot: repo,
        hooks: successfulHooks(lockRoot, { executeCommand: () => execution }),
      });
      ok(`${name} yields FAILED and never PASS`, run.exitCode === 1 &&
        run.result.decision === "FAILED" && reasonPattern.test(run.result.reason));
    }

    let fingerprintCalls = 0;
    const drift = runLocalFocusedGate({
      argv: ["--worktree"], repoRoot: repo,
      hooks: successfulHooks(lockRoot, {
        fingerprintSource: () => (++fingerprintCalls === 1 ? "a".repeat(64) : "b".repeat(64)),
      }),
    });
    ok("source drift fails immediately without automatic restore",
      drift.exitCode === 1 && /no automatic restore/.test(drift.result.reason));

    const held = acquireRepositoryLock(repo, lockRoot);
    try {
      const second = runLocalFocusedGate({ argv: ["--worktree"], repoRoot: repo, hooks: successfulHooks(lockRoot) });
      ok("second local gate fails before commands while repository lock is held",
        second.exitCode === 1 && /lock is held/.test(second.result.reason));
    } finally {
      held.release();
    }
    const reacquired = acquireRepositoryLock(repo, lockRoot);
    reacquired.release();
    ok("repository lock is released after failed and completed runs", !fs.existsSync(repositoryLockPath(repo, lockRoot)));

    const lockPath = repositoryLockPath(repo, lockRoot);
    const exitedChild = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: exitedChild.pid, token: "stale", repo }));
    const staleRecovered = acquireRepositoryLock(repo, lockRoot);
    staleRecovered.release();
    ok("stale lock is removed only after its recorded PID is proven dead", !fs.existsSync(lockPath));

    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, "owner.json"), "not-json\n");
    expectThrow("unverifiable stale-lock ownership fails closed",
      () => acquireRepositoryLock(repo, lockRoot), /unverifiable ownership/);
    ok("corrupt owner.json is not deleted during failed lock inspection",
      fs.existsSync(lockPath) && fs.readFileSync(path.join(lockPath, "owner.json"), "utf8") === "not-json\n");
    fs.rmSync(lockPath, { recursive: true, force: true });

    const deadForRace = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: deadForRace.pid, token: "race-stale", repo }));
    const barrier = path.join(lockRoot, `stale-takeover-barrier-${process.pid}`);
    const takeoverChildSource = `
      import fs from "node:fs";
      import { acquireRepositoryLock } from ${JSON.stringify(RUNNER_MODULE_URL)};
      const [repo, lockRoot, barrier, id] = process.argv.slice(1);
      fs.writeFileSync(barrier + "." + id + ".ready", "ready\\n");
      while (!fs.existsSync(barrier)) await new Promise((resolve) => setTimeout(resolve, 5));
      try {
        const lock = acquireRepositoryLock(repo, lockRoot);
        console.log("ACQUIRED");
        await new Promise((resolve) => setTimeout(resolve, 400));
        lock.release();
      } catch (error) {
        console.log("REJECTED " + error.message);
      }
    `;
    const contenders = ["a", "b"].map((id) => spawnCaptured([
      "--input-type=module", "-e", takeoverChildSource, repo, lockRoot, barrier, id,
    ]));
    await waitUntil(
      () => ["a", "b"].every((id) => fs.existsSync(`${barrier}.${id}.ready`)),
      5_000,
      "both stale-takeover contenders",
    );
    fs.writeFileSync(barrier, "go\n");
    const takeoverResults = await Promise.all(contenders.map((entry) => entry.done));
    const acquiredCount = takeoverResults.filter((entry) => entry.stdout.includes("ACQUIRED")).length;
    const rejectedCount = takeoverResults.filter((entry) => entry.stdout.includes("REJECTED")).length;
    ok("concurrent stale-lock takeover elects exactly one owner",
      takeoverResults.every((entry) => entry.code === 0) && acquiredCount === 1 && rejectedCount === 1 &&
      !fs.existsSync(lockPath), JSON.stringify(takeoverResults));
    for (const suffix of ["", ".a.ready", ".b.ready"]) fs.rmSync(`${barrier}${suffix}`, { force: true });

    const signalChildSource = `
      import { acquireRepositoryLock, installRepositoryLockSignalHandlers } from ${JSON.stringify(RUNNER_MODULE_URL)};
      const [repo, lockRoot] = process.argv.slice(1);
      const lock = acquireRepositoryLock(repo, lockRoot);
      installRepositoryLockSignalHandlers(lock);
      console.log("READY");
      setInterval(() => {}, 1_000);
    `;
    const signalChild = spawnCaptured(["--input-type=module", "-e", signalChildSource, repo, lockRoot]);
    await waitUntil(() => signalChild.stdout().includes("READY"), 5_000, "SIGTERM lock child readiness");
    signalChild.child.kill("SIGTERM");
    const signalResult = await signalChild.done;
    ok("child SIGTERM releases the repository lock and exits 143",
      signalResult.code === 143 && signalResult.signal === null && !fs.existsSync(lockPath),
      JSON.stringify(signalResult));
  } finally {
    removeRepo(repo);
    fs.rmSync(lockRoot, { recursive: true, force: true });
  }
}

// Fingerprint includes tracked and untracked source bytes, but ignores evidence output.
{
  const repo = makeRepo();
  try {
    const before = wholeSourceFingerprint(repo);
    write(repo, "output/evidence.txt", "operational evidence\n");
    const afterOutput = wholeSourceFingerprint(repo);
    write(repo, "scripts/untracked-source.js", "source\n");
    const afterSource = wholeSourceFingerprint(repo);
    ok("whole-source fingerprint ignores non-source evidence output", before === afterOutput);
    ok("whole-source fingerprint includes untracked source bytes", afterSource !== afterOutput);
  } finally {
    removeRepo(repo);
  }
}

const warm = warmSafeFixtureRuns(5);
ok("five warm safe fixture runs are deterministic", warm.runs === 5 && warm.deterministic, JSON.stringify(warm));
ok("five warm safe fixture samples are all measured", warm.samples_ms.length === 5 &&
  warm.samples_ms.every((sample) => Number.isFinite(sample) && sample >= 0));
console.log(`WARM_SAFE_FIXTURE_TIMING_JSON=${JSON.stringify(warm)}`);

ok("validator assertion count is exact and pinned", passed + failed + 1 === EXPECTED_ASSERTIONS,
  `got ${passed + failed + 1}, want ${EXPECTED_ASSERTIONS}`);

console.log(`\nlocal-focused-gate validation: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
