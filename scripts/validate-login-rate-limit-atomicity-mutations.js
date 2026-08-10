#!/usr/bin/env node
// F4 PR-2 mutation contract. Each mutant is applied transiently to the real
// module loaded by the Worker, executed in one fresh Node process, and restored
// before the next mutant. Closure/full gates are intentionally absent here.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// CI owns the Node 24 runtime. Do not treat a patch release as a proxy for
// SQLite/RETURNING behaviour: the focused baseline below executes the real
// atomic path, and M7 removes RETURNING to prove that capability is required.
const expectedNodeMajor = 24;
const observedNodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
if (observedNodeMajor !== expectedNodeMajor) {
  console.error(`F4 PR-2 mutations require Node ${expectedNodeMajor}.x; observed ${process.version}`);
  process.exit(1);
}

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-workflow-abuse-coverage.js");
const authRelative = "workers/scan-api/src/routes/auth.js";
const rateRelative = "workers/scan-api/src/lib/rate-limit.js";
const targets = {
  auth: path.join(root, ...authRelative.split("/")),
  rate: path.join(root, ...rateRelative.split("/")),
};
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");

function git(args, encoding = "utf8") {
  return execFileSync("git", args, { cwd: root, encoding });
}

function worktreeFingerprint() {
  const status = git(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  const paths = status.split("\0").filter(Boolean).map((entry) => entry.slice(3)).sort();
  const hash = crypto.createHash("sha256").update(status);
  for (const relative of paths) {
    const absolute = path.join(root, relative);
    hash.update(relative);
    hash.update("\0");
    if (fs.existsSync(absolute) && fs.statSync(absolute).isFile()) {
      hash.update(fs.readFileSync(absolute));
    }
    hash.update("\0");
  }
  return hash.digest("hex");
}

function replaceExactly(source, from, to, label) {
  if (from === to) throw new Error(`${label}: no-op replacement rejected`);
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}

function fixtureFailures(output) {
  return String(output).split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("FAIL [F4 PR-2 login rate-limit atomicity] "))
    .map((line) => line.slice("FAIL [F4 PR-2 login rate-limit atomicity] ".length).split(" — ")[0]);
}

function fixtureObservations(output) {
  const observations = new Map();
  for (const line of String(output).split(/\r?\n/)) {
    if (!line.startsWith("F4_PR2_OBSERVATION ")) continue;
    const observation = JSON.parse(line.slice("F4_PR2_OBSERVATION ".length));
    observations.set(observation.id, observation);
  }
  return observations;
}

function runFocusedValidator({ timeout = 180_000, env = {} } = {}) {
  const child = spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: "utf8",
    timeout,
    env: {
      ...process.env,
      F4_PR2_FOCUSED: "1",
      F4_PR2_FAIL_FIRST: "0",
      F4_PR2_BARRIER_MODE: "attached",
      ...env,
    },
  });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  const failures = fixtureFailures(output);
  let observations = new Map();
  try { observations = fixtureObservations(child.stdout || ""); } catch { /* invalid output stays non-normal */ }
  const summary = String(child.stdout || "").match(/Workflow abuse coverage: (\d+)\/(\d+) passed/);
  const total = summary ? Number(summary[2]) : null;
  const passed = summary ? Number(summary[1]) : null;
  const normalSuccess = child.error == null && child.signal == null && child.status === 0 &&
    total === 8 && passed === 8 && failures.length === 0 && observations.size === 8;
  const normalFailure = child.error == null && child.signal == null && child.status === 1 &&
    total === 8 && passed + failures.length === 8 && observations.size === 8;
  return { child, output, failures, observations, normalSuccess, normalFailure };
}

const authIpAtomicAnchor = `        // Abuse-critical: never allow unmetered credential guessing.
        { failClosed: true, atomic: true },`;
const authAccountAtomicAnchor = `        "login_account",
        20,
        900, // 15 minutes
        { failClosed: true, atomic: true },`;
const accountScopeAnchor = `        [{ scope: "user", scope_id: await rateLimitScopeId("login_acct", email) }],`;

const mutants = [
  {
    id: "M1", target: "auth", expected: ["X1", "X3", "X4a"], sibling: "X2",
    mutate: (source) => replaceExactly(source, authIpAtomicAnchor,
      `        // Abuse-critical: never allow unmetered credential guessing.
        { failClosed: true, atomic: false },`, "M1 site-1 atomic flag"),
    observations: (items) => items.get("X1")?.allowed === 11 && items.get("X1")?.denied429 === 0 &&
      items.get("X1")?.deferred_reads === 11 && items.get("X3")?.deferred_reads === 10 &&
      items.get("X4a")?.login_count === 10,
  },
  {
    id: "M2", target: "auth", expected: ["X2", "X4b"], sibling: "X1",
    mutate: (source) => replaceExactly(source, authAccountAtomicAnchor,
      `        "login_account",
        20,
        900, // 15 minutes
        { failClosed: true, atomic: false },`, "M2 site-2 atomic flag"),
    observations: (items) => items.get("X2")?.allowed === 21 && items.get("X2")?.denied429 === 0 &&
      items.get("X2")?.deferred_reads === 21 && items.get("X4b")?.login_account_count === 20,
  },
  {
    id: "M3", target: "auth", expected: ["X1", "X4a", "X5"], sibling: "X2",
    mutate: (source) => replaceExactly(source,
      "      if (_loginRlResult) {", "      if (false && _loginRlResult) {", "M3 disconnect IP result"),
    observations: (items) => items.get("X5")?.status === 401 && items.get("X5")?.login_account_count === 1,
  },
  {
    id: "M4", target: "auth", expected: ["X2", "X4b"], sibling: "X1",
    mutate: (source) => replaceExactly(source,
      "      if (_loginAcctRl) {", "      if (false && _loginAcctRl) {", "M4 disconnect account result"),
    observations: (items) => items.get("X2")?.allowed === 21 && items.get("X4b")?.allowed === 21,
  },
  {
    id: "M5", target: "auth", expected: ["X5"], sibling: "X2",
    mutate: (source) => replaceExactly(source, authIpAtomicAnchor,
      `        // Abuse-critical: never allow unmetered credential guessing.
        { failClosed: false, atomic: true },`, "M5 site-1 fail-closed flag"),
    observations: (items) => items.get("X5")?.status === 401 && items.get("X5")?.login_account_count === 1,
  },
  {
    id: "M6", target: "rate", expected: ["X1", "X2", "X3", "X4a", "X4b", "X6"], sibling: "X5",
    mutate: (source) => replaceExactly(source,
      "if ((row?.request_count ?? limit + 1) > limit)",
      "if ((row?.request_count ?? limit + 1) >= limit)", "M6 strict boundary"),
  },
  {
    id: "M7", target: "rate", expected: ["X1", "X2", "X3", "X4a", "X4b", "X6", "X7"], sibling: "X5",
    mutate: (source) => replaceExactly(source,
      "             RETURNING request_count", "", "M7 RETURNING removal"),
    observations: (items) => items.get("X1")?.allowed === 0 && items.get("X7")?.login_account_rows === 0,
  },
  {
    id: "M8", target: "auth", expected: ["X2", "X7"], sibling: "X1",
    mutate: (source) => replaceExactly(source, accountScopeAnchor,
      `        [{ scope: "user", scope_id: await rateLimitScopeId("login_acct", email) },
         { scope: "user", scope_id: "f4_pr2_second_scope" }],`, "M8 second account scope"),
    observations: (items) => items.get("X2")?.login_account_rows === 2 &&
      items.get("X7")?.login_account_rows === 2,
  },
];

const parentRateBytes = git(["show", `HEAD:${rateRelative}`], null);
if (!Buffer.isBuffer(parentRateBytes) || digest(parentRateBytes) !== digest(fs.readFileSync(targets.rate))) {
  console.error("F4 PR-2 mutation preflight: rate-limit.js differs from parent");
  process.exit(1);
}

const initialFingerprint = worktreeFingerprint();
const candidateAuthHash = digest(fs.readFileSync(targets.auth));
const parentRateHash = digest(parentRateBytes);
const baseline = runFocusedValidator();
if (!baseline.normalSuccess) {
  console.error(`F4 PR-2 mutation preflight: focused baseline is not 8/8\n${baseline.output}`);
  process.exit(1);
}
const baselineX1 = baseline.observations.get("X1");
const baselineX2 = baseline.observations.get("X2");
const baselineX4a = baseline.observations.get("X4a");
if (!(baselineX1?.allowed === 10 && baselineX1?.denied429 === 1 && baselineX1?.deferred_reads === 0 &&
  baselineX2?.allowed === 20 && baselineX2?.denied429 === 1 && baselineX2?.deferred_reads === 0 &&
  baseline.observations.get("X3")?.deferred_reads === 0 && baselineX4a?.login_count === 11)) {
  console.error("F4 PR-2 mutation preflight: atomic baseline observations are not discriminating");
  process.exit(1);
}
console.log(`PASS atomic baseline 8/8; X1=10+1, X2=20+1, deferred reads=0, sequential persisted=${baselineX4a.login_count}`);

let activeRestore = null;
const restoreActive = () => {
  if (!activeRestore) return;
  fs.writeFileSync(activeRestore.file, activeRestore.bytes);
  activeRestore = null;
};
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    restoreActive();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

let failures = 0;
let killed = 0;
for (const mutant of mutants) {
  const file = targets[mutant.target];
  const original = fs.readFileSync(file);
  try {
    const mutated = mutant.mutate(original.toString("utf8"));
    fs.writeFileSync(file, mutated);
    activeRestore = { file, bytes: original };
    const result = runFocusedValidator();
    const exact = JSON.stringify(result.failures) === JSON.stringify(mutant.expected);
    const siblingGreen = !result.failures.includes(mutant.sibling);
    const observationProof = mutant.observations ? mutant.observations(result.observations) : true;
    if (result.normalFailure && exact && siblingGreen && observationProof) {
      killed += 1;
      console.log(`PASS ${mutant.id} exact FAIL set ${JSON.stringify(result.failures)}; sibling ${mutant.sibling} green`);
    } else {
      failures += 1;
      console.error(`FAIL ${mutant.id} expected=${JSON.stringify(mutant.expected)} actual=${JSON.stringify(result.failures)} sibling=${mutant.sibling}:${siblingGreen ? "green" : "red"} observation=${observationProof} status=${result.child.status} signal=${result.child.signal} error=${result.child.error?.message || "none"}\n${result.output}`);
    }
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${mutant.id} — ${error?.message || error}`);
  } finally {
    fs.writeFileSync(file, original);
    activeRestore = null;
    const targetHash = digest(fs.readFileSync(file));
    const expectedTargetHash = mutant.target === "rate" ? parentRateHash : candidateAuthHash;
    if (targetHash !== expectedTargetHash) {
      failures += 1;
      console.error(`FAIL ${mutant.id} target hash not restored`);
    }
    if (digest(fs.readFileSync(targets.rate)) !== parentRateHash) {
      failures += 1;
      console.error(`FAIL ${mutant.id} rate-limit.js parent hash not restored`);
    }
    if (worktreeFingerprint() !== initialFingerprint) {
      failures += 1;
      console.error(`FAIL ${mutant.id} whole-worktree fingerprint not restored`);
    }
  }
}

let controls = 0;
const control = (name, pass) => {
  if (pass) { controls += 1; console.log(`PASS ${name}`); }
  else { failures += 1; console.error(`FAIL ${name}`); }
};

try {
  replaceExactly("anchor", "anchor", "anchor", "no-op control");
  control("NO_OP_REJECTED", false);
} catch (error) {
  control("NO_OP_REJECTED", /no-op/.test(error.message));
}

try {
  replaceExactly("canonical", "wrong-anchor", "replacement", "wrong-anchor control");
  control("WRONG_ANCHOR_REJECTED", false);
} catch (error) {
  control("WRONG_ANCHOR_REJECTED", /anchor count 0/.test(error.message));
}

// With M1 active but the barrier deliberately attached to the wrong action,
// synchronous SQLite yields the safe legacy 10+1 outcome. The missing X3 red
// makes the frozen M1 kill set fail, proving the real barrier is discriminating.
{
  const file = targets.auth;
  const original = fs.readFileSync(file);
  try {
    fs.writeFileSync(file, mutants[0].mutate(original.toString("utf8")));
    activeRestore = { file, bytes: original };
    const result = runFocusedValidator({ env: { F4_PR2_BARRIER_MODE: "wrong_action" } });
    const x1 = result.observations.get("X1");
    control("WRONGLY_ATTACHED_BARRIER_REJECTED", result.normalFailure &&
      JSON.stringify(result.failures) === JSON.stringify(["X1", "X4a"]) &&
      x1?.allowed === 10 && x1?.denied429 === 1 && x1?.deferred_reads === 0 &&
      JSON.stringify(result.failures) !== JSON.stringify(mutants[0].expected));
  } finally {
    fs.writeFileSync(file, original);
    activeRestore = null;
  }
}

{
  const file = targets.auth;
  const original = fs.readFileSync(file);
  try {
    fs.writeFileSync(file, `${original.toString("utf8")}\nthis is invalid syntax !\n`);
    activeRestore = { file, bytes: original };
    const result = runFocusedValidator();
    control("SYNTAX_FAILURE_REJECTED", !result.normalFailure && !result.normalSuccess && result.failures.length === 0);
  } finally {
    fs.writeFileSync(file, original);
    activeRestore = null;
  }
}

{
  const result = runFocusedValidator({ timeout: 1 });
  control("TIMEOUT_REJECTED", !result.normalFailure && !result.normalSuccess &&
    result.child.error?.code === "ETIMEDOUT");
}

if (digest(fs.readFileSync(targets.auth)) !== candidateAuthHash) {
  failures += 1;
  console.error("FAIL final auth.js candidate hash drift");
}
if (digest(fs.readFileSync(targets.rate)) !== parentRateHash) {
  failures += 1;
  console.error("FAIL final rate-limit.js parent hash drift");
}
if (worktreeFingerprint() !== initialFingerprint) {
  failures += 1;
  console.error("FAIL final whole-worktree fingerprint drift");
}

console.log(`F4 PR-2 mutations: ${killed}/${mutants.length} exact semantic kills; ${controls}/5 invalid-kill controls rejected`);
if (failures || killed !== mutants.length || controls !== 5) process.exit(1);
