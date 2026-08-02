#!/usr/bin/env node
// Migration 105 exact-reason mutation proof. Every case runs the canonical
// validator in a fresh process against an isolated SQL file; canonical target
// bytes and the complete worktree fingerprint must remain unchanged.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationPath = path.join(
  root,
  "database/migrations/105-ct-platform-deadline-provenance.sql",
);
const validatorPath = path.join(root, "scripts/validate-ct-platform-abort-migration.js");
const EXPECTED_MUTANTS = 15;

let killed = 0;
let controls = 0;
let failures = 0;
let activeTemp = null;
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => { failures += 1; console.error(`FAIL ${message}`); };

function gitStatusFingerprint() {
  const child = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: root,
    encoding: "utf8",
  });
  if (child.error || child.signal || child.status !== 0) {
    throw new Error(`cannot fingerprint worktree: ${child.error?.message || child.stderr}`);
  }
  return hash(child.stdout);
}

const initialFingerprint = gitStatusFingerprint();
const canonicalBytes = fs.readFileSync(migrationPath);
const canonicalHash = hash(canonicalBytes);

function cleanup() {
  if (!activeTemp) return;
  const resolved = fs.realpathSync(activeTemp);
  const tempRoot = fs.realpathSync(os.tmpdir());
  if (!resolved.startsWith(`${tempRoot}${path.sep}cm-ct105-mut-`)) {
    throw new Error(`refusing unexpected mutation cleanup target ${resolved}`);
  }
  if (fs.lstatSync(activeTemp).isSymbolicLink()) {
    throw new Error(`refusing symlink mutation cleanup target ${activeTemp}`);
  }
  fs.rmSync(activeTemp, { recursive: true, force: false });
  activeTemp = null;
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    try { cleanup(); } catch { /* preserve original interruption */ }
    console.error(`FAIL migration mutation suite interrupted by ${signal}`);
    process.exit(2);
  });
}

function replaceOnce(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}

function replaceRegexOnce(source, pattern, replacement, label) {
  const matches = source.match(new RegExp(pattern.source, pattern.flags.includes("g")
    ? pattern.flags : `${pattern.flags}g`)) || [];
  if (matches.length !== 1) throw new Error(`${label}: anchor count ${matches.length}, expected 1`);
  return source.replace(pattern, replacement);
}

function failureNames(output) {
  return String(output || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function runCase({ name, mutate, expectedFailures, harnessControl = false }) {
  let mutated;
  try { mutated = mutate(canonicalBytes.toString("utf8")); }
  catch (error) { fail(`${name}: ${error?.message || error}`); return; }
  activeTemp = fs.mkdtempSync(path.join(os.tmpdir(), "cm-ct105-mut-"));
  const mutantPath = path.join(activeTemp, "105-mutant.sql");
  fs.writeFileSync(mutantPath, mutated);
  try {
    const child = spawnSync(process.execPath, [validatorPath], {
      cwd: root,
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, CT_PLATFORM_ABORT_MIGRATION_PATH: mutantPath },
    });
    const combined = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actual = failureNames(combined);
    const summary = String(child.stdout || "").match(
      /CT platform-abort migration: (\d+)\/(\d+) assertions passed/,
    );
    const semanticExit = child.error == null
      && child.signal == null
      && child.status === 1
      && summary != null;
    const exact = JSON.stringify(actual) === JSON.stringify(expectedFailures);
    if (!harnessControl && semanticExit && exact) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else if (harnessControl && !(semanticExit && exact)) {
      controls += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(`${name}: ${harnessControl ? "invalid failure accepted" : "wrong exact FAIL set"}`
        + `\nexpected=${JSON.stringify(expectedFailures)} actual=${JSON.stringify(actual)}`
        + ` status=${child.status} signal=${child.signal} error=${child.error?.message || "none"}`
        + `\nstdout:\n${child.stdout || ""}\nstderr:\n${child.stderr || ""}`);
    }
  } finally {
    cleanup();
    if (hash(fs.readFileSync(migrationPath)) !== canonicalHash) {
      fail(`${name}: canonical migration bytes changed`);
    }
    if (gitStatusFingerprint() !== initialFingerprint) {
      fail(`${name}: worktree fingerprint changed`);
    }
  }
}

const removeStatement = (name) => (source) => replaceRegexOnce(
  source,
  new RegExp(`CREATE (?:INDEX|TRIGGER) ${name}\\b[\\s\\S]*?;`),
  "",
  name,
);

runCase({
  name: "omit CT-R1 scan index",
  mutate: removeStatement("idx_ct_provider_telemetry_scan"),
  expectedFailures: ["schema: CT-R1 scan index preserved"],
});
runCase({
  name: "omit CT-R1 provider/time index",
  mutate: removeStatement("idx_ct_provider_telemetry_provider_time"),
  expectedFailures: ["schema: CT-R1 provider/time index preserved"],
});
runCase({
  name: "omit CT-R1 row-bound trigger",
  mutate: (source) => replaceRegexOnce(
    source,
    /CREATE TRIGGER trg_ct_provider_telemetry_scan_row_bound[\s\S]*?\nEND;/,
    "",
    "CT-R1 row-bound trigger",
  ),
  expectedFailures: [
    "schema: CT-R1 row-bound trigger preserved by exact name",
    "schema: CT-R1 row-bound trigger remains effective",
  ],
});
runCase({
  name: "omit CT-R1 primary key",
  mutate: (source) => replaceOnce(
    source,
    "CREATE TABLE ct_provider_telemetry__105 (\n    id                    TEXT PRIMARY KEY,",
    "CREATE TABLE ct_provider_telemetry__105 (\n    id                    TEXT,",
    "CT-R1 primary key",
  ),
  expectedFailures: [
    "schema: CT-R1 TEXT PRIMARY KEY semantic constraint preserved",
    "schema: CT-R1 CREATE TABLE retains TEXT PRIMARY KEY contract",
  ],
});
runCase({
  name: "omit overlap scan index",
  mutate: removeStatement("idx_ct_provider_overlap_telemetry_scan"),
  expectedFailures: ["schema: overlap scan index preserved"],
});
runCase({
  name: "omit overlap status/time index",
  mutate: removeStatement("idx_ct_provider_overlap_telemetry_status_time"),
  expectedFailures: ["schema: overlap status/time index preserved"],
});
runCase({
  name: "omit overlap primary key",
  mutate: (source) => replaceOnce(
    source,
    "CREATE TABLE ct_provider_overlap_telemetry__105 (\n    id                                      TEXT PRIMARY KEY,",
    "CREATE TABLE ct_provider_overlap_telemetry__105 (\n    id                                      TEXT,",
    "overlap primary key",
  ),
  expectedFailures: [
    "schema: overlap TEXT PRIMARY KEY semantic constraint preserved",
    "schema: overlap CREATE TABLE retains TEXT PRIMARY KEY contract",
  ],
});
runCase({
  name: "omit overlap unique contract",
  mutate: (source) => replaceOnce(
    source,
    "    UNIQUE (scan_id, module, source_set_version),\n",
    "",
    "overlap unique",
  ),
  expectedFailures: [
    "schema: overlap UNIQUE semantic constraint preserved",
    "schema: overlap CREATE TABLE retains UNIQUE column contract",
  ],
});
runCase({
  name: "omit CT-R1 platform outcome vocabulary",
  mutate: (source) => replaceOnce(
    source,
    "                              'rate_limited', 'network_error',\n                              'platform_deadline_abort'\n",
    "                              'rate_limited', 'network_error'\n",
    "CT-R1 platform outcome",
  ),
  expectedFailures: ["vocabulary: CT-R1 platform_deadline_abort is accepted"],
});
runCase({
  name: "omit overlap platform attempt vocabulary",
  mutate: (source) => {
    let mutated = source;
    for (let index = 0; index < 2; index += 1) {
      mutated = mutated.replace(
        "                                              'terminal_platform_deadline_abort',\n",
        "",
      );
    }
    return mutated;
  },
  expectedFailures: [
    "vocabulary: mixed platform/provider cause accepts platform-censored precedence",
    "coherence: every supported provider-state pair has an explicit accepted status",
  ],
});
runCase({
  name: "omit overlap platform comparison vocabulary",
  mutate: (source) => replaceOnce(
    source,
    "                                              'censored_platform_deadline_abort',\n",
    "",
    "overlap platform comparison",
  ),
  expectedFailures: [
    "vocabulary: mixed platform/provider cause accepts platform-censored precedence",
    "coherence: every supported provider-state pair has an explicit accepted status",
  ],
});
runCase({
  name: "omit platform status/state coherence check",
  mutate: (source) => replaceRegexOnce(
    source,
    /,\n    CHECK \(\n      \(\n        comparison_status = 'censored_platform_deadline_abort'[\s\S]*?certspotter_attempt_state != 'terminal_platform_deadline_abort'\n      \)\n    \)\n\);/,
    "\n);",
    "platform reverse coherence check",
  ),
  expectedFailures: [
    "coherence: mixed platform/provider cause rejects provider-failure precedence",
    "coherence: platform plus in-flight rejects the non-platform status",
    "coherence: platform plus not-started-wrong-precedence rejects the non-platform status",
  ],
});
runCase({
  name: "alter one copied historical field",
  mutate: (source) => replaceOnce(
    source,
    "    outcome, http_status, latency_ms, result_count,\n    started_at, completed_at, completeness_impact, affected_signal,\n    cache_state, cache_age_s, created_at\nFROM ct_provider_telemetry;",
    "    outcome, http_status, latency_ms + 1 AS latency_ms, result_count,\n    started_at, completed_at, completeness_impact, affected_signal,\n    cache_state, cache_age_s, created_at\nFROM ct_provider_telemetry;",
    "historical field copy",
  ),
  expectedFailures: ["history: deterministic full-row fingerprint preserved"],
});
runCase({
  name: "omit one copied historical row",
  mutate: (source) => replaceOnce(
    source,
    "FROM ct_provider_telemetry;",
    "FROM ct_provider_telemetry\nWHERE id != 'ctpt-historical-000';",
    "historical row omission",
  ),
  expectedFailures: ["migration: applies successfully"],
});
runCase({
  name: "duplicate one copied historical row",
  mutate: (source) => replaceOnce(
    source,
    "FROM ct_provider_telemetry;",
    "FROM ct_provider_telemetry\nUNION ALL\nSELECT\n    id, scan_id, module, provider,\n    outcome, http_status, latency_ms, result_count,\n    started_at, completed_at, completeness_impact, affected_signal,\n    cache_state, cache_age_s, created_at\nFROM ct_provider_telemetry WHERE id = 'ctpt-historical-000';",
    "historical row duplication",
  ),
  expectedFailures: ["migration: applies successfully"],
});

runCase({
  name: "harness rejects validator load failure",
  mutate: (source) => `${source}\nTHIS IS NOT SQL;\n`,
  expectedFailures: ["wrong reason"],
  harnessControl: true,
});

if (killed !== EXPECTED_MUTANTS) fail(`killed ${killed}/${EXPECTED_MUTANTS} semantic mutants`);
if (controls !== 1) fail(`passed ${controls}/1 harness controls`);
if (gitStatusFingerprint() !== initialFingerprint) fail("suite exit worktree fingerprint changed");

console.log(`CT platform-abort migration mutations: ${killed}/${EXPECTED_MUTANTS} mutants killed; ${controls}/1 harness controls passed`);
if (failures > 0) process.exit(1);
process.exit(0);
