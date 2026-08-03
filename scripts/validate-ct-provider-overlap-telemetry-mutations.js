#!/usr/bin/env node
// CT-R2 PR-2A strict fresh-process mutation proof.
//
// A mutant is killed only by the exact expected assertion-name set through the
// validator's normal summary/exit path. Syntax/import/runtime/spawn/signal and
// wrong-reason failures are rejected. Target bytes and the complete worktree
// status fingerprint must be restored after every mutant and at suite exit.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const fixtureValidator = path.join(root, "scripts/validate-ct-provider-overlap-telemetry.js");
const engineValidator = path.join(root, "scripts/validate-ct-provider-overlap-engine-trace.js");
const EXPECTED_MUTANTS = 21;
const EXPECTED_FIXTURE_ASSERTIONS = 118;
const EXPECTED_ENGINE_ASSERTIONS = 24;

let sequence = 0;
let killed = 0;
let failures = 0;
let activeMutantPath = null;

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => {
  failures += 1;
  console.error(`FAIL ${message}`);
};

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

const initialWorktreeFingerprint = gitStatusFingerprint();

function cleanupActiveMutant() {
  if (!activeMutantPath) return;
  try { fs.rmSync(activeMutantPath, { force: true }); } catch { /* best effort */ }
  activeMutantPath = null;
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanupActiveMutant();
    console.error(`FAIL mutation suite interrupted by ${signal}; worktree must be treated as dirty until revalidated`);
    process.exit(2);
  });
}

function replaceExactlyOnce(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}

function failureNames(output) {
  return String(output || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function runMutant({
  name,
  sourcePath,
  sourceName = path.basename(sourcePath),
  validator = fixtureValidator,
  validatorAssertions = EXPECTED_FIXTURE_ASSERTIONS,
  summaryPattern = /CT provider overlap telemetry: (\d+)\/(\d+) assertions passed/,
  envName,
  asUrl = true,
  expectedFailures,
  mutate,
}) {
  sequence += 1;
  const original = fs.readFileSync(sourcePath);
  const originalHash = hash(original);
  let mutated;
  try {
    mutated = mutate(original.toString("utf8"));
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
    return;
  }

  const extension = path.extname(sourceName) || ".tmp";
  const base = sourceName.slice(0, -extension.length);
  const directory = extension === ".js" ? path.dirname(sourcePath) : os.tmpdir();
  const mutantPath = path.join(
    directory,
    `.${base}.ct-overlap-mutant.${process.pid}.${sequence}${extension}`,
  );
  activeMutantPath = mutantPath;
  fs.writeFileSync(mutantPath, mutated);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        [envName]: asUrl ? pathToFileURL(mutantPath).href : mutantPath,
      },
    });
    const combined = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = failureNames(combined);
    const summary = String(child.stdout || "").match(summaryPattern);
    const stderrLines = String(child.stderr || "").trim().split(/\r?\n/).filter(Boolean);
    const assertionOnlyStderr = stderrLines.every((line) => line.startsWith("FAIL "));
    const exactSet = JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalExit = child.error == null
      && child.signal == null
      && child.status === 1
      && assertionOnlyStderr
      && summary != null
      && Number(summary[2]) === validatorAssertions
      && Number(summary[1]) + expectedFailures.length === validatorAssertions;
    if (normalExit && exactSet) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: mutant ${child.status === 0 ? "survived" : "failed for the wrong reason"}`
        + `\nexpected failures: ${JSON.stringify(expectedFailures)}`
        + `\nactual failures: ${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } finally {
    cleanupActiveMutant();
    if (hash(fs.readFileSync(sourcePath)) !== originalHash) {
      fail(`${name}: target bytes were not restored exactly`);
    }
    if (gitStatusFingerprint() !== initialWorktreeFingerprint) {
      fail(`${name}: worktree fingerprint changed after mutant cleanup`);
    }
  }
}

const overlapPath = path.join(engines, "ct-provider-overlap.js");
const subdomainsPath = path.join(engines, "subdomains-scan.js");
const scanEnginePath = path.join(engines, "scan-engine.js");
const migrationPath = path.join(root, "database/migrations/104-ct-provider-overlap-telemetry.sql");
const indexPath = path.join(root, "workers/scan-api/src/index.js");
const tenantResourcesPath = path.join(root, "scripts/security/lib/tenant-resources.js");

runMutant({
  name: "provider failure overlap is fabricated as zero",
  sourcePath: overlapPath,
  envName: "CT_OVERLAP_MODULE_URL",
  expectedFailures: [
    "crt failure certspotter success: censored overlap fields are NULL",
    "certspotter failure crt success: censored overlap fields are NULL",
    "both provider failure: censored overlap fields are NULL",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `  if (pairStatus) return { comparison_status: pairStatus };`,
    `  if (pairStatus === "censored_provider_failure") {
    return {
      comparison_status: "censored_provider_failure",
      intersection_count: 0,
      crt_sh_only_count: 0,
      certspotter_only_count: 0,
      union_count: 0,
    };
  }
  if (pairStatus) return { comparison_status: pairStatus };`,
    "failure comparison NULL gate",
  ),
});

runMutant({
  name: "merge-order source count is relabelled as provider count",
  sourcePath: subdomainsPath,
  envName: "CT_OVERLAP_SUBDOMAINS_MODULE_URL",
  expectedFailures: ["exact-base production-result fixture fingerprint"],
  mutate: (source) => replaceExactlyOnce(
    source,
    "      sources.certspotter = projectSubdomainCtSource(result, seen.size - before);",
    "      sources.certspotter = projectSubdomainCtSource(result, seen.size);",
    "CertSpotter merge-order count",
  ),
});

runMutant({
  name: "shadow instrumentation leaks into production items",
  sourcePath: subdomainsPath,
  envName: "CT_OVERLAP_SUBDOMAINS_MODULE_URL",
  expectedFailures: [
    "partial overlap: instrumentation on/off production JSON byte-identical",
    "identical sets: instrumentation on/off production JSON byte-identical",
    "disjoint sets: instrumentation on/off production JSON byte-identical",
    "duplicate hostnames: instrumentation on/off production JSON byte-identical",
    "crt multi-name record and common name: instrumentation on/off production JSON byte-identical",
    "invalid out-of-domain wildcard candidates: instrumentation on/off production JSON byte-identical",
    "crt failure certspotter success: instrumentation on/off production JSON byte-identical",
    "certspotter failure crt success: instrumentation on/off production JSON byte-identical",
    "truncation: production JSON byte-identical",
    "normalization bound: production JSON byte-identical",
    "collector exception: production result byte-identical",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `  return {
    count:              items.length,
    items,
    sensitive,`,
    `  return {
    count:              items.length,
    items:              opts.ctOverlap ? items.slice(1) : items,
    sensitive,`,
    "customer items return",
  ),
});

runMutant({
  name: "production provider cap is changed by telemetry work",
  sourcePath: subdomainsPath,
  envName: "CT_OVERLAP_SUBDOMAINS_MODULE_URL",
  expectedFailures: ["exact-base production-result fixture fingerprint"],
  mutate: (source) => replaceExactlyOnce(
    source,
    "  const PER_CAP   = 200;   // max unique names from each CT source",
    "  const PER_CAP   = 1;   // mutant",
    "production PER_CAP",
  ),
});

runMutant({
  name: "truncated comparison is presented as complete",
  sourcePath: overlapPath,
  envName: "CT_OVERLAP_MODULE_URL",
  expectedFailures: [
    "truncation: comparison status is censored",
    "normalization bound: comparison is censored",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    comparison_status: truncated ? "compared_truncated" : "compared",`,
    `    comparison_status: "compared",`,
    "truncated comparison classification",
  ),
});

runMutant({
  name: "provider failure is collapsed into successful-empty",
  sourcePath: overlapPath,
  envName: "CT_OVERLAP_MODULE_URL",
  expectedFailures: [
    "crt failure certspotter success: comparison status",
    "crt failure certspotter success: censored overlap fields are NULL",
    "crt failure certspotter success: provider attempt states",
    "certspotter failure crt success: comparison status",
    "certspotter failure crt success: censored overlap fields are NULL",
    "certspotter failure crt success: provider attempt states",
    "both provider failure: comparison status",
    "both provider failure: censored overlap fields are NULL",
    "both provider failure: provider attempt states",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `      providerMeasurements.set(
        provider,
        unmeasuredProvider(value?.physical_attempt_state === "global_deadline_aborted"
          ? "terminal_platform_deadline_abort"
          : "terminal_failure"),
      );
        return;`,
    `      providerMeasurements.set(provider, measureSuccessfulProvider(
          provider,
          [],
          domain,
          { normalizationLimit: normalizedLimit, retainedLimit: boundedRetainedLimit },
        ));
        return;`,
    "successful-empty/failure boundary",
  ),
});

runMutant({
  name: "consumer-release freeze latch is removed",
  sourcePath: overlapPath,
  envName: "CT_OVERLAP_MODULE_URL",
  expectedFailures: [
    "release G: late success cannot overwrite frozen provider state",
    "release C: late failure remains censored in-flight",
    "release F: repeated release is idempotent",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "      consumerReleased = true;\n      return buildFrozenSnapshot();",
    "      consumerReleased = false; // mutant: release is not latched\n      return buildFrozenSnapshot();",
    "one-way consumer release latch",
  ),
});

runMutant({
  name: "late observe is allowed to overwrite frozen state",
  sourcePath: overlapPath,
  envName: "CT_OVERLAP_MODULE_URL",
  expectedFailures: [
    "release G: late success cannot overwrite frozen provider state",
    "release C: late failure remains censored in-flight",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    observe(provider, settled, domain) {
      if (consumerReleased || !PROVIDERS.includes(provider)) return;`,
    `    observe(provider, settled, domain) {
      if (!PROVIDERS.includes(provider)) return;`,
    "late-observe freeze guard",
  ),
});

runMutant({
  name: "outer 12s subdomains release hook is omitted",
  sourcePath: scanEnginePath,
  validator: engineValidator,
  validatorAssertions: EXPECTED_ENGINE_ASSERTIONS,
  summaryPattern: /CT provider overlap engine trace: (\d+)\/(\d+) assertions passed/,
  envName: "CT_OVERLAP_SCAN_ENGINE_MODULE_URL",
  expectedFailures: [
    "outer 12s release: frozen provider states are durable",
    "outer 12s release: overlap fields remain NULL",
    "outer 12s release: late provider settlement cannot rewrite durable state",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `runCappedModule("subdomains",           { fallback: subdomainsFallback, onConsumerRelease: (cause) => { ctCache.releaseConsumer?.(domain, "subdomains", cause); ctProviderOverlap.freeze({ global_deadline: deadline.globalDeadlineProvenance() }); }, run:`,
    `runCappedModule("subdomains",           { fallback: subdomainsFallback, run:`,
    "outer subdomains consumer-release hook",
  ),
});

runMutant({
  name: "inner 15s subdomains release hook is omitted",
  sourcePath: subdomainsPath,
  envName: "CT_OVERLAP_SUBDOMAINS_MODULE_URL",
  expectedFailures: [
    "release B: provider resolving after release is censored in-flight",
    "release B: censored in-flight overlap fields are NULL",
    "release G: late success cannot overwrite frozen provider state",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `        setTimeout(() => {
          freezeCtOverlap();
          resolve(emptyResult("Subdomain discovery timed out (15s hard cap)"));`,
    `        setTimeout(() => {
          resolve(emptyResult("Subdomain discovery timed out (15s hard cap)"));`,
    "inner subdomains consumer-release hook",
  ),
});

runMutant({
  name: "persistence failure runs before terminal finalization",
  sourcePath: scanEnginePath,
  validator: engineValidator,
  validatorAssertions: EXPECTED_ENGINE_ASSERTIONS,
  summaryPattern: /CT provider overlap engine trace: (\d+)\/(\d+) assertions passed/,
  envName: "CT_OVERLAP_SCAN_ENGINE_MODULE_URL",
  expectedFailures: [
    "engine trace: overlap write occurs only after terminal D1 finalization",
    "persistence failure: terminal scan remains completed",
    "persistence failure: terminal customer result is byte-identical",
    "repeated finalization: overlap insert attempted once",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "    const finalized = await finalizeScanResult(latch, {",
    `    const earlyOverlapOutcome = await persistCtProviderOverlapTelemetry(
      scanId,
      ctProviderOverlap.snapshot(),
      env,
    );
    if (earlyOverlapOutcome.status === "persistence_failed") {
      throw new Error("mutant overlap persistence failure");
    }
    const finalized = await finalizeScanResult(latch, {`,
    "terminal finalization ordering",
  ),
});

runMutant({
  name: "idempotency unique gate is removed",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "persistence: repeated write returns one durable row",
    "persistence: unique gate keeps one row",
    "tenant attribution: canonical scan join finds owning workspace",
    "migration 104 has source-version idempotency gate",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "    UNIQUE (scan_id, module, source_set_version),\n",
    "",
    "durable UNIQUE gate",
  ),
});

runMutant({
  name: "crt_sh attempt-state CHECK is removed",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "sqlite crt_sh attempt state: bogus row rejected by CHECK constraint",
    "migration 104 crt_sh attempt-state CHECK preserves historical v1 vocabulary",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    crt_sh_attempt_state                    TEXT NOT NULL CHECK (crt_sh_attempt_state IN (
                                              'terminal_success', 'terminal_failure',
                                              'not_started', 'in_flight_at_consumer_release'
                                            )),`,
    `    crt_sh_attempt_state                    TEXT NOT NULL,`,
    "crt_sh attempt-state CHECK",
  ),
});

runMutant({
  name: "certspotter attempt-state CHECK admits a migration-only extra state",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "migration 104 certspotter attempt-state CHECK preserves historical v1 vocabulary",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    certspotter_attempt_state               TEXT NOT NULL CHECK (certspotter_attempt_state IN (
                                              'terminal_success', 'terminal_failure',
                                              'not_started', 'in_flight_at_consumer_release'
                                            )),`,
    `    certspotter_attempt_state               TEXT NOT NULL CHECK (certspotter_attempt_state IN (
                                              'terminal_success', 'terminal_failure',
                                              'not_started', 'in_flight_at_consumer_release',
                                              'migration_only_attempt_state'
                                            )),`,
    "certspotter attempt-state extra value",
  ),
});

runMutant({
  name: "crt_sh attempt-state CHECK duplicates an engine state",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "migration 104 crt_sh attempt-state CHECK preserves historical v1 vocabulary",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    crt_sh_attempt_state                    TEXT NOT NULL CHECK (crt_sh_attempt_state IN (
                                              'terminal_success', 'terminal_failure',
                                              'not_started', 'in_flight_at_consumer_release'
                                            )),`,
    `    crt_sh_attempt_state                    TEXT NOT NULL CHECK (crt_sh_attempt_state IN (
                                              'terminal_success', 'terminal_success',
                                              'terminal_failure', 'not_started',
                                              'in_flight_at_consumer_release'
                                            )),`,
    "crt_sh attempt-state duplicate value",
  ),
});

runMutant({
  name: "comparison-status CHECK is removed",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "sqlite comparison status: bogus row rejected by CHECK constraint",
    "migration 104 comparison-status CHECK preserves historical v1 vocabulary",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    comparison_status                       TEXT NOT NULL CHECK (comparison_status IN (
                                              'compared', 'compared_truncated',
                                              'censored_provider_failure',
                                              'censored_in_flight', 'not_started'
                                            )),`,
    `    comparison_status                       TEXT NOT NULL,`,
    "comparison-status CHECK",
  ),
});

runMutant({
  name: "comparison-status CHECK admits a migration-only extra state",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "migration 104 comparison-status CHECK preserves historical v1 vocabulary",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    comparison_status                       TEXT NOT NULL CHECK (comparison_status IN (
                                              'compared', 'compared_truncated',
                                              'censored_provider_failure',
                                              'censored_in_flight', 'not_started'
                                            )),`,
    `    comparison_status                       TEXT NOT NULL CHECK (comparison_status IN (
                                              'compared', 'compared_truncated',
                                              'censored_provider_failure',
                                              'censored_in_flight', 'not_started',
                                              'migration_only_comparison_status'
                                            )),`,
    "comparison-status extra value",
  ),
});

runMutant({
  name: "comparison-status CHECK duplicates an engine state",
  sourcePath: migrationPath,
  envName: "CT_OVERLAP_MIGRATION_PATH",
  asUrl: false,
  expectedFailures: [
    "migration 104 comparison-status CHECK preserves historical v1 vocabulary",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `    comparison_status                       TEXT NOT NULL CHECK (comparison_status IN (
                                              'compared', 'compared_truncated',
                                              'censored_provider_failure',
                                              'censored_in_flight', 'not_started'
                                            )),`,
    `    comparison_status                       TEXT NOT NULL CHECK (comparison_status IN (
                                              'compared', 'compared', 'compared_truncated',
                                              'censored_provider_failure',
                                              'censored_in_flight', 'not_started'
                                            )),`,
    "comparison-status duplicate value",
  ),
});

runMutant({
  name: "raw hostname is emitted through a logging sink",
  sourcePath: overlapPath,
  envName: "CT_OVERLAP_MODULE_URL",
  expectedFailures: ["overlap helper has no logging sink"],
  mutate: (source) => replaceExactlyOnce(
    source,
    "  const retainedHostnames = new Set(orderedUnique.slice(0, retainedLimit));",
    `  const retainedHostnames = new Set(orderedUnique.slice(0, retainedLimit));
  console.log([...retainedHostnames]);`,
    "raw-hostname logging sink",
  ),
});

runMutant({
  name: "scan-child purge registration is removed",
  sourcePath: indexPath,
  envName: "CT_OVERLAP_INDEX_SOURCE_PATH",
  asUrl: false,
  expectedFailures: ["purge order includes overlap telemetry as a scan child"],
  mutate: (source) => replaceExactlyOnce(
    source,
    `  "scan_module_telemetry", "ct_provider_telemetry", "ct_provider_overlap_telemetry",`,
    `  "scan_module_telemetry", "ct_provider_telemetry",`,
    "scan child registration",
  ),
});

runMutant({
  name: "tenant resource inventory registration is removed",
  sourcePath: tenantResourcesPath,
  envName: "CT_OVERLAP_TENANT_RESOURCES_PATH",
  asUrl: false,
  expectedFailures: ["tenant resource inventory includes overlap telemetry via scans"],
  mutate: (source) => replaceExactlyOnce(
    source,
    `"ct_provider_telemetry", "ct_provider_overlap_telemetry", "scheduled_scans"`,
    `"ct_provider_telemetry", "scheduled_scans"`,
    "tenant resource registration",
  ),
});

if (sequence !== EXPECTED_MUTANTS) {
  fail(`pinned mutant count: defined ${sequence}, expected ${EXPECTED_MUTANTS}`);
}
if (killed !== EXPECTED_MUTANTS) {
  fail(`mutation score: killed ${killed}/${EXPECTED_MUTANTS}`);
}
cleanupActiveMutant();
if (gitStatusFingerprint() !== initialWorktreeFingerprint) {
  fail("final worktree fingerprint differs from suite entry");
}

console.log(`CT provider overlap telemetry mutations: ${killed}/${EXPECTED_MUTANTS} killed`);
process.exit(failures > 0 ? 1 : 0);
