#!/usr/bin/env node
//
// Mutation adequacy for the F-041 outbound fail-closed oracle.
//
// Every mutant runs in a disposable source copy. A kill is accepted only when
// the focused validator reaches its assertion summary and names the intended
// contract; import/syntax crashes do not count.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRoot = path.join(root, "workers", "scan-api");
const validatorName = "validate-f041-outbound-sink-failclosed.js";
const validatorPath = path.join(root, "scripts", validatorName);
const configValidatorName = "validate-f041-outbound-config.js";
const configValidatorPath = path.join(root, "scripts", configValidatorName);
const completionPatterns = Object.freeze({
  [validatorName]: /F-041 outbound fail-closed: \d+ passed, [1-9]\d* failed/,
  [configValidatorName]: /F-041 outbound config: \d+ passed, [1-9]\d* failed/,
});

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const candidateFiles = [
  path.join(workerRoot, "src", "lib", "ssrf.js"),
  path.join(workerRoot, "src", "lib", "http.js"),
  path.join(workerRoot, "src", "engines", "alerts.js"),
  path.join(workerRoot, "src", "routes", "domains.js"),
  path.join(workerRoot, "src", "engines", "cloud-storage-scan.js"),
  path.join(workerRoot, "src", "engines", "scan-engine.js"),
  path.join(workerRoot, "wrangler.toml"),
  path.join(root, "workers", "email-ingest", "wrangler.toml"),
  validatorPath,
  configValidatorPath,
];
const candidateHashes = new Map(candidateFiles.map((file) => [file, sha256(file)]));

function makeSandbox() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "f041-mutant-"));
  const sandbox = path.join(tempRoot, "repo");
  const sandboxWorker = path.join(sandbox, "workers", "scan-api");
  const sandboxEmailWorker = path.join(sandbox, "workers", "email-ingest");
  const sandboxScripts = path.join(sandbox, "scripts");
  fs.mkdirSync(sandboxWorker, { recursive: true });
  fs.mkdirSync(sandboxEmailWorker, { recursive: true });
  fs.mkdirSync(sandboxScripts, { recursive: true });
  fs.cpSync(path.join(workerRoot, "src"), path.join(sandboxWorker, "src"), { recursive: true });
  fs.cpSync(path.join(root, "shared"), path.join(sandbox, "shared"), { recursive: true });
  fs.copyFileSync(path.join(workerRoot, "package.json"), path.join(sandboxWorker, "package.json"));
  fs.copyFileSync(path.join(workerRoot, "wrangler.toml"), path.join(sandboxWorker, "wrangler.toml"));
  fs.copyFileSync(path.join(root, "workers", "email-ingest", "wrangler.toml"),
    path.join(sandboxEmailWorker, "wrangler.toml"));
  fs.copyFileSync(validatorPath, path.join(sandboxScripts, validatorName));
  fs.copyFileSync(configValidatorPath, path.join(sandboxScripts, configValidatorName));
  fs.symlinkSync(path.join(workerRoot, "node_modules"), path.join(sandboxWorker, "node_modules"), "dir");
  return { tempRoot, sandbox };
}

function replaceCount(file, before, after, expectedCount = 1) {
  const source = fs.readFileSync(file, "utf8");
  const occurrences = source.split(before).length - 1;
  if (occurrences !== expectedCount) {
    throw new Error(`mutation anchor count ${occurrences}, expected ${expectedCount}: ${before}`);
  }
  fs.writeFileSync(file, source.split(before).join(after));
}

function runValidator(sandbox, selectedValidator = validatorName) {
  return spawnSync(process.execPath, [path.join(sandbox, "scripts", selectedValidator)], {
    cwd: sandbox,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, F041_MUTANT_MODE: "1" },
  });
}

const mutants = [
  {
    id: "M_IPV6_BROAD_PARENT_PUBLIC",
    file: "workers/scan-api/src/lib/ssrf.js",
    before: '  ipv6Range("2001::", 23),',
    after: '  ipv6Range("2001::", 128),',
    expected: "F041_IPV6_2001_100_MIXED_BLOCKS",
  },
  {
    id: "M_EARLY_REJECT_DROPS_PRIVATE",
    file: "workers/scan-api/src/lib/ssrf.js",
    before: "  // Inspect fulfilled evidence before collapsing an ordinary sibling rejection.",
    after: "  if (settled.some((result) => result.status === \"rejected\")) {\n    return { state: STRICT_DNS_STATES.UNAVAILABLE, reason: \"resolver_error\", literal: false, addresses: [] };\n  }\n\n  // Inspect fulfilled evidence before collapsing an ordinary sibling rejection.",
    expected: "F041_PRIVATE_A_DOMINATES_AAAA_ERROR_BLOCKS",
  },
  {
    id: "M_GLOBAL_FETCH_STRICT_FLAG_MISSING",
    file: "workers/scan-api/wrangler.toml",
    before: 'compatibility_flags = ["global_fetch_strictly_public"]',
    after: "compatibility_flags = []",
    expected: "F041_CONFIG_SCAN_API_STRICT_PUBLIC",
    validator: configValidatorName,
  },
  {
    id: "M_MIXED_ANY_PUBLIC",
    file: "workers/scan-api/src/lib/ssrf.js",
    before: "  if (knownAddresses.some((address) => !address.public)) {",
    after: "  if (knownAddresses.every((address) => !address.public)) {",
    expected: "F041_MIXED_PUBLIC_A_PRIVATE_AAAA_BLOCKS",
  },
  {
    id: "M_RESOLVER_ERROR_IGNORED",
    file: "workers/scan-api/src/lib/ssrf.js",
    before: "  if (settled.some((result) => result.status === \"rejected\")) {\n    return { state: STRICT_DNS_STATES.UNAVAILABLE, reason: \"resolver_error\", literal: false, addresses: [] };\n  }",
    after: "  if (settled.some((result) => result.status === \"rejected\")) {\n    return { state: STRICT_DNS_STATES.PUBLIC, reason: null, literal: false, addresses: [] };\n  }",
    expected: "F041_RESOLVER_ERROR_WITH_PUBLIC_BLOCKS",
  },
  {
    id: "M_EMPTY_ALLOW",
    file: "workers/scan-api/src/lib/ssrf.js",
    before: "  if (addresses.length === 0) {",
    after: "  if (addresses.length < 0) {",
    expected: "F041_EMPTY_TERMINAL_BLOCKS",
  },
  {
    id: "M_FIRST_HOP_ONLY",
    file: "workers/scan-api/src/lib/http.js",
    before: "      if (dnsResolver) {",
    after: "      if (dnsResolver && hop === 0) {",
    expected: "F041_REDIRECT_DNS_PRIVATE_NO_SECOND_HTTP",
  },
  {
    id: "M_NATIVE_FOLLOW",
    file: "workers/scan-api/src/lib/http.js",
    before: "        redirect: \"manual\",\n        signal: combineSignals(fetchOptions.signal, accounting?.signal, AbortSignal.timeout(10_000)),",
    after: "        redirect: \"follow\",\n        signal: combineSignals(fetchOptions.signal, accounting?.signal, AbortSignal.timeout(10_000)),",
    expected: "F041_ALERT_3XX_BODY_NOT_FORWARDED",
  },
  {
    id: "M_CREATE_TIME_ONLY",
    file: "workers/scan-api/src/engines/alerts.js",
    before: "          dnsResolver: dnsQueryImpl,",
    after: "          dnsResolver: null,",
    expected: "F041_ALERT_CREATE_PUBLIC_DELIVERY_PRIVATE_BLOCKS",
  },
  {
    id: "M_POST_REDIRECT_FOLLOW",
    file: "workers/scan-api/src/engines/alerts.js",
    before: "          redirect: \"manual\",\n          dnsResolver: dnsQueryImpl,",
    after: "          redirect: \"follow\",\n          dnsResolver: dnsQueryImpl,",
    expected: "F041_ALERT_3XX_BODY_NOT_FORWARDED",
  },
  {
    id: "M_NULL_AS_SUCCESS",
    file: "workers/scan-api/src/routes/domains.js",
    before: "  return proof?.state === \"verified\" && proof?.verified === true;",
    after: "  return proof?.verified !== false;",
    expected: "F041_DOMAIN_BLOCK_NEVER_VERIFIES",
  },
  {
    id: "M_OUTER_COUNT_RETAINED",
    file: "workers/scan-api/src/engines/cloud-storage-scan.js",
    edits: [
      {
        before: "    headRes = await safeFetch(headUrl, {",
        after: "    accounting?.assertCanIssue?.();\n    accounting?.recordAttempt?.();\n    headRes = await safeFetch(headUrl, {",
      },
      {
        before: "    const getRes = await safeFetch(listUrl, {",
        after: "    accounting?.assertCanIssue?.();\n    accounting?.recordAttempt?.();\n    const getRes = await safeFetch(listUrl, {",
      },
    ],
    expected: "F041_CLOUD_PRIVATE_DNS_TWO_DNS_ZERO_HTTP_UNKNOWN_INCOMPLETE",
  },
  {
    id: "M_DNS_UNCOUNTED",
    file: "workers/scan-api/src/lib/http.js",
    before: "          accounting,\n          signal: fetchOptions.signal,",
    after: "          accounting: null,\n          signal: fetchOptions.signal,",
    expected: "F041_CLOUD_PRIVATE_DNS_TWO_DNS_ZERO_HTTP_UNKNOWN_INCOMPLETE",
  },
  {
    id: "M_CACHE_DROPPED",
    file: "workers/scan-api/src/engines/cloud-storage-scan.js",
    before: "      dnsCache: cache,",
    after: "      dnsCache: null,",
    expectedCount: 2,
    expected: "F041_CLOUD_PUBLIC_HEAD_GET_SHARED_CACHE_EXACT",
  },
  {
    id: "M_BUDGET_SWALLOWED",
    file: "workers/scan-api/src/engines/cloud-storage-scan.js",
    before: "  } catch (err) {\n    if (isOutboundControlError(err)) throw err;\n    return {\n      checked:  0,",
    after: "  } catch (err) {\n    return {\n      checked:  0,",
    expected: "F041_LIMIT_PLUS_ONE_DENIED_PRE_TRANSPORT_TYPED",
  },
];

let failures = 0;
let killed = 0;
let baselineSandbox = null;
try {
  baselineSandbox = makeSandbox();
  const baselines = [validatorName, configValidatorName]
    .map((selectedValidator) => runValidator(baselineSandbox.sandbox, selectedValidator));
  const output = baselines.map((baseline) =>
    `${baseline.stdout || ""}${baseline.stderr || ""}`).join("\n");
  if (baselines.every((baseline) => baseline.status === 0 && baseline.signal == null)
      && !/^FAIL /m.test(output)) {
    console.log("PASS F041_MUTATION_BASELINE_GREEN");
  } else {
    failures += 1;
    console.log(`FAIL F041_MUTATION_BASELINE_GREEN — ${baselines.map((baseline) =>
      `status=${baseline.status}, signal=${baseline.signal}`).join("; ")}`);
    console.log(output);
  }
} finally {
  if (baselineSandbox) fs.rmSync(baselineSandbox.tempRoot, { recursive: true, force: true });
}

for (const mutant of mutants) {
  let sandbox = null;
  try {
    sandbox = makeSandbox();
    const target = path.join(sandbox.sandbox, mutant.file);
    if (mutant.edits) {
      for (const edit of mutant.edits) replaceCount(target, edit.before, edit.after, edit.expectedCount || 1);
    } else {
      replaceCount(target, mutant.before, mutant.after, mutant.expectedCount || 1);
    }
    const selectedValidator = mutant.validator || validatorName;
    const result = runValidator(sandbox.sandbox, selectedValidator);
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const namedFailure = new RegExp(`^FAIL ${mutant.expected}(?:\\s|—|$)`, "m").test(output);
    const cleanAssertionExit = result.status === 1
      && result.signal == null
      && completionPatterns[selectedValidator].test(output)
      && !/SyntaxError|ERR_MODULE_NOT_FOUND|uncaught exception/i.test(output);
    if (namedFailure && cleanAssertionExit) {
      killed += 1;
      console.log(`PASS ${mutant.id} — killed by ${mutant.expected}`);
    } else {
      failures += 1;
      console.log(`FAIL ${mutant.id} — status=${result.status}, signal=${result.signal}, expected=${mutant.expected}`);
      console.log(output);
    }
  } catch (error) {
    failures += 1;
    console.log(`FAIL ${mutant.id} — harness error: ${error?.stack || error}`);
  } finally {
    if (sandbox) fs.rmSync(sandbox.tempRoot, { recursive: true, force: true });
  }
}

const candidateUnchanged = candidateFiles.every((file) => sha256(file) === candidateHashes.get(file));
if (candidateUnchanged) {
  console.log("PASS F041_MUTANTS_DID_NOT_TOUCH_CANDIDATE");
} else {
  failures += 1;
  console.log("FAIL F041_MUTANTS_DID_NOT_TOUCH_CANDIDATE");
}

console.log(`F-041 mutation adequacy: ${killed}/${mutants.length} named mutants killed; ${failures} harness failures`);
if (failures) process.exit(1);
