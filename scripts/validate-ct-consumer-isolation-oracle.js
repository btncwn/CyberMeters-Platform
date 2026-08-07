#!/usr/bin/env node
// CT-R2 PR-2A.1 contract-bound immutable semantic oracle.
//
// `--preflight-only` performs contract parsing, classification/evidence checks,
// and bidirectional assertion/mutant traceability. It deliberately exits before
// importing runtime modules or executing semantic fixtures.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  CT_ISOLATION_ASSERTIONS,
  CT_ISOLATION_BASE_COMMIT,
  CT_ISOLATION_HARNESS_CONTROLS,
  CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS,
  CT_ISOLATION_OLD_RUNTIME_PASS_IDS,
  CT_ISOLATION_SEMANTIC_MUTANTS,
} from "./ct-consumer-isolation-old-runtime-classification.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const contractPath = path.join(root, "docs/CT-R2-PR-2A1-BINDING-CONTRACT.md");
const contractBytes = fs.readFileSync(contractPath);
const contractText = contractBytes.toString("utf8");
export const CT_ISOLATION_BINDING_CONTRACT_SHA256 =
  "02266fd63b014773b340230c15f10cb0c830dc391efe4a8e2f8d66412c43cc0b";
const actualContractSha = crypto.createHash("sha256").update(contractBytes).digest("hex");
if (actualContractSha !== CT_ISOLATION_BINDING_CONTRACT_SHA256) {
  throw new Error(`Binding-contract SHA drift: ${actualContractSha}`);
}

const parsedRulingIds = [...contractText.matchAll(/^### (CT2A1-[A-Z0-9-]+)$/gm)]
  .map((match) => match[1]);
const uniqueRulingIds = [...new Set(parsedRulingIds)];
if (parsedRulingIds.length !== 17 || uniqueRulingIds.length !== 17) {
  throw new Error(`Binding-contract namespace drift: ${parsedRulingIds.length}/${uniqueRulingIds.length}`);
}
export const CT_ISOLATION_RULING_IDS = Object.freeze(uniqueRulingIds);

function contractSection(rulingId, nextHeading = /^### /m) {
  const start = contractText.indexOf(`### ${rulingId}`);
  if (start < 0) throw new Error(`Missing binding section ${rulingId}`);
  const bodyStart = contractText.indexOf("\n", start) + 1;
  const tail = contractText.slice(bodyStart);
  const next = tail.search(nextHeading);
  return next < 0 ? tail : tail.slice(0, next);
}

const customerWordingMatches = [...contractSection("CT2A1-CUSTOMER-01")
  .matchAll(/`([^`\r\n]+)`/g)].map((match) => match[1]);
if (customerWordingMatches.length !== 1) {
  throw new Error("CUSTOMER-01 must contain exactly one inline contract value");
}
export const CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING = customerWordingMatches[0];
const apostropheAt = CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING.indexOf("scan's");
if (apostropheAt < 0
  || CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING.charCodeAt(apostropheAt + 4) !== 0x27) {
  throw new Error("CUSTOMER-01 wording must contain ASCII apostrophe U+0027 in scan's");
}

const vocabularyValues = [...contractSection("CT2A1-VOCAB-01", /^## /m)
  .matchAll(/^\s{2}`([a-z_]+)`$/gm)].map((match) => match[1]);
if (vocabularyValues.length !== 5 || new Set(vocabularyValues).size !== 5) {
  throw new Error(`VOCAB-01 value extraction drift: ${vocabularyValues.length}`);
}
export const CT_ISOLATION_EXACT_VOCABULARY = Object.freeze(vocabularyValues);

const assertionIds = CT_ISOLATION_ASSERTIONS.map((entry) => entry.assertion_id);
const assertionSet = new Set(assertionIds);
const assertionOrder = new Map(assertionIds.map((id, index) => [id, index]));
if (assertionSet.size !== assertionIds.length) throw new Error("Duplicate assertion ID");
const rulingSet = new Set(CT_ISOLATION_RULING_IDS);
const rulingToAssertions = new Map(CT_ISOLATION_RULING_IDS.map((id) => [id, []]));

function verifyFrozenEvidence(entry) {
  if (entry.expected_old_runtime_result !== "FAIL") return;
  if (!["BEHAVIOURAL", "STRUCTURAL"].includes(entry.failure_class)) {
    throw new Error(`${entry.assertion_id}: invalid failure class`);
  }
  const evidence = entry.base_evidence;
  for (const field of ["commit", "path", "line", "source_snippet", "snippet_sha256"]) {
    if (evidence?.[field] == null) throw new Error(`${entry.assertion_id}: missing base evidence ${field}`);
  }
  if (evidence.commit !== CT_ISOLATION_BASE_COMMIT) {
    throw new Error(`${entry.assertion_id}: base evidence commit drift`);
  }
  const child = spawnSync("git", ["show", `${evidence.commit}:${evidence.path}`], {
    cwd: root,
    encoding: "utf8",
  });
  if (child.error || child.signal || child.status !== 0) {
    throw new Error(`${entry.assertion_id}: cannot read frozen base evidence`);
  }
  const lineCount = evidence.source_snippet.split("\n").length - 1;
  const actualSnippet = `${child.stdout.split("\n")
    .slice(evidence.line - 1, evidence.line - 1 + lineCount).join("\n")}\n`;
  const actualSnippetSha = crypto.createHash("sha256").update(actualSnippet).digest("hex");
  if (actualSnippet !== evidence.source_snippet
    || actualSnippetSha !== evidence.snippet_sha256) {
    throw new Error(`${entry.assertion_id}: frozen base snippet mismatch`);
  }
  for (const field of [
    "base_carrier", "expected_observed_value_or_state",
    "required_corrected_value_or_state", "claim_limit",
  ]) {
    if (typeof entry[field] !== "string" || entry[field].trim() === "") {
      throw new Error(`${entry.assertion_id}: missing classification ${field}`);
    }
  }
}

for (const entry of CT_ISOLATION_ASSERTIONS) {
  if (!Array.isArray(entry.ruling_ids) || entry.ruling_ids.length === 0) {
    throw new Error(`${entry.assertion_id}: no ruling IDs`);
  }
  if (new Set(entry.ruling_ids).size !== entry.ruling_ids.length) {
    throw new Error(`${entry.assertion_id}: duplicate ruling ID`);
  }
  const testedRulings = Object.keys(entry.ruling_tests || {});
  if (JSON.stringify(testedRulings) !== JSON.stringify(entry.ruling_ids)
    || testedRulings.some((rulingId) =>
      typeof entry.ruling_tests[rulingId] !== "string"
      || entry.ruling_tests[rulingId].trim() === "")) {
    throw new Error(`${entry.assertion_id}: incomplete ruling-meaning declaration`);
  }
  if (typeof entry.fixture_id !== "string" || entry.fixture_id.trim() === "") {
    throw new Error(`${entry.assertion_id}: no fixture/carrier mapping`);
  }
  for (const rulingId of entry.ruling_ids) {
    if (!rulingSet.has(rulingId)) {
      throw new Error(`${entry.assertion_id}: ruling outside binding contract: ${rulingId}`);
    }
    rulingToAssertions.get(rulingId).push(entry.assertion_id);
  }
  verifyFrozenEvidence(entry);
}
for (const [rulingId, mappedAssertions] of rulingToAssertions) {
  if (mappedAssertions.length === 0) throw new Error(`${rulingId}: no mapped assertion`);
}

const declaredPartition = [...CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS,
  ...CT_ISOLATION_OLD_RUNTIME_PASS_IDS].sort((a, b) => a.localeCompare(b));
const sortedAssertionIds = [...assertionIds].sort((a, b) => a.localeCompare(b));
if (JSON.stringify(declaredPartition) !== JSON.stringify(sortedAssertionIds)) {
  throw new Error("Old-runtime PASS/FAIL classification does not partition assertions");
}
const expectedFailuresFromMetadata = CT_ISOLATION_ASSERTIONS
  .filter((entry) => entry.expected_old_runtime_result === "FAIL")
  .map((entry) => entry.assertion_id);
if (JSON.stringify(expectedFailuresFromMetadata)
  !== JSON.stringify(CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS)) {
  throw new Error("Old-runtime FAIL partition drift");
}

const mutantIds = CT_ISOLATION_SEMANTIC_MUTANTS.map((entry) => entry.mutant_id);
if (new Set(mutantIds).size !== mutantIds.length) throw new Error("Duplicate semantic mutant ID");
const assertionToMutants = new Map(assertionIds.map((id) => [id, []]));
for (const mutant of CT_ISOLATION_SEMANTIC_MUTANTS) {
  if (!Array.isArray(mutant.expected_failure_ids) || mutant.expected_failure_ids.length === 0) {
    throw new Error(`${mutant.mutant_id}: no assertion mapping`);
  }
  if (new Set(mutant.expected_failure_ids).size !== mutant.expected_failure_ids.length) {
    throw new Error(`${mutant.mutant_id}: duplicate expected failure ID`);
  }
  const ordered = [...mutant.expected_failure_ids]
    .sort((a, b) => (assertionOrder.get(a) ?? Infinity) - (assertionOrder.get(b) ?? Infinity));
  if (JSON.stringify(ordered) !== JSON.stringify(mutant.expected_failure_ids)) {
    throw new Error(`${mutant.mutant_id}: expected failure IDs are not in contract order`);
  }
  for (const assertionId of mutant.expected_failure_ids) {
    if (!assertionSet.has(assertionId)) {
      throw new Error(`${mutant.mutant_id}: unknown assertion ${assertionId}`);
    }
    assertionToMutants.get(assertionId).push(mutant.mutant_id);
  }
}
for (const [assertionId, mappedMutants] of assertionToMutants) {
  if (mappedMutants.length === 0) {
    throw new Error(`${assertionId}: every CT2A1 assertion requires a semantic mutant`);
  }
}
if (CT_ISOLATION_HARNESS_CONTROLS.length !== 2) {
  throw new Error("Wrong-reason/harness-control count drift");
}
const mutationRunnerSource = fs.readFileSync(
  path.join(root, "scripts/validate-ct-consumer-isolation-oracle-mutations.js"),
  "utf8",
);
const registeredMutationCases = [...mutationRunnerSource.matchAll(
  /semantic\("([A-Z0-9_]+)"/g,
)].map((match) => match[1]);
if (JSON.stringify(registeredMutationCases) !== JSON.stringify(mutantIds)) {
  throw new Error("Mutation runner case registration does not match predeclared mutant order");
}

export const CT_ISOLATION_TRACEABILITY_MATRIX = Object.freeze(
  CT_ISOLATION_ASSERTIONS.map((entry) => Object.freeze({
    ruling_ids: entry.ruling_ids,
    assertion_id: entry.assertion_id,
    fixture_id: entry.fixture_id,
    classification: entry.failure_class || "PASS_POSITIVE_CONTROL",
    mutant_ids: Object.freeze([...assertionToMutants.get(entry.assertion_id)]),
  })),
);
const fixtureToAssertions = new Map();
for (const entry of CT_ISOLATION_ASSERTIONS) {
  if (!fixtureToAssertions.has(entry.fixture_id)) fixtureToAssertions.set(entry.fixture_id, []);
  fixtureToAssertions.get(entry.fixture_id).push(entry.assertion_id);
}
export const CT_ISOLATION_TRACEABILITY = Object.freeze({
  by_assertion: CT_ISOLATION_TRACEABILITY_MATRIX,
  by_ruling: Object.freeze(Object.fromEntries(
    [...rulingToAssertions].map(([rulingId, ids]) => [rulingId, Object.freeze([...ids])]),
  )),
  by_fixture: Object.freeze(Object.fromEntries(
    [...fixtureToAssertions].map(([fixtureId, ids]) => [fixtureId, Object.freeze([...ids])]),
  )),
  by_mutant: Object.freeze(Object.fromEntries(
    CT_ISOLATION_SEMANTIC_MUTANTS.map((entry) => [
      entry.mutant_id, entry.expected_failure_ids,
    ]),
  )),
});

if (process.argv.includes("--preflight-only")) {
  console.log(
    `CT isolation oracle preflight: ${CT_ISOLATION_RULING_IDS.length} rulings; `
    + `${assertionIds.length} assertions; ${CT_ISOLATION_SEMANTIC_MUTANTS.length} semantic mutants`,
  );
  process.exit(0);
}

const engineUrl = (name) => pathToFileURL(path.join(
  root, "workers/scan-api/src/engines", name,
)).href;
const load = (envName, name) => import(process.env[envName] || engineUrl(name));
const cacheModule = await load("CT_ORACLE_CACHE_MODULE_URL", "ct-provider-cache.js");
const overlapModule = await load("CT_ORACLE_OVERLAP_MODULE_URL", "ct-provider-overlap.js");
const budgetModule = await load("CT_ORACLE_BUDGET_MODULE_URL", "scan-budget.js");
const reservedModule = await load("CT_ORACLE_RESERVED_MODULE_URL", "reserved-scan.js");
const sslModule = await load("CT_ORACLE_SSL_MODULE_URL", "ssl-scan.js");
const subdomainsModule = await load("CT_ORACLE_SUBDOMAINS_MODULE_URL", "subdomains-scan.js");
const analyzerModule = await import(process.env.CT_ORACLE_ANALYZER_MODULE_URL
  || pathToFileURL(path.join(root, "scripts/analyze-ct-provider-telemetry.js")).href);
const inventoryModule = await import(process.env.CT_ORACLE_INVENTORY_MODULE_URL
  || pathToFileURL(path.join(root, "scripts/derive-ct-provider-source-consumer-inventory.js")).href);

const CRT_OK = [{
  name_value: "api.example.com\nexample.com",
  common_name: "example.com",
  not_before: "2026-07-01T00:00:00Z",
  not_after: "2099-07-01T00:00:00Z",
  issuer_name: "Fixture CA",
}];
const jsonResponse = (data, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: (name) => String(name).toLowerCase() === "content-type" ? "application/json" : null },
  async json() { return data; },
});
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};
const turn = () => new Promise((resolve) => setTimeout(resolve, 0));
const physicalAccounting = (signal = null) => ({
  signal,
  remainingMs: () => 60_000,
  assertCanIssue() {},
  recordAttempt() {},
  recordCompleted() {},
  recordError() {},
  markUnsettled() {},
  markSettled() {},
});
const policies = {
  crt_sh: { timeoutMs: 60_000, maxAttempts: 1, backoffMs: 0 },
  certspotter: { timeoutMs: 60_000, maxAttempts: 1, backoffMs: 0 },
};
const notAbortedProvenance = () => ({
  aborted: false,
  owner: "scan_global_deadline",
  reason: null,
  observed_at: null,
});

const results = new Map();
async function runAssertion(id, run) {
  if (!assertionSet.has(id) || results.has(id)) {
    throw new Error(`Oracle assertion registration drift: ${id}`);
  }
  try { results.set(id, (await run()) === true); }
  catch { results.set(id, false); }
}

let sharedFixture;
async function sharedLateSuccessFixture() {
  if (sharedFixture) return sharedFixture;
  const gate = deferred();
  const globalController = new AbortController();
  const sslController = new AbortController();
  const subdomainsController = new AbortController();
  let calls = 0;
  let physicalAbortCount = 0;
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(globalController.signal),
    fetcher: async (_url, init) => {
      calls += 1;
      const abort = () => {
        physicalAbortCount += 1;
        gate.reject(new DOMException("fixture abort", "AbortError"));
      };
      if (init.signal?.aborted) abort();
      else init.signal?.addEventListener?.("abort", abort, { once: true });
      return gate.promise;
    },
    globalDeadlineProvenance: notAbortedProvenance,
    signal: globalController.signal,
    policies,
    timeoutSignal: () => new AbortController().signal,
  });
  const lifecycleAvailable = typeof cache.releaseConsumer === "function"
    && typeof cache.consumerSnapshot === "function"
    && typeof cache.physicalSnapshot === "function";
  const sslWait = cache.get("example.com", "crt_sh", {
    module: "ssl",
    signal: sslController.signal,
    accounting: physicalAccounting(sslController.signal),
  });
  const subdomainsWait = cache.get("example.com", "crt_sh", {
    module: "subdomains",
    signal: subdomainsController.signal,
    accounting: physicalAccounting(subdomainsController.signal),
  });
  await turn();
  cache.releaseConsumer?.("example.com", "ssl", "module_budget_exhausted");
  sslController.abort("module_budget_exhausted");
  await turn();
  const physicalAbortCountAtRelease = physicalAbortCount;
  gate.resolve(jsonResponse(CRT_OK));
  const subdomainsResult = await subdomainsWait;
  await turn();
  const sslConsumer = cache.consumerSnapshot?.("example.com", "ssl")?.providers?.crt_sh;
  const physical = cache.physicalSnapshot?.("example.com")?.crt_sh;
  const rows = cache.telemetrySnapshot({
    modules: { subdomains: { sources: { crt_sh: { count: 1, error: null } } } },
    scanQuality: { status: "complete" },
  });
  void sslWait;
  sharedFixture = {
    calls, lifecycleAvailable, physicalAbortCountAtRelease,
    subdomainsResult, sslConsumer, physical, rows,
  };
  return sharedFixture;
}

let providerFailureFixture;
async function genuineProviderFailureFixture() {
  if (providerFailureFixture) return providerFailureFixture;
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(),
    fetcher: async () => jsonResponse({}, 503),
    policies,
  });
  const value = await cache.get("example.com", "crt_sh", { module: "ssl" });
  providerFailureFixture = {
    value,
    consumer: cache.consumerSnapshot?.("example.com", "ssl")?.providers?.crt_sh,
  };
  return providerFailureFixture;
}

let globalFixture;
async function globalAbortFixture() {
  if (globalFixture) return globalFixture;
  let nowMs = Date.parse("2026-08-02T12:00:00.000Z");
  const deadline = budgetModule.createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => nowMs);
  let abortDelivered = false;
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(deadline.signal),
    signal: deadline.signal,
    globalDeadlineProvenance: () => deadline.globalDeadlineProvenance?.()
      || (deadline.signal.aborted ? deadline.signal.reason : notAbortedProvenance()),
    policies,
    timeoutSignal: () => new AbortController().signal,
    fetcher: async (_url, init) => new Promise((_resolve, reject) => {
      const uncancelledGuard = setTimeout(() => reject(
        new Error("fixture global cancellation was not delivered"),
      ), 15);
      const abort = () => {
        abortDelivered = true;
        clearTimeout(uncancelledGuard);
        reject(new DOMException("fixture global abort", "AbortError"));
      };
      if (init.signal?.aborted) abort();
      else init.signal?.addEventListener?.("abort", abort, { once: true });
    }),
  });
  const wait = cache.get("example.com", "crt_sh", {
    module: "subdomains",
    accounting: physicalAccounting(deadline.signal),
  });
  await turn();
  nowMs += 1;
  deadline.cancel("scan_deadline_exhausted");
  const result = await wait;
  const rows = cache.telemetrySnapshot({
    modules: { subdomains: { incomplete: true, incomplete_reason: "ct_source_degraded", sources: { crt_sh: { error: result.error } } } },
    scanQuality: { status: "partial" },
  });
  globalFixture = {
    deadline, cache, result, rows, abortDelivered,
    physical: cache.physicalSnapshot?.("example.com")?.crt_sh,
  };
  return globalFixture;
}

async function sslProjection(result) {
  if (typeof sslModule.projectSslCtSource === "function") return sslModule.projectSslCtSource(result);
  const value = await sslModule.resolveCertificateTransparency("example.com", {
    ctCache: { get: async () => result },
  });
  return value.ct_sources.crt_sh;
}

async function subdomainsProjection(result) {
  if (typeof subdomainsModule.projectSubdomainCtSource === "function") {
    return subdomainsModule.projectSubdomainCtSource(result, result.status === "available" ? result.data.length : null);
  }
  const originalFetch = globalThis.fetch;
  const originalSetTimeout = globalThis.setTimeout;
  globalThis.fetch = async () => jsonResponse({ Status: 0, Answer: [] });
  globalThis.setTimeout = (callback, delay, ...args) => {
    const timer = originalSetTimeout(callback, delay, ...args);
    timer.unref?.();
    return timer;
  };
  try {
    const value = await subdomainsModule.runSubdomainsModule("example.com", {
      cache: new Map(),
      ctCache: { get: async () => result },
    });
    return value.sources.crt_sh;
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.setTimeout = originalSetTimeout;
  }
}

function realCompositionAvailable() {
  return typeof reservedModule.runReservedCtConsumer === "function"
    && typeof cacheModule.createCertificateTransparencyCache === "function"
    && typeof overlapModule.createCtProviderOverlapCollector === "function"
    && typeof budgetModule.createScanDeadline === "function";
}

async function realOrderingFixture(order, { asymmetric = false } = {}) {
  if (!realCompositionAvailable()) return null;
  let nowMs = Date.parse("2026-08-02T12:00:00.000Z");
  const deadline = budgetModule.createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => nowMs);
  if (typeof deadline.globalDeadlineProvenance !== "function") return null;
  const eventLog = [];
  const delayed = [];
  let providerIndex = 0;
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(deadline.signal),
    signal: deadline.signal,
    globalDeadlineProvenance: () => deadline.globalDeadlineProvenance(),
    policies,
    timeoutSignal: () => new AbortController().signal,
    fetcher: async (_url, init) => {
      const index = providerIndex++;
      eventLog.push(`physical_provider_launch:${index}`);
      return new Promise((_resolve, reject) => {
        const abort = () => {
          const settle = () => {
            eventLog.push(`physical_provider_settle:${index}`);
            reject(new DOMException("fixture global abort", "AbortError"));
          };
          if (asymmetric && index === 1) delayed.push(settle);
          else queueMicrotask(settle);
        };
        if (init.signal?.aborted) abort();
        else init.signal?.addEventListener?.("abort", abort, { once: true });
      });
    },
  });
  const collector = overlapModule.createCtProviderOverlapCollector({ now: () => nowMs });
  if (typeof cache.releaseConsumer !== "function"
    || typeof collector.freeze !== "function"
    || typeof collector.observe !== "function") return null;
  const releaseConsumer = cache.releaseConsumer.bind(cache);
  cache.releaseConsumer = (...args) => {
    if (args[1] === "subdomains") eventLog.push("subdomains_consumer_release");
    return releaseConsumer(...args);
  };
  const freezeOverlap = collector.freeze.bind(collector);
  collector.freeze = (...args) => {
    eventLog.push("overlap_freeze");
    return freezeOverlap(...args);
  };
  const observeOverlap = collector.observe.bind(collector);
  collector.observe = (...args) => {
    eventLog.push(`overlap_observe:${args[0]}`);
    return observeOverlap(...args);
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => jsonResponse({ Status: 0, Answer: [] });
  let releaseTimer;
  let abortTimer;
  try {
    const run = reservedModule.runReservedCtConsumer("example.com", "subdomains", {
      ctCache: cache,
      ctOverlap: collector,
      signal: deadline.signal,
      globalDeadlineProvenance: () => deadline.globalDeadlineProvenance(),
      budgetMs: order === "abort_before_release" ? 8 : 2,
      run: (consumerSignal) => subdomainsModule.runSubdomainsModule("example.com", {
        accounting: physicalAccounting(consumerSignal),
        signal: consumerSignal,
        cache: new Map(),
        ctCache: cache,
        ctOverlap: collector,
        globalDeadlineProvenance: () => deadline.globalDeadlineProvenance(),
      }),
      fallback: () => ({ count: 0, items: [], sources: {}, error: "fixture released" }),
      setTimer: (callback, delay) => {
        releaseTimer = setTimeout(() => {
          nowMs += delay;
          callback();
        }, delay);
        return releaseTimer;
      },
      clearTimer: (timer) => clearTimeout(timer),
    });
    abortTimer = setTimeout(() => {
      nowMs += 1;
      eventLog.push("global_abort_signal");
      deadline.cancel("scan_deadline_exhausted");
    }, order === "abort_before_release" ? 2 : 8);
    await run;
    await new Promise((resolve) => setTimeout(resolve, 12));
    for (const settle of delayed) settle();
    await turn();
    const snapshot = collector.snapshot();
    const persistence = await overlapModule.persistCtProviderOverlapTelemetry(
      "scan_fixture", snapshot, {
        cybermeters_db: {
          prepare() { return { bind() { return this; } }; },
          async batch() { return [{ success: true }, { success: true, results: [{ durable_count: 1 }] }]; },
        },
      },
    );
    eventLog.push("persistence_snapshot");
    return {
      snapshot,
      persistence,
      eventLog,
      rows: cache.telemetrySnapshot({
        modules: { subdomains: { incomplete: true, incomplete_reason: "ct_source_degraded", sources: {} } },
        scanQuality: { status: "partial" },
      }),
    };
  } finally {
    clearTimeout(releaseTimer);
    clearTimeout(abortTimer);
    globalThis.fetch = originalFetch;
  }
}

let abortBeforeFixture;
let releaseBeforeFixture;
let asymmetricFixture;
const abortBefore = async () => abortBeforeFixture
  || (abortBeforeFixture = await realOrderingFixture("abort_before_release"));
const releaseBefore = async () => releaseBeforeFixture
  || (releaseBeforeFixture = await realOrderingFixture("release_before_abort"));
const asymmetricAbort = async () => asymmetricFixture
  || (asymmetricFixture = await realOrderingFixture("abort_before_release", { asymmetric: true }));

function reservedCompositionCapability() {
  if (typeof reservedModule.runReservedScan !== "function"
    || typeof reservedModule.runReservedCtConsumer !== "function") return false;
  return /runReservedCtConsumer/.test(Function.prototype.toString.call(reservedModule.runReservedScan));
}

async function reservedPathFixture({ globalAbort = false } = {}) {
  if (!reservedCompositionCapability()) return null;
  // This invokes the actual reserved constructor. Network dependencies are
  // replaced at the fetch boundary; no helper-existence result is accepted as
  // final proof.
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const text = String(url);
    if (text.includes("dns-query")) return jsonResponse({ Status: 0, Answer: [] });
    if (text.includes("crt.sh") || text.includes("certspotter")) return jsonResponse([]);
    return { ...jsonResponse({}), headers: { get: () => null } };
  };
  const providerCalls = { crt_sh: 0, certspotter: 0 };
  const crtGate = deferred();
  let nowMs = Date.parse("2026-08-02T12:00:00.000Z");
  const deadline = globalAbort
    ? budgetModule.createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => nowMs)
    : null;
  if (globalAbort && typeof deadline.globalDeadlineProvenance !== "function") return null;
  if (globalAbort) {
    nowMs += 1;
    deadline.cancel("scan_deadline_exhausted");
  }
  const cache = cacheModule.createCertificateTransparencyCache({
    fetcher: async (url) => {
      const provider = String(url).includes("crt.sh") ? "crt_sh" : "certspotter";
      providerCalls[provider] += 1;
      if (!globalAbort && provider === "crt_sh") return crtGate.promise;
      return jsonResponse([]);
    },
    signal: deadline?.signal || null,
    globalDeadlineProvenance: deadline
      ? () => deadline.globalDeadlineProvenance()
      : notAbortedProvenance,
    policies,
  });
  const releaseCalls = [];
  const releaseConsumer = cache.releaseConsumer?.bind(cache);
  if (releaseConsumer) {
    cache.releaseConsumer = (...args) => {
      releaseCalls.push({ module: args[1], cause: args[2] });
      return releaseConsumer(...args);
    };
  }
  const collector = overlapModule.createCtProviderOverlapCollector();
  const physicalResolutionTimer = globalAbort ? null : setTimeout(() => {
    crtGate.resolve(jsonResponse([]));
  }, 5);
  try {
    const result = await reservedModule.runReservedScan("example.com", {
      capacity: { limit: 200, safetyMargin: 0, perHostCost: 1, maxProbeRedirectHops: 0 },
      ctCache: cache,
      ctOverlap: collector,
      signal: deadline?.signal || null,
      globalDeadlineProvenance: deadline
        ? () => deadline.globalDeadlineProvenance()
        : notAbortedProvenance,
      ctConsumerBudgets: { ssl: 1, subdomains: 20 },
    });
    return { result, providerCalls, releaseCalls, snapshot: collector.snapshot() };
  } finally {
    clearTimeout(physicalResolutionTimer);
    globalThis.fetch = originalFetch;
  }
}

const vocabulary = () => ({
  outcomes: cacheModule.CT_PROVIDER_TELEMETRY_OUTCOMES || [],
  physicalAttempts: cacheModule.CT_PROVIDER_PHYSICAL_ATTEMPT_STATES || [],
  consumer: cacheModule.CT_PROVIDER_CONSUMER_WAIT_STATES || [],
  comparison: overlapModule.CT_PROVIDER_OVERLAP_COMPARISON_STATUSES || [],
  persistence: overlapModule.CT_PROVIDER_PERSISTENCE_OUTCOMES || [],
  attempts: overlapModule.CT_PROVIDER_OVERLAP_ATTEMPT_STATES || [],
});

const runs = {
  SHARED_PHYSICAL_REQUEST_ONE: async () => (await sharedLateSuccessFixture()).calls === 1,
  SSL_RELEASE_IS_CONSUMER_ONLY: async () =>
    (await sharedLateSuccessFixture()).physicalAbortCountAtRelease === 0
      && (await sharedLateSuccessFixture()).sslConsumer?.consumer_wait_state
        === "released_budget_exhausted",
  SIBLING_LATE_SUCCESS_RECEIVED: async () => {
    const value = await sharedLateSuccessFixture();
    return value.subdomainsResult?.status === "available" && value.subdomainsResult?.data?.length === 1;
  },
  CT_R1_LATE_SUCCESS_IS_OK: async () => {
    const value = await sharedLateSuccessFixture();
    return value.rows.length === 2
      && value.rows.every((row) => row.outcome === "ok" && row.result_count === 1);
  },
  RELEASED_CONSUMER_REJECTS_LATE_RESULT: async () => {
    const value = await sharedLateSuccessFixture();
    return value.lifecycleAvailable
      && value.sslConsumer?.consumer_wait_state === "released_budget_exhausted";
  },
  CONSUMER_STATE_SEPARATE_FROM_PHYSICAL: async () => {
    const value = await sharedLateSuccessFixture();
    return value.lifecycleAvailable
      && value.sslConsumer?.consumer_wait_state === "released_budget_exhausted"
      && value.sslConsumer?.physical_attempt_state === "in_flight"
      && value.physical === "terminal_success";
  },
  RELEASED_OUTPUT_IMMUTABLE: async () => {
    if (typeof reservedModule.runReservedCtConsumer !== "function") return false;
    const gate = deferred();
    const cache = cacheModule.createCertificateTransparencyCache({ fetcher: async () => gate.promise, policies });
    const fallback = Object.freeze({ outcome: "deadline_exceeded", source: "tls_probe" });
    const published = await reservedModule.runReservedCtConsumer("example.com", "ssl", {
      ctCache: cache,
      budgetMs: 1,
      run: (signal) => sslModule.resolveCertificateTransparency("example.com", { ctCache: cache, signal }),
      fallback: () => fallback,
    });
    gate.resolve(jsonResponse(CRT_OK));
    await turn();
    return published === fallback
      && JSON.stringify(published) === '{"outcome":"deadline_exceeded","source":"tls_probe"}';
  },
  SUCCESSFUL_EMPTY_IS_ZERO: async () => {
    const cache = cacheModule.createCertificateTransparencyCache({ fetcher: async () => jsonResponse([]), policies });
    const value = await cache.get("example.com", "crt_sh", { module: "ssl" });
    const source = await sslProjection(value);
    return value.status === "available" && value.data.length === 0
      && JSON.stringify(source) === '{"count":0,"error":null}';
  },
  GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE: async () => {
    const { value } = await genuineProviderFailureFixture();
    return value.status === "unavailable" && value.error === "HTTP 503" && value.data === null;
  },
  CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL: async () => {
    const { consumer } = await genuineProviderFailureFixture();
    return consumer?.consumer_wait_state === "received_failure"
      && consumer?.physical_attempt_state === "terminal_failure";
  },
  STRUCTURED_GLOBAL_DEADLINE_PROVENANCE: async () => {
    const deadline = budgetModule.createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => 5_000);
    if (typeof deadline.globalDeadlineProvenance !== "function") return false;
    deadline.cancel("scan_deadline_exhausted");
    const value = deadline.globalDeadlineProvenance();
    return value?.aborted === true && value.owner === "scan_global_deadline"
      && value.reason === "scan_deadline_exhausted" && typeof value.observed_at === "string";
  },
  GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK: async () =>
    (await globalAbortFixture()).abortDelivered === true,
  CT_R1_GLOBAL_DEADLINE_CAUSE: async () => {
    const value = await globalAbortFixture();
    return value.rows.length === 1 && value.rows[0].outcome === vocabularyValues[0];
  },
  STATE_MACHINE_TYPES_REMAIN_DISTINCT: async () => {
    const value = vocabulary();
    return value.outcomes.includes(vocabularyValues[0])
      && value.physicalAttempts.includes("global_deadline_aborted")
      && value.consumer.includes("released_budget_exhausted")
      && !value.consumer.includes("terminal_success")
      && !value.physicalAttempts.includes("released_budget_exhausted")
      && value.attempts.includes(vocabularyValues[1])
      && value.comparison.includes(vocabularyValues[2])
      && ["not_attempted_empty", "persisted", "persistence_failed"]
        .every((state) => value.persistence.includes(state));
  },
  ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT: async () => {
    const value = await abortBefore();
    return value?.snapshot?.crt_sh_attempt_state === vocabularyValues[1]
      && value.snapshot.certspotter_attempt_state === vocabularyValues[1]
      && value.snapshot.comparison_status === vocabularyValues[2]
      && value.eventLog.indexOf("global_abort_signal")
        < value.eventLog.indexOf("subdomains_consumer_release");
  },
  RELEASE_BEFORE_ABORT_IS_IN_FLIGHT: async () => {
    const value = await releaseBefore();
    return value?.snapshot?.crt_sh_attempt_state === vocabularyValues[3]
      && value.snapshot.certspotter_attempt_state === vocabularyValues[3]
      && value.snapshot.comparison_status === vocabularyValues[4]
      && value.eventLog.indexOf("subdomains_consumer_release")
        < value.eventLog.indexOf("global_abort_signal");
  },
  FROZEN_OVERLAP_REJECTS_LATE_OBSERVE: async () => {
    const collector = overlapModule.createCtProviderOverlapCollector();
    collector.begin("crt_sh");
    collector.begin("certspotter");
    collector.freeze();
    const before = JSON.stringify(collector.snapshot());
    collector.observe("crt_sh", { status: "fulfilled", value: { status: "available", data: CRT_OK } }, "example.com");
    return JSON.stringify(collector.snapshot()) === before;
  },
  PA_IF_UNREACHABLE_ON_SHARED_SIGNAL: async () => {
    const value = await asymmetricAbort();
    if (!value) return false;
    const pair = [value.snapshot.crt_sh_attempt_state, value.snapshot.certspotter_attempt_state];
    return pair.every((state) => state === vocabularyValues[1])
      && value.snapshot.comparison_status === vocabularyValues[2]
      && overlapModule.CT_PROVIDER_OVERLAP_PAIR_STATUSES != null
      && !Object.hasOwn(
        overlapModule.CT_PROVIDER_OVERLAP_PAIR_STATUSES,
        `${vocabularyValues[3]}|${vocabularyValues[1]}`,
      );
  },
  PERSISTENCE_OUTCOME_IS_INDEPENDENT: async () => {
    const empty = await overlapModule.persistCtProviderOverlapTelemetry("scan", null, {});
    const failed = await overlapModule.persistCtProviderOverlapTelemetry("scan", { module: "subdomains" }, {});
    const collector = overlapModule.createCtProviderOverlapCollector();
    collector.begin("crt_sh");
    collector.begin("certspotter");
    const measurement = collector.freeze();
    const before = JSON.stringify(measurement);
    const persisted = await overlapModule.persistCtProviderOverlapTelemetry("scan", measurement, {
      cybermeters_db: {
        prepare() { return { bind() { return this; } }; },
        async batch() { return [{ success: true }, { success: true, results: [{ durable_count: 1 }] }]; },
      },
    });
    return empty.status === "not_attempted_empty" && failed.status === "persistence_failed"
      && persisted.status === "persisted" && JSON.stringify(measurement) === before;
  },
  CUSTOMER_PLATFORM_ABORT_WORDING_EXACT: async () => {
    const source = await sslProjection((await globalAbortFixture()).result);
    return source.error === CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING;
  },
  CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE: async () => {
    const source = await sslProjection((await globalAbortFixture()).result);
    const error = String(source.error || "").toLowerCase();
    return !error.includes("fetch failed") && !error.includes("unavailable")
      && source.error === CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING;
  },
  CUSTOMER_SOURCE_SCHEMA_IS_STABLE: async () => {
    const source = await sslProjection({ status: "available", data: CRT_OK, error: null });
    return JSON.stringify(source) === '{"count":1,"error":null}';
  },
  CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS: async () => {
    const source = await sslProjection({
      status: "unavailable", data: null, error: "HTTP 503",
      physical_attempt_state: "terminal_failure", consumer_wait_state: "received_failure",
    });
    return Object.keys(source).sort().join("|") === "count|error";
  },
  SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH: async () => {
    const result = (await globalAbortFixture()).result;
    const ssl = await sslProjection(result);
    const subdomains = await subdomainsProjection(result);
    return ssl.error === CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING
      && subdomains.error === CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING;
  },
  RESERVED_PLATFORM_ABORT_WORDING_MATCH: async () => {
    const value = await reservedPathFixture({ globalAbort: true });
    const sources = value?.result?.modules?.subdomains?.sources;
    if (!sources) return false;
    return [sources.crt_sh, sources.certspotter].every((source) =>
      source?.error == null || source.error === CT_ISOLATION_PLATFORM_ABORT_CUSTOMER_WORDING);
  },
  SENTINEL_ERROR_PRECEDENCE: async () => {
    const calibration = inventoryModule.calibrateCtProviderSourceInventoryDetector?.();
    return calibration && Object.values(calibration).every((value) => value === true);
  },
  SOURCE_SET_VERSION_IS_V2: async () =>
    overlapModule.CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION === "ct-provider-overlap/2",
  V1_ROWS_ARE_DECISION_QUARANTINED: async () => {
    if (typeof analyzerModule.analyzeCtProviderTelemetry !== "function") return false;
    const row = {
      scan_id: "scan-v1", workspace_id: "founder", module: "subdomains",
      provider: "crt_sh", outcome: "ok", completeness_impact: 0,
      source_set_version: "ct-provider-overlap/1",
      started_at: "2026-08-02T11:00:00.000Z", completed_at: "2026-08-02T11:00:00.010Z",
    };
    const value = analyzerModule.analyzeCtProviderTelemetry([row], {
      nowMs: Date.parse("2026-08-02T12:00:00.000Z"), founderWorkspaceIds: ["founder"],
    });
    return value.decision_grade?.required_source_set_version === "ct-provider-overlap/2"
      && value.decision_grade?.included_rows === 0;
  },
  INVENTORY_MECHANISM_IS_UNPINNED: async () => {
    const freeze = inventoryModule.CT_PROVIDER_SOURCE_INVENTORY_FREEZE;
    return freeze?.final_runtime_count === null && freeze.final_runtime_sites === null
      && freeze.final_runtime_fingerprint === null;
  },
  EXACT_PLATFORM_ABORT_VOCABULARY: async () => {
    const value = vocabulary();
    return value.outcomes.includes(vocabularyValues[0])
      && value.attempts.includes(vocabularyValues[1])
      && value.comparison.includes(vocabularyValues[2])
      && value.attempts.includes(vocabularyValues[3])
      && value.comparison.includes(vocabularyValues[4]);
  },
  ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION: async () => {
    const base = {
      scan_quality: "partial", scan_created_at: "2026-08-02T11:00:00.000Z",
      provider: "crt_sh", started_at: "2026-08-02T11:00:01.000Z",
      completed_at: "2026-08-02T11:00:01.010Z", http_status: null,
      latency_ms: 10, result_count: null, source_set_version: "ct-provider-overlap/2",
    };
    const analysis = analyzerModule.analyzeCtProviderTelemetry([
      { ...base, scan_id: "a", workspace_id: "founder", module: "ssl", outcome: vocabularyValues[0], completeness_impact: 0 },
      { ...base, scan_id: "b", workspace_id: "founder", module: "subdomains", outcome: vocabularyValues[0], completeness_impact: 1 },
      { ...base, scan_id: "c", workspace_id: "other", module: "subdomains", outcome: "ok", completeness_impact: 0 },
    ], { nowMs: Date.parse("2026-08-02T12:00:00.000Z"), founderWorkspaceIds: ["founder"] });
    const global = analysis.platform_deadline_censorship?.scopes?.global;
    return global?.total_attempt_rows === 3
      && global.platform_deadline_abort_attempt_rows === 2
      && global.completeness_impacting_platform_deadline_abort_attempt_rows === 1
      && global.by_module_provider?.some((row) =>
        row.module === "ssl" && row.platform_deadline_abort_attempt_rows === 1);
  },
  RESERVED_PATH_USES_ISOLATED_BOUNDARY: async () => {
    const value = await reservedPathFixture();
    return value != null
      && value.providerCalls.crt_sh === 1
      && value.providerCalls.certspotter === 1
      // The first-success orchestrator also releases each cache consumer. This
      // predicate specifically proves that the outer reserved boundary still
      // performs its independent terminal release instead of accepting the
      // helper's earlier `first_success` call as equivalent evidence.
      && value.releaseCalls.some((call) => call.module === "ssl" && call.cause !== "first_success")
      && value.releaseCalls.some((call) => call.module === "subdomains" && call.cause !== "first_success")
      && value.snapshot?.module === "subdomains";
  },
  CT_R1_OVERLAP_CAUSAL_COHERENCE: async () => {
    const value = await abortBefore();
    return value?.rows?.length === 2
      && value.rows.every((row) => row.outcome === vocabularyValues[0])
      && value.snapshot.crt_sh_attempt_state === vocabularyValues[1]
      && value.snapshot.certspotter_attempt_state === vocabularyValues[1]
      && value.snapshot.comparison_status === vocabularyValues[2]
      && value.persistence.status === "persisted";
  },
};

if (JSON.stringify(Object.keys(runs)) !== JSON.stringify(assertionIds)) {
  throw new Error("Oracle execution registry does not match classified assertion order");
}
for (const assertionId of assertionIds) await runAssertion(assertionId, runs[assertionId]);
if (results.size !== assertionIds.length) {
  throw new Error(`Oracle assertion count drift: ${results.size}/${assertionIds.length}`);
}
const failures = assertionIds.filter((id) => results.get(id) !== true);
for (const id of failures) console.log(`FAIL ${id}`);
console.log(`CT isolation oracle: ${results.size - failures.length}/${results.size} contracts passed`);

if (process.argv.includes("--expect-old-runtime")) {
  const exact = JSON.stringify(failures) === JSON.stringify(CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS);
  console.log(
    `CT isolation old-runtime oracle: ${exact ? "EXACT" : "MISMATCH"} `
    + `${failures.length}/${CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS.length} failure IDs`,
  );
  process.exit(exact ? 0 : 1);
}
process.exit(failures.length === 0 ? 0 : 1);
