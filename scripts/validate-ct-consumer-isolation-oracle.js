#!/usr/bin/env node
// CT-R2 PR-2A.1 immutable semantic oracle.
//
// Contract IDs are the public test vocabulary. `--expect-old-runtime` accepts
// exactly the predeclared old-runtime failure set below; normal execution accepts
// no failures. Every asynchronous contract is caught by the assertion carrier so
// syntax/import/runtime failures cannot impersonate semantic evidence.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS,
  CT_ISOLATION_OLD_RUNTIME_PASS_IDS,
} from "./ct-consumer-isolation-old-runtime-classification.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (name) => pathToFileURL(path.join(
  root, "workers/scan-api/src/engines", name,
)).href;
const load = (envName, name) => import(process.env[envName] || engineUrl(name));

const cacheModule = await load("CT_ORACLE_CACHE_MODULE_URL", "ct-provider-cache.js");
const overlapModule = await load("CT_ORACLE_OVERLAP_MODULE_URL", "ct-provider-overlap.js");
const budgetModule = await load("CT_ORACLE_BUDGET_MODULE_URL", "scan-budget.js");
const reservedModule = await load("CT_ORACLE_RESERVED_MODULE_URL", "reserved-scan.js");
const sslModule = await load("CT_ORACLE_SSL_MODULE_URL", "ssl-scan.js");
const analyzerModule = await import(
  process.env.CT_ORACLE_ANALYZER_MODULE_URL
    || pathToFileURL(path.join(root, "scripts/analyze-ct-provider-telemetry.js")).href
);

export const CT_ISOLATION_CONTRACT_IDS = Object.freeze([
  "SHARED_PHYSICAL_REQUEST_ONE",
  "SSL_RELEASE_IS_CONSUMER_ONLY",
  "SIBLING_LATE_SUCCESS_RECEIVED",
  "CT_R1_LATE_SUCCESS_IS_OK",
  "RELEASED_CONSUMER_REJECTS_LATE_RESULT",
  "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
  "RELEASED_OUTPUT_IMMUTABLE",
  "SUCCESSFUL_EMPTY_IS_ZERO",
  "GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE",
  "CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL",
  "STRUCTURED_GLOBAL_DEADLINE_PROVENANCE",
  "GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK",
  "CT_R1_GLOBAL_DEADLINE_CAUSE",
  "ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT",
  "RELEASE_BEFORE_ABORT_IS_IN_FLIGHT",
  "FROZEN_OVERLAP_REJECTS_LATE_OBSERVE",
  "PA_IF_UNREACHABLE_ON_SHARED_SIGNAL",
  "RESERVED_PATH_USES_ISOLATED_BOUNDARY",
  "SOURCE_SET_VERSION_IS_V2",
  "ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION",
  "CUSTOMER_SOURCE_SCHEMA_IS_STABLE",
  "CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS",
]);

const declaredPartition = [...CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS, ...CT_ISOLATION_OLD_RUNTIME_PASS_IDS]
  .sort((a, b) => a.localeCompare(b));
const contractPartition = [...CT_ISOLATION_CONTRACT_IDS].sort((a, b) => a.localeCompare(b));
if (JSON.stringify(declaredPartition) !== JSON.stringify(contractPartition)) {
  throw new Error("Old-runtime PASS/FAIL classification does not partition contract IDs");
}

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

function reservedIsolationCapability() {
  if (typeof reservedModule.runReservedScan !== "function"
    || typeof reservedModule.runReservedCtConsumer !== "function") return false;
  const composition = Function.prototype.toString.call(reservedModule.runReservedScan);
  const boundary = Function.prototype.toString.call(reservedModule.runReservedCtConsumer);
  return /runReservedCtConsumer/.test(composition)
    && /releaseConsumer/.test(boundary)
    && /ctOverlap\?\.freeze/.test(boundary);
}

const results = new Map();
async function contract(id, run) {
  if (!CT_ISOLATION_CONTRACT_IDS.includes(id) || results.has(id)) {
    throw new Error(`Oracle contract registration drift: ${id}`);
  }
  try {
    results.set(id, (await run()) === true);
  } catch {
    results.set(id, false);
  }
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
  const globalProvenance = () => globalController.signal.aborted
    ? globalController.signal.reason
    : { aborted: false, owner: "scan_global_deadline", reason: null, observed_at: null };
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
    globalDeadlineProvenance: globalProvenance,
    signal: globalController.signal,
    policies,
    timeoutSignal: () => new AbortController().signal,
  });
  const cacheHasConsumerLifecycle = typeof cache.releaseConsumer === "function"
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
  const physicalAbortCountAtSslRelease = physicalAbortCount;
  const atReleasePhysical = cache.physicalSnapshot?.("example.com")?.crt_sh;
  const atReleaseConsumer = cache.consumerSnapshot?.("example.com", "ssl")?.providers?.crt_sh;
  gate.resolve(jsonResponse(CRT_OK));
  const subdomainsResult = await subdomainsWait;
  await turn();
  const afterConsumer = cache.consumerSnapshot?.("example.com", "ssl")?.providers?.crt_sh;
  const afterPhysical = cache.physicalSnapshot?.("example.com")?.crt_sh;
  const rows = cache.telemetrySnapshot({
    modules: { subdomains: { sources: { crt_sh: { count: 1, error: null } } } },
    scanQuality: { status: "complete" },
  });
  void sslWait;
  sharedFixture = {
    calls,
    cacheHasConsumerLifecycle,
    physicalAbortCountAtSslRelease,
    atReleasePhysical,
    atReleaseConsumer,
    afterConsumer,
    afterPhysical,
    subdomainsResult,
    rows,
  };
  return sharedFixture;
}

await contract("SHARED_PHYSICAL_REQUEST_ONE", async () =>
  (await sharedLateSuccessFixture()).calls === 1);
await contract("SSL_RELEASE_IS_CONSUMER_ONLY", async () => {
  const value = await sharedLateSuccessFixture();
  return value.physicalAbortCountAtSslRelease === 0;
});
await contract("SIBLING_LATE_SUCCESS_RECEIVED", async () => {
  const value = await sharedLateSuccessFixture();
  return value.subdomainsResult?.status === "available"
    && value.subdomainsResult?.data?.length === 1;
});
await contract("CT_R1_LATE_SUCCESS_IS_OK", async () => {
  const value = await sharedLateSuccessFixture();
  return value.rows.length === 2
    && value.rows.every((row) => row.outcome === "ok" && row.result_count === 1);
});
await contract("RELEASED_CONSUMER_REJECTS_LATE_RESULT", async () => {
  const value = await sharedLateSuccessFixture();
  if (typeof value.cacheHasConsumerLifecycle !== "boolean") return false;
  if (value.cacheHasConsumerLifecycle !== true) return false;
  return value.afterConsumer?.consumer_wait_state === "released_budget_exhausted";
});
await contract("CONSUMER_STATE_SEPARATE_FROM_PHYSICAL", async () => {
  const value = await sharedLateSuccessFixture();
  if (value.cacheHasConsumerLifecycle !== true) return false;
  return value.afterConsumer?.consumer_wait_state === "released_budget_exhausted"
    && value.afterConsumer?.physical_attempt_state === "in_flight"
    && value.afterPhysical === "terminal_success";
});

await contract("RELEASED_OUTPUT_IMMUTABLE", async () => {
  if (!reservedIsolationCapability()) return false;
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(),
    fetcher: async () => {
      await new Promise((resolve) => setTimeout(resolve, 8));
      return jsonResponse(CRT_OK);
    },
    policies,
    timeoutSignal: () => new AbortController().signal,
  });
  const fallback = Object.freeze({ outcome: "deadline_exceeded", source: "tls_probe" });
  const published = await reservedModule.runReservedCtConsumer("example.com", "ssl", {
    ctCache: cache,
    budgetMs: 1,
    run: (signal) => sslModule.resolveCertificateTransparency("example.com", {
      ctCache: cache,
      signal,
    }),
    fallback: () => fallback,
  });
  await new Promise((resolve) => setTimeout(resolve, 12));
  return published === fallback
    && JSON.stringify(published) === '{"outcome":"deadline_exceeded","source":"tls_probe"}';
});

await contract("SUCCESSFUL_EMPTY_IS_ZERO", async () => {
  const cache = cacheModule.createCertificateTransparencyCache({
    fetcher: async () => jsonResponse([]),
    policies,
  });
  const successfulEmpty = await cache.get("example.com", "crt_sh", { module: "ssl" });
  const value = await sslModule.resolveCertificateTransparency("example.com", {
    ctCache: { get: async () => successfulEmpty },
  });
  return successfulEmpty.status === "available"
    && Array.isArray(successfulEmpty.data)
    && successfulEmpty.data.length === 0
    && successfulEmpty.error === null
    && value.ct_sources?.crt_sh?.count === 0
    && value.ct_sources?.crt_sh?.error === null
    && value.ct_sources?.certspotter?.count === 0
    && value.ct_sources?.certspotter?.error === null;
});

await contract("GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE", async () => {
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(),
    fetcher: async () => jsonResponse({}, 503),
    policies,
  });
  const value = await cache.get("example.com", "crt_sh", { module: "ssl" });
  return value.status === "unavailable" && value.error === "HTTP 503"
    && value.data === null;
});

await contract("CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL", async () => {
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(),
    fetcher: async () => jsonResponse({}, 503),
    policies,
  });
  if (typeof cache.consumerSnapshot !== "function") return false;
  const value = await cache.get("example.com", "crt_sh", { module: "ssl" });
  const consumer = cache.consumerSnapshot("example.com", "ssl")?.providers?.crt_sh;
  return value.status === "unavailable"
    && consumer?.consumer_wait_state === "received_failure"
    && consumer?.physical_attempt_state === "terminal_failure";
});

let structuredDeadline;
await contract("STRUCTURED_GLOBAL_DEADLINE_PROVENANCE", async () => {
  const deadline = budgetModule.createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => 5_000);
  if (typeof deadline.globalDeadlineProvenance !== "function") return false;
  deadline.cancel("scan_deadline_exhausted");
  structuredDeadline = deadline.globalDeadlineProvenance();
  return structuredDeadline?.aborted === true
    && structuredDeadline.owner === "scan_global_deadline"
    && structuredDeadline.reason === "scan_deadline_exhausted"
    && typeof structuredDeadline.observed_at === "string";
});

let globalFixture;
async function globalAbortFixture() {
  if (globalFixture) return globalFixture;
  const controller = new AbortController();
  const provenance = Object.freeze({
    aborted: true,
    owner: "scan_global_deadline",
    reason: "scan_deadline_exhausted",
    observed_at: "2026-08-02T12:00:00.000Z",
  });
  let abortDelivered = false;
  const cache = cacheModule.createCertificateTransparencyCache({
    accounting: () => physicalAccounting(controller.signal),
    signal: controller.signal,
    globalDeadlineProvenance: () => controller.signal.aborted
      ? provenance
      : { aborted: false, owner: "scan_global_deadline", reason: null, observed_at: null },
    policies,
    timeoutSignal: () => new AbortController().signal,
    fetcher: async (_url, init) => new Promise((_resolve, reject) => {
      const uncancelledGuard = setTimeout(() => reject(
        new Error("fixture global cancellation was not delivered"),
      ), 8);
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
    accounting: physicalAccounting(controller.signal),
  });
  await turn();
  controller.abort(provenance);
  const result = await wait;
  const rows = cache.telemetrySnapshot({
    modules: { subdomains: { incomplete: true, incomplete_reason: "ct_source_degraded", sources: { crt_sh: { error: result.error } } } },
    scanQuality: { status: "partial" },
  });
  globalFixture = {
    result,
    rows,
    abortDelivered,
    physicalState: cache.physicalSnapshot?.("example.com")?.crt_sh,
  };
  return globalFixture;
}

await contract("GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK", async () =>
  (await globalAbortFixture()).result.status === "unavailable"
    && (await globalAbortFixture()).abortDelivered === true);
await contract("CT_R1_GLOBAL_DEADLINE_CAUSE", async () => {
  const value = await globalAbortFixture();
  return value.rows.length === 1 && value.rows[0].outcome === "platform_deadline_abort";
});

await contract("ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT", async () => {
  const collector = overlapModule.createCtProviderOverlapCollector();
  collector.startConsumer?.();
  collector.begin("crt_sh");
  collector.begin("certspotter");
  const snapshot = collector.freeze({
    release_cause: "scan_global_deadline",
    global_deadline: {
      aborted: true,
      owner: "scan_global_deadline",
      reason: "scan_deadline_exhausted",
      observed_at: "2026-08-02T12:00:00.000Z",
    },
    physicalStates: { crt_sh: "global_deadline_aborted", certspotter: "global_deadline_aborted" },
  });
  return snapshot?.crt_sh_attempt_state === "terminal_platform_deadline_abort"
    && snapshot?.certspotter_attempt_state === "terminal_platform_deadline_abort"
    && snapshot?.comparison_status === "censored_platform_deadline_abort";
});

await contract("RELEASE_BEFORE_ABORT_IS_IN_FLIGHT", async () => {
  const collector = overlapModule.createCtProviderOverlapCollector();
  collector.startConsumer?.();
  collector.begin("crt_sh");
  collector.begin("certspotter");
  const snapshot = collector.freeze({
    release_cause: "module_budget_exhausted",
    global_deadline: { aborted: false, owner: "scan_global_deadline", reason: null, observed_at: null },
    physicalStates: { crt_sh: "in_flight", certspotter: "in_flight" },
  });
  return snapshot?.crt_sh_attempt_state === "in_flight_at_consumer_release"
    && snapshot?.certspotter_attempt_state === "in_flight_at_consumer_release"
    && snapshot?.comparison_status === "censored_in_flight";
});

await contract("FROZEN_OVERLAP_REJECTS_LATE_OBSERVE", async () => {
  const collector = overlapModule.createCtProviderOverlapCollector();
  collector.startConsumer?.();
  collector.begin("crt_sh");
  collector.begin("certspotter");
  collector.freeze({
    global_deadline: { aborted: false, owner: "scan_global_deadline", reason: null, observed_at: null },
    physicalStates: { crt_sh: "in_flight", certspotter: "in_flight" },
  });
  const before = JSON.stringify(collector.snapshot());
  collector.observe("crt_sh", { status: "fulfilled", value: { status: "available", data: CRT_OK } }, "example.com");
  return JSON.stringify(collector.snapshot()) === before;
});

await contract("PA_IF_UNREACHABLE_ON_SHARED_SIGNAL", async () =>
  Array.isArray(overlapModule.CT_PROVIDER_OVERLAP_ATTEMPT_STATES)
    && overlapModule.CT_PROVIDER_OVERLAP_ATTEMPT_STATES.includes("terminal_platform_deadline_abort")
    && overlapModule.CT_PROVIDER_OVERLAP_PAIR_STATUSES != null
    && !Object.hasOwn(
      overlapModule.CT_PROVIDER_OVERLAP_PAIR_STATUSES,
      "in_flight_at_consumer_release|terminal_platform_deadline_abort",
    ));
await contract("RESERVED_PATH_USES_ISOLATED_BOUNDARY", async () => {
  return reservedIsolationCapability();
});
await contract("SOURCE_SET_VERSION_IS_V2", async () =>
  overlapModule.CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION === "ct-provider-overlap/2");

await contract("ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION", async () => {
  const nowMs = Date.parse("2026-08-02T12:00:00.000Z");
  const base = {
    scan_quality: "partial",
    scan_created_at: "2026-08-02T11:00:00.000Z",
    provider: "crt_sh",
    started_at: "2026-08-02T11:00:01.000Z",
    completed_at: "2026-08-02T11:00:01.010Z",
    http_status: null,
    latency_ms: 10,
    result_count: null,
  };
  const analysis = analyzerModule.analyzeCtProviderTelemetry([
    { ...base, scan_id: "scan-a", workspace_id: "founder", module: "ssl", outcome: "platform_deadline_abort", completeness_impact: 0 },
    { ...base, scan_id: "scan-b", workspace_id: "founder", module: "subdomains", outcome: "platform_deadline_abort", completeness_impact: 1 },
    { ...base, scan_id: "scan-c", workspace_id: "other", module: "subdomains", outcome: "ok", completeness_impact: 0 },
  ], { nowMs, founderWorkspaceIds: ["founder"] });
  if (!Object.hasOwn(analysis, "platform_deadline_censorship")) return false;
  const global = analysis.platform_deadline_censorship?.scopes?.global;
  return global?.total_attempt_rows === 3
    && global?.platform_deadline_abort_attempt_rows === 2
    && global?.completeness_impacting_platform_deadline_abort_attempt_rows === 1
    && global?.by_module_provider?.some((row) =>
      row.module === "ssl" && row.platform_deadline_abort_attempt_rows === 1
    );
});

await contract("CUSTOMER_SOURCE_SCHEMA_IS_STABLE", async () => {
  const ssl = await sslModule.resolveCertificateTransparency("example.com", {
    ctCache: {
      get: async (_domain, provider) => provider === "crt_sh"
        ? { status: "available", data: CRT_OK, error: null }
        : { status: "available", data: [], error: null },
    },
  });
  return JSON.stringify(ssl.ct_sources?.crt_sh) === '{"count":1,"error":null}';
});
await contract("CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS", async () => {
  const ssl = await sslModule.resolveCertificateTransparency("example.com", {
    ctCache: {
      get: async () => ({
        status: "unavailable",
        data: null,
        error: "HTTP 503",
        physical_attempt_state: "terminal_failure",
        consumer_wait_state: "received_failure",
      }),
    },
  });
  return [ssl.ct_sources?.crt_sh, ssl.ct_sources?.certspotter].every((source) =>
    Object.keys(source || {}).sort().join("|") === "count|error");
});

if (results.size !== CT_ISOLATION_CONTRACT_IDS.length) {
  throw new Error(`Oracle contract count drift: ${results.size}/${CT_ISOLATION_CONTRACT_IDS.length}`);
}
const failures = CT_ISOLATION_CONTRACT_IDS.filter((id) => results.get(id) !== true);
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
