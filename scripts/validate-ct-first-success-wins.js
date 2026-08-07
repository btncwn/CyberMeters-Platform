#!/usr/bin/env node
// CT-R2 PR-3 structural first-success-wins semantic oracle.
//
// This file was added and executed against the exact pre-runtime base before the
// runtime implementation. Every assertion failed because the shared structural
// orchestrator did not exist. The stable IDs are also the right-reason predicates
// consumed by validate-ct-first-success-wins-mutations.js.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (file, envName) => process.env[envName]
  || pathToFileURL(path.join(root, "workers/scan-api/src/engines", file)).href;
const requestedMutation = process.argv.find((arg) => arg.startsWith("--mutation-case="))
  ?.split("=")[1] || null;

const ASSERTIONS = Object.freeze([
  "M1_ONE_SUCCESS_RETAINS_DEGRADATION",
  "M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE",
  "M3_SCAN_QUALITY_REMAINS_PARTIAL",
  "M4_FIRST_FAILURE_CANNOT_WIN",
  "M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL",
  "M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT",
  "M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY",
  "M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL",
  "M9_DEGRADATION_WORDING_REMAINS_EXPLICIT",
  "M10_SUCCESSFUL_EMPTY_STAYS_MEASURED",
  "M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED",
  "FAST_CERTSPOTTER_RELEASES_WITHOUT_CRT_SH",
  "FAST_CRT_SH_RELEASES_WITHOUT_CERTSPOTTER",
  "BOTH_FAILURES_ARE_RETAINED",
  "RELEASED_OUTPUT_IS_FROZEN",
  "LATE_SUCCESS_IS_TERMINAL_TELEMETRY",
  "LATE_SUCCESS_IS_EXCLUDED_FROM_CUSTOMER_OUTPUT",
  "LATE_FAILURE_IS_TERMINAL_TELEMETRY",
]);

const MUTATION_ASSERTION = Object.freeze({
  M1: "M1_ONE_SUCCESS_RETAINS_DEGRADATION",
  M2: "M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE",
  M3: "M3_SCAN_QUALITY_REMAINS_PARTIAL",
  M4: "M4_FIRST_FAILURE_CANNOT_WIN",
  M5: "M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL",
  M6: "M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT",
  M7: "M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY",
  M8: "M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL",
  M9: "M9_DEGRADATION_WORDING_REMAINS_EXPLICIT",
  M10: "M10_SUCCESSFUL_EMPTY_STAYS_MEASURED",
  M11: "M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED",
});

if (requestedMutation && !MUTATION_ASSERTION[requestedMutation]) {
  console.error(`Harness load error: unknown mutation case ${requestedMutation}`);
  process.exit(2);
}

let modules = null;
let loadError = null;
try {
  const [orchestrator, cache, ssl, subdomains, assetInventory, scanEngine] = await Promise.all([
    import(engineUrl("ct-first-success.js", "CT_PR3_ORCHESTRATOR_MODULE_URL")),
    import(engineUrl("ct-provider-cache.js", "CT_PR3_CACHE_MODULE_URL")),
    import(engineUrl("ssl-scan.js", "CT_PR3_SSL_MODULE_URL")),
    import(engineUrl("subdomains-scan.js", "CT_PR3_SUBDOMAINS_MODULE_URL")),
    import(engineUrl("asset-inventory.js", "CT_PR3_ASSET_MODULE_URL")),
    import(engineUrl("scan-engine.js", "CT_PR3_SCAN_ENGINE_MODULE_URL")),
  ]);
  modules = { orchestrator, cache, ssl, subdomains, assetInventory, scanEngine };
} catch (error) {
  loadError = error;
}

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};
const turn = () => new Promise((resolve) => setImmediate(resolve));
const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});
const NOW = "2026-08-01T00:00:00.000Z";
const providerBody = Object.freeze({
  crt_sh: [{
    not_after: "2027-01-01T00:00:00.000Z",
    not_before: "2025-01-01T00:00:00.000Z",
    issuer_name: "crt issuer",
    common_name: "example.com",
    name_value: "example.com\ncrt.example.com",
  }],
  certspotter: [{
    not_after: "2027-02-01T00:00:00.000Z",
    not_before: "2025-02-01T00:00:00.000Z",
    issuer: { name: "spot issuer" },
    dns_names: ["example.com", "spot.example.com"],
  }],
});

function cacheFixture() {
  if (!modules) throw loadError || new Error("runtime modules unavailable");
  const gates = { crt_sh: deferred(), certspotter: deferred() };
  const aborts = { crt_sh: 0, certspotter: 0 };
  const calls = { crt_sh: 0, certspotter: 0 };
  const cache = modules.cache.createCertificateTransparencyCache({
    policies: {
      crt_sh: { timeoutMs: 6_000, maxAttempts: 1, backoffMs: 150 },
      certspotter: { timeoutMs: 4_000, maxAttempts: 1, backoffMs: 100 },
    },
    remainingMs: () => 19_000,
    timeoutSignal: () => new AbortController().signal,
    fetcher: async (input, init = {}) => {
      const provider = String(input).includes("crt.sh") ? "crt_sh" : "certspotter";
      calls[provider] += 1;
      init.signal?.addEventListener?.("abort", () => { aborts[provider] += 1; }, { once: true });
      const value = await gates[provider].promise;
      if (value instanceof Error) throw value;
      return value instanceof Response ? value : jsonResponse(value);
    },
  });
  return { cache, gates, aborts, calls };
}

async function startRace(fixture, module = "subdomains") {
  return modules.orchestrator.raceCertificateTransparencyFirstSuccess({
    ctCache: fixture.cache,
    domain: "example.com",
    module,
  });
}

async function pendingAfter(promise, turns = 2) {
  let settled = false;
  promise.finally(() => { settled = true; });
  for (let index = 0; index < turns; index += 1) await turn();
  return !settled;
}

async function fastProviderFixture(fastProvider, slowTerminal = providerBody.crt_sh) {
  const fixture = cacheFixture();
  const outputPromise = startRace(fixture);
  fixture.gates[fastProvider].resolve(providerBody[fastProvider]);
  const output = await outputPromise;
  const before = JSON.stringify(output);
  const slowProvider = fastProvider === "crt_sh" ? "certspotter" : "crt_sh";
  fixture.gates[slowProvider].resolve(slowTerminal === providerBody.crt_sh
    ? providerBody[slowProvider]
    : slowTerminal);
  await turn();
  await turn();
  return { ...fixture, output, before, fastProvider, slowProvider };
}

async function subdomainsOneProviderFixture() {
  const fixture = cacheFixture();
  const realFetch = globalThis.fetch;
  const realRandom = Math.random;
  const realSetTimeout = globalThis.setTimeout;
  globalThis.fetch = async (input) => {
    if (String(input).includes("dns-query")) return jsonResponse({ Status: 0, Answer: [] });
    throw new Error(`unexpected non-cache fetch ${input}`);
  };
  Math.random = () => 0.123456789;
  globalThis.setTimeout = (callback, delay, ...args) => {
    const timer = realSetTimeout(callback, delay, ...args);
    if (delay >= 15_000) timer.unref?.();
    return timer;
  };
  try {
    const outputPromise = modules.subdomains.runSubdomainsModule("example.com", {
      ctCache: fixture.cache,
      cache: new Map(),
    });
    fixture.gates.certspotter.resolve(providerBody.certspotter);
    const output = await outputPromise;
    fixture.gates.crt_sh.resolve(providerBody.crt_sh);
    await turn();
    return output;
  } finally {
    globalThis.fetch = realFetch;
    Math.random = realRandom;
    globalThis.setTimeout = realSetTimeout;
  }
}

async function assertionBody(id) {
  switch (id) {
    case "M1_ONE_SUCCESS_RETAINS_DEGRADATION": {
      const output = await subdomainsOneProviderFixture();
      return output.incomplete === true && output.incomplete_reason === "ct_source_degraded";
    }
    case "M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE": {
      const output = await subdomainsOneProviderFixture();
      return modules.assetInventory.subdomainDiscoveryComplete({
        subdomains: output,
        dns_bruteforce: { items: [], error: null },
      }) === false;
    }
    case "M3_SCAN_QUALITY_REMAINS_PARTIAL": {
      const output = await subdomainsOneProviderFixture();
      return modules.scanEngine.buildScanQuality({ subdomains: output }).status === "partial";
    }
    case "M4_FIRST_FAILURE_CANNOT_WIN": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.crt_sh.resolve(jsonResponse({}, 404));
      const stillPending = await pendingAfter(outputPromise);
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const output = await outputPromise;
      return stillPending && output.release.winner === "certspotter"
        && output.providers.crt_sh.status === "unavailable"
        && output.providers.certspotter.status === "available";
    }
    case "M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL": {
      const result = await fastProviderFixture("certspotter");
      return result.aborts.crt_sh === 0
        && result.cache.physicalSnapshot("example.com").crt_sh === "terminal_success";
    }
    case "M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT": {
      const result = await fastProviderFixture("certspotter");
      return JSON.stringify(result.output) === result.before;
    }
    case "M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.crt_sh.resolve(jsonResponse({}, 404));
      fixture.gates.certspotter.resolve(jsonResponse({}, 503));
      const output = await outputPromise;
      return Object.values(output.providers).every((provider) =>
        provider.status === "unavailable" && provider.data === null);
    }
    case "M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL": {
      const fixture = cacheFixture();
      const realDateNow = Date.now;
      Date.now = () => Date.parse(NOW);
      try {
        const outputPromise = modules.ssl.resolveCertificateTransparency("example.com", {
          ctCache: fixture.cache,
        });
        fixture.gates.certspotter.resolve(providerBody.certspotter);
        const output = await outputPromise;
        fixture.gates.crt_sh.resolve(providerBody.crt_sh);
        await turn();
        return output.cert_issuer === "spot issuer" && output.cert_shared_san_count === null;
      } finally {
        Date.now = realDateNow;
      }
    }
    case "M9_DEGRADATION_WORDING_REMAINS_EXPLICIT": {
      const result = await fastProviderFixture("certspotter");
      return result.output.providers.crt_sh.error
        === "CyberMeters released this module after another Certificate Transparency provider succeeded; this provider result was still in flight and was excluded from the immutable module output.";
    }
    case "M10_SUCCESSFUL_EMPTY_STAYS_MEASURED": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.crt_sh.resolve([]);
      fixture.gates.certspotter.resolve(jsonResponse({}, 404));
      const output = await outputPromise;
      await turn();
      return output.release.reason === "first_success"
        && output.release.winner === "crt_sh"
        && output.providers.crt_sh.status === "available"
        && Array.isArray(output.providers.crt_sh.data)
        && output.providers.crt_sh.data.length === 0
        && output.providers.crt_sh.error === null;
    }
    case "M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.crt_sh.resolve(providerBody.crt_sh);
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const output = await outputPromise;
      return output.release.included_terminal_providers.join("|") === "crt_sh|certspotter"
        && output.providers.crt_sh.status === "available"
        && output.providers.certspotter.status === "available"
        && output.providers.crt_sh.data[0].issuer_name === "crt issuer"
        && output.providers.certspotter.data[0].issuer.name === "spot issuer";
    }
    case "FAST_CERTSPOTTER_RELEASES_WITHOUT_CRT_SH": {
      const result = await fastProviderFixture("certspotter");
      return result.output.release.winner === "certspotter"
        && result.output.providers.certspotter.status === "available";
    }
    case "FAST_CRT_SH_RELEASES_WITHOUT_CERTSPOTTER": {
      const result = await fastProviderFixture("crt_sh", providerBody.certspotter);
      return result.output.release.winner === "crt_sh"
        && result.output.providers.crt_sh.status === "available";
    }
    case "BOTH_FAILURES_ARE_RETAINED": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.crt_sh.resolve(jsonResponse({}, 404));
      fixture.gates.certspotter.resolve(jsonResponse({}, 503));
      const output = await outputPromise;
      return output.release.reason === "all_terminal_failure"
        && output.providers.crt_sh.error === "HTTP 404"
        && output.providers.certspotter.error === "HTTP 503";
    }
    case "RELEASED_OUTPUT_IS_FROZEN": {
      const result = await fastProviderFixture("certspotter");
      return Object.isFrozen(result.output)
        && Object.isFrozen(result.output.providers)
        && Object.isFrozen(result.output.providers.certspotter)
        && Object.isFrozen(result.output.release)
        && Object.isFrozen(result.output.release.included_terminal_providers);
    }
    case "LATE_SUCCESS_IS_TERMINAL_TELEMETRY": {
      const result = await fastProviderFixture("certspotter");
      const row = result.cache.telemetrySnapshot().find((entry) =>
        entry.provider === "crt_sh" && entry.module === "subdomains");
      const consumer = result.cache.consumerSnapshot("example.com", "subdomains")
        .providers.crt_sh;
      return row?.outcome === "ok"
        && row?.customer_evidence_disposition === "late_success_excluded_after_first_success"
        && consumer?.terminal_physical_attempt_state === "terminal_success";
    }
    case "LATE_SUCCESS_IS_EXCLUDED_FROM_CUSTOMER_OUTPUT": {
      const result = await fastProviderFixture("certspotter");
      return result.output.providers.crt_sh.status === "unavailable"
        && result.output.providers.crt_sh.error
          === modules.cache.CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING
        && JSON.stringify(result.output) === result.before;
    }
    case "LATE_FAILURE_IS_TERMINAL_TELEMETRY": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const output = await outputPromise;
      fixture.gates.crt_sh.resolve(jsonResponse({}, 404));
      await turn();
      await turn();
      const row = fixture.cache.telemetrySnapshot().find((entry) =>
        entry.provider === "crt_sh" && entry.module === "subdomains");
      const consumer = fixture.cache.consumerSnapshot("example.com", "subdomains")
        .providers.crt_sh;
      return output.providers.crt_sh.status === "unavailable"
        && row?.outcome === "http_error"
        && row?.customer_evidence_disposition === "late_failure_after_first_success"
        && consumer?.terminal_physical_attempt_state === "terminal_failure";
    }
    default:
      throw new Error(`missing assertion body ${id}`);
  }
}

const selected = requestedMutation
  ? [MUTATION_ASSERTION[requestedMutation]]
  : [...ASSERTIONS];
let passed = 0;
let failed = 0;
for (const id of selected) {
  try {
    if (await assertionBody(id)) {
      passed += 1;
      console.log(`PASS ${id}`);
    } else {
      failed += 1;
      console.log(`FAIL ${id} — predicate returned false`);
    }
  } catch (error) {
    failed += 1;
    console.log(`FAIL ${id} — ${error?.message || error}`);
  }
}

console.log(`CT-R2 PR-3 first-success: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exit(1);
console.log("CT-R2 PR-3 first-success validation passed");
