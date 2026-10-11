#!/usr/bin/env node
// CT-R2 PR-3 structural first-success-wins semantic oracle.
//
// This file was added and executed against the exact pre-runtime base before the
// runtime implementation. Every assertion failed because the shared structural
// orchestrator did not exist. The stable IDs are also the right-reason predicates
// consumed by validate-ct-first-success-wins-mutations.js.
//
// CertSpotter-only CT: production declares exactly one Certificate Transparency
// provider. Module-level assertions (subdomains, SSL, asset inventory, scan
// quality) therefore run against the real single-provider cache, where a
// CertSpotter failure is a total CT loss and a CertSpotter success is complete
// CT coverage. The orchestrator itself stays provider-neutral and races whatever
// providers a cache declares, so its multi-provider guarantees (first failure
// cannot win, release never cancels physical work, late settlement cannot mutate
// released evidence, bounded sibling grace) are exercised through a test double
// that declares a neutral second provider, "provider_b", served by a second real
// single-provider cache.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (file, envName) => process.env[envName]
  || pathToFileURL(path.join(root, "workers/scan-api/src/engines", file)).href;
const requestedMutation = process.argv.find((arg) => arg.startsWith("--mutation-case="))
  ?.split("=")[1] || null;

const ASSERTIONS = Object.freeze([
  "M1_CT_LOSS_IS_INCOMPLETE_NOT_DEGRADED",
  "M2_PROVIDER_LOSS_NEVER_DISCOVERY_COMPLETE",
  "M3_CT_LOSS_SCAN_QUALITY_IS_PARTIAL",
  "M4_FIRST_FAILURE_CANNOT_WIN",
  "M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL",
  "M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT",
  "M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY",
  "M8_SHARED_SAN_NULL_UNTIL_MEASURED",
  "M9_DEGRADATION_WORDING_REMAINS_EXPLICIT",
  "M10_SUCCESSFUL_EMPTY_STAYS_MEASURED",
  "M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED",
  "SINGLE_PROVIDER_SUCCESS_IS_FINAL_WITHOUT_GRACE",
  "SINGLE_PROVIDER_FAILURE_IS_TERMINAL_FAILURE",
  "SUBDOMAINS_CERTSPOTTER_SUCCESS_IS_COMPLETE",
  "SUBDOMAINS_CERTSPOTTER_EMPTY_IS_MEASURED_NOT_LOST",
  "FAST_CERTSPOTTER_RELEASES_WITHOUT_SIBLING",
  "FAST_SIBLING_RELEASES_WITHOUT_CERTSPOTTER",
  "BOTH_FAILURES_ARE_RETAINED",
  "RELEASED_OUTPUT_IS_FROZEN",
  "LATE_SUCCESS_IS_TERMINAL_TELEMETRY",
  "LATE_SUCCESS_IS_EXCLUDED_FROM_CUSTOMER_OUTPUT",
  "LATE_FAILURE_IS_TERMINAL_TELEMETRY",
  "GRACE_INCLUDES_SIBLING_THAT_FINISHES_IN_WINDOW",
  "GRACE_INCLUDES_SIBLING_FAILURE_AS_FAILURE",
  "GRACE_EXPIRY_EXCLUDES_IN_FLIGHT_SIBLING",
  "GRACE_ABORT_RELEASES_WITHOUT_WAITING",
  "GRACE_REQUEST_IS_CLAMPED",
]);

const MUTATION_ASSERTION = Object.freeze({
  M1: "M1_CT_LOSS_IS_INCOMPLETE_NOT_DEGRADED",
  M2: "M2_PROVIDER_LOSS_NEVER_DISCOVERY_COMPLETE",
  M3: "M3_CT_LOSS_SCAN_QUALITY_IS_PARTIAL",
  M4: "M4_FIRST_FAILURE_CANNOT_WIN",
  M5: "M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL",
  M6: "M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT",
  M7: "M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY",
  M8: "M8_SHARED_SAN_NULL_UNTIL_MEASURED",
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
const SCAN_ANCHOR = "2026-08-18T01:00:00Z";
// A neutral second provider for generic orchestration only; production never
// declares it.
const PROVIDER_B = "provider_b";
const providerBody = Object.freeze({
  certspotter: [{
    not_after: "2027-02-01T00:00:00.000Z",
    not_before: "2025-02-01T00:00:00.000Z",
    issuer: { name: "spot issuer" },
    dns_names: ["example.com", "spot.example.com"],
  }],
  // Served by a real (CertSpotter-shaped) cache, so it answers in the same
  // issuance shape with its own distinguishable issuer.
  [PROVIDER_B]: [{
    not_after: "2027-03-01T00:00:00.000Z",
    not_before: "2025-03-01T00:00:00.000Z",
    issuer: { name: "provider b issuer" },
    dns_names: ["example.com", "b.example.com"],
  }],
});
// The selected issuance also names a host outside the scanned domain: the
// shared-SAN count is measured from the issuance's own DNS names.
const sharedSanBody = Object.freeze([{
  not_after: "2027-02-01T00:00:00.000Z",
  not_before: "2025-02-01T00:00:00.000Z",
  issuer: { name: "spot issuer" },
  dns_names: ["example.com", "spot.example.com", "tenant.example.net"],
}]);

// One real CT cache whose only provider (CertSpotter) is gated by the test.
function singleProviderCache() {
  if (!modules) throw loadError || new Error("runtime modules unavailable");
  const state = { gate: deferred(), aborts: 0, calls: 0, cache: null };
  state.cache = modules.cache.createCertificateTransparencyCache({
    policies: {
      certspotter: { timeoutMs: 4_000, maxAttempts: 1, backoffMs: 100 },
    },
    remainingMs: () => 19_000,
    timeoutSignal: () => new AbortController().signal,
    fetcher: async (input, init = {}) => {
      if (!String(input).startsWith("https://api.certspotter.com/")) {
        throw new Error(`unexpected CT fetch ${input}`);
      }
      state.calls += 1;
      init.signal?.addEventListener?.("abort", () => { state.aborts += 1; }, { once: true });
      const value = await state.gate.promise;
      if (value instanceof Error) throw value;
      return value instanceof Response ? value : jsonResponse(value);
    },
  });
  return state;
}

function fixtureFrom(backing, cache) {
  const aborts = {};
  for (const name of Object.keys(backing)) {
    Object.defineProperty(aborts, name, { enumerable: true, get: () => backing[name].aborts });
  }
  return {
    cache,
    gates: Object.fromEntries(Object.entries(backing).map(([name, state]) => [name, state.gate])),
    aborts,
  };
}

// Production shape: the real cache, which declares exactly ["certspotter"].
function cacheFixture() {
  const backing = { certspotter: singleProviderCache() };
  return fixtureFrom(backing, backing.certspotter.cache);
}

// Generic multi-provider double. It declares two providers, and each is backed
// by its own real single-provider cache, so consumer release, late-settlement
// disposition, physical state and telemetry are the real implementation. Each
// backing cache knows its one provider as "certspotter"; the double relabels in
// place (preserving object identity, which M6 depends on) to the declared name.
function multiProviderFixture() {
  const backing = { certspotter: singleProviderCache(), [PROVIDER_B]: singleProviderCache() };
  const names = Object.freeze(Object.keys(backing));
  const relabel = (value, name) => {
    if (value && typeof value === "object" && !Object.isFrozen(value)) value.provider = name;
    return value;
  };
  const cache = {
    providers: names,
    get(domain, provider, options) {
      if (!backing[provider]) throw new Error(`undeclared provider ${provider}`);
      return backing[provider].cache.get(domain, "certspotter", options)
        .then((result) => relabel(result, provider));
    },
    releaseConsumer(domain, module, cause) {
      for (const name of names) backing[name].cache.releaseConsumer(domain, module, cause);
    },
    consumerSnapshot(domain, module) {
      const providers = {};
      for (const name of names) {
        const row = backing[name].cache.consumerSnapshot(domain, module).providers.certspotter;
        if (row) providers[name] = row;
      }
      return { module, providers };
    },
    physicalSnapshot(domain) {
      return Object.fromEntries(names.flatMap((name) => {
        const state = backing[name].cache.physicalSnapshot(domain).certspotter;
        return state ? [[name, state]] : [];
      }));
    },
    telemetrySnapshot(options) {
      return names.flatMap((name) => backing[name].cache.telemetrySnapshot(options)
        .map((row) => ({ ...row, provider: name })));
    },
  };
  return fixtureFrom(backing, cache);
}

async function startRace(fixture, module = "subdomains", extra = {}) {
  return modules.orchestrator.raceCertificateTransparencyFirstSuccess({
    ctCache: fixture.cache,
    domain: "example.com",
    module,
    ...extra,
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function pendingAfter(promise, turns = 2) {
  let settled = false;
  promise.finally(() => { settled = true; });
  for (let index = 0; index < turns; index += 1) await turn();
  return !settled;
}

const otherProvider = (provider) => (provider === PROVIDER_B ? "certspotter" : PROVIDER_B);

async function fastProviderFixture(fastProvider, slowTerminal = null) {
  const fixture = multiProviderFixture();
  const outputPromise = startRace(fixture);
  fixture.gates[fastProvider].resolve(providerBody[fastProvider]);
  const output = await outputPromise;
  const before = JSON.stringify(output);
  const slowProvider = otherProvider(fastProvider);
  fixture.gates[slowProvider].resolve(slowTerminal ?? providerBody[slowProvider]);
  await turn();
  await turn();
  return { ...fixture, output, before, fastProvider, slowProvider };
}

// The real subdomains module over the real single-provider cache. Only DoH is
// answered by global fetch; any other non-cache fetch is a fixture defect.
async function subdomainsFixture(terminal) {
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
    // The module's 15s hard-cap timer must not hold the process open.
    if (delay >= 15_000) timer.unref?.();
    return timer;
  };
  try {
    const outputPromise = modules.subdomains.runSubdomainsModule("example.com", {
      ctCache: fixture.cache,
      cache: new Map(),
    });
    fixture.gates.certspotter.resolve(terminal);
    return await outputPromise;
  } finally {
    globalThis.fetch = realFetch;
    Math.random = realRandom;
    globalThis.setTimeout = realSetTimeout;
  }
}

const discoveryComplete = (subdomains) => modules.assetInventory.subdomainDiscoveryComplete({
  subdomains,
  dns_bruteforce: { items: [], error: null },
});

async function assertionBody(id) {
  switch (id) {
    // SUCCESSOR of M1_ONE_SUCCESS_RETAINS_STRUCTURED_DEGRADATION. With one CT
    // provider there is no surviving fallback, so the governed one-provider
    // degradation can no longer occur and `degradations[]` is never emitted. The
    // intent — a CT loss must never read as full coverage — is now expressed by
    // the total-loss contract: CertSpotter failure makes the module incomplete,
    // names the failed source, and declares no degradation.
    case "M1_CT_LOSS_IS_INCOMPLETE_NOT_DEGRADED": {
      const output = await subdomainsFixture(jsonResponse({}, 503));
      return output.incomplete === true
        && output.incomplete_reason === "ct_sources_unavailable"
        && output.ct_error === "CT source failed — certspotter: HTTP 503"
        && output.sources?.certspotter?.error === "HTTP 503"
        && output.count === 0
        && output.error == null
        && output.degradations === undefined;
    }
    // SUCCESSOR of M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE. The live module can
    // no longer lose one of two providers, but a STORED record written while a
    // second, now retired, provider was queried can: the provider-generic reader
    // must keep its meaning (one lost source = partial coverage) without the code
    // naming that provider. Live CertSpotter loss stays incomplete, and a live
    // CertSpotter success is the positive control.
    case "M2_PROVIDER_LOSS_NEVER_DISCOVERY_COMPLETE": {
      const lost = await subdomainsFixture(jsonResponse({}, 503));
      const succeeded = await subdomainsFixture(providerBody.certspotter);
      const storedTwoProviderRecord = {
        count: 2,
        items: ["example.com", "spot.example.com"],
        sensitive: [],
        sources: {
          retired_provider: { count: 0, error: "HTTP 503" },
          certspotter: { count: 2, error: null },
        },
        error: null,
      };
      return discoveryComplete(lost) === false
        && discoveryComplete(storedTwoProviderRecord) === false
        && discoveryComplete(succeeded) === true;
    }
    // SUCCESSOR of M3_SCAN_QUALITY_IS_GOVERNED_DEGRADED. The governed `degraded`
    // grade needed a surviving provider; with CertSpotter alone a CT loss is a
    // total loss, which FD-006 has always kept `partial`. The positive control
    // proves a CertSpotter success leaves the scan complete.
    case "M3_CT_LOSS_SCAN_QUALITY_IS_PARTIAL": {
      const lost = await subdomainsFixture(jsonResponse({}, 503));
      const succeeded = await subdomainsFixture(providerBody.certspotter);
      const lostQuality = modules.scanEngine.buildScanQuality({ subdomains: lost }, SCAN_ANCHOR);
      const keptQuality = modules.scanEngine.buildScanQuality({ subdomains: succeeded }, SCAN_ANCHOR);
      return lostQuality.status === "partial"
        && Array.isArray(lostQuality.degradations)
        && lostQuality.degradations.length === 0
        && lostQuality.modules_incomplete.some((row) =>
          row.module === "subdomains" && row.incomplete_reason === "ct_sources_unavailable")
        && keptQuality.status === "complete";
    }
    case "M4_FIRST_FAILURE_CANNOT_WIN": {
      const fixture = multiProviderFixture();
      const outputPromise = startRace(fixture);
      fixture.gates[PROVIDER_B].resolve(jsonResponse({}, 404));
      const stillPending = await pendingAfter(outputPromise);
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const output = await outputPromise;
      return stillPending && output.release.winner === "certspotter"
        && output.providers[PROVIDER_B].status === "unavailable"
        && output.providers.certspotter.status === "available";
    }
    case "M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL": {
      const result = await fastProviderFixture("certspotter");
      return result.aborts[PROVIDER_B] === 0
        && result.cache.physicalSnapshot("example.com")[PROVIDER_B] === "terminal_success";
    }
    case "M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT": {
      const result = await fastProviderFixture("certspotter");
      return JSON.stringify(result.output) === result.before;
    }
    // Production shape: a CertSpotter failure is unavailable, never an empty
    // successful result.
    case "M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.certspotter.resolve(jsonResponse({}, 503));
      const output = await outputPromise;
      return Object.keys(output.providers).join("|") === "certspotter"
        && Object.values(output.providers).every((provider) =>
          provider.status === "unavailable" && provider.data === null);
    }
    // SUCCESSOR of M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL. SSL now measures the
    // shared-SAN count from the selected issuance's DNS names, so it is no
    // longer null for a CertSpotter selection. The sentinel still stays null
    // until a certificate is actually selected and measured, and CertSpotter
    // never supplies a certificate subject.
    case "M8_SHARED_SAN_NULL_UNTIL_MEASURED": {
      const realDateNow = Date.now;
      Date.now = () => Date.parse(NOW);
      try {
        const unmeasuredFixture = cacheFixture();
        const unmeasuredPromise = modules.ssl.resolveCertificateTransparency("example.com", {
          ctCache: unmeasuredFixture.cache,
        });
        unmeasuredFixture.gates.certspotter.resolve(jsonResponse({}, 503));
        const unmeasured = await unmeasuredPromise;

        const measuredFixture = cacheFixture();
        const measuredPromise = modules.ssl.resolveCertificateTransparency("example.com", {
          ctCache: measuredFixture.cache,
        });
        measuredFixture.gates.certspotter.resolve(sharedSanBody);
        const measured = await measuredPromise;
        return unmeasured.cert_shared_san_count === null
          && unmeasured.cert_not_after === null
          && unmeasured.cert_issuer === null
          && measured.cert_issuer === "spot issuer"
          && measured.cert_subject === null
          && measured.cert_raw_san_count === 3
          && measured.cert_shared_san_count === 1;
      } finally {
        Date.now = realDateNow;
      }
    }
    case "M9_DEGRADATION_WORDING_REMAINS_EXPLICIT": {
      const result = await fastProviderFixture("certspotter");
      return result.output.providers[PROVIDER_B].error
        === "CyberMeters released this module after another Certificate Transparency provider succeeded; this provider result was still in flight and was excluded from the immutable module output.";
    }
    // Production shape: CertSpotter answering with no issuances is a measured
    // success that releases the consumer, never a failure.
    case "M10_SUCCESSFUL_EMPTY_STAYS_MEASURED": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.certspotter.resolve([]);
      const output = await outputPromise;
      await turn();
      return output.release.reason === "first_success"
        && output.release.winner === "certspotter"
        && output.providers.certspotter.status === "available"
        && Array.isArray(output.providers.certspotter.data)
        && output.providers.certspotter.data.length === 0
        && output.providers.certspotter.error === null;
    }
    case "M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED": {
      const fixture = multiProviderFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      fixture.gates[PROVIDER_B].resolve(providerBody[PROVIDER_B]);
      const output = await outputPromise;
      return output.release.included_terminal_providers.join("|") === `certspotter|${PROVIDER_B}`
        && output.providers.certspotter.status === "available"
        && output.providers[PROVIDER_B].status === "available"
        && output.providers.certspotter.data[0].issuer.name === "spot issuer"
        && output.providers[PROVIDER_B].data[0].issuer.name === "provider b issuer";
    }
    // With the only production provider settled there is no sibling to wait
    // for: the requested grace never arms and the success is final at once.
    case "SINGLE_PROVIDER_SUCCESS_IS_FINAL_WITHOUT_GRACE": {
      const fixture = cacheFixture();
      const started = Date.now();
      const outputPromise = startRace(fixture, "subdomains", { siblingGraceMs: 5_000 });
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const output = await outputPromise;
      const waited = Date.now() - started;
      return waited < 1_000
        && output.release.reason === "first_success"
        && output.release.winner === "certspotter"
        && output.release.included_terminal_providers.join("|") === "certspotter"
        && Object.keys(output.providers).join("|") === "certspotter";
    }
    case "SINGLE_PROVIDER_FAILURE_IS_TERMINAL_FAILURE": {
      const fixture = cacheFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.certspotter.resolve(jsonResponse({}, 503));
      const output = await outputPromise;
      return output.release.reason === "all_terminal_failure"
        && output.release.winner === null
        && output.release.included_terminal_providers.join("|") === "certspotter"
        && output.providers.certspotter.status === "unavailable"
        && output.providers.certspotter.error === "HTTP 503";
    }
    case "SUBDOMAINS_CERTSPOTTER_SUCCESS_IS_COMPLETE": {
      const output = await subdomainsFixture(providerBody.certspotter);
      const perProviderKeys = Object.keys(output.discovery_coverage?.per_provider || {});
      return output.incomplete !== true
        && output.degradations === undefined
        && output.ct_error === undefined
        && JSON.stringify(Object.keys(output.sources || {})) === JSON.stringify(["certspotter"])
        && output.sources.certspotter.count === 2
        && output.sources.certspotter.error === null
        && JSON.stringify(output.ct_providers) === JSON.stringify(["certspotter"])
        && JSON.stringify(output.items) === JSON.stringify(["example.com", "spot.example.com"])
        && perProviderKeys.length > 0
        && perProviderKeys.every((key) => key.startsWith("certspotter_"))
        && output.discovery_coverage.coverage_state === "complete"
        && discoveryComplete(output) === true;
    }
    case "SUBDOMAINS_CERTSPOTTER_EMPTY_IS_MEASURED_NOT_LOST": {
      const output = await subdomainsFixture([]);
      return output.count === 0
        && output.incomplete !== true
        && output.ct_error === undefined
        && output.sources?.certspotter?.count === 0
        && output.sources?.certspotter?.error === null
        && discoveryComplete(output) === true;
    }
    case "FAST_CERTSPOTTER_RELEASES_WITHOUT_SIBLING": {
      const result = await fastProviderFixture("certspotter");
      return result.output.release.winner === "certspotter"
        && result.output.providers.certspotter.status === "available";
    }
    // The orchestrator privileges no provider: whichever declared provider
    // succeeds first releases the consumer.
    case "FAST_SIBLING_RELEASES_WITHOUT_CERTSPOTTER": {
      const result = await fastProviderFixture(PROVIDER_B);
      return result.output.release.winner === PROVIDER_B
        && result.output.providers[PROVIDER_B].status === "available";
    }
    case "BOTH_FAILURES_ARE_RETAINED": {
      const fixture = multiProviderFixture();
      const outputPromise = startRace(fixture);
      fixture.gates[PROVIDER_B].resolve(jsonResponse({}, 404));
      fixture.gates.certspotter.resolve(jsonResponse({}, 503));
      const output = await outputPromise;
      return output.release.reason === "all_terminal_failure"
        && output.providers[PROVIDER_B].error === "HTTP 404"
        && output.providers.certspotter.error === "HTTP 503";
    }
    case "RELEASED_OUTPUT_IS_FROZEN": {
      const result = await fastProviderFixture("certspotter");
      return Object.isFrozen(result.output)
        && Object.isFrozen(result.output.providers)
        && Object.isFrozen(result.output.providers.certspotter)
        && Object.isFrozen(result.output.providers[PROVIDER_B])
        && Object.isFrozen(result.output.release)
        && Object.isFrozen(result.output.release.included_terminal_providers);
    }
    case "LATE_SUCCESS_IS_TERMINAL_TELEMETRY": {
      const result = await fastProviderFixture("certspotter");
      const row = result.cache.telemetrySnapshot().find((entry) =>
        entry.provider === PROVIDER_B && entry.module === "subdomains");
      const consumer = result.cache.consumerSnapshot("example.com", "subdomains")
        .providers[PROVIDER_B];
      return row?.outcome === "ok"
        && row?.customer_evidence_disposition === "late_success_excluded_after_first_success"
        && consumer?.terminal_physical_attempt_state === "terminal_success";
    }
    case "LATE_SUCCESS_IS_EXCLUDED_FROM_CUSTOMER_OUTPUT": {
      const result = await fastProviderFixture("certspotter");
      return result.output.providers[PROVIDER_B].status === "unavailable"
        && result.output.providers[PROVIDER_B].error
          === modules.cache.CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING
        && JSON.stringify(result.output) === result.before;
    }
    case "LATE_FAILURE_IS_TERMINAL_TELEMETRY": {
      const fixture = multiProviderFixture();
      const outputPromise = startRace(fixture);
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const output = await outputPromise;
      fixture.gates[PROVIDER_B].resolve(jsonResponse({}, 404));
      await turn();
      await turn();
      const row = fixture.cache.telemetrySnapshot().find((entry) =>
        entry.provider === PROVIDER_B && entry.module === "subdomains");
      const consumer = fixture.cache.consumerSnapshot("example.com", "subdomains")
        .providers[PROVIDER_B];
      return output.providers[PROVIDER_B].status === "unavailable"
        && row?.outcome === "http_error"
        && row?.customer_evidence_disposition === "late_failure_after_first_success"
        && consumer?.terminal_physical_attempt_state === "terminal_failure";
    }
    // Bounded sibling grace: a sibling that finishes inside the window is real
    // evidence and is included; one still in flight when the window ends is
    // excluded exactly as before, so a slow provider still reads as reduced.
    case "GRACE_INCLUDES_SIBLING_THAT_FINISHES_IN_WINDOW": {
      const fixture = multiProviderFixture();
      const outputPromise = startRace(fixture, "subdomains", { siblingGraceMs: 2_000 });
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      const waitingForSibling = await pendingAfter(outputPromise, 4);
      fixture.gates[PROVIDER_B].resolve(providerBody[PROVIDER_B]);
      const output = await outputPromise;
      await turn();
      const row = fixture.cache.telemetrySnapshot().find((entry) =>
        entry.provider === PROVIDER_B && entry.module === "subdomains");
      return waitingForSibling
        && output.release.winner === "certspotter"
        && output.release.included_terminal_providers.join("|") === `certspotter|${PROVIDER_B}`
        && output.providers[PROVIDER_B].status === "available"
        && output.providers[PROVIDER_B].data[0].issuer.name === "provider b issuer"
        && row?.customer_evidence_disposition !== "late_success_excluded_after_first_success";
    }
    case "GRACE_INCLUDES_SIBLING_FAILURE_AS_FAILURE": {
      const fixture = multiProviderFixture();
      const outputPromise = startRace(fixture, "subdomains", { siblingGraceMs: 2_000 });
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      await turn();
      fixture.gates[PROVIDER_B].resolve(jsonResponse({}, 502));
      const output = await outputPromise;
      return output.providers[PROVIDER_B].status === "unavailable"
        && output.providers[PROVIDER_B].error === "HTTP 502"
        && output.providers.certspotter.status === "available";
    }
    case "GRACE_EXPIRY_EXCLUDES_IN_FLIGHT_SIBLING": {
      const fixture = multiProviderFixture();
      const started = Date.now();
      const output = await (async () => {
        const outputPromise = startRace(fixture, "subdomains", { siblingGraceMs: 30 });
        fixture.gates.certspotter.resolve(providerBody.certspotter);
        return outputPromise;
      })();
      const waited = Date.now() - started;
      fixture.gates[PROVIDER_B].resolve(providerBody[PROVIDER_B]);
      await turn();
      return waited >= 25
        && output.providers[PROVIDER_B].status === "unavailable"
        && output.providers[PROVIDER_B].error
          === modules.cache.CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING
        && output.release.included_terminal_providers.join("|") === "certspotter";
    }
    case "GRACE_ABORT_RELEASES_WITHOUT_WAITING": {
      const fixture = multiProviderFixture();
      const controller = new AbortController();
      const started = Date.now();
      const outputPromise = startRace(fixture, "subdomains", {
        siblingGraceMs: 5_000,
        signal: controller.signal,
      });
      fixture.gates.certspotter.resolve(providerBody.certspotter);
      await sleep(10);
      controller.abort(new Error("module deadline"));
      const output = await outputPromise;
      const waited = Date.now() - started;
      fixture.gates[PROVIDER_B].resolve(providerBody[PROVIDER_B]);
      await turn();
      return waited < 1_000
        && output.providers.certspotter.status === "available"
        && output.providers[PROVIDER_B].status === "unavailable";
    }
    // SUCCESSOR of GRACE_NEVER_EXCEEDS_ONE_CRT_SH_ATTEMPT, whose bound (the
    // retired provider's attempt timeout) no longer exists. The remaining
    // invariant is that the grace is bounded: whatever a caller requests, the
    // orchestrator arms at most CT_SIBLING_GRACE_MS.
    case "GRACE_REQUEST_IS_CLAMPED": {
      const ceiling = modules.orchestrator.CT_SIBLING_GRACE_MS;
      const fixture = multiProviderFixture();
      const realSetTimeout = globalThis.setTimeout;
      const delays = [];
      globalThis.setTimeout = (callback, delay, ...args) => {
        delays.push(delay);
        return realSetTimeout(callback, delay, ...args);
      };
      let output;
      try {
        const outputPromise = startRace(fixture, "subdomains", { siblingGraceMs: 10 * 60_000 });
        fixture.gates.certspotter.resolve(providerBody.certspotter);
        await pendingAfter(outputPromise, 4);
        fixture.gates[PROVIDER_B].resolve(providerBody[PROVIDER_B]);
        output = await outputPromise;
      } finally {
        globalThis.setTimeout = realSetTimeout;
      }
      return Number.isFinite(ceiling)
        && ceiling > 0
        && delays.includes(ceiling)
        && delays.every((delay) => delay <= ceiling)
        && output.release.included_terminal_providers.join("|") === `certspotter|${PROVIDER_B}`;
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
