#!/usr/bin/env node
// AS-C1/C2/C3 U1+U2+U3 — focused bounded-coverage contract.
//
// The F* assertions began as the founder-approved fail-first fixtures (on the
// exact 757b447 base all of them failed semantically while the positive
// controls completed normally). Subdomain discovery is CyberMeters' own
// observation (word list, SRV targets, home-page links), so its coverage is
// always bounded and never claims a complete inventory. The same file is the
// green oracle for the candidate and for the fresh-process semantic mutation
// registry.

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (file) => path.join(root, "workers", "scan-api", "src", "engines", file);
const engineUrl = (file) => pathToFileURL(enginePath(file)).href;
const moduleUrl = (envName, file) => process.env[envName] || engineUrl(file);

const assetModule = await import(moduleUrl("AS_C123_ASSET_MODULE_URL", "asset-intel.js"));
const subdomainModule = await import(moduleUrl("AS_C123_SUBDOMAIN_MODULE_URL", "subdomains-scan.js"));
const signalModule = await import(moduleUrl("AS_C123_SIGNAL_MODULE_URL", "attack-surface-signal-completeness.js"));
const lifecycleModule = await import(moduleUrl("AS_C123_LIFECYCLE_MODULE_URL", "attack-surface-lifecycle.js"));
const presentationModule = await import(moduleUrl("AS_C123_PRESENTATION_MODULE_URL", "attack-surface-customer-presentation.js"));
const scanEngineModule = await import(moduleUrl("AS_C123_SCAN_ENGINE_MODULE_URL", "scan-engine.js"));
const coverageModule = await import(moduleUrl("AS_C123_COVERAGE_MODULE_URL", "bounded-coverage.js"))
  .catch(() => ({}));

if (process.env.AS_C123_EMIT_MODULE_PROOF === "1") {
  const proof = {};
  for (const [name, file] of Object.entries({
    asset: "asset-intel.js",
    subdomains: "subdomains-scan.js",
    signal: "attack-surface-signal-completeness.js",
    lifecycle: "attack-surface-lifecycle.js",
    presentation: "attack-surface-customer-presentation.js",
    coverage: "bounded-coverage.js",
  })) {
    const resolved = fs.realpathSync(enginePath(file));
    proof[name] = {
      path: resolved,
      sha256: crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"),
    };
  }
  console.log(`AS_C123_MODULE_PROOF ${JSON.stringify(proof)}`);
}

let passed = 0;
let failed = 0;
const failureIds = [];
const seen = new Set();
function check(id, condition, detail = "") {
  if (seen.has(id)) throw new Error(`duplicate contract id: ${id}`);
  seen.add(id);
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    failureIds.push(id);
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function equal(id, actual, expected) {
  check(id, Object.is(actual, expected),
    `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

const originalFetch = globalThis.fetch;
const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (callback, delay, ...args) => {
  const timer = originalSetTimeout(callback, delay, ...args);
  timer?.unref?.();
  return timer;
};
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "cloudflare-dns.com") {
    return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
      status: 200,
      headers: { "content-type": "application/dns-json" },
    });
  }
  throw new TypeError(`fixture connection refused: ${url.hostname}`);
};

const refusedFetcher = async (input) => {
  throw new TypeError(`fixture connection refused: ${String(input)}`);
};
const hosts = (count, prefix = "host") => Array.from(
  { length: count },
  (_, index) => `${prefix}-${String(index).padStart(4, "0")}.example.com`,
);

async function exposureFixture(candidateCount, recheckCount = 0) {
  const candidates = hosts(candidateCount);
  const recheckHosts = candidates.slice(0, recheckCount);
  const exposure = await assetModule.runExposureModule("example.com", candidates, {
    fetcher: refusedFetcher,
    recheckHosts,
  });
  const admin = assetModule.runAdminSurfaceModule({ asset_exposure: exposure });
  const completeness = signalModule.deriveAttackSurfaceSignalCompleteness({
    asset_exposure: exposure,
    admin_surface_detection: admin,
  });
  return {
    candidates,
    exposure,
    admin,
    signal: completeness.signals.exposure_admin_surface,
  };
}

function discoverySignal(modules) {
  return signalModule.deriveAttackSurfaceSignalCompleteness(modules).signals.subdomain_discovery;
}
const wordlistComplete = (items = []) => ({ checked: 56, items, srv_items: [] });

try {
  const boundedExposure = await exposureFixture(300, 50);
  check(
    "F1_BOUNDED_EXPOSURE_NEVER_CLAIMS_COMPLETE_NO_SIGNAL",
    boundedExposure.signal.reason === "bounded_exposure_admin_probe_no_signal" &&
      boundedExposure.signal.reason !== "complete_exposure_admin_probe_no_signal",
    JSON.stringify(boundedExposure.signal),
  );
  check(
    "F2_EXPOSURE_DENOMINATOR_AND_DROPPED_COUNT",
    boundedExposure.exposure.probe_coverage?.candidate_total === 300 &&
      boundedExposure.exposure.probe_coverage?.checked === 50 &&
      boundedExposure.exposure.probe_coverage?.dropped_count === 250 &&
      boundedExposure.exposure.probe_coverage?.cap_reached === true &&
      boundedExposure.exposure.probe_coverage?.coverage_state === "bounded",
    JSON.stringify(boundedExposure.exposure.probe_coverage),
  );

  // Own discovery checks a bounded word list plus the names the domain's own
  // records and home page reference. It can never prove an inventory complete.
  const discovered = await subdomainModule.runSubdomainsModule("example.com", { cache: new Map() });
  const found = discoverySignal({
    subdomains: { ...discovered, count: 2, items: ["app.example.com", "mail.example.com"] },
    dns_bruteforce: wordlistComplete([{ hostname: "app.example.com" }]),
    technology_detection: { technologies: [] },
  });
  check(
    "F3_OWN_DISCOVERY_COVERAGE_IS_BOUNDED_AND_DECLARED",
    found.reason === "hostname_observed" &&
      found.coverage_state === "bounded" &&
      found.coverage?.basis === "own_observation" &&
      found.coverage?.wordlist_checked === 56,
    JSON.stringify(found),
  );

  const nothingFound = discoverySignal({
    subdomains: discovered,
    dns_bruteforce: wordlistComplete(),
    technology_detection: { technologies: [] },
  });
  check(
    "F4_OWN_DISCOVERY_WITHOUT_HOSTNAME_NEVER_CLAIMS_COMPLETE",
    nothingFound.state === "not_observed" &&
      nothingFound.reason === "bounded_discovery_no_hostname" &&
      nothingFound.coverage_state === "bounded",
    JSON.stringify(nothingFound),
  );

  // Without the wildcard check, word-list answers cannot be told apart from a
  // wildcard, so an empty result is incomplete rather than "nothing found".
  const wildcardUnknown = discoverySignal({
    subdomains: { ...discovered, incomplete: true, incomplete_reason: "wildcard_check_failed" },
    dns_bruteforce: wordlistComplete(),
    technology_detection: { technologies: [] },
  });
  check(
    "F6_WILDCARD_CHECK_FAILURE_IS_INCOMPLETE_NOT_NO_HOSTNAME",
    wildcardUnknown.state === "incomplete" &&
      wildcardUnknown.reason === "discovery_sources_incomplete" &&
      wildcardUnknown.limitations?.includes("wildcard_check_failed"),
    JSON.stringify(wildcardUnknown),
  );

  check(
    "F7_RECHECK_SATURATION_IS_OBSERVABLE_ONLY",
    boundedExposure.exposure.probe_coverage?.recheck_slots_used === 50 &&
      boundedExposure.exposure.probe_coverage?.new_candidate_slots_available === 0 &&
      boundedExposure.exposure.probe_coverage?.saturated === true &&
      boundedExposure.exposure.checked === 50,
    JSON.stringify(boundedExposure.exposure.probe_coverage),
  );

  const historicalModel = {
    model_version: "attack-surface-signal-completeness-v1",
    signals: {
      subdomain_discovery: {
        state: "observed", reason: "hostname_observed", evidence_count: 1,
        sources: ["dns_bruteforce"], limitations: [],
      },
      exposure_admin_surface: {
        state: "not_observed", reason: "complete_exposure_admin_probe_no_signal",
        evidence_count: 0, sources: ["http_probe"], limitations: [],
      },
    },
  };
  const historical = presentationModule.buildAttackSurfaceCustomerPresentation({
    signalCompleteness: historicalModel,
  });
  const historicalExposure = historical.signals.exposure_admin_surface;
  check(
    "F8_HISTORICAL_ABSENCE_PROJECTS_NOT_RECORDED",
    historicalExposure.coverage_state === "not_recorded" &&
      /coverage (?:was )?not recorded/i.test(historicalExposure.customer_message) &&
      !/coverage (?:was )?complete/i.test(historicalExposure.customer_message),
    JSON.stringify(historicalExposure),
  );

  const boundedQuality = scanEngineModule.buildScanQuality({
    asset_exposure: boundedExposure.exposure,
  });
  const legacyQuality = scanEngineModule.buildScanQuality({
    asset_exposure: {
      ...boundedExposure.exposure,
      probe_coverage: undefined,
    },
  });
  check(
    "F9_BOUNDED_COVERAGE_DOES_NOT_PROPAGATE_TO_SCAN_QUALITY",
    boundedExposure.exposure.probe_coverage?.coverage_state === "bounded" &&
      boundedExposure.exposure.incomplete !== true &&
      boundedQuality.status === legacyQuality.status &&
      boundedQuality.status === "complete" &&
      JSON.stringify(boundedQuality) === JSON.stringify(legacyQuality),
    JSON.stringify({ boundedQuality, legacyQuality, probe_coverage: boundedExposure.exposure.probe_coverage }),
  );

  const completeExposure = await exposureFixture(49, 10);
  check(
    "F10_UNBOUNDED_EXECUTION_IS_COMPLETE_NOT_ALWAYS_BOUNDED",
    completeExposure.exposure.probe_coverage?.coverage_state === "complete" &&
      completeExposure.exposure.probe_coverage?.candidate_total === 49 &&
      completeExposure.exposure.probe_coverage?.checked === 49 &&
      completeExposure.exposure.probe_coverage?.dropped_count === 0 &&
      completeExposure.exposure.probe_coverage?.cap_reached === false &&
      completeExposure.exposure.probe_coverage?.saturated === false,
    JSON.stringify(completeExposure.exposure.probe_coverage),
  );

  check(
    "P1_COVERAGE_VOCABULARY_IS_EXACT_AND_CLOSED",
    JSON.stringify(coverageModule.BOUNDED_COVERAGE_STATES) ===
      JSON.stringify(["bounded", "complete", "not_recorded"]),
    JSON.stringify(coverageModule.BOUNDED_COVERAGE_STATES),
  );
  const subdomainSource = fs.readFileSync(enginePath("subdomains-scan.js"), "utf8");
  const assetSource = fs.readFileSync(enginePath("asset-intel.js"), "utf8");
  const lifecycleSource = fs.readFileSync(enginePath("attack-surface-lifecycle.js"), "utf8");
  check(
    "P2_ALL_CAPS_RETAINED",
    /slice\(0, 50\)/.test(assetSource) &&
      /export const BRUTEFORCE_MAX_NAMES\s*=\s*40;/.test(subdomainSource) &&
      subdomainModule.BRUTE_FORCE_WORDLIST.length === subdomainModule.BRUTEFORCE_MAX_NAMES,
  );
  const referenced = subdomainModule.withReferencedHostnames(["app.example.com"], {
    srvItems: [{ hostname: "sip.example.com" }],
    linkedHostnames: ["shop.example.com", "app.example.com"],
  });
  check(
    "P3_REFERENCED_HOSTS_APPEND_AFTER_WORDLIST_WITHOUT_DUPLICATES",
    JSON.stringify(referenced) ===
      JSON.stringify(["app.example.com", "sip.example.com", "shop.example.com"]),
    JSON.stringify(referenced),
  );
  check(
    "P4_KNOWN_ASSET_SAFEGUARD_REMAINS_EXACT",
    (lifecycleSource.match(/asset_not_in_active_recheck_envelope/g) || []).length === 2 &&
      typeof lifecycleModule.notAssessedSignals === "function" &&
      lifecycleModule.notAssessedSignals().dns_resolution?.reason ===
        "asset_not_in_active_recheck_envelope" &&
      lifecycleModule.notAssessedSignals().http_https_service?.reason ===
        "asset_not_in_active_recheck_envelope",
  );
  check(
    "P5_DISCOVERY_COVERAGE_SHAPE_IS_EXACT",
    JSON.stringify(Object.keys(found.coverage || {})) ===
      JSON.stringify(["coverage_state", "basis", "wordlist_checked"]),
    JSON.stringify(found.coverage),
  );
  check(
    "P6_BOUNDED_SIGNAL_EXPOSES_ADDITIVE_CUSTOMER_COPY",
    boundedExposure.signal.coverage_state === "bounded" &&
      boundedExposure.signal.coverage?.candidate_total === 300 &&
      presentationModule.buildAttackSurfaceCustomerPresentation({
        signalCompleteness: {
          model_version: signalModule.ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
          signals: { exposure_admin_surface: boundedExposure.signal },
        },
      }).signals.exposure_admin_surface.customer_message ===
        "Exposure / admin surface was not observed in the retained probe set. Checked 50 of 300 discovered hosts. Hosts beyond this limit were not assessed; no conclusion is drawn about them.",
  );
  check(
    "P7_DISCOVERY_SOURCES_ARE_OWN_OBSERVATION",
    discovered.source === "dns_discovery" &&
      discovered.incomplete !== true &&
      !Object.prototype.hasOwnProperty.call(discovered, "sources") &&
      !Object.prototype.hasOwnProperty.call(discovered, "discovery_coverage") &&
      JSON.stringify(found.sources) === JSON.stringify(["dns_bruteforce", "dns_srv", "html_link"]),
    JSON.stringify({ discovered, sources: found.sources }),
  );

  // Discovery's fixed DNS-question budget is stated to the customer: how many
  // questions the scan asked, and whether it ran out before every candidate.
  const budgetModules = (reached) => ({
    dns_bruteforce: wordlistComplete([{ hostname: "www.example.com" }]),
    subdomains: {
      items: ["www.example.com"],
      discovery_budget: {
        version: "discovery-question-budget-v1", total: 786, spent: reached ? 786 : 412,
        remaining: reached ? 0 : 374, by_source: {}, refused: reached ? { discovery_depth: 12 } : {},
      },
    },
  });
  const presentDiscovery = (modules) => presentationModule.buildAttackSurfaceCustomerPresentation({
    signalCompleteness: signalModule.deriveAttackSurfaceSignalCompleteness(modules),
  }).signals.subdomain_discovery;
  const asked = presentDiscovery(budgetModules(false));
  const ranOut = presentDiscovery(budgetModules(true));
  const noBudget = presentDiscovery({ dns_bruteforce: wordlistComplete([{ hostname: "www.example.com" }]), subdomains: { items: ["www.example.com"] } });
  check(
    "F_DISCOVERY_QUESTION_BUDGET_IS_STATED",
    asked.coverage?.question_budget?.spent === 412 && asked.coverage?.question_budget?.reached === false &&
      / This scan asked 412 of its 786 DNS questions\. /.test(asked.customer_message) && !/ran out/.test(asked.customer_message) &&
      ranOut.coverage?.question_budget?.reached === true &&
      /asked 786 of its 786 DNS questions and ran out before every candidate name was tried\./.test(ranOut.customer_message) &&
      !/DNS questions/.test(noBudget.customer_message) && noBudget.coverage?.question_budget === undefined,
    JSON.stringify({ asked: asked.customer_message, ranOut: ranOut.customer_message, noBudget: noBudget.customer_message }),
  );
} finally {
  globalThis.fetch = originalFetch;
  globalThis.setTimeout = originalSetTimeout;
}

console.log(`\nAS-C1/C2/C3 bounded coverage: ${passed}/${passed + failed} passed, ${failed} failed`);
console.log(`AS_C123_FAILURE_IDS ${JSON.stringify(failureIds)}`);
if (failed) process.exit(1);
console.log("AS-C1/C2/C3 bounded coverage validation passed");
