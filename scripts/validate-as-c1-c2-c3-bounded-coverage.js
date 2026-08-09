#!/usr/bin/env node
// AS-C1/C2/C3 U1+U2+U3 — focused bounded-coverage contract.
//
// The ten F* assertions are the founder-approved fail-first fixtures. On the
// exact 757b447 base all ten must fail semantically while the positive controls
// complete normally. The same file is the green oracle for the candidate and
// for the fresh-process semantic mutation registry.

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

function available(data) {
  return { status: "available", data, error: null };
}
async function discoveryFixture(crtRows, certRows) {
  const ctCache = {
    get: async (_domain, provider) => provider === "crt_sh"
      ? available(crtRows)
      : available(certRows),
  };
  return subdomainModule.runSubdomainsModule("example.com", {
    ctCache,
    cache: new Map(),
  });
}
const crtRow = (name) => ({ name_value: name, common_name: name });
const certRow = (name) => ({ dns_names: [name] });

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

  const mergedCrt = hosts(200, "crt").map(crtRow);
  const mergedCert = hosts(172, "spot").map(certRow);
  const merged = await discoveryFixture(mergedCrt, mergedCert);
  check(
    "F3_MERGED_CAP_DENOMINATOR_AND_DROPPED_COUNT",
    merged.discovery_coverage?.merged?.candidate_total === 372 &&
      merged.discovery_coverage?.merged?.kept === 300 &&
      merged.discovery_coverage?.merged?.dropped_count === 72 &&
      merged.discovery_coverage?.merged?.cap_reached === true &&
      merged.discovery_coverage?.merged?.selection_order === "provider_response" &&
      merged.discovery_coverage?.coverage_state === "bounded",
    JSON.stringify(merged.discovery_coverage),
  );

  const rawRows = Array.from({ length: 2_001 }, (_, index) =>
    crtRow(index < 250 ? `raw-${String(index).padStart(4, "0")}.example.com` : "raw-0000.example.com"));
  const providerBounded = await discoveryFixture(rawRows, []);
  check(
    "F4_PER_PROVIDER_CAP_IS_INDEPENDENT",
    providerBounded.discovery_coverage?.per_provider?.crt_sh_unique_total === 250 &&
      providerBounded.discovery_coverage?.per_provider?.crt_sh_unique_kept === 200 &&
      providerBounded.discovery_coverage?.per_provider?.crt_sh_dropped_count === 50 &&
      providerBounded.discovery_coverage?.per_provider?.crt_sh_cap_reached === true &&
      providerBounded.discovery_coverage?.per_provider?.certspotter_cap_reached === false,
    JSON.stringify(providerBounded.discovery_coverage?.per_provider),
  );
  check(
    "F5_RAW_CRT_ROW_CAP_IS_INDEPENDENT",
    providerBounded.discovery_coverage?.crt_sh?.rows_received === 2_001 &&
      providerBounded.discovery_coverage?.crt_sh?.rows_examined === 2_000 &&
      providerBounded.discovery_coverage?.crt_sh?.rows_available === null &&
      providerBounded.discovery_coverage?.crt_sh?.dropped_count === 1 &&
      providerBounded.discovery_coverage?.crt_sh?.row_cap_reached === true,
    JSON.stringify(providerBounded.discovery_coverage?.crt_sh),
  );

  const boundedScope = typeof lifecycleModule.ctDiscoveryScopeSignals === "function"
    ? lifecycleModule.ctDiscoveryScopeSignals(
        { source: "certificate_transparency" },
        { discovery_coverage: { coverage_state: "bounded" } },
      )
    : null;
  check(
    "F6_BOUNDED_CT_SCOPE_FREEZES_LIFECYCLE",
    boundedScope?.dns_resolution?.state === "not_assessed" &&
      boundedScope?.http_https_service?.state === "not_assessed" &&
      boundedScope?.dns_resolution?.reason === "bounded_ct_discovery_scope" &&
      boundedScope?.http_https_service?.reason === "bounded_ct_discovery_scope",
    JSON.stringify(boundedScope),
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
        sources: ["crt_sh"], limitations: [],
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
    "P2_ALL_FOUR_CAPS_RETAINED",
    /slice\(0, 50\)/.test(assetSource) &&
      /slice\(0, 2_000\)/.test(subdomainSource) &&
      /const PER_CAP\s*=\s*200/.test(subdomainSource) &&
      /const MERGE_CAP\s*=\s*300/.test(subdomainSource),
  );
  check(
    "P3_MERGED_SELECTION_ORDER_REMAINS_SLICE_THEN_SORT",
    subdomainSource.includes("const items     = [...seen].slice(0, MERGE_CAP).sort();"),
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
    "P5_C2_MECHANISMS_REMAIN_SEPARATE",
    providerBounded.discovery_coverage?.crt_sh &&
      providerBounded.discovery_coverage?.per_provider &&
      providerBounded.discovery_coverage?.merged &&
      !Object.prototype.hasOwnProperty.call(providerBounded.discovery_coverage, "truncated"),
    JSON.stringify(providerBounded.discovery_coverage),
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
    "P7_RAW_ROWS_AVAILABLE_DENOMINATOR_IS_NEVER_FABRICATED",
    providerBounded.discovery_coverage?.crt_sh?.rows_available === null,
  );
} finally {
  globalThis.fetch = originalFetch;
  globalThis.setTimeout = originalSetTimeout;
}

console.log(`\nAS-C1/C2/C3 bounded coverage: ${passed}/${passed + failed} passed, ${failed} failed`);
console.log(`AS_C123_FAILURE_IDS ${JSON.stringify(failureIds)}`);
if (failed) process.exit(1);
console.log("AS-C1/C2/C3 bounded coverage validation passed");
