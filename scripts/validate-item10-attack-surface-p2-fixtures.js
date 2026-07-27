#!/usr/bin/env node
// Item 10 P2 production fixtures: complete, degraded, provider timeout, deadline.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(
  root, "workers/scan-api/src/engines", name,
)).href;
const {
  deriveAttackSurfaceSignalCompleteness,
  deriveRemovalObservation,
} = await import(engine("attack-surface-signal-completeness.js"));
const { unavailableRemovalObservations } = await import(engine("asset-intel.js"));
const { runCveModule } = await import(engine("vuln-intel.js"));
const {
  SCAN_DEADLINE_DEFAULTS,
  SCAN_MODULE_BUDGETS,
} = await import(engine("scan-budget.js"));

let passed = 0;
let failed = 0;
const eq = (name, actual, expected) => {
  if (actual === expected) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name} — got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
};

const complete = deriveAttackSurfaceSignalCompleteness({
  subdomains: {
    items: [],
    sources: {
      crt_sh: { count: 0, error: null },
      certspotter: { count: 0, error: null },
    },
  },
  dns_bruteforce: { checked: 23, items: [] },
  dns: { resolution_assessed: true, resolves_any: false },
  asset_exposure: {
    checked: 1,
    reachable: 0,
    assets: [{ host: "gone.example.com", reachable: false }],
  },
  technology_detection: { status_code: 200, technologies: [], info_findings: [] },
  admin_surface_detection: { evidence_status: "assessed_healthy", services: [] },
  subdomain_takeover: {
    checked: 1, potential_risks: 0, risks: [], lookup_failed_hosts: [], unconfirmed: [],
  },
  cve_intelligence: { technologies_checked: [], lookup_statuses: {}, total_cves: 0 },
  known_exploited_vulnerabilities: {
    checked: 1, matched: 0, matches: [], catalogue_source: "origin",
  },
  cloud_storage_discovery: { checked: 1, total: 0, candidates: [], findings: [] },
});
eq("complete fixture records authoritative DNS absence",
  complete.signals.dns_resolution.state, "absent");
eq("complete fixture records HTTP not_observed",
  complete.signals.http_https_service.state, "not_observed");
eq("complete fixture never collapses to a healthy aggregate",
  Object.hasOwn(complete, "healthy"), false);

const degraded = deriveAttackSurfaceSignalCompleteness({
  subdomains: {
    items: ["app.example.com"],
    sources: {
      crt_sh: { count: 1, error: null },
      certspotter: { count: 0, error: "provider timeout" },
    },
    incomplete: true,
    incomplete_reason: "ct_source_degraded",
  },
  dns: {
    resolution_assessed: true,
    resolves_any: true,
    a_records: [{ value: "93.184.216.34" }],
  },
  asset_exposure: {
    checked: 2,
    reachable: 1,
    assets: [
      { host: "app.example.com", reachable: true, status: 200 },
      { host: "slow.example.com", reachable: null, probe_status: "timed_out" },
    ],
    incomplete: true,
    incomplete_reason: "probe_timeout",
  },
  technology_detection: { error: "provider timeout" },
});
eq("degraded fixture retains reliable discovery sibling",
  degraded.signals.subdomain_discovery.state, "observed");
eq("degraded fixture retains reliable DNS sibling",
  degraded.signals.dns_resolution.state, "observed");
eq("degraded fixture marks failed technology independently",
  degraded.signals.technology.state, "unavailable");

const originalFetch = globalThis.fetch;
try {
  globalThis.fetch = async () => new Response(JSON.stringify({ vulnerabilities: [] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
  const zero = await runCveModule({ technologies: ["nginx"] });
  eq("valid provider zero records complete lookup",
    zero.lookup_statuses.nginx.status, "complete");

  globalThis.fetch = async () => {
    throw new DOMException("provider timeout", "TimeoutError");
  };
  const timedOut = await runCveModule({ technologies: ["nginx"] });
  eq("provider-timeout fixture records unavailable lookup",
    timedOut.lookup_statuses.nginx.status, "unavailable");
  eq("provider-timeout fixture resolves CVE signal unavailable",
    deriveAttackSurfaceSignalCompleteness({
      technology_detection: {
        status_code: 200,
        technologies: ["nginx"],
      },
      cve_intelligence: timedOut,
    }).signals.cve.state,
    "unavailable");
} finally {
  globalThis.fetch = originalFetch;
}

const deadlineEvidence = unavailableRemovalObservations(
  ["gone.example.com"],
  "asset_exposure_deadline",
)[0];
eq("deadline fixture is observation_unavailable",
  deriveRemovalObservation(deadlineEvidence.signal_states),
  "observation_unavailable");
eq("whole-scan executable deadline remains 19,000ms",
  SCAN_DEADLINE_DEFAULTS.budgetMs, 19_000);
eq("whole-scan configurable ceiling remains 19,000ms",
  SCAN_DEADLINE_DEFAULTS.maxBudgetMs, 19_000);
eq("asset exposure module cap remains 2,500ms",
  SCAN_MODULE_BUDGETS.asset_exposure, 2_500);
eq("CT/subdomain module cap remains 12,000ms",
  SCAN_MODULE_BUDGETS.subdomains, 12_000);

console.log(`\nItem 10 P2 fixtures: ${passed}/${passed + failed} assertions passed`);
if (failed) process.exit(1);
console.log("Item 10 P2 fixture validation passed");
