#!/usr/bin/env node
//
// Item 10 P1: deterministic proof for the pure nine-signal completeness model
// and the mutation-pinned confirmed-removal product policy.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const modelPath = path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "attack-surface-signal-completeness.js"
);
const mutation =
  process.argv.find((argument) => argument.startsWith("--mutation="))
    ?.split("=")[1] ?? null;

function mutateSource(source) {
  const mutations = {
    "collapse-siblings": [
      "signals.kev = resolveKev(modules, signals.technology);",
      "signals.kev = signals.cve;",
    ],
    "unavailable-as-absent": [
      'return signal("unavailable", "authoritative_dns_evidence_unavailable"',
      'return signal("absent", "authoritative_dns_evidence_unavailable"',
    ],
    "cve-zero-is-clean": [
      'return signal("incomplete", "cve_provider_outcome_not_recorded"',
      'return signal("not_observed", "cve_provider_outcome_not_recorded"',
    ],
    "one-scan-removes": [
      "required_qualifying_observations: 3,",
      "required_qualifying_observations: 1,",
    ],
    "drop-spacing": [
      "minimum_observation_spacing_ms: 24 * 60 * 60 * 1000,",
      "minimum_observation_spacing_ms: 0,",
    ],
    "drop-window": [
      "minimum_confirmation_window_ms: 48 * 60 * 60 * 1000,",
      "minimum_confirmation_window_ms: 0,",
    ],
    "either-source-removes": [
      'dnsState === "absent" && COMPLETE_NEGATIVE_STATES.has(httpState)',
      'dnsState === "absent" || COMPLETE_NEGATIVE_STATES.has(httpState)',
    ],
    "ct-advances-removal": [
      '  "http_https_service",\n]);',
      '  "http_https_service",\n  "certificate_transparency",\n]);',
    ],
    "unavailable-advances": [
      'if (observationState !== "not_observed") return base;',
      'if (false) return base;',
    ],
    "observed-keeps-counter": [
      "qualifying_observations: [],",
      "qualifying_observations: previousRows,",
    ],
  };
  const pair = mutations[mutation];
  if (!pair) throw new Error(`unknown mutation: ${mutation}`);
  const [from, to] = pair;
  if (!source.includes(from)) throw new Error(`mutation anchor missing: ${mutation}`);
  return source.replace(from, to);
}

async function loadModel() {
  if (!mutation) return import(pathToFileURL(modelPath).href);
  const source = mutateSource(fs.readFileSync(modelPath, "utf8"));
  return import(
    `data:text/javascript;base64,${Buffer.from(source).toString("base64")}#${mutation}`
  );
}

const {
  ATTACK_SURFACE_SIGNAL_KEYS,
  ATTACK_SURFACE_SIGNAL_STATES,
  ASSET_REMOVAL_CONFIRMATION_POLICY,
  applyAssetRemovalConfirmation,
  deriveAttackSurfaceSignalCompleteness,
  deriveRemovalObservation,
} = await loadModel();

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

eq("exactly nine independent signals", ATTACK_SURFACE_SIGNAL_KEYS.length, 9);
eq("exactly six non-overlapping states", ATTACK_SURFACE_SIGNAL_STATES.length, 6);
eq("state vocabulary is unique", new Set(ATTACK_SURFACE_SIGNAL_STATES).size, 6);

const mixed = deriveAttackSurfaceSignalCompleteness({
  subdomains: {
    items: ["app.example.com"],
    sources: {
      crt_sh: { count: 1, error: null },
      certspotter: { count: 0, error: "provider unavailable" },
    },
    incomplete: true,
    incomplete_reason: "ct_source_degraded",
  },
  dns_bruteforce: { checked: 23, items: [], error: null },
  dns: {
    resolution_assessed: true,
    resolves_any: true,
    a_records: [{ value: "203.0.113.10" }],
    aaaa_records: [],
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
  technology_detection: { error: "fetch failed" },
  admin_surface_detection: {
    evidence_status: "unavailable",
    services: [],
  },
  subdomain_takeover: {
    checked: 2,
    potential_risks: 0,
    risks: [],
    lookup_failed_hosts: [],
    unconfirmed: [],
  },
  cve_intelligence: {
    technologies_checked: [],
    results: {},
    total_cves: 0,
  },
  known_exploited_vulnerabilities: {
    checked: 1000,
    matched: 1,
    matches: [{ cve_id: "CVE-2026-0001" }],
    catalogue_source: "r2_cache",
  },
  cloud_storage_discovery: {
    checked: 2,
    total: 0,
    candidates: [],
    findings: [],
  },
});

eq("positive degraded discovery remains observed",
  mixed.signals.subdomain_discovery.state, "observed");
eq("DNS sibling remains observed", mixed.signals.dns_resolution.state, "observed");
eq("HTTP sibling remains observed despite partial host coverage",
  mixed.signals.http_https_service.state, "observed");
eq("technology failure is unavailable", mixed.signals.technology.state, "unavailable");
eq("exposure positive remains observed despite technology failure",
  mixed.signals.exposure_admin_surface.state, "observed");
eq("completed takeover zero is not_observed",
  mixed.signals.takeover_candidate.state, "not_observed");
eq("CVE depends on unavailable technology", mixed.signals.cve.state, "incomplete");
eq("positive KEV remains observed despite technology failure",
  mixed.signals.kev.state, "observed");
eq("cloud negative with incomplete source evidence is incomplete",
  mixed.signals.cloud_storage.state, "incomplete");

const dnsAbsent = deriveAttackSurfaceSignalCompleteness({
  dns: { resolution_assessed: true, resolves_any: false, resolves: false },
}).signals.dns_resolution;
eq("authoritative DNS negative is absent", dnsAbsent.state, "absent");

const dnsOutage = deriveAttackSurfaceSignalCompleteness({
  dns: {
    resolution_assessed: false,
    resolves_any: false,
    incomplete: true,
    incomplete_reason: "dns_resolution_unavailable",
  },
}).signals.dns_resolution;
eq("resolver outage is unavailable, never absent", dnsOutage.state, "unavailable");
eq("legacy positive DNS evidence remains observed",
  deriveAttackSurfaceSignalCompleteness({
    dns: { resolves: true, a_records: [{ value: "203.0.113.11" }] },
  }).signals.dns_resolution.state, "observed");
eq("legacy DNS zero without the authoritative contract is incomplete",
  deriveAttackSurfaceSignalCompleteness({
    dns: { resolves: false, a_records: [], aaaa_records: [] },
  }).signals.dns_resolution.state, "incomplete");

const cleanNegative = deriveAttackSurfaceSignalCompleteness({
  subdomains: {
    items: [],
    sources: {
      crt_sh: { count: 0, error: null },
      certspotter: { count: 0, error: null },
    },
  },
  dns_bruteforce: { checked: 23, items: [], error: null },
  asset_exposure: {
    checked: 1,
    reachable: 0,
    assets: [{ host: "mail.example.com", reachable: false }],
  },
  technology_detection: {
    status_code: 200,
    technologies: [],
    info_findings: [],
  },
  admin_surface_detection: { evidence_status: "assessed_healthy", services: [] },
  subdomain_takeover: {
    checked: 1,
    potential_risks: 0,
    risks: [],
    lookup_failed_hosts: [],
    unconfirmed: [],
  },
  cve_intelligence: {
    technologies_checked: [],
    results: {},
    total_cves: 0,
  },
  known_exploited_vulnerabilities: {
    checked: 1000,
    matched: 0,
    matches: [],
    catalogue_source: "origin",
  },
  cloud_storage_discovery: {
    checked: 1,
    total: 0,
    candidates: [],
    findings: [],
  },
});
for (const key of [
  "subdomain_discovery",
  "http_https_service",
  "technology",
  "exposure_admin_surface",
  "takeover_candidate",
  "cve",
  "kev",
  "cloud_storage",
]) {
  eq(`${key}: completed zero is not_observed`,
    cleanNegative.signals[key].state, "not_observed");
}

const missingCompletionMarkers = deriveAttackSurfaceSignalCompleteness({
  technology_detection: {},
  subdomain_takeover: {},
  cve_intelligence: {},
  known_exploited_vulnerabilities: {},
  cloud_storage_discovery: {},
});
for (const key of ["technology", "takeover_candidate", "cve", "kev", "cloud_storage"]) {
  eq(`${key}: missing completion markers fail incomplete`,
    missingCompletionMarkers.signals[key].state, "incomplete");
}

const ambiguousCve = deriveAttackSurfaceSignalCompleteness({
  technology_detection: { technologies: ["nginx"] },
  cve_intelligence: {
    technologies_checked: ["nginx"],
    results: {},
    total_cves: 0,
  },
}).signals.cve;
eq("current queried CVE zero remains incomplete until provider outcomes exist",
  ambiguousCve.state, "incomplete");

const provenCveZero = deriveAttackSurfaceSignalCompleteness({
  technology_detection: { technologies: ["nginx"] },
  cve_intelligence: {
    technologies_checked: ["nginx"],
    lookup_statuses: { nginx: { status: "complete" } },
    results: {},
    total_cves: 0,
  },
}).signals.cve;
eq("proven provider-complete CVE zero is not_observed",
  provenCveZero.state, "not_observed");

eq("removal requires three observations",
  ASSET_REMOVAL_CONFIRMATION_POLICY.required_qualifying_observations, 3);
eq("removal requires 24h spacing",
  ASSET_REMOVAL_CONFIRMATION_POLICY.minimum_observation_spacing_ms,
  24 * 60 * 60 * 1000);
eq("removal requires a 48h window",
  ASSET_REMOVAL_CONFIRMATION_POLICY.minimum_confirmation_window_ms,
  48 * 60 * 60 * 1000);
ok("CT is excluded from active removal sources",
  !ASSET_REMOVAL_CONFIRMATION_POLICY.relevant_active_sources
    .includes("certificate_transparency"));
eq("both complete active negatives produce not_observed",
  deriveRemovalObservation({
    dns_resolution: "absent",
    http_https_service: "not_observed",
  }), "not_observed");
eq("DNS not_observed is not positive absence and cannot advance removal",
  deriveRemovalObservation({
    dns_resolution: "not_observed",
    http_https_service: "not_observed",
  }), "observation_incomplete");
eq("one unavailable active source blocks the threshold",
  deriveRemovalObservation({
    dns_resolution: "absent",
    http_https_service: "unavailable",
  }), "observation_unavailable");
eq("one complete negative cannot substitute for the second source contract",
  deriveRemovalObservation({
    dns_resolution: "absent",
    http_https_service: "legacy_unknown",
  }), "observation_incomplete");
eq("one positive active source proves observed",
  deriveRemovalObservation({
    dns_resolution: "observed",
    http_https_service: "unavailable",
  }), "observed");

const negativeStates = {
  dns_resolution: "absent",
  http_https_service: "not_observed",
};
let lifecycle = applyAssetRemovalConfirmation({}, {
  scan_id: "scan-1",
  observed_at: "2026-07-01T00:00:00.000Z",
  signal_states: negativeStates,
});
eq("one complete negative is only not_observed",
  lifecycle.lifecycle_state, "not_observed");
eq("one complete negative advances once",
  lifecycle.qualifying_observations.length, 1);

lifecycle = applyAssetRemovalConfirmation(lifecycle, {
  scan_id: "scan-too-soon",
  observed_at: "2026-07-01T12:00:00.000Z",
  signal_states: negativeStates,
});
eq("a scan inside 24h cannot advance",
  lifecycle.qualifying_observations.length, 1);

lifecycle = applyAssetRemovalConfirmation(lifecycle, {
  scan_id: "scan-unavailable",
  observed_at: "2026-07-02T00:00:00.000Z",
  signal_states: {
    dns_resolution: "absent",
    http_https_service: "unavailable",
  },
});
eq("unavailable scan does not advance",
  lifecycle.qualifying_observations.length, 1);
eq("unavailable scan does not reset durable lifecycle",
  lifecycle.lifecycle_state, "not_observed");

lifecycle = applyAssetRemovalConfirmation(lifecycle, {
  scan_id: "scan-2",
  observed_at: "2026-07-02T00:00:01.000Z",
  signal_states: negativeStates,
});
eq("second qualifying observation remains not_observed",
  lifecycle.lifecycle_state, "not_observed");
eq("second qualifying observation advances to two",
  lifecycle.qualifying_observations.length, 2);

lifecycle = applyAssetRemovalConfirmation(lifecycle, {
  scan_id: "scan-3",
  observed_at: "2026-07-03T00:00:02.000Z",
  signal_states: negativeStates,
});
eq("third spaced complete observation confirms removal",
  lifecycle.lifecycle_state, "confirmed_removed");
eq("confirmed removal is time-stamped from evidence",
  lifecycle.confirmed_removed_at, "2026-07-03T00:00:02.000Z");

const unavailableAfterRemoval = applyAssetRemovalConfirmation(lifecycle, {
  scan_id: "scan-4",
  observed_at: "2026-07-04T00:00:03.000Z",
  signal_states: {
    dns_resolution: "unavailable",
    http_https_service: "not_observed",
  },
});
eq("unavailable after confirmation cannot undo removal",
  unavailableAfterRemoval.lifecycle_state, "confirmed_removed");
eq("unavailable after confirmation preserves evidence",
  unavailableAfterRemoval.qualifying_observations.length, 3);

const negativeAfterRemoval = applyAssetRemovalConfirmation(unavailableAfterRemoval, {
  scan_id: "scan-negative-after-confirmation",
  observed_at: "2026-07-05T00:00:04.000Z",
  signal_states: negativeStates,
});
eq("later negative evidence preserves the original confirmation time",
  negativeAfterRemoval.confirmed_removed_at, "2026-07-03T00:00:02.000Z");
eq("later negative evidence does not rewrite the qualifying projection",
  negativeAfterRemoval.qualifying_observations.length, 3);

const reappeared = applyAssetRemovalConfirmation(negativeAfterRemoval, {
  scan_id: "scan-5",
  observed_at: "2026-07-05T00:00:04.000Z",
  signal_states: {
    dns_resolution: "observed",
    http_https_service: "not_observed",
  },
});
eq("positive active evidence after confirmation is observed",
  reappeared.lifecycle_state, "observed");
eq("only confirmed removal can produce reappeared",
  reappeared.transition, "reappeared");
eq("reappearance resets qualifying observations",
  reappeared.qualifying_observations.length, 0);

console.log(`\nItem 10 P1: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) {
  console.error("Item 10 P1 validation FAILED");
  process.exit(1);
}
console.log("Item 10 P1 validation passed");
