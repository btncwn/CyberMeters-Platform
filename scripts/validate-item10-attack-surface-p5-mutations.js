#!/usr/bin/env node
// Item 10 P5 — load-bearing source mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  analyseOrderedRegistry,
  classifySemanticMutation,
  createMutationSandbox,
  filesUnder,
  fingerprintFiles,
  forcedInterruptionLeavesFingerprint,
  handledSignalCleansSandbox,
  installMutationSignalCleanup,
  preflightMutationTargets,
  replaceExactly,
} from "./item10-p5-mutation-harness.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const routes = path.join(root, "workers/scan-api/src/routes");
const frontendPages = path.join(root, "frontend/src/pages");
const validator = path.join(
  root,
  "scripts/validate-item10-attack-surface-p5-customer-parity.js",
);
installMutationSignalCleanup();
const paths = {
  presentation: path.join(
    engines,
    "attack-surface-customer-presentation.js",
  ),
  executive: path.join(engines, "executive-report.js"),
  assetAlerts: path.join(engines, "asset-alerts.js"),
  assetsPage: path.join(frontendPages, "AssetsPage.jsx"),
  route: path.join(routes, "attack-surface.js"),
};
const sources = Object.fromEntries(Object.entries(paths).map(([key, file]) => [
  key,
  fs.readFileSync(file, "utf8"),
]));
const EXPECTED_MUTANT_IDENTITIES = Object.freeze([
  "unavailable renders as healthy",
  "not_observed renders as removed",
  "Executive Report bypasses the shared projection",
  "pre-P5 historical snapshot is upgraded from an unfrozen field",
  "migration-102 absence renders healthy",
  "signal model-version stamp is dropped",
  "confirmed_removed internal enum is renamed",
  "asset_no_longer_seen wire event key is renamed",
  "eligible_confirmed_removal reason code is renamed",
  "eligible_reappearance_after_confirmed_removal reason code is renamed",
  "external-absence label reverts to confirmed removal",
  "lifecycleMessage active-source and window qualifier is removed",
  "eligible_confirmed_removal active-source and window qualifier is removed",
  "external-absence lifecycle limit is removed",
  "confirmed-removal alert explanation reverts to removal claim",
  "reappearance alert explanation reverts to removal claim",
  "stored P5 snapshot bypasses honest read-time projection",
  "AssetsPage event label reverts to removal",
  "honest summary alias is removed",
  "honest timeline alias is disconnected",
  "legacy summary field is removed",
  "legacy timeline field is removed",
]);
const EXPECTED_MUTANT_COUNT = 22;
const EXPECTED_VALIDATOR_ASSERTIONS = 258;
const EXPECTED_MUTATION_ANCHOR_ASSERTIONS = 24;
const EXPECTED_HARNESS_SAFETY_ASSERTIONS = 3;
const EXPECTED_FAILURES = Object.freeze({
  "unavailable renders as healthy": [
    "subdomain_discovery/unavailable: wording retained",
    "subdomain_discovery/unavailable: no favourable missing-evidence wording",
    "dns_resolution/unavailable: wording retained",
    "dns_resolution/unavailable: no favourable missing-evidence wording",
    "http_https_service/unavailable: wording retained",
    "http_https_service/unavailable: no favourable missing-evidence wording",
    "technology/unavailable: wording retained",
    "technology/unavailable: no favourable missing-evidence wording",
    "exposure_admin_surface/unavailable: wording retained",
    "exposure_admin_surface/unavailable: no favourable missing-evidence wording",
    "takeover_candidate/unavailable: wording retained",
    "takeover_candidate/unavailable: no favourable missing-evidence wording",
    "cve/unavailable: wording retained",
    "cve/unavailable: no favourable missing-evidence wording",
    "kev/unavailable: wording retained",
    "kev/unavailable: no favourable missing-evidence wording",
    "cloud_storage/unavailable: wording retained",
    "cloud_storage/unavailable: no favourable missing-evidence wording",
    "migration absent never renders healthy/no-issues",
  ],
  "not_observed renders as removed": [
    "subdomain_discovery/not_observed: wording retained",
    "dns_resolution/not_observed: wording retained",
    "http_https_service/not_observed: wording retained",
    "technology/not_observed: wording retained",
    "exposure_admin_surface/not_observed: wording retained",
    "takeover_candidate/not_observed: wording retained",
    "cve/not_observed: wording retained",
    "kev/not_observed: wording retained",
    "cloud_storage/not_observed: wording retained",
  ],
  "Executive Report bypasses the shared projection": [
    "surface 3 Executive Report and snapshot state agree",
  ],
  "pre-P5 historical snapshot is upgraded from an unfrozen field": [
    "pre-P5 snapshot projects not_recorded",
    "pre-P5 snapshot does not invent raw-module observation",
    "pre-P5 snapshot has an explicit notice",
  ],
  "migration-102 absence renders healthy": [
    "migration absent lifecycle is not_recorded",
    "migration absent never renders healthy/no-issues",
    "pre-P5 snapshot cannot read healthy or silently empty",
  ],
  "signal model-version stamp is dropped": ["signal model version stamped"],
  "confirmed_removed internal enum is renamed": [
    "lifecycle vocabulary is exact",
    "internal lifecycle enum remains confirmed_removed",
  ],
  "asset_no_longer_seen wire event key is renamed": [
    "wire event key remains exactly asset_no_longer_seen",
  ],
  "eligible_confirmed_removal reason code is renamed": [
    "confirmed-removal alert reason codes remain unchanged",
  ],
  "eligible_reappearance_after_confirmed_removal reason code is renamed": [
    "confirmed-removal alert reason codes remain unchanged",
  ],
  "external-absence label reverts to confirmed removal": [
    "confirmed_removed customer label is honest external absence",
    "surface 1 assets/API adapter and snapshot state agree",
    "stored P5 confirmed_removed label is projected honestly",
    "presentation: no positive confirmed-removal customer overclaim",
    "api_projection: no positive confirmed-removal customer overclaim",
  ],
  "lifecycleMessage active-source and window qualifier is removed": [
    "confirmed_removed narrative is bounded to the active sources and window",
    "confirmed_removed narrative does not claim platform-wide invisibility",
    "surface 1 assets/API adapter and snapshot state agree",
  ],
  "eligible_confirmed_removal active-source and window qualifier is removed": [
    "eligible_confirmed_removal narrative is bounded to the active sources and window",
    "eligible_confirmed_removal narrative does not use unqualified external absence",
  ],
  "external-absence lifecycle limit is removed": [
    "confirmed_removed message names the measured evidence",
    "confirmed_removed message denies removal/remediation proof",
    "confirmed_removed narrative is bounded to the active sources and window",
    "surface 1 assets/API adapter and snapshot state agree",
    "stored P5 lifecycle overclaim is projected with an explicit limit",
    "presentation: no positive confirmed-removal customer overclaim",
    "api_projection: no positive confirmed-removal customer overclaim",
  ],
  "confirmed-removal alert explanation reverts to removal claim": [
    "eligible_confirmed_removal narrative is bounded to the active sources and window",
    "eligible_confirmed_removal narrative denies removal/remediation proof",
  ],
  "reappearance alert explanation reverts to removal claim": [
    "eligible_reappearance_after_confirmed_removal: customer reason uses honest visibility vocabulary",
  ],
  "stored P5 snapshot bypasses honest read-time projection": [
    "stored P5 confirmed_removed label is projected honestly",
    "stored P5 lifecycle overclaim is projected with an explicit limit",
    "presentation: no positive confirmed-removal customer overclaim",
    "api_projection: no positive confirmed-removal customer overclaim",
  ],
  "AssetsPage event label reverts to removal": [
    "assets_page: no positive confirmed-removal customer overclaim",
  ],
  "honest summary alias is removed": [
    "posture summary keeps unsupported raw history out of honest count",
  ],
  "honest timeline alias is disconnected": [
    "posture timeline preserves raw history but excludes unsupported honest count",
  ],
  "legacy summary field is removed": [
    "posture summary retains finite non-negative legacy counts including zero",
  ],
  "legacy timeline field is removed": [
    "posture timeline retains finite non-negative legacy event counts including zero",
  ],
});
const registeredMutants = [];
let mutantsKilled = 0;
let mutantFailures = 0;
let assertionsPassed = 0;
let assertionFailures = 0;
const canonicalSourceFiles = () => [
  ...filesUnder(path.join(root, "workers/scan-api/src")),
  ...filesUnder(path.join(root, "frontend/src")),
];
const initialSourceFingerprint = fingerprintFiles(canonicalSourceFiles);

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function mutateRequired(source, from, to, label) {
  const mutated = replaceExactly(source, from, to, label);
  assert(`${label}: anchor guard`, true);
  return mutated;
}

function runMutant(name, {
  mutatePresentation = (source) => source,
  mutateExecutive = (source) => source,
  mutateAssetAlerts = (source) => source,
  mutateAssetsPage = (source) => source,
  mutateRoute = (source) => source,
}) {
  registeredMutants.push(name);
  const sandbox = createMutationSandbox(root, "item10-p5-arm1b-mutant-");
  try {
    const presentationFile = path.join(
      sandbox.workerSource,
      "engines/attack-surface-customer-presentation.js",
    );
    const executiveFile = path.join(sandbox.workerSource, "engines/executive-report.js");
    const assetAlertsFile = path.join(sandbox.workerSource, "engines/asset-alerts.js");
    const routeFile = path.join(sandbox.workerSource, "routes/attack-surface.js");
    const assetsPageFile = path.join(sandbox.tempRoot, "AssetsPage.jsx");
    const presentation = mutatePresentation(sources.presentation);
    const executive = mutateExecutive(sources.executive);
    const assetAlerts = mutateAssetAlerts(sources.assetAlerts);
    const assetsPage = mutateAssetsPage(sources.assetsPage);
    const route = mutateRoute(sources.route);
    fs.writeFileSync(presentationFile, presentation);
    fs.writeFileSync(executiveFile, executive);
    fs.writeFileSync(assetAlertsFile, assetAlerts);
    fs.writeFileSync(assetsPageFile, assetsPage);
    fs.writeFileSync(routeFile, route);

    const changedModuleUrls = [
      presentation !== sources.presentation && pathToFileURL(presentationFile).href,
      executive !== sources.executive && pathToFileURL(executiveFile).href,
      assetAlerts !== sources.assetAlerts && pathToFileURL(assetAlertsFile).href,
      route !== sources.route && pathToFileURL(routeFile).href,
    ].filter(Boolean);
    const preflight = preflightMutationTargets({ moduleUrls: changedModuleUrls });
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ...(presentation !== sources.presentation ? {
          ITEM10_P5_PRESENTATION_MODULE_URL: pathToFileURL(presentationFile).href,
        } : {}),
        ...(executive !== sources.executive ? {
          ITEM10_P5_EXECUTIVE_MODULE_URL: pathToFileURL(executiveFile).href,
        } : {}),
        ...(assetAlerts !== sources.assetAlerts ? {
          ITEM10_P5_ASSET_ALERTS_MODULE_URL: pathToFileURL(assetAlertsFile).href,
        } : {}),
        ...(assetsPage !== sources.assetsPage ? {
          ITEM10_P5_ASSETS_PAGE_SOURCE: assetsPageFile,
        } : {}),
        ...(route !== sources.route ? {
          ITEM10_P5_ROUTE_MODULE_URL: pathToFileURL(routeFile).href,
        } : {}),
      },
    });
    const childOutput = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = childOutput
      .split(/\r?\n/)
      .filter((line) => line.startsWith("FAIL "))
      .map((line) => line.slice(5).split(" — ")[0]);
    const terminalSummaries = [...childOutput.matchAll(
      /Item 10 P5 customer parity: (\d+)\/(\d+) assertions passed/g,
    )].map((summary) => ({
      passed: Number(summary[1]),
      total: Number(summary[2]),
    }));
    const expectedFailures = EXPECTED_FAILURES[name];
    const classified = classifySemanticMutation({
      child,
      output: childOutput,
      actualFailures,
      expectedFailures,
      summaries: terminalSummaries,
      expectedAssertions: EXPECTED_VALIDATOR_ASSERTIONS,
      preflight,
    });
    const killed = classified.killed;
    assert(`${name}: suite turns red`, killed,
      killed ? "" :
        `status=${child.status}; semantic=${classified.completedSemantically}; ` +
        `summaries=${terminalSummaries.length}; signal=${child.signal}; ` +
        `preflight=${JSON.stringify(preflight.failures)}; ` +
        `failures=${JSON.stringify(actualFailures)}`);
    if (killed) mutantsKilled += 1;
    else {
      mutantFailures += 1;
      console.error(`FAIL ${name}: mutant survived`);
    }
  } finally {
    sandbox.cleanup();
    if (fingerprintFiles(canonicalSourceFiles) !== initialSourceFingerprint) {
      throw new Error(`${name}: canonical source tree changed`);
    }
  }
}

runMutant("unavailable renders as healthy", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `  unavailable: "Evidence unavailable",`,
    `  unavailable: "Healthy",`,
    "unavailable wording",
  ),
});

runMutant("not_observed renders as removed", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `const SIGNAL_STATE_LABELS = Object.freeze({
  observed: "Observed",
  not_observed: "Not observed in this scan",`,
    `const SIGNAL_STATE_LABELS = Object.freeze({
  observed: "Observed",
  not_observed: "Removed",`,
    "not_observed wording",
  ),
});

runMutant("Executive Report bypasses the shared projection", {
  mutateExecutive: (source) => mutateRequired(
    source,
    `    attack_surface_assurance: attackSurfaceAssuranceFromSnapshot(snap),`,
    `    attack_surface_assurance: {
      schema: "parallel-asm-presentation",
      status: "current",
      signals: {},
    },`,
    "Executive Report projection call",
  ),
});

runMutant("pre-P5 historical snapshot is upgraded from an unfrozen field", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `  return buildAttackSurfaceCustomerPresentation({
    absenceReason: reason,`,
    `  return buildAttackSurfaceCustomerPresentation({
    signalCompleteness:
      snapshot?.modules?.attack_surface_signal_completeness || null,
    absenceReason: reason,`,
    "historical snapshot boundary",
  ),
});

runMutant("migration-102 absence renders healthy", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `    status: recorded ? "recorded" : "not_recorded",
    records: projected,
    customer_message: recorded`,
    `    status: recorded ? "recorded" : "healthy",
    records: projected,
    customer_message: recorded`,
    "migration-102 absence status",
  ),
});

runMutant("signal model-version stamp is dropped", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `      signal_completeness: signalRecorded
        ? (canonical.model_version || null)
        : null,`,
    `      signal_completeness: null,`,
    "signal model-version stamp",
  ),
});

runMutant("confirmed_removed internal enum is renamed", {
  mutatePresentation: (source) => mutateRequired(
    mutateRequired(
      source,
      `export const ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES = Object.freeze([
  "not_assessed",
  "observed",
  "not_observed",
  "confirmed_removed",
]);`,
      `export const ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES = Object.freeze([
  "not_assessed",
  "observed",
  "not_observed",
  "externally_absent",
]);`,
      "internal lifecycle enum",
    ),
    `const LIFECYCLE_STATE_SET =
  new Set(ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES);`,
    `const LIFECYCLE_STATE_SET =
  new Set([...ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES, "confirmed_removed"]);`,
    "runtime compatibility guard",
  ),
});

runMutant("asset_no_longer_seen wire event key is renamed", {
  mutateAssetAlerts: (source) => mutateRequired(
    mutateRequired(
      source,
      `export const ASSET_ALERT_EVENTS = new Set([
  "new_asset_discovered",
  "asset_reappeared",
  "asset_no_longer_seen",`,
      `export const ASSET_ALERT_EVENTS = new Set([
  "new_asset_discovered",
  "asset_reappeared",
  "asset_no_longer_observed",`,
      "wire event key",
    ),
    `  asset_no_longer_seen: "No longer seen",`,
    `  asset_no_longer_observed: "No longer seen",`,
    "wire event email label",
  ),
});

runMutant("eligible_confirmed_removal reason code is renamed", {
  mutateAssetAlerts: (source) => mutateRequired(
    source,
    `  "eligible_confirmed_removal",`,
    `  "eligible_external_absence",`,
    "confirmed-removal reason code",
  ),
});

runMutant("eligible_reappearance_after_confirmed_removal reason code is renamed", {
  mutateAssetAlerts: (source) => mutateRequired(
    source,
    `  "eligible_reappearance_after_confirmed_removal",`,
    `  "eligible_reappearance_after_external_absence",`,
    "reappearance reason code",
  ),
});

runMutant("external-absence label reverts to confirmed removal", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `  confirmed_removed: "No longer externally observed",`,
    `  confirmed_removed: "Confirmed removed",`,
    "external-absence customer label",
  ),
});

runMutant("lifecycleMessage active-source and window qualifier is removed", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `      return "Three qualifying observations over at least 48 hours found no authoritative DNS record and no HTTP or HTTPS service. CyberMeters therefore did not observe the asset through those active sources during that window. It is not evidence that the asset was removed, decommissioned or remediated; a firewalled, geo-restricted or temporarily unavailable asset can produce the same evidence.";`,
    `      return "Three qualifying observations over at least 48 hours found no authoritative DNS record and no HTTP or HTTPS service. This shows the asset is not externally visible to CyberMeters. It is not evidence that the asset was removed, decommissioned or remediated; a firewalled, geo-restricted or temporarily unavailable asset can produce the same evidence.";`,
    "lifecycleMessage scope qualifier",
  ),
});

runMutant("eligible_confirmed_removal active-source and window qualifier is removed", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `    "Three qualifying observations over at least 48 hours found no authoritative DNS record and no HTTP or HTTPS service. CyberMeters therefore did not observe the asset through those active sources during that window. This is not evidence of removal, decommissioning or remediation.",`,
    `    "Three qualifying observations over at least 48 hours found no authoritative DNS record and no HTTP or HTTPS service, so the asset was no longer externally observed. This is not evidence of removal, decommissioning or remediation.",`,
    "eligible_confirmed_removal scope qualifier",
  ),
});

runMutant("external-absence lifecycle limit is removed", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `      return "Three qualifying observations over at least 48 hours found no authoritative DNS record and no HTTP or HTTPS service. CyberMeters therefore did not observe the asset through those active sources during that window. It is not evidence that the asset was removed, decommissioned or remediated; a firewalled, geo-restricted or temporarily unavailable asset can produce the same evidence.";`,
    `      return "The asset met the deterministic confirmed-removal policy using qualifying active-source observations.";`,
    "external-absence lifecycle message",
  ),
});

runMutant("confirmed-removal alert explanation reverts to removal claim", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `    "Three qualifying observations over at least 48 hours found no authoritative DNS record and no HTTP or HTTPS service. CyberMeters therefore did not observe the asset through those active sources during that window. This is not evidence of removal, decommissioning or remediation.",`,
    `    "The removal claim satisfied the canonical confirmation policy.",`,
    "confirmed-removal alert explanation",
  ),
});

runMutant("reappearance alert explanation reverts to removal claim", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `    "The asset was externally observed after an earlier policy-qualified period with no authoritative DNS record and no HTTP or HTTPS service. This is an external-visibility change, not proof of removal, decommissioning or remediation.",`,
    `    "The asset was observed again after a canonically confirmed removal.",`,
    "reappearance alert explanation",
  ),
});

runMutant("stored P5 snapshot bypasses honest read-time projection", {
  mutatePresentation: (source) => mutateRequired(
    source,
    `    return projectRecordedAttackSurfaceAssurance(recorded);`,
    `    return recorded;`,
    "stored P5 read-time projection",
  ),
});

runMutant("AssetsPage event label reverts to removal", {
  mutateAssetsPage: (source) => mutateRequired(
    source,
    `const claimDisplay = assetLifecycleClaimDisplay(ev)`,
    `const claimDisplay = { ...assetLifecycleClaimDisplay(ev), title: 'Removal event' }`,
    "AssetsPage external-absence label",
  ),
});

runMutant("honest summary alias is removed", {
  mutateRoute: (source) => mutateRequired(
    source,
    `            no_longer_observed_assets_30d: noLongerObservedAssets30d,\n`,
    ``,
    "honest summary alias",
  ),
});

runMutant("honest timeline alias is disconnected", {
  mutateRoute: (source) => mutateRequired(
    source,
    `                  ? supportedNoLongerByDay.get(day) || 0
                  : null,`,
    `                  ? ev.removed_assets
                  : null,`,
    "honest timeline alias",
  ),
});

runMutant("legacy summary field is removed", {
  mutateRoute: (source) => mutateRequired(
    source,
    `            removed_assets_30d:          removedAssets30d,\n`,
    ``,
    "legacy summary field",
  ),
});

runMutant("legacy timeline field is removed", {
  mutateRoute: (source) => mutateRequired(
    source,
    `              removed_assets:    ev.removed_assets,\n`,
    ``,
    "legacy timeline field",
  ),
});

const registry = analyseOrderedRegistry({
  registeredIds: registeredMutants,
  expectedIds: EXPECTED_MUTANT_IDENTITIES,
  expectedCount: EXPECTED_MUTANT_COUNT,
  expectedFailureIds: Object.keys(EXPECTED_FAILURES),
});
assert("mutant registry identities and order are frozen",
  registry.exactOrder && registry.duplicates.length === 0 &&
    registry.missing.length === 0 && registry.unexpected.length === 0);
assert("mutant registry count is the independent literal",
  registry.countExact);
assert("mutant failure-set registry is complete and independently keyed",
  registry.failureRegistryExact && Object.values(EXPECTED_FAILURES).every(
    (failures) => Array.isArray(failures) && failures.length > 0,
  ));
assert("mutation targets remain byte-identical after every sandboxed mutant",
  fingerprintFiles(canonicalSourceFiles) === initialSourceFingerprint);
const signalCleanupProof = handledSignalCleansSandbox({
  root,
  files: canonicalSourceFiles,
});
assert("handled termination cleans the dedicated mutation sandbox",
  signalCleanupProof.ok, JSON.stringify(signalCleanupProof));
assert("forced interruption cannot write into canonical mutation targets",
  forcedInterruptionLeavesFingerprint({ files: canonicalSourceFiles }));
const EXPECTED_ASSERTIONS =
  EXPECTED_MUTANT_COUNT + EXPECTED_MUTATION_ANCHOR_ASSERTIONS + 3 +
  EXPECTED_HARNESS_SAFETY_ASSERTIONS;

console.log(
  `Item 10 P5 customer parity mutations: ${mutantsKilled}/${EXPECTED_MUTANT_COUNT} mutants killed; ` +
  `${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
if (
  mutantsKilled !== EXPECTED_MUTANT_COUNT ||
  mutantFailures > 0 ||
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
