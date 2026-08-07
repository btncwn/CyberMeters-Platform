#!/usr/bin/env node
// Item 10 P5 — load-bearing source mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const frontendPages = path.join(root, "frontend/src/pages");
const validator = path.join(
  root,
  "scripts/validate-item10-attack-surface-p5-customer-parity.js",
);
const paths = {
  presentation: path.join(
    engines,
    "attack-surface-customer-presentation.js",
  ),
  executive: path.join(engines, "executive-report.js"),
  assetAlerts: path.join(engines, "asset-alerts.js"),
  assetsPage: path.join(frontendPages, "AssetsPage.jsx"),
};
const sources = Object.fromEntries(Object.entries(paths).map(([key, file]) => [
  key,
  fs.readFileSync(file, "utf8"),
]));
const EXPECTED_MUTANTS = 18;
const EXPECTED_ASSERTIONS = EXPECTED_MUTANTS * 2;
let mutantsKilled = 0;
let mutantFailures = 0;
let assertionsPassed = 0;
let assertionFailures = 0;
let sequence = 0;

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function mutateRequired(source, from, to, label) {
  const mutated = source.replace(from, to);
  assert(`${label}: anchor guard`, mutated !== source, "mutated === original");
  return mutated;
}

function runMutant(name, {
  mutatePresentation = (source) => source,
  mutateExecutive = (source) => source,
  mutateAssetAlerts = (source) => source,
  mutateAssetsPage = (source) => source,
}) {
  sequence += 1;
  const presentationName =
    `.attack-surface-customer-presentation.item10-p5-mutant.${process.pid}.${sequence}.js`;
  const executiveName =
    `.executive-report.item10-p5-mutant.${process.pid}.${sequence}.js`;
  const assetAlertsName =
    `.asset-alerts.item10-p5-mutant.${process.pid}.${sequence}.js`;
  const assetsPageName =
    `.AssetsPage.item10-p5-mutant.${process.pid}.${sequence}.jsx`;
  const presentationFile = path.join(engines, presentationName);
  const executiveFile = path.join(engines, executiveName);
  const assetAlertsFile = path.join(engines, assetAlertsName);
  const assetsPageFile = path.join(frontendPages, assetsPageName);
  const presentation = mutatePresentation(sources.presentation);
  const executive = mutateExecutive(sources.executive);
  const assetAlerts = mutateAssetAlerts(sources.assetAlerts);
  const assetsPage = mutateAssetsPage(sources.assetsPage);
  fs.writeFileSync(presentationFile, presentation);
  fs.writeFileSync(executiveFile, executive);
  fs.writeFileSync(assetAlertsFile, assetAlerts);
  fs.writeFileSync(assetsPageFile, assetsPage);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_P5_PRESENTATION_MODULE_URL:
          pathToFileURL(presentationFile).href,
        ITEM10_P5_EXECUTIVE_MODULE_URL:
          pathToFileURL(executiveFile).href,
        ITEM10_P5_ASSET_ALERTS_MODULE_URL:
          pathToFileURL(assetAlertsFile).href,
        ITEM10_P5_ASSETS_PAGE_SOURCE: assetsPageFile,
      },
    });
    const killed = child.status !== 0;
    assert(`${name}: suite turns red`, killed,
      killed ? "" : "validator exited zero");
    if (killed) mutantsKilled += 1;
    else {
      mutantFailures += 1;
      console.error(`FAIL ${name}: mutant survived`);
    }
  } finally {
    fs.rmSync(presentationFile, { force: true });
    fs.rmSync(executiveFile, { force: true });
    fs.rmSync(assetAlertsFile, { force: true });
    fs.rmSync(assetsPageFile, { force: true });
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
    `  not_observed: "Not observed in this scan",`,
    `  not_observed: "Removed",`,
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
});

runMutant("asset_no_longer_seen wire event key is renamed", {
  mutateAssetAlerts: (source) => mutateRequired(
    source,
    `  "asset_no_longer_seen",`,
    `  "asset_no_longer_observed",`,
    "wire event key",
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
    `{ key: 'asset_no_longer_seen',   label: 'No longer observed' },`,
    `{ key: 'asset_no_longer_seen',   label: 'Removal event' },`,
    "AssetsPage external-absence label",
  ),
});

console.log(
  `Item 10 P5 customer parity mutations: ${mutantsKilled}/${EXPECTED_MUTANTS} mutants killed; ` +
  `${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
if (
  mutantsKilled !== EXPECTED_MUTANTS ||
  mutantFailures > 0 ||
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
