#!/usr/bin/env node
// Item 10 P4 — load-bearing source mutation proof.
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
const validator = path.join(
  root,
  "scripts/validate-item10-attack-surface-p4-alert-quality.js",
);
installMutationSignalCleanup();
const paths = {
  alerts: path.join(engines, "asset-alerts.js"),
  delivery: path.join(engines, "asset-alert-delivery.js"),
  support: path.join(engines, "asset-lifecycle-event-support.js"),
};
const sources = Object.fromEntries(Object.entries(paths).map(([key, file]) => [
  key,
  fs.readFileSync(file, "utf8"),
]));

const EXPECTED_MUTANT_IDENTITIES = Object.freeze([
  "count-only eligibility re-alerts the 15 Jul replay",
  "blanket scan-level gate kills healthy siblings",
  "required active-source proof is replaced by passive-source lookup",
  "canonical ordering drops bytewise scan_id tie-break",
  "withheld alert records no reason",
  "migration-102 absence globally silences mapped alerts",
]);
const EXPECTED_MUTANT_COUNT = 6;
const EXPECTED_VALIDATOR_ASSERTIONS = 45;
const EXPECTED_FAILURES = Object.freeze({
  "count-only eligibility re-alerts the 15 Jul replay": [
    "bytewise scan_id tie keeps the producer-faithful P4 reappearance eligible",
    "14 Jul CT blackout cannot alert a removal claim",
    "14 Jul removal has a declared reason",
    "14 Jul removal produces no alert-worthy eligible count",
    "15 Jul recovery cannot alert reappearance after unconfirmed disappearance",
    "15 Jul reappearance has a declared reason",
    "15 Jul replay produces no alert-worthy eligible count",
    "confirmed removal reason is canonical",
    "reappearance after confirmed removal remains alertable",
    "absent schema cannot assert confirmed reappearance",
    "withheld record is bounded and machine-inspectable",
    "withheld-only row records the frozen aggregate reason",
    "withheld reason remains inspectable in existing event_counts JSON",
  ],
  "blanket scan-level gate kills healthy siblings": [
    "CT-unavailable sibling does not suppress admin/takeover claims",
    "strongest independently observed sibling keeps existing severity",
    "one unsupported claim is withheld independently",
    "healthy sibling stays eligible",
    "unsupported critical claim cannot escalate eligible admin severity",
  ],
  "required active-source proof is replaced by passive-source lookup": [
    "bytewise scan_id tie keeps the producer-faithful P4 reappearance eligible",
    "three active-source observations confirm removal eligibility",
    "confirmed removal reason is canonical",
    "genuine confirmed removal is alert-worthy",
    "reappearance after confirmed removal remains alertable",
  ],
  "canonical ordering drops bytewise scan_id tie-break": [
    "bytewise scan_id tie keeps the producer-faithful P4 reappearance eligible",
  ],
  "withheld alert records no reason": [
    "unsupported reappearance is durably skipped",
    "withheld-only row records the frozen aggregate reason",
  ],
  "migration-102 absence globally silences mapped alerts": [
    "migration-102-absent world keeps independent event evidence alertable",
    "migration-102-absent world cannot globally silence ASM alerts",
    "absent-model fallback is explicitly labelled",
    "absent migration still routes independent admin event to canonical delivery",
    "entitlement suppression proves delivery gate was reached",
  ],
});

const canonicalSourceRoot = path.join(root, "workers/scan-api/src");
const canonicalSourceFiles = () => filesUnder(canonicalSourceRoot);
const initialSourceTreeFingerprint = fingerprintFiles(canonicalSourceFiles);
const registeredMutants = [];

let mutantsKilled = 0;
let mutantFailures = 0;
let assertionsPassed = 0;
let assertionFailures = 0;

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function mutateRequired(source, from, to, label) {
  const mutated = replaceExactly(source, from, to, label);
  assert(`${label}: exact anchor guard`, true);
  return mutated;
}

function runMutant(name, {
  mutateAlerts = (source) => source,
  mutateDelivery = (source) => source,
  mutateSupport = (source) => source,
}) {
  registeredMutants.push(name);
  const sandbox = createMutationSandbox(root, "item10-p5-p4-mutant-");
  const alertsFile = path.join(sandbox.workerSource, "engines/asset-alerts.js");
  const deliveryFile = path.join(sandbox.workerSource, "engines/asset-alert-delivery.js");
  const supportFile = path.join(
    sandbox.workerSource,
    "engines/asset-lifecycle-event-support.js",
  );
  const outsideCanonical = [alertsFile, deliveryFile, supportFile].every(
    (file) => !path.resolve(file).startsWith(`${path.resolve(canonicalSourceRoot)}${path.sep}`),
  );
  assert(`${name}: mutation modules stay outside the canonical source tree`,
    outsideCanonical);
  if (!outsideCanonical) throw new Error(`${name}: unsafe mutation target`);
  const alerts = mutateAlerts(sources.alerts);
  const delivery = mutateDelivery(sources.delivery);
  const support = mutateSupport(sources.support);
  try {
    fs.writeFileSync(alertsFile, alerts);
    fs.writeFileSync(deliveryFile, delivery);
    fs.writeFileSync(supportFile, support);
    const moduleUrls = [alertsFile, deliveryFile, supportFile].map(
      (file) => pathToFileURL(file).href,
    );
    const preflight = preflightMutationTargets({ moduleUrls });
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_P4_ALERTS_MODULE_URL: pathToFileURL(alertsFile).href,
        ITEM10_P4_DELIVERY_MODULE_URL: pathToFileURL(deliveryFile).href,
      },
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = output
      .split(/\r?\n/)
      .filter((line) => line.startsWith("FAIL "))
      .map((line) => line.slice(5).split(" — ")[0]);
    const summaries = [...output.matchAll(
      /Item 10 P4 alert-quality validation: (\d+)\/(\d+) assertions passed/g,
    )].map((summary) => ({
      passed: Number(summary[1]),
      total: Number(summary[2]),
    }));
    const classified = classifySemanticMutation({
      child,
      output,
      actualFailures,
      expectedFailures: EXPECTED_FAILURES[name],
      summaries,
      expectedAssertions: EXPECTED_VALIDATOR_ASSERTIONS,
      preflight,
    });
    const killed = classified.killed;
    assert(`${name}: exact semantic kill`, killed,
      killed ? "" :
        `status=${child.status}; signal=${child.signal}; ` +
        `semantic=${classified.completedSemantically}; ` +
        `preflight=${JSON.stringify(preflight.failures)}; ` +
        `failures=${JSON.stringify(actualFailures)}`);
    if (killed) mutantsKilled += 1;
    else {
      mutantFailures += 1;
      console.error(`FAIL ${name}: mutant survived`);
    }
  } finally {
    const tempRoot = sandbox.tempRoot;
    sandbox.cleanup();
    assert(`${name}: killed-run sandbox cleanup restores the canonical source tree`,
      !fs.existsSync(tempRoot) &&
      fingerprintFiles(canonicalSourceFiles) === initialSourceTreeFingerprint);
  }
}

runMutant("count-only eligibility re-alerts the 15 Jul replay", {
  mutateAlerts: (source) => mutateRequired(
    source,
    "  if (LIFECYCLE_CLAIMS.has(event.event_type)) {\n",
    `  if (LIFECYCLE_CLAIMS.has(event.event_type)) {
    return { eligible: true, reason_code: "eligible_event_evidence_fallback" };
  }
  if (false) {
`,
    "count-only eligibility",
  ),
});

runMutant("blanket scan-level gate kills healthy siblings", {
  mutateAlerts: (source) => mutateRequired(
    source,
    "function decisionForEvent(event, evidence) {\n",
    `function decisionForEvent(event, evidence) {
  if (Object.values(evidence.signal_states || {}).some(
    (signal) => signal?.state === "unavailable",
  )) {
    return { eligible: false, reason_code: "withheld_signal_not_supported" };
  }
`,
    "blanket scan-level gate",
  ),
});

runMutant("required active-source proof is replaced by passive-source lookup", {
  mutateSupport: (source) => mutateRequired(
    source,
    `      ASSET_REMOVAL_CONFIRMATION_POLICY.relevant_active_sources.every(
        (source) => activeSources.has(source),
      )`,
    `    ASSET_REMOVAL_CONFIRMATION_POLICY.passive_sources_excluded.some(
      (source) => (detail.passive_sources || []).includes(source),
    )`,
    "passive-source removal eligibility",
  ),
});

runMutant("canonical ordering drops bytewise scan_id tie-break", {
  mutateSupport: (source) => mutateRequired(
    source,
    "  return compareBytewise(a?.scan_id, b?.scan_id);",
    "  return 0;",
    "bytewise scan_id tie-break",
  ),
});

runMutant("withheld alert records no reason", {
  mutateDelivery: (source) => mutateRequired(
    source,
    `          await recordWithheldAlertDecision(
            env,
            recId,
            workspace_id,
            scanId,
            eligibility,
          );`,
    "          await Promise.resolve();",
    "withheld decision recording",
  ),
});

runMutant("migration-102 absence globally silences mapped alerts", {
  mutateAlerts: (source) => mutateRequired(
    source,
    `    return {
      eligible: true,
      reason_code: "eligible_event_evidence_fallback",
    };`,
    `    return {
      eligible: false,
      reason_code: "withheld_signal_not_supported",
    };`,
    "absent-model event fallback",
  ),
});

const registry = analyseOrderedRegistry({
  registeredIds: registeredMutants,
  expectedIds: EXPECTED_MUTANT_IDENTITIES,
  expectedCount: EXPECTED_MUTANT_COUNT,
  expectedFailureIds: Object.keys(EXPECTED_FAILURES),
});
assert("P4 mutant registry identities and order are independently frozen",
  registry.exactOrder && registry.duplicates.length === 0 &&
  registry.missing.length === 0 && registry.unexpected.length === 0);
assert("P4 mutant registry count is an independent literal", registry.countExact);
assert("P4 exact semantic failure registry is complete and independently keyed",
  registry.failureRegistryExact && Object.values(EXPECTED_FAILURES).every(
    (failures) => Array.isArray(failures) && failures.length > 0,
  ));
const signalCleanupProof = handledSignalCleansSandbox({
  root,
  files: canonicalSourceFiles,
});
assert("P4 handled interruption cleans its dedicated mutation sandbox",
  signalCleanupProof.ok, JSON.stringify(signalCleanupProof));
assert("P4 forced interruption cannot contaminate the canonical source tree",
  forcedInterruptionLeavesFingerprint({ files: canonicalSourceFiles }));

console.log(
  `Item 10 P4 alert-quality mutations: ${mutantsKilled}/${EXPECTED_MUTANT_COUNT} mutants killed; ` +
  `${assertionsPassed}/${assertionsPassed + assertionFailures} assertions passed`,
);
if (
  mutantsKilled !== EXPECTED_MUTANT_COUNT ||
  mutantFailures > 0 ||
  assertionFailures > 0
) process.exit(1);
