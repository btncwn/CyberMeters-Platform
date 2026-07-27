#!/usr/bin/env node
// Item 10 P4 — load-bearing source mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(
  root,
  "scripts/validate-item10-attack-surface-p4-alert-quality.js",
);
const paths = {
  alerts: path.join(engines, "asset-alerts.js"),
  delivery: path.join(engines, "asset-alert-delivery.js"),
};
const sources = Object.fromEntries(Object.entries(paths).map(([key, file]) => [
  key,
  fs.readFileSync(file, "utf8"),
]));

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
  mutateAlerts = (source) => source,
  mutateDelivery = (source) => source,
}) {
  sequence += 1;
  const alertsName =
    `.asset-alerts.item10-p4-mutant.${process.pid}.${sequence}.js`;
  const deliveryName =
    `.asset-alert-delivery.item10-p4-mutant.${process.pid}.${sequence}.js`;
  const alertsFile = path.join(engines, alertsName);
  const deliveryFile = path.join(engines, deliveryName);
  const alerts = mutateAlerts(sources.alerts);
  const delivery = mutateDelivery(sources.delivery).replace(
    '"./asset-alerts.js"',
    `"./${alertsName}"`,
  );
  fs.writeFileSync(alertsFile, alerts);
  fs.writeFileSync(deliveryFile, delivery);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_P4_ALERTS_MODULE_URL: pathToFileURL(alertsFile).href,
        ITEM10_P4_DELIVERY_MODULE_URL: pathToFileURL(deliveryFile).href,
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
    fs.rmSync(alertsFile, { force: true });
    fs.rmSync(deliveryFile, { force: true });
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

runMutant("CT/passive evidence confirms removal", {
  mutateAlerts: (source) => mutateRequired(
    source,
    `    ASSET_REMOVAL_CONFIRMATION_POLICY.relevant_active_sources.every(
      (source) => confirmationSources.has(source),
    )`,
    `    ASSET_REMOVAL_CONFIRMATION_POLICY.passive_sources_excluded.some(
      (source) => (detail.passive_sources || []).includes(source),
    )`,
    "passive-source removal eligibility",
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

console.log(
  `Item 10 P4 alert-quality mutations: ${mutantsKilled}/` +
  `${mutantsKilled + mutantFailures} mutants killed; ` +
  `${assertionsPassed}/${assertionsPassed + assertionFailures} assertions passed`,
);
if (mutantsKilled !== 5 || mutantFailures > 0 || assertionFailures > 0) process.exit(1);
