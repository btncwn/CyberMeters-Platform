#!/usr/bin/env node
// Item 10 P2 — load-bearing production-source mutation proof.
//
// Each mutant is a temporary copy beside the real engine module so relative
// imports stay faithful. The deterministic P2 integration validator must fail.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(root, "scripts/validate-item10-attack-surface-p2-integration.js");
const lifecyclePath = path.join(engines, "attack-surface-lifecycle.js");
const policyPath = path.join(engines, "attack-surface-signal-completeness.js");
const lifecycleSource = fs.readFileSync(lifecyclePath, "utf8");
const policySource = fs.readFileSync(policyPath, "utf8");
let passed = 0;
let failed = 0;
let sequence = 0;

function result(name, killed, detail = "") {
  if (killed) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}: mutant survived${detail ? ` — ${detail}` : ""}`);
  }
}

function runIntegrationMutant(name, {
  mutatePolicy = (source) => source,
  mutateLifecycle = (source) => source,
}) {
  sequence += 1;
  const policyName = `.attack-surface-signal-completeness.item10-p2-mutant.${process.pid}.${sequence}.js`;
  const lifecycleName = `.attack-surface-lifecycle.item10-p2-mutant.${process.pid}.${sequence}.js`;
  const mutantPolicy = mutatePolicy(policySource);
  const mutantLifecycle = mutateLifecycle(lifecycleSource).replace(
    '"./attack-surface-signal-completeness.js"',
    `"./${policyName}"`,
  );
  const policyMutated = mutantPolicy !== policySource;
  const lifecycleMutated = mutantLifecycle !== lifecycleSource;
  if (!policyMutated && !lifecycleMutated) {
    result(name, false, "mutation anchor missing");
    return;
  }
  const policyMutantPath = path.join(engines, policyName);
  const lifecycleMutantPath = path.join(engines, lifecycleName);
  fs.writeFileSync(policyMutantPath, mutantPolicy);
  fs.writeFileSync(lifecycleMutantPath, mutantLifecycle);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_LIFECYCLE_MODULE_URL: pathToFileURL(lifecycleMutantPath).href,
      },
    });
    result(name, child.status !== 0);
  } finally {
    fs.rmSync(policyMutantPath, { force: true });
    fs.rmSync(lifecycleMutantPath, { force: true });
  }
}

const oneScanPolicy = (source) => source
  .replace(
    "rows.length >= policy.required_qualifying_observations &&",
    "rows.length >= 1 &&",
  )
  .replace(
    "windowMs >= policy.minimum_confirmation_window_ms;",
    "windowMs >= 0;",
  );

runIntegrationMutant("one scan confirms removal", {
  mutatePolicy: oneScanPolicy,
});

runIntegrationMutant("module failure emits removal", {
  mutatePolicy: (source) => oneScanPolicy(source)
    .replace(
      "const observationState = deriveRemovalObservation(observation.signal_states);",
      "let observationState = deriveRemovalObservation(observation.signal_states);",
    )
    .replace(
      'if (observationState !== "not_observed") return base;',
      'if (observationState === "observation_unavailable") observationState = "not_observed";\n  if (observationState !== "not_observed") return base;',
    ),
});

runIntegrationMutant("unavailable advances threshold", {
  mutatePolicy: (source) => source
    .replace(
      "const observationState = deriveRemovalObservation(observation.signal_states);",
      "let observationState = deriveRemovalObservation(observation.signal_states);",
    )
    .replace(
      'if (observationState !== "not_observed") return base;',
      'if (observationState === "observation_unavailable") observationState = "not_observed";\n  if (observationState !== "not_observed") return base;',
    ),
  mutateLifecycle: (source) => source.replace(
    'result.last_observation_state === "not_observed" &&\n        result.qualifying_observations.length > previousRows.length;',
    "result.qualifying_observations.length > previousRows.length;",
  ),
});

runIntegrationMutant("CT advances removal", {
  mutateLifecycle: (source) => source
    .replace(
      'dns_resolution: { state: "not_assessed", reason: "asset_not_in_active_recheck_envelope" },',
      'dns_resolution: { state: "absent", reason: "passive_ct_absence" },',
    )
    .replace(
      'http_https_service: { state: "not_assessed", reason: "asset_not_in_active_recheck_envelope" },',
      'http_https_service: { state: "not_observed", reason: "passive_ct_absence" },',
    ),
});

runIntegrationMutant("reappeared creates new identity", {
  mutateLifecycle: (source) => source.replace(
    '} else if (result.transition === "reappeared") {\n        statements.push(',
    `} else if (result.transition === "reappeared") {
        statements.push(
          env.cybermeters_db
            .prepare("UPDATE workspace_assets SET id = ? WHERE id = ? AND workspace_id = ?")
            .bind(createId("asset"), asset.id, workspaceId)
        );
        statements.push(`,
  ),
});

sequence += 1;
const missingName = `.attack-surface-signal-completeness.item10-p2-mutant.${process.pid}.${sequence}.js`;
const missingPath = path.join(engines, missingName);
const missingMutant = policySource.replace(
  /signal\("not_assessed"/g,
  'signal("not_observed"',
);
if (missingMutant === policySource) {
  result("missing signal renders healthy", false, "mutation anchor missing");
} else {
  fs.writeFileSync(missingPath, missingMutant);
  try {
    const mutant = await import(`${pathToFileURL(missingPath).href}?mutation=${sequence}`);
    const resultValue = mutant.deriveAttackSurfaceSignalCompleteness({});
    result(
      "missing signal renders healthy",
      Object.values(resultValue.signals).some((signal) => signal.state === "not_observed"),
    );
  } finally {
    fs.rmSync(missingPath, { force: true });
  }
}

console.log(`\nItem 10 P2 mutations: ${passed}/${passed + failed} killed`);
if (failed) process.exit(1);
console.log("Item 10 P2 mutation validation passed");
