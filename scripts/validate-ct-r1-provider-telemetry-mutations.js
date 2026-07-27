#!/usr/bin/env node
// CT-R1 load-bearing mutation proof. Anchors and totals are pinned.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const fixtureValidator = path.join(
  root,
  "scripts/validate-ct-r1-provider-telemetry.js"
);
const engineValidator = path.join(
  root,
  "scripts/validate-ct-r1-provider-telemetry-engine-trace.js"
);
const EXPECTED_MUTANTS = 5;
const EXPECTED_ASSERTIONS = 11;
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

function replaceRequired(input, from, to, label) {
  const mutated = input.replace(from, to);
  assert(`${label}: anchor guard`, mutated !== input, "mutated === original");
  return mutated;
}

function runMutant({
  name,
  sourceName,
  validator,
  moduleEnv,
  mutate,
  extraEnv = {},
}) {
  sequence += 1;
  const sourceFile = path.join(engines, sourceName);
  const source = fs.readFileSync(sourceFile, "utf8");
  const mutantFile = path.join(
    engines,
    `.${sourceName.replace(/\.js$/, "")}.ct-r1-mutant.${process.pid}.${sequence}.js`
  );
  fs.writeFileSync(mutantFile, mutate(source));
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ...extraEnv,
        [moduleEnv]: pathToFileURL(mutantFile).href,
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
    fs.rmSync(mutantFile, { force: true });
  }
}

runMutant({
  name: "move telemetry write into executable pre-finalization phase",
  sourceName: "scan-engine.js",
  validator: engineValidator,
  moduleEnv: "CT_R1_SCAN_ENGINE_MODULE_URL",
  mutate: (source) => {
    const writeBlock = `    await persistCtProviderTelemetry(
      scanId,
      ctCache.telemetrySnapshot({ modules, scanQuality }),
      env
    );
`;
    const removed = replaceRequired(
      source,
      writeBlock,
      "",
      "post-finalization CT write"
    );
    return replaceRequired(
      removed,
      `      );
    } catch (err) {`,
      `      );
      await persistCtProviderTelemetry(
        scanId,
        ctCache.telemetrySnapshot(),
        env
      );
    } catch (err) {`,
      "budgeted module insertion point"
    );
  },
});

runMutant({
  name: "swap crt.sh and CertSpotter attribution",
  sourceName: "ct-provider-cache.js",
  validator: fixtureValidator,
  moduleEnv: "CT_R1_CACHE_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    "    providerAttempts.push({ ...row, outcome });",
    `    providerAttempts.push({
      ...row,
      provider: row.provider === "crt_sh" ? "certspotter" : "crt_sh",
      outcome,
    });`,
    "provider-attempt attribution"
  ),
});

runMutant({
  name: "make CT telemetry write failure fatal",
  sourceName: "scan-engine.js",
  validator: fixtureValidator,
  moduleEnv: "CT_R1_SCAN_ENGINE_MODULE_URL",
  extraEnv: { CT_R1_TEST_WRITE_FAILURE: "1" },
  mutate: (source) => replaceRequired(
    source,
    "    } catch { /* non-fatal per row — telemetry cannot affect scan completion */ }",
    "    } catch (error) { throw error; }",
    "per-row non-fatal persistence"
  ),
});

runMutant({
  name: "let telemetry drop a merged subdomain",
  sourceName: "subdomains-scan.js",
  validator: fixtureValidator,
  moduleEnv: "CT_R1_SUBDOMAINS_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    `  return {
    count:              items.length,
    items,
    sensitive,`,
    `  return {
    count:              items.length,
    items:              ctCache.telemetrySnapshot().length > 0 ? items.slice(1) : items,
    sensitive,`,
    "merged subdomain result"
  ),
});

runMutant({
  name: "collapse timeout into network_error",
  sourceName: "ct-provider-cache.js",
  validator: fixtureValidator,
  moduleEnv: "CT_R1_CACHE_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    `        outcome: timeoutFailure(err) ? "timeout" : "network_error",`,
    `        outcome: "network_error",`,
    "timeout outcome classification"
  ),
});

console.log(
  `CT-R1 provider telemetry mutations: ` +
  `${mutantsKilled}/${EXPECTED_MUTANTS} mutants killed; ` +
  `${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`
);
if (
  mutantsKilled !== EXPECTED_MUTANTS ||
  mutantFailures > 0 ||
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
