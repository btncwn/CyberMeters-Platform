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
const EXPECTED_MUTANTS = 11;
const EXPECTED_ASSERTIONS = 23;
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
  sourcePath,
  validator,
  moduleEnv,
  mutate,
  extraEnv = {},
}) {
  sequence += 1;
  const sourceFile = sourcePath || path.join(engines, sourceName);
  const source = fs.readFileSync(sourceFile, "utf8");
  const mutantFile = path.join(
    path.dirname(sourceFile),
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
      if (child.stdout) console.error(child.stdout.trim());
      if (child.stderr) console.error(child.stderr.trim());
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
    const removed = replaceRequired(
      source,
      "    await persistCtTelemetryAfterTerminal();\n",
      "",
      "post-finalization CT write"
    );
    return replaceRequired(
      removed,
      "    ctTelemetryModules = modules;\n",
      `    ctTelemetryModules = modules;
      await persistCtProviderTelemetry(
        scanId,
        ctCache.telemetrySnapshot(),
        env
      );
`,
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
    "  } catch { /* non-fatal atomic batch — telemetry cannot affect scan completion */ }",
    "  } catch (error) { throw error; }",
    "atomic non-fatal persistence"
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
    `        outcome: provenance
          ? "platform_deadline_abort"
          : (timeoutFailure(err) ? "timeout" : "network_error"),`,
    `        outcome: provenance
          ? "platform_deadline_abort"
          : "network_error",`,
    "timeout outcome classification"
  ),
});

runMutant({
  name: "remove CT persistence from failed terminal path",
  sourceName: "scan-engine.js",
  validator: engineValidator,
  moduleEnv: "CT_R1_SCAN_ENGINE_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    `    await finalizeScanResult(latch, {
      scanId, report: failedReport, score: 0, rating: "unknown", status: "failed", env,
    });
    await persistCtTelemetryAfterTerminal();
`,
    `    await finalizeScanResult(latch, {
      scanId, report: failedReport, score: 0, rating: "unknown", status: "failed", env,
    });
`,
    "failed terminal CT persistence"
  ),
});

runMutant({
  name: "drop CT telemetry once-only guard",
  sourceName: "scan-engine.js",
  validator: engineValidator,
  moduleEnv: "CT_R1_SCAN_ENGINE_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    `      ctTelemetryPersistenceStarted
      || latch.d1Written !== true`,
    `      latch.d1Written !== true`,
    "once-only persistence guard"
  ),
});

const analyzerSource = path.join(root, "scripts/analyze-ct-provider-telemetry.js");

runMutant({
  name: "report zero for unmeasured co-failure rate",
  sourceName: "analyze-ct-provider-telemetry.js",
  sourcePath: analyzerSource,
  validator: fixtureValidator,
  moduleEnv: "CT_R1_ANALYZER_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    `co_failure_rate_pct: bothAttempted === 0
        ? null`,
    `co_failure_rate_pct: bothAttempted === 0
        ? 0`,
    "co-failure no-data rate"
  ),
});

runMutant({
  name: "drop first-class CT telemetry coverage count",
  sourceName: "analyze-ct-provider-telemetry.js",
  sourcePath: analyzerSource,
  validator: fixtureValidator,
  moduleEnv: "CT_R1_ANALYZER_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    "      scans_with_ct_telemetry: scansWithTelemetry.size,\n",
    "",
    "coverage output field"
  ),
});

runMutant({
  name: "count unattributed completion loss as attributed",
  sourceName: "analyze-ct-provider-telemetry.js",
  sourcePath: analyzerSource,
  validator: fixtureValidator,
  moduleEnv: "CT_R1_ANALYZER_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    "  const completionLossAttributed = attributedCompletionLossScans.size;",
    "  const completionLossAttributed = completionLoss;",
    "attributed completion-loss count"
  ),
});

runMutant({
  name: "make CT telemetry persistence partial-tolerant",
  sourceName: "scan-engine.js",
  validator: engineValidator,
  moduleEnv: "CT_R1_SCAN_ENGINE_MODULE_URL",
  mutate: (source) => replaceRequired(
    source,
    "    const results = await env.cybermeters_db.batch(statements);",
    `    const results = [];
    for (const statement of statements) {
      try {
        results.push(await statement.run());
      } catch { /* mutant: silently retain the other rows */ }
    }`,
    "atomic CT telemetry batch"
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
