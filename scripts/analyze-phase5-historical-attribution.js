#!/usr/bin/env node
// Bounded read-only production attribution reducer for the Phase-5 historical
// customer-read P1.
//
// Input is a local JSON array produced by an authorised READ-ONLY extraction of
// the bounded candidate cohort. Each row needs only:
//   { scan_quality, score, rating, modules: {
//       cve_intelligence, known_exploited_vulnerabilities,
//       email_security_intelligence } }
//
// The extraction must not include tenant/workspace/domain/report identifiers.
// This reducer performs no network calls and no writes. It emits aggregate
// counts only:
//
//   node scripts/analyze-phase5-historical-attribution.js \
//     --input=/tmp/phase5-candidate-evidence.json \
//     --verify=scripts/fixtures/phase5-historical-attribution-aggregate.json
//
// Candidate selection used for the recorded run:
//   completed reports whose stored scan quality was partial/degraded and whose
//   frozen customer fields contained rating=excellent or score>=90. The
//   authorised extractor read each referenced immutable R2 report and emitted
//   only the evidence fields above. It made zero D1/R2 writes.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { PHASE5_EVIDENCE_MODULES } = await import(pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines/phase5-evidence.js",
)).href);
const { isPublishableModuleEvidence } = await import(pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines/scan-budget.js",
)).href);

const arg = (name) => process.argv.find((value) => value.startsWith(`--${name}=`))
  ?.slice(name.length + 3);
const inputPath = arg("input");
const verifyPath = arg("verify");
if (!inputPath) {
  console.error("usage: analyze-phase5-historical-attribution.js --input=<sanitised-json> [--verify=<aggregate-json>]");
  process.exit(2);
}

const rows = JSON.parse(fs.readFileSync(inputPath, "utf8"));
if (!Array.isArray(rows)) throw new Error("input must be a JSON array");

const totals = {
  phase5_deadline_exceeded: 0,
  phase5_incomplete_without_deadline: 0,
  phase5_fully_completed: 0,
  unattributable_from_historical_contract: 0,
};
const moduleKeys = Object.values(PHASE5_EVIDENCE_MODULES);
for (const row of rows) {
  const modules = row?.modules;
  if (!modules || typeof modules !== "object" ||
      moduleKeys.some((key) => !modules[key] || typeof modules[key] !== "object")) {
    totals.unattributable_from_historical_contract += 1;
    continue;
  }
  const values = moduleKeys.map((key) => modules[key]);
  if (values.some((value) => value.outcome === "deadline_exceeded")) {
    totals.phase5_deadline_exceeded += 1;
  } else if (values.every(isPublishableModuleEvidence)) {
    totals.phase5_fully_completed += 1;
  } else if (values.some((value) =>
    value.executed === false ||
    value.incomplete === true ||
    value.skipped === true ||
    Boolean(value.error)
  )) {
    totals.phase5_incomplete_without_deadline += 1;
  } else {
    totals.unattributable_from_historical_contract += 1;
  }
}

const output = {
  population: rows.length,
  ...totals,
};
if (verifyPath) {
  const expected = JSON.parse(fs.readFileSync(verifyPath, "utf8"));
  const expectedCounts = expected.aggregate ?? expected;
  if (JSON.stringify(output) !== JSON.stringify(expectedCounts)) {
    console.error("aggregate verification failed");
    console.error(JSON.stringify({ expected: expectedCounts, actual: output }, null, 2));
    process.exit(1);
  }
}
process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
