#!/usr/bin/env node
// Each regression fixture must fail by name when its correction is removed.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const suite = path.join(root, "scripts/validate-launch-reliability-a.js");
const cases = [
  {
    name: "CM-1 admin token admitted",
    file: "workers/scan-api/src/routes/account.js",
    from: "adminSession = !user.api_token_id",
    to: "adminSession = true",
    failure: "CM-1 admin token read/null status",
  },
  {
    name: "CM-P1-002 queue write outside transaction",
    file: "workers/scan-api/src/routes/workspaces-core.js",
    from: "const results = await db.batch(changes);",
    to: "const results = []; for (const change of changes) { try { results.push(await change.run()); } catch { results.push({ meta: { changes: 0 } }); } }",
    failure: "CM-P1-002 failed enqueue leaves workspace visible",
  },
  {
    name: "CM-P1-001 scheduled query error swallowed",
    file: "workers/scan-api/src/cron/scheduled.js",
    from: "if (!recorded.persisted) console.error(\"[scheduled-scan-query] failure event unavailable\");\n        throw error;",
    to: "if (!recorded.persisted) console.error(\"[scheduled-scan-query] failure event unavailable\");\n        return;",
    failure: "CM-P1-001 query cron error classification",
  },
  {
    name: "CM-P1-001 same-minute outcomes deduplicated",
    file: "workers/scan-api/src/cron/scheduled.js",
    from: "const queryCorrelationId = `scheduled-scan:${now.slice(0, 16)}:${crypto.randomUUID()}`;",
    to: "const queryCorrelationId = `scheduled-scan:${now.slice(0, 16)}`;",
    failure: "CM-P1-001 same-minute retries record each outcome",
  },
  {
    name: "CM-P1-001 recent failure signal misclassified",
    file: "workers/scan-api/src/lib/ops-health.js",
    from: "AND status IN ('error','table_missing') AND datetime(created_at)",
    to: "AND status = 'ok' AND datetime(created_at)",
    failure: "CM-P1-001 later success does not erase recent failure from ops health",
  },
  {
    name: "CM-P1-005 failed requests remain at queue head",
    file: "workers/scan-api/src/index.js",
    from: "                  AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime('now'))\n",
    to: "",
    failure: "CM-P1-005 retry delay excludes lease-expired failures from the next healthy turn",
  },
  {
    name: "CM-P1-007 global limiter fails open",
    file: "workers/scan-api/src/index.js",
    from: "globalAction, globalLimit, 300, { failClosed: true });",
    to: "globalAction, globalLimit, 300);",
    failure: "CM-P1-007 global guard closes on storage failure",
  },
];

// Optional exact case selection keeps a requested local proof bounded; CI
// without arguments still runs the complete existing harness.
const requested = [];
for (let i = 2; i < process.argv.length; i += 2) {
  if (process.argv[i] !== "--case" || !cases.some((item) => item.name === process.argv[i + 1])) {
    throw new Error("Expected --case followed by an exact mutation name");
  }
  requested.push(process.argv[i + 1]);
}
const selectedCases = requested.length ? cases.filter((item) => requested.includes(item.name)) : cases;

function run() {
  try {
    return { passed: true, output: execFileSync(process.execPath, [suite], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (error) {
    return { passed: false, output: String(error.stdout ?? "") + String(error.stderr ?? "") };
  }
}
const baseline = run();
if (!baseline.passed) {
  console.error("Baseline fixture failed:\n" + baseline.output);
  process.exit(1);
}
let allKilled = true;
for (const mutant of selectedCases) {
  const filename = path.join(root, mutant.file);
  const original = fs.readFileSync(filename, "utf8");
  const matches = original.split(mutant.from).length - 1;
  if (matches !== 1) {
    console.error(`ANCHOR FAILURE ${mutant.name}: ${matches} matches`);
    allKilled = false;
    continue;
  }
  let result;
  try {
    fs.writeFileSync(filename, original.replace(mutant.from, mutant.to));
    result = run();
  } finally {
    fs.writeFileSync(filename, original);
  }
  const namedFailure = result.output.split("\n").some((line) => line.startsWith(`FAIL ${mutant.failure}`));
  const finished = /Launch reliability fixtures: \d+\/\d+ passed/.test(result.output);
  const restored = fs.readFileSync(filename, "utf8") === original;
  const killed = !result.passed && namedFailure && finished && restored;
  console.log(`${killed ? "KILLED" : "SURVIVED"} ${mutant.name}`);
  if (!killed) console.error(result.output.slice(-1200));
  allKilled &&= killed;
}
console.log(`Launch reliability mutations: ${allKilled ? `${selectedCases.length}/${selectedCases.length} killed` : "failed"}`);
if (!allKilled) process.exit(1);
