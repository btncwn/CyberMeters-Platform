#!/usr/bin/env node
//
// Load-bearing Item 8 PR-B mutations. Each mutant runs the full
// validate-brand-idn-discovery.js in a fresh isolated source tree and must fail
// with exactly the pinned assertion names: no syntax/load/wrong-reason kill is
// accepted.
//
// The original single mutant (customer-owned IDN exclusion in the passive
// certificate-log filter) targeted code that has been removed. These mutants
// target the live code paths the validator still proves.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = "scripts/validate-brand-idn-discovery.js";
const asset = "workers/scan-api/src/engines/asset-persistence.js";
const protection = "workers/scan-api/src/engines/brand-protection.js";
const EXPECTED_MUTANTS = 4;
const EXPECTED_ASSERTIONS = EXPECTED_MUTANTS + 4;

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const replaceOnce = (source, from, to) => {
  const first = source.indexOf(from);
  if (first < 0 || source.indexOf(from, first + from.length) >= 0) {
    throw new Error(`mutation anchor missing or non-unique: ${JSON.stringify(from)}`);
  }
  return source.slice(0, first) + to + source.slice(first + from.length);
};
const M = (name, file, expectedFailures, from, to) => ({ name, file, expectedFailures, from, to });

const MUTANTS = Object.freeze([
  M("canonical merge drops stored evidence", asset,
    [
      "generated scan cannot erase stored CT evidence",
      "generated scan preserves unrelated stored history",
      "stored CT evidence keeps the CT-only IDN tier",
    ],
    "const out = safeJsonArray(existingValue)",
    "const out = safeJsonArray([])"),
  M("generated re-observation overwrites customer-protected reasons", asset,
    ["customer classification outranks generated re-observation"],
    "const riskReasons = protectedState",
    "const riskReasons = false"),
  M("generated insert claims DNS absence without a probe", asset,
    ["activity remains unknown until the existing enrichment sweep runs"],
    "c.risk_reasons, c.evidence_json, NULL, NULL, NULL,",
    "c.risk_reasons, c.evidence_json, 0, NULL, NULL,"),
  M("CT-only IDN escapes the low tier", protection,
    [
      "bare CT IDN remains low until activity is observed",
      "stored CT evidence keeps the CT-only IDN tier",
    ],
    "score = Math.min(score, idnHomograph ? 39 : 84);",
    "score = Math.min(score, 84);"),
]);

let passed = 0;
let failed = 0;
function check(name, condition, detail = "") {
  if (condition) passed++;
  else { failed++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}

function runValidator(repo) {
  return spawnSync(process.execPath, [path.join(repo, validator)], {
    cwd: repo,
    encoding: "utf8",
    timeout: 60_000,
    maxBuffer: 16 * 1024 * 1024,
  });
}

function failNames(output) {
  return [...String(output).matchAll(/^FAIL (.+?)(?: — .*)?$/gm)]
    .map((match) => match[1]).sort();
}

const targetPaths = [...new Set(MUTANTS.map((mutant) => mutant.file))];
const before = new Map(targetPaths.map((relative) =>
  [relative, sha256(fs.readFileSync(path.join(root, relative)))]));

check("mutant table count is exact", MUTANTS.length === EXPECTED_MUTANTS,
  `got ${MUTANTS.length} want ${EXPECTED_MUTANTS}`);
const baseline = runValidator(root);
check("unmutated baseline is green", baseline.status === 0 && baseline.signal === null &&
  !/^(FAIL|SyntaxError|Error)/m.test(`${baseline.stdout}\n${baseline.stderr}`),
  `${baseline.stdout}\n${baseline.stderr}`.trim());

for (const mutant of MUTANTS) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cm-brand-idn-mutant-"));
  let exact = false;
  let detail = "";
  try {
    const workerRoot = path.join(temp, "workers", "scan-api");
    const pageDir = path.join(temp, "frontend", "src", "pages", "ws");
    fs.mkdirSync(path.join(temp, "scripts"), { recursive: true });
    fs.mkdirSync(workerRoot, { recursive: true });
    fs.mkdirSync(pageDir, { recursive: true });
    fs.cpSync(path.join(root, "workers", "scan-api", "src"), path.join(workerRoot, "src"), { recursive: true });
    fs.cpSync(path.join(root, "shared"), path.join(temp, "shared"), { recursive: true });
    fs.copyFileSync(path.join(root, "frontend", "src", "api.js"), path.join(temp, "frontend", "src", "api.js"));
    fs.copyFileSync(path.join(root, "frontend", "src", "pages", "ws", "BrandMonitoringPage.jsx"),
      path.join(pageDir, "BrandMonitoringPage.jsx"));
    fs.copyFileSync(path.join(root, validator), path.join(temp, validator));
    fs.symlinkSync(path.join(root, "workers", "scan-api", "node_modules"),
      path.join(workerRoot, "node_modules"), "dir");

    const target = path.join(temp, mutant.file);
    const original = fs.readFileSync(target, "utf8");
    const mutated = replaceOnce(original, mutant.from, mutant.to);
    if (mutated === original) throw new Error("mutation did not change target bytes");
    fs.writeFileSync(target, mutated);

    const result = runValidator(temp);
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    const got = failNames(output);
    const want = [...mutant.expectedFailures].sort();
    const problems = [];
    if (result.error) problems.push(`spawn ${result.error.message}`);
    if (result.signal !== null) problems.push(`signal ${result.signal}`);
    if (result.status !== 1) problems.push(`exit ${result.status}, want 1`);
    if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module/.test(output)) problems.push("syntax/load failure");
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      problems.push(`FAIL set ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
    exact = problems.length === 0;
    detail = problems.length ? `${problems.join("; ")}\n${output.trim()}` : want.join(", ");
  } catch (error) {
    detail = error?.stack || error?.message || String(error);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  check(`mutant ${mutant.name} killed for exact reason`, exact, detail);
}

check("source target bytes remain restored", targetPaths.every((relative) =>
  sha256(fs.readFileSync(path.join(root, relative))) === before.get(relative)));
check("mutation assertion count is exact", passed + failed + 1 === EXPECTED_ASSERTIONS,
  `got ${passed + failed + 1} want ${EXPECTED_ASSERTIONS}`);

console.log(`\nBrand IDN discovery mutations: ${passed}/${passed + failed} assertions; ${MUTANTS.length} exact mutants`);
if (failed || passed + failed !== EXPECTED_ASSERTIONS) process.exit(1);
console.log("Brand IDN discovery mutation validation passed");
