#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const fixturePath = path.join(repoRoot, "docs", "regression-fixtures.json");
const workerPath = path.join(repoRoot, "workers", "scan-api", "src", "index.js");

function loadScanner() {
  const source = fs.readFileSync(workerPath, "utf8")
    .replace(/\bexport\s+default\b/, "const __workerDefault =");
  const context = {
    console,
    crypto: {
      randomUUID: () => "00000000-0000-4000-8000-000000000000",
      getRandomValues: (arr) => arr.fill(0),
      subtle: {},
    },
    fetch: async () => { throw new Error("network disabled in regression runner"); },
    AbortSignal: { timeout: () => undefined },
    TextEncoder,
    TextDecoder,
    URL,
    Date,
    setTimeout,
    clearTimeout,
  };
  vm.createContext(context);
  vm.runInContext(`${source}\nthis.__scanner = { computeScore, validateFindingEvidence, applyEvidenceQuality };`, context, {
    filename: workerPath,
  });
  return context.__scanner;
}

function fail(message) {
  console.error(`Fixture validation failed: ${message}`);
  process.exitCode = 1;
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function expectedFinding(fixture) {
  return fixture.expected_finding ?? null;
}

function validateFixtureSchema(fixture, index) {
  assert(typeof fixture.scenario === "string" && fixture.scenario.length > 0, `fixture ${index} missing scenario`);
  assert(typeof fixture.description === "string" && fixture.description.length > 0, `${fixture.scenario} missing description`);
  assert(fixture.mock_modules && typeof fixture.mock_modules === "object", `${fixture.scenario} missing mock_modules`);

  const expected = expectedFinding(fixture);
  if (expected) {
    assert(typeof expected.id === "string", `${fixture.scenario} expected_finding missing id`);
    assert(["critical", "high", "medium", "low", "info"].includes(expected.severity), `${fixture.scenario} invalid severity`);
    assert(["high", "medium", "low"].includes(expected.confidence), `${fixture.scenario} invalid confidence`);
    assert(typeof expected.score_impact === "number", `${fixture.scenario} score_impact must be numeric`);
  }

  if (fixture.expected_findings) {
    assert(Array.isArray(fixture.expected_findings), `${fixture.scenario} expected_findings must be an array`);
  }

  if (fixture.expected_finding_ids_absent) {
    assert(Array.isArray(fixture.expected_finding_ids_absent), `${fixture.scenario} expected_finding_ids_absent must be an array`);
  }
}

function resolveExpectedValue(value, domain) {
  return typeof value === "string" ? value.replaceAll("<domain>", domain) : value;
}

function compareExpectedFinding(fixture, findings, domain) {
  const expected = expectedFinding(fixture);
  if (!expected) return [];

  const failures = [];
  const actual = findings.find((f) => f.id === expected.id);
  if (!actual) return [`missing expected finding ${expected.id}`];

  for (const key of ["severity", "confidence", "score_impact"]) {
    if (actual[key] !== expected[key]) {
      failures.push(`${expected.id} ${key}: expected ${expected[key]}, got ${actual[key]}`);
    }
  }

  if (expected.evidence_type && actual.evidence?.evidence_type !== expected.evidence_type) {
    failures.push(`${expected.id} evidence_type: expected ${expected.evidence_type}, got ${actual.evidence?.evidence_type}`);
  }

  if (expected.has_manual_verification_command && !actual.evidence?.manual_verification_command) {
    failures.push(`${expected.id} missing manual verification command`);
  }

  if (expected.evidence) {
    for (const [key, value] of Object.entries(expected.evidence)) {
      const resolved = resolveExpectedValue(value, domain);
      if (actual.evidence?.[key] !== resolved) {
        failures.push(`${expected.id} evidence.${key}: expected ${String(resolved)}, got ${String(actual.evidence?.[key])}`);
      }
    }
  }

  if (!actual.evidence_quality || actual.evidence_quality === "missing") {
    failures.push(`${expected.id} missing usable evidence quality`);
  }

  return failures;
}

function runFixture(scanner, fixture) {
  const domain = fixture.domain || "fixture.cybermeters.test";
  const result = scanner.computeScore(fixture.mock_modules, domain);
  const findings = result.findings || [];
  const findingIds = new Set(findings.map((f) => f.id));
  const failures = compareExpectedFinding(fixture, findings, domain);

  for (const id of fixture.expected_finding_ids_absent || []) {
    if (findingIds.has(id)) failures.push(`unexpected finding ${id}`);
  }

  for (const expected of fixture.expected_findings || []) {
    if (!findingIds.has(expected.id || expected)) {
      failures.push(`missing expected finding ${expected.id || expected}`);
    }
  }

  return {
    scenario: fixture.scenario,
    passed: failures.length === 0,
    failures,
    findings: findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      confidence: f.confidence,
      score_impact: f.score_impact,
      evidence_quality: f.evidence_quality,
    })),
  };
}

const raw = fs.readFileSync(fixturePath, "utf8");
const parsed = JSON.parse(raw);

assert(Array.isArray(parsed.fixtures), "top-level fixtures must be an array");
assert(parsed.fixtures.length > 0, "fixtures array must not be empty");

const scenarios = new Set();
parsed.fixtures.forEach((fixture, index) => {
  validateFixtureSchema(fixture, index);
  assert(!scenarios.has(fixture.scenario), `duplicate scenario: ${fixture.scenario}`);
  scenarios.add(fixture.scenario);
});

if (process.exitCode) process.exit(process.exitCode);

const scanner = loadScanner();
const results = parsed.fixtures.map((fixture) => runFixture(scanner, fixture));
const passed = results.filter((r) => r.passed).length;
const passRate = Math.round((passed / results.length) * 100);

for (const result of results) {
  const mark = result.passed ? "PASS" : "FAIL";
  console.log(`${mark} ${result.scenario}`);
  for (const failure of result.failures) console.log(`  - ${failure}`);
}

console.log(`Regression pass rate: ${passed}/${results.length} (${passRate}%)`);

if (passed === results.length) {
  console.log("accuracy validation passed");
} else {
  console.error("accuracy validation failed");
  process.exit(1);
}
