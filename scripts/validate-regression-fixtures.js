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
  vm.runInContext(`${source}\nthis.__scanner = {
    computeScore,
    validateFindingEvidence,
    applyEvidenceQuality,
    resolveCanonicalScanScore,
    riskLevelForScore,
    isValidDomain,
    isValidEmail,
    parseBoundedInteger,
    validateFrontendRedirectUrl,
    normalizeApiResponseData,
    validateMicrosoftIdTokenClaims,
    hasWorkspacePermission,
    computeBusinessRiskScoreFromIds: (ids, data) => computeBusinessRiskScore(new Set(ids), data),
  };`, context, {
    filename: workerPath,
  });
  return context.__scanner;
}

// Sprint 9E.1: mapping from legacy string confidence to numeric equivalents.
// Sprint 9B converted confidence from strings to numeric (0-100) at the
// report boundary. computeScore() still returns strings for most findings,
// but some findings (e.g. email_dkim_not_detected) were changed to numeric
// in Sprint 9D. This map normalises both sides of the comparison so fixtures
// written with numeric expected values work against the current string-returning
// computeScore(), and will continue to work when computeScore is fully numeric.
const CONFIDENCE_NUMERIC_MAP = {
  confirmed: 95,
  high:      90,
  medium:    70,
  low:       60,
};

function normalizeConfidence(c) {
  if (typeof c === "number") return c;
  return CONFIDENCE_NUMERIC_MAP[c] ?? null;
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
    // Accept numeric (Sprint 9B format) or legacy strings for backward compat
    const confValid = (typeof expected.confidence === "number" && expected.confidence >= 0 && expected.confidence <= 100)
      || Object.keys(CONFIDENCE_NUMERIC_MAP).includes(expected.confidence);
    assert(confValid, `${fixture.scenario} invalid confidence (expected numeric 0-100 or one of: ${Object.keys(CONFIDENCE_NUMERIC_MAP).join(", ")})`);
    assert(typeof expected.score_impact === "number", `${fixture.scenario} score_impact must be numeric`);
  }

  if (fixture.expected_findings) {
    assert(Array.isArray(fixture.expected_findings), `${fixture.scenario} expected_findings must be an array`);
  }

  if (fixture.expected_finding_ids_absent) {
    assert(Array.isArray(fixture.expected_finding_ids_absent), `${fixture.scenario} expected_finding_ids_absent must be an array`);
  }

  if (fixture.expected_score !== undefined) {
    assert(Number.isInteger(fixture.expected_score), `${fixture.scenario} expected_score must be an integer`);
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

  for (const key of ["severity", "score_impact"]) {
    if (actual[key] !== expected[key]) {
      failures.push(`${expected.id} ${key}: expected ${expected[key]}, got ${actual[key]}`);
    }
  }
  // Confidence: normalize both sides to numeric before comparing.
  // computeScore() returns strings for most findings; some Sprint 9D findings
  // return numeric. Fixtures should use numeric values (Sprint 9B scale) but
  // legacy strings are accepted for backward compat.
  {
    const actualConf   = normalizeConfidence(actual.confidence);
    const expectedConf = normalizeConfidence(expected.confidence);
    if (actualConf !== expectedConf) {
      failures.push(`${expected.id} confidence: expected ${expected.confidence} (→${expectedConf}), got ${actual.confidence} (→${actualConf})`);
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

  // finding_type: "finding" | "observation" — Sprint 10A additive field.
  // Only checked when explicitly listed in the fixture.
  if (expected.finding_type !== undefined) {
    if (actual.finding_type !== expected.finding_type) {
      failures.push(`${expected.id} finding_type: expected ${expected.finding_type}, got ${actual.finding_type}`);
    }
  }

  if (expected.title !== undefined && actual.title !== expected.title) {
    failures.push(`${expected.id} title: expected "${expected.title}", got "${actual.title}"`);
  }

  if (Array.isArray(expected.description_contains)) {
    for (const substring of expected.description_contains) {
      if (!String(actual.description ?? "").includes(substring)) {
        failures.push(`${expected.id} description missing expected text: "${substring}"`);
      }
    }
  }

  // evidence_contains: array of substrings that must ALL appear somewhere in
  // evidence.observed_value.  Preferred over exact-matching observed_value for
  // outputs that list dynamic content (e.g. selector lists that grow over time).
  if (Array.isArray(expected.evidence_contains)) {
    const observedStr = String(actual.evidence?.observed_value ?? "");
    for (const substring of expected.evidence_contains) {
      if (!observedStr.includes(substring)) {
        failures.push(`${expected.id} evidence.observed_value missing expected text: "${substring}" (got: ${observedStr.slice(0, 120)})`);
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

  if (fixture.expected_score !== undefined && result.score !== fixture.expected_score) {
    failures.push(`score: expected ${fixture.expected_score}, got ${result.score}`);
  }

  for (const id of fixture.expected_finding_ids_absent || []) {
    if (findingIds.has(id)) failures.push(`unexpected finding ${id}`);
  }

  for (const expected of fixture.expected_findings || []) {
    if (!findingIds.has(expected.id || expected)) {
      failures.push(`missing expected finding ${expected.id || expected}`);
    }
  }

  for (const title of fixture.expected_recommendation_titles_absent || []) {
    if ((result.recommendations || []).some((recommendation) => recommendation.title === title)) {
      failures.push(`unexpected recommendation ${title}`);
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

function securityContract(scenario, check) {
  try {
    const passed = check();
    return { scenario, passed, failures: passed ? [] : ["security contract returned false"], findings: [] };
  } catch (error) {
    return { scenario, passed: false, failures: [error.message], findings: [] };
  }
}

function rejects(check) {
  try { check(); return false; } catch { return true; }
}

const validMicrosoftClaims = {
  aud: "client-id",
  exp: 2000,
  nbf: 900,
  oid: "object-id",
  tid: "tenant-id",
  iss: "https://login.microsoftonline.com/tenant-id/v2.0",
  nonce: "expected-nonce",
};

results.push(
  securityContract("security_valid_domain_contract", () =>
    scanner.isValidDomain("example.co.uk") &&
    !scanner.isValidDomain(".example.com") &&
    !scanner.isValidDomain("example..com") &&
    !scanner.isValidDomain("-example.com")
  ),
  securityContract("security_email_length_contract", () =>
    scanner.isValidEmail("user@example.com") &&
    !scanner.isValidEmail(`${"a".repeat(250)}@example.com`)
  ),
  securityContract("security_pagination_bounds_contract", () =>
    scanner.parseBoundedInteger("invalid", 50, 1, 100) === 50 &&
    scanner.parseBoundedInteger("999", 50, 1, 100) === 100 &&
    scanner.parseBoundedInteger("-1", 50, 1, 100) === 1
  ),
  securityContract("security_redirect_origin_contract", () =>
    scanner.validateFrontendRedirectUrl("https://app.cybermeters.com/billing", { FRONTEND_URL: "https://app.cybermeters.com" }) !== null &&
    scanner.validateFrontendRedirectUrl("https://attacker.example/billing", { FRONTEND_URL: "https://app.cybermeters.com" }) === null &&
    scanner.validateFrontendRedirectUrl("http://app.cybermeters.com/billing", { FRONTEND_URL: "https://app.cybermeters.com" }) === null
  ),
  securityContract("security_error_shape_contract", () => {
    const shaped = scanner.normalizeApiResponseData({ error: "Database error", detail: "sensitive", stack: "trace" }, 500);
    return shaped.error === "Database error" && shaped.code === "server_error" && !("detail" in shaped) && !("stack" in shaped);
  }),
  securityContract("security_rbac_fail_closed_contract", () =>
    scanner.hasWorkspacePermission("owner", "unknown:permission") === false &&
    scanner.hasWorkspacePermission("admin", "billing:manage") === false &&
    scanner.hasWorkspacePermission("owner", "billing:manage") === true
  ),
  securityContract("security_oidc_claims_contract", () => {
    scanner.validateMicrosoftIdTokenClaims(
      { alg: "RS256", kid: "key-id" },
      validMicrosoftClaims,
      "client-id",
      "tenant-id",
      "expected-nonce",
      1000,
    );
    return true;
  }),
  securityContract("security_oidc_algorithm_rejection", () =>
    rejects(() => scanner.validateMicrosoftIdTokenClaims(
      { alg: "none", kid: "key-id" }, validMicrosoftClaims, "client-id", "tenant-id", "expected-nonce", 1000
    ))
  ),
  securityContract("security_oidc_tenant_nonce_rejection", () =>
    rejects(() => scanner.validateMicrosoftIdTokenClaims(
      { alg: "RS256", kid: "key-id" }, validMicrosoftClaims, "client-id", "other-tenant", "expected-nonce", 1000
    )) && rejects(() => scanner.validateMicrosoftIdTokenClaims(
      { alg: "RS256", kid: "key-id" }, validMicrosoftClaims, "client-id", "tenant-id", "wrong-nonce", 1000
    ))
  ),
);

for (const contract of parsed.score_contracts || []) {
  const actualScore = scanner.resolveCanonicalScanScore(contract.d1_score, contract.report_score);
  const actualRating = scanner.riskLevelForScore(actualScore);
  results.push({
    scenario: contract.scenario,
    passed: actualScore === contract.expected_score && actualRating === contract.expected_rating,
    failures: [
      ...(actualScore === contract.expected_score ? [] : [`score: expected ${contract.expected_score}, got ${actualScore}`]),
      ...(actualRating === contract.expected_rating ? [] : [`rating: expected ${contract.expected_rating}, got ${actualRating}`]),
    ],
    findings: [],
  });
}

for (const contract of parsed.business_risk_contracts || []) {
  const result = scanner.computeBusinessRiskScoreFromIds(contract.finding_ids, contract.workspace_data || {});
  results.push({
    scenario: contract.scenario,
    passed: result.score === contract.expected_score,
    failures: result.score === contract.expected_score
      ? []
      : [`business risk score: expected ${contract.expected_score}, got ${result.score}`],
    findings: [],
  });
}
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
