#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const fixturePath = path.join(repoRoot, "docs", "regression-fixtures.json");
const workerPath = path.join(repoRoot, "workers", "scan-api", "src", "index.js");

function loadScanner(fetchImpl = async () => { throw new Error("network disabled in regression runner"); }) {
  const source = fs.readFileSync(workerPath, "utf8")
    .replace(/\bexport\s+default\b/, "const __workerDefault =");
  const context = {
    console,
    crypto: {
      randomUUID: () => "00000000-0000-4000-8000-000000000000",
      getRandomValues: (arr) => arr.fill(0),
      subtle: {},
    },
    fetch: fetchImpl,
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
    getEmailVerificationTokenStatus,
    isEmailVerificationResendCoolingDown,
    normalizeEmailRecipients,
    resolveEmailSender,
    getEmailFrontendOrigin,
    formatAlertEmail,
    buildAssetAlertEmail,
    deliverEmail,
    buildExecutiveReportV2,
    INTELLIGENCE_ENGINE_REGISTRY,
    resolveIntelligenceEngine,
    normalizeDiscoveredHostname,
    normalizeCertificateSanNames,
    filterWildcardBruteforceResults,
    providerForInfrastructureHostname,
    providerMetadataForHostname,
    classifyProviderInfrastructure,
    annotateExposureInfrastructure,
    deduplicateExposureAssets,
    consolidateInventoryAssetAliases,
    assetFingerprintSignals,
    runAdminSurfaceModule,
    runSaasExposureModule,
    runCertificateIntelligenceModule,
    buildCertificateOwnershipAssessment,
    parseDmarcRecord,
    parseSpfRecord,
    buildDmarcPolicyJourney,
    buildDkimDetail,
    parseBimiRecord,
    buildEmailTransportDetails,
    buildEmailRemediationActions,
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

async function asyncSecurityContract(scenario, check) {
  try {
    const passed = await check();
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
  securityContract("detection_literal_wildcard_certificate_ignored", () =>
    scanner.normalizeDiscoveredHostname("*.example.com", "example.com") === null &&
    scanner.normalizeDiscoveredHostname("api.example.com", "example.com") === "api.example.com" &&
    scanner.normalizeDiscoveredHostname("api.attacker.test", "example.com") === null &&
    JSON.stringify(scanner.normalizeCertificateSanNames(
      "*.example.com example.com api.example.com *.api.example.com",
      "example.com"
    )) === JSON.stringify(["example.com", "api.example.com"])
  ),
  securityContract("detection_wildcard_dns_bruteforce_classification", () => {
    const result = scanner.filterWildcardBruteforceResults({
      checked: 2,
      found: 2,
      items: [
        { hostname: "admin.example.com", ip_addresses: ["192.0.2.10"] },
        { hostname: "api.example.com", ip_addresses: ["192.0.2.20"] },
      ],
    }, ["192.0.2.10"]);
    return result.wildcard_filtered === 1 &&
      result.found === 1 &&
      result.items[0].hostname === "api.example.com" &&
      result.wildcard_observations[0].wildcard_match === true &&
      result.wildcard_observations[0].classification === "observation" &&
      result.wildcard_observations[0].confidence === 40 &&
      result.wildcard_observations[0].score_impact === 0;
  }),
  securityContract("detection_provider_infrastructure_registry", () =>
    scanner.providerForInfrastructureHostname("site.pages.dev") === "Cloudflare" &&
    scanner.providerForInfrastructureHostname("d111.cloudfront.net") === "AWS" &&
    scanner.providerForInfrastructureHostname("site.azurewebsites.net") === "Microsoft Azure" &&
    scanner.providerForInfrastructureHostname("site.global.fastly.net") === "Fastly" &&
    scanner.providerForInfrastructureHostname("site.edgekey.net") === "Akamai" &&
    scanner.providerForInfrastructureHostname("owner.github.io") === "GitHub Pages" &&
    scanner.providerForInfrastructureHostname("site.netlify.app") === "Netlify" &&
    scanner.providerForInfrastructureHostname("cname.vercel-dns.com") === "Vercel" &&
    scanner.providerMetadataForHostname("site.firebaseapp.com").service === "Google/Firebase Hosting" &&
    scanner.providerMetadataForHostname("site.gitlab.io").service === "GitLab Pages" &&
    scanner.providerMetadataForHostname("site.herokudns.com").service === "Heroku Hosting" &&
    scanner.providerMetadataForHostname("shop.myshopify.com").service === "Shopify" &&
    scanner.providerMetadataForHostname("site.wixdns.net").service === "Wix Hosting" &&
    scanner.providerMetadataForHostname("site.wordpress.com").service === "WordPress.com Hosting" &&
    scanner.providerMetadataForHostname("tenant.okta.com").service === "Okta Identity Cloud" &&
    scanner.providerMetadataForHostname("tenant.auth0.com").service === "Auth0" &&
    scanner.providerMetadataForHostname("tenant.sharepoint.com").service === "Microsoft 365"
  ),
  securityContract("detection_provider_asset_supporting_infrastructure", () => {
    const result = scanner.annotateExposureInfrastructure({
      assets: [{ host: "admin.example.com", url: "https://admin.example.com", status: 200, tech: [] }],
    }, [{ host: "admin.example.com", cname: "customer.github.io" }]);
    const asset = result.assets[0];
    return asset.provider_owned_infrastructure === true &&
      asset.infrastructure_provider === "GitHub Pages" &&
      asset.infrastructure_relationship === "supporting_infrastructure" &&
      asset.infrastructure_evidence === "dns_cname";
  }),
  securityContract("detection_provider_hostname_heuristic_is_observation", () => {
    const result = scanner.computeScore({
      dns: { resolves: true, has_mx: true },
      ssl: { https_available: true, http_redirects_to_https: true },
      email_security: {
        spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true },
      },
      subdomains: { count: 1, items: ["admin.example.com"], sensitive: [] },
      dns_bruteforce: { items: [] },
      subdomain_takeover: { risks: [] },
      asset_exposure: { assets: [{
        host: "admin.example.com", status: 200, reachable: true, title: "Welcome",
        tech: [], provider_owned_infrastructure: true, infrastructure_provider: "AWS",
      }] },
      brand_monitoring: null,
    }, "example.com");
    const ids = new Set(result.findings.map((finding) => finding.id));
    const observation = result.findings.find((finding) => finding.id === "asset_provider_infrastructure_observed");
    return !ids.has("asset_exposure_admin_interface") &&
      observation?.finding_type === "observation" &&
      observation?.confidence === 50 &&
      observation?.score_impact === 0 &&
      result.score === 100;
  }),
  securityContract("detection_wildcard_http_response_is_observation", () => {
    const result = scanner.computeScore({
      dns: { resolves: true, has_mx: true },
      ssl: { https_available: true, http_redirects_to_https: true },
      email_security: {
        spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true },
      },
      subdomains: {
        count: 1, items: ["admin.example.com"], sensitive: ["admin.example.com"], wildcard_dns: true,
      },
      dns_bruteforce: { items: [] },
      subdomain_takeover: { risks: [] },
      asset_exposure: { assets: [{ host: "admin.example.com", status: 200, reachable: true, title: "Welcome", tech: [] }] },
      brand_monitoring: null,
    }, "example.com");
    const finding = result.findings.find((item) => item.id === "subdomain_sensitive_admin_example_com");
    return finding?.finding_type === "observation" && finding?.confidence === 60 &&
      finding?.score_impact === 0 && result.score === 100;
  }),
  securityContract("detection_wildcard_certificate_signals_are_observations", () => {
    const result = scanner.runCertificateIntelligenceModule({
      ssl: { https_available: true, cert_expiry_days: 90 },
      subdomains: {
        wildcard_dns: true,
        items: ["admin.example.com"],
        sensitive: ["admin.example.com"],
        sources: { crt_sh: { count: 60 }, certspotter: { count: 60 } },
      },
      dns_bruteforce: { items: [{ hostname: "dev.example.com", wildcard_match: true }] },
    }, "example.com");
    return result.certificate_risk_level === "low" &&
      !result.issued_for_sensitive_hosts.includes("dev.example.com") &&
      result.suspicious_certificate_signals.every((signal) => signal.severity === "info");
  }),
  securityContract("detection_admin_hostname_only_is_observation", () => {
    const result = scanner.computeScore({
      dns: { resolves: true, has_mx: true },
      ssl: { https_available: true, http_redirects_to_https: true },
      email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
      subdomains: { count: 1, items: ["admin.example.com"], sensitive: [] },
      subdomain_takeover: { risks: [] },
      asset_exposure: { assets: [{ host: "admin.example.com", status: 200, reachable: true, title: "Welcome", tech: [] }] },
      brand_monitoring: null,
    }, "example.com");
    const ids = new Set(result.findings.map((finding) => finding.id));
    const observation = result.findings.find((finding) => finding.id === "asset_exposure_interface_observed");
    return !ids.has("asset_exposure_admin_interface") && observation?.finding_type === "observation" &&
      observation?.score_impact === 0 && result.score === 100;
  }),
  securityContract("detection_admin_hostname_and_title_is_finding", () => {
    const result = scanner.computeScore({
      dns: { resolves: true, has_mx: true },
      ssl: { https_available: true, http_redirects_to_https: true },
      email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
      subdomains: { count: 1, items: ["admin.example.com"], sensitive: [] },
      subdomain_takeover: { risks: [] },
      asset_exposure: { assets: [{ host: "admin.example.com", status: 200, reachable: true, title: "Administrator Login", tech: [] }] },
      brand_monitoring: null,
    }, "example.com");
    const finding = result.findings.find((item) => item.id === "asset_exposure_admin_interface");
    return finding?.finding_type === "finding" && finding?.confidence === 80 &&
      finding?.score_impact === -8 && result.score === 92;
  }),
  securityContract("detection_sensitive_products_are_findings", () => {
    const titles = ["Jenkins", "Grafana", "phpMyAdmin", "Kibana", "Prometheus", "Portainer", "SonarQube"];
    return titles.every((title) => {
      const result = scanner.computeScore({
        dns: { resolves: true, has_mx: true },
        ssl: { https_available: true, http_redirects_to_https: true },
        email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
        subdomains: { count: 0, items: [], sensitive: [] },
        subdomain_takeover: { risks: [] },
        asset_exposure: { assets: [{ host: "service.example.com", status: 200, reachable: true, title, tech: [] }] },
        brand_monitoring: null,
      }, "example.com");
      const finding = result.findings.find((item) => item.id === "asset_exposure_sensitive_tool");
      return finding?.finding_type === "finding" && finding?.confidence === 90 && finding?.score_impact === -10;
    });
  }),
  securityContract("detection_admin_module_separates_observations", () => {
    const result = scanner.runAdminSurfaceModule({ asset_exposure: { assets: [
      { host: "jenkins.example.com", reachable: true, status: 200, title: "Welcome", server: "nginx" },
      { host: "grafana.example.com", reachable: true, status: 200, title: "Grafana", server: "nginx" },
    ] } });
    return result.total === 1 && result.observed_total === 2 && result.observations.length === 1 &&
      result.services.find((service) => service.product === "Jenkins")?.finding_type === "observation" &&
      result.services.find((service) => service.product === "Grafana")?.finding_type === "finding";
  }),
  securityContract("detection_duplicate_asset_representations_collapse", () => {
    const deduped = scanner.deduplicateExposureAssets({ assets: [
      { host: "www.example.com", url: "https://www.example.com/", reachable: true, status: 200, tech: [] },
      { host: "example.com", url: "https://www.example.com/", reachable: true, status: 200, tech: [] },
    ] }, "example.com");
    const inventory = scanner.consolidateInventoryAssetAliases([
      { hostname: "example.com" }, { hostname: "www.example.com" },
    ], deduped.assets);
    return deduped.assets.length === 1 && deduped.duplicates_collapsed === 1 &&
      deduped.assets[0].aliases.includes("example.com") && deduped.assets[0].aliases.includes("www.example.com") &&
      inventory.every((asset) => asset.hostname === "example.com");
  }),
  securityContract("detection_saas_cname_is_provider_dependency", () => {
    const result = scanner.runSaasExposureModule({
      vendor_risk: { vendors: [{ name: "Zendesk", confidence: "high", evidence: [{ source: "cname" }] }] },
      asset_exposure: { assets: [{ host: "support.example.com", cname: "customer.zendesk.com" }] },
    });
    const dependency = result.dependencies[0];
    return result.detected === false && result.dependency_detected === true && result.total === 0 && result.observed_total === 1 &&
      dependency.classification === "provider_dependency" && dependency.finding_type === "observation" &&
      dependency.customer_exposure_confirmed === false && dependency.score_impact === 0;
  }),
  securityContract("detection_shared_certificate_reduces_ownership_confidence", () => {
    const result = scanner.runCertificateIntelligenceModule({
      ssl: {
        https_available: true,
        cert_subject: "example.com",
        cert_san_names: ["example.com"],
        cert_san_count: 1,
        cert_raw_san_count: 4,
        cert_wildcard_san_count: 1,
        cert_shared_san_count: 2,
        cert_age_days: 30,
      },
      subdomains: { items: [], sensitive: [], sources: {} },
    }, "example.com");
    return result.ownership.status === "shared_certificate" && result.ownership.confidence === 50 &&
      result.san_count === 1 && result.raw_san_count === 4 && result.wildcard_san_count === 1 &&
      result.certificate_age_days === 30 &&
      result.suspicious_certificate_signals.find((signal) => signal.signal === "shared_certificate_observed")?.severity === "info";
  }),
  securityContract("email_remediation_dmarc_parser", () => {
    const detail = scanner.parseDmarcRecord(
      "v=DMARC1; p=quarantine; sp=reject; pct=75; rua=mailto:agg@example.com,mailto:backup@example.com; ruf=mailto:forensic@example.com; adkim=s; aspf=r; fo=1",
      1,
    );
    return detail.valid === true && detail.policy === "quarantine" && detail.subdomain_policy === "reject" &&
      detail.percentage === 75 && detail.rua.length === 2 && detail.ruf.length === 1 &&
      detail.adkim === "s" && detail.aspf === "r" && detail.fo === "1" &&
      detail.has_reporting === true && detail.has_failure_reporting === true;
  }),
  securityContract("email_remediation_dmarc_policy_journey", () => {
    const missing = scanner.buildDmarcPolicyJourney(scanner.parseDmarcRecord(null, 0));
    const monitoring = scanner.buildDmarcPolicyJourney(scanner.parseDmarcRecord("v=DMARC1; p=none", 1));
    const quarantine = scanner.buildDmarcPolicyJourney(scanner.parseDmarcRecord("v=DMARC1; p=quarantine", 1));
    const reject = scanner.buildDmarcPolicyJourney(scanner.parseDmarcRecord("v=DMARC1; p=reject", 1));
    return missing.stage === "missing" && monitoring.stage === "monitoring" &&
      quarantine.stage === "partial_enforcement" && reject.stage === "full_enforcement";
  }),
  securityContract("email_remediation_dmarc_invalid_and_multiple", () => {
    const invalid = scanner.parseDmarcRecord("v=DMARC1; p=invalid; pct=abc", 1);
    const multiple = scanner.parseDmarcRecord("v=DMARC1; p=reject", 2);
    return invalid.valid === false && invalid.warnings.some((warning) => warning.includes("policy")) &&
      invalid.warnings.some((warning) => warning.includes("pct")) &&
      multiple.valid === false && multiple.warnings.some((warning) => warning.includes("Multiple DMARC"));
  }),
  securityContract("email_remediation_spf_parser", () => {
    const detail = scanner.parseSpfRecord(
      "v=spf1 include:_spf.google.com include:sendgrid.net redirect=spf.example.net ip4:192.0.2.0/24 ip6:2001:db8::/32 -all",
      1,
    );
    return detail.valid === true && detail.includes.length === 2 && detail.redirects[0] === "spf.example.net" &&
      detail.ip4[0] === "192.0.2.0/24" && detail.ip6[0] === "2001:db8::/32" &&
      detail.all_mechanism === "-all" && detail.policy_strength === "strong" && detail.lookup_count_estimate === 3;
  }),
  securityContract("email_remediation_spf_weak_and_multiple", () => {
    const permissive = scanner.parseSpfRecord("v=spf1 +all", 1);
    const neutral = scanner.parseSpfRecord("v=spf1 ?all", 1);
    const soft = scanner.parseSpfRecord("v=spf1 ~all", 1);
    const multiple = scanner.parseSpfRecord("v=spf1 -all", 2);
    return permissive.policy_strength === "weak" && neutral.policy_strength === "neutral" &&
      soft.policy_strength === "soft" && multiple.valid === false &&
      multiple.warnings.some((warning) => warning.includes("Multiple SPF"));
  }),
  securityContract("email_remediation_spf_lookup_limit_and_ptr", () => {
    const includes = Array.from({ length: 10 }, (_, index) => `include:sender${index}.example.net`).join(" ");
    const detail = scanner.parseSpfRecord(`v=spf1 ${includes} ptr -all`, 1);
    return detail.lookup_count_estimate === 11 && detail.warnings.some((warning) => warning.includes("at most 10")) &&
      detail.warnings.some((warning) => warning.includes("ptr mechanism"));
  }),
  securityContract("email_remediation_dkim_and_bimi_detail", () => {
    const dkim = scanner.buildDkimDetail({ present: false, provider: "google", selectors_probed: ["google"] });
    const dmarc = scanner.parseDmarcRecord("v=DMARC1; p=none", 1);
    const bimi = scanner.parseBimiRecord("v=BIMI1; l=https://example.com/logo.svg", dmarc);
    return dkim.status === "uncertain" && dkim.confidence === "medium" &&
      dkim.explanation.includes("custom selector") && bimi.record_found === true &&
      bimi.logo_url === "https://example.com/logo.svg" && bimi.certificate_url === null &&
      bimi.blockers.length === 1 && bimi.warnings.length === 1 && bimi.gmail_ready === "unknown";
  }),
  securityContract("email_remediation_action_generation", () => {
    const dmarc = scanner.parseDmarcRecord("v=DMARC1; p=none; pct=50", 1);
    const spf = scanner.parseSpfRecord("v=spf1 ptr ~all", 1);
    const dkim = scanner.buildDkimDetail({ present: false });
    const bimi = scanner.parseBimiRecord(null, dmarc);
    const actions = scanner.buildEmailRemediationActions("example.com", {
      dmarc_detail: dmarc,
      spf_detail: spf,
      dkim_detail: dkim,
      bimi_readiness: bimi,
    }, {
      mta_sts: { enabled: false, errors: [] },
      tls_rpt: { enabled: false, reporting_uris: [], errors: [] },
    });
    const ids = new Set(actions.map((action) => action.id));
    return [
      "dmarc_policy_monitoring_only", "dmarc_reporting_missing", "dmarc_partial_percentage",
      "spf_softfail_all", "spf_ptr_mechanism", "dkim_verification_uncertain",
      "bimi_not_configured", "mta_sts_policy_missing", "tls_rpt_missing",
    ].every((id) => ids.has(id)) &&
      actions.every((action) => action.category === "email_authentication" && action.status === "open");
  }),
  securityContract("email_remediation_missing_multiple_and_permissive_actions", () => {
    const missingDmarc = scanner.parseDmarcRecord(null, 0);
    const missingSpf = scanner.parseSpfRecord(null, 0);
    const missingActions = scanner.buildEmailRemediationActions("example.com", {
      dmarc_detail: missingDmarc,
      spf_detail: missingSpf,
      dkim_detail: scanner.buildDkimDetail({ present: true, selector: "selector1" }),
      bimi_readiness: scanner.parseBimiRecord(null, missingDmarc),
    });
    const multipleActions = scanner.buildEmailRemediationActions("example.com", {
      dmarc_detail: scanner.parseDmarcRecord("v=DMARC1; p=reject", 2),
      spf_detail: scanner.parseSpfRecord("v=spf1 +all", 2),
      dkim_detail: scanner.buildDkimDetail({ present: true, selector: "selector1" }),
      bimi_readiness: scanner.parseBimiRecord("v=BIMI1; l=https://example.com/logo.svg", scanner.parseDmarcRecord("v=DMARC1; p=reject", 2)),
    });
    const missingIds = new Set(missingActions.map((action) => action.id));
    const multipleIds = new Set(multipleActions.map((action) => action.id));
    return missingIds.has("dmarc_missing") && missingIds.has("spf_missing") &&
      multipleIds.has("dmarc_multiple_records") && multipleIds.has("spf_multiple_records") &&
      multipleIds.has("spf_permissive_all") && multipleIds.has("bimi_certificate_not_listed");
  }),
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
  securityContract("email_verification_new_account_token_valid", () =>
    scanner.getEmailVerificationTokenStatus({
      email_verified: 0,
      verification_token_expires_at: "2026-06-28T12:00:00.000Z",
    }, Date.parse("2026-06-27T12:00:00.000Z")) === "valid"
  ),
  securityContract("email_verification_invalid_token", () =>
    scanner.getEmailVerificationTokenStatus(null, Date.parse("2026-06-27T12:00:00.000Z")) === "invalid"
  ),
  securityContract("email_verification_expired_token", () =>
    scanner.getEmailVerificationTokenStatus({
      email_verified: 0,
      verification_token_expires_at: "2026-06-27T11:59:59.000Z",
    }, Date.parse("2026-06-27T12:00:00.000Z")) === "expired" &&
    scanner.getEmailVerificationTokenStatus({
      email_verified: 0,
      verification_token_expires_at: null,
    }, Date.parse("2026-06-27T12:00:00.000Z")) === "expired"
  ),
  securityContract("email_verification_already_verified_account", () =>
    scanner.getEmailVerificationTokenStatus({
      email_verified: 1,
      verification_token_expires_at: null,
    }, Date.parse("2026-06-27T12:00:00.000Z")) === "already_verified"
  ),
  securityContract("email_verification_resend_cooldown", () => {
    const now = Date.parse("2026-06-27T12:00:00.000Z");
    return scanner.isEmailVerificationResendCoolingDown("2026-06-28T11:59:30.000Z", now) &&
      !scanner.isEmailVerificationResendCoolingDown("2026-06-28T11:58:59.000Z", now) &&
      !scanner.isEmailVerificationResendCoolingDown(null, now);
  }),
  securityContract("email_delivery_sender_identity", () =>
    scanner.resolveEmailSender({ HELLO_EMAIL_FROM: "hello@cybermeters.com" }, "HELLO_EMAIL_FROM") === "hello@cybermeters.com" &&
    scanner.resolveEmailSender({ HELLO_EMAIL_FROM: "invalid" }, "HELLO_EMAIL_FROM") === null &&
    scanner.resolveEmailSender({ UNKNOWN_FROM: "sender@cybermeters.com" }, "UNKNOWN_FROM") === null
  ),
  securityContract("email_delivery_recipient_normalization", () => {
    const recipients = scanner.normalizeEmailRecipients([
      " Owner@Example.com ", "owner@example.com", "invalid", "admin@example.com",
    ]);
    return recipients.length === 2 && recipients[0] === "owner@example.com" && recipients[1] === "admin@example.com";
  }),
  securityContract("email_delivery_frontend_origin", () =>
    scanner.getEmailFrontendOrigin({ FRONTEND_URL: "https://app.cybermeters.com/path" }) === "https://app.cybermeters.com" &&
    scanner.getEmailFrontendOrigin({ FRONTEND_URL: "http://app.cybermeters.com" }) === null &&
    scanner.getEmailFrontendOrigin({ FRONTEND_URL: "not-a-url" }) === null
  ),
  securityContract("email_alert_template_rendering", () => {
    const rendered = scanner.formatAlertEmail({
      workspaceName: "<Workspace>",
      domain: "example.com",
      whatChanged: "Finding <script>",
      recommendation: "Review & fix",
      link: "https://app.cybermeters.com/scans/scan_1",
    });
    return rendered.text.includes("example.com") &&
      rendered.html.includes("&lt;Workspace&gt;") &&
      rendered.html.includes("Finding &lt;script&gt;") &&
      rendered.html.includes("Review &amp; fix") &&
      rendered.html.includes("https://app.cybermeters.com/scans/scan_1") &&
      !rendered.html.includes("${domain}");
  }),
  securityContract("email_scheduled_asset_alert_rendering", () => {
    const rendered = scanner.buildAssetAlertEmail(
      "example.com",
      "workspace_1",
      "scan_1",
      { new_asset_discovered: 1 },
      ["<admin>.example.com"],
      "high",
      "https://app.cybermeters.com/assets",
    );
    return rendered.subject.includes("example.com") &&
      rendered.text.includes("https://app.cybermeters.com/assets") &&
      rendered.html.includes("&lt;admin&gt;.example.com") &&
      !rendered.html.includes("cybermeters.pages.dev");
  }),
);

const acceptedRequests = [];
const acceptedEmailScanner = loadScanner(async (requestUrl, options) => {
  acceptedRequests.push({ requestUrl, options });
  return { ok: true, status: 200, json: async () => ({ id: "email_test_1" }) };
});
results.push(await asyncSecurityContract("email_delivery_provider_acceptance", async () => {
  const delivery = await acceptedEmailScanner.deliverEmail(
    "Security alert\r\nInjected",
    "Plain text body",
    "<p>HTML body</p>",
    { RESEND_API_KEY: "test-key", ALERT_EMAIL_FROM: "alerts@cybermeters.com" },
    "ALERT_EMAIL_FROM",
    ["owner@example.com"],
  );
  const payload = JSON.parse(acceptedRequests[0]?.options?.body || "{}");
  return delivery.sent === true && delivery.provider_id === "email_test_1" &&
    acceptedRequests[0]?.requestUrl === "https://api.resend.com/emails" &&
    payload.subject === "Security alert Injected" &&
    payload.from === "alerts@cybermeters.com" &&
    payload.to?.[0] === "owner@example.com";
}));

const rejectedEmailScanner = loadScanner(async () => ({ ok: false, status: 429, json: async () => ({}) }));
results.push(await asyncSecurityContract("email_delivery_provider_rejection", async () => {
  const delivery = await rejectedEmailScanner.deliverEmail(
    "Security alert",
    "Plain text body",
    "<p>HTML body</p>",
    { RESEND_API_KEY: "test-key", ALERT_EMAIL_FROM: "alerts@cybermeters.com" },
    "ALERT_EMAIL_FROM",
    ["owner@example.com"],
  );
  return delivery.sent === false && delivery.reason === "provider_rejected" && delivery.status === 429;
}));

const executiveV2Fixture = scanner.buildExecutiveReportV2({
  scan: {
    id: "scan_contract_1",
    domain_id: "domain_contract_1",
    domain: "example.com",
    status: "completed",
    score: 77,
    rating: "good",
    created_at: "2026-06-27T10:00:00.000Z",
  },
  workspace: { id: "workspace_contract_1", name: "Contract Workspace" },
  generatedAt: "2026-06-27T12:00:00.000Z",
  rawReport: {
    cyber_metrics_score: 5,
    completed_at: "2026-06-27T10:01:00.000Z",
    findings: [
      {
        id: "dns_no_resolution",
        module: "dns",
        finding_type: "finding",
        severity: "critical",
        confidence: 90,
        score_impact: -30,
        title: "Domain Does Not Resolve",
        description: "No DNS response was observed.",
        recommendation: "Restore DNS resolution.",
      },
      {
        id: "email_dkim_not_detected",
        module: "email_security",
        finding_type: "observation",
        severity: "info",
        confidence: 60,
        score_impact: 0,
        title: "DKIM Could Not Be Verified Using Common Selectors",
        description: "A custom selector may exist.",
      },
    ],
    recommendations: [
      { priority: 1, module: "dns", title: "Fix DNS Configuration", description: "Restore DNS records." },
      { priority: 3, module: "email_security", title: "Verify DKIM Selector", description: "Review custom selectors." },
    ],
    modules: {
      dns: { resolves: false, has_mx: true, mx: [{ exchange: "mx.example.com" }] },
      ssl: { https_available: false },
      headers: { accessible: false },
      email_security: {
        spf: { present: true },
        dkim: { present: false, provider: "google" },
        dmarc: { present: true, policy: "reject" },
        spf_detail: { valid: true, includes: ["_spf.google.com"] },
        dmarc_detail: { valid: true, policy: "reject", has_reporting: true },
        dkim_detail: { status: "uncertain", confidence: "medium" },
        bimi_readiness: { record_found: false },
        policy_journey: { stage: "full_enforcement", label: "Reject" },
        remediation_actions: [{ id: "bimi_not_configured", protocol: "BIMI", status: "open" }],
      },
      email_security_intelligence: {
        mta_sts: { enabled: false },
        tls_rpt: { enabled: true },
        email_security_score: 75,
        rating: "Good",
      },
      historical_changes: { has_previous: false },
      remediation_plan: {
        p1_immediate: [{ title: "Domain Does Not Resolve", action: "Restore DNS resolution.", source: "dns" }],
        p2_high: [],
        p3_medium_low: [{ title: "DKIM Could Not Be Verified Using Common Selectors", source: "email_security" }],
      },
      vendor_risk: { vendors: [{ name: "Example Vendor" }] },
    },
  },
});

results.push(
  securityContract("intelligence_engine_registry_contains_all_engines", () =>
    ["attack_surface", "business_email", "identity", "brand", "executive"]
      .every((engine) => scanner.INTELLIGENCE_ENGINE_REGISTRY[engine]) &&
    Object.keys(scanner.INTELLIGENCE_ENGINE_REGISTRY).length === 5
  ),
  securityContract("intelligence_engine_registry_dns", () =>
    scanner.resolveIntelligenceEngine({ module: "dns", id: "dns_no_resolution" }) === "attack_surface"
  ),
  securityContract("intelligence_engine_registry_email", () =>
    scanner.resolveIntelligenceEngine({ module: "email_security", id: "email_missing_dmarc" }) === "business_email"
  ),
  securityContract("intelligence_engine_registry_identity", () =>
    scanner.resolveIntelligenceEngine({ module: "identity_discovery", id: "identity_provider_observed" }) === "identity"
  ),
  securityContract("intelligence_engine_registry_brand", () =>
    scanner.resolveIntelligenceEngine({ module: "brand_monitoring", id: "brand_lookalike_detected" }) === "brand"
  ),
  securityContract("intelligence_engine_registry_unknown_default", () =>
    scanner.resolveIntelligenceEngine({ module: "future_detector", id: "future_signal" }) === "attack_surface"
  ),
  securityContract("executive_report_v2_contract_shape", () =>
    executiveV2Fixture.version === "2.0" &&
    executiveV2Fixture.report_type === "executive" &&
    executiveV2Fixture.workspace.id === "workspace_contract_1" &&
    executiveV2Fixture.domain.scan_id === "scan_contract_1" &&
    executiveV2Fixture.cyber_metrics_score.value === 77 &&
    executiveV2Fixture.generated_at === "2026-06-27T12:00:00.000Z"
  ),
  securityContract("executive_report_v2_intelligence_engines", () =>
    ["attack_surface", "business_email", "identity", "brand", "executive"]
      .every((key) => executiveV2Fixture.intelligence_engines[key])
  ),
  securityContract("executive_report_v2_attack_surface", () =>
    executiveV2Fixture.intelligence_engines.attack_surface.evidence.dns.resolves === false &&
    executiveV2Fixture.intelligence_engines.attack_surface.evidence.ssl_tls.https_available === false &&
    executiveV2Fixture.intelligence_engines.attack_surface.findings[0].id === "dns_no_resolution"
  ),
  securityContract("executive_report_v2_business_email", () =>
    executiveV2Fixture.intelligence_engines.business_email.evidence.spf.present === true &&
    executiveV2Fixture.intelligence_engines.business_email.evidence.dmarc.policy === "reject" &&
    executiveV2Fixture.intelligence_engines.business_email.evidence.provider_detection === "google" &&
    executiveV2Fixture.intelligence_engines.business_email.evidence.remediation.policy_journey.stage === "full_enforcement" &&
    executiveV2Fixture.intelligence_engines.business_email.evidence.remediation.actions[0].id === "bimi_not_configured"
  ),
  securityContract("executive_report_v2_identity_fallback", () => {
    const identity = executiveV2Fixture.intelligence_engines.identity;
    return identity.status === "not_available" &&
      identity.summary === "Identity Intelligence is not enabled for this workspace yet." &&
      identity.findings.length === 0 && identity.observations.length === 0;
  }),
  securityContract("executive_report_v2_findings_observations_separated", () =>
    executiveV2Fixture.verified_findings.length === 1 &&
    executiveV2Fixture.verified_findings[0].id === "dns_no_resolution" &&
    executiveV2Fixture.observations.length === 1 &&
    executiveV2Fixture.observations[0].id === "email_dkim_not_detected" &&
    executiveV2Fixture.prioritized_remediation.every((item) => !item.title.includes("DKIM")) &&
    executiveV2Fixture.intelligence_engines.business_email.recommendations.length === 0
  ),
  securityContract("executive_report_v2_legacy_sections_not_top_level", () =>
    !("vendor_risk" in executiveV2Fixture) &&
    !("supply_chain" in executiveV2Fixture) &&
    !("cyber_essentials" in executiveV2Fixture) &&
    executiveV2Fixture.supporting_evidence.legacy_vendor_context.vendors.length === 1
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
