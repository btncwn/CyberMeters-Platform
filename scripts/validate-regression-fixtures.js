#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
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
      // randomUUID stays deterministic so existing id-dependent fixtures are stable.
      randomUUID: () => "00000000-0000-4000-8000-000000000000",
      // Real entropy + real SHA-256 so token/hash helpers behave as in production.
      getRandomValues: (arr) => webcrypto.getRandomValues(arr),
      subtle: webcrypto.subtle,
    },
    btoa: (s) => Buffer.from(String(s), "binary").toString("base64"),
    atob: (s) => Buffer.from(String(s), "base64").toString("binary"),
    // Streams/Response for inbound RUA decompression helpers (present in Workers
    // and in Node 18+); CompressionStream is used by tests to build fixtures.
    Response,
    DecompressionStream,
    CompressionStream,
    Uint8Array,
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
    inferBrandProfileFromDomains,
    buildBrandProfileDomainScope,
    filterBrandCandidatesToProfile,
    validateBrandProfileInput,
    scoreBrandCandidateRisk,
    brandCandidateToApi,
    buildBrandProtectionSummary,
    brandClassificationAuditMetadata,
    parseBrandCandidateListParams,
    legacyBrandAssetToApi,
    parseDmarcRecord,
    buildDmarcDnsRecommendedValue,
    verifyDmarcDnsSetup,
    parseSpfRecord,
    buildDmarcPolicyJourney,
    buildDkimDetail,
    parseBimiRecord,
    buildEmailTransportDetails,
    buildEmailRemediationActions,
    parseDmarcAggregateXml,
    guessEmailSenderProvider,
    updateEmailSenderSources,
    summarizeEmailSenders,
    buildDmarcEnforcementReadiness,
    buildDmarcReportRemediationActions,
    buildDmarcBusinessRisk,
    computeBecExposureScore,
    cybermetersRuaPresentInDmarcRecord,
    dmarcSenderRiskLevel,
    dmarcReportIdentity,
    dmarcReportDomainMatches,
    generateIngestToken,
    hashIngestToken,
    ingestEndpointIsActive,
    ingestEndpointToApi,
    ensureCloudflareEmailRoute,
    revokeCloudflareEmailRoute,
    persistDmarcRouteResult,
    auditDmarcRouteResult,
    configureDmarcEndpointRoute,
    generateInboundLocalpart,
    normalizeInboundRecipientDomain,
    parseInboundRecipient,
    extractInboundLocalpart,
    gunzipXmlBytes,
    unzipSingleEntryXmlBytes,
    extractDmarcXmlFromAttachment,
    parseMimeParts,
    selectDmarcAttachment,
    normalizeInboundDropReason,
    sanitizeInfraErrorMessage,
    ingestDmarcReport,
    emailHandler: __workerDefault.email,
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
    scanner.hasWorkspacePermission("owner", "billing:manage") === true &&
    scanner.hasWorkspacePermission("analyst", "workspace:manage") === false &&
    scanner.hasWorkspacePermission("admin", "workspace:manage") === true
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

results.push(
  securityContract("brand_profile_default_inference_safe", () => {
    const profile = scanner.inferBrandProfileFromDomains("workspace-1", [
      { domain: "example.com" }, { domain: "shop.example.net" }, { domain: "invalid domain" },
    ]);
    return profile?.inferred === true && profile.inference_confidence === "low" &&
      profile.brand_name === "example" && profile.primary_domain === "example.com" &&
      profile.keywords.length === 0 && profile.protected_domains.length === 1 &&
      profile.protected_domains[0] === "example.com" && profile.id === null;
  }),
  securityContract("brand_profile_inference_single_primary_domain", () => {
    const profile = scanner.inferBrandProfileFromDomains("workspace-1", [
      { domain: "blackbullbarbers.co.uk" }, { domain: "cloudflare.com" },
      { domain: "google.com" }, { domain: "tesla.com" },
    ]);
    return profile.brand_name === "blackbullbarbers" &&
      profile.primary_domain === "blackbullbarbers.co.uk" &&
      JSON.stringify(profile.protected_domains) === JSON.stringify(["blackbullbarbers.co.uk"]);
  }),
  securityContract("brand_candidates_scoped_to_protected_domains", () => {
    const profile = { primary_domain: "blackbullbarbers.co.uk", protected_domains: ["blackbullbarbers.co.uk"] };
    const candidates = scanner.filterBrandCandidatesToProfile([
      { domain: "blackbullbarbers.co.uk", candidate_domain: "blackbullbarber5.co.uk" },
      { domain: "google.com", candidate_domain: "g00gle.com" },
      { domain: "tesla.com", candidate_domain: "tes1a.com" },
    ], profile);
    const scope = scanner.buildBrandProfileDomainScope(profile);
    return candidates.length === 1 && candidates[0].domain === "blackbullbarbers.co.uk" &&
      scope.clause === "domain IN (?)" &&
      JSON.stringify(scope.bindings) === JSON.stringify(["blackbullbarbers.co.uk"]);
  }),
  securityContract("brand_summary_scoped_to_protected_domains", () => {
    const profile = { primary_domain: "blackbullbarbers.co.uk", protected_domains: ["blackbullbarbers.co.uk"] };
    const scoped = scanner.filterBrandCandidatesToProfile([
      { domain: "blackbullbarbers.co.uk", dns_active: true, risk_level: "high", classification: "suspicious" },
      { domain: "google.com", dns_active: true, risk_level: "critical", classification: "confirmed_abuse" },
    ], profile);
    const summary = scanner.buildBrandProtectionSummary(scoped);
    return summary.total_candidates === 1 && summary.active_dns === 1 && summary.high_risk === 1 &&
      summary.suspicious === 1 && summary.confirmed_abuse === 0;
  }),
  securityContract("brand_summary_high_risk_matches_candidate_serialization", () => {
    const profile = { brand_name: "blackbullbarbers", primary_domain: "blackbullbarbers.co.uk",
      protected_domains: ["blackbullbarbers.co.uk"] };
    const candidate = scanner.brandCandidateToApi({
      id: "bra-summary-1", domain: "blackbullbarbers.co.uk",
      candidate_domain: "account-blackbullbarbers.co.uk", variant_type: "keyword_abuse",
      similarity_score: 90, risk_level: "low", dns_resolves: 1, https_available: 1,
      classification: "unreviewed", status: "active", first_seen: "2020-01-01",
    }, profile);
    const summary = scanner.buildBrandProtectionSummary([candidate]);
    return ["critical", "high"].includes(candidate.risk_level) && summary.high_risk === 1;
  }),
  securityContract("brand_summary_ignores_stale_stored_risk_level", () => {
    const profile = { brand_name: "blackbullbarbers", primary_domain: "blackbullbarbers.co.uk",
      protected_domains: ["blackbullbarbers.co.uk"] };
    const rows = [
      { id: "bra-summary-2", domain: "blackbullbarbers.co.uk",
        candidate_domain: "blackbullbarbers-login.co.uk", variant_type: "keyword_abuse",
        similarity_score: 94, risk_level: "info", dns_resolves: 1, https_available: 1,
        classification: "unreviewed", status: "active", first_seen: "2020-01-01" },
    ];
    const candidates = rows.map((row) => scanner.brandCandidateToApi(row, profile));
    const summary = scanner.buildBrandProtectionSummary(candidates);
    return rows[0].risk_level === "info" && ["critical", "high"].includes(candidates[0].risk_level) &&
      summary.high_risk === 1;
  }),
  securityContract("brand_summary_normalized_scope_excludes_unrelated_domains", () => {
    const profile = { brand_name: "blackbullbarbers", primary_domain: "blackbullbarbers.co.uk",
      protected_domains: ["blackbullbarbers.co.uk"] };
    const rows = [
      { id: "bra-summary-3", domain: "blackbullbarbers.co.uk", candidate_domain: "blackbullbarbers-login.co.uk",
        variant_type: "keyword_abuse", similarity_score: 94, dns_resolves: 1, classification: "unreviewed" },
      { id: "bra-summary-4", domain: "tesla.com", candidate_domain: "tesla-login.com",
        variant_type: "keyword_abuse", similarity_score: 95, dns_resolves: 1, classification: "confirmed_abuse" },
    ];
    const candidates = scanner.filterBrandCandidatesToProfile(rows, profile)
      .map((row) => scanner.brandCandidateToApi(row, profile));
    const summary = scanner.buildBrandProtectionSummary(candidates);
    return summary.total_candidates === 1 && summary.high_risk === 1 && summary.confirmed_abuse === 0;
  }),
  securityContract("brand_summary_closed_classifications_not_high_risk", () => {
    const profile = { brand_name: "example", primary_domain: "example.com", protected_domains: ["example.com"] };
    const candidates = ["owned", "ignored", "false_positive"].map((classification, index) =>
      scanner.brandCandidateToApi({
        id: `bra-closed-${index}`, domain: "example.com", candidate_domain: `example-login-${index}.top`,
        variant_type: "keyword_abuse", similarity_score: 100, dns_resolves: 1, https_available: 1,
        mx_present: 1, risk_level: "critical", classification, status: "active", first_seen: "2020-01-01",
      }, profile));
    const summary = scanner.buildBrandProtectionSummary(candidates);
    return summary.total_candidates === 3 && summary.high_risk === 0 && summary.owned === 1 &&
      summary.ignored === 1 && candidates.every((candidate) => candidate.risk_level === "info");
  }),
  securityContract("brand_unrelated_workspace_domains_do_not_pollute_protection", () => {
    const profile = scanner.inferBrandProfileFromDomains("workspace-1", [
      { domain: "blackbullbarbers.co.uk" }, { domain: "cloudflare.com" },
      { domain: "claudflare.com" }, { domain: "google.com" }, { domain: "tesla.com" },
    ]);
    const scoped = scanner.filterBrandCandidatesToProfile([
      { domain: "cloudflare.com" }, { domain: "blackbullbarbers.co.uk" }, { domain: "tesla.com" },
    ], profile);
    return scoped.length === 1 && scoped[0].domain === "blackbullbarbers.co.uk" &&
      !profile.protected_domains.includes("cloudflare.com") && !profile.protected_domains.includes("tesla.com");
  }),
  securityContract("brand_persisted_multiple_protected_domains_supported", () => {
    const profile = {
      primary_domain: "example.com",
      protected_domains: ["example.com", "example.co.uk"],
      inferred: false,
    };
    const scoped = scanner.filterBrandCandidatesToProfile([
      { domain: "example.com" }, { domain: "example.co.uk" }, { domain: "unrelated.test" },
    ], profile);
    const sqlScope = scanner.buildBrandProfileDomainScope(profile);
    return scoped.length === 2 && sqlScope.clause === "domain IN (?,?)" &&
      JSON.stringify(sqlScope.bindings) === JSON.stringify(["example.com", "example.co.uk"]);
  }),
  securityContract("brand_profile_update_validates_workspace", () => {
    const valid = scanner.validateBrandProfileInput({
      brand_name: "Example", primary_domain: "example.com",
      keywords: ["example", "example login"], protected_domains: ["example.com"],
    }, ["example.com"]);
    const outside = scanner.validateBrandProfileInput({
      brand_name: "Example", primary_domain: "attacker.test",
      keywords: [], protected_domains: ["attacker.test"],
    }, ["example.com"]);
    return valid.ok === true && outside.ok === false && outside.error === "primary_domain_not_in_workspace";
  }),
  securityContract("brand_candidate_risk_mx_high_similarity", () => {
    const risk = scanner.scoreBrandCandidateRisk({
      variant_type: "homoglyph", similarity_score: 96, dns_active: true,
      https_active: true, mx_present: true, classification: "unreviewed",
    });
    return risk.score >= 85 && risk.risk_level === "critical" &&
      risk.reasons.includes("high_brand_similarity") && risk.reasons.includes("mx_present_possible_mail_abuse");
  }),
  securityContract("brand_candidate_owned_reduces_risk", () => {
    const risk = scanner.scoreBrandCandidateRisk({
      variant_type: "homoglyph", similarity_score: 100, dns_active: true,
      https_active: true, mx_present: true, classification: "owned",
    });
    return risk.score === 0 && risk.risk_level === "info" && risk.reasons[0] === "classification_owned";
  }),
  securityContract("brand_candidate_ignore_hides_from_open_actions", () => {
    const candidate = scanner.brandCandidateToApi({
      id: "bra-1", domain: "example.com", candidate_domain: "example-login.top",
      variant_type: "keyword_abuse", similarity_score: 90, dns_resolves: 1,
      https_available: 1, mx_present: 1, classification: "ignored", status: "active",
      first_seen: "2020-01-01T00:00:00.000Z",
    }, { brand_name: "example", primary_domain: "example.com" });
    return candidate.classification === "ignored" && candidate.risk_level === "info" &&
      candidate.risk_score === 0 && candidate.action_required === false;
  }),
  securityContract("brand_candidate_classification_audit_safe", () => {
    const metadata = scanner.brandClassificationAuditMetadata(
      { candidate_domain: "examp1e.com", token_hash: "SECRET", internal_error: "STACK" },
      "unreviewed", "suspicious", "high",
    );
    const keys = Object.keys(metadata).sort();
    const serialized = JSON.stringify(metadata);
    return JSON.stringify(keys) === JSON.stringify([
      "candidate_domain", "classification", "previous_classification", "risk_level",
    ]) && !serialized.includes("SECRET") && !serialized.includes("STACK");
  }),
  securityContract("brand_candidates_pagination_bounds", () => {
    const values = { risk: "invalid", status: "active", classification: "ignored", limit: "999", offset: "-4" };
    const params = scanner.parseBrandCandidateListParams({ get: (key) => values[key] ?? null });
    return params.risk === null && params.status === "active" && params.classification === "ignored" &&
      params.limit === 100 && params.offset === 0;
  }),
  securityContract("brand_summary_counts_consistent", () => {
    const summary = scanner.buildBrandProtectionSummary([
      { dns_active: true, risk_level: "critical", classification: "confirmed_abuse", updated_at: "2026-06-01" },
      { dns_active: true, risk_level: "high", classification: "suspicious", updated_at: "2026-06-03" },
      { dns_active: false, risk_level: "info", classification: "ignored", updated_at: "2026-06-02" },
      { dns_active: null, risk_level: "low", classification: "owned", updated_at: "2026-05-01" },
      { dns_active: null, risk_level: "medium", classification: "unreviewed", updated_at: "2026-04-01" },
    ]);
    return summary.total_candidates === 5 && summary.active_dns === 2 && summary.high_risk === 2 &&
      summary.confirmed_abuse === 1 && summary.suspicious === 1 && summary.ignored === 1 &&
      summary.owned === 1 && summary.unreviewed === 1 && summary.last_updated_at === "2026-06-03";
  }),
  securityContract("brand_candidate_no_secret_or_internal_error_leak", () => {
    const candidate = scanner.brandCandidateToApi({
      id: "bra-2", domain: "example.com", candidate_domain: "examp1e.com",
      variant_type: "substitution", classification: "unreviewed", status: "active",
      dns_resolves: 1, token_hash: "SECRET_HASH", api_token: "SECRET_TOKEN",
      internal_error: "STACK_TRACE", evidence_json: JSON.stringify([{ signal: "not_allowed", value: "SECRET" }]),
    }, { brand_name: "example", primary_domain: "example.com" });
    const serialized = JSON.stringify(candidate);
    return !("token_hash" in candidate) && !("internal_error" in candidate) &&
      !serialized.includes("SECRET_HASH") && !serialized.includes("SECRET_TOKEN") &&
      !serialized.includes("STACK_TRACE") && !serialized.includes('"not_allowed"');
  }),
  securityContract("brand_existing_brand_monitoring_contract_preserved", () => {
    const legacy = scanner.legacyBrandAssetToApi({
      candidate_domain: "examp1e.com", domain: "example.com", variant_type: "substitution",
      risk_level: "high", risk_reasons: '["homoglyph"]', dns_resolves: 1,
      https_available: 0, ip_address: "192.0.2.1", status: "active",
      first_seen: "2026-01-01", last_seen: "2026-01-02",
    });
    return legacy.candidate_domain === "examp1e.com" && legacy.domain === "example.com" &&
      legacy.dns_resolves === true && legacy.https_available === false &&
      Array.isArray(legacy.risk_reasons) && legacy.risk_reasons[0] === "homoglyph" && legacy.status === "active";
  }),
);

function _dmarcDnsCheckEnv(endpoint = { address_local: "cmrua_abc123def456" }) {
  return {
    RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
    cybermeters_db: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return endpoint; },
        };
      },
    },
  };
}

function _dmarcDnsAnswer(...records) {
  return { Status: 0, Answer: records.map((data) => ({ type: 16, data: `"${data}"` })) };
}

const DMARC_DNS_CHECKED_AT = "2026-06-29T12:00:00.000Z";

results.push(await asyncSecurityContract("dmarc_dns_check_verified_when_rua_present", async () => {
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () =>
      _dmarcDnsAnswer("v=DMARC1; p=none; rua=mailto:existing@example.com, MAILTO:CMRUA_ABC123DEF456@REPORTS.CYBERMETERS.COM ") }
  );
  return result.status === "verified" && result.dmarc_present === true &&
    result.cybermeters_rua_present === true && result.policy === "none" &&
    result.recommended_rua === "mailto:cmrua_abc123def456@reports.cybermeters.com";
}));

results.push(await asyncSecurityContract("dmarc_dns_check_missing_cybermeters_rua", async () => {
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () =>
      _dmarcDnsAnswer("v=DMARC1; p=none; rua=mailto:existing@example.com") }
  );
  return result.status === "missing_cybermeters_rua" && result.dmarc_present === true &&
    result.cybermeters_rua_present === false && result.rua[0] === "mailto:existing@example.com";
}));

results.push(await asyncSecurityContract("dmarc_dns_check_no_dmarc", async () => {
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () => ({ Status: 3, Answer: [] }) }
  );
  return result.status === "no_dmarc" && result.dmarc_present === false && result.rua.length === 0 &&
    result.policy === null &&
    result.recommended_txt_value === "v=DMARC1; p=none; rua=mailto:cmrua_abc123def456@reports.cybermeters.com";
}));

results.push(await asyncSecurityContract("dmarc_dns_check_multiple_dmarc_records", async () => {
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () =>
      _dmarcDnsAnswer("v=DMARC1; p=none", "v=DMARC1; p=reject") }
  );
  return result.status === "multiple_dmarc_records" && result.dmarc_present === true &&
    result.cybermeters_rua_present === false && result.recommended_txt_value === null;
}));

results.push(await asyncSecurityContract("dmarc_dns_check_endpoint_missing_no_secret_leak", async () => {
  let dnsCalls = 0;
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(null), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () => { dnsCalls++; throw new Error("not called"); } }
  );
  const serialized = JSON.stringify(result);
  return result.status === "endpoint_missing" && dnsCalls === 0 &&
    !/token_hash|cloudflare_route_id|raw token|secret/i.test(serialized);
}));

results.push(await asyncSecurityContract("dmarc_dns_check_recommended_value_preserves_existing_rua", async () => {
  const record = "v=DMARC1; p=none; sp=none; pct=50; rua=mailto:existing@example.com";
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () => _dmarcDnsAnswer(record) }
  );
  const recommended = result.recommended_txt_value;
  return recommended.includes("p=none") && recommended.includes("sp=none") && recommended.includes("pct=50") &&
    recommended.includes("mailto:existing@example.com") &&
    recommended.includes("mailto:cmrua_abc123def456@reports.cybermeters.com") &&
    !recommended.includes("p=quarantine") && !recommended.includes("p=reject");
}));

results.push(await asyncSecurityContract("dmarc_dns_check_invalid_record_safe_status", async () => {
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () =>
      _dmarcDnsAnswer("v=DMARC1; p=invalid; pct=abc; rua=mailto:existing@example.com") }
  );
  return result.status === "invalid_dmarc" && result.dmarc_present === true &&
    result.cybermeters_rua_present === false && !JSON.stringify(result).includes("stack");
}));

results.push(await asyncSecurityContract("dmarc_dns_check_no_token_hash_or_route_id_leak", async () => {
  const endpoint = {
    address_local: "cmrua_abc123def456", token_hash: "SECRET_TOKEN_HASH",
    cloudflare_route_id: "SECRET_ROUTE_ID", cloudflare_route_error: "SECRET_RAW_ERROR",
  };
  const result = await scanner.verifyDmarcDnsSetup(
    _dmarcDnsCheckEnv(endpoint), "workspace-1", "example.com",
    { checkedAt: DMARC_DNS_CHECKED_AT, dnsQueryImpl: async () =>
      _dmarcDnsAnswer("v=DMARC1; p=none; rua=mailto:cmrua_abc123def456@reports.cybermeters.com") }
  );
  const serialized = JSON.stringify(result);
  return result.status === "verified" && !serialized.includes("SECRET_TOKEN_HASH") &&
    !serialized.includes("SECRET_ROUTE_ID") && !serialized.includes("SECRET_RAW_ERROR") &&
    !("token_hash" in result) && !("cloudflare_route_id" in result);
}));

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

// ── DMARC Sender Intelligence v1 contracts ──────────────────────────────────
const dmarcCleanXml = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>noreply-dmarc@google.com</email>
    <report_id>RPT-CLEAN-1</report_id><date_range><begin>1717200000</begin><end>1717286400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record><row><source_ip>209.85.220.41</source_ip><count>100</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>
</feedback>`;
const dmarcFailXml = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>Yahoo</org_name><email>dmarc@yahoo.com</email><report_id>RPT-FAIL-1</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><pct>100</pct></policy_published>
  <record><row><source_ip>198.51.100.7</source_ip><count>40</count>
    <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>spammer.test</domain><result>fail</result></dkim>
      <spf><domain>spammer.test</domain><result>fail</result></spf></auth_results></record>
</feedback>`;
const dmarcMixedXml = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>noreply-dmarc@google.com</email><report_id>RPT-MIX-1</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><pct>100</pct></policy_published>
  <record><row><source_ip>209.85.220.41</source_ip><count>200</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>
  <record><row><source_ip>198.51.100.7</source_ip><count>60</count>
    <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>spammer.test</domain><result>fail</result></dkim>
      <spf><domain>spammer.test</domain><result>fail</result></spf></auth_results></record>
</feedback>`;

const dmarcCleanParsed = scanner.parseDmarcAggregateXml(dmarcCleanXml);
const dmarcFailParsed  = scanner.parseDmarcAggregateXml(dmarcFailXml);
const dmarcMixedParsed = scanner.parseDmarcAggregateXml(dmarcMixedXml);

results.push(securityContract("dmarc_parse_clean_passing_sender", () =>
  !dmarcCleanParsed.error && dmarcCleanParsed.records.length === 1 &&
  dmarcCleanParsed.records[0].source_ip === "209.85.220.41" &&
  dmarcCleanParsed.records[0].count === 100 &&
  dmarcCleanParsed.records[0].dkim_aligned_result === "pass" &&
  dmarcCleanParsed.records[0].spf_aligned_result === "pass" &&
  dmarcCleanParsed.metadata.report_id === "RPT-CLEAN-1"
));
results.push(securityContract("dmarc_parse_unknown_failing_sender", () =>
  !dmarcFailParsed.error &&
  dmarcFailParsed.records[0].dkim_aligned_result === "fail" &&
  dmarcFailParsed.records[0].spf_aligned_result === "fail" &&
  scanner.guessEmailSenderProvider(dmarcFailParsed.records[0]).provider === "unknown" &&
  scanner.guessEmailSenderProvider(dmarcFailParsed.records[0]).confidence === "low"
));
results.push(securityContract("dmarc_provider_guess_known_and_unknown", () => {
  const sg = scanner.guessEmailSenderProvider({ dkim_domain: "u1.wl.sendgrid.net" });
  const ms = scanner.guessEmailSenderProvider({ spf_domain: "spf.protection.outlook.com" });
  const un = scanner.guessEmailSenderProvider({ dkim_domain: "random.example" });
  return sg.provider === "sendgrid" && sg.confidence === "medium" &&
    ms.provider === "microsoft" && un.provider === "unknown" && un.confidence === "low";
}));
results.push(securityContract("dmarc_parse_mixed_multi_record", () =>
  !dmarcMixedParsed.error && dmarcMixedParsed.records.length === 2 &&
  dmarcMixedParsed.records[1].disposition === "quarantine" &&
  dmarcMixedParsed.records[0].count === 200
));
results.push(securityContract("dmarc_duplicate_dedupe_key_stable", () => {
  const a = scanner.parseDmarcAggregateXml(dmarcCleanXml).metadata;
  const b = scanner.parseDmarcAggregateXml(dmarcCleanXml).metadata;
  return a.report_id === b.report_id && a.date_range_begin === b.date_range_begin &&
    a.date_range_end === b.date_range_end && a.org_name === b.org_name;
}));
results.push(securityContract("dmarc_xml_safety_rejections", () =>
  scanner.parseDmarcAggregateXml("").error === "empty_xml" &&
  scanner.parseDmarcAggregateXml("<!DOCTYPE feedback SYSTEM 'x'><feedback></feedback>").error === "unsafe_xml" &&
  scanner.parseDmarcAggregateXml("<html><body>not dmarc</body></html>").error === "invalid_structure"
));
results.push(await asyncSecurityContract("dmarc_sender_rollup_totals", async () => {
  const inserts = [];
  const mockEnv = { cybermeters_db: { prepare(sql) { return {
    _sql: sql, _b: null,
    bind(...a) { this._b = a; return this; },
    async first() { return null; },
    async all() { return { results: [] }; },
    async run() { if (this._sql.includes("INSERT INTO email_sender_sources")) inserts.push(this._b); return {}; },
  }; } } };
  const out = await scanner.updateEmailSenderSources(mockEnv, "ws1", "example.com", dmarcMixedParsed);
  // INSERT binds: [id,ws,domain,ip,prov,conf,reason,header_from,first,last,total,aligned,failed,quar,rej,pass_rate]
  const good = inserts.find((b) => b[3] === "209.85.220.41");
  const bad  = inserts.find((b) => b[3] === "198.51.100.7");
  return out.sources_updated === 2 && inserts.length === 2 &&
    good[10] === 200 && good[11] === 200 && good[12] === 0 && good[15] === 100 &&
    bad[10] === 60 && bad[11] === 0 && bad[12] === 60 && bad[13] === 60 && bad[15] === 0;
}));
results.push(securityContract("dmarc_readiness_blocked_by_unknown", () => {
  const r = scanner.buildDmarcEnforcementReadiness({ days_with_data: 10, total_messages: 1000, pass_rate: 99, unknown_senders: 2, high_volume_failed_senders: 0 });
  return r.ready_for_quarantine === false && r.ready_for_reject === false &&
    r.blockers.some((b) => b.toLowerCase().includes("unknown"));
}));
results.push(securityContract("dmarc_readiness_cautious_quarantine", () => {
  const r = scanner.buildDmarcEnforcementReadiness({ days_with_data: 10, total_messages: 5000, pass_rate: 97, unknown_senders: 0, high_volume_failed_senders: 0 });
  return r.ready_for_quarantine === true && r.ready_for_reject === false &&
    /confirm all legitimate senders/i.test(r.next_step);
}));
// business_risk copy must reflect CURRENT classifications, not always "unknown senders".
results.push(securityContract("dmarc_business_risk_suspicious_not_unknown", () => {
  // Acceptance case: trusted=1, unknown=0, suspicious=1, failed_messages=60
  const r = scanner.buildDmarcBusinessRisk({ threat_senders: 0, suspicious_senders: 1, unknown_senders: 0, failed_messages: 60, pass_rate: 76.9 });
  return r.level === "high" && /suspicious sender activity/i.test(r.summary) && !/unknown email senders/i.test(r.summary);
}));
results.push(securityContract("dmarc_business_risk_threat_copy", () => {
  const r = scanner.buildDmarcBusinessRisk({ threat_senders: 1, suspicious_senders: 0, unknown_senders: 0, failed_messages: 0, pass_rate: 50 });
  return r.level === "high" && /threat-classified senders/i.test(r.summary);
}));
results.push(securityContract("dmarc_business_risk_unknown_no_failures", () => {
  const r = scanner.buildDmarcBusinessRisk({ threat_senders: 0, suspicious_senders: 0, unknown_senders: 2, failed_messages: 0, pass_rate: 100 });
  return r.level === "medium" && /should be classified before tightening/i.test(r.summary);
}));
results.push(securityContract("dmarc_business_risk_failed_after_classification", () => {
  const r = scanner.buildDmarcBusinessRisk({ threat_senders: 0, suspicious_senders: 0, unknown_senders: 0, failed_messages: 30, pass_rate: 90 });
  return r.level === "medium" && /failed dmarc alignment remains a risk/i.test(r.summary);
}));
results.push(securityContract("dmarc_business_risk_clean_low", () => {
  const r = scanner.buildDmarcBusinessRisk({ threat_senders: 0, suspicious_senders: 0, unknown_senders: 0, failed_messages: 0, pass_rate: 99 });
  return r.level === "low" && /alignment looks strong/i.test(r.summary);
}));

// ── BEC Exposure Score v1 contracts ─────────────────────────────────────────
const BEC_BASE = {
  domain: "example.com",
  dmarc_present: true,
  dmarc_policy: "reject",
  dmarc_pct: 100,
  spf_status: "valid",
  dkim_status: "valid",
  reports_received: true,
  cybermeters_rua_verified: true,
  last_report_received_at: "2026-06-28T12:00:00.000Z",
  total_messages: 1000,
  aligned_messages: 990,
  failed_messages: 10,
  pass_rate: 99,
  known_senders: 3,
  unknown_senders: 0,
  suspicious_senders: 0,
  high_volume_failing_senders: 0,
  dns_status_known: true,
  brand: { available: false },
};

results.push(securityContract("bec_score_dmarc_none_failed_alignment_medium_without_sender_risk", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    dmarc_policy: "none",
    pass_rate: 77.1,
    total_messages: 523,
    aligned_messages: 403,
    failed_messages: 120,
    cybermeters_rua_verified: false,
  }, { now: "2026-06-29T12:00:00.000Z" });
  return r.exposure_score >= 46 && r.exposure_level === "medium" &&
    r.reasons.some((reason) => reason.code === "dmarc_policy_none") &&
    r.evidence.pass_rate === 77.1 && r.evidence.failed_messages === 120;
}));

results.push(securityContract("bec_score_blackbullbarbers_style_high_not_critical", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    domain: "blackbullbarbers.co.uk",
    dmarc_policy: "none",
    reports_received: true,
    cybermeters_rua_verified: false,
    spf_status: "valid",
    dkim_status: "unknown",
    pass_rate: 77.1,
    total_messages: 523,
    aligned_messages: 403,
    failed_messages: 120,
    known_senders: 3,
    unknown_senders: 1,
    suspicious_senders: 1,
    high_volume_failing_senders: 1,
  }, { now: "2026-06-29T12:00:00.000Z" });
  const reasonCodes = new Set(r.reasons.map((reason) => reason.code));
  return r.exposure_level === "high" &&
    r.exposure_score >= 80 && r.exposure_score <= 88 &&
    r.evidence.reports_received === true &&
    r.evidence.cybermeters_rua_verified === false &&
    reasonCodes.has("dmarc_policy_none") &&
    reasonCodes.has("cybermeters_rua_not_verified") &&
    reasonCodes.has("dmarc_pass_rate_low") &&
    reasonCodes.has("suspicious_sender_present") &&
    reasonCodes.has("high_volume_failing_sender");
}));

results.push(securityContract("bec_score_reject_policy_good_alignment_low", () => {
  const r = scanner.computeBecExposureScore(BEC_BASE, { now: "2026-06-29T12:00:00.000Z" });
  return r.exposure_score <= 15 && ["minimal", "low"].includes(r.exposure_level) &&
    r.confidence === "high" && !r.reasons.some((reason) => reason.code === "dmarc_policy_none");
}));

results.push(securityContract("bec_score_no_reports_lowers_confidence", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    reports_received: false,
    total_messages: 0,
    aligned_messages: 0,
    failed_messages: 0,
    pass_rate: null,
    known_senders: 0,
  }, { now: "2026-06-29T12:00:00.000Z" });
  return r.confidence === "medium" && r.reasons.some((reason) => reason.code === "no_dmarc_reports") &&
    r.evidence.reports_received === false;
}));

results.push(securityContract("bec_score_unknown_and_suspicious_senders_increase_exposure", () => {
  const base = scanner.computeBecExposureScore(BEC_BASE, { now: "2026-06-29T12:00:00.000Z" });
  const elevated = scanner.computeBecExposureScore({
    ...BEC_BASE,
    unknown_senders: 1,
    suspicious_senders: 1,
  }, { now: "2026-06-29T12:00:00.000Z" });
  return elevated.exposure_score >= base.exposure_score + 20 &&
    elevated.reasons.some((reason) => reason.code === "unknown_sender_present") &&
    elevated.reasons.some((reason) => reason.code === "suspicious_sender_present");
}));

results.push(securityContract("bec_score_high_volume_failing_sender_increases_exposure", () => {
  const base = scanner.computeBecExposureScore(BEC_BASE, { now: "2026-06-29T12:00:00.000Z" });
  const elevated = scanner.computeBecExposureScore({
    ...BEC_BASE,
    high_volume_failing_senders: 1,
  }, { now: "2026-06-29T12:00:00.000Z" });
  return elevated.exposure_score >= base.exposure_score + 14 &&
    elevated.reasons.some((reason) => reason.code === "high_volume_failing_sender");
}));

results.push(securityContract("bec_score_rua_not_verified_adds_reason", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    cybermeters_rua_verified: false,
  }, { now: "2026-06-29T12:00:00.000Z" });
  return r.exposure_score >= 10 &&
    r.evidence.cybermeters_rua_verified === false &&
    r.reasons.some((reason) => reason.code === "cybermeters_rua_not_verified") &&
    r.recommended_actions.some((action) => action.code === "add_cybermeters_rua");
}));

results.push(securityContract("bec_score_reports_received_does_not_verify_rua_dns", () => {
  const endpoint = {
    status: "active",
    address_local: "cmrua_abc123def456",
    last_inbound_at: "2026-06-29T10:00:00.000Z",
    inbound_domain: "reports.cybermeters.com",
  };
  const missingRua = scanner.cybermetersRuaPresentInDmarcRecord(
    "v=DMARC1; p=none; rua=mailto:vendor@example.com",
    endpoint,
  );
  const verifiedRua = scanner.cybermetersRuaPresentInDmarcRecord(
    "v=DMARC1; p=none; rua=mailto:vendor@example.com,mailto:cmrua_abc123def456@reports.cybermeters.com",
    endpoint,
  );
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    dmarc_policy: "none",
    reports_received: true,
    last_report_received_at: endpoint.last_inbound_at,
    cybermeters_rua_verified: missingRua,
  }, { now: "2026-06-29T12:00:00.000Z" });
  return missingRua === false && verifiedRua === true &&
    r.evidence.reports_received === true &&
    r.evidence.cybermeters_rua_verified === false &&
    r.evidence.last_report_received_at === endpoint.last_inbound_at &&
    r.reasons.some((reason) => reason.code === "cybermeters_rua_not_verified") &&
    r.recommended_actions.some((action) => action.code === "add_cybermeters_rua");
}));

results.push(securityContract("bec_score_brand_candidates_optional", () => {
  const absent = scanner.computeBecExposureScore({ ...BEC_BASE, brand: undefined }, { now: "2026-06-29T12:00:00.000Z" });
  const unavailable = scanner.computeBecExposureScore({ ...BEC_BASE, brand: { available: false } }, { now: "2026-06-29T12:00:00.000Z" });
  return Number.isInteger(absent.exposure_score) && absent.exposure_score === unavailable.exposure_score &&
    absent.evidence.brand_candidates_available === false;
}));

results.push(securityContract("bec_score_owned_ignored_brand_candidates_do_not_increase_score", () => {
  const base = scanner.computeBecExposureScore(BEC_BASE, { now: "2026-06-29T12:00:00.000Z" });
  const ownedIgnored = scanner.computeBecExposureScore({
    ...BEC_BASE,
    brand: { available: true, owned_ignored_or_false_positive: 4, high_risk_active_dns: 0, high_risk_mx: 0, suspicious_or_confirmed: 0 },
  }, { now: "2026-06-29T12:00:00.000Z" });
  return ownedIgnored.exposure_score === base.exposure_score &&
    !ownedIgnored.reasons.some((reason) => reason.code === "brand_impersonation_candidates");
}));

results.push(securityContract("bec_score_clamps_to_100", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    dmarc_present: false,
    dmarc_policy: "missing",
    spf_status: "missing",
    dkim_status: "missing",
    cybermeters_rua_verified: false,
    reports_received: false,
    pass_rate: 10,
    total_messages: 10000,
    aligned_messages: 1000,
    failed_messages: 9000,
    unknown_senders: 10,
    suspicious_senders: 5,
    high_volume_failing_senders: 3,
    brand: { available: true, high_risk_active_dns: 3, high_risk_mx: 2, suspicious_or_confirmed: 1 },
  }, { now: "2026-06-29T12:00:00.000Z" });
  return r.exposure_score === 100 && r.exposure_level === "critical";
}));

results.push(securityContract("bec_score_extreme_missing_controls_critical", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    dmarc_present: false,
    dmarc_policy: "missing",
    reports_received: false,
    spf_status: "missing",
    dkim_status: "missing",
    cybermeters_rua_verified: false,
    pass_rate: 20,
    total_messages: 10000,
    aligned_messages: 2000,
    failed_messages: 8000,
    unknown_senders: 4,
    suspicious_senders: 2,
    high_volume_failing_senders: 2,
    brand: { available: true, high_risk_active_dns: 2, high_risk_mx: 1, suspicious_or_confirmed: 1 },
  }, { now: "2026-06-29T12:00:00.000Z" });
  return r.exposure_level === "critical" && r.exposure_score >= 90;
}));

results.push(securityContract("bec_endpoint_no_secret_or_raw_error_leak", () => {
  const r = scanner.computeBecExposureScore({
    ...BEC_BASE,
    raw_xml: "<feedback>SECRET</feedback>",
    token_hash: "SECRET_HASH",
    api_token: "SECRET_TOKEN",
  }, { now: "2026-06-29T12:00:00.000Z" });
  const safeError = scanner.normalizeApiResponseData({
    error: "BEC exposure score could not be calculated",
    detail: "SQL SECRET detail",
    stack: "STACK SECRET",
  }, 500);
  const body = JSON.stringify(r);
  const err = JSON.stringify(safeError);
  return !body.includes("SECRET") && !body.includes("<feedback") &&
    !err.includes("SQL SECRET") && !err.includes("STACK SECRET") && !("detail" in safeError) && !("stack" in safeError);
}));

// ── Assisted DMARC Upload v1 — shared ingestion + signed-upload token model ───
// Dedupe identity is source-agnostic: the same report (whatever the source)
// resolves to the same key, so manual_paste then signed_upload counts once.
results.push(await asyncSecurityContract("dmarc_ingest_dedupe_source_agnostic", async () => {
  const a = await scanner.dmarcReportIdentity(dmarcMixedXml, dmarcMixedParsed);
  const b = await scanner.dmarcReportIdentity(dmarcMixedXml, dmarcMixedParsed);
  const keyA = JSON.stringify([a.org_name, a.external_report_id, a.date_range_begin, a.date_range_end]);
  const keyB = JSON.stringify([b.org_name, b.external_report_id, b.date_range_begin, b.date_range_end]);
  // identical key across two ingestions, and the identity carries NO source field.
  return keyA === keyB && a.external_report_id === dmarcMixedParsed.metadata.report_id &&
    !("source" in a) && typeof a.raw_hash === "string" && a.raw_hash.length === 64;
}));
// Domain-binding safety: a report is accepted for its own domain and rejected
// for a different bound domain (prevents cross-domain poisoning via token).
results.push(securityContract("dmarc_ingest_domain_match_and_mismatch", () =>
  scanner.dmarcReportDomainMatches(dmarcMixedParsed, "example.com") === true &&
  scanner.dmarcReportDomainMatches(dmarcMixedParsed, "attacker.test") === false &&
  // no published policy domain → cannot disprove → allowed (documented)
  scanner.dmarcReportDomainMatches({ policy_published: {} }, "example.com") === true
));
// Token model: high-entropy, unique, deterministic SHA-256 hash, hash != raw.
results.push(await asyncSecurityContract("dmarc_ingest_token_hash_resolution", async () => {
  const t1 = scanner.generateIngestToken();
  const t2 = scanner.generateIngestToken();
  const h1 = await scanner.hashIngestToken(t1);
  const h1again = await scanner.hashIngestToken(t1);
  const h2 = await scanner.hashIngestToken(t2);
  return t1.startsWith("cmdi_") && t1.length >= 40 && t1 !== t2 &&
    /^[0-9a-f]{64}$/.test(h1) && h1 === h1again && h1 !== h2 && h1 !== t1;
}));
// Revocation + customer-safe serialization: revoked/inactive rejected at ingest;
// token_hash never serialized; raw token only present when explicitly passed.
results.push(securityContract("dmarc_ingest_active_state_and_serialization", () => {
  const activeOk = scanner.ingestEndpointIsActive({ status: "active" }) === true;
  const revokedFlag = scanner.ingestEndpointIsActive({ status: "active", revoked_at: "2026-01-01" }) === false;
  const revokedStatus = scanner.ingestEndpointIsActive({ status: "revoked" }) === false;
  const nullRow = scanner.ingestEndpointIsActive(null) === false;
  const row = { id: "e1", domain: "example.com", status: "active", token_hash: "SECRETHASH", created_at: "x" };
  const safe = scanner.ingestEndpointToApi(row);
  const withTok = scanner.ingestEndpointToApi(row, { rawToken: "cmdi_raw" });
  // Safe serialization: no token_hash, no raw token, and no internal row id.
  const noLeak = !("token_hash" in safe) && !("token" in safe) && !("id" in safe) && safe.domain === "example.com";
  const tokenOnce = withTok.token === "cmdi_raw" && !("token_hash" in withTok);
  return activeOk && revokedFlag && revokedStatus && nullRow && noLeak && tokenOnce;
}));

// ── Assisted RUA Ingestion v1 (Phase 2) — inbound email helpers ──────────────
// Test fixture builders (use platform CompressionStream; Workers + Node 18+).
async function _gzipBytes(str) {
  const cs = new CompressionStream("gzip");
  const stream = new Response(new TextEncoder().encode(str)).body.pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
function _bytesToB64(bytes) {
  let bin = ""; for (const b of bytes) bin += String.fromCharCode(b);
  return Buffer.from(bin, "binary").toString("base64");
}
// Minimal single-entry STORED zip: [local header][name][data][EOCD]. The reader
// only needs the local header fields + EOCD total-entry count.
function _buildStoredZip(name, dataStr, totalEntries = 1) {
  const enc = new TextEncoder();
  const nameB = enc.encode(name);
  const dataB = enc.encode(dataStr);
  const lh = new Uint8Array(30 + nameB.length + dataB.length);
  const dv = new DataView(lh.buffer);
  dv.setUint32(0, 0x04034b50, true);     // local file header signature
  dv.setUint16(4, 20, true);             // version
  dv.setUint16(6, 0, true);              // flags
  dv.setUint16(8, 0, true);              // method 0 = stored
  dv.setUint32(18, dataB.length, true);  // compressed size
  dv.setUint32(22, dataB.length, true);  // uncompressed size
  dv.setUint16(26, nameB.length, true);  // name length
  dv.setUint16(28, 0, true);             // extra length
  lh.set(nameB, 30);
  lh.set(dataB, 30 + nameB.length);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);     // EOCD signature
  ev.setUint16(10, totalEntries, true);  // total entries
  const out = new Uint8Array(lh.length + eocd.length);
  out.set(lh, 0); out.set(eocd, lh.length);
  return out;
}

const RUA_TEST_CAPS = { attachmentMax: 10 * 1024 * 1024, decompressedMax: 10 * 1024 * 1024, ratioMax: 100 };

async function _buildRuaMime(xmlString) {
  const gz = await _gzipBytes(xmlString);
  const b64 = _bytesToB64(gz).replace(/(.{76})/g, "$1\r\n");
  return "From: reports@example.net\r\nSubject: DMARC report\r\n" +
    'Content-Type: multipart/mixed; boundary="RUA-CATCHALL"\r\n\r\n' +
    "--RUA-CATCHALL\r\nContent-Type: text/plain\r\n\r\nReport attached.\r\n" +
    "--RUA-CATCHALL\r\n" +
    'Content-Type: application/gzip; name="report.xml.gz"\r\n' +
    'Content-Disposition: attachment; filename="report.xml.gz"\r\n' +
    "Content-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n--RUA-CATCHALL--\r\n";
}

function _ruaMessage(to, mime) {
  const bytes = new TextEncoder().encode(mime);
  return { to, rawSize: bytes.length, raw: new Response(bytes).body };
}

function _ruaHandlerHarness({ duplicate = false, status = "active", revoked_at = null } = {}) {
  const endpoint = {
    id: "endpoint-1", workspace_id: "workspace-1", domain_id: "domain-1",
    domain: "example.com", address_local: "cmrua_abc123def456", status, revoked_at,
  };
  const state = {
    reportSeen: duplicate, reportInserts: 0, recordInserts: 0,
    senderInserts: 0, senderMessages: 0, lastInboundUpdates: 0,
    endpointLookups: 0, audits: [], runs: [],
  };
  const env = {
    RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
    cybermeters_db: {
      prepare(sql) {
        return {
          _sql: sql, _bindings: [],
          bind(...bindings) { this._bindings = bindings; return this; },
          async first() {
            if (/FROM dmarc_ingest_endpoints WHERE address_local/.test(this._sql)) {
              state.endpointLookups++;
              return this._bindings[0] === endpoint.address_local ? endpoint : null;
            }
            if (/SELECT id FROM dmarc_aggregate_reports/.test(this._sql)) {
              return state.reportSeen ? { id: "existing-report" } : null;
            }
            if (/FROM email_sender_sources/.test(this._sql)) return null;
            return null;
          },
          async all() { return { results: [] }; },
          async run() {
            state.runs.push({ sql: this._sql, bindings: this._bindings });
            if (/INSERT INTO dmarc_aggregate_reports/.test(this._sql)) {
              state.reportSeen = true;
              state.reportInserts++;
            }
            if (/INSERT INTO dmarc_aggregate_records/.test(this._sql)) state.recordInserts++;
            if (/INSERT INTO email_sender_sources/.test(this._sql)) {
              state.senderInserts++;
              state.senderMessages += this._bindings[10] || 0;
            }
            if (/UPDATE dmarc_ingest_endpoints SET last_used_at/.test(this._sql)) state.lastInboundUpdates++;
            if (/INSERT INTO audit_events/.test(this._sql)) {
              state.audits.push({
                event_type: this._bindings[3],
                description: this._bindings[6],
                metadata: this._bindings[7] ? JSON.parse(this._bindings[7]) : null,
              });
            }
            return {};
          },
        };
      },
    },
  };
  return { env, state, endpoint };
}

results.push(securityContract("rua_localpart_generation_and_extraction", () => {
  const a = scanner.generateInboundLocalpart();
  const b = scanner.generateInboundLocalpart();
  const ok = a.startsWith("cmrua_") && a.length >= 14 && a !== b;
  const ext = scanner.extractInboundLocalpart(`<${a.toUpperCase()}@reports.cybermeters.com>`) === a;
  const reject = scanner.extractInboundLocalpart("postmaster@reports.cybermeters.com") === null &&
    scanner.extractInboundLocalpart("") === null &&
    scanner.extractInboundLocalpart(`${a}@otherdomain.com`, "reports.cybermeters.com") === null;
  const parsed = scanner.parseInboundRecipient("Random.Local@REPORTS.CYBERMETERS.COM.");
  return ok && ext && reject && parsed?.localpart === "random.local" &&
    parsed?.domain === "reports.cybermeters.com" &&
    scanner.parseInboundRecipient("invalid recipient") === null;
}));
results.push(securityContract("rua_endpoint_serialization_exposes_rua_no_leak", () => {
  const row = { id: "e9", domain: "example.com", status: "active", address_local: "cmrua_abc123def456",
    token_hash: "SECRET", created_at: "x", last_inbound_at: "2026-06-29T10:00:00Z",
    last_signed_upload_at: "2026-06-28T09:00:00Z" };
  const s = scanner.ingestEndpointToApi(row, { inboundDomain: "reports.cybermeters.com" });
  return s.address_local === "cmrua_abc123def456" &&
    s.inbound_address === "cmrua_abc123def456@reports.cybermeters.com" &&
    s.rua_mailto === "rua=mailto:cmrua_abc123def456@reports.cybermeters.com" &&
    s.last_inbound_at === "2026-06-29T10:00:00Z" &&
    s.last_signed_upload_at === "2026-06-28T09:00:00Z" &&
    !("token_hash" in s) && !("token" in s) && !("id" in s);
}));

// ── Cloudflare Email Routing exact-route automation contracts ──────────────
function _routeAutomationDb() {
  const runs = [];
  return {
    runs,
    db: {
      prepare(sql) {
        return {
          _sql: sql, _bindings: [],
          bind(...bindings) { this._bindings = bindings; return this; },
          async run() { runs.push({ sql: this._sql, bindings: this._bindings }); return {}; },
          async first() { return null; },
          async all() { return { results: [] }; },
        };
      },
    },
  };
}

const ROUTE_ENDPOINT = {
  id: "endpoint-route-1", workspace_id: "workspace-1", domain_id: "domain-1",
  domain: "example.com", address_local: "cmrua_abc123def456", status: "active",
};

results.push(await asyncSecurityContract("rua_route_automation_missing_config_does_not_block_endpoint", async () => {
  const mock = _routeAutomationDb();
  const env = { cybermeters_db: mock.db, RUA_INBOUND_DOMAIN: "reports.cybermeters.com" };
  const result = await scanner.configureDmarcEndpointRoute(env, ROUTE_ENDPOINT, "user-1");
  const persisted = mock.runs.find((run) => /cloudflare_route_status/.test(run.sql));
  const audit = mock.runs.find((run) => /INSERT INTO audit_events/.test(run.sql));
  const metadata = audit?.bindings?.[7] ? JSON.parse(audit.bindings[7]) : null;
  const serialized = JSON.stringify({ result, metadata });
  return result.ok === false && result.status === "not_configured" && result.reason === "missing_config" &&
    persisted?.bindings?.[1] === "not_configured" && audit?.bindings?.[3] === "dmarc_ingest_route_skipped" &&
    metadata?.reason === "missing_config" && !/token|secret/i.test(serialized);
}));

results.push(await asyncSecurityContract("rua_route_automation_rejects_apex_domain", async () => {
  let calls = 0;
  const result = await scanner.ensureCloudflareEmailRoute(
    { RUA_INBOUND_DOMAIN: "reports.cybermeters.com" }, "cmrua_abc123def456", "cybermeters.com",
    { fetchImpl: async () => { calls++; throw new Error("must not call"); } }
  );
  return !result.ok && result.reason === "unsupported_domain" && calls === 0;
}));

results.push(await asyncSecurityContract("rua_route_automation_rejects_wildcard", async () => {
  let calls = 0;
  const result = await scanner.ensureCloudflareEmailRoute(
    { RUA_INBOUND_DOMAIN: "reports.cybermeters.com" }, "*", "reports.cybermeters.com",
    { fetchImpl: async () => { calls++; throw new Error("must not call"); } }
  );
  return !result.ok && result.reason === "unsupported_localpart" && calls === 0;
}));

results.push(await asyncSecurityContract("rua_route_automation_valid_exact_route_payload", async () => {
  const calls = [];
  const routeId = "a".repeat(32);
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if ((init.method || "GET") === "POST") {
      return new Response(JSON.stringify({ success: true, result: { id: routeId } }),
        { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, result: [], result_info: { total_pages: 1 } }),
      { status: 200, headers: { "content-type": "application/json" } });
  };
  const env = {
    RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
    CLOUDFLARE_API_TOKEN: "test-api-token",
    CLOUDFLARE_ZONE_ID: "b".repeat(32),
    CLOUDFLARE_EMAIL_ROUTING_WORKER_NAME: "cybermeters-platform",
  };
  const result = await scanner.ensureCloudflareEmailRoute(
    env, "cmrua_abc123def456", "reports.cybermeters.com", { fetchImpl }
  );
  const create = calls.find((call) => call.init.method === "POST");
  const payload = create ? JSON.parse(create.init.body) : null;
  return result.ok && result.status === "active" && result.route_id === routeId &&
    payload?.matchers?.length === 1 && payload.matchers[0].type === "literal" &&
    payload.matchers[0].field === "to" &&
    payload.matchers[0].value === "cmrua_abc123def456@reports.cybermeters.com" &&
    payload?.actions?.length === 1 && payload.actions[0].type === "worker" &&
    payload.actions[0].value?.[0] === "cybermeters-platform" &&
    !JSON.stringify(payload).includes("*") && !JSON.stringify(payload).includes('"type":"all"');
}));

results.push(securityContract("rua_route_automation_serialization_safe", () => {
  const row = {
    ...ROUTE_ENDPOINT, created_at: "2026-06-29T10:00:00Z", token_hash: "SECRET_HASH",
    cloudflare_route_id: "private-route-id", cloudflare_route_status: "active",
    cloudflare_route_error: null, cloudflare_route_updated_at: "2026-06-29T11:00:00Z",
    cloudflare_raw_response: "RAW_SECRET_RESPONSE", CLOUDFLARE_API_TOKEN: "SECRET_TOKEN",
  };
  const serialized = scanner.ingestEndpointToApi(row, { inboundDomain: "reports.cybermeters.com" });
  const text = JSON.stringify(serialized);
  return serialized.route_status === "active" && serialized.route_error === null &&
    serialized.route_updated_at === "2026-06-29T11:00:00Z" &&
    !("cloudflare_route_id" in serialized) && !("token_hash" in serialized) && !("token" in serialized) &&
    !text.includes("SECRET") && !text.includes("RAW_SECRET_RESPONSE") && !text.includes("private-route-id");
}));

results.push(await asyncSecurityContract("rua_route_automation_revoke_safe_failure", async () => {
  const mock = _routeAutomationDb();
  const env = {
    cybermeters_db: mock.db, RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
    CLOUDFLARE_API_TOKEN: "test-api-token", CLOUDFLARE_ZONE_ID: "b".repeat(32),
  };
  let endpointRevoked = true; // Lifecycle updates endpoint status before this non-blocking adapter call.
  const result = await scanner.revokeCloudflareEmailRoute(env, "a".repeat(32), {
    fetchImpl: async () => new Response(JSON.stringify({
      success: false, errors: [{ message: "SECRET upstream rejection body" }],
    }), { status: 500, headers: { "content-type": "application/json" } }),
  });
  await scanner.persistDmarcRouteResult(env, ROUTE_ENDPOINT.id, result);
  await scanner.auditDmarcRouteResult(env, ROUTE_ENDPOINT, "user-1", result, "revoke");
  const audit = mock.runs.find((run) => /INSERT INTO audit_events/.test(run.sql));
  const metadata = audit?.bindings?.[7] ? JSON.parse(audit.bindings[7]) : null;
  return endpointRevoked && !result.ok && result.status === "failed" && result.reason === "api_rejected" &&
    audit?.bindings?.[3] === "dmarc_ingest_route_failed" && metadata?.reason === "api_rejected" &&
    !JSON.stringify({ result, metadata }).includes("SECRET upstream");
}));
results.push(await asyncSecurityContract("rua_gzip_extract_parses", async () => {
  const gz = await _gzipBytes(dmarcCleanXml);
  const r = await scanner.extractDmarcXmlFromAttachment("clean.xml.gz", gz, RUA_TEST_CAPS);
  if (r.error) return false;
  const parsed = scanner.parseDmarcAggregateXml(r.xml);
  return !parsed.error && parsed.metadata.report_id === "RPT-CLEAN-1";
}));
results.push(await asyncSecurityContract("rua_gzip_bomb_cap_rejected", async () => {
  const gz = await _gzipBytes("X".repeat(50000));
  const r = await scanner.gunzipXmlBytes(gz, { attachmentMax: 10 * 1024 * 1024, decompressedMax: 1024, ratioMax: 100 });
  return r.error === "decompressed_too_large";
}));
results.push(await asyncSecurityContract("rua_zip_single_entry_accepted", async () => {
  const zip = _buildStoredZip("report.xml", dmarcCleanXml, 1);
  const r = await scanner.extractDmarcXmlFromAttachment("report.zip", zip, RUA_TEST_CAPS);
  if (r.error) return false;
  const parsed = scanner.parseDmarcAggregateXml(r.xml);
  return !parsed.error && parsed.records.length === 1;
}));
results.push(await asyncSecurityContract("rua_zip_multi_entry_rejected", async () => {
  const zip = _buildStoredZip("report.xml", dmarcCleanXml, 2);
  const r = await scanner.unzipSingleEntryXmlBytes(zip, RUA_TEST_CAPS);
  return r.error === "zip_multi_entry";
}));
results.push(await asyncSecurityContract("rua_mime_email_to_xml", async () => {
  const gz = await _gzipBytes(dmarcMixedXml);
  const b64 = _bytesToB64(gz).replace(/(.{76})/g, "$1\r\n");
  const email =
    "From: noreply@google.com\r\nTo: cmrua_abc@reports.cybermeters.com\r\n" +
    "Subject: Report domain: example.com\r\n" +
    'Content-Type: multipart/mixed; boundary="BOUND1"\r\n\r\n' +
    "--BOUND1\r\nContent-Type: text/plain\r\n\r\nDMARC aggregate report attached.\r\n" +
    "--BOUND1\r\n" +
    'Content-Type: application/gzip; name="example.com!report.xml.gz"\r\n' +
    'Content-Disposition: attachment; filename="example.com!report.xml.gz"\r\n' +
    "Content-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n--BOUND1--\r\n";
  const parts = scanner.parseMimeParts(email);
  const sel = scanner.selectDmarcAttachment(parts);
  if (sel.error) return false;
  const ext = await scanner.extractDmarcXmlFromAttachment(sel.part.filename, sel.part.bytes, RUA_TEST_CAPS);
  if (ext.error) return false;
  const parsed = scanner.parseDmarcAggregateXml(ext.xml);
  return !parsed.error && parsed.records.length === 2;
}));
results.push(securityContract("rua_attachment_selection_zero_and_multi", () => {
  const none = scanner.selectDmarcAttachment([{ contentType: "text/plain", filename: "note.txt" }]);
  const multi = scanner.selectDmarcAttachment([
    { contentType: "application/gzip", filename: "a.xml.gz" },
    { contentType: "application/zip", filename: "b.xml.zip" },
  ]);
  return none.error === "no_dmarc_attachment" && multi.error === "multiple_attachments";
}));

// ── Catch-all routing safety contracts ─────────────────────────────────────
results.push(await asyncSecurityContract("rua_catchall_unknown_localpart_safe_drop", async () => {
  const { env, state } = _ruaHandlerHarness();
  const mime = await _buildRuaMime(dmarcMixedXml);
  await scanner.emailHandler(_ruaMessage("randomlocalpart@reports.cybermeters.com", mime), env, {});
  const drop = state.audits.find((audit) => audit.event_type === "dmarc_inbound_email_dropped");
  return state.endpointLookups === 0 && state.reportInserts === 0 && state.recordInserts === 0 &&
    state.senderInserts === 0 && state.senderMessages === 0 && state.lastInboundUpdates === 0 &&
    drop?.metadata?.reason === "endpoint_not_found" &&
    drop.metadata.recipient_localpart === "randomlocalpart" &&
    drop.metadata.recipient_domain === "reports.cybermeters.com" &&
    drop.metadata.source === "inbound_email";
}));

results.push(await asyncSecurityContract("rua_catchall_valid_localpart_still_ingests", async () => {
  const { env, state, endpoint } = _ruaHandlerHarness();
  const mime = await _buildRuaMime(dmarcMixedXml);
  await scanner.emailHandler(_ruaMessage(`${endpoint.address_local}@reports.cybermeters.com`, mime), env, {});
  const ingested = state.audits.find((audit) => audit.event_type === "dmarc_report_ingested");
  const received = state.audits.find((audit) => audit.event_type === "dmarc_inbound_email_received");
  return state.endpointLookups === 1 && state.reportInserts === 1 && state.recordInserts === 2 &&
    state.senderInserts === 2 && state.senderMessages === 260 && state.lastInboundUpdates === 1 &&
    ingested?.metadata?.source === "inbound_email" && received?.metadata?.source === "inbound_email" &&
    received.metadata.message_count === 260;
}));

results.push(await asyncSecurityContract("rua_catchall_wrong_domain_safe_drop", async () => {
  const { env, state, endpoint } = _ruaHandlerHarness();
  const mime = await _buildRuaMime(dmarcMixedXml);
  await scanner.emailHandler(_ruaMessage(`${endpoint.address_local}@cybermeters.com`, mime), env, {});
  const drop = state.audits.find((audit) => audit.event_type === "dmarc_inbound_email_dropped");
  return state.endpointLookups === 0 && state.reportInserts === 0 && state.recordInserts === 0 &&
    state.senderInserts === 0 && state.senderMessages === 0 && state.lastInboundUpdates === 0 &&
    drop?.metadata?.reason === "unsupported_recipient_domain" &&
    drop.metadata.recipient_domain === "cybermeters.com" && drop.metadata.source === "inbound_email";
}));

results.push(await asyncSecurityContract("rua_catchall_duplicate_no_double_count", async () => {
  const { env, state, endpoint } = _ruaHandlerHarness();
  const mime = await _buildRuaMime(dmarcMixedXml);
  const recipient = `${endpoint.address_local}@reports.cybermeters.com`;
  await scanner.emailHandler(_ruaMessage(recipient, mime), env, {});
  const totalsAfterFirst = {
    reports: state.reportInserts, records: state.recordInserts, senders: state.senderMessages,
  };
  await scanner.emailHandler(_ruaMessage(recipient, mime), env, {});
  const duplicateAudit = state.audits.find((audit) => audit.event_type === "dmarc_report_duplicate");
  return totalsAfterFirst.reports === 1 && totalsAfterFirst.records === 2 && totalsAfterFirst.senders === 260 &&
    state.reportInserts === totalsAfterFirst.reports && state.recordInserts === totalsAfterFirst.records &&
    state.senderMessages === totalsAfterFirst.senders && state.lastInboundUpdates === 2 &&
    duplicateAudit?.metadata?.duplicate === true && duplicateAudit.metadata.source === "inbound_email";
}));

results.push(await asyncSecurityContract("rua_catchall_audit_metadata_safe", async () => {
  const { env, state } = _ruaHandlerHarness();
  const rawMarker = "RAW_XML_SHOULD_NOT_APPEAR";
  await scanner.emailHandler(
    _ruaMessage("unknown@reports.cybermeters.com", `<feedback>${rawMarker}</feedback>`), env, {}
  );
  const drop = state.audits.find((audit) => audit.event_type === "dmarc_inbound_email_dropped");
  if (!drop?.metadata) return false;
  const allowedKeys = new Set(["source", "reason", "recipient_localpart", "recipient_domain"]);
  const serialized = JSON.stringify(drop);
  return Object.keys(drop.metadata).every((key) => allowedKeys.has(key)) &&
    !serialized.includes(rawMarker) &&
    !Object.keys(drop.metadata).some((key) => ["raw_xml", "raw_mime", "token_hash", "token", "attachment_content"].includes(key));
}));

// ── Sprint 3 — RUA hardening: dedupe, stable reasons, error sanitization ─────
// A duplicate inbound report must NOT insert rows or change totals, must return
// duplicate:true, and must emit dmarc_report_duplicate with source=inbound_email.
results.push(await asyncSecurityContract("rua_duplicate_inbound_no_double_count", async () => {
  const runs = [];
  const mockEnv = { cybermeters_db: { prepare(sql) { return {
    _sql: sql, _b: null,
    bind(...a) { this._b = a; return this; },
    async first() { return this._sql.includes("SELECT id FROM dmarc_aggregate_reports") ? { id: "existing" } : null; },
    async all() { return { results: [] }; },
    async run() { runs.push({ sql: this._sql, b: this._b }); return {}; },
  }; } } };
  const res = await scanner.ingestDmarcReport(mockEnv, {
    workspaceId: "ws1", domain: "example.com", source: "inbound_email", xmlString: dmarcMixedXml,
    ingestEndpointId: "e1", enforceDomainMatch: true,
  });
  const insertedReport = runs.some((r) => /INSERT INTO dmarc_aggregate_reports/.test(r.sql));
  const insertedRecords = runs.some((r) => /INSERT INTO dmarc_aggregate_records/.test(r.sql));
  const auditDup = runs.find((r) => /INSERT INTO audit_events/.test(r.sql) && r.b[3] === "dmarc_report_duplicate");
  const dupMetaOk = auditDup && typeof auditDup.b[7] === "string" && auditDup.b[7].includes('"source":"inbound_email"');
  return res.ok && res.duplicate === true && !insertedReport && !insertedRecords && !!dupMetaOk;
}));
// Every internal drop cause maps to a STABLE reason in the documented set.
results.push(securityContract("rua_drop_reason_normalization_stable", () => {
  const STABLE = new Set(["endpoint_not_found", "endpoint_inactive", "no_dmarc_attachment",
    "multiple_dmarc_attachments", "attachment_too_large", "decompressed_too_large",
    "compression_ratio_exceeded", "domain_mismatch", "parse_error", "unsupported_attachment",
    "unsupported_recipient_domain"]);
  const cases = {
    invalid_recipient: "endpoint_not_found", unknown_address: "endpoint_not_found",
    unsupported_recipient_domain: "unsupported_recipient_domain",
    endpoint_revoked: "endpoint_inactive", email_too_large: "attachment_too_large",
    zip_too_large: "attachment_too_large", multiple_attachments: "multiple_dmarc_attachments",
    zip_inflate_failed: "parse_error", zip_multi_entry: "parse_error", empty_xml: "parse_error",
    empty_attachment: "unsupported_attachment", domain_mismatch: "domain_mismatch",
    decompressed_too_large: "decompressed_too_large", compression_ratio_exceeded: "compression_ratio_exceeded",
    something_unexpected: "parse_error",
  };
  return Object.entries(cases).every(([k, v]) => scanner.normalizeInboundDropReason(k) === v && STABLE.has(v));
}));
// Internal platform errors are sanitized; genuine findings pass through intact.
results.push(securityContract("infra_error_sanitized_for_customer", () => {
  const raw = "Too many subrequests by single Worker invocation. The limit is 50.";
  const tls = scanner.sanitizeInfraErrorMessage(raw, "tls_rpt");
  const mta = scanner.sanitizeInfraErrorMessage(raw, "mta_sts");
  const finding = "No TXT record found at _smtp._tls.example.com.";
  return /TLS-RPT could not be verified/.test(tls) && !/subrequest/i.test(tls) &&
    /MTA-STS could not be verified/.test(mta) &&
    scanner.sanitizeInfraErrorMessage(finding, "tls_rpt") === finding;
}));

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
