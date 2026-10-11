#!/usr/bin/env node
// PR-2A.2 — shared-SAN measurement and ownership honesty.
//
// Deterministic executable contract for the fifth known unknown != zero defect
// class. The fixture uses the real SSL producer and certificate-intelligence
// consumer. Optional module URLs let the separate mutation runner exercise
// temporary source-level mutants in fresh processes without modifying checked-in
// bytes. CertSpotter is the only CT provider: its selected issuance measures the
// shared SAN, it carries no subject (none is claimed), and with no selected
// certificate the count stays unmeasured even though the provider answered.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (file) => pathToFileURL(
  path.join(root, "workers", "scan-api", "src", "engines", file),
).href;
const sslModuleUrl = process.env.PR2A2_SSL_MODULE_URL || engineUrl("ssl-scan.js");
const certIntelModuleUrl = process.env.PR2A2_CERT_INTEL_MODULE_URL || engineUrl("cert-intel.js");

const { resolveCertificateTransparency } = await import(sslModuleUrl);
const {
  buildCertificateOwnershipAssessment,
  runCertificateIntelligenceModule,
} = await import(certIntelModuleUrl);

let passed = 0;
let failed = 0;
const seen = new Set();
function check(id, condition, detail = "") {
  if (seen.has(id)) throw new Error(`duplicate contract id: ${id}`);
  seen.add(id);
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function equal(id, actual, expected) {
  check(id, Object.is(actual, expected),
    `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}
function containsExactNumber(value, target) {
  if (typeof value === "number") return value === target;
  if (Array.isArray(value)) return value.some((entry) => containsExactNumber(entry, target));
  if (value && typeof value === "object") {
    return Object.values(value).some((entry) => containsExactNumber(entry, target));
  }
  return false;
}

const NOW = "2026-08-03T14:00:00.000Z";
const realNow = Date.now;
Date.now = () => Date.parse(NOW);

const available = (data) => ({
  status: "available",
  data,
  error: null,
});
const unavailable = (error) => ({
  status: "unavailable",
  data: null,
  error,
});
function cacheFor(results) {
  return {
    async get(domain, provider) {
      if (!domain) throw new Error("fixture domain missing");
      if (!(provider in results)) throw new Error(`unexpected provider ${provider}`);
      return results[provider];
    },
  };
}
// The current subdomains producer shape: CertSpotter is the only CT source and
// the record declares it (ct-providers.js).
function subdomainsFor({ certSpotterError = null, items = [] } = {}) {
  return {
    items,
    sensitive: [],
    sources: {
      certspotter: { count: certSpotterError ? 0 : items.length, error: certSpotterError },
    },
    ct_providers: ["certspotter"],
  };
}
function intelligenceFor(ssl, subdomains) {
  return runCertificateIntelligenceModule({
    ssl,
    subdomains,
    dns_bruteforce: { items: [] },
  }, "example.com");
}
// Ownership is assessed from the SSL record only when HTTPS was observed; the
// measured and unmeasured cases below both carry that observation so the
// shared-SAN measurement gate alone decides ownership.
const withHttps = (ssl) => ({ ...ssl, https_available: true, https_probe_executed: true });
const issuance = (dnsNames, {
  notBefore = "2026-07-01T00:00:00.000Z",
  notAfter = "2026-12-01T00:00:00.000Z",
  issuer = "CertSpotter Fixture CA",
} = {}) => ({
  not_before: notBefore,
  not_after: notAfter,
  issuer: { name: issuer },
  dns_names: dnsNames,
});

try {
  // CertSpotter is the sole CT source, so its selected issuance's complete DNS
  // SAN list is the shared-SAN measurement. An issuance carries no certificate
  // subject, so none is claimed and ownership rests on the certificate's own
  // customer-domain names.
  const measuredOwnedSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({ certspotter: available([issuance(["example.com"])]) }),
  });
  const measuredOwnedIntel = intelligenceFor(
    withHttps(measuredOwnedSsl),
    subdomainsFor({ items: ["example.com"] }),
  );
  equal("CS_MEASURED_ZERO_PRESERVED", measuredOwnedSsl.cert_shared_san_count, 0);
  equal("CS_EVIDENCE_PRESERVED", measuredOwnedSsl.cert_issuer, "CertSpotter Fixture CA");
  equal("CS_NO_SUBJECT_CLAIMED", measuredOwnedSsl.cert_subject, null);
  equal("CS_SOLE_SOURCE_RECORDED", JSON.stringify(measuredOwnedSsl.ct_sources),
    JSON.stringify({ certspotter: { count: 1, error: null } }));
  equal("CS_MEASURED_OWNERSHIP_STATUS", measuredOwnedIntel.ownership.status, "customer_domain_certificate");
  equal("CS_MEASURED_CUSTOMER_OWNED_TRUE", measuredOwnedIntel.ownership.customer_owned, true);
  equal("CS_MEASURED_CONFIDENCE_90", measuredOwnedIntel.ownership.confidence, 90);
  equal("CS_MEASURED_MODULE_ZERO_PRESERVED", measuredOwnedIntel.shared_san_count, 0);
  equal("CS_OWNERSHIP_RESTS_ON_CUSTOMER_SAN",
    JSON.stringify(measuredOwnedIntel.ownership.evidence_signals), JSON.stringify(["customer_san"]));

  const measuredSharedSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({
      certspotter: available([issuance(["example.com", "unrelated.test"], { issuer: "Shared Fixture CA" })]),
    }),
  });
  const measuredSharedIntel = intelligenceFor(
    withHttps(measuredSharedSsl),
    subdomainsFor({ items: ["example.com"] }),
  );
  equal("CS_MEASURED_POSITIVE_COUNT", measuredSharedSsl.cert_shared_san_count, 1);
  equal("CS_MEASURED_SHARED_STATUS", measuredSharedIntel.ownership.status, "shared_certificate");
  equal("CS_MEASURED_SHARED_CUSTOMER_FALSE", measuredSharedIntel.ownership.customer_owned, false);
  equal("CS_MEASURED_SHARED_CONFIDENCE", measuredSharedIntel.ownership.confidence, 50);

  // A wildcard-only issuance has no customer-domain hostname of its own. With no
  // subject claimed, nothing supports customer ownership; a placeholder subject
  // (the scanned domain) would fabricate a customer-owned wildcard here.
  const wildcardOnlySsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({ certspotter: available([issuance(["*.example.com"])]) }),
  });
  const wildcardOnlyIntel = intelligenceFor(
    withHttps(wildcardOnlySsl),
    subdomainsFor({ items: ["www.example.com"] }),
  );
  equal("WILDCARD_ONLY_MEASURED_ZERO", wildcardOnlySsl.cert_shared_san_count, 0);
  equal("WILDCARD_ONLY_STATUS_UNCERTAIN", wildcardOnlyIntel.ownership.status, "ownership_uncertain");
  equal("WILDCARD_ONLY_NOT_CUSTOMER_OWNED", wildcardOnlyIntel.ownership.customer_owned, false);

  // CertSpotter answered, but no currently valid issuance covers the apex: one
  // apex issuance has expired and the valid one names only a subdomain. No
  // certificate was selected, so the shared-SAN count was not measured and an
  // answering provider never turns it into one.
  const unselectedSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({
      certspotter: available([
        issuance(["example.com"], {
          notBefore: "2025-07-01T00:00:00.000Z",
          notAfter: "2026-01-01T00:00:00.000Z",
        }),
        issuance(["mail.example.com"]),
      ]),
    }),
  });
  const unselectedIntel = intelligenceFor(
    withHttps(unselectedSsl),
    subdomainsFor({ items: ["mail.example.com"] }),
  );

  equal("UNSELECTED_SSL_SHARED_SAN_NULL", unselectedSsl.cert_shared_san_count, null);
  equal("UNSELECTED_SOURCE_ANSWERED", JSON.stringify(unselectedSsl.ct_sources),
    JSON.stringify({ certspotter: { count: 2, error: null } }));
  check("UNSELECTED_CERTIFICATE_DETAIL_NULL",
    unselectedSsl.cert_not_after === null && unselectedSsl.cert_subject === null &&
      unselectedSsl.cert_issuer === null);
  equal("UNSELECTED_MODULE_SHARED_SAN_NULL", unselectedIntel.shared_san_count, null);
  equal("UNSELECTED_OWNERSHIP_UNKNOWN", unselectedIntel.ownership.status, "unknown");
  equal("UNSELECTED_OWNERSHIP_NOT_ASSESSED", unselectedIntel.ownership.assessment_state, "not_assessed");
  equal("UNSELECTED_OWNERSHIP_REASON", unselectedIntel.ownership.assessment_reason, "shared_san_not_measured");
  equal("UNSELECTED_CUSTOMER_OWNED_NULL", unselectedIntel.ownership.customer_owned, null);
  equal("UNSELECTED_CONFIDENCE_NULL", unselectedIntel.ownership.confidence, null);
  check("UNSELECTED_NO_CONFIDENCE_90", !containsExactNumber(unselectedIntel.ownership, 90));
  check(
    "UNSELECTED_BRITISH_NOT_ASSESSED_WORDING",
    /not assessed/i.test(unselectedIntel.ownership.customer_message) &&
      !/\b0\s+(?:shared\s+)?SAN/i.test(unselectedIntel.ownership.customer_message),
    unselectedIntel.ownership.customer_message,
  );

  const serialisedUnselected = JSON.stringify(unselectedIntel);
  check("UNSELECTED_SERIALISATION_NO_OBJECT_OBJECT", !serialisedUnselected.includes("[object Object]"));
  check("UNSELECTED_SERIALISATION_NO_FAKE_ZERO_COPY", !/0 shared (?:SAN|certificate hostname)/i.test(serialisedUnselected));

  const blackoutSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({ certspotter: unavailable("CertSpotter timed out") }),
  });
  const blackoutIntel = intelligenceFor(
    blackoutSsl,
    subdomainsFor({ certSpotterError: "CertSpotter timed out" }),
  );
  equal("BLACKOUT_SSL_SHARED_SAN_NULL", blackoutSsl.cert_shared_san_count, null);
  equal("BLACKOUT_CERTIFICATE_DETAIL_UNCHANGED", blackoutSsl.cert_not_after, null);
  equal("BLACKOUT_SOURCE_ERROR_PRESERVED", blackoutSsl.ct_sources.certspotter?.error, "CertSpotter timed out");
  equal("BLACKOUT_MODULE_SHARED_SAN_NULL", blackoutIntel.shared_san_count, null);
  equal("BLACKOUT_OWNERSHIP_UNKNOWN", blackoutIntel.ownership.status, "unknown");
  equal("BLACKOUT_RISK_UNKNOWN_UNCHANGED", blackoutIntel.certificate_risk_level, "unknown");
  equal("BLACKOUT_INCOMPLETE_TRUE_UNCHANGED", blackoutIntel.incomplete, true);
  equal("BLACKOUT_REASON_UNCHANGED", blackoutIntel.incomplete_reason, "ct_sources_unavailable");
  check(
    "BLACKOUT_DIAGNOSTIC_SINGLE_SOURCE",
    blackoutIntel.suspicious_certificate_signals.some((signal) =>
      signal.signal === "ct_sources_unavailable" && signal.severity === "info" &&
      signal.description === "The Certificate Transparency source was unavailable during this scan. No CT inventory evidence was collected; live TLS evidence, when available, is assessed separately."),
  );
  equal("BLACKOUT_WITHOUT_LIVE_EVIDENCE_IS_NOT_LIVE_VERIFIED", blackoutIntel.live_certificate_verified, false);
  equal("BLACKOUT_WITHOUT_LIVE_EVIDENCE_RETAINS_NO_LIVE_RECEIPT", blackoutIntel.live_tls, null);

  // A stored historical two-provider subdomains record (undeclared providers,
  // the retired provider under a neutral key) keeps its original meaning: every
  // recorded provider failed, so it is still a blackout with the two-source copy.
  const historicalBlackoutIntel = intelligenceFor(blackoutSsl, {
    items: [],
    sensitive: [],
    sources: {
      retired_provider: { count: 0, error: "provider timed out" },
      certspotter: { count: 0, error: "CertSpotter timed out" },
    },
  });
  check("HISTORICAL_BLACKOUT_INCOMPLETE",
    historicalBlackoutIntel.incomplete === true &&
      historicalBlackoutIntel.incomplete_reason === "ct_sources_unavailable");
  check(
    "HISTORICAL_BLACKOUT_DIAGNOSTIC_KEPT",
    historicalBlackoutIntel.suspicious_certificate_signals.some((signal) =>
      signal.signal === "ct_sources_unavailable" && signal.severity === "info" &&
      signal.description === "Both Certificate Transparency sources were unavailable during this scan. No CT inventory evidence was collected; live TLS evidence, when available, is assessed separately."),
  );

  const errorSentinelOwnership = buildCertificateOwnershipAssessment({
    cert_subject: "example.com",
    cert_san_names: ["example.com"],
    cert_shared_san_count: 0,
    cert_wildcard_san_count: 0,
    ct_sources: { certspotter: { count: 9, error: "HTTP 502" } },
  }, "example.com");
  equal("SENTINEL_ERROR_DOMINATES_ZERO", errorSentinelOwnership.status, "unknown");
  equal("SENTINEL_ERROR_BLOCKS_CUSTOMER_OWNED", errorSentinelOwnership.customer_owned, null);
  equal("SENTINEL_ERROR_BLOCKS_CONFIDENCE", errorSentinelOwnership.confidence, null);

  // A provider that answered with no issuances supplied no SAN-bearing result,
  // so a zero beside it is not a measurement.
  const emptyAnswerOwnership = buildCertificateOwnershipAssessment({
    cert_subject: "example.com",
    cert_san_names: ["example.com"],
    cert_shared_san_count: 0,
    cert_wildcard_san_count: 0,
    ct_sources: { certspotter: { count: 0, error: null } },
  }, "example.com");
  equal("SENTINEL_EMPTY_ANSWER_DOMINATES_ZERO", emptyAnswerOwnership.status, "unknown");

  const missingSourceOwnership = buildCertificateOwnershipAssessment({
    cert_subject: "example.com",
    cert_san_names: ["example.com"],
    cert_shared_san_count: 0,
  }, "example.com");
  equal("MISSING_SOURCE_DOMINATES_ZERO", missingSourceOwnership.status, "unknown");

  const reportSnapshotSource = fs.readFileSync(
    path.join(root, "workers/scan-api/src/engines/report-snapshot.js"), "utf8",
  );
  const pdfSource = fs.readFileSync(
    path.join(root, "workers/scan-api/src/engines/pdf.js"), "utf8",
  );
  const scanRouteSource = fs.readFileSync(
    path.join(root, "workers/scan-api/src/routes/scans.js"), "utf8",
  );
  const frontendSources = [
    "frontend/src/components/CertificateAssuranceSummary.jsx",
    "frontend/src/components/ExecutiveReportV2.jsx",
    "frontend/src/pages/ScanDetail.jsx",
    "frontend/src/pages/IntelligencePage.jsx",
    "frontend/src/pages/ws/CertificatesPage.jsx",
  ].map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  const affectedRead = /\b(?:cert_shared_san_count|shared_san_count|customer_owned)\b/;
  check("SNAPSHOT_HAS_NO_AFFECTED_READER", !affectedRead.test(reportSnapshotSource));
  check("PDF_HAS_NO_AFFECTED_READER", !affectedRead.test(pdfSource));
  check("FRONTEND_HAS_NO_AFFECTED_READER", !affectedRead.test(frontendSources));
  check(
    "REPORT_API_TRANSPORTS_MODULE_NULLS",
    /const customerReport = projectTlsReportForCustomer\(raw\);/.test(scanRouteSource) &&
      /const storedModules = projectPhase5EvidenceForCustomer\(customerReport\.modules \?\? \{\}\);/.test(scanRouteSource) &&
      /modules: \{\s*\.\.\.normalisedModules,/s.test(scanRouteSource),
  );
} finally {
  Date.now = realNow;
}

console.log(`PR-2A.2 shared-SAN honesty: ${passed}/${passed + failed} contracts passed`);
if (failed > 0) process.exit(1);
console.log("PR-2A.2 shared-SAN honesty validation passed");
