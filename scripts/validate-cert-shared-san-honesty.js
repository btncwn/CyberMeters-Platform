#!/usr/bin/env node
// PR-2A.2 — shared-SAN measurement and ownership honesty.
//
// Deterministic executable contract for the fifth known unknown != zero defect
// class. The fixture uses the real SSL producer and certificate-intelligence
// consumer. Optional module URLs let the separate mutation runner exercise
// temporary source-level mutants in fresh processes without modifying checked-in
// bytes.
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
function subdomainsFor({ crtError = null, certSpotterError = null, items = [] } = {}) {
  return {
    items,
    sensitive: [],
    sources: {
      crt_sh: { count: crtError ? 0 : items.length, error: crtError },
      certspotter: { count: certSpotterError ? 0 : items.length, error: certSpotterError },
    },
  };
}
function intelligenceFor(ssl, subdomains) {
  return runCertificateIntelligenceModule({
    ssl,
    subdomains,
    dns_bruteforce: { items: [] },
  }, "example.com");
}

try {
  const certSpotterIssuance = [{
    not_before: "2026-07-01T00:00:00.000Z",
    not_after: "2026-12-01T00:00:00.000Z",
    issuer: { name: "CertSpotter Fixture CA" },
    dns_names: ["example.com"],
  }];
  const certSpotterOnlySsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({
      crt_sh: unavailable("HTTP 502"),
      certspotter: available(certSpotterIssuance),
    }),
  });
  const certSpotterOnlyIntel = intelligenceFor(
    certSpotterOnlySsl,
    subdomainsFor({ crtError: "HTTP 502", items: ["example.com"] }),
  );

  equal("CS_ONLY_SSL_SHARED_SAN_NULL", certSpotterOnlySsl.cert_shared_san_count, null);
  equal("CS_ONLY_CERTSPOTTER_EVIDENCE_PRESERVED", certSpotterOnlySsl.cert_issuer, "CertSpotter Fixture CA");
  equal("CS_ONLY_SUBJECT_PRESERVED", certSpotterOnlySsl.cert_subject, "example.com");
  equal("CS_ONLY_CRT_ERROR_PRESERVED", certSpotterOnlySsl.ct_sources.crt_sh.error, "HTTP 502");
  equal("CS_ONLY_MODULE_SHARED_SAN_NULL", certSpotterOnlyIntel.shared_san_count, null);
  equal("CS_ONLY_OWNERSHIP_UNKNOWN", certSpotterOnlyIntel.ownership.status, "unknown");
  equal("CS_ONLY_OWNERSHIP_NOT_ASSESSED", certSpotterOnlyIntel.ownership.assessment_state, "not_assessed");
  equal("CS_ONLY_OWNERSHIP_REASON", certSpotterOnlyIntel.ownership.assessment_reason, "shared_san_not_measured");
  equal("CS_ONLY_CUSTOMER_OWNED_NULL", certSpotterOnlyIntel.ownership.customer_owned, null);
  equal("CS_ONLY_CONFIDENCE_NULL", certSpotterOnlyIntel.ownership.confidence, null);
  check("CS_ONLY_NO_CONFIDENCE_90", !containsExactNumber(certSpotterOnlyIntel.ownership, 90));
  check(
    "CS_ONLY_BRITISH_NOT_ASSESSED_WORDING",
    /not assessed/i.test(certSpotterOnlyIntel.ownership.customer_message) &&
      !/\b0\s+(?:shared\s+)?SAN/i.test(certSpotterOnlyIntel.ownership.customer_message),
    certSpotterOnlyIntel.ownership.customer_message,
  );

  const serialisedCertSpotterOnly = JSON.stringify(certSpotterOnlyIntel);
  check("CS_ONLY_SERIALISATION_NO_OBJECT_OBJECT", !serialisedCertSpotterOnly.includes("[object Object]"));
  check("CS_ONLY_SERIALISATION_NO_FAKE_ZERO_COPY", !/0 shared (?:SAN|certificate hostname)/i.test(serialisedCertSpotterOnly));

  const measuredOwnedSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({
      crt_sh: available([{
        not_before: "2026-07-01T00:00:00.000Z",
        not_after: "2026-12-01T00:00:00.000Z",
        issuer_name: "crt.sh Fixture CA",
        common_name: "example.com",
        name_value: "example.com",
      }]),
      certspotter: available([]),
    }),
  });
  const measuredOwnedIntel = intelligenceFor(
    measuredOwnedSsl,
    subdomainsFor({ items: ["example.com"] }),
  );
  equal("CRT_MEASURED_ZERO_PRESERVED", measuredOwnedSsl.cert_shared_san_count, 0);
  equal("CRT_MEASURED_OWNERSHIP_STATUS", measuredOwnedIntel.ownership.status, "customer_domain_certificate");
  equal("CRT_MEASURED_CUSTOMER_OWNED_TRUE", measuredOwnedIntel.ownership.customer_owned, true);
  equal("CRT_MEASURED_CONFIDENCE_90", measuredOwnedIntel.ownership.confidence, 90);
  equal("CRT_MEASURED_MODULE_ZERO_PRESERVED", measuredOwnedIntel.shared_san_count, 0);

  const measuredSharedSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({
      crt_sh: available([{
        not_before: "2026-07-01T00:00:00.000Z",
        not_after: "2026-12-01T00:00:00.000Z",
        issuer_name: "Shared Fixture CA",
        common_name: "example.com",
        name_value: "example.com\nunrelated.test",
      }]),
      certspotter: available([]),
    }),
  });
  const measuredSharedIntel = intelligenceFor(
    measuredSharedSsl,
    subdomainsFor({ items: ["example.com"] }),
  );
  equal("CRT_MEASURED_POSITIVE_COUNT", measuredSharedSsl.cert_shared_san_count, 1);
  equal("CRT_MEASURED_SHARED_STATUS", measuredSharedIntel.ownership.status, "shared_certificate");
  equal("CRT_MEASURED_SHARED_CUSTOMER_FALSE", measuredSharedIntel.ownership.customer_owned, false);
  equal("CRT_MEASURED_SHARED_CONFIDENCE", measuredSharedIntel.ownership.confidence, 50);

  const blackoutSsl = await resolveCertificateTransparency("example.com", {
    ctCache: cacheFor({
      crt_sh: unavailable("crt.sh timed out"),
      certspotter: unavailable("CertSpotter timed out"),
    }),
  });
  const blackoutIntel = intelligenceFor(
    blackoutSsl,
    subdomainsFor({
      crtError: "crt.sh timed out",
      certSpotterError: "CertSpotter timed out",
    }),
  );
  equal("BLACKOUT_SSL_SHARED_SAN_NULL", blackoutSsl.cert_shared_san_count, null);
  equal("BLACKOUT_CERTIFICATE_DETAIL_UNCHANGED", blackoutSsl.cert_not_after, null);
  equal("BLACKOUT_MODULE_SHARED_SAN_NULL", blackoutIntel.shared_san_count, null);
  equal("BLACKOUT_OWNERSHIP_UNKNOWN", blackoutIntel.ownership.status, "unknown");
  equal("BLACKOUT_RISK_UNKNOWN_UNCHANGED", blackoutIntel.certificate_risk_level, "unknown");
  equal("BLACKOUT_INCOMPLETE_TRUE_UNCHANGED", blackoutIntel.incomplete, true);
  equal("BLACKOUT_REASON_UNCHANGED", blackoutIntel.incomplete_reason, "ct_sources_unavailable");
  check(
    "BLACKOUT_DIAGNOSTIC_UNCHANGED",
    blackoutIntel.suspicious_certificate_signals.some((signal) =>
      signal.signal === "ct_sources_unavailable" && /could not be assessed/i.test(signal.description)),
  );

  const errorSentinelOwnership = buildCertificateOwnershipAssessment({
    cert_subject: "example.com",
    cert_san_names: ["example.com"],
    cert_shared_san_count: 0,
    cert_wildcard_san_count: 0,
    ct_sources: { crt_sh: { count: 9, error: "HTTP 502" } },
  }, "example.com");
  equal("SENTINEL_ERROR_DOMINATES_ZERO", errorSentinelOwnership.status, "unknown");
  equal("SENTINEL_ERROR_BLOCKS_CUSTOMER_OWNED", errorSentinelOwnership.customer_owned, null);
  equal("SENTINEL_ERROR_BLOCKS_CONFIDENCE", errorSentinelOwnership.confidence, null);

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
    /const storedModules = projectPhase5EvidenceForCustomer\(raw\.modules \?\? \{\}\);/.test(scanRouteSource) &&
      /modules: \{\s*\.\.\.normalisedModules,/s.test(scanRouteSource),
  );
} finally {
  Date.now = realNow;
}

console.log(`PR-2A.2 shared-SAN honesty: ${passed}/${passed + failed} contracts passed`);
if (failed > 0) process.exit(1);
console.log("PR-2A.2 shared-SAN honesty validation passed");
