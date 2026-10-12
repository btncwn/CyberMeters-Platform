#!/usr/bin/env node
// PR-2A.2 — shared-SAN measurement and ownership honesty.
//
// Deterministic executable contract for the unknown != zero defect class on
// certificate ownership. The shared-SAN count is measured only from the SAN
// list of the certificate the live site presented; with no captured leaf it
// stays unmeasured and ownership is not assessed. Stored records from earlier
// scans keep their historical sentinel precedence. An optional module URL lets
// the separate mutation runner exercise temporary source-level mutants in
// fresh processes without modifying checked-in bytes.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { liveTlsSsl, liveTlsReceipt } from "./lib/live-tls-fixture.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (file) => pathToFileURL(
  path.join(root, "workers", "scan-api", "src", "engines", file),
).href;
const certIntelModuleUrl = process.env.PR2A2_CERT_INTEL_MODULE_URL || engineUrl("cert-intel.js");

const {
  buildCertificateOwnershipAssessment,
  runCertificateIntelligenceModule,
} = await import(certIntelModuleUrl);
const { attachLiveTlsToSsl } = await import(engineUrl("network-probe.js"));

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

const intelligenceFor = (ssl) => runCertificateIntelligenceModule({
  ssl,
  subdomains: { items: [], wildcard_dns: false },
  dns_bruteforce: { items: [] },
}, "example.com");

// ── Live leaf: the SAN list of the served certificate is the measurement ────
const ownedIntel = intelligenceFor(liveTlsSsl({ subject: "CN=example.com", dnsNames: ["example.com", "www.example.com"] }));
equal("LIVE_MEASURED_ZERO_PRESERVED", ownedIntel.shared_san_count, 0);
equal("LIVE_OWNERSHIP_STATUS", ownedIntel.ownership.status, "customer_domain_certificate");
equal("LIVE_CUSTOMER_OWNED_TRUE", ownedIntel.ownership.customer_owned, true);
equal("LIVE_CONFIDENCE_90", ownedIntel.ownership.confidence, 90);
equal("LIVE_SUBJECT_FROM_CERTIFICATE",
  JSON.stringify(ownedIntel.ownership.evidence_signals), JSON.stringify(["subject_match"]));

// A served certificate whose subject names another host still belongs to the
// customer through its own customer-domain SANs, never through a placeholder.
const sanOwnedIntel = intelligenceFor(liveTlsSsl({ subject: "CN=other.test", dnsNames: ["example.com"] }));
equal("LIVE_OWNERSHIP_RESTS_ON_CUSTOMER_SAN",
  JSON.stringify(sanOwnedIntel.ownership.evidence_signals), JSON.stringify(["customer_san"]));

const sharedIntel = intelligenceFor(liveTlsSsl({ subject: "CN=example.com", dnsNames: ["example.com", "unrelated.test"] }));
equal("LIVE_POSITIVE_COUNT", sharedIntel.shared_san_count, 1);
equal("LIVE_SHARED_STATUS", sharedIntel.ownership.status, "shared_certificate");
equal("LIVE_SHARED_CUSTOMER_FALSE", sharedIntel.ownership.customer_owned, false);
equal("LIVE_SHARED_CONFIDENCE", sharedIntel.ownership.confidence, 50);

// A customer wildcard is not a foreign name.
const wildcardIntel = intelligenceFor(liveTlsSsl({ subject: "CN=*.example.com", dnsNames: ["*.example.com"] }));
equal("LIVE_WILDCARD_MEASURED_ZERO", wildcardIntel.shared_san_count, 0);
equal("LIVE_WILDCARD_STATUS", wildcardIntel.ownership.status, "customer_domain_wildcard");

// A wildcard-only certificate with no common name has no customer-domain host
// of its own; nothing supports customer ownership.
const wildcardNoSubjectIntel = intelligenceFor(liveTlsSsl({ subject: "O=Fixture Org", dnsNames: ["*.example.com"] }));
equal("LIVE_WILDCARD_NO_SUBJECT_UNCERTAIN", wildcardNoSubjectIntel.ownership.status, "ownership_uncertain");
equal("LIVE_WILDCARD_NO_SUBJECT_NOT_CUSTOMER_OWNED", wildcardNoSubjectIntel.ownership.customer_owned, false);

// ── No live leaf: unmeasured, never zero ────────────────────────────────────
const unobservedIntel = intelligenceFor({ tls_state: "observed_present", https_available: true });
equal("NOT_OBSERVED_SHARED_SAN_NULL", unobservedIntel.shared_san_count, null);
equal("NOT_OBSERVED_OWNERSHIP_UNKNOWN", unobservedIntel.ownership.status, "unknown");
equal("NOT_OBSERVED_OWNERSHIP_NOT_ASSESSED", unobservedIntel.ownership.assessment_state, "not_assessed");
equal("NOT_OBSERVED_OWNERSHIP_REASON", unobservedIntel.ownership.assessment_reason, "shared_san_not_measured");
equal("NOT_OBSERVED_CUSTOMER_OWNED_NULL", unobservedIntel.ownership.customer_owned, null);
equal("NOT_OBSERVED_CONFIDENCE_NULL", unobservedIntel.ownership.confidence, null);
check("NOT_OBSERVED_NO_CONFIDENCE_90", !containsExactNumber(unobservedIntel.ownership, 90));
check(
  "NOT_OBSERVED_BRITISH_NOT_ASSESSED_WORDING",
  /not assessed/i.test(unobservedIntel.ownership.customer_message) &&
    !/\b0\s+(?:shared\s+)?SAN/i.test(unobservedIntel.ownership.customer_message),
  unobservedIntel.ownership.customer_message,
);
const serialisedUnobserved = JSON.stringify(unobservedIntel);
check("NOT_OBSERVED_SERIALISATION_NO_OBJECT_OBJECT", !serialisedUnobserved.includes("[object Object]"));
check("NOT_OBSERVED_SERIALISATION_NO_FAKE_ZERO_COPY", !/0 shared (?:SAN|certificate hostname)/i.test(serialisedUnobserved));
equal("NOT_OBSERVED_RISK_UNKNOWN", unobservedIntel.certificate_risk_level, "unknown");
equal("NOT_OBSERVED_INCOMPLETE", unobservedIntel.incomplete, true);
equal("NOT_OBSERVED_REASON", unobservedIntel.incomplete_reason, "certificate_not_observed");
// An informational observation (wildcard DNS) never turns an unknown
// certificate into a graded risk.
const unobservedWildcardIntel = runCertificateIntelligenceModule({
  ssl: { tls_state: "observed_present", https_available: true },
  subdomains: { items: [], wildcard_dns: true },
  dns_bruteforce: { items: [] },
}, "example.com");
equal("NOT_OBSERVED_INFO_SIGNAL_KEEPS_RISK_UNKNOWN", unobservedWildcardIntel.certificate_risk_level, "unknown");

// A configured collector that failed leaves the same unknown, and is never a
// verified live certificate.
const failedCollectorIntel = intelligenceFor(attachLiveTlsToSsl(
  { tls_state: "observed_present", https_available: true },
  { receipt: null, error: "live_tls_unavailable" },
));
equal("COLLECTOR_FAILURE_SHARED_SAN_NULL", failedCollectorIntel.shared_san_count, null);
equal("COLLECTOR_FAILURE_OWNERSHIP_UNKNOWN", failedCollectorIntel.ownership.status, "unknown");
equal("COLLECTOR_FAILURE_NOT_LIVE_VERIFIED", failedCollectorIntel.live_certificate_verified, false);

// A receipt whose only endpoint did not complete the leaf capture measures
// nothing either.
const partialReceipt = liveTlsReceipt({ subject: "CN=example.com" });
partialReceipt.observations[0].tls = { ...partialReceipt.observations[0].tls, leaf_collected: false, reason: "handshake_timeout" };
partialReceipt.quality = "partial";
const partialIntel = intelligenceFor(attachLiveTlsToSsl({ tls_state: "observed_present", https_available: true }, { receipt: partialReceipt }));
equal("PARTIAL_RECEIPT_SHARED_SAN_NULL", partialIntel.shared_san_count, null);

// ── historical: stored records keep their sentinel precedence ───────────────
const storedRecord = (sources, extra = {}) => ({
  cert_subject: "example.com",
  cert_san_names: ["example.com"],
  cert_shared_san_count: 0,
  cert_wildcard_san_count: 0,
  ...(sources === undefined ? {} : { ct_sources: sources }),
  ...extra,
});
const storedMeasured = buildCertificateOwnershipAssessment(storedRecord({ provider_a: { count: 4, error: null } }), "example.com");
equal("HISTORICAL_MEASURED_ZERO_READS", storedMeasured.status, "customer_domain_certificate");
const errorSentinelOwnership = buildCertificateOwnershipAssessment(storedRecord({ provider_a: { count: 9, error: "HTTP 502" } }), "example.com");
equal("SENTINEL_ERROR_DOMINATES_ZERO", errorSentinelOwnership.status, "unknown");
equal("SENTINEL_ERROR_BLOCKS_CUSTOMER_OWNED", errorSentinelOwnership.customer_owned, null);
equal("SENTINEL_ERROR_BLOCKS_CONFIDENCE", errorSentinelOwnership.confidence, null);
// A source that answered with no SAN-bearing result supplied no measurement.
const emptyAnswerOwnership = buildCertificateOwnershipAssessment(storedRecord({ provider_a: { count: 0, error: null } }), "example.com");
equal("SENTINEL_EMPTY_ANSWER_DOMINATES_ZERO", emptyAnswerOwnership.status, "unknown");
const missingSourceOwnership = buildCertificateOwnershipAssessment(storedRecord(undefined), "example.com");
equal("MISSING_SOURCE_DOMINATES_ZERO", missingSourceOwnership.status, "unknown");

// ── Readers ─────────────────────────────────────────────────────────────────
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

console.log(`PR-2A.2 shared-SAN honesty: ${passed}/${passed + failed} contracts passed`);
if (failed > 0) process.exit(1);
console.log("PR-2A.2 shared-SAN honesty validation passed");
