#!/usr/bin/env node
// Item 9 P5 — deterministic customer-surface parity and legacy compatibility.
//
// Production engines provide the canonical P1-P4 model. This validator only
// checks the additive customer projection and its snapshot/report/PDF readers.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCertificateIntelligenceModule } from "../workers/scan-api/src/engines/cert-intel.js";
import { attachLiveTlsToSsl, liveCertificateFindings } from "../workers/scan-api/src/engines/network-probe.js";
import {
  buildCertificateCustomerPresentation,
  buildCertificateRelationshipPresentation,
  certificateAssuranceApiProjection,
  certificateAssuranceFromSnapshot,
  CERTIFICATE_CUSTOMER_STATES,
} from "../workers/scan-api/src/engines/certificate-customer-presentation.js";
import { composeSnapshot } from "../workers/scan-api/src/engines/report-snapshot.js";
import { buildExecutiveReportV2 } from "../workers/scan-api/src/engines/executive-report.js";
import {
  buildScanReportPdf,
  pdfEsc,
  buildWorkspaceExecutivePdf,
} from "../workers/scan-api/src/engines/pdf.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(fs.readFileSync(path.join(
  root,
  "scripts",
  "fixtures",
  "item9-p5-certificate-customer-parity.json",
), "utf8"));
const trustFixture = JSON.parse(fs.readFileSync(path.join(
  root,
  "scripts",
  "fixtures",
  "item9-p4-certificate-trust-depth.json",
), "utf8"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) =>
  ok(name, actual === expected,
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
const clone = (value) => structuredClone(value);
const run = (modules) =>
  runCertificateIntelligenceModule(modules, trustFixture.domain, {
    providerHealth: trustFixture.provider_health,
    observedAt: trustFixture.observed_at,
    engineVersion: trustFixture.engine_version,
  });

const completeIntelligence = run(clone(trustFixture.base_modules));
const completeModel = completeIntelligence.signal_completeness;
const presentation = buildCertificateCustomerPresentation({
  signalCompleteness: completeModel,
});

eq("all canonical signals are presented",
  presentation.signal_order.length, fixture.expected_signal_count);
eq("customer state vocabulary is exact",
  JSON.stringify(CERTIFICATE_CUSTOMER_STATES),
  JSON.stringify(fixture.expected_customer_states));
for (const key of presentation.signal_order) {
  const source = completeModel.signals[key];
  const customer = presentation.signals[key];
  ok(`${key}: customer projection exists`, Boolean(customer));
  eq(`${key}: achieved grade retained`,
    customer.evidence_grade.achieved, source.achieved_grade);
  eq(`${key}: source type retained`, customer.source_type, source.source_type);
  eq(`${key}: provenance retained`,
    JSON.stringify(customer.provenance), JSON.stringify(source.provenance));
  eq(`${key}: required corroboration retained`,
    JSON.stringify(customer.required_corroboration),
    JSON.stringify(source.grade_contract.required_corroboration));
  eq(`${key}: cited authorities retained`,
    JSON.stringify(customer.cited_authorities),
    JSON.stringify(source.authorities));
  ok(`${key}: no healthy/passed customer state`,
    !["healthy", "passed", "secure", "compliant"].includes(customer.state));
}
const authorityIds = new Set(
  Object.values(presentation.signals)
    .flatMap((signal) => signal.cited_authorities || [])
    .map((authority) => authority.standard_id),
);
for (const standard of fixture.expected_authorities) {
  ok(`${standard}: customer projection retains authority`,
    authorityIds.has(standard));
}

const missingFieldModel = clone(completeModel);
delete missingFieldModel.signals.chain;
const missingField = buildCertificateCustomerPresentation({
  signalCompleteness: missingFieldModel,
});
eq("missing signal is not_observed, not passed",
  missingField.signals.chain.state, "not_observed");
ok("missing signal explanation refuses favourable synthesis",
  /not recorded|not inferred/i.test(missingField.signals.chain.customer_message));

const noRevocationModules = clone(trustFixture.base_modules);
noRevocationModules.ssl.certificate_evidence.live_tls.revocation_assurance = {
  assessment_performed: false,
  stapled_ocsp: null,
  response_validated: false,
  status: "unknown",
};
const noRevocationModel = run(noRevocationModules).signal_completeness;
const noRevocation = buildCertificateCustomerPresentation({
  signalCompleteness: noRevocationModel,
});
eq("missing OCSP degrades revocation only",
  noRevocation.signals.revocation_assurance.state, "incomplete");
for (const sibling of ["leaf", "san", "issuer", "expiry", "active_service"]) {
  eq(`${sibling}: revocation absence does not erase sibling`,
    noRevocation.signals[sibling].state, "observed");
}

const ctOnlyModules = clone(trustFixture.base_modules);
ctOnlyModules.ssl.certificate_evidence.live_tls = {
  leaf_collected: false,
  chain_collected: false,
  reason: "peer_certificate_not_exposed",
};
const ctOnly = buildCertificateCustomerPresentation({
  signalCompleteness: run(ctOnlyModules).signal_completeness,
});
eq("CT-only summary remains explicit", ctOnly.summary.ct_only, true);
ok("CT-only customer copy refuses live-serving promotion",
  ctOnly.summary.live_tls_certificate.message.includes(
    fixture.ct_only_live_message_fragment,
  ));
ok("CT-only does not promote live leaf",
  ctOnly.signals.leaf.state !== "observed");
ok("CT-only does not promote hostname match",
  ctOnly.signals.hostname_match.state !== "observed");
ok("CT-only does not promote trust-store validation",
  ctOnly.signals.trust_store_validation.state !== "observed");

const previousModel = clone(completeModel);
previousModel.signals.leaf.value.certificate_identity =
  fixture.relationship.previous_identity;
const currentModel = clone(completeModel);
currentModel.signals.leaf.value.certificate_identity =
  fixture.relationship.current_identity;
currentModel.signals.parallel_certificate_set = {
  ...currentModel.signals.parallel_certificate_set,
  observation: "present",
  completeness_state: "monitoring_healthy",
  observation_scope: "live_tls_endpoint_set",
  value: {
    observations: [
      {
        certificate_identity: fixture.relationship.previous_identity,
        source: "live_tls",
        endpoint: "edge-a",
      },
      {
        certificate_identity: fixture.relationship.current_identity,
        source: "live_tls",
        endpoint: "edge-b",
      },
    ],
  },
};
const relationship = buildCertificateRelationshipPresentation({
  lifecycle: {
    replacement_detected_at: "2026-07-26T14:58:00.000Z",
    certificate_identity: fixture.relationship.current_identity,
  },
  currentSignalCompleteness: currentModel,
  previousSignalCompleteness: previousModel,
});
eq("replacement/parallel has one deterministic precedence",
  relationship.relationship, fixture.relationship.expected_precedence);
eq("replacement/parallel pair is unified",
  relationship.same_certificate_pair, true);
ok("relationship wording rejects contradictory findings",
  /one transition-context explanation, not two contradictory/i.test(
    relationship.customer_message,
  ));

const lifecycleRecord = {
  certificate_lifecycle_id: "certlife-fixture",
  domain_id: "dom-fixture",
  replacement_detected_at: "2026-07-26T14:58:00.000Z",
  certificate_assurance: {
    relationship,
  },
};
const report = {
  status: "completed",
  domain: fixture.domain,
  started_at: fixture.observed_at,
  completed_at: fixture.observed_at,
  cyber_metrics_score: 70,
  scan_quality: {
    status: "complete",
    modules_skipped: [],
    warnings: [],
  },
  monitoring_states: {
    signals: {},
  },
  modules: {
    certificate_intelligence: {
      ...completeIntelligence,
      signal_completeness: currentModel,
    },
  },
  findings: [],
};
const snapshot = composeSnapshot({
  snapshotId: "snap-fixture",
  workspaceId: "ws-fixture",
  domainId: "dom-fixture",
  scanId: "scan-fixture",
  domain: fixture.domain,
  report,
  cyberEssentials: { status: "not_assessed" },
  ceReadiness: null,
  caseRows: [],
  questionSetVersions: [],
  certificateLifecycleRecords: [lifecycleRecord],
  supersedesSnapshotId: null,
  builtAt: fixture.built_at,
});
eq("new snapshot stores additive certificate presentation",
  snapshot.certificate_assurance.schema,
  "certificate-customer-presentation-v1");
eq("snapshot freezes relationship precedence",
  snapshot.certificate_assurance.relationship.relationship,
  fixture.relationship.expected_precedence);
eq("snapshot lifecycle is recorded", snapshot.certificate_assurance.lifecycle.status,
  "recorded");

// New snapshots describe admitted live measurements without regrading CT
// coverage or turning a scoped trust-store result into universal verification.
const liveModules = clone(trustFixture.base_modules);
const liveCarrier = liveModules.ssl.certificate_evidence.live_tls;
delete liveCarrier.presented_chain;
delete liveCarrier.chain;
delete liveCarrier.revocation_assurance;
liveCarrier.runtime_chain = { observation_scope: "node_tls_issuer_chain", collection_complete: false, certificates: [] };
liveCarrier.all_planned_endpoints_observed = true;
liveCarrier.endpoint_observations = ["93.184.216.34", "93.184.216.35"].map(address => ({
  address, hostname: trustFixture.domain, port: 443,
  tls: { ...clone(liveCarrier), leaf_collected: true },
}));
const snapshotForModules = (modules, findings = []) => composeSnapshot({
  snapshotId: "snap-live-basis", workspaceId: "ws-fixture", domainId: "dom-fixture",
  scanId: "scan-live-basis", domain: trustFixture.domain,
  report: { ...clone(report), modules: { ...clone(modules), certificate_intelligence: run(modules) }, findings },
  cyberEssentials: { status: "not_assessed" }, ceReadiness: null, caseRows: [],
  questionSetVersions: [], builtAt: fixture.built_at,
});
const certificateDomain = value => value.domains.find(d => d.domain_key === "certificates_trust");
const liveSnapshot = snapshotForModules(liveModules);
const liveDomain = certificateDomain(liveSnapshot);
ok("live domain basis names captured leaf, hostname match and declared store result",
  liveDomain.evidence_grade.basis.includes("leaf certificate was captured") &&
  liveDomain.evidence_grade.basis.includes("Hostname matching was performed: matched") &&
  liveDomain.evidence_grade.basis.includes("fixture-public-root-store") &&
  liveDomain.evidence_grade.basis.includes("was performed: valid"));
ok("live domain no longer claims all trust measurements were unperformed",
  !liveDomain.limitations.some(x => x.includes("Chain validity, root trust, OCSP and revocation status are not checked")));
ok("live domain retains exact-wire-chain and unmeasured revocation limits",
  liveDomain.limitations.some(x => x.includes("not proof of the exact certificate chain")) &&
  liveDomain.limitations.includes("OCSP and revocation status were not assessed."));
eq("scoped live measurements never set a blanket domain verified flag", liveDomain.live_certificate_verified, false);

const invalidTrust = clone(liveModules);
invalidTrust.ssl.certificate_evidence.live_tls.trust_store_validation.validation_result = "invalid";
ok("failed declared-store validation is described as invalid, not a trust pass",
  certificateDomain(snapshotForModules(invalidTrust)).evidence_grade.basis.includes("was performed: invalid."));
const unknownTrust = clone(liveModules);
delete unknownTrust.ssl.certificate_evidence.live_tls.trust_store_validation;
ok("missing trust measurement remains explicitly unrecorded",
  certificateDomain(snapshotForModules(unknownTrust)).evidence_grade.basis.includes("Validation against a declared trust store was not recorded."));
const incompleteEndpoints = clone(liveModules);
incompleteEndpoints.ssl.certificate_evidence.live_tls.all_planned_endpoints_observed = false;
ok("partial endpoint coverage stays explicit alongside an observed live leaf",
  certificateDomain(snapshotForModules(incompleteEndpoints)).limitations.includes("Not all planned live TLS endpoints were observed."));

const ctOnlySnapshotModules = clone(liveModules);
delete ctOnlySnapshotModules.ssl.certificate_evidence.live_tls;
const ctOnlySnapshot = snapshotForModules(ctOnlySnapshotModules);
const ctOnlyBefore = JSON.stringify(ctOnlySnapshot);
const ctOnlyDomain = certificateDomain(ctOnlySnapshot);
eq("CT-only domain preserves its original evidence basis", ctOnlyDomain.evidence_grade.basis,
  "Certificate Transparency (RFC 9162) records that a certificate or precertificate was logged; it does not establish which certificate a server currently presents.");
ok("CT-only domain retains its original unmeasured trust caveat",
  ctOnlyDomain.limitations.includes("Analysis is based on Certificate Transparency logs. Chain validity, root trust, OCSP and revocation status are not checked and remain unknown."));
const unadmittedReport = clone(report);
unadmittedReport.modules.certificate_intelligence.signal_completeness.signals.leaf.publishable = false;
const unadmitted = composeSnapshot({ snapshotId: "unadmitted", workspaceId: "ws-fixture", domainId: "dom-fixture", scanId: "unadmitted", domain: fixture.domain, report: unadmittedReport, caseRows: [], questionSetVersions: [] });
ok("an unpublished live signal cannot authorize live summary wording",
  !certificateDomain(unadmitted).evidence_grade.basis.includes("leaf certificate was captured"));

const blackoutModules = clone(liveModules);
blackoutModules.ssl.ct_sources = {};
blackoutModules.subdomains = { ...(blackoutModules.subdomains || {}), sources: {} };
for (const provider of ["crt_sh", "certspotter"]) {
  blackoutModules.ssl.ct_sources[provider] = { error: "provider unavailable", count: 0 };
  blackoutModules.subdomains.sources[provider] = { error: "provider unavailable", count: 0 };
}
const blackoutIntelligence = runCertificateIntelligenceModule(blackoutModules, trustFixture.domain, {
  observedAt: trustFixture.observed_at, engineVersion: trustFixture.engine_version,
});
const blackoutReport = { ...clone(report), scan_quality: { status: "degraded", modules_skipped: [] },
  modules: { ...blackoutModules, certificate_intelligence: blackoutIntelligence } };
const blackout = composeSnapshot({ snapshotId: "blackout-live", workspaceId: "ws-fixture", domainId: "dom-fixture", scanId: "blackout-live", domain: fixture.domain, report: blackoutReport, caseRows: [], questionSetVersions: [] });
eq("CT provider blackout still caps live-summary domain grade at L0", certificateDomain(blackout).evidence_grade.grade, "L0");
ok("CT provider blackout cannot become assessed healthy from a live leaf", certificateDomain(blackout).state !== "assessed_healthy");
ok("CT blackout still describes the separately admitted live measurement", certificateDomain(blackout).evidence_grade.basis.includes("was performed: valid"));

const liveFinding = { id: "certificate_untrusted", title: "Measured trust failure", module: "certificate_intelligence", severity: "high", finding_type: "finding",
  evidence: [{ type: "live_tls", certificate_identity: liveCarrier.leaf_certificate.certificate_identity }] };
const findingSnapshot = snapshotForModules(invalidTrust, [liveFinding]);
ok("a retained matching live finding uses live rather than CT evidence provenance",
  findingSnapshot.observed_findings[0]?.evidence_grade.basis.includes("endpoint evidence retained with this finding") &&
  !findingSnapshot.observed_findings[0]?.evidence_grade.limits.some(x => x.includes("root trust, OCSP and revocation were not verified")));
const foreignFinding = { ...liveFinding, evidence: [{ type: "live_tls", certificate_identity: "unbound-leaf" }] };
ok("a finding with an unrelated leaf cannot borrow live summary provenance",
  !snapshotForModules(invalidTrust, [foreignFinding]).observed_findings[0]?.evidence_grade.basis.includes("leaf certificate was captured"));

// Exercise the real multi-endpoint producer: the selected summary leaf is
// expired/matched; the different, current leaf supplies a hostname mismatch.
const mixedEndpointRow = (address, identity, notAfter, name, trust) => {
  const tls = clone(liveCarrier);
  tls.leaf_collected = true;
  tls.endpoint = { address, hostname: trustFixture.domain, port: 443 };
  tls.observed_at = trustFixture.observed_at;
  tls.leaf_certificate.certificate_identity = identity;
  tls.leaf_certificate.not_after = notAfter;
  tls.hostname_match.result = name;
  tls.hostname_match.certificate_identity = identity;
  tls.trust_store_validation.validation_result = trust;
  tls.trust_store_validation.certificate_identity = identity;
  return { address, hostname: trustFixture.domain, port: 443, state: "open", tls };
};
const mixedModules = clone(liveModules);
mixedModules.ssl = attachLiveTlsToSsl(mixedModules.ssl, { receipt: {
  schema_version: "network-probe-receipt-v1", profile: "live_tls", request_id: "mixed-endpoint-fixture",
  quality: "complete", finished_at: trustFixture.observed_at,
  observations: [
    mixedEndpointRow("93.184.216.34", "sha256:expired-selected", "2026-07-25T00:00:00.000Z", "matched", "invalid"),
    mixedEndpointRow("93.184.216.35", "sha256:current-mismatch", "2026-11-30T00:00:00.000Z", "mismatched", "invalid"),
  ],
} });
const mixedFindings = liveCertificateFindings(mixedModules.ssl, trustFixture.domain)
  .map(finding => ({ ...finding, id: finding.signal, module: "certificate_intelligence" }));
const mixedSnapshot = snapshotForModules(mixedModules, mixedFindings);
const mismatchSource = mixedFindings.find(finding => finding.id === "certificate_hostname_mismatch");
const mismatchFinding = mixedSnapshot.observed_findings.find(finding => finding.finding_id === "certificate_hostname_mismatch");
eq("real mixed endpoint producer selects the expired matched leaf", mixedModules.ssl.live_certificate.certificate_identity, "sha256:expired-selected");
ok("mixed endpoint domain summary still describes only its selected matched leaf", certificateDomain(mixedSnapshot).evidence_grade.basis.includes("Hostname matching was performed: matched"));
ok("real mismatch finding references its different endpoint identity and result", mismatchFinding?.evidence_ref.count === 1 && mismatchSource?.evidence.some(item => item.certificate_identity === "sha256:current-mismatch" && item.hostname_match === "mismatched"));
ok("mixed endpoint finding cannot borrow the selected leaf hostname outcome", mismatchFinding?.evidence_grade.basis.includes("endpoint evidence retained with this finding") && !mismatchFinding.evidence_grade.basis.includes("Hostname matching was performed: matched"));
ok("mixed endpoint finding cannot borrow a selected trust-store verdict", mismatchFinding?.evidence_grade.basis.includes("not inferred from the selected summary leaf") && !mismatchFinding.evidence_grade.basis.includes("was performed: invalid"));
eq("new live compositions do not mutate a previously composed CT-only snapshot", JSON.stringify(ctOnlySnapshot), ctOnlyBefore);

const apiProjection = certificateAssuranceApiProjection(snapshot);
const read = {
  status: "ok",
  snapshot,
  row: { id: "snap-fixture" },
  integrity: { verified: true },
  dmarcPolicy: null,
};
const executive = buildExecutiveReportV2({
  scan: { id: "scan-fixture", domain_id: "dom-fixture", domain: fixture.domain },
  workspace: { id: "ws-fixture", name: "Fixture Workspace" },
  read,
});
eq("API and snapshot semantics are identical",
  JSON.stringify(apiProjection.certificate_assurance),
  JSON.stringify(snapshot.certificate_assurance));
eq("Executive Report and snapshot semantics are identical",
  JSON.stringify(executive.certificate_assurance),
  JSON.stringify(snapshot.certificate_assurance));
const pdfText = new TextDecoder().decode(
  buildScanReportPdf({ id: "scan-fixture", domain: fixture.domain }, read),
);
for (const phrase of [
  "Certificate Evidence & Trust",
  "CT issuance",
  "Live TLS certificate",
  "Declared trust-store validation",
  "OCSP / revocation assurance",
  "Trust evidence ceiling",
  "replacement was observed over time",
  "Evidence grade:",
  "Required corroboration:",
  "Cited authorities:",
]) {
  ok(`PDF renders certificate semantic: ${phrase}`, pdfText.includes(phrase));
}
ok("PDF retains RFC 5280 authority", pdfText.includes("RFC 5280"));
ok("PDF retains product-policy distinction",
  pdfText.includes("product_policy"));
const executivePdfText = new TextDecoder().decode(
  buildWorkspaceExecutivePdf({
    workspaceName: "Fixture Workspace",
    reads: [read],
    generatedAt: fixture.built_at,
  }),
);
const executiveVisibleText = [...executivePdfText.matchAll(/\(((?:\\.|[^()\\])*)\) Tj/g)]
  .map((match) => match[1]).join(" ").replace(/\s+/g, " ");
ok("Executive brief retains the canonical Certificates & Trust conclusion",
  executivePdfText.includes("Certificates & Trust") &&
  executiveVisibleText.includes(pdfEsc(snapshot.domains.find((d) => d.domain_key === "certificates_trust").state_reason).replace(/\s+/g, " ")));
ok("Executive brief points to full technical certificate assurance without duplicating citations",
  executivePdfText.includes("download the technical PDF") && !executivePdfText.includes("Cited authorities:"));

const legacySnapshot = {
  snapshot: {
    snapshot_id: "snap-legacy",
    snapshot_schema_version: "1",
    domain: "legacy.example",
  },
  domains: [],
};
const legacyBefore = JSON.stringify(legacySnapshot);
const legacy = certificateAssuranceFromSnapshot(legacySnapshot);
eq("legacy snapshot object is not rewritten",
  JSON.stringify(legacySnapshot), legacyBefore);
eq("legacy projection status is not_recorded", legacy.status, "not_recorded");
for (const signal of Object.values(legacy.signals)) {
  eq(`${signal.signal_key}: legacy missing field is not_observed`,
    signal.state, "not_observed");
}
ok("legacy explanation is explicit",
  legacy.historical_notice.includes(fixture.legacy_notice_fragment));
const legacyExec = buildExecutiveReportV2({
  scan: { id: "scan-legacy", domain: "legacy.example" },
  read: {
    snapshot: legacySnapshot,
    row: { id: "snap-legacy" },
    integrity: { verified: true },
    dmarcPolicy: null,
  },
});
eq("legacy Executive Report uses same notice-only projection",
  JSON.stringify(legacyExec.certificate_assurance), JSON.stringify(legacy));
const legacyPdfText = new TextDecoder().decode(buildScanReportPdf(
  { id: "scan-legacy", domain: "legacy.example" },
  {
    snapshot: legacySnapshot,
    row: { id: "snap-legacy" },
    integrity: { verified: true },
    dmarcPolicy: null,
  },
));
ok("legacy PDF says not recorded", /not recorded in this historical snapshot/i.test(
  legacyPdfText,
));
ok("legacy PDF does not synthesise a pass",
  !/Certificate Evidence & Trust[\\s\\S]{0,400}(healthy|passed)/i.test(
    legacyPdfText,
  ));

const presentationSource = fs.readFileSync(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "certificate-customer-presentation.js",
), "utf8");
const certificatesPageSource = fs.readFileSync(path.join(
  root,
  "frontend",
  "src",
  "pages",
  "ws",
  "CertificatesPage.jsx",
), "utf8");
const snapshotSource = fs.readFileSync(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "report-snapshot.js",
), "utf8");
const certificateRouteSource = fs.readFileSync(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "routes",
  "attack-surface.js",
), "utf8");
ok("presentation adapter introduces no CT/network lookup",
  !/\bfetch\s*\(|crt\.sh|certspotter/i.test(presentationSource));
ok("certificate UI no longer labels CT evidence healthy",
  !/CT evidence healthy/i.test(certificatesPageSource));
ok("certificate UI renders the backend-owned presentation",
  /CertificateAssuranceSummary/.test(certificatesPageSource));
ok("snapshot addition is additive and no historical backfill exists",
  /certificate_assurance: certificateAssurance/.test(snapshotSource) &&
  !/UPDATE\s+scan_report_snapshots[\s\S]*certificate_assurance/i.test(
    snapshotSource,
  ));
ok("certificate API latest-scan read is one workspace-scoped window query",
  /ROW_NUMBER\(\) OVER/.test(certificateRouteSource) &&
  /s\.workspace_id = \?/.test(certificateRouteSource));

console.log(`\nItem 9 P5 customer parity: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("Item 9 P5 customer parity validation passed");
