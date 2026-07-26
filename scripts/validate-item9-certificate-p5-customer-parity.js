#!/usr/bin/env node
// Item 9 P5 — deterministic customer-surface parity and legacy compatibility.
//
// Production engines provide the canonical P1-P4 model. This validator only
// checks the additive customer projection and its snapshot/report/PDF readers.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCertificateIntelligenceModule } from "../workers/scan-api/src/engines/cert-intel.js";
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
for (const phrase of [
  "Certificate Evidence & Trust",
  "CT issuance",
  "Live TLS certificate",
  "Declared trust-store validation",
  "OCSP / revocation assurance",
  "Certificate relationship",
  "Cited authorities:",
]) {
  ok(`Executive PDF renders certificate semantic: ${phrase}`,
    executivePdfText.includes(phrase));
}

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
