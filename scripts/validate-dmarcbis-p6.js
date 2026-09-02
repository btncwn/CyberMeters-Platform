#!/usr/bin/env node
// Item 7 P6 — customer surfaces, Executive Report, PDF, historical notice and
// API/UI/report parity. Runtime fixtures use the backend-owned presentation
// projection; source guards prevent renderer-side DMARC derivation.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  name,
)).href;

const {
  buildDmarcPolicyPresentation,
  DMARCBIS_PRESENTATION_SCHEMA,
} = await import(engine("dmarcbis-presentation.js"));
const { dmarcPolicyApiProjection } =
  await import(engine("dmarcbis-contract.js"));
const { buildExecutiveReportV2 } =
  await import(engine("executive-report.js"));
const { buildScanReportPdf } =
  await import(engine("pdf.js"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) {
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  ok(name, got === want,
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function evidence(overrides = {}) {
  return {
    schema: "dmarc-policy.v2",
    methodology_version: "rfc9989-treewalk-v1",
    parser_version: "dmarcbis-policy-parser-v1",
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    author_domain: "mail.example.test",
    submitted_domain: "mail.example.test",
    observed_at: "2026-07-25T20:00:00.000Z",
    observation_state: "absent",
    record_validity: "not_applicable",
    raw_records: [],
    parsed_tags: [],
    lookup_path: [{
      question: {
        name: "_dmarc.mail.example.test",
        type: "TXT",
        purpose: "policy_tree_walk",
      },
      outcome: "nodata",
      logically_used: true,
    }],
    organisational_domain: "example.test",
    organisational_domain_provenance: "psd_n",
    organisational_domain_completeness: "complete",
    policy_source_domain: "example.test",
    policy_source_kind: "organisational",
    domain_existence: "exists",
    existence_completeness: "complete",
    declared_policy: "reject",
    effective_requested_policy: "quarantine",
    testing_adjustment: "one_level_below",
    effective_policy_tag: "sp",
    inheritance_reason: "organisational_sp",
    p: { present: true, raw: "reject", normalized: "reject", valid: true },
    sp: {
      present: true,
      raw: "quarantine",
      normalized: "quarantine",
      valid: true,
    },
    np: { present: false, raw: null, normalized: null, valid: true },
    t: { present: true, raw: "y", normalized: "y", valid: true },
    psd: { present: true, raw: "n", normalized: "n", valid: true },
    legacy_pct: {
      observed: true,
      raw: "25",
      numeric: 25,
      applied_to_effective_policy: false,
    },
    policy_completeness: "complete",
    core_completeness: "complete",
    rua_authorisation_completeness: "incomplete",
    monitoring_state: "monitoring_degraded",
    provider_state: "available",
    corroboration_state: "corroborated",
    receiver_enforcement_observed: false,
    external_rua_authorisation: {
      all_destinations_authorized: null,
      destinations: [
        {
          uri: "mailto:local@example.test",
          destination_host: "example.test",
          authorization_status:
            "not_required_same_organisational_domain",
          lookup_completeness: "not_applicable",
        },
        {
          uri: "mailto:agg@reports.vendor.test",
          destination_host: "reports.vendor.test",
          authorization_status: "authorized",
          lookup_completeness: "complete",
          trusted_ingestion_status:
            "observational_item5_gate_required",
        },
        {
          uri: "mailto:backup@other.vendor.test",
          destination_host: "other.vendor.test",
          authorization_status: "not_assessed_budget",
          lookup_completeness: "incomplete",
        },
      ],
    },
    evidence_grade: {
      grade: "L3",
      source_type: "normative_protocol",
      basis: "Complete RFC 9989 policy discovery.",
      limits: ["Receiver enforcement is not observed."],
      repeat_confirmed: false,
    },
    evidence_fingerprint: "fixture-fingerprint",
    ...overrides,
  };
}

function currentRead(overrides = {}) {
  return { status: "current", evidence: evidence(overrides) };
}

const inherited = buildDmarcPolicyPresentation(currentRead());
eq("presentation schema is stable",
  inherited.schema, DMARCBIS_PRESENTATION_SCHEMA);
eq("current evidence stays current", inherited.status, "current");
eq("effective requested policy is snapshot-derived quarantine",
  inherited.policy.effective_requested, "quarantine");
eq("declared reject remains distinct",
  inherited.policy.declared, "reject");
ok("sp inheritance is explicit",
  inherited.policy.inheritance_message.includes("sp=quarantine"));
ok("t=y clause wording is explicit",
  inherited.policy.testing_message.includes("t=y") &&
  inherited.policy.testing_message.includes("effective requested policy"));
ok("legacy pct is non-operative",
  inherited.legacy_pct.applied_to_effective_policy === false &&
  inherited.legacy_pct.message.includes("no longer applies"));
eq("same-domain RUA stays local",
  inherited.external_rua.destinations[0].authorization_status,
  "not_required_same_organisational_domain");
ok("external authorization does not claim report delivery",
  inherited.external_rua.destinations[1].message.includes(
    "does not prove reports were sent",
  ));
eq("budgeted destination remains incomplete",
  inherited.external_rua.destinations[2].authorization_status,
  "not_assessed_budget");
eq("incomplete destinations prohibit all-authorized",
  inherited.external_rua.all_destinations_authorized, null);
eq("Evidence Grade is carried unchanged",
  inherited.evidence_grade.grade, "L3");
ok("technical appendix keeps ordered lookup evidence",
  inherited.technical_appendix.lookup_path.length === 1);

for (const [policy, label] of [
  ["none", "No-action policy"],
  ["quarantine", "Quarantine requested"],
  ["reject", "Rejection requested"],
]) {
  const result = buildDmarcPolicyPresentation(currentRead({
    declared_policy: policy,
    effective_requested_policy: policy,
    testing_adjustment: "none",
    t: { present: false, raw: null, normalized: null, valid: true },
  }));
  eq(`${policy} requested-policy label`, result.policy.effective_requested_label,
    label);
}

const inheritedP = buildDmarcPolicyPresentation(currentRead({
  effective_policy_tag: "p",
  inheritance_reason: "organisational_p",
}));
ok("inherited p names its tag",
  inheritedP.policy.inheritance_message.includes("p=quarantine"));

const inheritedNp = buildDmarcPolicyPresentation(currentRead({
  domain_existence: "nonexistent",
  effective_policy_tag: "np",
  inheritance_reason: "organisational_np",
  np: { present: true, raw: "reject", normalized: "reject", valid: true },
  effective_requested_policy: "reject",
}));
ok("inherited np explains non-existent domain",
  inheritedNp.policy.inheritance_message.includes(
    "did not exist in DNS",
  ));

for (const [state, phrase] of [
  ["present_invalid", "syntax prevents"],
  ["multiple", "does not allow CyberMeters to select"],
  ["resolver_disagreement", "resolvers disagreed"],
  ["incomplete_oversized", "exceeded the supported evidence limit"],
  ["unavailable", "required DNS lookup was unavailable"],
]) {
  const result = buildDmarcPolicyPresentation(currentRead({
    observation_state: state,
    record_validity: "invalid",
    effective_requested_policy: null,
    policy_completeness: "unavailable",
    core_completeness: "unavailable",
  }));
  ok(`${state} fails honestly`, result.customer_message.includes(phrase));
  ok(`${state} never becomes healthy`,
    result.completeness.core_label !== "Complete");
}

const completeNoPolicy = buildDmarcPolicyPresentation(currentRead({
  observation_state: "absent",
  effective_requested_policy: null,
  policy_source_domain: null,
  policy_source_kind: "none",
  inheritance_reason: "none",
}));
ok("complete no-policy is distinct from unavailable",
  completeNoPolicy.customer_message.includes("completed") &&
  completeNoPolicy.customer_message.includes("no applicable policy"));

const legacyRead = {
  status: "legacy_snapshot",
  evidence: null,
  notice:
    "This report preserves the DMARC methodology and conclusions used when the scan completed.",
  reason: "dmarc_block_absent",
};
const legacy = buildDmarcPolicyPresentation(legacyRead);
eq("legacy reader emits notice-only presentation",
  legacy.status, "legacy_snapshot");
eq("legacy renderer never manufactures technical evidence",
  legacy.technical_appendix, null);
ok("legacy notice is retained verbatim",
  legacy.customer_message.includes("preserves the DMARC methodology"));

const unavailable = buildDmarcPolicyPresentation({
  status: "integrity_error",
  evidence: null,
  reason: "fingerprint_mismatch",
});
eq("integrity failure remains unavailable",
  unavailable.status, "integrity_error");
ok("integrity failure is neither healthy nor missing",
  unavailable.customer_message.includes(
    "not a healthy or missing-record result",
  ));

const api = dmarcPolicyApiProjection(currentRead());
eq("API projection carries evidence and presentation status parity",
  api.dmarc_policy_evidence_status, api.dmarc_policy_presentation.status);
eq("API presentation requested policy matches immutable evidence",
  api.dmarc_policy_presentation.policy.effective_requested,
  api.dmarc_policy_evidence.effective_requested_policy);
const legacyApi = dmarcPolicyApiProjection(legacyRead);
ok("legacy API keeps approved notice",
  legacyApi.dmarc_methodology_notice ===
  legacyApi.dmarc_policy_presentation.historical_notice);
ok("legacy API does not add a current evidence block",
  !Object.hasOwn(legacyApi, "dmarc_policy_evidence"));

function snapshot() {
  return {
    snapshot: {
      snapshot_id: "snap-p6",
      domain: "mail.example.test",
      scan_id: "scan-p6",
      as_of: "2026-07-25T20:00:00.000Z",
      built_at: "2026-07-25T20:00:01.000Z",
      provenance: "scan_finalize",
    },
    methodology: { snapshot_builder_version: "canonical-report-snapshot-v3" },
    overall: {
      cyber_metrics_score: null,
      score_band: null,
      assessment: {
        provisional: true,
        comparable: false,
        quality: "partial",
        message: "Assessment evidence is incomplete.",
      },
      business_risk_indicator: {},
      summary: "Assessment evidence is incomplete.",
      evidence_completeness: {},
    },
    domains: [],
    observed_findings: [],
    observations: [],
    remediation_actions: [],
    monitoring_states: {},
    limitations: [],
  };
}

const read = {
  status: "ok",
  snapshot: snapshot(),
  row: { id: "snap-p6" },
  integrity: { status: "verified" },
  dmarcPolicy: currentRead(),
};
const executive = buildExecutiveReportV2({
  scan: { id: "scan-p6", domain: "mail.example.test" },
  read,
});
eq("Executive Report carries the same presentation schema",
  executive.dmarc_policy_presentation.schema,
  DMARCBIS_PRESENTATION_SCHEMA);
eq("Executive Report policy matches API policy",
  executive.dmarc_policy_presentation.policy.effective_requested,
  api.dmarc_policy_presentation.policy.effective_requested);

const pdf = new TextDecoder().decode(buildScanReportPdf(
  { id: "scan-p6", domain: "mail.example.test" },
  read,
));
ok("PDF renders the DMARC policy section",
  pdf.includes("DMARC Policy Evidence"));
ok("PDF renders requested-policy wording",
  pdf.includes("Effective requested policy: Quarantine requested"));
ok("PDF renders technical appendix",
  pdf.includes("Technical Appendix - DMARC Policy"));
ok("PDF renders legacy pct as non-operative",
  pdf.includes("RFC 9989 no longer applies this value"));

const legacyPdf = new TextDecoder().decode(buildScanReportPdf(
  { id: "scan-legacy", domain: "legacy.example.test" },
  { ...read, dmarcPolicy: legacyRead },
));
ok("historical PDF renders approved methodology notice",
  legacyPdf.includes(
    "This report preserves the DMARC methodology and conclusions used when the scan completed.",
  ));
ok("historical PDF does not manufacture a DMARC technical appendix",
  !legacyPdf.includes("Technical Appendix - DMARC Policy"));

const sources = {
  presentation: fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/dmarcbis-presentation.js",
  ), "utf8"),
  snapshot: fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/report-snapshot.js",
  ), "utf8"),
  scanDetail: fs.readFileSync(path.join(
    root, "frontend/src/pages/ScanDetail.jsx",
  ), "utf8"),
  intelligence: fs.readFileSync(path.join(
    root, "frontend/src/pages/IntelligencePage.jsx",
  ), "utf8"),
  emailDashboard: fs.readFileSync(path.join(
    root, "frontend/src/pages/ws/WorkspaceEmailProtectionPage.jsx",
  ), "utf8"),
  executive: fs.readFileSync(path.join(
    root, "frontend/src/components/ExecutiveReportV2.jsx",
  ), "utf8"),
  component: fs.readFileSync(path.join(
    root, "frontend/src/components/DmarcPolicyEvidenceCard.jsx",
  ), "utf8"),
  openapi: fs.readFileSync(path.join(root, "docs/openapi.json"), "utf8"),
};

for (const [surface, source] of Object.entries({
  scanDetail: sources.scanDetail,
  intelligence: sources.intelligence,
  emailDashboard: sources.emailDashboard,
  executive: sources.executive,
})) {
  ok(`${surface} consumes the canonical presentation component`,
    source.includes("DmarcPolicyEvidenceCard"));
}
ok("snapshot writer never imports P6 presentation logic",
  !sources.snapshot.includes("dmarcbis-presentation"));
ok("presentation projection has no DNS/parser/resolver calls",
  !/\b(fetch|resolveDmarcbisPolicy|parseDmarcbisPolicyRecord)\s*\(/.test(
    sources.presentation,
  ));
ok("frontend component consumes presentation, not raw policy evidence",
  !sources.component.includes("dmarc_policy_evidence"));
const managedDmarcStart = sources.emailDashboard.indexOf(
  "export function ManagedDmarcCard",
);
const managedDmarcEnd = sources.emailDashboard.indexOf(
  "function DmarcSetupWizard",
  managedDmarcStart,
);
const managedDmarcSource = managedDmarcStart >= 0 && managedDmarcEnd > managedDmarcStart
  ? sources.emailDashboard.slice(managedDmarcStart, managedDmarcEnd)
  : "";
const manualGateStart = managedDmarcSource.indexOf(
  "rec.status === 'connected' && rec.policy_step && (",
);
const manualActionStart = managedDmarcSource.indexOf(
  "api.setHostedDmarcPolicy",
  manualGateStart,
);
const autopilotGuardStart = managedDmarcSource.indexOf(
  "{!automationSuspended && (",
  manualActionStart,
);
const autopilotActionStart = managedDmarcSource.indexOf(
  "api.setHostedDmarcAutopilot",
  autopilotGuardStart,
);
ok("Hosted-DMARC suspended state stays explicit and honest",
  managedDmarcSource.includes(
    "const automationSuspended = ramp?.interpretation?.automation_status === 'suspended'",
  ) &&
  managedDmarcSource.includes(
    "Automatic policy advancement and rollback from inbound DMARC (RUA) reports are suspended.",
  ) &&
  managedDmarcSource.includes(
    "Governed manual changes remain available below and require your explicit action.",
  ));
ok("Hosted-DMARC governed manual policy path remains available while automation is suspended",
  manualGateStart >= 0 &&
  manualActionStart > manualGateStart &&
  !managedDmarcSource.slice(manualGateStart, manualActionStart).includes(
    "!automationSuspended",
  ));
ok("Hosted-DMARC Self-Driving control remains separately guarded while suspended",
  autopilotGuardStart > manualActionStart &&
  autopilotActionStart > autopilotGuardStart &&
  managedDmarcSource.slice(autopilotGuardStart, autopilotActionStart).includes(
    "!automationSuspended",
  ));
ok("OpenAPI exposes additive presentation schema",
  sources.openapi.includes('"DmarcPolicyPresentation"') &&
  sources.openapi.includes('"dmarc-policy-presentation.v1"'));

const wordingCorpus = Object.values(sources).join("\n");
const prohibited = [
  /full DMARC protection/i,
  /DMARC enforcement is proven/i,
  /receivers are blocking spoofed email/i,
  /attackers cannot spoof/i,
  /fully RFC compliant/i,
  /malicious activity/i,
  /CyberMeters (?:changed|applied) your DNS/i,
  /external reporting is working/i,
  /monitoring recovered/i,
  /RFC Monitoring Mode/i,
  /full protection against spoofing/i,
  /actively blocked/i,
  /monitor-only/i,
];
for (const phrase of prohibited) {
  ok(`prohibited wording absent: ${phrase}`, !phrase.test(wordingCorpus));
}

console.log(`\nDMARCbis P6 fixtures: ${pass} passed, ${fail} failed`);
if (!fail) console.log("DMARCbis P6 customer-surface proof passed");
process.exit(fail ? 1 : 0);
