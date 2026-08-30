#!/usr/bin/env node

// A2 production-shape and historical-consistency gate.
// Pure local fixture: no DNS, D1, R2, network, customer data or production writes.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

import { deriveDmarcStateFromPolicyEvidence } from "../workers/scan-api/src/engines/dmarc-state.js";
import { budgetRefusedDmarcbisExternal } from "../workers/scan-api/src/engines/dmarcbis-production.js";
import { buildEmailRemediationActions } from "../workers/scan-api/src/engines/email-analysis.js";
import { applyDmarcbisEmailCompatibilityProjection } from "../workers/scan-api/src/engines/email-scan.js";
import { applyScanComparability, reconcileLateFindings, runHistoricalModule } from "../workers/scan-api/src/engines/historical-scan.js";
import { runScanEngine } from "../workers/scan-api/src/engines/scan-engine.js";
import { computeScore } from "../workers/scan-api/src/engines/scoring.js";
import { resolveCyberMotDomainStates } from "../workers/scan-api/src/engines/cyber-mot-domains.js";
import { projectHistoricalChangesForCustomer, scanRoutes } from "../workers/scan-api/src/routes/scans.js";
import { splitStatements, isToleratedStatement } from "./lib/migration-apply-tolerated.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_PATH = path.join(ROOT, "scripts", "fixtures", "dmarc-production-shape.json");
const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
const DOMAIN = "fixture.example";

let passed = 0;
let failed = 0;
function ok(name, condition, detail = "") {
  if (condition) passed += 1;
  else failed += 1;
  console.log(`${condition ? "ok  " : "FAIL"} - ${name}${condition || !detail ? "" : ` -- ${detail}`}`);
}

function emailBase() {
  return {
    executed: true,
    spf: { present: true, record: "v=spf1 -all" },
    dkim: { present: true, selector: "selector1" },
    spf_detail: {
      raw: "v=spf1 -all",
      valid: true,
      record_count: 1,
      all_mechanism: "-all",
      lookup_count_estimate: 0,
      mechanisms: [],
      warnings: [],
    },
    dkim_detail: { status: "detected", selector: "selector1", warnings: [] },
    bimi_readiness: { record_found: false, blockers: [], warnings: [] },
    remediation_actions: [],
  };
}

function projectEmail(policyEvidence) {
  return applyDmarcbisEmailCompatibilityProjection(
    DOMAIN,
    emailBase(),
    policyEvidence,
  );
}

function modulesFor(emailSecurity, dmarcCore) {
  return {
    dns: { has_mx: true, error: null },
    email_security: emailSecurity,
    dmarc_core: dmarcCore,
  };
}

function scoreFor(emailSecurity, dmarcCore) {
  return computeScore(modulesFor(emailSecurity, dmarcCore), DOMAIN);
}

function reportFor(emailSecurity, dmarcCore, findings) {
  return {
    scan_id: "scan-a2-fixture",
    status: "completed",
    completed_at: fixture.observed_at,
    scan_quality: { status: "complete", modules_skipped: [] },
    modules: modulesFor(emailSecurity, dmarcCore),
    findings,
  };
}

function withPolicy(policy) {
  const next = structuredClone(fixture);
  const value = `v=DMARC1; p=${policy}; rua=mailto:redacted@reports.cybermeters.com`;
  const raw = { data: `\"${value}\"` };
  next.effective_requested_policy = policy;
  next.declared_policy = policy;
  next.source_record = { raw, value };
  next.raw_records = [{ raw: structuredClone(raw), value }];
  const recordSet = next.lookup_path[0].record_set;
  recordSet.candidates[0] = {
    ...recordSet.candidates[0],
    raw: structuredClone(raw),
    value,
    p: { ...recordSet.candidates[0].p, raw: policy, normalized: policy },
  };
  recordSet.selected = structuredClone(recordSet.candidates[0]);
  return next;
}

function unavailableFixture() {
  const next = structuredClone(fixture);
  next.observation_state = "unavailable";
  next.record_validity = "indeterminate";
  next.effective_requested_policy = null;
  next.declared_policy = null;
  next.policy_source_domain = null;
  next.policy_source_kind = "unknown";
  next.policy_completeness = "unavailable";
  next.organisational_domain_completeness = "unavailable";
  next.existence_completeness = "unavailable";
  next.core_completeness = "unavailable";
  next.provider_state = "unavailable";
  next.monitoring_state = "monitoring_unavailable";
  next.rua_authorisation_completeness = "unavailable";
  next.source_record = null;
  next.raw_records = [];
  next.lookup_path = [];
  next.rua_destinations = [];
  return next;
}

function incompleteConclusionFixture() {
  const next = structuredClone(fixture);
  // Retain an exact parsed p=none detail, but remove the authoritative retained
  // record. This is the shape that previously let parsed detail outrun the
  // canonical "no conclusion" state when core_completeness was still complete.
  next.source_record = { raw: { data: null } };
  next.raw_records = [{ raw: { data: null } }];
  return next;
}

function priorFinding() {
  return {
    id: "email_dmarc_policy_none",
    module: "email_security",
    severity: "medium",
    title: "DMARC Policy is Monitor-Only (p=none)",
  };
}

function historicalEnv(previousReport) {
  return {
    cybermeters_db: {
      prepare: () => ({
        bind: () => ({
          first: async () => ({ id: "scan-previous", score: 95 }),
        }),
      }),
    },
    cybermeters_reports: {
      get: async () => ({ json: async () => structuredClone(previousReport) }),
    },
  };
}

function previousReport() {
  return {
    cyber_metrics_score: 95,
    risk_level: "good",
    scan_quality: { status: "complete" },
    findings: [priorFinding()],
    modules: {
      subdomains: { items: [] },
      subdomain_takeover: { risks: [] },
      asset_exposure: { assets: [] },
      cve_intelligence: { executed: true, cve_coverage: "complete" },
      known_exploited_vulnerabilities: { executed: true },
      email_security_intelligence: { executed: true },
    },
  };
}

// M6 fixture-drift guard: the fixture must retain the production raw-object/value-string split.
ok("fixture source_record.raw is a DoH-shaped object",
  fixture.source_record?.raw != null && typeof fixture.source_record.raw === "object");
ok("fixture source_record.value is the retained string",
  typeof fixture.source_record?.value === "string" && fixture.source_record.value.startsWith("v=DMARC1"));
ok("fixture raw_records preserve object raw plus string value",
  typeof fixture.raw_records?.[0]?.raw === "object" && typeof fixture.raw_records?.[0]?.value === "string");
ok("fixture is redacted and contains no customer domain or RUA token",
  fixture.submitted_domain === DOMAIN &&
    fixture.source_record.value.includes("redacted@reports.cybermeters.com") &&
    !fixture.source_record.value.includes("cmrua_"));

const productionState = deriveDmarcStateFromPolicyEvidence(fixture);
ok("production shape derives observed_policy",
  productionState.canonical_evidence_state === "observed_policy",
  productionState.canonical_evidence_state);
ok("production shape derives monitoring p=none",
  productionState.enforcement_level === "monitoring" && productionState.policy === "none");
ok("retained positive policy does not blame RUA incompleteness",
  !/aggregate-report|could not be completed/i.test(productionState.canonical_summary || ""),
  productionState.canonical_summary);

const productionEmail = projectEmail(fixture);
const productionScore = scoreFor(productionEmail, fixture);
const productionFinding = productionScore.findings.find((item) => item.id === "email_dmarc_policy_none");
ok("production projection emits the canonical p=none finding",
  productionFinding?.severity === "medium" && productionFinding?.score_impact === -5 &&
    productionFinding?.finding_type === "finding");
ok("production projection emits monitoring-only remediation",
  productionEmail.remediation_actions?.some((item) => item.id === "dmarc_policy_monitoring_only"));
const productionMot = resolveCyberMotDomainStates(
  reportFor(productionEmail, fixture, productionScore.findings),
).find((item) => item.domain_key === "email_protection");
ok("Cyber MOT surfaces the observed p=none policy as issue_detected",
  productionMot?.state === "issue_detected", productionMot?.state);

const unavailable = unavailableFixture();
const unavailableState = deriveDmarcStateFromPolicyEvidence(unavailable);
const unavailableEmail = projectEmail(unavailable);
const unavailableScore = scoreFor(unavailableEmail, unavailable);
ok("unavailable evidence remains unavailable/not_observed",
  unavailableState.canonical_evidence_state === "unavailable" &&
    unavailableState.enforcement_level === "not_observed");
ok("unavailable evidence emits no DMARC finding",
  !unavailableScore.findings.some((item) => item.id.startsWith("email_dmarc") || item.id === "email_missing_dmarc"));
ok("unavailable evidence emits no DMARC remediation action",
  !unavailableEmail.remediation_actions?.some((item) => item.id.startsWith("dmarc_")));
ok("direct action rebuild also rejects unavailable canonical state", (() => {
  const details = {
    spf_detail: emailBase().spf_detail,
    dkim_detail: emailBase().dkim_detail,
    bimi_readiness: emailBase().bimi_readiness,
    dmarc_detail: productionEmail.dmarc_detail,
  };
  Object.defineProperty(details, "dmarc_state", { value: unavailableState });
  return !buildEmailRemediationActions(DOMAIN, details).some((item) => item.id.startsWith("dmarc_"));
})());
const unavailableMot = resolveCyberMotDomainStates(
  reportFor(unavailableEmail, unavailable, unavailableScore.findings),
).find((item) => item.domain_key === "email_protection");
ok("Cyber MOT surfaces unavailable DMARC evidence as evidence_insufficient",
  unavailableMot?.state === "evidence_insufficient", unavailableMot?.state);

const incompleteConclusion = incompleteConclusionFixture();
const incompleteConclusionState = deriveDmarcStateFromPolicyEvidence(incompleteConclusion);
const incompleteConclusionEmail = projectEmail(incompleteConclusion);
ok("parsed p=none detail cannot outrun an incomplete canonical conclusion",
  incompleteConclusionState.canonical_evidence_state === "incomplete" &&
    incompleteConclusionEmail.dmarc_detail?.policy === "none" &&
    !incompleteConclusionEmail.remediation_actions?.some((item) => item.id.startsWith("dmarc_")));

const historicalUnavailable = await runHistoricalModule(
  "scan-current",
  DOMAIN,
  95,
  [],
  modulesFor(unavailableEmail, unavailable),
  historicalEnv(previousReport()),
  "workspace-fixture",
);
ok("historical incomplete producer does not resolve prior DMARC finding",
  historicalUnavailable.resolved_findings.length === 0);
ok("historical incomplete producer records prior DMARC as not re-observed",
  historicalUnavailable.not_reobserved_findings?.[0]?.id === "email_dmarc_policy_none");

const rejectFixture = withPolicy("reject");
const rejectEmail = projectEmail(rejectFixture);
const historicalReject = await runHistoricalModule(
  "scan-current",
  DOMAIN,
  100,
  [],
  modulesFor(rejectEmail, rejectFixture),
  historicalEnv(previousReport()),
  "workspace-fixture",
);
ok("historical observed reject resolves prior p=none finding",
  historicalReject.resolved_findings?.[0]?.id === "email_dmarc_policy_none" &&
    historicalReject.not_reobserved_findings.length === 0);
ok("historical baseline retains compact previous findings privately",
  historicalReject._previous_findings?.length === 1 &&
    historicalReject._previous_findings[0]?.id === "email_dmarc_policy_none" &&
    Object.keys(historicalReject._previous_findings[0]).join(",") === "id,module,severity,title");
ok("private previous findings never enter enumerable or JSON report shape",
  !Object.keys(historicalReject).includes("_previous_findings") &&
    !("_previous_findings" in { ...historicalReject }) &&
    !JSON.stringify(historicalReject).includes("_previous_findings"));

const latePersistent = {
  id: "fixture_persistent",
  module: "headers",
  severity: "medium",
  title: "Persistent fixture",
};
const lateKev = {
  id: "kev_fixture_previous",
  module: "known_exploited_vulnerabilities",
  severity: "high",
  title: "Previous KEV fixture",
};
const lateCloud = {
  id: "cloud_fixture_previous",
  module: "cloud_storage_discovery",
  severity: "medium",
  title: "Previous cloud fixture",
};
const lateMta = {
  id: "email_intel_mta_sts_missing",
  module: "email_security_intelligence",
  severity: "low",
  title: "MTA-STS policy not published",
};
const lateHistoryInput = {
  has_previous: true,
  previous_scan_id: "scan-late-previous",
  previous_score: 90,
  current_score: 90,
  score_change: 0,
  new_findings: [{ id: "stale_early_diff" }],
  resolved_findings: [],
  not_reobserved_findings: [],
  source: "previous_scan_comparison",
  error: null,
};
Object.defineProperty(lateHistoryInput, "_previous_findings", {
  value: [priorFinding(), lateKev, lateCloud, latePersistent],
  enumerable: false,
});
const lateHistoryInputBefore = JSON.stringify(lateHistoryInput);
const lateCurrentFindings = [latePersistent, lateMta, { ...lateMta }];
const lateCurrentBefore = JSON.stringify(lateCurrentFindings);
const lateReconciled = reconcileLateFindings(lateHistoryInput, lateCurrentFindings, {
  email_security: rejectEmail,
  email_security_intelligence: { executed: true, error: null },
  known_exploited_vulnerabilities: { executed: true, error: null },
  cloud_storage_discovery: { executed: false, incomplete: true, outcome: "deadline_exceeded" },
  headers: { executed: true, error: null },
});
ok("late reconcile is generic, stable and dedupes current finding ids",
  lateReconciled.new_findings.length === 1 &&
    lateReconciled.new_findings[0]?.id === lateMta.id &&
    !lateReconciled.new_findings.some((finding) => finding.id === "stale_early_diff"));
ok("late reconcile preserves DMARC and KEV producer re-observation law",
  lateReconciled.resolved_findings.map((finding) => finding.id).join(",") ===
    "email_dmarc_policy_none,kev_fixture_previous");
ok("late reconcile keeps a deferred cloud producer not re-observed",
  lateReconciled.not_reobserved_findings?.[0]?.id === lateCloud.id);
ok("late reconcile preserves persistent rows and non-finding history facts",
  !lateReconciled.new_findings.some((finding) => finding.id === latePersistent.id) &&
    !lateReconciled.resolved_findings.some((finding) => finding.id === latePersistent.id) &&
    lateReconciled.previous_scan_id === "scan-late-previous" && lateReconciled.score_change === 0);
ok("late reconcile does not mutate inputs and keeps private rows non-enumerable",
  JSON.stringify(lateHistoryInput) === lateHistoryInputBefore &&
    JSON.stringify(lateCurrentFindings) === lateCurrentBefore &&
    !Object.keys(lateReconciled).includes("_previous_findings") &&
    !JSON.stringify(lateReconciled).includes("_previous_findings"));

const lateProducerFixtures = [
  {
    module: "known_exploited_vulnerabilities",
    finding: {
      id: "kev_active_exploitation",
      module: "known_exploited_vulnerabilities",
      severity: "medium",
      title: "Detected technology has known-exploited vulnerabilities (version unconfirmed)",
    },
  },
  {
    module: "cloud_storage_discovery",
    finding: {
      id: "cloud_storage_public_listing",
      module: "cloud_storage_discovery",
      severity: "high",
      title: "Public Cloud Storage Listing Detected",
    },
  },
];
const lateProducerScenarios = [
  {
    name: "new",
    previous: false,
    current: true,
    moduleResult: { executed: true, incomplete: false, skipped: false, error: null, outcome: "complete" },
    comparable: true,
    quality: "complete",
    expected: "new",
  },
  {
    name: "persistent",
    previous: true,
    current: true,
    moduleResult: { executed: true, incomplete: false, skipped: false, error: null, outcome: "complete" },
    comparable: true,
    quality: "complete",
    expected: "persistent",
  },
  {
    name: "completed producer resolved",
    previous: true,
    current: false,
    moduleResult: { executed: true, incomplete: false, skipped: false, error: null, outcome: "complete" },
    comparable: true,
    quality: "complete",
    expected: "resolved",
  },
  {
    name: "unavailable producer not re-observed",
    previous: true,
    current: false,
    moduleResult: { executed: true, incomplete: false, skipped: false, error: "provider_unavailable", outcome: "unavailable" },
    comparable: false,
    quality: "partial",
    expected: "not_reobserved",
  },
  {
    name: "deferred producer not re-observed",
    previous: true,
    current: false,
    moduleResult: { executed: false, incomplete: true, skipped: false, error: null, outcome: "deadline_exceeded" },
    comparable: false,
    quality: "partial",
    expected: "not_reobserved",
  },
];

for (const producer of lateProducerFixtures) {
  for (const scenario of lateProducerScenarios) {
    const baseline = {
      has_previous: true,
      new_findings: [],
      resolved_findings: [],
      not_reobserved_findings: [],
    };
    Object.defineProperty(baseline, "_previous_findings", {
      value: scenario.previous ? [producer.finding] : [],
      enumerable: false,
    });
    const reconciled = reconcileLateFindings(
      baseline,
      scenario.current ? [producer.finding] : [],
      { [producer.module]: scenario.moduleResult },
    );
    const projected = applyScanComparability(
      reconciled,
      scenario.comparable,
      scenario.quality,
    );
    const actual = [
      ...(projected.new_findings || []).map((finding) => `new:${finding.id}`),
      ...(projected.resolved_findings || []).map((finding) => `resolved:${finding.id}`),
      ...(projected.not_reobserved_findings || []).map((finding) => `not_reobserved:${finding.id}`),
    ];
    const expected = scenario.expected === "persistent"
      ? []
      : [`${scenario.expected}:${producer.finding.id}`];
    ok(`late ${producer.module} ${scenario.name} transition is exact`,
      JSON.stringify(actual) === JSON.stringify(expected) &&
        projected.comparable === scenario.comparable,
      JSON.stringify({ actual, expected, comparable: projected.comparable }));
  }
}

const CERT_HISTORY_NOW = "2026-08-30T12:00:00.000Z";
const CERT_HISTORY_NOW_MS = Date.parse(CERT_HISTORY_NOW);
const certHistoryFinding = (id) => ({
  id,
  module: "certificate_intelligence",
  severity: id === "certificate_expiring_critical" ? "high" : "medium",
  title: id === "certificate_expiring_critical"
    ? "Logged certificate validity ends within 14 days"
    : "Logged certificate validity ends within 30 days",
});
const certHistoryModule = (days = 30, overrides = {}) => ({
  executed: true,
  incomplete: false,
  skipped: false,
  error: null,
  outcome: "complete",
  tls_state: "observed_present",
  evidence_source: "certificate_transparency",
  live_certificate_verified: false,
  expiry_evidence: "usable",
  expires_at: new Date(CERT_HISTORY_NOW_MS + (days + 0.5) * 86_400_000).toISOString(),
  days_until_expiry: days,
  ct_sources: { crt_sh: 1, certspotter: 0 },
  signal_completeness: {
    signals: { expiry: { provenance: { observed_at: CERT_HISTORY_NOW } } },
  },
  ...overrides,
});
const certHistoryTransition = ({
  previousId = "certificate_expiring_critical",
  currentId = null,
  ssl = { tls_state: "observed_present" },
  certificate = certHistoryModule(),
} = {}) => {
  const previous = certHistoryFinding(previousId);
  const baseline = {
    has_previous: true,
    new_findings: [], resolved_findings: [], not_reobserved_findings: [],
  };
  Object.defineProperty(baseline, "_previous_findings", {
    value: [previous], enumerable: false,
  });
  const current = currentId ? [certHistoryFinding(currentId)] : [];
  const baselineBefore = JSON.stringify(baseline);
  const currentBefore = JSON.stringify(current);
  const reconciled = reconcileLateFindings(baseline, current, {
    ssl,
    certificate_intelligence: certificate,
  });
  return { baseline, current, baselineBefore, currentBefore, reconciled };
};

const certPersistent = certHistoryTransition({
  currentId: "certificate_expiring_critical",
  certificate: certHistoryModule(13),
});
ok("certificate history keeps the same admitted id persistent",
  certPersistent.reconciled.new_findings.length === 0 &&
    certPersistent.reconciled.resolved_findings.length === 0 &&
    certPersistent.reconciled.not_reobserved_findings.length === 0);

const certRenewed = certHistoryTransition({ certificate: certHistoryModule(30) });
ok("certificate history resolves a prior id only after coherent 30-day re-observation",
  certRenewed.reconciled.resolved_findings?.[0]?.id === "certificate_expiring_critical" &&
    certRenewed.reconciled.not_reobserved_findings.length === 0);

for (const [previousId, currentId, days] of [
  ["certificate_expiring_critical", "certificate_expiring_soon", 14],
  ["certificate_expiring_soon", "certificate_expiring_critical", 13],
]) {
  const changed = certHistoryTransition({ previousId, currentId, certificate: certHistoryModule(days) });
  ok(`certificate history band change ${previousId} -> ${currentId} is new plus resolved`,
    changed.reconciled.new_findings?.[0]?.id === currentId &&
      changed.reconciled.resolved_findings?.[0]?.id === previousId &&
      changed.reconciled.not_reobserved_findings.length === 0);
}

const inconclusiveCertificateScenarios = [
  ["TLS unavailable", { ssl: { tls_state: "unavailable" }, certificate: certHistoryModule(13) }],
  ["TLS deferred", {
    ssl: { tls_state: "unavailable" },
    certificate: certHistoryModule(13, { executed: false, incomplete: true, outcome: "deadline_exceeded" }),
  }],
  ["certificate module incomplete", { certificate: certHistoryModule(13, { incomplete: true }) }],
  ["certificate module error", { certificate: certHistoryModule(13, { error: "provider unavailable" }) }],
  ["expiry evidence not usable", { certificate: certHistoryModule(13, { expiry_evidence: "not_usable" }) }],
  ["blank expiry date", { certificate: certHistoryModule(13, { expires_at: "" }) }],
  ["past expiry date", { certificate: certHistoryModule(13, { expires_at: "2026-08-29T12:00:00.000Z" }) }],
  ["incoherent expiry pair", { certificate: certHistoryModule(13, {
    expires_at: new Date(CERT_HISTORY_NOW_MS + 16 * 86_400_000).toISOString(),
  }) }],
  ["zero CT providers", { certificate: certHistoryModule(13, {
    ct_sources: { crt_sh: 0, certspotter: 0 },
  }) }],
];
for (const [name, fixture] of inconclusiveCertificateScenarios) {
  const transition = certHistoryTransition(fixture);
  ok(`certificate history keeps ${name} not re-observed`,
    transition.reconciled.resolved_findings.length === 0 &&
      transition.reconciled.not_reobserved_findings?.[0]?.id ===
        "certificate_expiring_critical");
}
ok("certificate history reconciliation preserves inputs and private rows",
  certRenewed.baselineBefore === JSON.stringify(certRenewed.baseline) &&
    certRenewed.currentBefore === JSON.stringify(certRenewed.current) &&
    !Object.keys(certRenewed.reconciled).includes("_previous_findings") &&
    !JSON.stringify(certRenewed.reconciled).includes("_previous_findings"));

const nonCertificateBaseline = {
  has_previous: true,
  new_findings: [], resolved_findings: [], not_reobserved_findings: [],
};
Object.defineProperty(nonCertificateBaseline, "_previous_findings", {
  value: [{ id: "header_fixture", module: "headers", severity: "medium", title: "Header fixture" }],
  enumerable: false,
});
const nonCertificateReconciled = reconcileLateFindings(nonCertificateBaseline, [], {
  headers: { executed: true, incomplete: false, skipped: false, error: null, outcome: "complete" },
});
ok("certificate-specific history gate never captures a non-certificate identity",
  nonCertificateReconciled.resolved_findings?.[0]?.id === "header_fixture" &&
    nonCertificateReconciled.not_reobserved_findings.length === 0);

const lateMtaBaseline = {
  has_previous: true,
  new_findings: [],
  resolved_findings: [],
  not_reobserved_findings: [],
};
Object.defineProperty(lateMtaBaseline, "_previous_findings", {
  value: [lateMta],
  enumerable: false,
});
const conclusiveMtaServiceability = {
  serviceable: true,
  conclusion_class: "conclusive",
};
const lateMtaResolved = reconcileLateFindings(lateMtaBaseline, [], {
  email_security_intelligence: {
    executed: true,
    incomplete: false,
    mta_sts: {
      observation_state: "present",
      status_code: 200,
      reason: "origin_response",
      serviceability: conclusiveMtaServiceability,
    },
  },
});
ok("late reconcile resolves MTA absence only after a coherent present re-observation",
  lateMtaResolved.resolved_findings?.[0]?.id === lateMta.id &&
    lateMtaResolved.not_reobserved_findings.length === 0);
const lateMtaUnavailable = reconcileLateFindings(lateMtaBaseline, [], {
  email_security_intelligence: {
    executed: true,
    incomplete: false,
    mta_sts: {
      observation_state: "unavailable",
      status_code: 503,
      reason: "http_5xx",
      serviceability: { serviceable: false, conclusion_class: "evidence_insufficient" },
    },
  },
});
ok("late reconcile keeps unavailable MTA evidence not re-observed",
  lateMtaUnavailable.not_reobserved_findings?.[0]?.id === lateMta.id &&
    lateMtaUnavailable.resolved_findings.length === 0);
const noLateBaseline = { has_previous: false, new_findings: [] };
Object.defineProperty(noLateBaseline, "_previous_findings", { value: null, enumerable: false });
ok("late reconcile manufactures no state without a comparable private baseline",
  reconcileLateFindings(noLateBaseline, [lateMta], {}) === noLateBaseline);

const storedFalseResolution = {
  new_findings: [priorFinding()],
  resolved_findings: [priorFinding()],
  not_reobserved_findings: [],
};
const nonComparable = projectHistoricalChangesForCustomer(storedFalseResolution, {
  comparable: false,
  currentModules: { dmarc_core: fixture },
});
ok("API projection suppresses new and resolved lists when not comparable",
  nonComparable.new_findings.length === 0 && nonComparable.resolved_findings.length === 0);

const observedNoneProjection = projectHistoricalChangesForCustomer(storedFalseResolution, {
  comparable: true,
  currentModules: { dmarc_core: fixture },
});
ok("API read repair does not call still-observed p=none resolved",
  observedNoneProjection.resolved_findings.length === 0);
const unavailableProjection = projectHistoricalChangesForCustomer(storedFalseResolution, {
  comparable: true,
  currentModules: { dmarc_core: unavailable },
});
ok("API read repair moves unobserved DMARC resolution to not_reobserved",
  unavailableProjection.resolved_findings.length === 0 &&
    unavailableProjection.not_reobserved_findings?.[0]?.id === "email_dmarc_policy_none");
const rejectProjection = projectHistoricalChangesForCustomer(storedFalseResolution, {
  comparable: true,
  currentModules: { dmarc_core: rejectFixture },
});
ok("API read repair preserves a genuine observed reject resolution",
  rejectProjection.resolved_findings?.[0]?.id === "email_dmarc_policy_none");

const hostedRefusal = await budgetRefusedDmarcbisExternal(fixture, "launch_refused");
ok("hosted RUA refusal preserves complete/not-required result",
  hostedRefusal.rua_authorisation_completeness === "complete" &&
    hostedRefusal.destinations?.[0]?.authorization_status === "not_required_cybermeters_hosted");
const externalFixture = structuredClone(fixture);
externalFixture.rua_destinations[0] = {
  ...externalFixture.rua_destinations[0],
  raw: "mailto:redacted@reports.external.test",
  normalized_uri: "mailto:redacted@reports.external.test",
  destination_host_raw: "reports.external.test",
  destination_host: "reports.external.test",
};
const externalRefusal = await budgetRefusedDmarcbisExternal(externalFixture, "launch_refused");
ok("external RUA refusal remains incomplete",
  externalRefusal.rua_authorisation_completeness === "incomplete" &&
    externalRefusal.destinations?.[0]?.authorization_status === "not_assessed_budget");

const legacyStringFixture = structuredClone(fixture);
legacyStringFixture.source_record = { raw: fixture.source_record.value };
legacyStringFixture.raw_records = [];
ok("legacy string raw remains observed_policy",
  deriveDmarcStateFromPolicyEvidence(legacyStringFixture).canonical_evidence_state === "observed_policy");

const helperCandidateNew = {
  id: "fixture_new_high",
  module: "headers",
  severity: "high",
  title: "Fixture new high finding",
};
const helperCandidateResolved = {
  id: "fixture_resolved",
  module: "brand_monitoring",
  severity: "medium",
  title: "Fixture candidate resolution",
};
const helperNotReobserved = {
  id: "fixture_not_reobserved",
  module: "fixture_unobserved_producer",
  severity: "low",
  title: "Fixture producer not re-observed",
};
const helperInput = {
  has_previous: true,
  previous_scan_id: "scan-helper-previous",
  previous_score: 91,
  current_score: 84,
  score_change: -7,
  new_subdomains: ["new.fixture.example"],
  removed_subdomains: ["old.fixture.example"],
  new_findings: [helperCandidateNew],
  resolved_findings: [helperCandidateResolved],
  not_reobserved_findings: [helperNotReobserved],
  new_takeover_risks: [{ host: "risk.fixture.example" }],
  new_exposed_assets: [{ host: "asset.fixture.example" }],
  source: "previous_scan_comparison",
  error: null,
};
const helperInputBefore = JSON.stringify(helperInput);
const helperComparable = applyScanComparability(helperInput, true, "complete");
ok("comparability helper returns a new comparable shape",
  helperComparable !== helperInput && helperComparable.comparable === true);
ok("comparable helper preserves genuine comparison arrays and score facts",
  helperComparable.new_findings?.[0]?.id === helperCandidateNew.id &&
    helperComparable.resolved_findings?.[0]?.id === helperCandidateResolved.id &&
    helperComparable.not_reobserved_findings?.[0]?.id === helperNotReobserved.id &&
    helperComparable.score_change === -7 && helperComparable.previous_scan_id === "scan-helper-previous");
ok("comparable helper emits no suppression metadata",
  !("comparison_suppressed_reason" in helperComparable) &&
    !("comparison_scan_quality" in helperComparable));
ok("comparable helper copies arrays without rewriting nested findings",
  helperComparable.new_findings !== helperInput.new_findings &&
    helperComparable.new_findings[0] === helperInput.new_findings[0]);

const helperSuppressed = applyScanComparability(helperInput, "true", " partial ");
ok("only literal true is comparable",
  helperSuppressed.comparable === false && helperSuppressed.score_change === null);
ok("non-comparable helper suppresses only derived new/resolved claims",
  helperSuppressed.new_findings.length === 0 &&
    helperSuppressed.resolved_findings.length === 0 &&
    helperSuppressed.not_reobserved_findings?.[0]?.id === helperNotReobserved.id);
ok("non-comparable helper stamps exact reason and actual quality",
  helperSuppressed.comparison_suppressed_reason === "scan_not_comparable" &&
    helperSuppressed.comparison_scan_quality === "partial");
ok("non-comparable helper preserves baseline, source and observation arrays",
  helperSuppressed.has_previous === true &&
    helperSuppressed.previous_scan_id === "scan-helper-previous" &&
    helperSuppressed.previous_score === 91 &&
    helperSuppressed.source === "previous_scan_comparison" &&
    helperSuppressed.new_subdomains?.[0] === "new.fixture.example" &&
    helperSuppressed.new_exposed_assets?.[0]?.host === "asset.fixture.example");
ok("comparability helper does not mutate input, arrays or nested findings",
  JSON.stringify(helperInput) === helperInputBefore &&
    helperInput.new_findings[0] === helperCandidateNew &&
    helperInput.resolved_findings[0] === helperCandidateResolved);
ok("missing quality fails closed to unknown",
  applyScanComparability(helperInput, false, " ").comparison_scan_quality === "unknown");
ok("null and non-object helper inputs do not manufacture comparison state",
  applyScanComparability(null, false, "partial") === null &&
    applyScanComparability("legacy", false, "partial") === "legacy");

const scanEngineSource = fs.readFileSync(
  path.join(ROOT, "workers", "scan-api", "src", "engines", "scan-engine.js"),
  "utf8",
);
const historicalCatchBlock = scanEngineSource.slice(
  scanEngineSource.indexOf("    } catch (err) {\n      modules.historical_changes = {"),
  scanEngineSource.indexOf("\n    // Phase 5: CVE", scanEngineSource.indexOf("    } catch (err) {\n      modules.historical_changes = {")),
);
ok("engine historical catch fallback carries not-reobserved shape parity",
  /not_reobserved_findings:\s*\[\]/.test(historicalCatchBlock));
const phase7hIndex = scanEngineSource.indexOf("modules.certificate_intelligence = runCertificateIntelligenceModule(");
const lateReconcileIndex = scanEngineSource.indexOf("modules.historical_changes = reconcileLateFindings(");
const relocatedComparabilityIndex = scanEngineSource.indexOf(
  "modules.historical_changes = applyScanComparability(",
  lateReconcileIndex,
);
ok("engine reconciles once after Phase 7h and before comparability",
  phase7hIndex >= 0 && lateReconcileIndex > phase7hIndex &&
    relocatedComparabilityIndex > lateReconcileIndex &&
    scanEngineSource.indexOf("modules.historical_changes = reconcileLateFindings(", lateReconcileIndex + 1) === -1);
ok("engine performs exactly one historical D1/R2 comparison read",
  scanEngineSource.match(/modules\.historical_changes = await runHistoricalModule\(/g)?.length === 1);

function buildA2bDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(fs.readFileSync(path.join(ROOT, "database", "schema.sql"), "utf8"));
  for (const name of fs.readdirSync(path.join(ROOT, "database", "migrations"))
    .filter((entry) => entry.endsWith(".sql")).sort()) {
    const raw = fs.readFileSync(path.join(ROOT, "database", "migrations", name), "utf8");
    const fileSha = createHash("sha256").update(raw).digest("hex");
    for (const statement of splitStatements(raw)) {
      try { db.exec(statement); }
      catch (error) {
        if (!isToleratedStatement(name, fileSha, statement, error.message)) throw error;
      }
    }
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeA2bD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return {
        success: true,
        meta: { changes: result.changes, last_row_id: Number(result.lastInsertRowid || 0) },
      };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => {
      const results = [];
      db.exec("BEGIN");
      try {
        for (const entry of statements) {
          results.push(/^\s*(select|with)\b/i.test(entry.__sql)
            ? await entry.all()
            : await entry.run());
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function makeA2bR2(store) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      if (body == null) return null;
      return {
        text: async () => body,
        json: async () => JSON.parse(body),
        arrayBuffer: async () => new TextEncoder().encode(body).buffer,
      };
    },
    put: async (key, body) => { store.set(String(key), String(body)); return {}; },
    delete: async (key) => { store.delete(String(key)); return {}; },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

function a2bPreviousReport() {
  return {
    cyber_metrics_score: 96,
    risk_level: "excellent",
    scan_quality: { status: "complete" },
    findings: [helperCandidateResolved, helperNotReobserved],
    modules: {
      subdomains: { items: [] },
      subdomain_takeover: { risks: [] },
      asset_exposure: { assets: [] },
      cve_intelligence: {
        executed: true, technologies_checked: [], lookup_statuses: {}, results: {},
        total_cves: 0, critical_count: 0, high_count: 0, cve_coverage: "complete",
      },
      known_exploited_vulnerabilities: { executed: true, matches: [], checked: 0, matched: 0 },
      email_security_intelligence: { executed: true, mta_sts: { configured: true }, tls_rpt: { configured: true } },
    },
  };
}

const NOW = "2026-08-30T09:00:00.000Z";
const A2B_COMPARABLE_NOW = "2026-08-30T09:30:00.000Z";

const a2bDb = buildA2bDb();
const a2bStore = new Map();
const a2bEnv = {
  cybermeters_db: makeA2bD1(a2bDb),
  cybermeters_reports: makeA2bR2(a2bStore),
  SCAN_CAPACITY_MODE: "legacy",
  SCAN_SUBREQUEST_LIMIT: "200",
  SCAN_DEADLINE_MS: "19000",
  APP_VERSION: "a2b-write-time-fixture",
  MFA_ENCRYPTION_KEY: "a2b-write-time-fixture-key",
  ALLOWED_ORIGIN: "https://app.cybermeters.test",
  FRONTEND_URL: "https://app.cybermeters.test",
  RESEND_API_KEY: "",
  ADMIN_EMAILS: "",
};
a2bDb.prepare(`INSERT INTO users
  (id,email,name,plan,status,email_verified,mfa_enabled)
  VALUES ('usr-a2b','fixture@cybermeters.test','A2b Fixture','starter','active',1,0)`).run();
a2bDb.prepare(`INSERT INTO workspaces
  (id,name,owner_user_id,deleted_at)
  VALUES ('ws-a2b','A2b Fixture','usr-a2b',NULL)`).run();
a2bDb.prepare(`INSERT INTO workspace_members
  (id,workspace_id,user_id,role)
  VALUES ('member-a2b','ws-a2b','usr-a2b','owner')`).run();
a2bDb.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom-a2b','usr-a2b','fixture.example')").run();
a2bDb.prepare(`INSERT INTO workspace_domains
  (workspace_id,domain_id,verification_status)
  VALUES ('ws-a2b','dom-a2b','verified')`).run();
a2bDb.prepare(`INSERT INTO scans
  (id,workspace_id,domain_id,domain,status,score,rating,scan_quality,created_at)
  VALUES ('scan-a2b-previous','ws-a2b','dom-a2b','fixture.example','completed',96,'excellent','complete','2026-08-30T08:00:00.000Z')`).run();
a2bStore.set("reports/scan-a2b-previous.json", JSON.stringify(a2bPreviousReport()));

let a2bProviderMode = "partial";
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
  if (url.hostname === "www.cisa.gov") {
    return jsonResponse({
      title: "CISA Known Exploited Vulnerabilities Catalog",
      catalogVersion: "fixture",
      dateReleased: "2026-08-30T00:00:00.000Z",
      count: 0,
      vulnerabilities: [],
    });
  }
  if (url.hostname === "crt.sh") {
    if (a2bProviderMode === "partial") return jsonResponse({}, 403);
    return jsonResponse([{
      id: 1,
      name_value: "fixture.example\nwww.fixture.example",
      common_name: "fixture.example",
      issuer_name: "A2b Fixture CA",
      entry_timestamp: "2026-08-30T07:00:00.000Z",
      not_before: "2026-08-01T00:00:00.000Z",
      not_after: "2027-08-01T00:00:00.000Z",
    }]);
  }
  if (url.hostname === "api.certspotter.com") {
    return jsonResponse([{
      id: "a2b-cert",
      not_before: "2026-08-01T00:00:00.000Z",
      not_after: "2027-08-01T00:00:00.000Z",
      issuer: { name: "A2b Fixture CA" },
      dns_names: ["fixture.example", "www.fixture.example"],
    }]);
  }
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "fixture.example" && type === "A") {
      return jsonResponse({ Status: 0, Answer: [{ type: 1, data: "192.0.2.44" }] });
    }
    if (name === "fixture.example" && type === "MX") {
      return jsonResponse({ Status: 0, Answer: [{ type: 15, data: "10 mail.fixture.example." }] });
    }
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("<html><head><title>A2b Fixture</title></head><body>ok</body></html>", {
    status: 200,
    headers: { "content-type": "text/html", server: "a2b-fixture" },
  });
};

const seedA2bRunningScan = (id, createdAt) => {
  a2bDb.prepare(`INSERT INTO scans
    (id,workspace_id,domain_id,domain,status,scan_quality,created_at)
    VALUES (?,'ws-a2b','dom-a2b','fixture.example','running',NULL,?)`).run(id, createdAt);
};

const callA2bReportRoute = async (scanId) => {
  const request = new Request(`https://api.cybermeters.test/api/scans/${scanId}/report`);
  const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
  const response = await scanRoutes({
    request,
    env: a2bEnv,
    ctx: { waitUntil() {} },
    url: new URL(request.url),
    json,
    serverError: (_scope, error) => json({ error: String(error?.message || error) }, 500),
    corsHeaders: {},
    requireAuth: async () => ({ id: "usr-a2b" }),
    requireWorkspaceRole: async () => ({ role: "owner" }),
    requireScanReadAccess: async () => true,
    getAccessibleWorkspaceIds: async () => ["ws-a2b"],
  });
  return { status: response.status, body: await response.json() };
};

try {
  seedA2bRunningScan("scan-a2b-partial", "2026-08-30T09:00:00.000Z");
  let engineError = null;
  try {
    await runScanEngine(
      "scan-a2b-partial",
      "dom-a2b",
      "ws-a2b",
      "fixture.example",
      a2bEnv,
      { executionContext: "waituntil", now: () => Date.parse(NOW) },
    );
  } catch (error) {
    engineError = error;
  }
  ok("A2b real engine fixture completes without throwing", engineError === null,
    engineError?.message || "");
  const rawPartial = JSON.parse(a2bStore.get("reports/scan-a2b-partial.json") || "{}");
  const rawHist = rawPartial.modules?.historical_changes || {};
  const preQualityComparison = await runHistoricalModule(
    "scan-a2b-partial-replay",
    "fixture.example",
    rawPartial.cyber_metrics_score,
    rawPartial.findings,
    rawPartial.modules,
    {
      cybermeters_db: {
        prepare: () => ({ bind: () => ({ first: async () => ({ id: "scan-a2b-previous", score: 96 }) }) }),
      },
      cybermeters_reports: {
        get: async () => ({ json: async () => structuredClone(a2bPreviousReport()) }),
      },
    },
    "ws-a2b",
  );
  ok("pre-quality comparison genuinely contains a new high/critical finding",
    preQualityComparison.new_findings.some((item) => ["high", "critical"].includes(item.severity)));
  ok("pre-quality comparison genuinely contains a candidate resolution",
    preQualityComparison.resolved_findings.some((item) => item.id === helperCandidateResolved.id));
  ok("later module makes the real terminal scan non-complete",
    rawPartial.scan_quality?.status && rawPartial.scan_quality.status !== "complete",
    rawPartial.scan_quality?.status || "missing");
  ok("raw terminal R2 marks historical comparison non-comparable",
    rawHist.comparable === false);
  ok("raw terminal R2 suppresses derived new and resolved lists",
    Array.isArray(rawHist.new_findings) && rawHist.new_findings.length === 0 &&
    Array.isArray(rawHist.resolved_findings) && rawHist.resolved_findings.length === 0);
  ok("raw terminal R2 preserves producer-owned not-reobserved findings only",
    rawHist.not_reobserved_findings?.some((item) => item.id === helperNotReobserved.id) &&
    !rawHist.not_reobserved_findings?.some((item) =>
      item.id === helperCandidateResolved.id || preQualityComparison.new_findings.some((candidate) => candidate.id === item.id)));
  ok("raw terminal R2 stamps exact suppression reason and final quality",
    rawHist.comparison_suppressed_reason === "scan_not_comparable" &&
    rawHist.comparison_scan_quality === rawPartial.scan_quality.status);
  ok("raw terminal R2 nulls score delta while preserving baseline facts",
    rawHist.score_change === null && rawHist.has_previous === true &&
    rawHist.previous_scan_id === "scan-a2b-previous" && rawHist.previous_score === 96 &&
    rawHist.source === "previous_scan_comparison");
  ok("raw terminal R2 preserves actual high/critical source findings",
    rawPartial.findings?.some((item) => ["high", "critical"].includes(item.severity)));
  ok("raw terminal R2 emits no hidden replacement candidate list",
    !Object.keys(rawHist).some((key) => /candidate|suppressed_(?:new|resolved)/i.test(key)));
  ok("suppressed comparison carries no healthy/fixed/resolved/no-change conclusion",
    !Object.entries(rawHist).some(([key, value]) =>
      /conclusion|summary|state/i.test(key) && /healthy|fixed|resolved|no[_ ]?change/i.test(String(value))));
  ok("unchanged Phase 10 emits no legacy new_finding notification",
    a2bDb.prepare(`SELECT COUNT(*) AS n FROM notification_events
      WHERE workspace_id = 'ws-a2b' AND type = 'new_finding'`).get().n === 0);

  const legacyComparableInput = {
    ...rawHist,
    comparable: true,
    new_findings: [helperCandidateNew],
    resolved_findings: [helperCandidateResolved, priorFinding()],
    not_reobserved_findings: [],
    legacy_marker: "preserved",
  };
  const comparableRaw = structuredClone(rawPartial);
  comparableRaw.modules.historical_changes = legacyComparableInput;
  comparableRaw.modules.dmarc_core = fixture;
  a2bStore.set("reports/scan-a2b-partial.json", JSON.stringify(comparableRaw));
  const completedLegacyRoute = await callA2bReportRoute("scan-a2b-partial");
  ok("completed legacy report route keeps HTTP lifecycle and arrays compatible",
    completedLegacyRoute.status === 200 &&
    Array.isArray(completedLegacyRoute.body.modules?.historical_changes?.new_findings) &&
    Array.isArray(completedLegacyRoute.body.modules?.historical_changes?.resolved_findings) &&
    completedLegacyRoute.body.modules?.historical_changes?.legacy_marker === "preserved");
  ok("completed non-comparable legacy route suppresses stored false claims",
    completedLegacyRoute.body.modules.historical_changes.new_findings.length === 0 &&
    completedLegacyRoute.body.modules.historical_changes.resolved_findings.length === 0);

  a2bProviderMode = "complete";
  seedA2bRunningScan("scan-a2b-comparable", "2026-08-30T09:30:00.000Z");
  let comparableEngineError = null;
  try {
    await runScanEngine(
      "scan-a2b-comparable",
      "dom-a2b",
      "ws-a2b",
      "fixture.example",
      a2bEnv,
      { executionContext: "waituntil", now: () => Date.parse(A2B_COMPARABLE_NOW) },
    );
  } catch (error) {
    comparableEngineError = error;
  }
  const comparableControl = JSON.parse(a2bStore.get("reports/scan-a2b-comparable.json") || "{}");
  ok("real comparable completed control remains available",
    comparableEngineError === null && comparableControl.scan_quality?.status === "complete" &&
    comparableControl.modules?.historical_changes?.comparable === true,
    comparableEngineError?.message || comparableControl.scan_quality?.status || "missing");
  comparableControl.modules.historical_changes = {
    ...comparableControl.modules.historical_changes,
    comparable: true,
    new_findings: [helperCandidateNew],
    resolved_findings: [helperCandidateResolved, priorFinding()],
    not_reobserved_findings: [],
    legacy_marker: "comparable-preserved",
  };
  comparableControl.modules.dmarc_core = fixture;
  a2bStore.set("reports/scan-a2b-comparable.json", JSON.stringify(comparableControl));
  const comparableSnapshotRow = a2bDb.prepare(
    "SELECT r2_key FROM scan_report_snapshots WHERE scan_id = 'scan-a2b-comparable'",
  ).get();
  const comparableSnapshot = JSON.parse(a2bStore.get(comparableSnapshotRow.r2_key));
  comparableSnapshot.overall.assessment.comparable = true;
  const comparableSnapshotRaw = JSON.stringify(comparableSnapshot);
  const comparableSnapshotChecksum = createHash("sha256")
    .update(comparableSnapshotRaw)
    .digest("hex");
  a2bStore.set(comparableSnapshotRow.r2_key, comparableSnapshotRaw);
  a2bDb.prepare(`UPDATE scan_report_snapshots
    SET checksum_sha256 = ?, size_bytes = ? WHERE scan_id = 'scan-a2b-comparable'`)
    .run(comparableSnapshotChecksum, new TextEncoder().encode(comparableSnapshotRaw).length);
  const comparableLegacyRoute = await callA2bReportRoute("scan-a2b-comparable");
  ok("comparable completed legacy route preserves genuine new/resolved lists",
    comparableLegacyRoute.status === 200 &&
    comparableLegacyRoute.body.modules?.historical_changes?.new_findings?.[0]?.id === helperCandidateNew.id &&
    comparableLegacyRoute.body.modules?.historical_changes?.resolved_findings?.some(
      (item) => item.id === helperCandidateResolved.id) &&
    comparableLegacyRoute.body.modules?.historical_changes?.legacy_marker === "comparable-preserved",
    JSON.stringify(comparableLegacyRoute.body.modules?.historical_changes || null));
  ok("comparable completed legacy route retains A2 DMARC read repair",
    !comparableLegacyRoute.body.modules.historical_changes.resolved_findings.some(
      (item) => item.id === "email_dmarc_policy_none"));

  a2bDb.prepare(`INSERT INTO scans
    (id,workspace_id,domain_id,domain,status,score,rating,scan_quality,created_at)
    VALUES ('scan-a2b-failed','ws-a2b','dom-a2b','fixture.example','failed',NULL,NULL,'partial','2026-08-30T10:00:00.000Z')`).run();
  const failedLegacyHistorical = {
    has_previous: true,
    previous_scan_id: "scan-a2b-previous",
    previous_score: 96,
    current_score: null,
    score_change: null,
    new_findings: [helperCandidateNew],
    resolved_findings: [helperCandidateResolved],
    not_reobserved_findings: [helperNotReobserved],
    legacy_marker: "failed-preserved",
    source: "previous_scan_comparison",
    error: null,
  };
  a2bStore.set("reports/scan-a2b-failed.json", JSON.stringify({
    scan_id: "scan-a2b-failed",
    domain: "fixture.example",
    status: "failed",
    scan_quality: { status: "partial" },
    findings: [],
    recommendations: [],
    modules: { historical_changes: failedLegacyHistorical },
    failed_at: "2026-08-30T10:00:01.000Z",
    error: "Synthetic fixture failure",
  }));
  const failedLegacyRoute = await callA2bReportRoute("scan-a2b-failed");
  ok("failed legacy report route preserves status, lifecycle and additive fields",
    failedLegacyRoute.status === 200 && failedLegacyRoute.body.status === "failed" &&
    failedLegacyRoute.body.failed_at === "2026-08-30T10:00:01.000Z" &&
    failedLegacyRoute.body.modules?.historical_changes?.legacy_marker === "failed-preserved" &&
    failedLegacyRoute.body.modules.historical_changes.not_reobserved_findings?.[0]?.id === helperNotReobserved.id);
  ok("failed legacy report route suppresses stored new and resolved claims",
    Array.isArray(failedLegacyRoute.body.modules.historical_changes.new_findings) &&
    failedLegacyRoute.body.modules.historical_changes.new_findings.length === 0 &&
    Array.isArray(failedLegacyRoute.body.modules.historical_changes.resolved_findings) &&
    failedLegacyRoute.body.modules.historical_changes.resolved_findings.length === 0);
} finally {
  globalThis.fetch = originalFetch;
  a2bDb.close();
}

console.log(`\nDMARC historical consistency: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
