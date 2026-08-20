#!/usr/bin/env node
// U3 + XD-1 — Identity customer/action/risk/report truth projection.
//
// The accepted V3 registry is executable: every stable fixture ID is emitted,
// the count is derived from FIXTURES, and missing additive exports fail as
// semantic REDs on the parent instead of aborting the harness.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveCyberMotDomainStates } from "../workers/scan-api/src/engines/cyber-mot-domains.js";
import { computeBusinessRiskScore } from "../workers/scan-api/src/engines/business-risk.js";
import { computeWorkspaceVendorRisk } from "../workers/scan-api/src/engines/vendor-risk.js";
import { resolveRemediation } from "../workers/scan-api/src/engines/remediation-registry.js";
import { getRule } from "../workers/scan-api/src/engines/related-changes-rules.js";
import { deriveLevel } from "../workers/scan-api/src/engines/identity-exposure.js";
import * as contract from "../workers/scan-api/src/engines/identity-evidence-contract.js";
import * as lifecycle from "../workers/scan-api/src/engines/identity-lifecycle.js";
import * as inventory from "../workers/scan-api/src/engines/shadow-it-inventory.js";
import * as supplyChain from "../workers/scan-api/src/engines/supply-chain.js";
import * as phase5 from "../workers/scan-api/src/engines/phase5-evidence.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), "utf8");
const OBSERVED_AT = "2026-08-11T09:10:11.000Z";
// Scope CAPABILITIES assertions to the Identity Exposure section only.
function capabilitySection() {
  const doc = read("docs/CAPABILITIES.md");
  const start = doc.indexOf("### 7. Identity Exposure");
  if (start < 0) return "";
  const next = doc.indexOf("### 8.", start);
  return doc.slice(start, next < 0 ? doc.length : next);
}
const unsupportedIds = [
  "identity_microsoft_365_detected",
  "identity_legacy_auth_exposed",
  "identity_autodiscover_exposed",
];

function datum({ precision = "label_boundary", subject = "provider_identification", resolution = "not_evaluated" } = {}) {
  return {
    schema_version: "identity_evidence.v2",
    source: subject === "provider_identification" ? "cname" : "certificate_transparency",
    value: subject === "provider_identification" ? "login.microsoftonline.com" : "login.example.com",
    provenance: { producer: "identity_discovery", module: subject === "provider_identification" ? "subdomain_takeover" : "subdomains", path: "fixture" },
    match_precision: precision,
    name_resolution: resolution,
    validation_state: "observed",
    confidence_detail: contract.identityConfidenceForPrecision?.(precision, subject),
    observed_at: OBSERVED_AT,
  };
}

function claim(row) {
  return contract.buildIdentityClaim?.({ ...row, evidence: JSON.stringify(row.evidence ?? []) });
}

function providerRow(precision = "label_boundary") {
  return { id: "ia-provider", asset_type: "provider", identity_type: "idp", provider: "Microsoft Entra ID", hostname: null, internet_exposed: 1, risk_score: 20, evidence: [datum({ precision })] };
}

function candidateRow({ resolution = "not_evaluated", malformed = false } = {}) {
  return { id: "ia-candidate", asset_type: "portal", identity_type: "admin_login", provider: null, hostname: "admin.example.com", internet_exposed: 1, risk_score: 20, evidence: malformed ? "{" : [datum({ precision: "hostname_prefix", subject: "hostname_classification", resolution })] };
}

function measuredRow() {
  return {
    ...candidateRow({ resolution: "resolved" }),
    reachability_measurement: {
      producer: "synthetic_contract_control",
      supported: true,
      status: "reachable",
      endpoint: "https://admin.example.com",
      method: "https_get",
      measured_at: OBSERVED_AT,
      confidence_detail: {
        schema_version: "identity_confidence.v1", subject: "endpoint_reachability",
        level: "high", score: 95, quality: "excellent", basis: "https_response",
      },
    },
  };
}

function cleanComplete() {
  return {
    scan_id: "scan-u3", completed_at: OBSERVED_AT,
    scan_quality: { status: "complete", warnings: [], modules_skipped: [] },
    modules: {
      email_security: {}, dns: {}, ssl: { https_available: true, https_probe_executed: true }, headers: {},
      subdomains: { count: 3 }, admin_surface_detection: {}, cloud_storage_discovery: {},
      certificate_intelligence: {}, brand_monitoring: {}, identity_discovery: { detected: true, high_risk_count: 4 },
      saas_exposure: { count: 2 }, technology_detection: { count: 5 },
    },
    monitoring_states: { version: "signal-monitoring-state-v1", signals: { certificate_transparency: { state: "monitoring_healthy", message: "complete", evidence: { modules: ["subdomains"], incomplete_modules: [], providers: { crt_sh: "available" } } } } },
    findings: [],
  };
}

function managedRow(identityClaim) {
  return {
    id: "ie-u3", workspace_id: "ws-u3", domain_id: "d-u3", canonical_identity_key: "provider:microsoft_entra_id:identity_provider",
    provider_key: "microsoft_entra_id", provider_name: "Microsoft Entra ID", surface_type: "identity_provider", primary_hostname: null,
    observed_urls_json: "[]", observed_endpoints_json: "[]", observed_protocols_json: "[]", source_types_json: '["cname"]',
    source_evidence_json: JSON.stringify([{ source_table: "identity_assets", source_record_id: "ia-provider", identity_claim: identityClaim }]),
    first_seen_at: OBSERVED_AT, last_seen_at: OBSERVED_AT, confidence: "high", exposure_status: "observed",
    customer_classification: "unreviewed", ownership_status: "missing", remediation_status: "not_started",
    verification_status: "not_verified", monitoring_status: "observed", lifecycle_state: "observed",
    created_at: OBSERVED_AT, updated_at: OBSERVED_AT,
  };
}

const source = {
  academy: () => read("frontend/src/data/academy.js"),
  contract: () => read("workers/scan-api/src/engines/identity-evidence-contract.js"),
  lifecycle: () => read("workers/scan-api/src/engines/identity-lifecycle.js"),
  workspace: () => read("workers/scan-api/src/routes/workspace-intel.js"),
  route: () => read("workers/scan-api/src/routes/identity-exposure.js"),
  shadow: () => read("workers/scan-api/src/engines/shadow-it-inventory.js"),
  landing: () => read("frontend/src/pages/PublicLandingPage.jsx"),
  dashboard: () => read("frontend/src/pages/Dashboard.jsx"),
  capabilities: () => read("docs/CAPABILITIES.md"),
  methodology: () => read("docs/risk-methodology-v1.md"),
  scorecard: () => read("workers/scan-api/src/engines/scorecard.js"),
  scans: () => read("workers/scan-api/src/routes/scans.js"),
  snapshot: () => read("workers/scan-api/src/engines/report-snapshot.js"),
  pdf: () => read("workers/scan-api/src/engines/pdf.js"),
  frontend: () => [
    "frontend/src/pages/ws/WorkspaceIdentityPage.jsx",
    "frontend/src/pages/ws/IdentityExposurePage.jsx",
    "frontend/src/components/IdentityExposureCard.jsx",
    "frontend/src/lib/identityExposureDisplay.js",
    "frontend/src/lib/relatedChangesDisplay.js",
    "frontend/src/components/CyberMotDomains.jsx",
    "frontend/src/components/ServiceLauncher.jsx",
  ].map(read).join("\n"),
};

const noReachabilityWords = (value) => !/internet-facing login|publicly reachable admin|login or admin surface|none exposed|credentials are attacked/i.test(value);
const claimIsUnmeasured = (c) => c?.reachability?.status === "not_evaluated" && c?.reachability?.endpoint === null && c?.evidence_grade?.reachability === "L0";
const allowed = (c) => contract.identityAllowedActionsForClaim?.(c) ?? [];

const FIXTURES = [
  { id: "U3-A01", control: true, run: () => unsupportedIds.every((id) => !new RegExp(`(?:id|finding_type)\\s*[:=]\\s*[\"']${id}[\"']`).test([source.lifecycle(), read("workers/scan-api/src/engines/identity-scan.js")].join("\n"))) },
  { id: "U3-A02", run: () => /What CyberMeters can observe/.test(source.academy()) && /What CyberMeters cannot observe/.test(source.academy()) && !/Re-scan in CyberMeters — M365 identity exposure findings will reflect updated configuration/.test(source.academy()) },
  { id: "U3-A03", run: () => unsupportedIds.every((id) => { const r = resolveRemediation({ finding_type: id }); return r?.status === "resolved" && r?.lifecycle_status === "deprecated" && r?.verification_method === "unsupported"; }) },
  { id: "U3-P01", run: () => { const c = claim(providerRow()); return c?.provider_relationship?.status === "observed" && c?.claim_kind === "provider_relationship" && claimIsUnmeasured(c); } },
  { id: "U3-P02", run: () => { const c = claim({ ...providerRow("token_substring"), internet_exposed: 0 }); return c?.provider_relationship?.status === "possible" && c?.provider_relationship?.confidence_detail?.level === "low" && claimIsUnmeasured(c); } },
  { id: "U3-P03", run: () => { const c = claim(candidateRow()); return c?.surface_classification?.status === "possible" && c?.name_resolution?.status === "not_evaluated" && claimIsUnmeasured(c); } },
  { id: "U3-P04", run: () => { const c = claim(candidateRow({ resolution: "resolved" })); return c?.surface_classification?.status === "possible" && c?.name_resolution?.status === "resolved" && claimIsUnmeasured(c); } },
  { id: "U3-P05", run: () => { const c = contract.buildIdentityClaim?.({ ...candidateRow({ malformed: true }), evidence: "{" }); return ["unknown", "unknown_legacy"].includes(c?.surface_classification?.status) && claimIsUnmeasured(c); } },
  { id: "U3-POS-01", control: true, run: () => { const c = claim(measuredRow()); return c?.claim_kind === "measured_identity_surface" && c?.reachability?.status === "reachable" && contract.isMeasuredIdentityClaim?.(c) === true; } },
  { id: "U3-API-01", run: () => { const p = contract.projectIdentityCustomerRow?.({ ...candidateRow({ resolution: "resolved" }), internet_exposed: 0 }); return p?.identity_claim?.reachability?.status === "not_evaluated" && p?.candidate_urls?.length === 1 && p?.measured_endpoints?.length === 0 && /provider_relationship_count/.test(source.workspace()) && /surface_candidate_count/.test(source.workspace()) && /reachability_evaluated_count/.test(source.workspace()) && /reachable_surface_count/.test(source.workspace()) && /internet_facing: claimCounts\.reachable_surface_count/.test(read("workers/scan-api/src/engines/identity-exposure.js")); } },
  { id: "U3-API-02", run: () => { const item = lifecycle.identityExposureToApi?.(managedRow(claim(providerRow()))); return Array.isArray(item?.allowed_actions) && JSON.stringify(item.allowed_actions) === JSON.stringify(allowed(item.identity_claim)) && !item.allowed_actions.includes("record_surface_removed") && /item\?\.allowed_actions/.test(read("frontend/src/pages/ws/IdentityExposurePage.jsx")); } },
  { id: "U3-API-03", run: () => !allowed(claim(providerRow())).includes("record_surface_removed") && !allowed(claim(providerRow())).includes("request_verification") && /identityAllowedActionsForClaim/.test(source.route()) && /action_not_allowed/.test(source.lifecycle()) },
  { id: "U3-API-04", control: true, run: () => /deleted_at IS NULL/.test(source.route()) && /WHERE id = \? AND workspace_id = \?/.test(source.lifecycle()) && /Forbidden/.test(source.route()) },
  { id: "U3-LIFE-01", run: () => /isMeasuredIdentityClaim\([^)]*identity_claim/.test(source.lifecycle()) && /measuredIdentityClaim && admin/.test(source.lifecycle()) },
  { id: "U3-LIFE-02", run: () => allowed(claim(candidateRow())).includes("classify_unexpected") && /neutral_candidate_review/.test(source.lifecycle()) },
  { id: "U3-LIFE-03", run: () => { const item = lifecycle.identityExposureToApi?.(managedRow(claim(providerRow()))); return item?.candidate_urls?.length === 0 && item?.measured_endpoints?.length === 0 && !item?.allowed_actions?.includes("request_verification"); } },
  { id: "U3-LIFE-04", control: true, run: () => /linked_case_id/.test(source.lifecycle()) && !/DELETE FROM managed_cases/.test(source.lifecycle()) && !/UPDATE managed_cases SET status = ['\"]closed/.test(source.lifecycle()) },
  { id: "U3-ALERT-01", run: () => /measuredIdentityClaim && admin/.test(source.lifecycle()) && /measuredIdentityClaim && cls === "unexpected"/.test(source.lifecycle()) && /const alertEligible = measuredIdentityClaim \|\| recurrence_type === "provider_change"/.test(source.lifecycle()) && /await emitLifecycleAlert/.test(source.lifecycle()) },
  { id: "U3-BRI-01", run: () => { const legacy = computeBusinessRiskScore(new Set(), { vendorTotal: 1, identityHighRiskCount: 9, identityReachableSurfaceCount: 0 }); const control = computeBusinessRiskScore(new Set(), { vendorTotal: 1, identityHighRiskCount: 0, identityReachableSurfaceCount: 0 }); return legacy.categories?.attack_surface_exposure?.score === control.categories?.attack_surface_exposure?.score && legacy.categories?.attack_surface_exposure?.identity_reachability?.status === "not_evaluated"; } },
  { id: "U3-BRI-02", control: true, run: () => { const base = computeBusinessRiskScore(new Set(), { vendorTotal: 1, identityReachableSurfaceCount: 0 }); const measured = computeBusinessRiskScore(new Set(), { vendorTotal: 1, identityReachableSurfaceCount: 2 }); return measured.categories?.attack_surface_exposure?.score < base.categories?.attack_surface_exposure?.score; } },
  // ── I11B F-50 / F-51 — CLAIM-SURFACE PARITY GUARD ────────────────────────
  //
  // Wording IS the claim, so wording gets a guard (same principle as the F-47
  // removal-vocabulary guard). IDENTITY_REACHABILITY_PRODUCERS is empty, so no
  // customer-facing surface may assert that an identity endpoint is exposed,
  // reachable or detected. Each fixture is a CONJUNCTION — the forbidden claim
  // must be absent AND the honest qualifier must be present — so it cannot pass
  // vacuously by deleting the sentence altogether.
  //
  // capabilitySection() scopes the CAPABILITIES assertions to section 7 only, so
  // another domain's wording can never satisfy or break this guard.
  { id: "U3-CS-01", run: () => {
      const src = source.landing();
      const forbidden = /Public login surfaces and identity-facing entry points/.test(src)
        || /'IdP exposure'/.test(src)
        || /Where are our login surfaces exposed/.test(src);
      const qualified = /roadmap and is not performed today/.test(src)
        && /Reachability: roadmap/.test(src);
      return forbidden === false && qualified === true;
    } },
  { id: "U3-CS-02", run: () => {
      const src = source.landing();
      return /login surfaces'/.test(src) === false
        && /identity-facing hostnames/.test(src) === true;
    } },
  { id: "U3-CS-03", run: () => {
      const src = source.dashboard();
      return /Review public login surfaces and identity-facing entry points/.test(src) === false
        && /Endpoint reachability is not measured/.test(src) === true;
    } },
  { id: "U3-CS-04", run: () => {
      const sec = capabilitySection();
      const forbidden = /\*\*Observes:\*\* public login surfaces/.test(sec)
        || /\*\*Detects:\*\* externally visible identity\/login exposure/.test(sec);
      const qualified = /no reachability producer is registered/.test(sec)
        && /not evaluated/.test(sec);
      return forbidden === false && qualified === true;
    } },
  { id: "U3-CS-05", run: () => {
      const doc = source.methodology();
      const forbidden = /high_risk_count \u00d7 7/.test(doc);
      const qualified = /measured reachable surfaces \u00d7 7/.test(doc)
        && /none is registered today/.test(doc);
      return forbidden === false && qualified === true;
    } },
  // POSITIVE CONTROL — the guard must be capable of seeing the defect. It builds
  // the pre-fix wording in memory and requires the same predicates to REJECT it.
  // If this control ever passes trivially, the guard above is not discriminating.
  { id: "U3-CS-CONTROL", control: true, run: () => {
      const preFix = "copy: 'Public login surfaces and identity-facing entry points, without unsupported breach or dark-web claims.'";
      const preFixDoc = "| Identity exposure (high_risk_count \u00d7 7, capped at \u221220) | Up to \u221220 |";
      const landingRejected = /Public login surfaces and identity-facing entry points/.test(preFix) === true;
      const docRejected = /high_risk_count \u00d7 7/.test(preFixDoc) === true;
      return landingRejected && docRejected;
    } },
  // F-51 code parity: the doc now describes what the implementation actually does.
  { id: "U3-CS-06", run: () => {
      const brs = read("workers/scan-api/src/engines/business-risk.js");
      return /identityHighRiskCount\s*=\s*0,\s*\/\/ deprecated, deliberately ignored/.test(brs)
        && /identityReachableSurfaceCount \* 7/.test(brs)
        && /measured reachable surfaces/.test(source.methodology());
    } },
  { id: "U3-DOM-01", run: () => { const d = resolveCyberMotDomainStates(cleanComplete()); const i = d.find((x) => x.domain_key === "identity_exposure"); return d.length === 8 && i?.state === "evidence_insufficient" && /not evaluated|producer/i.test(i?.summary || ""); } },
  { id: "U3-DOM-02", control: true, run: () => { const d = resolveCyberMotDomainStates(cleanComplete()).filter((x) => x.domain_key !== "identity_exposure"); return d.length === 7 && d.every((x) => x?.state); } },
  { id: "U3-XD-01", run: () => { const row = { ...providerRow("token_substring"), risk_score: 20 }; const value = inventory.projectIdentityProviderObservation?.(row); return value?.confidence === "low" && value?.confidence_detail?.subject === "provider_identification" && !/row\.risk_score/.test(source.shadow()); } },
  { id: "U3-XD-02", control: true, run: () => inventory.strongerObservationConfidence?.("high", "medium") === "high" || /strongerConfidence/.test(source.shadow()) },
  { id: "U3-VR-01", run: () => { const r = computeWorkspaceVendorRisk([{ id: "v1", vendor_name: "Microsoft Entra ID", category: "identity_provider", source: "identity_discovery", source_module: "identity_discovery", risk_level: "high", confidence: "high", status: "active" }]); return r.scored_vendors?.[0]?.score === 0 && r.scored_vendors?.[0]?.risk_evidence_status === "relationship_only" && /COALESCE\(source_module, ''\) != 'identity_discovery'/.test(source.scorecard()); } },
  { id: "U3-VR-02", control: true, run: () => { const r = computeWorkspaceVendorRisk([{ id: "v1", vendor_name: "Microsoft Entra ID", category: "identity_provider", source: "csp:connect-src", source_module: "vendor_risk", evidence: JSON.stringify([{ source: "csp:connect-src" }]), risk_level: "high", confidence: "high", status: "active" }]); return r.scored_vendors?.[0]?.score > 0; } },
  { id: "U3-SC-01", run: () => { const rows = [{ vendor_name: "Microsoft Entra ID", category: "identity_provider", status: "active", source_module: "identity_discovery", risk_level: null }]; const enriched = supplyChain.enrichVendors?.(rows); const risks = enriched && supplyChain.computeCascadingRisks?.(enriched, {}); return Array.isArray(risks) && risks.every((r) => r.severity !== "critical") && /relationship_only/.test(read("workers/scan-api/src/engines/supply-chain.js")); } },
  { id: "U3-RC-01", run: () => { const a = getRule("new_host_with_identity"); const b = getRule("identity_with_cert"); return /possible identity-facing hostname/i.test(`${a?.title} ${a?.summary}`) && /possible identity-facing hostname/i.test(`${b?.title} ${b?.summary}`) && /possible identity-facing hostname/i.test(source.pdf()); } },
  { id: "U3-RC-02", run: () => noReachabilityWords(`${getRule("new_host_with_identity")?.title} ${getRule("identity_with_cert")?.title} ${source.pdf()}`) },
  { id: "U3-SNAP-RAW-01", control: true, run: () => /const customerSnapshot =/.test(source.snapshot()) && !/snapshot\.(domains|overall)\s*=/.test(source.snapshot()) },
  { id: "U3-SNAP-LIVE-01", run: () => { const raw = { domains: [{ domain_key: "identity_exposure", state: "assessed_healthy", summary: "Assessed" }], overall: { business_risk_indicator: { band: "Low", explanation: "clean", internal_metrics: { score: 98 } } } }; const out = phase5.projectIdentitySnapshotForCustomer?.(raw, { identity_discovery: { high_risk_count: 2 } }); return raw.domains[0].state === "assessed_healthy" && out?.domains?.[0]?.state === "evidence_insufficient" && out?.overall?.business_risk_indicator?.band === null && out?.customer_projection?.reason === "legacy_identity_reachability_semantics" && /snapshot: read\.snapshot/.test(source.scans()) && /customer_snapshot: customerSnapshot/.test(source.scans()); } },
  { id: "U3-SNAP-LIVE-02", control: true, run: () => { const raw = { domains: [{ domain_key: "email_protection", state: "assessed_healthy" }], overall: { business_risk_indicator: { band: "Low" } } }; const out = phase5.projectIdentitySnapshotForCustomer?.(raw, {}); return out?.domains?.[0]?.state === "assessed_healthy" && out?.overall?.business_risk_indicator?.band === "Low"; } },
  { id: "U3-FE-01", run: () => { const p = contract.projectIdentityCustomerRow?.({ ...candidateRow({ resolution: "resolved" }), internet_exposed: 0 }); return p?.identity_claim?.reachability?.status === "not_evaluated" && /Provider relationship|Possible identity-facing hostname/.test(read("frontend/src/pages/ws/WorkspaceIdentityPage.jsx")) && !/asset\.internet_exposed/.test(read("frontend/src/pages/ws/WorkspaceIdentityPage.jsx")) && !/risk score ≥ 15.*Business Risk Score/is.test(read("frontend/src/pages/ws/WorkspaceIdentityPage.jsx")); } },
  { id: "U3-FE-02", run: () => { const x = deriveLevel({ count: 1, internet_facing: 0, reachability_evaluated_count: 0 }, { total: 0, active: 0, can_send_mail: 0, can_host_login: 0 }, { checked_domains: 0, spoofable_domains: 0 }, { assessed: true, unavailable: false }); return x.identity_exposure_level === "Not Assessed" && /not evaluated/i.test(x.summary) && /internet_facing: claimCounts\.reachable_surface_count/.test(read("workers/scan-api/src/engines/identity-exposure.js")) && !/None exposed|No exposed login portals/.test(read("frontend/src/components/IdentityExposureCard.jsx")); } },
  { id: "U3-FE-03", run: () => /allowed_actions/.test(read("frontend/src/pages/ws/IdentityExposurePage.jsx")) && /confidence_detail/.test(read("frontend/src/pages/ws/IdentityExposurePage.jsx")) && /identity_claim/.test(read("frontend/src/pages/ws/IdentityExposurePage.jsx")) },
  { id: "U3-FE-04", run: () => noReachabilityWords([read("frontend/src/components/CyberMotDomains.jsx"), read("frontend/src/components/ServiceLauncher.jsx"), source.academy(), read("frontend/src/lib/relatedChangesDisplay.js")].join("\n")) && /What CyberMeters can observe/.test(source.academy()) && /review provider relationships and possible identity-facing hostnames/i.test(read("frontend/src/components/ServiceLauncher.jsx")) },
  { id: "U3-COMPAT-01", control: true, run: () => { const p = contract.buildIdentityEvidenceProjection?.({ ...providerRow(), evidence: JSON.stringify(providerRow().evidence) }); const item = lifecycle.identityExposureToApi?.(managedRow(p?.identity_claim)); return typeof providerRow().internet_exposed === "number" && typeof providerRow().risk_score === "number" && typeof item?.externally_observed === "boolean" && Array.isArray(item?.observed_urls) && typeof item?.exposure_status === "string"; } },
  { id: "U3-ITEM11-01", control: true, run: () => Array.isArray(contract.IDENTITY_REACHABILITY_PRODUCERS) && contract.IDENTITY_REACHABILITY_PRODUCERS.length === 0 && contract.hasIdentityReachabilityProducer?.() === false && !/row\.internet_exposed\s*\?\s*"reachable"/.test(source.contract()) && !/fetch\(|https?_probe|autodiscover.*fetch|legacy_auth.*fetch/i.test(source.contract()) },
];

let passed = 0;
const failed = [];
const controls = [];
console.log(`LOADED identity truth contract=${Object.keys(contract).length > 0} lifecycle=${Object.keys(lifecycle).length > 0}`);
for (const fixture of FIXTURES) {
  let ok = false;
  let detail = "";
  try { ok = Boolean(await fixture.run()); } catch (error) { detail = error?.message ?? String(error); }
  if (fixture.control) controls.push({ id: fixture.id, ok });
  if (ok) passed += 1; else failed.push(fixture.id);
  console.log(`${ok ? "PASS" : "FAIL"} ${fixture.id}${detail ? ` — ${detail}` : ""}`);
}

const executedIds = FIXTURES.map((fixture) => fixture.id);
console.log(`U3 fixtures executed (${executedIds.length}): ${executedIds.join(",")}`);
console.log(`U3 identity truth projection: ${passed}/${FIXTURES.length} fixtures passed`);
console.log(`U3 controls: ${controls.filter((item) => item.ok).length}/${controls.length} passed`);
if (new Set(executedIds).size !== FIXTURES.length || failed.length > 0) process.exit(1);
