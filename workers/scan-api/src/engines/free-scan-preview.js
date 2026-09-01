// Public Free Cyber MOT projection.
//
// This module does not create a second scoring or domain-state authority. It
// builds the bounded, non-persistent preview report, asks the existing scoring
// and canonical eight-domain resolvers for meaning, then removes everything an
// anonymous caller is not entitled to see.

import { runCertificateIntelligenceModule } from "./cert-intel.js";
import { resolveCyberMotDomainStates } from "./cyber-mot-domains.js";
import {
  runSaasExposureModule,
  runThirdPartyDiscoveryModule,
} from "./discovery-scan.js";
import { runIdentityDiscoveryModule } from "./identity-scan.js";
import { computeScore } from "./scoring.js";
import { normalizeFindingSchema } from "./findings.js";
import { detectVendorsFromModules } from "./vendor-signatures.js";
import { runVendorRelationshipModule } from "./vendor-relationship.js";
import {
  filterFreeScanFindings,
  FREE_SCAN_MODULE_STATES,
  resolveFreeScanPreviewState,
} from "./free-scan-evidence.js";

export const FREE_SCAN_SUBREQUEST_LIMIT = 72;
export const FREE_SCAN_DEADLINE_MS = 20_000;
export const FREE_SCAN_EXPOSED_FINDING_LIMIT = 2;

export const FREE_SCAN_DEEP_MODULES = Object.freeze([
  "dns_bruteforce",
  "subdomain_takeover",
  "asset_exposure",
  "admin_surface_detection",
  "cloud_storage_discovery",
  "whois_intelligence",
  "cve_intelligence",
  "known_exploited_vulnerabilities",
  "email_security_intelligence",
]);

const SEVERITY_WEIGHT = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
});

const LIMITATION_BY_DOMAIN = Object.freeze({
  email_protection:
    "DKIM checks use common selectors only. A non-match is not proof that DKIM is absent.",
  brand_protection:
    "Anonymous preview does not validate lookalike registrations. Unlock the watchlist after ownership verification.",
  attack_surface:
    "Certificate Transparency hostnames are observed here; takeover, CVE/KEV and asset fan-out checks unlock after verification.",
  certificates_trust:
    "Certificate observations are CT/TLS based. Chain trust, OCSP and revocation remain unknown.",
  cyber_essentials_readiness:
    "Cyber Essentials is indicative only and needs customer input. CyberMeters does not certify organisations.",
  website_security:
    "Passive external checks only; no active, authenticated or intrusive testing.",
  identity_exposure:
    "Provider and hostname signals only; reachability and leaked-credential monitoring are not part of this preview.",
  shadow_it_unmanaged_technology:
    "Public technology signals only. They are observed, not classified as authorised or unauthorised.",
});

const DEEP_UNLOCK_DOMAINS = new Set([
  "brand_protection",
  "attack_surface",
  "cyber_essentials_readiness",
  "identity_exposure",
  "shadow_it_unmanaged_technology",
]);

function derivedEvidenceState(result, dependencies, evidenceByModule) {
  if (!result || result.error || result.incomplete === true || result.skipped === true) {
    return FREE_SCAN_MODULE_STATES.INCOMPLETE;
  }
  const dependencyStates = dependencies.map(
    (name) => evidenceByModule.get(name) ?? FREE_SCAN_MODULE_STATES.INCOMPLETE,
  );
  if (dependencyStates.some((state) => ![
    FREE_SCAN_MODULE_STATES.COMPLETED,
    FREE_SCAN_MODULE_STATES.PARTIAL,
  ].includes(state))) {
    return FREE_SCAN_MODULE_STATES.INCOMPLETE;
  }
  return dependencyStates.includes(FREE_SCAN_MODULE_STATES.PARTIAL)
    ? FREE_SCAN_MODULE_STATES.PARTIAL
    : FREE_SCAN_MODULE_STATES.COMPLETED;
}

function uniqueStrings(values) {
  return [...new Set((values || [])
    .map((value) => String(value || "").trim())
    .filter(Boolean))];
}

function limitedFinding(finding, resolveAcademySlug) {
  return {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    description: finding.description,
    academy_slug: resolveAcademySlug?.(finding.id) ?? null,
  };
}

function observationSamples(domainKey, modules) {
  if (domainKey === "attack_surface") {
    return uniqueStrings(modules.subdomains?.items).map((name) => ({
      title: name,
      detail: "Observed in public Certificate Transparency data",
      kind: "observation",
    }));
  }
  if (domainKey === "certificates_trust") {
    const names = uniqueStrings(modules.subdomains?.items);
    return names.map((name) => ({
      title: name,
      detail: "Certificate Transparency hostname observed",
      kind: "observation",
    }));
  }
  if (domainKey === "identity_exposure") {
    const providers = (modules.identity_discovery?.providers || [])
      .map((entry) => entry?.provider);
    const portals = (modules.identity_discovery?.portals || [])
      .map((entry) => entry?.hostname || entry?.host || entry?.provider);
    return uniqueStrings([...providers, ...portals]).map((name) => ({
      title: name,
      detail: "Public identity-facing signal observed; reachability not asserted",
      kind: "observation",
    }));
  }
  if (domainKey === "shadow_it_unmanaged_technology") {
    const technologies = modules.technology_detection?.technologies || [];
    const thirdParties = (modules.third_party_discovery?.assets || [])
      .map((entry) => entry?.name);
    const vendors = (modules.vendor_relationships?.vendors || [])
      .map((entry) => entry?.name);
    const dependencies = (modules.saas_exposure?.dependencies || [])
      .map((entry) => entry?.name);
    return uniqueStrings([
      ...technologies,
      ...thirdParties,
      ...vendors,
      ...dependencies,
    ]).map((name) => ({
      title: name,
      detail: "Externally observed technology or service",
      kind: "observation",
    }));
  }
  return [];
}

function publicDomainProjection(domainState, findings, modules) {
  const matchingFindings = (domainState.finding_ids || [])
    .map((id) => findings.find((finding) => finding.id === id))
    .filter(Boolean);
  const observations = observationSamples(domainState.domain_key, modules);
  const findingSamples = matchingFindings.slice(0, 2).map((finding) => ({
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    detail: finding.description,
    kind: "finding",
  }));
  const samples = findingSamples.length > 0
    ? findingSamples
    : observations.slice(0, 2);
  const realTotal = matchingFindings.length > 0
    ? domainState.finding_count
    : observations.length;
  const deepUnlock = DEEP_UNLOCK_DOMAINS.has(domainState.domain_key);
  const hasIssue = domainState.state === "issue_detected";
  const state = deepUnlock && !hasIssue
    ? "customer_input_required"
    : domainState.state;

  return {
    domain_key: domainState.domain_key,
    display_name: domainState.display_name,
    state,
    display_state: deepUnlock && !hasIssue ? "input_required" : state,
    coverage: domainState.coverage,
    severity: domainState.highest_severity,
    headline_count: deepUnlock && realTotal === 0 ? null : realTotal,
    count_kind: matchingFindings.length > 0
      ? "finding"
      : observations.length > 0
        ? "observation"
        : deepUnlock
          ? "input_required"
          : "finding",
    samples,
    locked_count: Math.max(0, realTotal - samples.length),
    unlock_required: deepUnlock,
    summary: domainState.summary,
    limitation: LIMITATION_BY_DOMAIN[domainState.domain_key]
      ?? domainState.limitations?.[0]
      ?? "Evidence scope is limited to this bounded public preview.",
  };
}

export function buildFreeScanPreview({
  domain,
  scannedAt,
  freeScanEvidence,
  resolveAcademySlug = null,
  execution = null,
}) {
  const modules = { ...freeScanEvidence.modules };

  // Deliberately bounded opt-outs. Their explicit incomplete/skipped state is
  // part of the honesty contract: absence cannot become a healthy conclusion.
  for (const moduleName of FREE_SCAN_DEEP_MODULES) {
    modules[moduleName] = { skipped: true, incomplete: true, reason: "preview_scope" };
  }
  modules.subdomain_takeover = { skipped: true, incomplete: true, risks: [] };
  modules.asset_exposure = { skipped: true, incomplete: true, assets: [] };
  modules.dns_bruteforce = { skipped: true, incomplete: true, items: [] };
  modules.brand_monitoring = {
    skipped: true,
    incomplete: true,
    candidates_validated: false,
    findings: [],
  };

  modules.vendor_risk = detectVendorsFromModules(modules);
  modules.third_party_discovery = runThirdPartyDiscoveryModule(modules);
  modules.vendor_relationships = runVendorRelationshipModule(modules);
  modules.saas_exposure = runSaasExposureModule(modules);
  modules.certificate_intelligence = runCertificateIntelligenceModule(
    modules,
    domain,
    { monitoringStates: freeScanEvidence.monitoring_states, observedAt: scannedAt },
  );
  modules.identity_discovery = runIdentityDiscoveryModule(
    modules,
    domain,
    { observedAt: scannedAt },
  );

  const { findings } = computeScore(modules, domain);
  const evidenceByModule = new Map(
    freeScanEvidence.module_evidence.map((entry) => [entry.module, entry.state]),
  );
  const derivedEvidence = [
    {
      module: "certificate_intelligence",
      state: derivedEvidenceState(
        modules.certificate_intelligence,
        ["ssl", "subdomains"],
        evidenceByModule,
      ),
    },
    {
      module: "identity_discovery",
      state: derivedEvidenceState(
        modules.identity_discovery,
        ["dns", "headers", "subdomains", "technology_detection"],
        evidenceByModule,
      ),
    },
    { module: "vendor_risk", state: FREE_SCAN_MODULE_STATES.COMPLETED },
    { module: "third_party_discovery", state: FREE_SCAN_MODULE_STATES.COMPLETED },
    { module: "vendor_relationships", state: FREE_SCAN_MODULE_STATES.COMPLETED },
    { module: "saas_exposure", state: FREE_SCAN_MODULE_STATES.COMPLETED },
  ];
  const eligibleFindings = filterFreeScanFindings(
    findings,
    [...freeScanEvidence.module_evidence, ...derivedEvidence],
  );
  const normalised = eligibleFindings.map(normalizeFindingSchema);
  normalised.sort((a, b) =>
    (SEVERITY_WEIGHT[a.severity] ?? 5) - (SEVERITY_WEIGHT[b.severity] ?? 5)
  );

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of normalised) {
    if (Object.hasOwn(severityCounts, finding.severity)) {
      severityCounts[finding.severity] += 1;
    }
  }

  const report = {
    scan_id: null,
    created_at: scannedAt,
    completed_at: scannedAt,
    modules,
    findings: eligibleFindings,
    monitoring_states: freeScanEvidence.monitoring_states,
    scan_quality: {
      status: "partial",
      modules_skipped: [...FREE_SCAN_DEEP_MODULES, "brand_monitoring"],
      reason: "anonymous_preview_scope",
    },
  };
  const domainStates = resolveCyberMotDomainStates(report);
  const cyberMotDomains = domainStates.map((state) =>
    publicDomainProjection(state, normalised, modules)
  );
  const shownFindings = normalised
    .slice(0, FREE_SCAN_EXPOSED_FINDING_LIMIT)
    .map((finding) => limitedFinding(finding, resolveAcademySlug));
  const exposedFindingIds = new Set([
    ...shownFindings.map((finding) => finding.id),
    ...cyberMotDomains.flatMap((domainEntry) =>
      domainEntry.samples
        .filter((sample) => sample.kind === "finding")
        .map((sample) => sample.id)
    ),
  ]);
  const lockedCount = normalised.filter(
    (finding) => !exposedFindingIds.has(finding.id),
  ).length;
  const exposedFindingCount = normalised.length - lockedCount;
  const previewState = resolveFreeScanPreviewState({
    findingsCount: normalised.length,
    coverage: { complete: false },
    moduleEvidence: freeScanEvidence.module_evidence,
  });

  return {
    domain,
    score: null,
    risk_level: null,
    severity_counts: severityCounts,
    total_findings: normalised.length,
    shown_findings: shownFindings,
    preview_findings: shownFindings,
    exposed_finding_count: exposedFindingCount,
    locked_count: lockedCount,
    hidden_count: lockedCount,
    cyber_mot_domains: cyberMotDomains,
    modules_attempted: freeScanEvidence.modules_attempted,
    modules_scanned: freeScanEvidence.modules_scanned,
    module_evidence: freeScanEvidence.module_evidence,
    monitoring_states: freeScanEvidence.monitoring_states,
    evidence_coverage: freeScanEvidence.evidence_coverage,
    preview_state: previewState,
    limitations: {
      snapshot: "One bounded public snapshot; no monitoring history and no report is stored.",
      ownership: "Full results require a free account and canonical domain-ownership verification.",
      deep_checks: "Takeover, CVE/KEV, asset fan-out and active checks are not run anonymously.",
    },
    execution: execution ? {
      subrequest_limit: FREE_SCAN_SUBREQUEST_LIMIT,
      deadline_ms: FREE_SCAN_DEADLINE_MS,
      issued_subrequests: execution.issued ?? null,
      denied_subrequests: execution.denied ?? null,
    } : {
      subrequest_limit: FREE_SCAN_SUBREQUEST_LIMIT,
      deadline_ms: FREE_SCAN_DEADLINE_MS,
      issued_subrequests: null,
      denied_subrequests: null,
    },
    persistence: "none",
    scanned_at: scannedAt,
  };
}
