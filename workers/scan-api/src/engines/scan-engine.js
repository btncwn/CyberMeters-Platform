// ── Scan pipeline orchestrator ──
// The main scan engine (runs via ctx.waitUntil): sequences every scan/analysis/persistence
// module through all phases, computes the score + report, and persists results + fires alerts.
// Plus the scan-budget/quality helpers, CA-concentration, admin-surface event insertion, and
// vendor inventory/relationship persistence. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). buildCanonicalUrlProfile is a nested function inside runScanEngine.
import { customerSafeFailure } from "../lib/errors.js";
import { isWorkspaceDomainVerified } from "../lib/domain-verification.js";
import { brandWatchlistDnsObservations } from "./brand-dns-enrichment.js";
import { createAuditEvent, createNotificationsForDomain, scanCompletionAuditStatement } from "../lib/events.js";
import { json, sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { createId } from "../lib/util.js";
import { hashToken } from "../lib/auth-crypto.js";
import { redactedJson } from "../lib/redact.js";
import { processAlertsForWorkspace } from "./alerts.js";
import { createManagedAsmCasesForScan, verifyManagedAsmCasesForScan, withdrawSupersededAsmClaims } from "./asm-cases.js";
import { sendAssetChangeAlert } from "./asset-alert-delivery.js";
import { annotateExposureInfrastructure, deduplicateExposureAssets, runAdminSurfaceModule, runExposureModule, runRemediationModule, runRiskModule, unavailableRemovalObservations } from "./asset-intel.js";
import { buildDseFindings } from "./dse-findings.js";
import { upsertAssetInventory } from "./asset-inventory.js";
import { loadKnownAssetRecheckHosts, persistAttackSurfaceLifecycle } from "./attack-surface-lifecycle.js";
import { buildScanAssetEvidence, collectAssetHints } from "./asset-evidence.js";
import { deriveAttackSurfaceSignalCompleteness } from "./attack-surface-signal-completeness.js";
import { upsertBrandAssets, upsertIdentityAssets } from "./asset-persistence.js";
import { runTyposquatModule } from "./brand-typosquat.js";
import { loadBrandValidationState } from "./brand-validation-state.js";
import { computeAndPersistWorkspaceBrs, computeBusinessRiskScore, expandFindingIds, hstsMissingSeverity } from "./business-risk.js";
import { getCyberEssentialsSnapshot } from "./ce-readiness.js";
import { buildCaConcentrationAnalytics } from "./cert-analysis.js";
import { persistSecurityCheckDomainStates } from "./security-check-state-history.js";
import { persistDomainMaturity } from "./domain-maturity.js";
import { buildScanReportSnapshot } from "./report-snapshot.js";
import { insertCertificateEvents, upsertCertificateObservation } from "./cert-events.js";
import { runCertificateIntelligenceModule } from "./cert-intel.js";
import { CLOUD_STORAGE_MAX_PHYSICAL_ATTEMPTS, runCloudStorageModule } from "./cloud-storage-scan.js";
import { deriveSignalMonitoringStates } from "./signal-monitoring-state.js";
import { runSaasExposureModule, runThirdPartyDiscoveryModule } from "./discovery-scan.js";
import { buildDnsOperationalResilience } from "./dns-resilience.js";
import { dnsQuery } from "./dns.js";
import { runDnsModule } from "./dns-scan.js";
import { runDomainSecurityEnrichmentModule } from "./domain-enrichment.js";
import { buildEmailRemediationActions, buildEmailTransportDetails, isPublishableEmailEvidence, mtaStsAdmission } from "./email-analysis.js";
import { persistFindingsWithIdentity } from "./finding-identity.js";
import { runEmailIntelModule } from "./email-intel.js";
import { runMailTransportModule } from "./mail-transport.js";
import { runRemoteAdminExposureModule } from "./remote-admin-exposure.js";
import { runDaneModule } from "./dane.js";
import { applyDmarcbisEmailCompatibilityProjection, deadlineDeferredEmailModuleResult, runEmailModule } from "./email-scan.js";
import { establishDmarcPolicyBaseline } from "./email-protection-lifecycle.js";
import { recordDmarcPolicyLifecycle } from "./dmarcbis-lifecycle.js";
import {
  emitDmarcPolicyAlerts,
  verifyDmarcPolicyCasesForScan,
} from "./dmarcbis-managed-lifecycle.js";
import {
  attachDmarcbisExternalResult,
  budgetRefusedDmarcbisExternal,
  DMARCBIS_EXTERNAL_HOST_RESERVATION,
  runDmarcbisCore,
  runDmarcbisExternalRuaPhase,
  unavailableDmarcbisCore,
} from "./dmarcbis-production.js";
import { sealDmarcPolicyEvidence } from "./dmarcbis-contract.js";
import { isActionableFinding, normalizeFindingSchema } from "./findings.js";
import { runHeadersModule } from "./headers-scan.js";
import { applyScanComparability, reconcileLateFindings, runHistoricalModule } from "./historical-scan.js";
import { runIdentityDiscoveryModule } from "./identity-scan.js";
import { observeOidcMetadata, oidcMetadataFindings, OIDC_LIMITS } from "./identity-oidc-observation.js";
import { recordPostureEvents } from "./posture-events.js";
import { loadUnauthorisedSendingSourceAlerts, recordSpfRuaCorroboration } from "./spf-corroboration.js";
import { buildAssetTimelineTrustMetadata, loadTimelineComparisonContext } from "./timeline-trust.js";
import { runReservedScan } from "./reserved-scan.js";
import { buildExecutionDiagnostics, createModuleTelemetry, createOutboundAccounting, createScanDeadline, createSubOperationTelemetry, durableCoreModuleBudget, isPublishableModuleEvidence, isSubrequestBudgetExhaustedError, makeDnsCache, markDeadlineDeferred, MODULE_SUBREQUEST_COST, raceModuleDeadline, resolveScanCapacity, SCAN_DURABLE_PHASE5_MODULE_BUDGETS, SCAN_DURABLE_SURFACE_MODULE_BUDGETS, SCAN_MODULE_BUDGETS, skippedModuleResult, SUB_OPERATION_TELEMETRY_ROW_LIMIT } from "./scan-budget.js";
import { computeScore, isEmailApplicable } from "./scoring.js";
import { runSslModule } from "./ssl-scan.js";
import { collectLiveTls, attachLiveTlsToSsl, liveCertificateFindings } from "./network-probe.js";
import { collectReferencedHostnames, confirmReferencedHostnames, REFERENCED_HOSTNAME_LIMITS, referencedHostnamesNotExecuted, withConfirmedReferences } from "./referenced-hostnames.js";
import { DISCOVERY_DEPTH_LIMITS, discoveryDepthNotExecuted, loadDiscoveryRotationIndex, runDiscoveryDepth } from "./discovery-depth.js";
import { confirmListedHostnames, customerHostnamesNotExecuted, HOSTNAME_LIST_LIMITS, loadActiveHostnames } from "./discovery-hostname-list.js";
import { confirmPageReferences, PAGE_REFERENCE_LIMITS, pageReferencesNotExecuted, pendingPageReferences } from "./page-references.js";
import { resolveTlsRuntimeState, TLS_RUNTIME_STATES } from "./tls-evidence.js";
import { BRUTEFORCE_MAX_NAMES, SUBDOMAIN_DISCOVERY_SOURCE, filterWildcardBruteforceResults, isSensitiveSubdomain, prioritizeExposureTargets, runBruteforceModule, runSubdomainsModule } from "./subdomains-scan.js";
import { createDiscoveryQuestionBudget } from "./discovery-confirmation.js";
import { computeSupplyChainIntelligence, upsertSupplyChainScore } from "./supply-chain.js";
import { correlateShadowItInventory } from "./shadow-it-inventory.js";
import { correlateCertificateLifecycle } from "./certificate-lifecycle.js";
import { correlateIdentityExposure } from "./identity-lifecycle.js";
import { evaluateWebsiteSecurityForScan } from "./website-security-lifecycle.js";
import { PAGE_DISCOVERY_VERSION, runPageDiscoveryModule } from "./page-discovery.js";
import { persistWebsitePagesForScan } from "./website-pages.js";
import { signInPageFindings } from "./signin-page-findings.js";
import { readExposureForScan, readTlsAssessmentForScan } from "./exposure-jobs.js";
import { externalExposureModule, reconcileCurrentDnsHostCoverage } from "./exposure-findings.js";
import { tlsAssessmentFindings } from "./tls-findings.js";
import { projectTlsScanQualityForCustomer } from "./tls-quality.js";
import { homePageAvailabilityFindings } from "./website-availability.js";

import { SIGNED_IN_SCAN_VERSION, runSignedInScan, signedInSummary } from "./website-signed-in-scan.js";
import { loadSignedInScanProfile, recordSignInAttempt } from "./website-sign-in-profiles.js";

// Phase 7a cap for important-page discovery (durable scans only), and the
// headroom it must leave for post-terminal work (verification, lifecycle,
// snapshot, alerts, notifications) that shares the same invocation deadline.
const PAGE_DISCOVERY_BUDGET_MS = 25_000;
const PAGE_DISCOVERY_POST_TERMINAL_RESERVE_MS = 40_000;
// Phase 7b cap for signed-in scanning (sign-in + up to 10 signed-in pages).
const SIGNED_IN_SCAN_BUDGET_MS = 30_000;
import { evaluateCyberEssentialsLifecycle } from "./ce-lifecycle.js";
import { correlateRelatedChanges } from "./related-changes.js";
import {
  reconcilePhase5HistoricalScore,
  resolvePhase5CustomerAssessment,
} from "./phase5-evidence.js";
import { runTakeoverModule } from "./takeover-scan.js";
import { runTechModule } from "./tech-scan.js";
import { websiteScriptFindings } from "./website-script-observations.js";
import { runVendorRelationshipModule } from "./vendor-relationship.js";
import { recomputeVendorRiskScoresForDomain } from "./vendor-risk.js";
import { detectVendorsFromModules, dnsServiceRegistrationObservations } from "./vendor-signatures.js";
import { checkForFinding, checkPackSummary, moduleNotInCheckPack } from "./check-pack.js";
import { REGISTRATION_DATA_OPTIONAL, runWhoisModule, whoisReportFindings } from "./whois-scan.js";
import { collectDegradations, mayGradeDegraded } from "./scan-degradation-contract.js";
import { SECURITY_CHECK_DOMAINS } from "./security-check-domains.js";
import { beginAlertMonitoring, finishAlertMonitoring } from "./managed-alerts.js";

export function buildCertificateAuthorityConcentrationFromModule(certMod) {
  const issuer = certMod?.issuer ? String(certMod.issuer).trim() : "";
  if (!issuer) {
    return {
      dependency: "unknown",
      issuers: [],
      issuer_count: 0,
      ca_owner_count: 0,
      dominant_ca_owner: "unknown",
      dominant_ca_share: 0,
      concentration_level: "unknown",
      observations: ["No certificate issuer was available from certificate intelligence."],
      recommendations: [],
    };
  }
  return buildCaConcentrationAnalytics([issuer]);
}

export function computeScanBudget(bruteforceChecked) {
  const moduleEstimates = {
    dns:                        17,
    ssl:                        4,
    headers:                    2,
    email_security:             22,
    dmarc_core:                 18,
    dmarc_external_rua:         11,
    ct_discovery:               4,
    dns_bruteforce:             typeof bruteforceChecked === "number" ? bruteforceChecked : BRUTEFORCE_MAX_NAMES,
    asset_exposure:             0,
    admin_surface:              0,
    cve_kev:                    2,
    domain_security_enrichment: 0,
  };

  const total = Object.values(moduleEstimates).reduce((sum, n) => sum + n, 0);

  return {
    estimated_subrequests_total: total,
    modules: moduleEstimates,
    warnings: [],
  };
}

// `observedAt` is the scan's PERSISTED observation anchor (scans.created_at),
// threaded in by the caller. It is deliberately NOT generated here: a degradation
// is observed DURING A SCAN, so one scan has one anchor. Stamping `new Date()` at
// collection time recorded when this function happened to run — a different fact
// from the one the field claims — and made two invocations of one scan disagree
// about an unchanged observation. That is the same defect class as the gate's
// double read: one logical fact, read twice from a live source. The default
// remains a generated value ONLY for callers that have no scan context (fixtures
// and the 50 validator call sites); the engine always passes the persisted value.
// Modules whose evidence is optional: see buildScanQuality.
const OPTIONAL_EVIDENCE_MODULES = new Set(["whois_intelligence"]);

export function buildScanQuality(modules = {}, observedAt = undefined, capacity = null) {
  // F-026 capacity truth. 10,000 is the authenticated Workers Paid provider
  // default ceiling, NOT the application's effective admission/report limit and
  // NOT a claim that legacy mode installs a whole-scan physical counter. The
  // effective limit is derived independently from resolveScanCapacity and passed
  // in by the engine. Callers without scan context see the provider value only as
  // a ceiling, never as a fabricated effective limit.
  const PLATFORM_SUBREQUEST_CEILING = 10_000;
  // Never GUESS the legacy 50 here: an absent capacity means "no effective
  // budget resolved for this context", surfaced as null — not a hard-coded
  // constant that could drift from resolveScanCapacity.
  const effectiveLimit = Number.isFinite(capacity?.limit) ? capacity.limit : null;

  const budget = modules.scan_budget || computeScanBudget();
  const estimated = budget.estimated_subrequests_total ?? 0;
  const warnings = [];
  const modulesSkipped = [];
  // Optional evidence (registration data from the registry's RDAP service) is
  // reported by its own module and monitoring signal; it never decides whether
  // the scan's checks completed. Only a result that states it is optional and
  // belongs to an optional module qualifies, so a stored scan graded before
  // registration data became optional keeps its recorded meaning.
  const isOptionalEvidence = (name, value) =>
    OPTIONAL_EVIDENCE_MODULES.has(name) && value?.optional === true;

  // Sprint 10C: "subdomains" (discovery) is NOT a core module. DNS, SSL,
  // Headers, Email directly assess the domain's own config.
  const coreModules = ["dns", "ssl", "headers", "email_security", "dmarc_core"];
  const coreIncomplete = coreModules.filter((name) => modules[name]?.error);

  // Classify modules that actually timed out or were skipped via the CAA budget sentinel.
  // Exclude "subdomains" — a discovery timeout is not a core scan failure and
  // does not degrade scan_quality status through this path.
  for (const [name, value] of Object.entries(modules)) {
    if (name === "subdomains") continue;
    if (isOptionalEvidence(name, value)) continue;
    const error = String(value?.error || "").toLowerCase();
    if (error.includes("skipped_due_to_subrequest_budget") || error.includes("timed out")) {
      modulesSkipped.push(name);
    }
  }

  // A module may execute and still return incomplete evidence. Keep that separate
  // from a module that did not run; either condition makes the scan partial.
  // A stated limit (21 Oct 2026, Executive): technology detection that the site
  // itself withheld (a challenge or closed-store page: origin_access_restricted)
  // is not a gap in OUR assessment. The module record stays incomplete with its
  // reason; the scan lists it as a stated limit instead of turning partial.
  // Technology is not score-bearing; every other reason or module still counts.
  // Subdomain takeover (22 Oct 2026, Executive): a candidate whose provider
  // answered the confirming probe with its access-restricted page is reported
  // as a hedged finding (subdomain_takeover_unconfirmed, scoring.js), so the
  // coverage is stated, not missing. Only when that is the module's SOLE
  // reason and EVERY unconfirmed row is origin_access_restricted; truncation,
  // lookup failure or any fetch/refusal still makes the scan partial.
  const takeoverWithheldOnly = (value) => {
    const reasons = Array.isArray(value?.incomplete_reasons) ? value.incomplete_reasons : [value?.incomplete_reason];
    const rows = Array.isArray(value?.unconfirmed) ? value.unconfirmed : [];
    return !value?.error && reasons.length === 1 && reasons[0] === "host_probe_unconfirmed" &&
      rows.length > 0 && rows.every((row) => row?.reason === "origin_access_restricted" && row.host && row.cname);
  };
  // Remote-admin exposure (S3-0) is supplementary: its gaps (address cap,
  // deadline, lookup or probe unavailable) are stated, never a partial scan.
  // The module stays incomplete, so it can never close a case it did not
  // fully re-check (asm-cases.js moduleCompletionGate).
  const isStatedAccessLimit = (name, value) => value?.incomplete === true && (
    name === "remote_admin_exposure" || name === "dane" ||
    (name === "technology_detection" && value?.incomplete_reason === "origin_access_restricted") ||
    (name === "subdomain_takeover" && takeoverWithheldOnly(value)));
  const statedLimits = Object.entries(modules)
    .filter(([name, value]) => isStatedAccessLimit(name, value))
    .map(([name, value]) => ({ module: name,
      reason: name === "subdomain_takeover" ? "origin_access_restricted" : value.incomplete_reason || value.error || null }));
  const incompleteModules = Object.entries(modules)
    .filter(([name, value]) => value?.incomplete === true && !isOptionalEvidence(name, value))
    .filter(([name, value]) => !isStatedAccessLimit(name, value))
    .map(([name]) => name);
  // The evidence proposition, kept SEPARATE from the execution proposition.
  //
  // `modules_skipped` answers "did it run?". `modules_incomplete` answers whether
  // the evidence it observed supports a conclusion. Preserve both propositions.
  const modulesIncomplete = incompleteModules.map((name) => ({
    module: name,
    incomplete_reason: modules[name]?.incomplete_reason ?? null,
  }));
  for (const name of incompleteModules) {
    warnings.push(`Module incomplete: ${name}`);
  }

  // Reserved mode: a module explicitly skipped because exposure consumed its reserved
  // subrequest budget ({skipped:true, skip_reason:"subrequest_budget"}) is honest
  // absence, never a clean result. List it as skipped + warn; a skipped CORE module
  // (dns/ssl/headers/email) degrades the scan to "partial". Legacy never sets skipped.
  const budgetSkippedModules = Object.entries(modules)
    .filter(([name, value]) => value?.skipped === true && !isOptionalEvidence(name, value))
    .map(([name]) => name);
  for (const name of budgetSkippedModules) {
    if (!modulesSkipped.includes(name)) modulesSkipped.push(name);
    warnings.push(`Module skipped (subrequest budget): ${name}`);
  }
  const coreBudgetSkipped = budgetSkippedModules.filter((n) => coreModules.includes(n));

  // Only warn on real core module failures.
  for (const name of coreIncomplete) {
    warnings.push(`Core module incomplete: ${name}`);
  }

  // ── D1 Option D (FD-006 seq 50) ──────────────────────────────────────────
  // A declared, structured single-source loss with surviving publishable evidence
  // grades `degraded`. Every legacy `partial` driver DOMINATES: if any independent
  // incomplete cause exists, the scan stays `partial` regardless of how well-formed
  // the degradation is. A rejected (malformed/unknown) degradation record also
  // keeps the scan `partial` — the contract module fails closed and reports it.
  // LV-01: no special case for a missing anchor. Passing it through unconditionally
  // is what makes the contract's fail-closed admission reachable; the old branch
  // called collectDegradations WITHOUT an anchor precisely when none was read, which
  // is exactly when the wall-clock default used to manufacture `observed_at`.
  const { degradations, rejected: rejectedDegradations } = collectDegradations(modules, observedAt);
  // A REJECTED degradation record is malformed/unknown contract data, which
  // FD-006 places firmly on the `partial` side. It is counted as a partial DRIVER,
  // not merely as a warning: emitting only a warning would have let it fall
  // through to the legacy `warnings.length > 0 -> degraded` branch below and grade
  // degraded off unreadable data — the exact escape this contract forbids.
  const partialDrivers = coreIncomplete.length + incompleteModules.length
    + coreBudgetSkipped.length + rejectedDegradations;
  const governedDegraded = mayGradeDegraded({
    partialDrivers,
    degradations,
    rejected: rejectedDegradations,
  });
  for (const record of degradations) {
    // The existing customer warning surface carries the disclosure; no parallel
    // status system is introduced.
    warnings.push(`Evidence source degraded: ${record.dependency} (${record.module}) — ${record.reason}`);
  }
  if (rejectedDegradations > 0) {
    warnings.push("Degradation contract not recognised — treated as incomplete evidence");
  }

  const status = partialDrivers > 0
    ? "partial"
    : (governedDegraded
      ? "degraded"
      : (warnings.length > 0 || modulesSkipped.length > 0 ? "degraded" : "complete"));

  return projectTlsScanQualityForCustomer({
    status,
    warnings,
    // Structured carrier. Always an array so consumers never branch on undefined.
    degradations,
    modules_skipped: modulesSkipped,
    // Both arrays are explicit so readers can distinguish an unrun module from
    // attempted checks that returned insufficient evidence.
    modules_incomplete: modulesIncomplete,
    stated_limits: statedLimits,
    subrequest_budget: {
      estimated,
      // Effective per-scan limit (resolveScanCapacity); null when no scan
      // context supplied it. The remaining estimate is computed against THIS,
      // never the platform ceiling.
      effective_limit:    effectiveLimit,
      platform_ceiling:   PLATFORM_SUBREQUEST_CEILING,
      remaining_estimate: effectiveLimit === null
        ? null
        : Math.max(0, effectiveLimit - estimated),
    },
  }, modules.tls_assessment);
}

// ── Durable, tri-state scan finalization (Tier 1) ─────────────────────────────
// The latch has three states: "open" → "finalizing" → "finalized". It reaches
// "finalized" ONLY after BOTH the terminal R2 report and the D1 status are durably
// written. This is the key correctness property: the latch prevents DUPLICATE
// terminal writes without SUPPRESSING RECOVERY when a first attempt fails partway.
//
//   • Each write is individually guarded, so one failing cannot skip the other, and
//     finalizeScanResult NEVER throws — the caller inspects `finalized`.
//   • It is re-entrant: a later call retries only the side(s) not yet durable.
//   • Downgrade-safe: once a COMPLETED report is durable in R2, a later 'failed'
//     attempt can never overwrite it — it only (re)writes the D1 completed status.
//     (Closes both the orphan hazard AND the "downgrade a persisted scan" hazard.)
//
// R2 first (the stuck-scan reconciler trusts the report), then the D1 status the UI
// polls. If R2 is written but the D1 write keeps failing, the scan is left with a
// durable completed report the reconciler converges D1 from — never a silent orphan.
export function createFinalizeLatch() {
  return {
    state: "open", status: null, at: null,
    r2Written: false, d1Written: false,
    r2WriteUncertain: false, d1WriteUncertain: false,
    score: null, rating: null, quality: null,
    completion: null,
  };
}

export async function finalizeScanResult(latch, {
  scanId, report, score = null, rating = null, status, env, deadline = null,
  workspaceId = null,
}) {
  if (latch.state === "finalized") {
    return { finalized: true, wrote: false, reason: "already_finalized", status: latch.status };
  }

  // Downgrade guard: a 'failed' attempt AFTER a completed report is already durable
  // in R2 must not clobber it — keep the completed intent; only the D1 status is
  // (re)written, as completed.
  const guardCompleted = latch.status === "completed" && latch.r2Written && status !== "completed";

  latch.state = "finalizing";
  if (!guardCompleted) {
    latch.status = status;
    latch.score  = score;
    latch.rating = rating;
    // Persist the SAME coverage quality that is written into the R2 report, so D1 and
    // R2 can never present contradictory quality. NULL for a failed/qualityless report
    // (= 'unknown'); never inferred from status/score.
    latch.quality = report?.scan_quality?.status ?? null;
    if (status === "completed" && !latch.completion) {
      latch.completion = {
        workspace_id: workspaceId ?? null,
        scan_id: scanId,
        domain: report?.domain ?? null,
        domain_id: report?.domain_id ?? null,
        score: report?.cyber_metrics_score ?? score,
        risk_level: report?.risk_level ?? rating,
        scan_quality: report?.scan_quality?.status ?? null,
        monitoring_states: report?.monitoring_states ?? null,
      };
    }
  }
  const effStatus  = latch.status;
  const effScore   = latch.score;
  const effRating  = latch.rating;
  const effQuality = latch.quality;

  const errors = {};
  const runTerminalWrite = async (side, write) => {
    if (typeof deadline?.raceToTotal !== "function") {
      await write();
      return { settled: true, uncertain: false };
    }
    let started = false;
    const outcome = await deadline.raceToTotal(
      async () => {
        started = true;
        await write();
        return { settled: true, uncertain: false };
      },
      () => ({ settled: false, uncertain: started }),
    );
    if (!outcome.settled) {
      errors[side] = outcome.uncertain
        ? "scan_total_ceiling_exhausted_write_outcome_unknown"
        : "scan_total_ceiling_exhausted_before_write";
      if (outcome.uncertain) latch[`${side}WriteUncertain`] = true;
    }
    return outcome;
  };
  // Terminal R2 report — skipped when the completed report is already durable
  // (guardCompleted) so a failed report can never overwrite it.
  if (!latch.r2Written && !guardCompleted && !latch.r2WriteUncertain) {
    try {
      const write = await runTerminalWrite("r2", () =>
        env.cybermeters_reports.put(
          `reports/${scanId}.json`,
          JSON.stringify(report, null, 2),
          { httpMetadata: { contentType: "application/json" } },
        ),
      );
      if (write.settled) latch.r2Written = true;
    } catch (e) { errors.r2 = e?.message || String(e); }
  } else if (latch.r2WriteUncertain && !latch.r2Written) {
    errors.r2 = "terminal_r2_write_outcome_unknown";
  }
  // Terminal D1 status — a 'completed' status is written ONLY once its R2 report is
  // durable (never claim completed in D1 while R2 still holds the running placeholder;
  // the reconciler trusts R2). A 'failed' terminal is written regardless, so a scan
  // whose report could not be persisted still ends 'failed', never silently 'running'.
  if (!latch.d1Written && !latch.d1WriteUncertain
      && (latch.r2Written || effStatus === "failed")) {
    try {
      const write = await runTerminalWrite("d1", async () => {
        const statusStatement = env.cybermeters_db
          .prepare(`UPDATE scans SET status = ?, score = ?, rating = ?, scan_quality = ? WHERE id = ?`)
          .bind(effStatus, effScore, effRating, effQuality, scanId);
        if (effStatus === "completed") {
          await env.cybermeters_db.batch([
            statusStatement,
            scanCompletionAuditStatement(env, latch.completion),
          ]);
        } else {
          await statusStatement.run();
        }
      });
      if (write.settled) latch.d1Written = true;
    } catch (e) { errors.d1 = e?.message || String(e); }
  } else if (latch.d1WriteUncertain && !latch.d1Written) {
    errors.d1 = "terminal_d1_write_outcome_unknown";
  }

  if (latch.r2Written && latch.d1Written) {
    latch.state = "finalized";
    latch.at = new Date().toISOString();
    return { finalized: true, wrote: true, status: effStatus };
  }
  // Partial/total failure: stay "finalizing" so the failure path can still recover.
  return { finalized: false, wrote: latch.r2Written || latch.d1Written, errors, status: effStatus };
}

// Heartbeat: record how far a scan got and when it was last alive. Purely
// diagnostic — an orphaned (waitUntil-cancelled) scan's last heartbeat pinpoints
// the stage it died in. Fully non-fatal; never blocks or fails the scan.
export async function heartbeatScan(env, scanId, stage, completedModules = null) {
  try {
    await env.cybermeters_db
      .prepare(`UPDATE scans SET last_heartbeat_at = ?, current_stage = ?, completed_modules = ? WHERE id = ?`)
      .bind(new Date().toISOString(), stage, completedModules, scanId)
      .run();
  } catch { /* non-fatal — heartbeat is observability only */ }
}

// Persist collected per-module telemetry rows. Best-effort, per-row guarded so one
// bad row cannot abort the rest, and the whole call is non-fatal to the scan.
export async function persistModuleTelemetry(scanId, telemetry, env) {
  const rows = telemetry?.rows || [];
  for (const r of rows) {
    try {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO scan_module_telemetry
             (id, scan_id, module, started_at, completed_at, duration_ms, outbound_calls, outcome, timeout, error_class)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          createId("smt"), scanId, r.module,
          r.started_at ?? null, r.completed_at ?? null, r.duration_ms ?? null,
          r.outbound_calls ?? null, r.outcome ?? null, r.timeout ? 1 : 0, r.error_class ?? null
        )
        .run();
    } catch { /* non-fatal per row */ }
  }
}

// Track B: sub-operation rows land in scan_module_telemetry through ONE bounded
// D1 batch(), never a per-row await loop. This runs in the post-terminal chain
// ahead of snapshot Phase 8o, where the existing per-row module-telemetry inserts
// already cost ~2-3s live and the completed → report-ready gap is what the
// customer meets as "Report not ready" — up to 24 additional sequential writes
// there is a customer-facing regression, not an implementation detail. Batch
// failure is non-fatal and produces zero rows for this scan.
export async function persistSubOperationTelemetry(scanId, rows, env) {
  const boundedRows = (rows || []).slice(0, SUB_OPERATION_TELEMETRY_ROW_LIMIT);
  if (boundedRows.length === 0) return;
  try {
    const statements = boundedRows.map((r) =>
      env.cybermeters_db
        .prepare(
          `INSERT INTO scan_module_telemetry
             (id, scan_id, module, started_at, completed_at, duration_ms, outbound_calls, outcome, timeout, error_class)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          createId("smt"), scanId, r.module,
          r.started_at ?? null, r.completed_at ?? null, r.duration_ms ?? null,
          null, r.outcome ?? null, 0, null
        )
    );
    await env.cybermeters_db.batch(statements);
  } catch { /* non-fatal — telemetry cannot affect scan completion or report readiness */ }
}

// The network/enrichment modules we expect a telemetry row for. Backfilled at
// finalization from the modules object for any not captured by the live wrapper
// (reserved-mode results, deferred phases) so both scan modes get full coverage.
const TELEMETRY_TRACKED_MODULES = Object.freeze([
  "dns", "ssl", "headers", "email_security", "dmarc_core", "dmarc_external_rua",
  "subdomains", "technology_detection",
  "whois_intelligence", "dns_bruteforce", "subdomain_takeover", "asset_exposure",
  "email_security_intelligence",
  "cloud_storage_discovery",
]);

// Queue/Cron callers need a caller-visible total ceiling even when a provider
// promise is not abortable (notably D1). This guard does not pretend to cancel an
// already-issued provider operation. It freezes admission, records the in-flight
// outcome as unknown, and refuses every later D1/R2 launch. A running scan with an
// unknown initial write remains intentionally recoverable by the stuck-scan
// reconciler; the engine must not race it with a competing terminal body.
const TOTAL_CEILING_REFUSAL_CODE = "scan_total_ceiling_provider_refused";
const RAW_D1_STATEMENT = Symbol("raw_d1_statement");
// Customer email uses a provider-owned 10s fetch timeout. Stop admitting a new
// send with two seconds of room for response handling + its delivery-ledger
// update, so an accepted provider response cannot outrun the invocation result.
const EXTERNAL_SIDE_EFFECT_MIN_TOTAL_REMAINING_MS = 12_000;

export function createInvocationProviderGuard(sourceEnv, deadline) {
  let frozen = false;
  let nextOperationId = 0;
  let refusedOperations = 0;
  let lateCompletionsRefused = 0;
  let externalSideEffectsRefused = 0;
  const active = new Map();
  const unknown = new Map();

  const totalExceeded = () => frozen || deadline?.totalExceeded?.() === true;
  const externalSideEffectAdmissionClosed = () => totalExceeded()
    || (typeof deadline?.totalRemainingMs === "function"
      && deadline.totalRemainingMs() < EXTERNAL_SIDE_EFFECT_MIN_TOTAL_REMAINING_MS);
  const refusal = (label) => {
    refusedOperations += 1;
    const error = new Error(`Provider operation refused after scan total ceiling (${label})`);
    error.name = "ScanTotalCeilingRefusalError";
    error.code = TOTAL_CEILING_REFUSAL_CODE;
    return error;
  };
  const classifySql = (sql) => /^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP)\b/i.test(String(sql || ""))
    ? "write"
    : "read";
  const track = (label, mutation, thunk) => {
    if (totalExceeded()) throw refusal(label);
    const id = ++nextOperationId;
    let value;
    try {
      value = thunk();
    } catch (error) {
      throw error;
    }
    if (!value || typeof value.then !== "function") return value;
    active.set(id, { label, mutation: mutation === true });
    return Promise.resolve(value).then(
      (result) => {
        active.delete(id);
        // An uncancellable provider operation may finish after the caller has
        // returned. Its underlying outcome stays reconciliation-owned, but its
        // late value must never resume an abandoned continuation that can launch
        // a fresh D1/R2/email/webhook side effect.
        if (frozen && unknown.has(id)) {
          lateCompletionsRefused += 1;
          throw refusal(`${label}.late_completion`);
        }
        return result;
      },
      (error) => { active.delete(id); throw error; },
    );
  };

  const wrapStatement = (statement, sqlClass) => new Proxy({}, {
    get(_target, property) {
      if (property === RAW_D1_STATEMENT) return statement;
      if (property === "bind") {
        return (...args) => wrapStatement(statement.bind(...args), sqlClass);
      }
      if (["run", "all", "first", "raw"].includes(String(property))) {
        return (...args) => track(
          `d1.${sqlClass}.${String(property)}`,
          sqlClass === "write" && property === "run",
          () => statement[property](...args),
        );
      }
      const value = statement[property];
      return typeof value === "function" ? value.bind(statement) : value;
    },
  });

  const database = sourceEnv?.cybermeters_db;
  const guardedDatabase = database && new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (sql) => wrapStatement(target.prepare(sql), classifySql(sql));
      }
      if (property === "batch") {
        return (statements) => track("d1.batch", true, () =>
          target.batch((statements || []).map((statement) => statement?.[RAW_D1_STATEMENT] ?? statement)));
      }
      if (["exec", "dump"].includes(String(property))) {
        return (...args) => track(`d1.${String(property)}`, property === "exec", () => target[property](...args));
      }
      const value = target[property];
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  const bucket = sourceEnv?.cybermeters_reports;
  const guardedBucket = bucket && new Proxy(bucket, {
    get(target, property) {
      if (["put", "delete", "get", "head", "list"].includes(String(property))) {
        return (...args) => track(
          `r2.${String(property)}`,
          property === "put" || property === "delete",
          () => target[property](...args),
        );
      }
      const value = target[property];
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  const guardedEnv = new Proxy(sourceEnv || {}, {
    get(target, property) {
      if (property === "cybermeters_db") return guardedDatabase;
      if (property === "cybermeters_reports") return guardedBucket;
      // Every scan-owned customer email trunk reads this binding immediately
      // before its Resend fetch. Returning no credential is the existing
      // fail-closed `missing_api_key` path; it launches no external request and
      // leaves the idempotency row retryable rather than falsely marking sent.
      if (property === "RESEND_API_KEY" && externalSideEffectAdmissionClosed()) {
        externalSideEffectsRefused += 1;
        return undefined;
      }
      return target[property];
    },
  });

  const snapshot = () => ({
    frozen,
    active_count: active.size,
    in_flight_outcome_unknown_count: unknown.size,
    in_flight_mutation_outcome_unknown_count:
      [...unknown.values()].filter((operation) => operation.mutation).length,
    in_flight_outcome_unknown: [...unknown.values()].map((operation) => ({ ...operation })),
    refused_operations: refusedOperations,
    late_completions_refused: lateCompletionsRefused,
    external_side_effect_admission_closed: externalSideEffectAdmissionClosed(),
    external_side_effects_refused: externalSideEffectsRefused,
    external_side_effect_min_total_remaining_ms: EXTERNAL_SIDE_EFFECT_MIN_TOTAL_REMAINING_MS,
  });

  return {
    env: guardedEnv,
    freeze() {
      frozen = true;
      for (const [id, operation] of active) {
        if (!unknown.has(id)) unknown.set(id, { ...operation });
      }
      return snapshot();
    },
    snapshot,
  };
}

export function markPhysicalBudgetIncomplete(module, value, ctx) {
  const issued = ctx?.physicalAttemptsIssued?.() || 0;
  ctx?.markIncomplete?.("subrequest_budget_exhausted");
  const evidence = value && typeof value === "object" ? { ...value } : {};
  // The empty TLS shape is also used for deadline deferral. At this boundary
  // the cause is known to be capacity, even when no endpoint result survived.
  for (const field of ["tls_state_reason", "https_observation_reason"]) {
    if (evidence[field] === "deadline_deferred") evidence[field] = "subrequest_budget_exhausted";
  }
  if (evidence.http_redirect_chain?.observation_reason === "deadline_deferred") {
    evidence.http_redirect_chain = {
      ...evidence.http_redirect_chain,
      observation_reason: "subrequest_budget_exhausted",
    };
  }
  if (issued === 0) {
    return skippedModuleResult(module, {
      ...evidence,
      executed: false,
      incomplete: true,
      outcome: "not_run",
      reason: "subrequest_budget_exhausted",
      incomplete_reason: "subrequest_budget_exhausted",
      timeout_source: "subrequest_budget",
      physical_attempts_issued: 0,
    });
  }
  return {
    ...evidence,
    executed: true,
    incomplete: true,
    outcome: "subrequest_budget_exhausted",
    reason: "subrequest_budget_exhausted",
    incomplete_reason: "subrequest_budget_exhausted",
    timeout_source: "subrequest_budget",
    physical_attempts_issued: issued,
  };
}

export function cappedModuleCutoffProvenance(value, timedOut) {
  if (typeof value?.timeout_source === "string" && value.timeout_source) {
    return value.timeout_source;
  }
  return timedOut ? "module_race" : null;
}

export async function loadTlsAssessmentModuleForScan(env, { workspaceId, scanId, durableInvocation }) {
  if (!workspaceId || !durableInvocation) return null;
  try {
    // A rollout flag stops new TLS work, but a queued scan can still contain
    // previously planned controls. Preserve their partial result in the report.
    return await readTlsAssessmentForScan(env, { workspaceId, scanId });
  } catch {
    return { source: "tls_assessment", quality: "unavailable", coverage: "unknown", endpoints: [], gaps: ["result_unavailable"] };
  }
}

export async function runScanEngine(scanId, domainId, workspaceId, domain, env, opts = {}) {
  // Injectable clock (tests drive it deterministically); production uses Date.now.
  const now = typeof opts.now === "function" ? opts.now : Date.now;
  // Certificate evidence uses one scan instant; deadline/telemetry clocks keep advancing.
  const certificateNowMs = now();
  const startedAt = new Date(certificateNowMs).toISOString();
  // Resolve the invocation owner before creating its deadline. Durable Queue/Cron
  // invocations receive the bounded 120s total safety profile; waitUntil and
  // unknown callers retain the fail-closed 19s cancellation profile.
  const executionContext = opts.executionContext === "queue" || opts.executionContext === "cron" || opts.executionContext === "waituntil"
    ? opts.executionContext
    : null;
  const durableInvocation = executionContext === "queue" || executionContext === "cron";
  const deadline = createScanDeadline(env, now, { executionContext });
  // A durable invocation owns its ceiling from true engine entry, including the
  // initial D1 status/identity reads. Reserved legacy callers are armed later,
  // once their capacity mode is known, to preserve waitUntil/unknown behaviour.
  if (durableInvocation) deadline.arm();
  const providerGuard = durableInvocation
    ? createInvocationProviderGuard(env, deadline)
    : null;
  if (providerGuard) env = providerGuard.env;
  // Finalize-once latch shared by the success and failure paths.
  const latch = createFinalizeLatch();
  // Per-module telemetry collector (persisted at finalization; non-fatal).
  const telemetry = createModuleTelemetry(now);
  // Track B: per-sub-operation timing inside ssl/headers/subdomains (measurement
  // only). Engine-scoped so rows recorded before a module-race abandonment
  // survive, and in-flight sub-operations read honestly as `aborted` at snapshot.
  const subOpTelemetry = createSubOperationTelemetry(now);
  const outboundAccounting = createOutboundAccounting();
  // Assigned only by the dormant/reserved branch. Later enrichment phases still
  // run in this function, so their telemetry contexts compose with the SAME hard
  // physical counter instead of starting an unmetered second budget episode.
  let reservedPhysicalCounter = null;
  // Deterministic validation seam only. Production callers never pass this;
  // focused validators use the real nested runCappedModule wiring with a real
  // PhysicalSubrequestCounter already at/near exhaustion.
  if (opts.testOnlyPhysicalSubrequestCounter?.contextFor) {
    reservedPhysicalCounter = opts.testOnlyPhysicalSubrequestCounter;
  }
  const dnsCache = makeDnsCache();
  // Every discovery DNS question of this scan — wildcard check, fixed name
  // check, references, customer list, word list, variants, NSEC walk and page
  // references — spends one shared budget (discovery-confirmation.js).
  const discoveryBudget = createDiscoveryQuestionBudget();
  const createChildSignal = () => {
    const controller = new AbortController();
    if (deadline.signal?.aborted) controller.abort(deadline.signal.reason);
    else deadline.signal?.addEventListener("abort", () => controller.abort(deadline.signal.reason), { once: true });
    return controller;
  };
  const outboundContext = (module, signal = null) => {
    const ctx = outboundAccounting.contextFor(module);
    const physical = reservedPhysicalCounter?.contextFor?.(module, { signal }) || null;
    const recordTelemetryAttempt = ctx.recordAttempt;
    ctx.signal = signal || null;
    ctx.assertCanIssue = () => {
      if (deadline.exceeded()) {
        deadline.cancel?.("scan_deadline_exhausted");
        throw new DOMException("Scan deadline exhausted", "AbortError");
      }
      if (ctx.signal?.aborted) throw new DOMException("Module budget exhausted", "AbortError");
      physical?.assertCanIssue?.();
    };
    // Physical charge first. If candidate limit+1 is denied, no telemetry row may
    // claim an issued attempt and, more importantly, fetch() is never reached.
    ctx.recordAttempt = () => {
      physical?.recordAttempt?.();
      recordTelemetryAttempt();
    };
    ctx.physicalBudgetExhausted = () => physical?.budgetExhausted?.() === true;
    // Legacy mode has no admission counter, but records every attempted fetch.
    // Provider refusals must retain those observations instead of claiming zero.
    // An attempt does not assert that the provider completed the request.
    ctx.physicalAttemptsIssued = () => physical?.issuedDuringContext?.()
      ?? ctx.snapshot().outbound_attempts_observed;
    return ctx;
  };
  const moduleCapFor = (module) => durableInvocation
    ? (durableCoreModuleBudget(module)
      ?? SCAN_DURABLE_PHASE5_MODULE_BUDGETS[module]
      ?? SCAN_MODULE_BUDGETS[module]
      ?? deadline.remainingMs())
    : (SCAN_MODULE_BUDGETS[module] ?? deadline.remainingMs());
  const runCappedModule = async (module, {
    fallback,
    estimateMs = moduleCapFor(module),
    hardMs = moduleCapFor(module),
    onConsumerRelease = null,
    run,
  }) => {
    const deadlineFallback = (cause) => {
      const value = fallback();
      // Preserve the legacy waitUntil/unknown module bytes. Durable owners add
      // one canonical source so the module record agrees with abort + telemetry.
      // Attribute the fresh fallback in place: some canonical module contracts
      // carry non-enumerable evidence-status properties that object spreading
      // would silently erase and reinterpret as observed evidence.
      if (durableInvocation && value && typeof value === "object") {
        value.reason = cause.reason;
        value.timeout_source = cause.timeoutSource;
      }
      return value;
    };
    let allocatedMs = 0;
    let startedMs = null;
    let finishedMs = null;
    let ctx = null;
    if (!deadline.canRun(estimateMs)) {
      return {
        value: deadlineFallback({ reason: "scan_deadline_exhausted", timeoutSource: "launch_gate" }),
        ctx, allocatedMs, startedMs, durationMs: null, timedOut: true, timeoutSource: "launch_gate",
      };
    }
    const controller = createChildSignal();
    ctx = outboundContext(module, controller.signal);
    startedMs = now();
    let value = null, thrown = null;
    // This boundary owns the consumer release for every outcome — budget
    // exhaustion, normal completion and throw alike. Modules must not release
    // themselves, or two release paths would race to define the ordering.
    let released = false;
    const releaseConsumer = (cause) => {
      if (released) return;
      released = true;
      try { onConsumerRelease?.(cause); } catch { /* observational only */ }
    };
    try {
      value = await raceModuleDeadline(
        deadline,
        () => run({
          accounting: ctx,
          signal: controller.signal,
          remainingMs: () => Math.max(0, allocatedMs - Math.max(0, now() - startedMs)),
        }),
        () => {
          releaseConsumer("module_budget_exhausted");
          controller.abort("module_budget_exhausted");
          return deadlineFallback({ reason: "module_budget_exhausted", timeoutSource: "module_race" });
        },
        { hardMs, onStart: (capMs) => { allocatedMs = capMs; } },
      );
    } catch (err) {
      if (ctx?.physicalBudgetExhausted?.() || isSubrequestBudgetExhaustedError(err)) {
        value = markPhysicalBudgetIncomplete(module, fallback(), ctx);
      } else {
        thrown = err;
      }
    } finally {
      finishedMs = now();
    }
    if (!thrown && ctx?.physicalBudgetExhausted?.()
        && value?.incomplete_reason !== "subrequest_budget_exhausted") {
      value = markPhysicalBudgetIncomplete(module, value, ctx);
    }
    releaseConsumer(thrown ? "consumer_error" : "consumer_completed");
    const timedOut = value?.outcome === "deadline_exceeded";
    if (timedOut && !controller.signal.aborted) controller.abort("module_budget_exhausted");
    const timeoutSource = cappedModuleCutoffProvenance(value, timedOut);
    const durationMs = startedMs == null || finishedMs == null
      ? null
      : Math.max(0, finishedMs - startedMs);
    return { value, thrown, ctx, allocatedMs, startedMs, durationMs, timedOut, timeoutSource };
  };
  const settleOutbound = (ctx, module, settled) => {
    if (!ctx) return null;
    if (settled?.status === "fulfilled" && telemetry.outcomeOf(settled.value) === "ok") {
      ctx.markSettled();
    } else {
      const outcome = settled?.status === "fulfilled" ? telemetry.outcomeOf(settled.value) : "error";
      ctx.markIncomplete(outcome === "error" ? "module_error" : `module_${outcome}`);
    }
    const snap = outboundAccounting.snapshot(module);
    telemetry.setOutbound(module, snap);
    return snap;
  };
  const settleOutboundValue = (ctx, module, value) => {
    if (!ctx) return null;
    const outcome = telemetry.outcomeOf(value);
    if (outcome === "ok") ctx.markSettled();
    else ctx.markIncomplete(outcome === "error" ? "module_error" : `module_${outcome}`);
    return outboundAccounting.snapshot(module);
  };
  const abandonOutbound = (ctx, module, cutoff = "module_race") => {
    ctx?.markAbandoned?.(cutoff);
    return outboundAccounting.snapshot(module);
  };
  const invocationCeilingResult = (stage) => {
    const providerState = providerGuard?.freeze?.() || {
      in_flight_outcome_unknown_count: 0,
      in_flight_mutation_outcome_unknown_count: 0,
      in_flight_outcome_unknown: [],
      refused_operations: 0,
    };
    return {
      completed: false,
      ceiling_exceeded: true,
      outcome: "scan_total_ceiling_exhausted",
      stage,
      // An issued D1/R2 operation is not cancellable. `unknown` is deliberate:
      // the caller is bounded, later provider launches are frozen, and the
      // existing reconciler remains authoritative for any running scan.
      provider_outcome: providerState.in_flight_outcome_unknown_count > 0
        ? "in_flight_unknown"
        : "no_in_flight_provider_operation",
      reconciliation_required:
        stage !== "initial_d1_running"
        || providerState.in_flight_mutation_outcome_unknown_count > 0,
      provider_guard: providerState,
    };
  };
  const raceInvocationCeiling = async (stage, thunk, timers = {}) => {
    if (!durableInvocation) return thunk();
    // Deterministic focused-test seam. Production callers never provide it;
    // tests can fire one exact inner stage without shortening the durable
    // Queue/Cron profile or sleeping for its 120-second safety ceiling.
    const stageTimers = opts.testOnlyInvocationCeilingTimers?.[stage] || timers;
    return deadline.raceToTotal(
      thunk,
      () => invocationCeilingResult(stage),
      stageTimers,
    );
  };
  const runInitialCeilingAwareStep = async (stage, thunk) => {
    if (!durableInvocation) return { settled: true, value: await thunk() };
    const outcome = await raceInvocationCeiling(
      stage,
      async () => ({ settled: true, value: await thunk() }),
      opts.preTerminalCeilingTimers || {},
    );
    return outcome?.ceiling_exceeded
      ? { settled: false, ceiling: outcome }
      : outcome;
  };
  // PR-B1A: advisory scan origin (manual | scheduled) for diagnostics only —
  // after the scheduled Queue cutover both origins execute with
  // executionContext "queue", so origin needs its own additive field. Same
  // contract as executionContext: telemetry-only, never authoritative, fails
  // safe to null.
  const trigger = opts.trigger === "manual" || opts.trigger === "scheduled"
    ? opts.trigger
    : null;

  const runInvocationBody = async () => {
  try {
    // Mark scan as running in D1
    const runningWrite = await runInitialCeilingAwareStep("initial_d1_running", () =>
      env.cybermeters_db
        .prepare(`UPDATE scans SET status = 'running' WHERE id = ?`)
        .bind(scanId)
        .run());
    if (!runningWrite.settled) return runningWrite.ceiling;

    // Existing identities are rechecked through the same active DNS + SSRF-safe
    // HTTP paths. This is one bounded read.
    const identityRead = await runInitialCeilingAwareStep("initial_identity_read", () =>
      loadKnownAssetRecheckHosts(env, domainId, domain, { workspaceId }));
    if (!identityRead.settled) return identityRead.ceiling;
    const knownAssetHosts = identityRead.value;
    // What discovery read this scan that no module result keeps — the
    // customer's list and every configuration reference — for the per-asset
    // evidence written with the inventory (engines/asset-evidence.js).
    const evidenceHints = { listedHostnames: [], referencedCandidates: [] };

    // Capacity mode (default "legacy" — the legacy branch below is byte-for-byte the
    // prior behaviour). "reserved" runs the separated exposure-first flow.
    const capacity = resolveScanCapacity(env);
    // Reserved mode retains its independent hard-50 physical counter. Durable
    // Queue/Cron was armed at engine entry; only a legacy reserved caller still
    // needs arming here. Default waitUntil/unknown remains byte-compatible.
    const reservedMode = capacity.mode === "reserved";
    if (!durableInvocation && reservedMode) deadline.arm();

    // Private Cloudflare collector runs alongside the existing HTTP modules.
    // No binding means the historical capability set; a configured failed probe
    // remains explicit incomplete evidence and cannot make the report clean.
    const liveTlsPromise = env.NETWORK_PROBE?.fetch
      ? collectLiveTls(env, { domain, scanId, workspaceId, requestId: createId("probe"), signal: deadline.signal })
      : null;

    // Network module results — set by whichever path runs; both produce the same shape
    // so the modules object and everything downstream are identical.
    let dnsResult, sslResult, headersResult, emailResult, subdomainsResult,
        techResult, whoisResult, bruteforceResult, takeoverResult, assetExposureResult,
        dmarcCoreResult;
    let criticalPrefixResult = null;
    let reservedBudget = null;

    if (reservedMode) {
      // ── Reserved path (isolated in reserved-scan.js): root/www then the
      // guaranteed DMARC core are reserved before customer-critical ASSET
      // EXPOSURE. Remaining modules run only if budget permits and otherwise
      // skip honestly. admin_surface is derived downstream (zero network). ──
      const reserved = await runReservedScan(domain, {
        capacity,
        dnsCache,
        knownAssetHosts,
        signal: deadline.signal,
        moduleBudgets: {
          ssl: SCAN_MODULE_BUDGETS.ssl,
          subdomains: SCAN_MODULE_BUDGETS.subdomains,
        },
        now,
      });
      const m = reserved.modules;
      dnsResult = m.dns; sslResult = m.ssl; headersResult = m.headers; emailResult = m.email_security;
      dmarcCoreResult = m.dmarc_core;
      subdomainsResult = m.subdomains; techResult = m.technology_detection; whoisResult = m.whois_intelligence;
      bruteforceResult = m.dns_bruteforce; takeoverResult = m.subdomain_takeover;
      assetExposureResult = m.asset_exposure; criticalPrefixResult = m.critical_prefix_discovery;
      reservedBudget = reserved.budget;
      reservedPhysicalCounter = reserved.physicalCounter;
    } else {
      // ── Queue-era default path: 9 core modules in parallel under measured
      // per-module caps, then takeover and asset exposure over the merged
      // (name-check + referenced-host) subdomain list. ──
      const subdomainsFallback = () => markDeadlineDeferred({
        count: 0, items: [], sensitive: [], source: SUBDOMAIN_DISCOVERY_SOURCE,
        wildcard_dns: false, wildcard_dns_addresses: [], wildcard_dns_ipv6_addresses: [], wildcard_test_host: null, wildcard_warning: null,
      });
      const [dnsSettled, sslSettled, headersSettled, emailSettled, dmarcSettled, subdomainsSettled, techSettled, whoisSettled, bruteforceSettled] =
        await Promise.allSettled([
          // The DNS deadline fallback states its non-observation EXPLICITLY rather
          // than omitting the resolution contract. Omission was read downstream as
          // authoritative absence and produced a CRITICAL "Domain Does Not Resolve"
          // (-30) for a module that performed no lookup at all.
          //
          // The tri-state is load-bearing and `false` is NOT available here:
          //   true  — resolvers queried, at least one authoritative NOERROR/NXDOMAIN
          //   false — resolvers queried, no authoritative answer (a MEASURED outage,
          //           produced by dns-scan.js when requests actually ran)
          //   null  — the probe never executed; nothing was measured
          // Using `false` on this path would collapse "not measured" into "measured
          // unavailable" and recreate the same evidence-integrity defect under a
          // different value. Mirrors the adjacent SSL deadline fallback.
          runCappedModule("dns",                  { fallback: () => markDeadlineDeferred({ resolves: null, resolves_any: null, resolution_assessed: null, resolution_observation_state: "not_assessed", incomplete_reason: "dns_not_executed", has_ipv6: null, has_mx: null, nameservers: [], a_records: [], aaaa_records: [], mx_records: [], source: "dns" }), run: ({ accounting, signal }) => runDnsModule(domain, { accounting, signal, cache: dnsCache }) }),
          // https_available stays NULL on a deadline-deferred SSL module: the probe
          // never ran, so it observed nothing. It previously fell back to `false`,
          // which scoring.js reads as positive evidence of absence and turns into the
          // CRITICAL "HTTPS Not Available" finding — a second, independent path to the
          // same false claim the classifier fix closes. Not assessed is not a verdict.
          runCappedModule("ssl",                  { fallback: () => markDeadlineDeferred({ http_redirect_chain: { original_url: null, final_url: null, redirect_count: 0, http_redirect_validated: false, observation_state: "not_assessed", observation_reason: "deadline_deferred", observation_completeness: "not_assessed", hop_observations: [] }, tls_state: TLS_RUNTIME_STATES.UNAVAILABLE, tls_state_reason: "deadline_deferred", https_available: null, https_probe_executed: false, https_observation_state: "not_assessed", https_observation_reason: "deadline_deferred", https_origin_status: null, https_endpoint_observations: [], incomplete: true, incomplete_reason: "https_probe_not_executed", source: "tls_probe" }), run: ({ accounting, signal }) => runSslModule(domain, { dnsResolver: dnsQuery, dnsCache, accounting, signal, subOps: subOpTelemetry, now: () => certificateNowMs }) }),
          runCappedModule("headers",              { fallback: () => markDeadlineDeferred({ headers: {}, source: "http_headers" }), run: ({ accounting, signal, remainingMs }) => runHeadersModule(domain, { dnsResolver: dnsQuery, dnsCache, accounting, signal, remainingMs: durableInvocation ? remainingMs : null, subOps: subOpTelemetry }) }),
          // The email deadline fallback is the CANONICAL unassessed email result
          // owned by email-scan.js. The previous bare shape ({spf:{},dmarc:{},
          // dkim:{}}) did not match the completed contract: scoring fabricated a
          // Missing-SPF finding from the absent A1 evidence status, and the
          // remediation builder crashed the WHOLE scan dereferencing the absent
          // spf_detail (`reading 'raw'`) — every sibling module's completed
          // evidence was then discarded by the failed terminal.
          runCappedModule("email_security",       { fallback: deadlineDeferredEmailModuleResult, run: ({ accounting, signal }) => runEmailModule(domain, { accounting, signal, cache: dnsCache, dmarcOwnedByCore: true }) }),
          runCappedModule("dmarc_core",           {
            fallback: () => unavailableDmarcbisCore(domain, "core_launch_refused"),
            run: ({ accounting, signal }) => runDmarcbisCore(domain, {
              accounting,
              signal,
              cache: dnsCache,
              now,
            }),
          }),
          runCappedModule("subdomains",           { fallback: subdomainsFallback, run: ({ accounting, signal }) => runSubdomainsModule(domain, { accounting, signal, cache: dnsCache, subOps: subOpTelemetry, budget: discoveryBudget }) }),
          runCappedModule("technology_detection", { fallback: () => markDeadlineDeferred({ technologies: [], info_findings: [], source: "technology_detection" }), run: ({ accounting, signal, remainingMs }) => runTechModule(domain, { dnsResolver: dnsQuery, dnsCache, accounting, signal, remainingMs: durableInvocation ? remainingMs : null }) }),
          runCappedModule("whois_intelligence",   { fallback: () => markDeadlineDeferred({ ...REGISTRATION_DATA_OPTIONAL }), run: ({ accounting, signal }) => runWhoisModule(domain, { accounting, signal }) }),
          runCappedModule("dns_bruteforce",       { fallback: () => markDeadlineDeferred({ checked: 0, found: 0, items: [], source: "dns_bruteforce" }), run: ({ accounting, signal }) => runBruteforceModule(domain, { accounting, signal, cache: dnsCache, budget: discoveryBudget }) }),
        ]);
      const settledValue = (s) => s.status === "fulfilled" ? s.value : null;
      for (const [module, settled] of [
        ["dns", dnsSettled],
        ["ssl", sslSettled],
        ["headers", headersSettled],
        ["email_security", emailSettled],
        ["dmarc_core", dmarcSettled],
        ["subdomains", subdomainsSettled],
        ["technology_detection", techSettled],
        ["whois_intelligence", whoisSettled],
        ["dns_bruteforce", bruteforceSettled],
      ]) {
        const wrapped = settledValue(settled);
        const snap = wrapped?.thrown
          ? (() => { wrapped.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot(module); })()
          : wrapped?.timedOut
          ? abandonOutbound(wrapped.ctx, module, wrapped.timeoutSource)
          : settleOutboundValue(wrapped?.ctx, module, wrapped?.value);
        telemetry.setOutbound(module, snap);
        let row = telemetry.rows.find((r) => r.module === module);
        if (!row && wrapped) {
          telemetry.record(module, {
            outcome: wrapped.thrown ? "error" : telemetry.outcomeOf(wrapped.value),
            timeout: wrapped.timedOut || /timed out|timeout|abort/i.test(String(wrapped.thrown?.message || "")),
            error_class: wrapped.thrown?.name || null,
            duration_ms: wrapped.durationMs,
            outbound: snap,
            outbound_calls: snap?.outbound_measurement_complete ? snap.outbound_attempts_observed : null,
          });
          row = telemetry.rows.find((r) => r.module === module);
        }
        if (row && wrapped) {
          row.allocated_ms = wrapped.startedMs != null ? wrapped.allocatedMs : 0;
          row.timeout_source = wrapped.timeoutSource;
          row.timeout = row.timeout || wrapped.timedOut;
        }
      }

      dnsResult = dnsSettled.status === "fulfilled" && !dnsSettled.value.thrown ? dnsSettled.value.value : { error: customerSafeFailure("scan/dns", dnsSettled.value?.thrown || dnsSettled.reason, "DNS module failed") };
      sslResult = sslSettled.status === "fulfilled" && !sslSettled.value.thrown ? sslSettled.value.value : { error: customerSafeFailure("scan/ssl", sslSettled.value?.thrown || sslSettled.reason, "SSL module failed") };
      headersResult = headersSettled.status === "fulfilled" && !headersSettled.value.thrown ? headersSettled.value.value : { error: customerSafeFailure("scan/headers", headersSettled.value?.thrown || headersSettled.reason, "Headers module failed") };
      emailResult = emailSettled.status === "fulfilled" && !emailSettled.value.thrown ? emailSettled.value.value : { error: customerSafeFailure("scan/email", emailSettled.value?.thrown || emailSettled.reason, "Email module failed") };
      dmarcCoreResult = dmarcSettled.status === "fulfilled" && !dmarcSettled.value.thrown
        ? dmarcSettled.value.value
        : unavailableDmarcbisCore(
          domain,
          dmarcSettled.value?.thrown ? "core_provider_error" : "core_module_failed",
        );
      subdomainsResult = subdomainsSettled.status === "fulfilled" && !subdomainsSettled.value.thrown
        ? subdomainsSettled.value.value
        : { count: 0, items: [], sensitive: [], source: SUBDOMAIN_DISCOVERY_SOURCE,
            wildcard_dns: false, wildcard_dns_addresses: [], wildcard_dns_ipv6_addresses: [], wildcard_test_host: null, wildcard_warning: null,
            error: customerSafeFailure("scan/subdomains", subdomainsSettled.value?.thrown || subdomainsSettled.reason, "Subdomain module failed") };
      techResult = techSettled.status === "fulfilled" && !techSettled.value.thrown ? techSettled.value.value : { error: customerSafeFailure("scan/technology", techSettled.value?.thrown || techSettled.reason, "Technology module failed") };
      whoisResult = whoisSettled.status === "fulfilled" && !whoisSettled.value.thrown ? whoisSettled.value.value : { ...REGISTRATION_DATA_OPTIONAL, error: customerSafeFailure("scan/whois", whoisSettled.value?.thrown || whoisSettled.reason, "WHOIS module failed") };

      const rawBruteforceResult = bruteforceSettled.status === "fulfilled" && !bruteforceSettled.value.thrown
        ? bruteforceSettled.value.value
        : { checked: 0, found: 0, items: [], source: "dns_bruteforce",
            error: customerSafeFailure("scan/dns-bruteforce", bruteforceSettled.value?.thrown || bruteforceSettled.reason, "Brute-force module failed") };
      bruteforceResult = filterWildcardBruteforceResults(rawBruteforceResult, subdomainsResult.wildcard_dns_addresses, subdomainsResult.wildcard_dns_ipv6_addresses);
      // Page references are read late in the scan; hold their share of the
      // discovery budget so earlier guesses cannot spend it.
      discoveryBudget.reserve("page_references", 2 * PAGE_REFERENCE_LIMITS.maxChecks);

      const bruteNewItems = (bruteforceResult.items || [])
        .filter((item) => item.wildcard_match !== true)
        .map((i) => i.hostname)
        .filter(Boolean);
      // First-party references the word list cannot guess (SRV targets, hosts
      // the home page links to) are configuration references like the others
      // below: each joins discovery only when DNS answers for it.
      const mergedSubdomainItems = bruteNewItems;
      // Names the customer's own configuration points at (live certificate,
      // website headers and redirects, MX/NS/SPF/DMARC records) join discovery
      // once DNS answers for them. Only durable invocations run the lookups; the
      // compact waitUntil path records that the step did not run.
      let referencedResult;
      if (durableInvocation) {
        const liveTlsEarly = liveTlsPromise ? await liveTlsPromise : null;
        const referencedEvidence = collectReferencedHostnames(domain, {
          ssl: liveTlsEarly ? attachLiveTlsToSsl(sslResult, liveTlsEarly) : sslResult,
          headers: headersResult,
          dns: dnsResult,
          spfRecord: emailResult?.spf?.record ?? null,
          dmarcRecord: applyDmarcbisEmailCompatibilityProjection(domain, { ...(emailResult || {}) }, dmarcCoreResult)?.dmarc?.record ?? null,
          bimiRecord: emailResult?._bimi_record ?? null,
          srvTargets: bruteforceResult.srv_items,
          linkedHostnames: techResult?.linked_hostnames,
        });
        evidenceHints.referencedCandidates = referencedEvidence.candidates;
        let referencedThrown = null;
        const referencedRun = await runCappedModule("referenced_hostnames", {
          estimateMs: REFERENCED_HOSTNAME_LIMITS.budgetMs,
          hardMs: REFERENCED_HOSTNAME_LIMITS.budgetMs,
          fallback: () => markDeadlineDeferred(referencedHostnamesNotExecuted("deadline_deferred", referencedEvidence)),
          run: ({ accounting, signal }) => confirmReferencedHostnames(domain, referencedEvidence, {
            exclude: mergedSubdomainItems,
            wildcardAddresses: subdomainsResult.wildcard_dns_addresses,
            wildcardIpv6Addresses: subdomainsResult.wildcard_dns_ipv6_addresses,
            budget: discoveryBudget,
            accounting,
            signal,
            cache: dnsCache,
          }),
        });
        referencedThrown = referencedRun.thrown;
        referencedResult = referencedThrown
          ? referencedHostnamesNotExecuted("lookup_step_failed", referencedEvidence)
          : referencedRun.value;
        const referencedTimedOut = referencedResult?.outcome === "deadline_exceeded";
        const referencedOutbound = referencedThrown
          ? (() => { referencedRun.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("referenced_hostnames"); })()
          : referencedTimedOut
          ? abandonOutbound(referencedRun.ctx, "referenced_hostnames", referencedRun.startedMs != null ? "module_race" : "launch_gate")
          : settleOutboundValue(referencedRun.ctx, "referenced_hostnames", referencedResult);
        telemetry.record("referenced_hostnames", {
          outcome:        telemetry.outcomeOf(referencedResult),
          timeout:        referencedTimedOut,
          error_class:    referencedThrown?.name || null,
          duration_ms:    referencedRun.durationMs,
          allocated_ms:   referencedRun.startedMs != null ? referencedRun.allocatedMs : 0,
          timeout_source: referencedTimedOut ? (referencedRun.startedMs != null ? "module_race" : "launch_gate") : null,
          outbound:       referencedOutbound,
          outbound_calls: referencedOutbound?.outbound_measurement_complete ? referencedOutbound.outbound_attempts_observed : null,
        });
      } else {
        referencedResult = referencedHostnamesNotExecuted("invocation_not_durable");
      }
      const referencedHosts = withConfirmedReferences(mergedSubdomainItems, referencedResult);

      // Hostnames the customer listed for this verified domain (migration 117):
      // each is asked about, and joins discovery only when DNS answers for it.
      let customerResult;
      if (!durableInvocation) {
        customerResult = customerHostnamesNotExecuted("invocation_not_durable");
      } else {
        const listedHostnames = await loadActiveHostnames(env, { workspaceId, domainId, domain });
        if (Array.isArray(listedHostnames)) evidenceHints.listedHostnames = listedHostnames;
        if (listedHostnames === null) {
          customerResult = customerHostnamesNotExecuted("list_unavailable");
        } else if (listedHostnames.length === 0) {
          customerResult = customerHostnamesNotExecuted("no_list");
        } else {
          let customerThrown = null;
          const customerRun = await runCappedModule("customer_hostnames", {
            estimateMs: HOSTNAME_LIST_LIMITS.budgetMs,
            hardMs: HOSTNAME_LIST_LIMITS.budgetMs,
            fallback: () => markDeadlineDeferred(customerHostnamesNotExecuted("deadline_deferred", listedHostnames.length)),
            // Listed names this scan already re-checks (known inventory) are
            // not asked twice: the inventory re-check covers them.
            run: ({ accounting, signal }) => confirmListedHostnames(domain, listedHostnames, {
              exclude: [...referencedHosts, ...knownAssetHosts],
              wildcardAddresses: subdomainsResult.wildcard_dns_addresses,
              wildcardIpv6Addresses: subdomainsResult.wildcard_dns_ipv6_addresses,
              budget: discoveryBudget,
              accounting,
              signal,
              cache: dnsCache,
            }),
          });
          customerThrown = customerRun.thrown;
          customerResult = customerThrown
            ? customerHostnamesNotExecuted("lookup_step_failed", listedHostnames.length)
            : customerRun.value;
          const customerTimedOut = customerResult?.outcome === "deadline_exceeded";
          const customerOutbound = customerThrown
            ? (() => { customerRun.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("customer_hostnames"); })()
            : customerTimedOut
            ? abandonOutbound(customerRun.ctx, "customer_hostnames", customerRun.startedMs != null ? "module_race" : "launch_gate")
            : settleOutboundValue(customerRun.ctx, "customer_hostnames", customerResult);
          telemetry.record("customer_hostnames", {
            outcome:        telemetry.outcomeOf(customerResult),
            timeout:        customerTimedOut,
            error_class:    customerThrown?.name || null,
            duration_ms:    customerRun.durationMs,
            allocated_ms:   customerRun.startedMs != null ? customerRun.allocatedMs : 0,
            timeout_source: customerTimedOut ? (customerRun.startedMs != null ? "module_race" : "launch_gate") : null,
            outbound:       customerOutbound,
            outbound_calls: customerOutbound?.outbound_measurement_complete ? customerOutbound.outbound_attempts_observed : null,
          });
        }
      }
      const listedHosts = withConfirmedReferences(referencedHosts, customerResult);

      // Deeper DNS discovery: a rotating slice of the authored word list, name
      // variants of hosts already found and a bounded NSEC walk. Guesses need
      // the wildcard answer to be told apart from real names, so the step does
      // not run when the wildcard check did not finish.
      let depthResult;
      if (!durableInvocation) {
        depthResult = discoveryDepthNotExecuted("invocation_not_durable");
      } else if (subdomainsResult.incomplete === true || subdomainsResult.error) {
        depthResult = discoveryDepthNotExecuted("wildcard_check_incomplete");
      } else {
        const rotation = await loadDiscoveryRotationIndex(env, { domainId, workspaceId });
        let depthThrown = null;
        const depthRun = await runCappedModule("discovery_depth", {
          estimateMs: DISCOVERY_DEPTH_LIMITS.budgetMs,
          hardMs: DISCOVERY_DEPTH_LIMITS.budgetMs,
          fallback: () => markDeadlineDeferred(discoveryDepthNotExecuted("deadline_deferred")),
          run: ({ accounting, signal }) => runDiscoveryDepth(domain, {
            knownHosts: [...listedHosts, ...knownAssetHosts],
            discoveredHosts: listedHosts,
            wildcardAddresses: subdomainsResult.wildcard_dns_addresses,
            wildcardIpv6Addresses: subdomainsResult.wildcard_dns_ipv6_addresses,
            rotationIndex: rotation.index,
            budget: discoveryBudget,
            accounting,
            signal,
            cache: dnsCache,
          }),
        });
        depthThrown = depthRun.thrown;
        depthResult = depthThrown ? discoveryDepthNotExecuted("lookup_step_failed") : depthRun.value;
        if (depthResult?.wordlist) depthResult.wordlist.rotation_source = rotation.source;
        const depthTimedOut = depthResult?.outcome === "deadline_exceeded";
        const depthOutbound = depthThrown
          ? (() => { depthRun.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("discovery_depth"); })()
          : depthTimedOut
          ? abandonOutbound(depthRun.ctx, "discovery_depth", depthRun.startedMs != null ? "module_race" : "launch_gate")
          : settleOutboundValue(depthRun.ctx, "discovery_depth", depthResult);
        telemetry.record("discovery_depth", {
          outcome:        telemetry.outcomeOf(depthResult),
          timeout:        depthTimedOut,
          error_class:    depthThrown?.name || null,
          duration_ms:    depthRun.durationMs,
          allocated_ms:   depthRun.startedMs != null ? depthRun.allocatedMs : 0,
          timeout_source: depthTimedOut ? (depthRun.startedMs != null ? "module_race" : "launch_gate") : null,
          outbound:       depthOutbound,
          outbound_calls: depthOutbound?.outbound_measurement_complete ? depthOutbound.outbound_attempts_observed : null,
        });
      }
      const discoveryHosts = withConfirmedReferences(listedHosts, depthResult);

      // The subdomains module carries the discovered set, so scoring and
      // certificate intelligence see every name found in this scan.
      const discoveredItems = [...new Set(discoveryHosts.map((h) => String(h).toLowerCase()))].sort();
      subdomainsResult = {
        ...subdomainsResult,
        count: discoveredItems.length,
        items: discoveredItems,
        sensitive: discoveredItems.filter((host) => isSensitiveSubdomain(host, domain)),
        referenced_hostnames: referencedResult,
        customer_hostnames: customerResult,
        discovery_depth: depthResult,
      };
      // Exposure probes the first 50 targets: high-value names (admin, VPN,
      // login, dev…) go first so a discovered admin host is never cut off by
      // ordinary names, then known assets for lifecycle re-checks.
      const exposureTargets = prioritizeExposureTargets(domain, {
        knownHosts: knownAssetHosts,
        discoveredHosts: discoveryHosts,
      });

      // Takeover: canRun() gates the launch; raceModuleDeadline BOUNDS the run so an
      // overrun cannot cross the ~30s cliff. On the bound it defers honestly.
      // PR-A1: launched/allocated/started are telemetry-only observations.
      let takeoverAllocatedMs = null, takeoverStartedMs = null, takeoverDurationMs = null;
      let takeoverOutbound = null;
      let takeoverThrown = null;
      try {
        const takeoverRun = await runCappedModule("subdomain_takeover", {
          fallback: () => markDeadlineDeferred({ checked: 0, potential_risks: 0, risks: [], cname_observations: [], source: "subdomain_cname_fingerprint" }),
          // Names already in the inventory are checked too, after this scan's
          // discoveries: a forgotten host whose alias outlived its service is
          // the classic takeover, and it may no longer be rediscovered.
          run: ({ accounting, signal }) => runTakeoverModule(domain, [...discoveryHosts, ...knownAssetHosts], { accounting, signal, cache: dnsCache }),
        });
        takeoverThrown = takeoverRun.thrown;
        takeoverResult = takeoverThrown
          ? { checked: 0, potential_risks: 0, risks: [], cname_observations: [], source: "subdomain_cname_fingerprint", incomplete: true, incomplete_reason: "takeover_probe_failed", error: customerSafeFailure("scan/takeover", takeoverThrown, "Takeover module failed") }
          : takeoverRun.value;
        takeoverOutbound = takeoverRun.ctx;
        takeoverStartedMs = takeoverRun.startedMs;
        takeoverDurationMs = takeoverRun.durationMs;
        takeoverAllocatedMs = takeoverRun.allocatedMs;
      } catch (err) {
        takeoverThrown = err;
        takeoverResult = { checked: 0, potential_risks: 0, risks: [], cname_observations: [], source: "subdomain_cname_fingerprint", incomplete: true, incomplete_reason: "takeover_probe_failed", error: customerSafeFailure("scan/takeover", err, "Takeover module failed") };
      }
      const takeoverTimedOut = takeoverResult?.outcome === "deadline_exceeded";
      const takeoverOutboundSnapshot = takeoverThrown
        ? (() => { takeoverOutbound?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("subdomain_takeover"); })()
        : takeoverTimedOut
        ? abandonOutbound(takeoverOutbound, "subdomain_takeover", takeoverStartedMs != null ? "module_race" : "launch_gate")
        : settleOutboundValue(takeoverOutbound, "subdomain_takeover", takeoverResult);
      telemetry.record("subdomain_takeover", {
        outcome:        telemetry.outcomeOf(takeoverResult),
        timeout:        takeoverTimedOut || /timed out|timeout|abort/i.test(String(takeoverThrown?.message || "")),
        error_class:    takeoverThrown?.name || null,
        duration_ms:    takeoverDurationMs,
        allocated_ms:   takeoverStartedMs != null ? takeoverAllocatedMs : 0,
        timeout_source: takeoverTimedOut ? (takeoverStartedMs != null ? "module_race" : "launch_gate") : null,
        outbound:       takeoverOutboundSnapshot,
        outbound_calls: takeoverOutboundSnapshot?.outbound_measurement_complete ? takeoverOutboundSnapshot.outbound_attempts_observed : null,
      });

      // Asset exposure (admin-surface signal): customer-critical, so it runs before the
      // cheaper enrichment phases — but its probes time out at 8-10s each, exceeding the
      // 6s launch estimate, so the run is hard-bounded to the remaining budget. On the
      // bound it defers honestly rather than orphaning the scan.
      let exposureAllocatedMs = null, exposureStartedMs = null, exposureDurationMs = null;
      let exposureOutbound = null;
      let exposureThrown = null;
      try {
        const exposureRun = await runCappedModule("asset_exposure", {
          // Launch with the measured 2.5s estimate; on a durable (queue/cron)
          // scan the race cap is the module's structural worst case, still
          // bounded by the remaining deadline.
          ...(durableInvocation ? { hardMs: SCAN_DURABLE_SURFACE_MODULE_BUDGETS.asset_exposure } : {}),
          fallback: () => markDeadlineDeferred({
            checked: 0,
            reachable: 0,
            assets: [],
            removal_observations: unavailableRemovalObservations(knownAssetHosts, "asset_exposure_deadline"),
            source: "http_probe",
          }),
          run: ({ accounting, signal }) => runExposureModule(domain, exposureTargets, {
            accounting,
            signal,
            cache: dnsCache,
            recheckHosts: knownAssetHosts,
          }),
        });
        exposureThrown = exposureRun.thrown;
        assetExposureResult = exposureThrown
          ? { checked: 0, reachable: 0, assets: [], removal_observations: unavailableRemovalObservations(knownAssetHosts), source: "http_probe", incomplete: true, incomplete_reason: "exposure_probe_failed", error: customerSafeFailure("scan/asset-exposure", exposureThrown, "Asset exposure module failed") }
          : exposureRun.value;
        exposureOutbound = exposureRun.ctx;
        exposureStartedMs = exposureRun.startedMs;
        exposureDurationMs = exposureRun.durationMs;
        exposureAllocatedMs = exposureRun.allocatedMs;
        if (!assetExposureResult.incomplete) {
          assetExposureResult = annotateExposureInfrastructure(assetExposureResult, takeoverResult.cname_observations);
          assetExposureResult = deduplicateExposureAssets(assetExposureResult, domain);
        }
      } catch (err) {
        exposureThrown = err;
        // A thrown exposure module never assessed the HTTP attack surface. Mark it
        // incomplete (not just error) so buildScanQuality goes partial and the
        // completion gate defers admin-surface verification — a failed probe must
        // never read as a completed clean assessment. asset_exposure is non-core, so
        // without this flag the scan would still certify "complete".
        assetExposureResult = { checked: 0, reachable: 0, assets: [], removal_observations: unavailableRemovalObservations(knownAssetHosts), source: "http_probe", incomplete: true, incomplete_reason: "exposure_probe_failed", error: customerSafeFailure("scan/asset-exposure", err, "Asset exposure module failed") };
      }
      const exposureTimedOut = assetExposureResult?.outcome === "deadline_exceeded";
      const exposureOutboundSnapshot = exposureThrown
        ? (() => { exposureOutbound?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("asset_exposure"); })()
        : exposureTimedOut
        ? abandonOutbound(exposureOutbound, "asset_exposure", exposureStartedMs != null ? "module_race" : "launch_gate")
        : settleOutboundValue(exposureOutbound, "asset_exposure", assetExposureResult);
      telemetry.record("asset_exposure", {
        outcome:        telemetry.outcomeOf(assetExposureResult),
        timeout:        exposureTimedOut || /timed out|timeout|abort/i.test(String(exposureThrown?.message || "")),
        error_class:    exposureThrown?.name || null,
        duration_ms:    exposureDurationMs,
        allocated_ms:   exposureStartedMs != null ? exposureAllocatedMs : 0,
        timeout_source: exposureTimedOut ? (exposureStartedMs != null ? "module_race" : "launch_gate") : null,
        outbound:       exposureOutboundSnapshot,
        outbound_calls: exposureOutboundSnapshot?.outbound_measurement_complete ? exposureOutboundSnapshot.outbound_attempts_observed : null,
      });
    }

    // Launch alongside later phases. The private collector rechecks current
    // MX DNS and uses one TCP/25 connection per verified host.
    const mailTransportController = workspaceId && env.NETWORK_PROBE?.fetch ? createChildSignal() : null;
    const mailTransportOutbound = mailTransportController
      ? outboundContext("mail_transport", mailTransportController.signal) : null;
    const mailTransportTimeout = mailTransportController
      ? setTimeout(() => mailTransportController.abort("mail_transport_deadline"), 33_000) : null;
    const mailTransportPromise = mailTransportController
      ? runMailTransportModule(env, { id: scanId, domain_id: domainId, workspace_id: workspaceId, domain }, dnsResult, {
          signal: mailTransportController.signal,
          accounting: mailTransportOutbound,
        }).catch(() => ({ source: "mail_transport", state: "not_tested", reason: "probe_unavailable", hosts: [],
          coverage: { planned: 0, tested: 0, not_tested: 0 }, observed_at: new Date(now()).toISOString() }))
        .finally(() => clearTimeout(mailTransportTimeout))
      : null;
    // S3-C: DANE/TLSA for the MX hosts and the website. Passive DNS, every scan.
    const daneOutbound = outboundContext("dane", deadline.signal || null);
    const danePromise = runDaneModule(domain, dnsResult, { accounting: daneOutbound })
      .catch(() => ({ source: "dane", mail: [], web: null, incomplete: true, incomplete_reason: "tlsa_lookup_failed",
        error: "dane_unavailable", observed_at: new Date(now()).toISOString() }));
    // S3-0: remote-administration ports on the addresses this verified
    // domain's DNS points at. One bounded collector call, launched alongside.
    const remoteAdminController = workspaceId && env.NETWORK_PROBE?.fetch ? createChildSignal() : null;
    const remoteAdminOutbound = remoteAdminController
      ? outboundContext("remote_admin_exposure", remoteAdminController.signal) : null;
    const remoteAdminTimeout = remoteAdminController
      ? setTimeout(() => remoteAdminController.abort("remote_admin_deadline"), 33_000) : null;
    const remoteAdminPromise = remoteAdminController
      ? runRemoteAdminExposureModule(env, { id: scanId, domain_id: domainId, workspace_id: workspaceId, domain }, {
          signal: remoteAdminController.signal,
          accounting: remoteAdminOutbound,
        }).catch(() => ({ source: "remote_admin_exposure", state: "not_assessed", reason: "probe_unavailable", exposures: [],
          incomplete: true, incomplete_reason: "probe_unavailable", error: "probe_unavailable", observed_at: new Date(now()).toISOString() }))
        .finally(() => clearTimeout(remoteAdminTimeout))
      : null;
    if (liveTlsPromise) sslResult = attachLiveTlsToSsl(sslResult, await liveTlsPromise);

    emailResult = applyDmarcbisEmailCompatibilityProjection(
      domain,
      emailResult,
      dmarcCoreResult,
    );

    const modules = {
      dns:                       dnsResult,
      ssl:                       sslResult,
      headers:                   headersResult,
      email_security:            emailResult,
      // Technical R2 evidence in P2. P3 adds the versioned snapshot/API dual
      // readers; existing exact-record fields remain on email_security.
      dmarc_core:                dmarcCoreResult,
      subdomains:                subdomainsResult,
      subdomain_takeover:        takeoverResult,
      asset_exposure:            assetExposureResult,
      // Present only in reserved mode (null in legacy) — the deterministic critical-prefix pass.
      critical_prefix_discovery: criticalPrefixResult,
      technology_detection:      techResult,
      whois_intelligence:        whoisResult,
      dns_bruteforce:            bruteforceResult,
      // Phase 7i: pure computation, zero network I/O — must run before computeScore
      // so brand findings are included in the scored findings array.
      brand_monitoring:          runTyposquatModule(domain),
    };
    // Admin detection is a pure consumer of the exposure evidence and must be
    // present before scoring and the explicit admin-finding projection below.
    // The previous late assignment made that live consumer path unreachable.
    modules.admin_surface_detection = runAdminSurfaceModule(modules);

    // Phase 7c: Domain security enrichment — pure computation, zero network I/O.
    // Reads CAA from modules.dns.caa, HSTS from modules.headers, cookies from
    // modules.headers.set_cookie_raw.  All data was captured in Phase 1.
    try {
      modules.domain_security_enrichment = runDomainSecurityEnrichmentModule(domain, modules);
    } catch {
      modules.domain_security_enrichment = {
        caa:     {
          present: false, records: [], issuers: [], wildcard_issuers: [], iodef: [],
          quality: { score: 0, status: "lookup_failed", wildcard_issuer_usage: false, iodef_present: false, issuer_count: 0 },
          error: "enrichment failed",
        },
        hsts:    { present: false, value: null, max_age: null, include_subdomains: false, preload_directive: false, preload_eligible: false, error: "enrichment failed" },
        cookies: { found: 0, cookies: [], insecure_count: 0, no_httponly: 0, no_samesite: 0, error: "enrichment failed" },
        source:  "dns_headers_analysis", error: "enrichment failed",
      };
    }
    // Heartbeat: discovery + exposure done. An orphan cancelled after this point
    // died in scoring/enrichment/finalization, not discovery.
    await heartbeatScan(env, scanId, "discovery_complete", telemetry.rows.filter((r) => r.outcome === "ok").length);

    const emailApplicability = isEmailApplicable(domain, modules.dns);
    if (!modules.email_security.error) {
      modules.email_security.applicability = emailApplicability;
      if (!emailApplicability.applicable) modules.email_security.remediation_actions = [];
    }

    // Brand decision honesty: merge the enrichment state the workspace already
    // holds (hourly DNS / daily HTTPS results in workspace_brand_assets, open
    // confirmed-abuse cases) into the brand module BEFORE scoring and BEFORE the
    // report is frozen. `candidates_validated` is derived from that state; a
    // read failure fails closed (unvalidated → provisional, never healthy). The
    // resolver, the 091 state rows and the M5.c snapshot all read this one
    // report, so the card can no longer read provisional or healthy while a
    // live high-risk lookalike or an open abuse case exists.
    modules.brand_monitoring = await loadBrandValidationState(env, {
      workspaceId, domain, brandModule: modules.brand_monitoring,
      now: new Date(now()).toISOString(),
    });

    // Email Protection: an unauthorised-sending-source alert (SPF-RUA
    // corroboration, Phase 8a.2 of an earlier scan) does not change the
    // published-record conclusion, but the domain conclusion must not stay
    // silent about it. The bounded alert summary rides on email_security so the
    // resolver marks coverage partial and names it; an unreadable ledger adds
    // nothing (not evidence either way).
    if (!modules.email_security.error) {
      modules.email_security.unauthorised_sending_sources = await loadUnauthorisedSendingSourceAlerts(env, {
        workspaceId, domain, now: new Date(now()).toISOString(),
      });
    }

    // Compute Cyber Metrics Score
    const { score, risk_level, findings, recommendations } = computeScore(modules, domain);

    // Append technology detection info-findings (score_impact: 0 — informational only)
    const techMod = modules.technology_detection;
    if (techMod && !techMod.error && Array.isArray(techMod.info_findings)) {
      for (const f of techMod.info_findings) {
        findings.push({
          module:      "technology_detection",
          ...f,
        });
      }
    }

    // Registration data: the WHOIS/RDAP module's expiry findings reach the ONE
    // report findings array (score_impact 0, explicit finding authority) so the
    // Attack Surface domain owns them and an expired or expiring registration
    // can turn the card red. Unavailable or deferred registries add nothing.
    for (const f of whoisReportFindings(modules.whois_intelligence)) {
      if (findings.some((existing) => existing?.id === f.id)) continue;
      findings.push(f);
    }

    // Append admin surface detection findings (score_impact: 0 — no scoring changes in Phase 1)
    const adminMod = modules.admin_surface_detection;
    if (adminMod && !adminMod.error && adminMod.detected && adminMod.total > 0) {
      const adminHostKey = (hostname) => String(hostname || "")
        .trim().toLowerCase().replace(/\.$/, "");
      const scoredAdminHosts = new Set(findings
        .filter((finding) => finding.id === "asset_exposure_sensitive_tool" ||
          finding.id === "asset_exposure_admin_interface")
        .flatMap((finding) => finding.affected_hosts || [])
        .map(adminHostKey)
        .filter(Boolean));
      const claimedAdminHosts = new Set(scoredAdminHosts);
      const bucketServices = (adminMod.services || []).filter((service) => {
        if (service.finding_type !== "finding") return false;
        const hostKey = adminHostKey(service.hostname);
        if (!hostKey || claimedAdminHosts.has(hostKey)) return false;
        claimedAdminHosts.add(hostKey);
        return true;
      });
      const criticalSvcs = bucketServices.filter((s) => s.risk_level === "critical");
      const highSvcs     = bucketServices.filter((s) => s.risk_level === "high");
      const mediumSvcs   = bucketServices.filter((s) => s.risk_level === "medium");

      if (criticalSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_critical",
          module:       "admin_surface_detection",
          severity:     "critical",
          finding_type: "finding",
          score_impact: 0,
          // Machine-readable affected hosts. Managed cases derive their verification
          // target from this — never from the prose description below.
          affected_hosts: criticalSvcs.map((s) => s.hostname).filter(Boolean),
          title:        `Critical Admin Interface${criticalSvcs.length > 1 ? "s" : ""} Exposed`,
          description:  `${criticalSvcs.length} critical administrative interface${criticalSvcs.length > 1 ? "s are" : " is"} publicly reachable: ${criticalSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}. These provide direct access to sensitive systems and should never be internet-facing.`,
          recommendation: `Immediately restrict access to: ${criticalSvcs.map((s) => s.hostname).join(", ")}. Place behind VPN or allowlist-only firewall rules.`,
        });
      }
      if (highSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_high",
          module:       "admin_surface_detection",
          severity:     "high",
          finding_type: "finding",
          score_impact: 0,
          affected_hosts: highSvcs.map((s) => s.hostname).filter(Boolean),
          title:        `High-Risk Admin Interface${highSvcs.length > 1 ? "s" : ""} Exposed`,
          description:  `${highSvcs.length} high-risk administrative interface${highSvcs.length > 1 ? "s are" : " is"} publicly reachable: ${highSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}.`,
          recommendation: `Restrict access to: ${highSvcs.map((s) => s.hostname).join(", ")} via VPN or IP allowlist.`,
        });
      }
      if (mediumSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_medium",
          module:       "admin_surface_detection",
          severity:     "medium",
          finding_type: "finding",
          score_impact: 0,
          affected_hosts: mediumSvcs.map((s) => s.hostname).filter(Boolean),
          title:        `Collaboration Tool${mediumSvcs.length > 1 ? "s" : ""} Publicly Accessible`,
          description:  `${mediumSvcs.length} collaboration or source-control service${mediumSvcs.length > 1 ? "s are" : " is"} publicly accessible: ${mediumSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}. Verify these require authentication and enforce MFA.`,
          recommendation: `Ensure ${mediumSvcs.map((s) => s.hostname).join(", ")} enforce MFA and are patched to the latest version.`,
        });
      }
    }

    // Append domain security enrichment findings (score_impact: 0 — no major scoring
    // changes). The conditions and copy live in dse-findings.js so that the managed
    // verification profile evaluates the SAME predicates when deciding whether a
    // customer's fix actually removed the issue.
    findings.push(...buildDseFindings(modules.domain_security_enrichment, domain));


    // score and findings are known. Mutates modules in place before R2 write.
    try {
      modules.historical_changes = await runHistoricalModule(
        scanId, domain, score, findings, modules, env, workspaceId
      );
    } catch (err) {
      modules.historical_changes = {
        has_previous:       false,
        previous_scan_id:   null,
        previous_score:     null,
        current_score:      score,
        score_change:       null,
        new_subdomains:     [],
        removed_subdomains: [],
        new_findings:       [],
        resolved_findings:  [],
        not_reobserved_findings: [],
        new_takeover_risks: [],
        new_exposed_assets: [],
        source:             "previous_scan_comparison",
        error:              customerSafeFailure("scan/history", err, "Historical module failed"),
      };
    }

    // Phase 5: email intelligence — MTA-STS, TLS-RPT and email detail from the
    // scan's own DNS and HTTPS observations. Matching reported software against
    // outside vulnerability databases and exploited-vulnerability catalogues is
    // not part of the check pack (check-pack.js): those two modules record that
    // in the report, so no reader mistakes their absence for a failure.
    modules.cve_intelligence = moduleNotInCheckPack("vulnerability_database_matching", "outside_vulnerability_data_not_used");
    modules.known_exploited_vulnerabilities = moduleNotInCheckPack("exploited_vulnerability_data", "outside_vulnerability_data_not_used");
    // In reserved mode email intelligence is budget-permitting enrichment:
    // skipped honestly (no fetch attempted) when the exposure-first budget is
    // already spent.
    const phase5Cost = 4;
    const durablePhase5 = executionContext === "queue" || executionContext === "cron";
    const phase5LaunchEstimate = durablePhase5
      ? SCAN_DURABLE_PHASE5_MODULE_BUDGETS.email_security_intelligence
      : SCAN_MODULE_BUDGETS.phase5_intelligence;
    // Deadline first: if email intelligence can't finish in budget, defer it
    // honestly (partial scan) rather than risk the whole invocation being
    // cancelled mid-write.
    await heartbeatScan(env, scanId, "phase5_intelligence", telemetry.rows.filter((r) => r.outcome === "ok").length);
    // Admission is evaluated after the heartbeat write so time spent reaching
    // this boundary is included; a phase never launches on a stale clock sample.
    const phase5DeadlineBlocked = !deadline.canRun(phase5LaunchEstimate);
    if (phase5DeadlineBlocked) {
      const phase5LaunchCause = durablePhase5
        ? { reason: "scan_deadline_exhausted", timeoutSource: "launch_gate" }
        : {};
      modules.email_security_intelligence = markDeadlineDeferred({ source: "email_intelligence" }, phase5LaunchCause);
      telemetry.record("email_security_intelligence", { outcome: "deadline_exceeded", allocated_ms: 0, timeout_source: "launch_gate" });
    } else if (reservedMode && reservedBudget && reservedBudget.wouldExceed(phase5Cost)) {
      modules.email_security_intelligence = skippedModuleResult("email_intelligence");
    } else {
    if (reservedMode && reservedBudget) reservedBudget.spend("phase5", phase5Cost);
    if (!durablePhase5) {
      // Byte-compatible legacy path: waitUntil/unknown callers retain one
      // shared one-second race and the established terminal fallback.
      const PHASE5_DEADLINE = "__phase5_deadline__";
      let phase5AllocatedMs = null;
      const phase5StartedMs = now();
      const phase5Controller = createChildSignal();
      const emailIntelOutbound = outboundContext("email_security_intelligence", phase5Controller.signal);
      const settled = await raceModuleDeadline(
        deadline,
        () => Promise.allSettled([
          runEmailIntelModule(domain, modules.email_security, modules.dns, {
            accounting: emailIntelOutbound,
            signal: phase5Controller.signal,
            cache: dnsCache,
          }),
        ]),
        () => {
          phase5Controller.abort("module_budget_exhausted");
          return PHASE5_DEADLINE;
        },
        { hardMs: SCAN_MODULE_BUDGETS.phase5_intelligence, onStart: (capMs) => { phase5AllocatedMs = capMs; } },
      );
      if (settled === PHASE5_DEADLINE) {
        modules.email_security_intelligence = markDeadlineDeferred({ source: "email_intelligence" });
      } else {
        const [emailIntelSettled] = settled;
        modules.email_security_intelligence = emailIntelSettled.status === "fulfilled"
          ? emailIntelSettled.value
          : { error: customerSafeFailure("scan/email-intelligence", emailIntelSettled.reason, "Email intelligence module failed") };
      }
      if (emailIntelOutbound?.physicalBudgetExhausted?.()) {
        modules.email_security_intelligence = markPhysicalBudgetIncomplete("email_security_intelligence", modules.email_security_intelligence, emailIntelOutbound);
      }
      const phase5WallMs = now() - phase5StartedMs;
      const phase5Raced = settled === PHASE5_DEADLINE;
      const emailIntelOutboundSnapshot = phase5Raced ? abandonOutbound(emailIntelOutbound, "email_security_intelligence", "module_race") : settleOutboundValue(emailIntelOutbound, "email_security_intelligence", modules.email_security_intelligence);
      telemetry.record("email_security_intelligence", {
        outcome: telemetry.outcomeOf(modules.email_security_intelligence), timeout: modules.email_security_intelligence?.outcome === "deadline_exceeded",
        duration_ms: phase5WallMs, allocated_ms: phase5AllocatedMs, timeout_source: phase5Raced ? "module_race" : null,
        outbound: emailIntelOutboundSnapshot,
        outbound_calls: emailIntelOutboundSnapshot.outbound_measurement_complete ? emailIntelOutboundSnapshot.outbound_attempts_observed : null,
      });
    } else {
      const emailIntelFallback = () => markDeadlineDeferred({ source: "email_intelligence" });
      const emailIntelRun = await runCappedModule("email_security_intelligence", {
        fallback: emailIntelFallback,
        estimateMs: SCAN_DURABLE_PHASE5_MODULE_BUDGETS.email_security_intelligence,
        hardMs: SCAN_DURABLE_PHASE5_MODULE_BUDGETS.email_security_intelligence,
        run: ({ accounting, signal }) => runEmailIntelModule(domain, modules.email_security, modules.dns, {
          accounting,
          signal,
          cache: dnsCache,
        }),
      });
      modules.email_security_intelligence = emailIntelRun.thrown
        ? { error: customerSafeFailure("scan/email-intelligence", emailIntelRun.thrown, "Email intelligence module failed") }
        : emailIntelRun.value;
      // A late work promise can finish only into its own discarded local value;
      // no promise writes modules/report state after its race resolves.
      const value = modules.email_security_intelligence;
      const outbound = emailIntelRun.timedOut
        ? abandonOutbound(emailIntelRun.ctx, "email_security_intelligence", emailIntelRun.timeoutSource || "module_race")
        : settleOutboundValue(emailIntelRun.ctx, "email_security_intelligence", value);
      telemetry.record("email_security_intelligence", {
        outcome: telemetry.outcomeOf(value),
        timeout: value?.outcome === "deadline_exceeded",
        duration_ms: emailIntelRun.durationMs,
        allocated_ms: emailIntelRun.allocatedMs,
        timeout_source: emailIntelRun.timeoutSource,
        outbound,
        outbound_calls: outbound.outbound_measurement_complete ? outbound.outbound_attempts_observed : null,
      });
    }
    }
    modules.mail_transport = mailTransportPromise ? await mailTransportPromise
      : { source: "mail_transport", state: "not_tested", reason: "verified_workspace_required", hosts: [],
          coverage: { planned: 0, tested: 0, not_tested: 0 }, observed_at: new Date(now()).toISOString() };
    // Every call it made has now returned or been aborted after being counted,
    // so its outbound count is final whatever the security outcome. Without
    // this the RFC 9990 launch gate read it as an unsettled leaf on every scan.
    mailTransportOutbound?.markSettled();
    modules.dane = await danePromise;
    daneOutbound.markSettled();
    if (remoteAdminPromise) {
      modules.remote_admin_exposure = await remoteAdminPromise;
      remoteAdminOutbound?.markSettled();
    } else {
      modules.remote_admin_exposure = { source: "remote_admin_exposure", state: "not_assessed", reason: "verified_workspace_required",
        exposures: [], incomplete: false, incomplete_reason: null, error: null, observed_at: new Date(now()).toISOString() };
    }
    // One module never stands in as the completion guard for the other:
    //   • the intelligence module proves its OWN completion — deferred, errored
    //     or skipped intel evidence is non-publishable and must not fabricate
    //     transport detail ("not confirmed during this scan") for checks that
    //     never ran;
    //   • remediation generation additionally requires the PRIMARY
    //     email_security module's completed canonical evidence
    //     (isPublishableEmailEvidence). A deadline-deferred primary module used
    //     to reach the builder here — gated only on the OTHER module — and its
    //     absent spf_detail crashed the entire scan.
    const emailIntelUsable =
      isPublishableModuleEvidence(modules.email_security_intelligence) && emailApplicability.applicable;
    const mtaStsEvidence = modules.email_security_intelligence?.mta_sts;
    const mtaStsMissingRows = Array.isArray(modules.email_security_intelligence?.findings)
      ? modules.email_security_intelligence.findings.filter((finding) =>
        finding?.id === "email_intel_mta_sts_missing" &&
        finding?.module === "email_security_intelligence" &&
        finding?.severity === "low" &&
        Number.isFinite(finding?.score_impact) &&
        finding.score_impact === 0)
      : [];
    if (
      emailIntelUsable &&
      emailApplicability.applicable &&
      mtaStsAdmission(mtaStsEvidence).missing_finding === true &&
      mtaStsMissingRows.length === 1 &&
      !findings.some((finding) => finding?.id === "email_intel_mta_sts_missing")
    ) {
      findings.push({
        ...mtaStsMissingRows[0],
        finding_type: "finding",
        severity: "low",
        score_impact: 0,
        evidence: [{
          type: "https_probe",
          target: `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
          status: 404,
          reason: "well_known_404",
          source: "cloudflare_workers_fetch",
          contract: mtaStsEvidence.serviceability.contract_version,
        }],
      });
    }
    if (emailIntelUsable) {
      const transportDetails = buildEmailTransportDetails(modules.email_security_intelligence);
      Object.assign(modules.email_security, transportDetails);
    }
    if (emailIntelUsable && isPublishableEmailEvidence(modules.email_security)) {
      modules.email_security.remediation_actions = buildEmailRemediationActions(
        domain,
        modules.email_security,
        modules.email_security_intelligence
      );
    }
    const phase5CustomerAssessment = resolvePhase5CustomerAssessment({
      score,
      riskLevel: risk_level,
      modules,
    });
    const customerScore = phase5CustomerAssessment.score;
    const customerRiskLevel = phase5CustomerAssessment.risk_level;
    // Historical comparison ran before the bounded Phase-5 provider fan-out.
    // Reconcile its current-score fields to the canonical post-Phase-5 owner so
    // history never reports the pre-KEV number beside the final report score.
    reconcilePhase5HistoricalScore(modules.historical_changes, customerScore);

    // Optional RFC 9990 external-RUA phase. Core evidence is already durable in
    // memory before this gate. Launch requires the whole 600 ms slot, complete
    // default-path outbound accounting (or the reserved ledger), and one full
    // 11-question host reservation. Refusal is explicit and issues no question.
    const ruaSet = modules.dmarc_core?.rua_destinations;
    let externalGateReason = null;
    let externalAccountingSnapshot = null;
    let externalCapacityRemaining = null;
    if (!Array.isArray(ruaSet)) {
      externalGateReason = "core_dependency_unavailable";
    } else if (ruaSet.length > 0 && modules.dmarc_core?.core_completeness !== "complete") {
      externalGateReason = "core_dependency_unavailable";
    } else if (ruaSet.length > 0 && !deadline.canRun(SCAN_MODULE_BUDGETS.dmarc_external_rua)) {
      externalGateReason = "deadline_budget";
    } else if (ruaSet.length > 0 && reservedMode) {
      externalCapacityRemaining = reservedBudget?.remaining?.() ?? 0;
      if (!reservedBudget || reservedBudget.wouldExceed(DMARCBIS_EXTERNAL_HOST_RESERVATION)) {
        externalGateReason = "subrequest_budget";
      }
    } else if (ruaSet.length > 0) {
      externalAccountingSnapshot = outboundAccounting.aggregate({
        required: [
          "dns", "ssl", "headers", "email_security", "dmarc_core",
          "subdomains", "technology_detection", "whois_intelligence",
          "dns_bruteforce", "subdomain_takeover", "asset_exposure",
          "email_security_intelligence",
        ],
      });
      if (!externalAccountingSnapshot
        .subrequest_capacity_accounting_complete) {
        externalGateReason = "outbound_accounting_incomplete";
      } else {
        // Physical headroom: every outbound call so far is counted, so the
        // optional phase is measured against the provider ceiling. The
        // application figure (SCAN_SUBREQUEST_LIMIT) is below what a real
        // scan already issues (~700), so measuring against it refused the
        // phase on every real domain (21 Oct 2026, scan_b384ffeb).
        externalCapacityRemaining = Math.max(
          0,
          capacity.platformCeiling - capacity.safetyMargin
            - externalAccountingSnapshot.outbound_attempts_observed,
        );
        if (externalCapacityRemaining < DMARCBIS_EXTERNAL_HOST_RESERVATION) {
          externalGateReason = "subrequest_budget";
        }
      }
    }

    let externalRuaResult;
    if (!Array.isArray(ruaSet) || ruaSet.length === 0 || externalGateReason) {
      externalRuaResult = await budgetRefusedDmarcbisExternal(
        modules.dmarc_core,
        ruaSet?.length === 0 ? "not_applicable" : externalGateReason,
      );
      telemetry.record("dmarc_external_rua", {
        outcome: externalRuaResult.rua_authorisation_completeness === "not_applicable"
          ? "ok"
          : "skipped",
        allocated_ms: ruaSet?.length === 0 ? null : 0,
        timeout_source: externalGateReason === "deadline_budget" ? "launch_gate" : null,
        outbound: null,
      });
    } else {
      let reservedHostUnits = 0;
      const externalStartedAt = now();
      const fallback = await budgetRefusedDmarcbisExternal(
        modules.dmarc_core,
        "provider_timeout",
      );
      const externalRun = await runCappedModule("dmarc_external_rua", {
        fallback: () => fallback,
        run: ({ accounting, signal }) => runDmarcbisExternalRuaPhase(
          modules.dmarc_core,
          {
            accounting,
            signal,
            cache: dnsCache,
            now,
            // A second unique host starts only when the full measured host
            // schedule remains. The first host owns the phase reservation.
            reserveHost: ({ questions, ordinal }) => {
              if (questions !== DMARCBIS_EXTERNAL_HOST_RESERVATION) return false;
              const phaseRemaining = SCAN_MODULE_BUDGETS.dmarc_external_rua
                - Math.max(0, now() - externalStartedAt);
              if (ordinal > 1 && phaseRemaining < 575) return false;
              if (reservedMode) {
                if (reservedBudget.wouldExceed(questions)) return false;
                reservedBudget.spend("dmarc_external_rua", questions);
                return true;
              }
              if (reservedHostUnits + questions > externalCapacityRemaining) return false;
              reservedHostUnits += questions;
              return true;
            },
          },
        ),
      });
      if (externalRun.startedMs == null) {
        externalGateReason = "deadline_budget";
        externalRuaResult = await budgetRefusedDmarcbisExternal(
          modules.dmarc_core,
          externalGateReason,
        );
      } else if (externalRun.thrown) {
        externalRuaResult = {
          ...fallback,
          assessment_reason: "provider_error",
        };
      } else {
        externalRuaResult = externalRun.value;
      }
      const externalOutbound = externalRun.startedMs == null
        ? null
        : externalRun.thrown
        ? (() => {
          externalRun.ctx?.markIncomplete?.("module_error");
          return outboundAccounting.snapshot("dmarc_external_rua");
        })()
        : externalRuaResult?.assessment_reason === "provider_timeout"
          ? abandonOutbound(externalRun.ctx, "dmarc_external_rua", "module_race")
          : settleOutboundValue(
            externalRun.ctx,
            "dmarc_external_rua",
            externalRuaResult,
          );
      telemetry.record("dmarc_external_rua", {
        outcome: externalRuaResult.rua_authorisation_completeness === "complete"
          || externalRuaResult.rua_authorisation_completeness === "not_applicable"
          ? "ok"
          : "degraded",
        timeout: ["provider_timeout", "deadline_budget"].includes(
          externalRuaResult?.assessment_reason,
        ),
        error_class: externalRun.thrown?.name || null,
        duration_ms: externalRun.durationMs,
        allocated_ms: externalRun.allocatedMs,
        timeout_source:
          externalRuaResult?.assessment_reason === "provider_timeout"
            ? "module_race"
            : externalRuaResult?.assessment_reason === "deadline_budget"
              ? "launch_gate"
              : null,
        outbound: externalOutbound,
        outbound_calls: externalOutbound?.outbound_measurement_complete
          ? externalOutbound.outbound_attempts_observed
          : null,
      });
    }
    externalRuaResult = {
      ...externalRuaResult,
      launch_gate: {
        reason: externalGateReason,
        accounting_complete:
          externalAccountingSnapshot?.subrequest_capacity_accounting_complete
          ?? (reservedMode ? true : ruaSet?.length === 0 ? true : null),
        observed_outbound_attempts:
          externalAccountingSnapshot?.outbound_attempts_observed ?? null,
        accounting_cutoff:
          externalAccountingSnapshot?.subrequest_capacity_accounting_cutoff
          ?? null,
        capacity_remaining: externalCapacityRemaining,
        required_host_units: DMARCBIS_EXTERNAL_HOST_RESERVATION,
      },
    };
    modules.dmarc_core = attachDmarcbisExternalResult(
      modules.dmarc_core,
      externalRuaResult,
    );
    modules.email_security = applyDmarcbisEmailCompatibilityProjection(
      domain,
      modules.email_security,
      modules.dmarc_core,
    );

    // Optional public identity metadata; shares verified scope, strict fetch,
    // hard invocation counter and deadline. No advertised endpoint is followed.
    const registrationScopeVerified = await isWorkspaceDomainVerified(env, workspaceId, domainId);
    let oidcMetadata = { state: "not_assessed", reason: "verified_workspace_required", observations: [] };
    if (registrationScopeVerified && !(reservedMode && reservedBudget?.wouldExceed(OIDC_LIMITS.physical_attempts))) {
      if (reservedMode && reservedBudget) reservedBudget.spend("identity_discovery", OIDC_LIMITS.physical_attempts);
      const oidcRun = await runCappedModule("identity_discovery", {
        estimateMs: OIDC_LIMITS.module_ms, hardMs: OIDC_LIMITS.module_ms,
        fallback: () => markDeadlineDeferred({ state: "not_assessed", observations: [] }),
        run: ({ accounting, signal }) => observeOidcMetadata(domain, modules, {
          verified: registrationScopeVerified, observedAt: startedAt, cache: dnsCache, accounting, signal,
        }),
      });
      oidcMetadata = oidcRun.thrown ? { state: "unavailable", observations: [] } : oidcRun.value;
      const outbound = oidcRun.timedOut ? abandonOutbound(oidcRun.ctx, "identity_discovery", oidcRun.timeoutSource)
        : settleOutboundValue(oidcRun.ctx, "identity_discovery", oidcMetadata);
      telemetry.record("identity_discovery", { outcome: telemetry.outcomeOf(oidcMetadata),
        duration_ms: oidcRun.durationMs, allocated_ms: oidcRun.allocatedMs, timeout_source: oidcRun.timeoutSource,
        timeout: oidcRun.timedOut, outbound,
        outbound_calls: outbound?.outbound_measurement_complete ? outbound.outbound_attempts_observed : null });
    } else if (registrationScopeVerified) oidcMetadata.reason = "subrequest_budget_exhausted";

    // Phase 6: Risk intelligence + Remediation plan (pure computation — no I/O)
    // Risk module enriches all findings with business-impact language and risk categories.
    // Remediation module converts findings + takeover risks into a P1/P2/P3 roadmap.
    modules.risk_intelligence = runRiskModule(findings, modules);
    modules.remediation_plan  = runRemediationModule(
      findings,
      modules.subdomain_takeover,
    );
    // Canonical Phase-5 customer findings are produced after the score has been
    // finalised. Append them to the ONE report findings array so API, UI,
    // immutable snapshot, PDF and historical reads all carry the same cause and
    // applied impact. They are not fed back into computeScore or remediation
    // generation (no duplicate charge or duplicate roadmap item).
    findings.push(...(modules.risk_intelligence.customer_findings || []));

    // Phase 7: Cloud storage discovery — validates only evidence-backed storage
    // candidates from observed ASM/CNAME/header signals. No guessing or listing
    // enumeration; response bodies are only inspected for listing indicators.
    // Reserved mode: cloud-storage validation is budget-permitting enrichment.
    let cloudAllocatedMs = null, cloudStartedMs = null, cloudDurationMs = null, cloudOutbound = null;
    let cloudThrown = null;
    if (!deadline.canRun(SCAN_MODULE_BUDGETS.cloud_storage_discovery)) {
      modules.cloud_storage_discovery = markDeadlineDeferred({ total: 0, checked: 0, findings: [] });
    } else if (reservedMode && reservedBudget && reservedBudget.wouldExceed(CLOUD_STORAGE_MAX_PHYSICAL_ATTEMPTS)) {
      modules.cloud_storage_discovery = skippedModuleResult("cloud_storage", { total: 0, checked: 0, findings: [] });
    } else {
      if (reservedMode && reservedBudget) reservedBudget.spend("cloud_storage", CLOUD_STORAGE_MAX_PHYSICAL_ATTEMPTS);
      // Bound the run so a slow validation cannot cross the cliff; defer honestly on the bound.
      const cloudRun = await runCappedModule("cloud_storage_discovery", {
        fallback: () => markDeadlineDeferred({ total: 0, checked: 0, findings: [] }),
        run: ({ accounting, signal }) => runCloudStorageModule(domain, modules, { accounting, signal, cache: dnsCache }),
      });
      cloudThrown = cloudRun.thrown;
      modules.cloud_storage_discovery = cloudThrown
        ? { total: 0, checked: 0, findings: [], incomplete: true, incomplete_reason: "cloud_storage_probe_failed", error: customerSafeFailure("scan/cloud-storage", cloudThrown, "Cloud storage module failed") }
        : cloudRun.value;
      cloudStartedMs = cloudRun.startedMs;
      cloudDurationMs = cloudRun.durationMs;
      cloudAllocatedMs = cloudRun.allocatedMs;
      cloudOutbound = cloudRun.ctx;
    }
    const cloudTimedOut = modules.cloud_storage_discovery?.outcome === "deadline_exceeded";
    const cloudOutboundSnapshot = cloudThrown
      ? (() => { cloudOutbound?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("cloud_storage_discovery"); })()
      : cloudTimedOut
      ? abandonOutbound(cloudOutbound, "cloud_storage_discovery", cloudStartedMs != null ? "module_race" : "launch_gate")
      : settleOutboundValue(cloudOutbound, "cloud_storage_discovery", modules.cloud_storage_discovery);
    // PR-A1: explicit row (previously left to the coarse finalization backfill) so
    // the launched/deferred/skipped distinction and timing are diagnosable. A
    // reserved-budget skip carries no allocation semantics (null, not 0).
    telemetry.record("cloud_storage_discovery", {
      outcome:        telemetry.outcomeOf(modules.cloud_storage_discovery),
      timeout:        cloudTimedOut || /timed out|timeout|abort/i.test(String(cloudThrown?.message || "")),
      error_class:    cloudThrown?.name || null,
      duration_ms:    cloudDurationMs,
      allocated_ms:   cloudStartedMs != null ? cloudAllocatedMs : (modules.cloud_storage_discovery?.skipped ? null : 0),
      timeout_source: cloudTimedOut ? (cloudStartedMs != null ? "module_race" : "launch_gate") : null,
      outbound:       cloudOutboundSnapshot,
      outbound_calls: cloudOutboundSnapshot?.outbound_measurement_complete ? cloudOutboundSnapshot.outbound_attempts_observed : null,
    });
    for (const f of modules.cloud_storage_discovery.findings || []) {
      findings.push(f);
    }

    // The private content/exposure job finishes before the domain scan claim.
    // Read it once: the page projection and content rules describe the SAME
    // physical responses, with all network costs charged to that job.
    let exposureReceipt = null;
    if (workspaceId) {
      try { exposureReceipt = await readExposureForScan(env, { workspaceId, scanId }); } catch { /* unavailable is explicit below */ }
    }
    const tlsAssessment = await loadTlsAssessmentModuleForScan(env, { workspaceId, scanId, durableInvocation });
    if (tlsAssessment) modules.tls_assessment = tlsAssessment;

    // Phase 7a: Website important-page discovery (engines/page-discovery.js).
    // Bounded passive GETs of the site's own pages (homepage links, sitemap,
    // a short well-known list; max 15 pages) on the scanned host only. Durable
    // (queue/cron) scans only, after the external-RUA capacity gate, under its
    // own explicit cap. It NEVER sets `incomplete`: a partial or skipped crawl
    // is reported on the module's own `coverage`, so it cannot downgrade scan
    // quality or block verification for any other domain. Produces no findings
    // yet; its observations are persisted per workspace in Phase 8m-ii.
    {
      const notRun = (reason) => ({ source: "page_discovery", version: PAGE_DISCOVERY_VERSION, coverage: "not_run", partial_reasons: [reason], pages: [] });
      if (!durableInvocation) {
        modules.page_discovery = notRun("not_durable_execution");
      } else if (exposureReceipt?.page_discovery) {
        modules.page_discovery = exposureReceipt.page_discovery;
      } else if (reservedMode) {
        modules.page_discovery = notRun("reserved_capacity_mode");
      } else if (!deadline.canRun(PAGE_DISCOVERY_BUDGET_MS + PAGE_DISCOVERY_POST_TERMINAL_RESERVE_MS)) {
        modules.page_discovery = notRun("deadline_budget");
      } else {
        const pageRun = await runCappedModule("page_discovery", {
          estimateMs: PAGE_DISCOVERY_BUDGET_MS,
          hardMs: PAGE_DISCOVERY_BUDGET_MS,
          fallback: () => notRun("module_budget_exhausted"),
          run: ({ accounting, signal, remainingMs }) => runPageDiscoveryModule(domain, {
            dnsResolver: dnsQuery, dnsCache, accounting, signal, remainingMs,
          }),
        });
        modules.page_discovery = pageRun.thrown ? notRun("module_failed") : (pageRun.value || notRun("module_failed"));
        const pageTimedOut = pageRun.timedOut === true || Boolean(modules.page_discovery.timeout_source);
        try {
          const pageOutbound = pageRun.thrown
            ? (() => { pageRun.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("page_discovery"); })()
            : pageTimedOut
            ? abandonOutbound(pageRun.ctx, "page_discovery", pageRun.startedMs != null ? "module_race" : "launch_gate")
            : settleOutboundValue(pageRun.ctx, "page_discovery", modules.page_discovery);
          telemetry.record("page_discovery", {
            outcome:        telemetry.outcomeOf(modules.page_discovery),
            timeout:        pageTimedOut,
            error_class:    pageRun.thrown?.name || null,
            duration_ms:    pageRun.durationMs,
            allocated_ms:   pageRun.allocatedMs,
            timeout_source: pageTimedOut ? (modules.page_discovery.timeout_source || "module_race") : null,
            outbound:       pageOutbound,
            outbound_calls: pageOutbound?.outbound_measurement_complete ? pageOutbound.outbound_attempts_observed : null,
          });
        } catch { /* telemetry is observational only */ }
      }
    }

    // One canonical projection feeds the frozen report,
    // Website lifecycle, cases and alerts, without changing CMS weights.
    // Unrequested exposure coverage is outside free/legacy scan scope. Only an
    // expected durable job can contribute an explicit unavailable coverage gap.
    if (exposureReceipt || (workspaceId && durableInvocation && env.EXPOSURE_SCAN_MODE === "evidence-v1")) {
      modules.external_exposure = reconcileCurrentDnsHostCoverage(
        externalExposureModule(exposureReceipt), modules.asset_exposure, new Date(now()).toISOString());
    }

    // Phase 7a-i: hostnames the site's own robots.txt, sitemaps and scripts
    // name (engines/page-references.js). They arrive after this scan's
    // takeover and exposure checks, so a name DNS confirms joins the inventory
    // now and gets those checks from the next scan's inventory re-check.
    if (modules.subdomains && typeof modules.subdomains === "object") {
      const pending = pendingPageReferences(domain, { candidates: [
        ...(modules.page_discovery?.hostname_references?.candidates || []),
        ...(modules.external_exposure?.hostname_references?.candidates || []),
      ] },
        [...(modules.subdomains.items || []), ...knownAssetHosts]);
      let pageReferences;
      if (!durableInvocation) {
        pageReferences = pageReferencesNotExecuted("invocation_not_durable");
      } else if (pending.length === 0) {
        pageReferences = pageReferencesNotExecuted("no_references");
      } else {
        const refRun = await runCappedModule("page_references", {
          estimateMs: PAGE_REFERENCE_LIMITS.budgetMs,
          hardMs: PAGE_REFERENCE_LIMITS.budgetMs,
          fallback: () => markDeadlineDeferred(pageReferencesNotExecuted("deadline_deferred", pending.length)),
          run: ({ accounting, signal }) => confirmPageReferences(pending, {
            wildcardAddresses: modules.subdomains.wildcard_dns_addresses,
            wildcardIpv6Addresses: modules.subdomains.wildcard_dns_ipv6_addresses,
            budget: discoveryBudget,
            accounting,
            signal,
            cache: dnsCache,
          }),
        });
        pageReferences = refRun.thrown ? pageReferencesNotExecuted("lookup_step_failed", pending.length) : refRun.value;
        const refTimedOut = pageReferences?.outcome === "deadline_exceeded";
        try {
          const refOutbound = refRun.thrown
            ? (() => { refRun.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("page_references"); })()
            : refTimedOut
            ? abandonOutbound(refRun.ctx, "page_references", refRun.startedMs != null ? "module_race" : "launch_gate")
            : settleOutboundValue(refRun.ctx, "page_references", pageReferences);
          telemetry.record("page_references", {
            outcome:        telemetry.outcomeOf(pageReferences),
            timeout:        refTimedOut,
            error_class:    refRun.thrown?.name || null,
            duration_ms:    refRun.durationMs,
            allocated_ms:   refRun.startedMs != null ? refRun.allocatedMs : 0,
            timeout_source: refTimedOut ? (refRun.startedMs != null ? "module_race" : "launch_gate") : null,
            outbound:       refOutbound,
            outbound_calls: refOutbound?.outbound_measurement_complete ? refOutbound.outbound_attempts_observed : null,
          });
        } catch { /* telemetry is observational only */ }
      }
      // What every discovery DNS question of this scan was spent on.
      modules.subdomains = { ...modules.subdomains, page_references: pageReferences, discovery_budget: discoveryBudget.snapshot() };
    }

    // Phase 7a-ii: Website Security findings from the site's own SIGN-IN pages
    // (engines/signin-page-findings.js) — only pages with an observed password
    // field. Pushed after computeScore, so they never move the CMS; they feed
    // the Website Security domain state, lifecycle, cases and alerts like any
    // other website finding. None when the page check did not run.
    try {
      for (const f of signInPageFindings(modules.page_discovery, { domain, checkedAt: new Date(now()).toISOString() })) findings.push(f);
    } catch { /* non-fatal: an observation must not break the scan */ }

    findings.push(...(modules.external_exposure?.findings || []));
    if (modules.tls_assessment) findings.push(...tlsAssessmentFindings(modules.tls_assessment));

    // Phase 7a-iii: is a website actually served? (engines/website-availability.js)
    // An observation only, built from the headers module's own home-page GET and
    // raised only on a conclusive 404/410 that stayed on this domain. Pushed
    // after computeScore, so it never moves the CMS.
    try {
      for (const f of homePageAvailabilityFindings(modules, { domain, checkedAt: new Date(now()).toISOString() })) findings.push(f);
    } catch { /* non-fatal: an observation must not break the scan */ }

    // Phase 7b: Signed-in scanning (engines/website-signed-in-scan.js). Only
    // for THIS scan's workspace, only with an active sign-in profile on a
    // verified domain of a live workspace with a paid plan or trial, durable
    // scans only, under its own cap. The result is workspace-private: it is
    // recorded on that workspace's sign-in attempt row and is deliberately
    // NOT placed in `modules` (the domain's shared scan report). It never sets
    // `incomplete` and never produces findings.
    if (workspaceId && durableInvocation && !reservedMode) {
      let prepared = null;
      try { prepared = await loadSignedInScanProfile(env, { workspaceId, domainId }); } catch { prepared = null; }
      if (prepared?.blocked) {
        try {
          await recordSignInAttempt(env, { workspaceId, domainId, profile: prepared.profile, source: "scan", scanId, outcome: prepared.blocked, coverage: "not_run" });
        } catch { /* non-fatal */ }
      } else if (prepared?.secret) {
        let { profile, secret } = prepared;
        prepared = null;
        // `progress.submitted` survives a module timeout, so a sign-in form that
        // was sent still counts toward the lock-out protection.
        const progress = { submitted: false };
        const notRun = (reason) => ({ source: "signed_in_scan", version: SIGNED_IN_SCAN_VERSION, sign_in: { outcome: "budget_exhausted", detail: progress.submitted ? { submitted: true } : {} }, coverage: "not_run", partial_reasons: [reason], counts: {}, pages: [] });
        let signedIn;
        if (!deadline.canRun(SIGNED_IN_SCAN_BUDGET_MS + PAGE_DISCOVERY_POST_TERMINAL_RESERVE_MS)) {
          signedIn = notRun("deadline_budget");
        } else {
          const run = await runCappedModule("signed_in_scan", {
            estimateMs: SIGNED_IN_SCAN_BUDGET_MS,
            hardMs: SIGNED_IN_SCAN_BUDGET_MS,
            fallback: () => notRun("module_budget_exhausted"),
            run: ({ accounting, signal, remainingMs }) => runSignedInScan(domain, profile, secret, {
              dnsResolver: dnsQuery, dnsCache, accounting, signal, remainingMs, progress,
            }),
          });
          signedIn = run.thrown ? notRun("module_failed") : (run.value || notRun("module_failed"));
          try {
            const timedOut = run.timedOut === true || Boolean(signedIn.timeout_source);
            const outbound = run.thrown
              ? (() => { run.ctx?.markIncomplete?.("module_error"); return outboundAccounting.snapshot("signed_in_scan"); })()
              : timedOut
              ? abandonOutbound(run.ctx, "signed_in_scan", run.startedMs != null ? "module_race" : "launch_gate")
              : settleOutboundValue(run.ctx, "signed_in_scan", { coverage: signedIn.coverage });
            telemetry.record("signed_in_scan", {
              outcome:        signedIn.sign_in?.outcome === "signed_in" ? "ok" : "skipped",
              timeout:        timedOut,
              error_class:    run.thrown?.name || null,
              duration_ms:    run.durationMs,
              allocated_ms:   run.allocatedMs,
              timeout_source: timedOut ? (signedIn.timeout_source || "module_race") : null,
              outbound,
              outbound_calls: outbound?.outbound_measurement_complete ? outbound.outbound_attempts_observed : null,
            });
          } catch { /* telemetry is observational only */ }
        }
        secret = null;
        try {
          await recordSignInAttempt(env, {
            workspaceId, domainId, profile, source: "scan", scanId,
            outcome: signedIn.sign_in?.outcome || "error", detail: signedIn.sign_in?.detail || {},
            coverage: signedIn.coverage, summary: signedInSummary(signedIn),
          });
        } catch { /* non-fatal — the next scan records it again */ }
      }
    }

/**
 * buildCanonicalUrlProfile(modules)
 *
 * Pure computation — synthesises a canonical URL profile from existing module data.
 * No additional network calls. Uses data already collected by runSslModule and
 * runHeadersModule (http_redirect_chain, final_url, status_code, redirect_count).
 *
 * Returns:
 *   { canonical_url, canonical_confidence, variants, profile_complete, built_at }
 */
function buildCanonicalUrlProfile(modules) {
  const ssl     = modules.ssl     || {};
  const headers = modules.headers || {};
  const domain  = modules._domain ?? "unknown";

  // Variant data derived from existing module observations
  const variants = [];

  // http://domain — from SSL module redirect chain
  const httpChain = ssl.http_redirect_chain || {};
  const httpFinalUrl = httpChain.final_url ?? null;
  variants.push({
    variant:                 "http_bare",
    requested_url:           httpChain.original_url   ?? `http://${domain}`,
    final_url:               httpFinalUrl,
    redirect_count:          httpChain.redirect_count  ?? 0,
    response_family:         httpChain.http_redirect_validated ? (httpChain.redirect_count > 0 ? "3xx" : "unknown") : "unavailable",
    is_canonical_candidate:  false,  // HTTP is not a canonical candidate
    probe_method:            "observed",
    note:                    httpChain.http_redirect_validated ? "HTTP redirect chain observed" : "HTTP probe blocked or unavailable",
  });

  // https://domain — from SSL module availability + headers final URL
  const tls = resolveTlsRuntimeState(ssl, { assessedDomain: modules?._domain ?? null });
  const httpsAvailable = tls.state === TLS_RUNTIME_STATES.OBSERVED_PRESENT;
  const httpsPositivelyAbsent = tls.state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT;
  const headersUrl     = headers.response_url ?? headers.original_url ?? null;
  const headersStatus  = headers.status_code  ?? null;
  const isWwwRedirect  = headersUrl ? headersUrl.includes("//www.") : false;
  variants.push({
    variant:                 "https_bare",
    requested_url:           `https://${domain}`,
    final_url:               headersUrl,
    status_code:             headersStatus,
    redirect_count:          headers.redirect_count ?? 0,
    response_family:         headersStatus != null
      ? (headersStatus < 300 ? "2xx" : headersStatus < 400 ? "3xx" : headersStatus < 500 ? "4xx" : "5xx")
      : "unavailable",
    headers_observed:        Object.keys(headers.values || {}).filter((k) => headers.values[k]),
    is_canonical_candidate:  httpsAvailable && !isWwwRedirect && headersStatus != null && headersStatus < 400,
    probe_method:            "observed",
    tls_state:               tls.state,
    note:                    headers.validation_uncertain
      ? "Response may be from bot-protection layer — headers not reliable"
      : httpsAvailable
        ? "HTTPS available"
        : httpsPositivelyAbsent
          ? "HTTPS positively absent"
          : "HTTPS availability could not be assessed",
  });

  // http://www.domain — inferred from redirect chain destinations
  // If http://domain redirected to a www. URL we know www exists.
  const httpRedirectsToWww = httpFinalUrl ? httpFinalUrl.includes("//www.") : false;
  const httpsRedirectsToWww = headersUrl ? headersUrl.includes("//www.") : false;
  const wwwInferred = httpRedirectsToWww || httpsRedirectsToWww;
  variants.push({
    variant:                 "http_www",
    requested_url:           `http://www.${domain}`,
    final_url:               wwwInferred ? (httpFinalUrl || headersUrl) : null,
    status_code:             null,
    redirect_count:          null,
    response_family:         wwwInferred ? "inferred_redirect" : "not_probed",
    is_canonical_candidate:  false,
    probe_method:            "inferred",
    note:                    wwwInferred
      ? "www variant inferred from redirect chain observation"
      : "www variant not directly probed in this scan",
  });

  // https://www.domain — canonical if isWwwRedirect from https://domain
  const wwwCanonicalUrl = isWwwRedirect ? headersUrl : null;
  variants.push({
    variant:                 "https_www",
    requested_url:           `https://www.${domain}`,
    final_url:               wwwCanonicalUrl,
    status_code:             isWwwRedirect ? headersStatus : null,
    redirect_count:          isWwwRedirect ? (headers.redirect_count ?? 0) : null,
    response_family:         isWwwRedirect
      ? (headersStatus != null ? (headersStatus < 400 ? "2xx_or_3xx" : "4xx_or_5xx") : "unknown")
      : "not_probed",
    is_canonical_candidate:  isWwwRedirect && headersStatus != null && headersStatus < 400,
    probe_method:            isWwwRedirect ? "observed_via_redirect" : "inferred",
    note:                    isWwwRedirect
      ? "https://domain redirected to www — www variant is likely canonical"
      : "www HTTPS not directly probed",
  });

  // Determine canonical_url
  let canonical_url        = null;
  let canonical_confidence = "low";

  if (httpsAvailable && headersUrl && headersStatus != null && headersStatus < 400) {
    canonical_url = headersUrl;
    canonical_confidence = headers.validation_uncertain ? "medium" : "high";
  } else if (httpChain.final_url) {
    canonical_url = httpChain.final_url;
    canonical_confidence = "low";
  }

  const profileComplete = httpsAvailable && headersUrl != null && !headers.validation_uncertain;

  // canonical_consistency_score (v5): 0-100
  // Starts at 100, deduct for each uncertainty signal.
  let consistencyScore = tls.state === TLS_RUNTIME_STATES.UNAVAILABLE ? null : 100;
  const deductConsistency = (amount) => {
    if (consistencyScore != null) consistencyScore -= amount;
  };
  if (httpsPositivelyAbsent)                    deductConsistency(25);  // approved positive absence
  if (headers.validation_uncertain)             deductConsistency(20);  // bot-protection interference
  if (!httpChain.http_redirect_validated)       deductConsistency(15);  // HTTP probe failed
  if (canonical_confidence === "low")           deductConsistency(15);  // low confidence canonical
  if (isWwwRedirect && httpsPositivelyAbsent)   deductConsistency(10);  // www redirect but positively absent HTTPS
  if (!canonical_url)                           deductConsistency(15);  // cannot determine canonical
  consistencyScore = consistencyScore == null ? null : Math.max(0, consistencyScore);

  return {
    canonical_url,
    canonical_confidence,
    tls_state: tls.state,
    canonical_consistency_score: consistencyScore,
    variants,
    profile_complete: profileComplete,
    http_redirects_to_https:    ssl.http_redirects_to_https ?? null,
    http_redirect_validated:    httpChain.http_redirect_validated ?? false,
    validation_uncertain:       headers.validation_uncertain ?? false,
    built_at:                   new Date().toISOString(),
  };
}

    // Phase 7b: Admin surface detection — pure fingerprint pass over HTTP probe
    // results already collected by runExposureModule.  Zero additional I/O.
    modules.attack_surface_signal_completeness =
      deriveAttackSurfaceSignalCompleteness(modules);

    // Phase 7b-ii: Canonical URL profile — pure computation from existing SSL/headers data.
    modules._domain = domain;
    modules.canonical_url_profile = buildCanonicalUrlProfile(modules);

    // Phase 7d: Scan budget — pure computation, zero I/O.
    // Estimates subrequest usage across all modules and warns if close to the
    // Cloudflare Worker free-plan 50-subrequest limit.
    modules.scan_budget = computeScanBudget(bruteforceResult.checked);
    if (reservedPhysicalCounter) {
      modules.scan_budget.physical = reservedPhysicalCounter.snapshot();
    }
    // The scan's PERSISTED observation anchor. `scans.created_at` is written once by
    // the DB default at row creation and never recomputed, so it survives a
    // persistence-failure retry BY CONSTRUCTION rather than by luck — unlike the
    // deadline start, which is recreated on every invocation. Read once here and
    // threaded down, so a degradation observed during this scan is stamped with when
    // the scan was observed, which is what the field claims to mean.
    let persistedObservationAnchor;
    try {
      const scanRow = await env.cybermeters_db
        .prepare("SELECT created_at FROM scans WHERE id = ?")
        .bind(scanId)
        .first();
      const raw = scanRow?.created_at;
      // SQLite CURRENT_TIMESTAMP is "YYYY-MM-DD HH:MM:SS" (UTC, no zone marker).
      if (typeof raw === "string" && raw.length > 0) {
        const parsed = new Date(raw.includes("T") ? raw : `${raw.replace(" ", "T")}Z`);
        if (!Number.isNaN(parsed.getTime())) persistedObservationAnchor = parsed.toISOString();
      }
    } catch { persistedObservationAnchor = undefined; }
    // F-026: pass the resolved effective capacity so scan_quality reports the
    // real per-scan limit, not the platform ceiling. resolveScanCapacity is a
    // pure read of env — never guessed.
    const scanQuality = buildScanQuality(modules, persistedObservationAnchor, resolveScanCapacity(env));
    // PR-5.4: backend-owned within-scan monitoring truth. No new probe,
    // scan-quality rule or scoring input is introduced.
    const monitoringStates = deriveSignalMonitoringStates({
      modules,
      scanQuality,
    });

    // Trend eligibility (partial-scan honesty): only a COMPLETE assessment is a
    // comparable trend point. A partial/degraded/unknown current scan must never
    // produce a score delta (improved/declined/+N), so suppress its own report's
    // score_change here — the single central gate feeding the report, scan-detail,
    // and the executive-report trend direction.
    if (modules.historical_changes && !phase5CustomerAssessment.evidence.complete) {
      modules.historical_changes.current_score = null;
    }

    // Phase 7e: Vendor Risk — pure computation, zero I/O.
    // Detects third-party vendors from signals already captured in modules:
    // SPF, MX, NS, DKIM, CSP, Server header, CNAME targets, tech detection.
    modules.vendor_risk = detectVendorsFromModules(modules);
    findings.push(...dnsServiceRegistrationObservations(modules, {
      domain, checkedAt: startedAt, verified: registrationScopeVerified,
    }));
    findings.push(...brandWatchlistDnsObservations(modules.brand_monitoring, {
      domain, checkedAt: startedAt, verified: registrationScopeVerified,
    }));
    if (!registrationScopeVerified && modules.technology_detection) modules.technology_detection.script_observations = null;
    findings.push(...websiteScriptFindings(modules.technology_detection, { domain, verified: registrationScopeVerified }));

    // Phase 7f: Third-Party Asset Discovery — pure computation, zero I/O.
    // Business-focused SaaS inventory derived from vendor_risk.  Excludes
    // infrastructure/cloud/hosting; remaps to email/crm/collaboration/support/
    // marketing/ecommerce taxonomy.
    modules.third_party_assets = runThirdPartyDiscoveryModule(modules);

    // Phase 7g: SaaS Exposure Discovery — pure computation, zero I/O.
    // Cross-references vendor_risk detections with known portal/tenant patterns to
    // identify externally accessible SaaS portals, admin interfaces and tenant URLs.
    modules.saas_exposure = runSaasExposureModule(modules);

    // Phase 7h: Certificate Intelligence — pure computation, zero I/O.
    // Reads the live TLS certificate attached to modules.ssl and the discovered
    // hostnames to produce expiry status and the suspicious signal list.
    modules.certificate_intelligence = runCertificateIntelligenceModule(
      modules,
      domain,
      {
        monitoringStates,
        observedAt: startedAt,
        nowMs: certificateNowMs,
        engineVersion: env.APP_VERSION ?? "unknown",
      },
    );
    if (modules.dns) {
      modules.dns.operational_resilience = buildDnsOperationalResilience({
        nameservers: modules.dns.nameservers || [],
        dnssec: modules.dns.dnssec || null,
        certificateAuthority: buildCertificateAuthorityConcentrationFromModule(modules.certificate_intelligence),
      });
    }

    // Certificate findings come only from the live TLS collector and retain exact
    // endpoint/certificate evidence. No HTTP-only signal may enter this admission
    // path or claim peer validation.
    for (const signal of liveCertificateFindings(modules.ssl, domain)) {
      if (findings.some(finding => finding.id === signal.signal)) continue;
      findings.push({ ...signal, id: signal.signal, module: 'certificate_intelligence' });
    }

    if (modules.historical_changes) {
      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );
      modules.historical_changes = applyScanComparability(
        modules.historical_changes,
        scanQuality.status === "complete",
        scanQuality.status,
      );
    }

    // Phase 7i: brand_monitoring already populated in modules before computeScore —
    // see module initialisation block above. No re-run needed here.

    // Phase 7j: Identity Asset Discovery — pure computation, zero network I/O.
    // Identifies authentication surfaces, login portals, SSO/OAuth/SAML endpoints
    // and identity provider relationships from signals already captured in Phases 1–7i.
    // Detects Okta, Auth0, Entra ID, Ping Identity, OneLogin, Duo, JumpCloud, Keycloak,
    // ADFS, and Google Workspace IdP from CNAME/SPF/MX/CSP/server signals.
    // Also classifies discovered subdomains with identity-related hostname prefixes.
    const identityObservedAt = new Date(now()).toISOString();
    modules.identity_discovery = runIdentityDiscoveryModule(
      modules,
      domain,
      { observedAt: identityObservedAt },
    );
    modules.identity_discovery.openid_connect = oidcMetadata;
    findings.push(...oidcMetadataFindings(oidcMetadata, { domain, verified: registrationScopeVerified }));

    // Phase 7k: Vendor Relationship Discovery — pure computation, zero network I/O.
    // Parses CSP directives (script-src, connect-src, frame-src, img-src) to identify
    // third-party vendor relationships from JavaScript, API, and iframe dependencies.
    // Uses CNAME signals for high-confidence DNS-level confirmation.
    // 10-category taxonomy: analytics | payments | crm | support | identity |
    //   collaboration | cloud | cdn | security | certificate_authority
    modules.vendor_relationships = runVendorRelationshipModule(modules);

    const completedAt = new Date(now()).toISOString();

    // Sprint 9A: Normalise all findings to v2 schema before report assembly.
    // Additive only — existing fields are preserved; missing fields default to
    // null / [] so every finding exposes a consistent shape to consumers.
    // Every finding names the check (and check-pack version) that produced it.
    const normalizedFindings = findings.map(normalizeFindingSchema)
      .map((finding) => (finding && typeof finding === "object" && !finding.check
        ? { ...finding, check: checkForFinding(finding) }
        : finding));
    const managedAsmFindings = normalizedFindings.filter((finding) => {
      if (!isActionableFinding(finding)) return false;
      const isDomainSecurityEnrichment =
        finding?.module === "domain_security_enrichment"
        || String(finding?.id || "").startsWith("dse_");
      if (!isDomainSecurityEnrichment) return true;
      const domainKeys = SECURITY_CHECK_DOMAINS
        .filter((definition) => definition.match(finding))
        .map((definition) => definition.domain_key);
      return domainKeys.length === 1 && domainKeys[0] === "attack_surface";
    });

    // Item 7 P3: seal the one canonical DMARCbis protocol object before the
    // immutable scan report is written. The snapshot copies this same object;
    // the fingerprint excludes only itself and is reused by lifecycle refs.
    modules.dmarc_core = await sealDmarcPolicyEvidence(modules.dmarc_core);

    // Build full structured report
    const report = {
      scan_id:             scanId,
      domain_id:           domainId,
      domain,
      status:              "completed",
      cyber_metrics_score: customerScore,
      risk_level:          customerRiskLevel,
      started_at:          startedAt,
      completed_at:        completedAt,
      findings:            normalizedFindings,
      recommendations,
      scan_quality:         scanQuality,
      monitoring_states:    monitoringStates,
      timeline_trust:       buildAssetTimelineTrustMetadata(),
      // The check pack (rules, outside sources, what is not checked) in force.
      check_pack:           checkPackSummary(),
      modules,
    };

    // Backfill telemetry rows for tracked modules not captured by the live wrapper
    // (reserved-mode results, cloud-storage, deferred phases) so both scan modes get
    // full per-module coverage; derive a coarse outcome from the final module value.
    for (const name of TELEMETRY_TRACKED_MODULES) {
      if (!telemetry.has(name)) telemetry.record(name, { outcome: telemetry.outcomeOf(modules[name]) });
    }

    // PR-A1: additive execution diagnostics — versioned, R2-only, built AFTER the
    // telemetry backfill so both scan modes get full module coverage. No runtime
    // consumer reads this block; scan_quality/events/alerts are untouched.
    report.execution_diagnostics = buildExecutionDiagnostics({
      executionContext,
      trigger,
      deadline,
      telemetry,
    });

    // Heartbeat: entering finalization. A cancellation after this is a finalize-time
    // failure (the reconciler is the backstop), not a mid-scan orphan.
    await heartbeatScan(env, scanId, "finalizing", telemetry.rows.filter((r) => r.outcome === "ok").length);

    // Finalize: write the completed report to R2 and flip the D1 status. report.status
    // stays "completed"; scan_quality.status carries "partial" when the deadline
    // deferred any module (honest partial finalization). finalizeScanResult never
    // throws and only reaches "finalized" when BOTH writes are durable.
    const finalizeStartedMs = now();
    const finalized = await finalizeScanResult(latch, {
      scanId, report, score: customerScore, rating: customerRiskLevel, status: "completed", env,
      workspaceId,
      deadline: durableInvocation ? deadline : null,
    });
    if (!finalized.finalized) {
      if (durableInvocation && deadline.totalExceeded()) {
        return invocationCeilingResult("terminal_finalization");
      }
      // A terminal write did not durably land. Do NOT silently continue with a
      // half-written state — throw into the failure path, which (downgrade-safe)
      // preserves a durable completed R2 report and retries the D1 status, or writes
      // a consistent 'failed' terminal if the report never persisted. Either way the
      // scan never remains 'running'.
      throw new Error(`scan finalization incomplete: ${JSON.stringify(finalized.errors || {})}`);
    }

    // PR-A1: finalisation wall time (terminal R2 put + D1 status write). The R2
    // report is frozen BEFORE finalize completes, so this lands as a D1-only
    // pseudo-row in scan_module_telemetry using the EXISTING columns — no schema
    // change. It is not in TELEMETRY_TRACKED_MODULES, so the backfill never
    // duplicates it, and it is purged with the scan via SCAN_CHILD_TABLES.
    telemetry.record("scan_finalisation", { outcome: "ok", duration_ms: now() - finalizeStartedMs });

    // Everything below is post-terminal, best-effort projection/persistence. A
    // durable Queue/Cron invocation must return at its total ceiling even when a
    // non-critical dependency stalls. The terminal R2+D1 pair above remains the
    // authoritative, separately bounded result; abandoning this local promise
    // cannot mutate the already-frozen report or downgrade the finalized latch.
    const runPostTerminalWork = async () => {
    // Persist per-module telemetry (non-fatal; after the terminal status is written
    // so a telemetry failure can never leave the scan 'running').
    await persistModuleTelemetry(scanId, telemetry, env);
    // Track B sub-operation rows ride the SAME channel as scan_module_telemetry
    // pseudo-rows (dotted module names, existing columns — no schema change), but
    // through ONE bounded batch, never the per-row insert loop. Snapshot AFTER
    // terminal finalization so a sub-operation still in flight from a
    // race-abandoned module reads honestly as `aborted`.
    await persistSubOperationTelemetry(scanId, subOpTelemetry.snapshotRows(), env);

    // Shared by the 091 state persistence below AND the M5.c snapshot build
    // (Phase 8o): both must resolve the eight domains from the SAME Cyber
    // Essentials snapshot, or the snapshot could disagree with the persisted
    // per-domain state rows for the same scan.
    let ceSnap = null;

    if (workspaceId) {
      // Compute BRS using scan findings + workspace intelligence data
      let brsScore = null;
      // Only complete evidence may establish a canonical BRS trend point. A partial
      // scan still gets its technical score/history row, but brs_score remains NULL:
      // missing findings are not evidence of health.
      if (scanQuality?.status === "complete") try {
        const findingIds = expandFindingIds(findings.filter(isActionableFinding));
        const [brandRows, vendorRows] = await Promise.all([
          env.cybermeters_db
            .prepare(`SELECT risk_level, COUNT(*) AS n FROM workspace_brand_assets WHERE workspace_id = ? AND dns_resolves = 1 AND status = 'active' GROUP BY risk_level`)
            .bind(workspaceId).all(),
          env.cybermeters_db
            .prepare(`SELECT risk_level, COUNT(*) AS n FROM workspace_vendors WHERE workspace_id = ? AND status = 'active' AND source_module = 'vendor_risk' GROUP BY risk_level`)
            .bind(workspaceId).all(),
        ]);
        const brandMap  = Object.fromEntries((brandRows.results  ?? []).map(r => [r.risk_level, r.n]));
        const vendorMap = Object.fromEntries((vendorRows.results ?? []).map(r => [r.risk_level, r.n]));
        const vendorTotal = (vendorRows.results ?? []).reduce((s, r) => s + r.n, 0);
        const brs = computeBusinessRiskScore(findingIds, {
          brandHighRisk:        brandMap.high   ?? 0,
          brandMedRisk:         brandMap.medium ?? 0,
          brandLowRisk:         brandMap.low    ?? 0,
          vendorHigh:           vendorMap.high   ?? 0,
          vendorMedium:         vendorMap.medium ?? 0,
          vendorTotal,
          identityHighRiskCount: modules.identity_discovery?.high_risk_count ?? 0,
          vendorRelHighConf:     modules.vendor_relationships?.high_confidence ?? 0,
          hstsMissingSeverity:   hstsMissingSeverity(findings.filter(isActionableFinding)),
        });
        brsScore = brs.brs;
      } catch { /* non-fatal — BRS unavailable for this scan */ }

      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO historical_scores
               (id, workspace_id, domain_id, scan_id, domain, score, rating, brs_score, scan_quality, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(createId("hscore"), workspaceId, domainId, scanId, domain, customerScore, customerRiskLevel, brsScore, scanQuality?.status ?? null, completedAt)
          .run();
      } catch { /* non-fatal — scan completion remains source of truth */ }

      // Canonical workspace Business Risk (M5.e): computed + persisted here —
      // at scan cadence, never page-view cadence — so GET /business-risk is a
      // pure read that can never diverge from the persisted canonical value.
      // Non-fatal by the 091 doctrine.
      try {
        await computeAndPersistWorkspaceBrs(env, workspaceId, {
          scanId,
          scanQuality: scanQuality?.status,
          assessedAt: completedAt,
        });
      } catch { /* non-fatal — BRS refreshes on the next finalized scan */ }

      // Canonical eight-domain state history (mig 091). Resolved from the report ALREADY
      // in memory, so this costs zero R2 reads here and zero R2 reads on every portfolio
      // page load forever after — the whole reason the table exists.
      //
      // After the terminal status write and non-fatal by construction: this is a record
      // of a decision, and a scan that completed must never be reported as failed because
      // recording it did not. A missing row reads as not_yet_assessed, which is honest;
      // a scan stuck at 'running' is not.
      //
      // The CE snapshot is one D1 query in the common case — getCyberEssentialsSnapshot
      // short-circuits on a workspace with no questionnaire answers and only runs the
      // heavier readiness build once the questionnaire is COMPLETE.
      try {
        try { ceSnap = await getCyberEssentialsSnapshot(workspaceId, env); } catch { ceSnap = null; }
        await persistSecurityCheckDomainStates(env, {
          workspaceId, domainId, scanId, report, cyberEssentials: ceSnap, assessedAt: completedAt,
        });
      } catch { /* non-fatal — see above */ }

      // Canonical per-workspace eight-domain maturity ledger (M5.f). Layered on the SAME
      // resolved states + CE snapshot + completedAt as the 091 write above, so maturity,
      // domain state and the M5.c snapshot can never disagree for one scan. Eligible
      // COMPLETE scans only (partial evidence writes nothing); append-only; idempotent.
      // Non-fatal by the 091 doctrine — recording maturity must never fail a completed scan.
      try {
        await persistDomainMaturity(env, {
          workspaceId, domainId, scanId, report, cyberEssentials: ceSnap, assessedAt: completedAt,
        });
      } catch { /* non-fatal — a missing row reads as not_established, which is honest */ }
    }

    // Forward-only D1 identity: historical rows remain untouched. The shared writer
    // verifies the scan belongs to this active workspace before the first insert.
    await persistFindingsWithIdentity(env, { scanId, workspaceId, findings });

    // Persist remediation items to D1
    for (const r of recommendations) {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO remediation_items (id, scan_id, priority, title, reason, action)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(
          createId("rem"),
          scanId,
          String(r.priority),
          r.title,
          r.module,
          r.description
        )
        .run();
    }

    // P2 DMARCbis lifecycle reuse: establish only non-alertable baselines in
    // migration 088's existing Email Protection occurrence source. P4 owns
    // customer timeline transitions; P5 owns alerts and case eligibility.
    // The terminal R2 report is already durable, so detail stores only bounded
    // references/fingerprints and never duplicates raw DNS evidence in D1.
    try {
      await establishDmarcPolicyBaseline(env, {
        workspace_id: workspaceId,
        domain_id: domainId,
        domain,
        scan_id: scanId,
        policy_evidence: modules.dmarc_core,
      });
    } catch { /* non-fatal — baseline catches up on the next complete scan */ }

    // Phase 8: Asset Inventory Upsert — runs AFTER completion status is written.
    // Failure here cannot leave the scan stuck in "running".
    // Uses D1 batch() to minimise round-trips.
    // Only the scanning workspace's inventory is written; each name carries
    // where it was seen and this scan's evidence for it.
    let assetEvidence = null;
    try {
      const assetHints = collectAssetHints(domain, modules, evidenceHints);
      assetEvidence = buildScanAssetEvidence({ domain, modules, findings: normalizedFindings, hints: assetHints });
      await upsertAssetInventory(scanId, domainId, domain, modules, env, {
        currentReport: report,
        observedAt: completedAt,
        workspaceId,
        hints: assetHints,
        assetEvidence,
      });
      await persistAttackSurfaceLifecycle({
        env,
        scanId,
        domainId,
        domain,
        workspaceId,
        signalCompleteness: modules.attack_surface_signal_completeness,
        assetExposure: modules.asset_exposure,
        assetEvidence,
        observedAt: completedAt,
      });
    } catch { /* non-fatal — inventory update will catch up on next scan */ }

    // Phase 8a.-1: alert monitoring start. Before any phase below can alert, the
    // first scan of each workspace on this domain writes its eight alert
    // watermarks, held in the future; the hold is released after Phase 8p. What
    // this first pass observes is pre-existing state and never alerts; every
    // later new condition does (engines/managed-alerts.js, monitoring start).
    let monitoringStarted = [];
    try {
      const monitoringRows = await env.cybermeters_db
        .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
        .bind(domainId).all();
      monitoringStarted = await beginAlertMonitoring(env, [
        ...(workspaceId ? [workspaceId] : []),
        ...(monitoringRows?.results || []).map((row) => row.workspace_id),
      ]);
    } catch { monitoringStarted = []; /* the lazy watermark still applies */ }

    // A domain's first scan in a workspace raises no alert: its findings already
    // existed before CyberMeters looked at the domain (managed-alerts.js, 2a).
    // The phases below get their own env copy carrying the held workspaces.
    const firstScanHold = new Set();
    try {
      const linked = [...new Set([...(workspaceId ? [workspaceId] : []), ...monitoringStarted.map((pair) => pair.workspace_id)])];
      const workspaceRows = await env.cybermeters_db
        .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?").bind(domainId).all();
      for (const id of new Set([...linked, ...(workspaceRows?.results || []).map((row) => row.workspace_id)])) {
        const earlier = await env.cybermeters_db.prepare(
          `SELECT 1 AS seen FROM scans WHERE workspace_id = ? AND domain_id = ? AND id <> ? AND status = 'completed' LIMIT 1`,
        ).bind(id, domainId, scanId).first();
        if (!earlier) firstScanHold.add(id);
      }
    } catch { /* unknown: the watermark still applies */ }
    const phaseEnv = firstScanHold.size ? { ...env, ALERT_FIRST_SCAN_HOLD: firstScanHold } : env;

    // Phase 8a.0: Managed ASM cases — opens cases for new exposure findings,
    // verifies customer-completed fixes against the fresh scan, and reopens
    // resolved cases when the same finding returns. Reuses scan evidence only.
    try {
      await createManagedAsmCasesForScan(scanId, domainId, domain, managedAsmFindings, recommendations, phaseEnv);
      // Cases opened from a claim the current rule no longer makes are resolved
      // as withdrawn, judged on their own originating evidence.
      await withdrawSupersededAsmClaims(phaseEnv, { domainId });
      await verifyManagedAsmCasesForScan(scanId, domainId, domain, normalizedFindings, env, {
        modules,
        scanQuality,
        // This hook runs only after the terminal R2 report and completed D1
        // status are durable. P3 lifecycle verification must never infer this
        // from "the engine returned"; publishability is explicit.
        scanPublished: true,
        observedAt: completedAt,
      });
    } catch { /* non-fatal — managed cases catch up on the next scan */ }

    // Phase 8a.1: Posture Timeline Events — cross-scan email-auth and exposed
    // service diffs. Uses previous completed scan report from R2 as baseline.
    try {
      await recordPostureEvents(scanId, domainId, domain, modules, phaseEnv, { currentReport: report });
    } catch { /* non-fatal — posture events catch up on next scan */ }

    // Phase 8a.2: SPF-RUA corroboration (PR-B) — cross-checks this scan's freshly
    // resolved SPF PASS-authorisation set against the domain's recent DMARC-RUA
    // fail-sources and raises a canonical alert for an OBSERVED failure from a
    // source outside the authorised set. Only fires firm wording when the
    // resolution is complete; fails safe otherwise. Non-fatal.
    try {
      await recordSpfRuaCorroboration(scanId, domainId, domain, modules, phaseEnv);
    } catch { /* non-fatal — corroboration catches up on the next scan */ }

    // Phase 8b: Admin Surface Events — one asset_event per detected service per workspace.
    // Runs after upsertAssetInventory so workspace_assets rows are already present,
    // allowing asset_id FK resolution.
    try {
      await insertAdminSurfaceEvents(scanId, domainId, modules.admin_surface_detection, phaseEnv, { currentReport: report });
    } catch { /* non-fatal */ }

    // Phase 8c: Vendor Inventory Upsert — persists vendor_risk detections to D1.
    // Uses workspace lookup internally. Preserves first_seen; marks unseen vendors inactive.
    try {
      await upsertVendorInventory(domainId, modules.vendor_risk, phaseEnv);
    } catch { /* non-fatal */ }

    // Phase 8d: Certificate Events — fires asset_events for sensitive
    // discovered hosts, expiry warnings, and growth signals.
    try {
      await insertCertificateEvents(scanId, domainId, modules.certificate_intelligence, phaseEnv, { currentReport: report, now: () => certificateNowMs });
    } catch { /* non-fatal */ }

    // Phase 8d.1: Certificate Timeline — persists cross-scan certificate
    // observations and emits alerts for new certs, SANs, and issuers.
    try {
      await upsertCertificateObservation(scanId, domainId, modules.certificate_intelligence, phaseEnv, { currentReport: report, now: () => certificateNowMs });
    } catch { /* non-fatal */ }

    // Phase 8e: Brand Asset Upsert — persists generated typosquat candidates to
    // workspace_brand_assets as 'unverified'.  DNS validation happens separately
    // (hourly brand-dns-enrichment sweep, daily HTTPS enrichment, manual
    // /brand-monitoring/refresh); the NEXT scan reads that state back into its
    // brand decision through loadBrandValidationState above.
    try {
      await upsertBrandAssets(domainId, modules.brand_monitoring, phaseEnv);
    } catch { /* non-fatal */ }

    // Phase 8f: Identity Asset Upsert — persists identity_discovery results into
    // identity_assets table. Also upserts detected IdP providers into workspace_vendors.
    try {
      await upsertIdentityAssets(domainId, scanId, modules.identity_discovery, phaseEnv);
    } catch { /* non-fatal */ }

    // Phase 8g: Vendor Relationship Upsert — persists CSP-derived vendor relationships
    // into workspace_vendors with source_module='vendor_relationship'. Additive to
    // Phase 8c (DNS-sourced vendor_risk entries) — no inactive sweep here.
    try {
      await upsertVendorRelationships(domainId, modules.vendor_relationships, phaseEnv);
    } catch { /* non-fatal */ }

    // Phase 8h: Vendor Risk Score Upsert — calculates workspace-level vendor
    // exposure scores from current workspace_vendors rows.
    try {
      await recomputeVendorRiskScoresForDomain(domainId, phaseEnv);
    } catch { /* non-fatal */ }

    // Phase 8i: Supply Chain Intelligence — computes and persists supply chain
    // risk scores, concentration analysis, and cascading risk scenarios per workspace.
    // Runs after all vendor phases so it sees the full vendor picture.
    try {
      const scWsRows = await phaseEnv.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (scWsRows.results || [])) {
        const scPayload = await computeSupplyChainIntelligence(workspace_id, phaseEnv);
        await upsertSupplyChainScore(workspace_id, scPayload, phaseEnv);
      }
    } catch { /* non-fatal */ }

    // Phase 8j: Shadow IT approved inventory — correlate the workspace's active
    // vendor observations (+ ephemeral SaaS portal URLs) into the canonical
    // externally-observed technology inventory. Soft-deleted workspaces are
    // skipped inside correlateShadowItInventory. Non-fatal.
    try {
      const siWsRows = await phaseEnv.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (siWsRows.results || [])) {
        await correlateShadowItInventory(phaseEnv, workspace_id, { saasExposure: modules.saas_exposure, subdomainDiscovery: modules.subdomains || { executed: false } });
      }
    } catch { /* non-fatal — inventory catches up on the next scan */ }

    // Phase 8k: Certificate Managed Lifecycle — correlate the raw certificate
    // observations (mig 031) into the canonical managed lifecycle record: pick
    // the current cert per host, detect replacement (old evidence preserved),
    // assess renewal readiness + coverage, and run the monitoring evaluator.
    // Soft-deleted workspaces are skipped inside correlateCertificateLifecycle.
    try {
      const clWsRows = await phaseEnv.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (clWsRows.results || [])) {
        await correlateCertificateLifecycle(phaseEnv, workspace_id, { now: startedAt });
      }
    } catch { /* non-fatal — lifecycle catches up on the next scan */ }

    // Phase 8l: Identity Exposure Managed Workflow — correlate the raw
    // identity_assets (mig 030) into the canonical managed identity-exposure
    // record: one record per external identity surface, provider/endpoint change
    // detection (old evidence preserved), externally-observable risk + the
    // monitoring evaluator. Soft-deleted workspaces are skipped inside
    // correlateIdentityExposure. Non-fatal.
    try {
      const ieWsRows = await phaseEnv.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (ieWsRows.results || [])) {
        await correlateIdentityExposure(phaseEnv, workspace_id);
      }
    } catch { /* non-fatal — lifecycle catches up on the next scan */ }

    // Phase 8m: Website Security Managed Lifecycle — correlate THIS scan's website
    // findings into the canonical per-condition record + append-only history, and
    // alert on genuine transitions.
    //
    // It takes `normalizedFindings` rather than re-reading D1 deliberately: the
    // findings INSERT above binds createId("finding") and DROPS the canonical slug
    // (`header_missing_strict_transport_security`), so D1 cannot answer "is this the
    // same condition as last scan?" at all. The in-memory findings still carry it —
    // the same reason createManagedAsmCasesForScan is handed them.
    //
    // `modules` + `scanQuality` are passed because absence only means "fixed" when
    // the detecting module provably ran; without them a timed-out probe would read
    // as the customer fixing it. Soft-deleted workspaces are skipped inside the
    // evaluator. Non-fatal.
    try {
      const wsWsRows = await phaseEnv.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (wsWsRows.results || [])) {
        await evaluateWebsiteSecurityForScan(phaseEnv, {
          workspace_id, domain_id: domainId, domain, scan_id: scanId,
          findings: normalizedFindings, modules, scanQuality,
        });
      }
    } catch { /* non-fatal — lifecycle catches up on the next scan */ }

    // Phase 8m-ii: Website important-page inventory (migration 115). Persists
    // THIS scan's page observations for each workspace that owns the domain and
    // has it verified (checked inside). Non-fatal; never touches findings.
    try {
      if (modules.page_discovery?.source === "page_discovery") {
        const pageWsRows = await phaseEnv.cybermeters_db
          .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
          .bind(domainId)
          .all();
        for (const { workspace_id } of (pageWsRows.results || [])) {
          // One workspace failing must not stop the others.
          try {
            await persistWebsitePagesForScan(phaseEnv, {
              workspace_id, domain_id: domainId, domain, scan_id: scanId,
              discovery: modules.page_discovery,
            });
          } catch { /* non-fatal for this workspace */ }
        }
      }
    } catch { /* non-fatal — the next scan records the pages again */ }

    // Phase 8n: Cyber Essentials external-evidence lifecycle — re-assess the
    // workspace's externally evidenced control-theme readiness now that a new scan
    // has landed, and alert on genuine readiness transitions.
    //
    // Runs AFTER 8m so the scan's own evidence is in place. It reads the workspace's
    // latest completed scan itself (buildCyberEssentialsReadiness), so it needs no
    // findings passed in. CE had no evaluator anywhere before this — no cron task and
    // no scan hook — which is why its verdict was compute-on-read only.
    //
    // Non-fatal.
    try {
      const ceWsRows = await phaseEnv.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (ceWsRows.results || [])) {
        await evaluateCyberEssentialsLifecycle(phaseEnv, workspace_id, { scanId });
      }
    } catch { /* non-fatal — readiness catches up on the next scan */ }

    // Phase 8o: Canonical reporting snapshot (M5.c) — one completed security check →
    // one immutable eight-domain snapshot (D1 index + R2 JSON). Runs AFTER the
    // lifecycle/case phases (8a, 8k–8n) so the managed-workflow summaries and
    // case linkage it freezes include THIS scan's own case activity. Uses the
    // SAME in-memory report and the SAME ceSnap as the 091 state persistence,
    // so snapshot domains and cyber_mot_domain_states rows for one scan can
    // never disagree.
    //
    // Non-fatal by construction (the 091 doctrine): a scan that completed must
    // never be reported as failed because recording it did not. A failed build
    // leaves a visible 'failed' row, retried by the snapshot read route's
    // repair-on-read (the stuck-scan reconciler precedent); an absent snapshot
    // reads as "no snapshot", which is honest.
    //
    // Known duplicate cost, accepted for M5.c: the builder re-runs
    // buildCyberEssentialsReadiness (~3 D1 + up to 2 R2 reads) that Phase 8n's
    // lifecycle evaluator just ran, because 8n does not return it. Threading it
    // through is a ce-lifecycle contract change — deferred to the M5.g CI/cost
    // closure rather than smuggled in here.
    if (workspaceId) {
      try {
        await buildScanReportSnapshot(env, {
          workspaceId, domainId, scanId, domain, report,
          cyberEssentials: ceSnap, assessedAt: completedAt,
        });
      } catch { /* non-fatal — the snapshot row records its own failure reason */ }
    }

    // Phase 8p: DMARCbis immutable lifecycle comparison. P4 reads the current
    // snapshot written above and its append-only predecessor through the one
    // integrity-gated snapshot reader. It appends only bounded evidence
    // pointers/fingerprints to migration 088; raw DNS remains in R2.
    //
    // P5 may alert only on the five founder-approved complete actionable
    // descriptors returned by that write. The alert resolver re-reads the
    // append-only occurrence before publishing. It never opens a case.
    // Separately, awaiting-verification DMARC cases may be verified only by this
    // scan's later, integrity-verified, whole-scan-complete DNS snapshot. Neither
    // path reads RUA reports or treats scan completion alone as verification.
    // Failed/missing snapshots and incomplete components suppress honestly.
    if (workspaceId) {
      try {
        const dmarcLifecycle = await recordDmarcPolicyLifecycle(phaseEnv, {
          workspace_id: workspaceId,
          domain_id: domainId,
          domain,
          scan_id: scanId,
        });
        await emitDmarcPolicyAlerts(phaseEnv, {
          workspace_id: workspaceId,
          lifecycle_result: dmarcLifecycle,
        });
      } catch { /* non-fatal — the next complete pair can establish continuity */ }
      try {
        await verifyDmarcPolicyCasesForScan(phaseEnv, {
          workspace_id: workspaceId,
          domain_id: domainId,
          scan_id: scanId,
        });
      } catch { /* non-fatal — only a later complete re-observation may verify */ }
    }

    // Phase 8q: release the monitoring-start hold written in Phase 8a.-1. If this
    // fails, the hold still expires on its own (MONITORING_START_HOLD).
    try { await finishAlertMonitoring(env, monitoringStarted); } catch { /* self-expiring */ }

    // Phase 8x: M6 Phase B1 Related Changes — deterministic same-entity/same-window
    // correlation over the change-event producers written by the phases above. Runs
    // AFTER the lifecycle/case phases (8a, 8k–8p) so it sees this scan's producer rows.
    // The canonical snapshot is already durable; the existing report route freezes
    // Related Changes separately in the snapshot row's related_changes_json sidecar.
    // It reads only existing producer rows (adapter, no table moves), correlates with
    // registered deterministic rules, and persists clusters + evidence POINTERS
    // (mig 098). No automatic case or alert is created (design §8) — the rule decides,
    // the customer confirms. Runs only on a complete scan with a complete previous scan
    // (the posture-events evidence floor). Non-fatal.
    try {
      const rcWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (rcWsRows.results || [])) {
        await correlateRelatedChanges(env, {
          workspaceId: workspace_id, domainId, scanId,
          scanQuality: scanQuality?.status, assessedAt: completedAt,
        });
      }
    } catch (err) {
      // Non-fatal — correlation catches up on the next scan. But a silent failure must
      // still be VISIBLE to operators, so emit ONE sanitized line. It carries only the
      // scan id (the operational correlation key) and the error TYPE — never the error
      // message (which could carry a D1/query fragment), never raw evidence, customer
      // data or internal rule thresholds. Routed through redactedJson as a backstop, and
      // itself wrapped so logging can never break finalize.
      try {
        console.warn("[related-changes] correlation phase failed (non-fatal): " +
          redactedJson({ scan_id: scanId, error: err?.name || "Error" }));
      } catch { /* logging must never break finalize */ }
    }

    // Phase 9: Asset Change Alert — one grouped email per workspace per scan.
    // Reads asset_events written by Phase 8, deduped via asset_alert_records.
    // Fully non-fatal — swallows all errors.
    try {
      await sendAssetChangeAlert(domainId, domain, scanId, env, scanQuality?.status, { modules, assetEvidence, observedAt: completedAt });
    } catch { /* non-fatal */ }

    // Phase 10: Notification Events — create in-app notifications for scan
    // completion and any critical/high findings. Non-fatal.
    try {
      await createNotificationsForDomain(
        domainId,
        domain,
        scanId,
        customerScore,
        customerRiskLevel,
        findings,
        env,
        scanQuality?.status,
        monitoringStates,
      );
      
      const wsRows = await env.cybermeters_db
        .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
        .bind(domainId)
        .all();
      for (const { workspace_id } of (wsRows.results || [])) {
        await processAlertsForWorkspace(
          workspace_id,
          domainId,
          domain,
          scanId,
          customerScore,
          findings,
          modules,
          startedAt,
          env
        );
      }
    } catch { /* non-fatal */ }

    // Phase 11: first-scan lifecycle delivery remains per-workspace. The
    // scan_completed audit is part of the atomic terminal D1 unit above.
    try {
      const wsRows = await env.cybermeters_db
        .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
        .bind(domainId)
        .all();
      for (const { workspace_id } of (wsRows.results || [])) {
        // Lifecycle: first scan completed (once per workspace+domain via dedupe).
        await sendLifecycleEmail(env, {
          type: "lifecycle_first_scan_completed", workspace_id, domain, scan_quality: scanQuality?.status,
        }).catch(() => {});
      }
    } catch { /* non-fatal */ }

      return { completed: true, ceiling_exceeded: false };
    };
    if (durableInvocation) {
      const postTerminal = await raceInvocationCeiling(
        "success_post_terminal",
        runPostTerminalWork,
      );
      return postTerminal;
    } else {
      await runPostTerminalWork();
    }
    return { completed: true, ceiling_exceeded: false };

  } catch (err) {
    // If a terminal state was already DURABLY finalized (completed or partial), a
    // later error — e.g. a post-completion persistence phase throwing — must NEVER
    // downgrade it. Refuse to touch it.
    if (latch.state === "finalized") {
      const persistFinalizedDiagnostics = async () => ({ completed: true, ceiling_exceeded: false });
      if (durableInvocation) {
        return raceInvocationCeiling(
          "finalized_diagnostics",
          persistFinalizedDiagnostics,
        );
      } else {
        await persistFinalizedDiagnostics();
      }
      return { completed: true, ceiling_exceeded: false };
    }

    // Otherwise the scan is NOT durably finalized (finalization never started, or a
    // first attempt failed partway). Route through the same downgrade-safe finalize:
    //   • if a completed report is already durable in R2, it keeps that report and
    //     only (re)writes the D1 completed status (recovers the earlier D1 failure);
    //   • if no completed report is durable, it writes a consistent 'failed' terminal.
    // finalizeScanResult never throws and never leaves the scan silently 'running'
    // when D1 is reachable; if D1 itself is down, the durable R2 report (if any) lets
    // the reconciler converge D1 later. This can no longer be suppressed by the latch.
    const failedAt = new Date().toISOString();
    const failedReport = {
      scan_id:             scanId,
      domain,
      status:              "failed",
      cyber_metrics_score: 0,
      risk_level:          "unknown",
      findings:            [],
      recommendations:     [],
      error:               err?.message ?? "Unknown scan engine error",
      started_at:          startedAt,
      failed_at:           failedAt,
      // PR-A1: additive diagnostics on the failed report too — a failed scan's
      // execution timing is exactly what a diagnosis needs. Observational only.
      execution_diagnostics: buildExecutionDiagnostics({
        executionContext,
        trigger,
        deadline,
        telemetry,
      }),
    };
    await finalizeScanResult(latch, {
      scanId, report: failedReport, score: 0, rating: "unknown", status: "failed", env,
      workspaceId,
      deadline: durableInvocation ? deadline : null,
    });
    if (durableInvocation && deadline.totalExceeded()) {
      return invocationCeilingResult("failure_terminal_finalization");
    }
    const runFailurePostTerminalWork = async () => {
      // Clean outcome: durably finalized as completed (original or recovered) → no
      // failure audit needed. Otherwise emit an auditable event for the terminal state:
      //   • "failed"    — the scan genuinely failed (results could not be persisted);
      //   • "completed" but not durably finalized — a DEGRADED finalize: the completed
      //     R2 report is durable, D1 convergence is pending (the reconciler backstops).
      // Both are recorded so the outcome is never silent.
      if (latch.state === "finalized" && latch.status === "completed") {
        return { completed: true, ceiling_exceeded: false };
      }
      const degraded = latch.status !== "failed";
      const auditType = degraded ? "scan_finalize_degraded" : "scan_failed";
      const auditDesc = degraded
        ? `Scan for ${domain} degraded during finalization — results persisted, status convergence pending`
        : `Scan failed for ${domain}`;

      try {
        let wsRows = [];
        if (workspaceId) {
          wsRows = [{ workspace_id: workspaceId }];
        } else {
          const linked = await env.cybermeters_db
            .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
            .bind(domainId)
            .all();
          wsRows = linked.results || [];
        }
        const auditRows = wsRows.length > 0 ? wsRows : [{ workspace_id: null }];
        for (const { workspace_id } of auditRows) {
          await createAuditEvent(env, {
            workspace_id: workspace_id ?? null,
            event_type:  auditType,
            entity_type: "scan",
            entity_id:   scanId,
            description: auditDesc,
            metadata:    { scan_id: scanId, domain, domain_id: domainId, degraded, error: err?.message ?? "Unknown scan engine error" },
          });
        }
      } catch { /* non-fatal */ }
      return { completed: true, ceiling_exceeded: false };
    };
    if (durableInvocation) {
      return raceInvocationCeiling(
        "failure_post_terminal",
        runFailurePostTerminalWork,
      );
    } else {
      await runFailurePostTerminalWork();
    }
    return { completed: true, ceiling_exceeded: false };
  } finally {
    deadline.disarm?.();
  }
  };

  if (!durableInvocation) return runInvocationBody();
  return raceInvocationCeiling(
    "whole_invocation",
    runInvocationBody,
  );
}

// One asset_event per admin surface that the workspace's previous comparable
// scan did not have (host + product): a surface that stays reachable is
// announced when it appears, not on every scan. Written for the scanning
// workspace only, live and still linked to the domain; the event id is fixed
// per (workspace, scan, host, product), so a replay writes nothing twice.
export async function insertAdminSurfaceEvents(scanId, domainId, adminModule, env, opts = {}) {
  const actionableServices = (adminModule?.services || [])
    .filter((service) => service.finding_type !== "observation");
  if (!adminModule || !adminModule.detected || actionableServices.length === 0) return;
  const comparison = await loadTimelineComparisonContext(env, {
    scanId,
    domainId,
    currentReport: opts.currentReport,
  }).catch(() => ({ comparable: false }));
  if (!comparison.comparable) return;
  const scanWorkspaceId = comparison.currentScan?.workspace_id ?? null;
  if (!scanWorkspaceId) return;

  const surfaceKey = (service) => {
    const hostname = String(service?.hostname || "").trim().toLowerCase();
    const product = String(service?.product || "").trim().toLowerCase();
    return hostname && product ? `${hostname}::${product}` : "";
  };
  const previousSurfaces = new Set((comparison.previousReport?.modules?.admin_surface_detection?.services || [])
    .filter((service) => service?.finding_type !== "observation")
    .map(surfaceKey)
    .filter(Boolean));
  const newServices = actionableServices.filter((service) => {
    const key = surfaceKey(service);
    return key && !previousSurfaces.has(key);
  });
  if (newServices.length === 0) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare(
        `SELECT wd.workspace_id FROM workspace_domains wd
         JOIN workspaces w ON w.id = wd.workspace_id
         WHERE wd.domain_id = ? AND wd.workspace_id = ? AND w.deleted_at IS NULL`
      )
      .bind(domainId, scanWorkspaceId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();

  for (const { workspace_id } of wsRows) {
    for (const svc of newServices) {
      try {
        // Resolve asset_id if the asset was already upserted by upsertAssetInventory
        const assetRow = await env.cybermeters_db
          .prepare(`SELECT id FROM workspace_assets WHERE workspace_id = ? AND hostname = ?`)
          .bind(workspace_id, svc.hostname)
          .first();
        const digest = await hashToken(JSON.stringify(["admin-surface-event-v1", workspace_id, scanId, surfaceKey(svc)]));

        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, asset_id, scan_id,
                event_type, hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            `evt-${digest.slice(0, 32)}`,
            workspace_id,
            domainId,
            assetRow?.id ?? null,
            scanId,
            "admin_surface_detected",
            svc.hostname,
            svc.risk_level,
            `${svc.product} (${svc.category}) detected on ${svc.hostname} — confidence: ${svc.confidence}`,
            now
          )
          .run();
      } catch { /* non-fatal per service */ }
    }
  }

  console.log("[admin-surface]", JSON.stringify({
    scan_id:      scanId,
    domain_id:    domainId,
    detected:     adminModule.detected,
    new_surfaces: newServices.length,
    workspaces:   wsRows.length,
  }));
}

export async function upsertVendorRelationships(domainId, relModule, env) {
  // The module must have EXECUTED for its result to say anything about absence:
  // no result, or a result with an error, is silence (nothing is retired). A result
  // that ran clean and detected nothing is evidence — the suppliers it no longer sees
  // are retired below, exactly as vendor_risk suppliers are, so vendor_relationship
  // rows enter the same disappearance flow (the Shadow IT correlator reads only
  // status = 'active' rows and records the absence through its own evaluator).
  if (!relModule || relModule.error) return;
  const vendors = Array.isArray(relModule.vendors) ? relModule.vendors : [];

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch { return; }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();
  const detectedNames = vendors.map((v) => v.name).filter(Boolean);

  for (const { workspace_id } of wsRows) {
    for (const v of vendors) {
      try {
        const id           = createId("vendor");
        // Structured { source, detail } evidence (Catalogue B carries the observed
        // hostname as detail); an older module result that only has signal names is
        // kept as objects with no detail rather than as bare strings.
        const evidenceEntries = Array.isArray(v.evidence) && v.evidence.length
          ? v.evidence
          : (v.source_signals || []).map((source) => ({ source, detail: null }));
        const evidenceJson = JSON.stringify(evidenceEntries);

        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO workspace_vendors
               (id, workspace_id, vendor_name, category, source, evidence,
                confidence, risk_level, source_module,
                first_seen, last_seen, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'vendor_relationship', ?, ?, 'active', ?, ?)`
          )
          .bind(
            id, workspace_id, v.name, v.category, v.source, evidenceJson,
            v.confidence, v.risk_level, now, now, now, now
          )
          .run();

        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_vendors
             SET last_seen = ?, confidence = ?, risk_level = ?,
                 evidence = ?, source_module = 'vendor_relationship',
                 status = 'active', updated_at = ?
             WHERE workspace_id = ? AND vendor_name = ? AND category = ?`
          )
          .bind(now, v.confidence, v.risk_level, evidenceJson, now, workspace_id, v.name, v.category)
          .run();
      } catch { /* non-fatal per-vendor */ }
    }

    // Retire the relationship suppliers this clean run did not see — including
    // every one of them when it saw none. Only when the analysis' input modules
    // (headers, technology_detection) actually observed the site: the analysis is
    // pure, so an unreadable site produces an honest-looking "0 vendors" that must
    // be silence, not a retirement that flaps back next scan. Only this workspace,
    // only rows this module owns; last_seen is preserved as the last observation.
    if (relModule.inputs_complete !== true) continue;
    try {
      const placeholders = detectedNames.map(() => "?").join(", ");
      await env.cybermeters_db
        .prepare(
          `UPDATE workspace_vendors
           SET status = 'inactive', updated_at = ?
           WHERE workspace_id = ? AND status = 'active'
             AND source_module = 'vendor_relationship'${detectedNames.length ? ` AND vendor_name NOT IN (${placeholders})` : ""}`
        )
        .bind(now, workspace_id, ...detectedNames)
        .run();
    } catch { /* non-fatal */ }
  }
}

export async function upsertVendorInventory(domainId, vendorRisk, env) {
  if (!vendorRisk?.detected || !vendorRisk.vendors?.length) return;

  // Find all workspaces that own this domain
  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();
  const detectedNames = vendorRisk.vendors.map((v) => v.name);

  for (const { workspace_id } of wsRows) {
    // Upsert each detected vendor
    for (const v of vendorRisk.vendors) {
      try {
        const id = createId("vendor");
        const evidenceJson = JSON.stringify(v.evidence || []);

        // INSERT OR IGNORE preserves first_seen for existing rows
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO workspace_vendors
               (id, workspace_id, vendor_name, category, source, evidence,
                confidence, risk_level, first_seen, last_seen, status,
                created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
          )
          .bind(
            id, workspace_id, v.name, v.category, v.source, evidenceJson,
            v.confidence, v.risk_level, now, now, now, now
          )
          .run();

        // UPDATE existing row — refresh last_seen, evidence, confidence, status
        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_vendors
             SET last_seen = ?, evidence = ?, confidence = ?, risk_level = ?,
                 status = 'active', updated_at = ?
             WHERE workspace_id = ? AND vendor_name = ? AND category = ?`
          )
          .bind(
            now, evidenceJson, v.confidence, v.risk_level, now,
            workspace_id, v.name, v.category
          )
          .run();
      } catch { /* non-fatal per-vendor failure */ }
    }

    // Mark previously-detected vendors that were not seen this scan as inactive.
    // Only touch rows in this workspace — preserve other workspaces.
    if (detectedNames.length > 0) {
      try {
        // Variable-length IN list via generated `?` placeholders — every value
        // stays a bound parameter, never string-embedded SQL.
        const placeholders = detectedNames.map(() => "?").join(", ");
        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_vendors
             SET status = 'inactive', updated_at = ?
             WHERE workspace_id = ? AND status = 'active'
               AND source_module = 'vendor_risk'
               AND vendor_name NOT IN (${placeholders})`
          )
          .bind(now, workspace_id, ...detectedNames)
          .run();
      } catch { /* non-fatal */ }
    }
  }
}
