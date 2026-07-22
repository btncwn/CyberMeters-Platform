import { handleInboundEmail } from "./email/inbound.js";
import { runScheduled } from "./cron/scheduled.js";
import { handleScanDispatchBatch } from "./engines/scan-dispatch.js";
import { recoverInterruptedScans } from "./engines/scan-recovery.js";
import { recordMetric } from "./lib/metrics.js";
import { redactedJson } from "./lib/redact.js";
import { computeOpsHealth, formatOpsHealthEmail } from "./lib/ops-health.js";
import { CE_QUESTIONS, CE_QUESTION_SET_VERSION, mergeReadiness } from "./lib/cyber-essentials.js";
import { createId, isValidDomain, isValidEmail, normalizeApiResponseData, pageMeta, paginationParams, parseBoundedInteger } from "./lib/util.js";
import { createAuditEvent, createNotificationEvent, createNotificationsForDomain, sanitizeAuditMetadata } from "./lib/events.js";
import { RUA_INBOUND_DOMAIN_DEFAULT, ingestDmarcReport, ingestEndpointIsActive, normalizeInboundRecipientDomain, parseEmailAuthHeaders, sha256Hex, updateEmailSenderSources } from "./lib/dmarc-ingest.js";
import { buildCorsHeaders, buildJsonHeaders, deliverEmail, escapeEmailHtml, getEmailFrontendOrigin, json, retryFailedLifecycleEmails, sendCustomerEmail, sendLifecycleEmail } from "./lib/lifecycle-email.js";
import { RDAP_UA, safeFetch } from "./lib/http.js";
import { ACTIVE_SCAN_CONFLICT_CODE, isUniqueConstraintError } from "./lib/scan-admission.js";
import { generateTotpSecret, verifyTotp } from "./lib/totp.js";
import { hashPassword, verifyPassword } from "./lib/password.js";
import { validateMicrosoftIdToken, validateMicrosoftIdTokenClaims } from "./lib/microsoft-jwt.js";
import { generateSessionToken, generateApiToken, generateInviteToken, generateEmailVerificationToken, getEmailVerificationTokenStatus, isEmailVerificationResendCoolingDown, generatePasswordResetToken, generateMfaChallengeToken, encryptTotpSecret, decryptTotpSecret, generateRecoveryCodes, verifyRecoveryCode, hashToken } from "./lib/auth-crypto.js";
import { checkDnsTxtProof, outcomeForDnsCategory, persistVerification, recordVerificationAttempt,
         VERIFICATION_OUTCOMES, VERIFICATION_RECHECK_BATCH, VERIFICATION_WINDOW_HOURS } from "./lib/domain-verification.js";
// dnsQuery is deliberately absent: the only caller left in this file was the
// domain-verification cron, which now shares the canonical proof in
// lib/domain-verification.js rather than carrying its own copy of the lookup.
import { dnsQueryDnssec, dnsQueryGoogle, dnsQueryQuad9, dnsAnswerValues, computeResolverAgreementScore, buildDnsCrossCheck } from "./engines/dns.js";
import { buildDnsOperationalResilience } from "./engines/dns-resilience.js";
import { SCANNER_REGRESSION_FIXTURES } from "./engines/regression-fixtures.js";
import { ENTERPRISE_BENCHMARK, ENTERPRISE_DOMAINS, POSTURE_WEIGHTS } from "./engines/scoring-config.js";
import { customerSafeFailure } from "./lib/errors.js";
import { runDnsModule } from "./engines/dns-scan.js";
import { normalizeCertificateSanNames, normalizeDiscoveredHostname, normalizeHostname, parseCertificateSanNames } from "./engines/hostnames.js";
import { runSslModule } from "./engines/ssl-scan.js";
import { classifyHeaderStrength, runHeadersModule } from "./engines/headers-scan.js";
import { DKIM_PROVIDER_LABELS, DKIM_SELECTORS, buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions, buildEmailTransportDetails, normalizeDnsTxtValue, parseBimiRecord, parseDmarcRecord, parseSpfRecord, remediationAction, sanitizeInfraErrorMessage } from "./engines/email-analysis.js";
import { runEmailModule } from "./engines/email-scan.js";
import { runTechModule } from "./engines/tech-scan.js";
import { runWhoisModule } from "./engines/whois-scan.js";
import { runCveModule, runKevModule } from "./engines/vuln-intel.js";
import { runTakeoverModule } from "./engines/takeover-scan.js";
import { filterWildcardBruteforceResults, runBruteforceModule, runSubdomainsModule } from "./engines/subdomains-scan.js";
import { hostnameFromValue, runCloudStorageModule } from "./engines/cloud-storage-scan.js";
import { annotateExposureInfrastructure, assetFingerprintSignals, buildAssetInventoryMetadata, classifyProviderInfrastructure, consolidateInventoryAssetAliases, deduplicateExposureAssets, probeAsset, providerForInfrastructureHostname, providerMetadataForHostname, runAdminSurfaceModule, runExposureModule, runRemediationModule, runRiskModule } from "./engines/asset-intel.js";
import { buildCaConcentrationAnalytics, buildCertificateLifecycleIntelligence, detectSelfSignedCertificate, extractCertificateCryptoMetadata, mapCertificateAuthorityOwner, normalizeCertificateAuthorityVendor, normalizeCertificateIssuer } from "./engines/cert-analysis.js";
import { buildCertificateOwnershipAssessment, isCertSensitiveHost, runCertificateIntelligenceModule } from "./engines/cert-intel.js";
import { VENDOR_SIGNATURES, detectVendorsFromModules } from "./engines/vendor-signatures.js";
import { remapToThirdPartyCategory, runSaasExposureModule, runThirdPartyDiscoveryModule } from "./engines/discovery-scan.js";
import { HIGH_RISK_BRAND_KEYWORDS, extractBrandParts, generateTyposquatCandidates, runTyposquatModule } from "./engines/brand-typosquat.js";
import { runDomainSecurityEnrichmentModule } from "./engines/domain-enrichment.js";
import { runHistoricalModule } from "./engines/historical-scan.js";
import { runIdentityDiscoveryModule } from "./engines/identity-scan.js";
import { runVendorRelationshipModule } from "./engines/vendor-relationship.js";
import { ASSET_ALERT_EVENTS, assetAlertSeverity, assetAlertWorthy, buildAssetAlertEmail } from "./engines/asset-alerts.js";
import { insertCertificateEvents, upsertCertificateObservation } from "./engines/cert-events.js";
import { upsertBrandAssets, upsertIdentityAssets } from "./engines/asset-persistence.js";
import { computeScore, isEmailApplicable, resolveCanonicalScanScore, riskLevelForScore } from "./engines/scoring.js";
import { fetchMtaSts, runEmailIntelModule } from "./engines/email-intel.js";
import { buildExecutiveReportV2 } from "./engines/executive-report.js";
import { composeSnapshot, readScanReportSnapshot } from "./engines/report-snapshot.js";
import { computeWorkspaceVendorRisk, confidenceToScore, normalizeVendorKey, normalizeVendorRiskCategory, recomputeVendorRiskScoresForDomain, signalWeightForVendor } from "./engines/vendor-risk.js";
import { computeConcentration, computeSupplyChainIntelligence, upsertSupplyChainScore } from "./engines/supply-chain.js";
import { clamp, computeSecurityPosture } from "./engines/posture-scoring.js";
import { buildScorecardData } from "./engines/scorecard.js";
import { buildCyberEssentialsReadiness } from "./engines/ce-readiness.js";
import { computeBusinessRiskScore, deriveScanBusinessRisk, expandFindingIds } from "./engines/business-risk.js";
import { computeBecExposureScore } from "./engines/bec.js";
import { CHANGE_STATES, applyChangeTransition, buildChangeReviewQueue, canTransitionChange, changeRequestToApi, isTerminalChangeState, newChangeRequestId } from "./engines/dmarc-change-workflow.js";
import { upsertAssetInventory } from "./engines/asset-inventory.js";
import { computePortfolioRisk } from "./engines/portfolio-risk.js";
import { _cloudflareEmailRoutingRequest, _cloudflareRouteFailure, auditDmarcRouteResult, buildDmarcEnforcementReadiness, buildEnforcementReadinessChecks, classifyHostedCfError, configureDmarcEndpointRoute, dmarcSenderRiskLevel, emailSenderToApi, ensureCloudflareEmailRoute, extractIngestToken, generateInboundLocalpart, generateIngestToken, hashIngestToken, ingestEndpointToApi, loadEmailSenderSources, persistDmarcRouteResult, resolveWorkspaceDomain, revokeCloudflareEmailRoute, safelyEnsureCloudflareEmailRoute, safelyRevokeCloudflareEmailRoute, summarizeEmailSenders } from "./engines/rua-routing.js";
import { DMARC_RAMP_LADDER, HOSTED_DNS_REMOVAL_GRACE_DAYS, REMEDIATION_REGISTRY, analyzeSpfChain, applyHostedDmarcChange, buildDmarcDnsRecommendedValue, buildDmarcPolicyValue, cfCreateHostedTxt, dmarcRampStepIndex, dmarcTagDiff, evaluateRampReadiness, getHostedDmarcPassRate, getRemediation, hostedDmarcSubdomain, hostedDnsRecordToApi, newHostedDnsRecordId, nextHostedDnsStatus, parseServerMsHosted, planAllowsHostedPolicyManagement, reconcileHostedIntent, remediationToApi, resolveRampThresholds, rollbackHostedDmarc, runHostedDnsVerificationSweep, shouldAutoRollback, verifyDmarcDnsSetup, verifyHostedDmarcRecord } from "./engines/hosted-dmarc.js";
import { retryFailedAlertDeliveries } from "./engines/managed-alerts.js";
import { buildDmarcBusinessRisk, buildDmarcReportRemediationActions, buildDmarcSenderIntelligenceEvidence, cybermetersRuaPresentInDmarcRecord, loadBecExposureEvidence } from "./engines/sender-provenance.js";
import { retryFailedAssetAlerts, sendAssetChangeAlert } from "./engines/asset-alert-delivery.js";
import { sendWeeklyDigests } from "./engines/weekly-digest.js";
import { runBrandTakedownFollowupSweep } from "./engines/brand-cases.js";
import { runBrandDnsEnrichmentSweep } from "./engines/brand-dns-enrichment.js";
import { runBrandPassiveDiscoverySweep } from "./engines/brand-passive-discovery.js";
import { runBrandHttpEnrichmentSweep } from "./engines/brand-http-enrichment.js";
import { calculateNextRun, checkReportLimit, checkScanLimit, checkScheduledScanLimit, computeScheduledReportNextRunAt, countEnabledScheduledScans, countReportsThisMonth, countScansThisMonth, evaluateScheduledScanEligibility, generateWorkspaceExecutiveReport, getAccountUsage, getEntitlementUsage, getMonthResetAt, getMonthStart, getOwnedWorkspaceIds, getPlanContext, getPlanLimits, getPlanRetentionDays, getReportExpiresAt, getReportRetentionPolicyForWorkspace, getRetentionCutoff, getRetentionCutoffForDays, getUpgradeRecommendation, getWorkspaceBillingUserId, getWorkspaceOwnerId, getWorkspaceReportStorageMetrics, getWorkspaceRetentionSettings, normalizeReportScheduleFrequency, normalizeReportScheduleRecipients, planLimitExceeded, retentionDaysToPolicy, retentionPolicyToDays } from "./engines/plan-usage.js";
import { TRIAL_PLAN, TRIAL_DURATION_DAYS, auditApiTokenSessionRouteDenied, createWorkspaceTrialSubscription, getPublicBillingPlans, getTrialRemainingDays, getWorkspaceSubscription, isSubscriptionActive, isTrialActive, parseCheckoutPlan } from "./engines/subscription-state.js";
import { workspaceAnalyticsRoutes } from "./routes/workspace-analytics.js";
import { workspaceIntelRoutes } from "./routes/workspace-intel.js";
import { brandRoutes } from "./routes/brand.js";
import { workspaceReportsRoutes } from "./routes/workspace-reports.js";
import { workspaceActivityRoutes } from "./routes/workspace-activity.js";
import { workspaceMembersRoutes } from "./routes/workspace-members.js";
import { executiveDashboardRoutes } from "./routes/executive-dashboard.js";
import { emailProtectionRoutes } from "./routes/email-protection.js";
import { domainRoutes } from "./routes/domains.js";
import { workspacesCoreRoutes } from "./routes/workspaces-core.js";
import { billingRoutes } from "./routes/billing.js";
import { scanRoutes } from "./routes/scans.js";
import { portfolioRoutes } from "./routes/portfolio.js";
import { accountRoutes } from "./routes/account.js";
import { globalBillingRoutes } from "./routes/global-billing.js";
import { authRoutes } from "./routes/auth.js";
import { attackSurfaceRoutes } from "./routes/attack-surface.js";
import { managedCasesRoutes } from "./routes/managed-cases.js";
import { relatedChangesRoutes } from "./routes/related-changes.js";
import { shadowItRoutes } from "./routes/shadow-it.js";
import { certificatesLifecycleRoutes } from "./routes/certificates-lifecycle.js";
import { identityExposureRoutes } from "./routes/identity-exposure.js";
import { websiteSecurityRoutes } from "./routes/website-security.js";
import { cyberEssentialsControlsRoutes } from "./routes/cyber-essentials-controls.js";
import { emailProtectionLifecycleRoutes } from "./routes/email-protection-lifecycle.js";
import { workspaceInsightRoutes } from "./routes/workspace-insights.js";
import { workspaceBrandingRoutes } from "./routes/workspace-branding.js";
import { buildCertificateAuthorityConcentrationFromModule, buildScanQuality, computeScanBudget, insertAdminSurfaceEvents, runScanEngine, upsertVendorInventory, upsertVendorRelationships } from "./engines/scan-engine.js";
import { runBoundedScheduledReports } from "./engines/scheduled-reports.js";
import { assemblePdf, buildScanReportPdf, buildWorkspaceExecutivePdf, pdfUtcDate } from "./engines/pdf.js";
import { BILLING_PLAN_METADATA, PLAN_FEATURES, PLAN_LIMITS, getEffectivePlan, getPaymentGraceState, getPlanFeatures, getUserPlan, hasFeatureEntitlement, normalizeBillingInterval, normalizePlan } from "./engines/entitlements.js";
import { findSubscriptionRowId, getBillingIntervalFromStripeSubscription, getPlanFromStripePriceId, getStripeObjectId, getStripePriceIdForPlan, getStripeSubscriptionPrice, handleCheckoutSessionCompleted, handleStripeInvoicePaymentFailed, handleStripeInvoicePaymentSucceeded, handleStripeSubscriptionDeleted, handleStripeSubscriptionUpsert, normalizeStripeSubscriptionStatus, stripeUnixToIso, validateStripeBillingConfig, validateStripeSecretConfig, validateStripeWebhookConfig, verifyStripeWebhookSignature, writeSubscriptionEvent } from "./engines/stripe.js";
import { ALERT_CHANNEL_MAX_PER_WORKSPACE, alertChannelToApi, buildAlertChannelPayload, deliverWorkspaceAlert, formatAlertEmail, processAlertsForWorkspace, sendAlertEmail, signAlertWebhookBody, validateAlertChannelInput } from "./engines/alerts.js";
import { BRAND_CLASSIFICATIONS, BRAND_SUSPICIOUS_TLDS, brandCandidateToApi, brandClassificationAuditMetadata, brandProfileToApi, brandSimilarityScore, buildBrandProfileDomainScope, buildBrandProtectionSummary, filterBrandCandidatesToProfile, inferBrandProfileFromDomains, legacyBrandAssetToApi, loadWorkspaceBrandProfile, normalizeBrandVariantType, parseBrandCandidateListParams, scoreBrandCandidateRisk, validateBrandProfileInput } from "./engines/brand-protection.js";
import { applyEvidenceQuality, isActionableFinding, normalizeFindingSchema, validateFindingEvidence } from "./engines/findings.js";
// ─────────────────────────────────────────────────────────────────────────────
// CyberMeters Scan API — Cloudflare Worker
// ─────────────────────────────────────────────────────────────────────────────

// ── Utilities ────────────────────────────────────────────────────────────────

function validateFrontendRedirectUrl(value, env) {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    const parsed = new URL(value.trim());
    const configuredFrontend = new URL(
      env.FRONTEND_URL || env.ALLOWED_ORIGIN || "https://app.cybermeters.com"
    );
    if (parsed.protocol !== "https:" || parsed.origin !== configuredFrontend.origin) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * requireAuth — unified Bearer-token authentication.
 *
 * Accepts both user sessions and API tokens transparently:
 *   - cm_<secret>  → api_tokens table lookup; returns user + token_scope + token_workspace_id
 *   - anything else → user_sessions table lookup; token_scope/token_workspace_id are undefined
 *
 * All existing call sites receive token auth with zero changes because
 * requireWorkspaceAccess and requireWorkspaceRole enforce scope + workspace binding
 * whenever token_scope is present on the resolved identity.
 */
async function requireAuth(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const rawToken = authHeader.slice(7).trim();
  if (!rawToken) return null;
  try {
    const tokenHash = await hashToken(rawToken);

    // ── API Token path (cm_ prefix) ──────────────────────────────────────────
    if (rawToken.startsWith("cm_")) {
      const token = await env.cybermeters_db
        .prepare(
          `SELECT t.id AS api_token_id, t.user_id,
                  t.workspace_id AS token_workspace_id,
                  t.scope        AS token_scope,
                  u.id, u.email, u.name, u.plan, u.status
           FROM api_tokens t
           JOIN users u ON u.id = t.user_id
           WHERE t.token_hash = ?
             AND t.status = 'active'
             AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))
           LIMIT 1`
        )
        .bind(tokenHash)
        .first();
      if (!token || token.status === "suspended") return null;
      // Fire-and-forget: last_used_at + audit log (never block the request)
      env.cybermeters_db
        .prepare("UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?")
        .bind(token.api_token_id)
        .run()
        .catch(() => {});
      createAuditEvent(env, {
        user_id:     token.user_id,
        event_type:  "api_token_used",
        entity_type: "api_token",
        entity_id:   token.api_token_id,
        description: "API token authenticated request",
        metadata:    { scope: token.token_scope, workspace_id: token.token_workspace_id ?? null },
      }).catch(() => {});
      return token;
    }

    // ── Session path ──────────────────────────────────────────────────────────
    const session = await env.cybermeters_db
      .prepare(
        `SELECT s.id AS session_id, s.user_id, u.id, u.email, u.name, u.plan, u.status
         FROM user_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
      )
      .bind(tokenHash)
      .first();
    if (!session || session.status === "suspended") return null;
    // Fire-and-forget: track last activity time for session visibility feature
    env.cybermeters_db
      .prepare("UPDATE user_sessions SET last_seen_at = datetime('now') WHERE id = ?")
      .bind(session.session_id)
      .run()
      .catch(() => {});
    return session;
  } catch {
    return null;
  }
}

/**
 * @deprecated requireApiToken is now a thin shim.
 * requireAuth handles both cm_ API tokens and user sessions transparently.
 * All call sites should use requireAuth directly.
 */
async function requireApiToken(request, env) {
  return requireAuth(request, env);
}

// ── Enterprise Benchmark Dataset ─────────────────────────────────────────────
//
// Known-good enterprise domains.  Used by:
//   • GET /api/validation/benchmark  — regression check
//   • computeScore                   — enterprise edge uncertainty detection
//
// Enterprise CDN deployments (Cloudflare Workers, Google Front End, Akamai, etc.)
// often serve different responses to automated scanner IPs than to real browsers.
// We track these domains so the scoring engine can apply conservative confidence
// when the probe results are internally contradictory.

function evaluateRegressionFixtures(fixtures = SCANNER_REGRESSION_FIXTURES) {
  const results = fixtures.map((fixture) => {
    const { findings } = computeScore(fixture.mock_modules, fixture.domain || "fixture.cybermeters.test");
    const findingIds = expandFindingIds(findings);
    const failures = [];

    if (fixture.expected) {
      const actual = findings.find((f) => f.id === fixture.expected.id);
      if (!actual) {
        failures.push(`missing expected finding ${fixture.expected.id}`);
      } else {
        for (const key of ["severity", "confidence", "score_impact"]) {
          if (actual[key] !== fixture.expected[key]) {
            failures.push(`${fixture.expected.id} ${key}: expected ${fixture.expected[key]}, got ${actual[key]}`);
          }
        }
        if (!actual.evidence_quality || actual.evidence_quality === "missing") {
          failures.push(`${fixture.expected.id} missing usable evidence quality`);
        }
      }
    }

    for (const id of fixture.expected_absent || []) {
      if (findingIds.has(id)) failures.push(`unexpected finding ${id}`);
    }

    return {
      scenario: fixture.scenario,
      passed: failures.length === 0,
      failures,
      findings: findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        confidence: f.confidence,
        score_impact: f.score_impact,
        evidence_quality: f.evidence_quality,
      })),
    };
  });

  const passed = results.filter((r) => r.passed).length;
  return {
    total: results.length,
    passed,
    failed: results.length - passed,
    pass_rate: results.length > 0 ? Math.round((passed / results.length) * 100) : 0,
    results,
  };
}

// ── Module 1: DNS Analysis ────────────────────────────────────────────────────

// ── Module: Domain Security Enrichment ───────────────────────────────────────
//
// Three low-cost checks that run in parallel during Phase 1:
//
//   CAA     — DNS CAA record lookup (DoH).  Detects missing CAA, lists allowed
//             CAs, wildcard issuers, and IODEF incident-report addresses.
//
//   HSTS    — Parses the Strict-Transport-Security header from the live HTTPS
//             response.  Computes preload eligibility (max-age >= 1 yr,
//             includeSubDomains, preload directive all required).
//
//   Cookies — Parses Set-Cookie headers from the same HTTPS response.
//             Flags cookies missing the Secure, HttpOnly, or SameSite attributes.
//
// All three sub-checks are internally parallel (Promise.allSettled). Individual
// sub-failures are non-fatal and leave only that sub-section errored.

// ── Intelligence Module: Email Security Intelligence ─────────────────────────
// Ported from email_security/ package:
//   spf.py, dmarc.py, mta_sts.py, tls_rpt.py, starttls.py,
//   scoring.py, intelligence.py, business_impact.py
//
// Design decisions vs. Python originals:
//   • SPF + DMARC + DKIM: reuses runEmailModule DNS results (no extra queries)
//   • MTA-STS: HTTP fetch to https://mta-sts.<domain>/.well-known/mta-sts.txt
//   • TLS-RPT: new DNS TXT query on _smtp._tls.<domain> via existing dnsQuery()
//   • STARTTLS: raw TCP port 25 is unavailable in Worker runtime → structured stub
//   • Score weights preserved exactly from scoring.py v1.1:
//       DMARC=50, SPF=20, DKIM=20, MTA-STS=5, TLS-RPT=5
//   • All failures are swallowed; no scan can fail because of this module

// ── Module 8: Historical Change Detection ─────────────────────────────────────

// ── normalizeHostname ─────────────────────────────────────────────────────────
// Returns a bare, lowercase hostname with no trailing dot, port, path, query,
// or fragment.  Accepts:
//   • Plain hostname          "api.example.com"
//   • Hostname with port      "api.example.com:8443"
//   • Full URL                "https://api.example.com/path?x=1"
//   • URL without scheme      "//api.example.com/path"
//   • Hostname with path      "api.example.com/path"   (no scheme)
// ── Scan Budget Tracking ──────────────────────────────────────────────────────
// Pure computation — estimates subrequest usage per module.
// CyberMeters runs on Workers Paid plan (1,000 subrequest limit per invocation).
//
// Sprint 10B audit — corrected counts:
//   dns             — 17 (5 CF DoH: A/AAAA/NS/MX/CAA; 4 Google DoH: A/AAAA/MX/TXT;
//                         1 Google DoH: _dmarc TXT; 1 Quad9 DoH: A; 2 CF DoH: TXT+_dmarcTXT
//                         cross-check; 1 Google DoH: CAA cross-check; 3 CF DNSSEC: DS/DNSKEY/RRSIG)
//                         Was: 11 — missed DNSSEC (3) + CAA Google cross-check (1) + TXT cross-checks (2)
//   ssl             — 4  (HTTPS + www-HTTPS fallback + HTTP + crt.sh)
//   headers         — 2  (HTTPS + HTTP fallback)
//   email_security  — 23 (TXT root + _dmarc + BIMI + 19 DKIM selector probes + up to 3 Phase 2 provider extras)
//                         Was: 15 — DKIM expanded from 13 → 19 selectors in Sprint 9D but estimate never updated
//   ct_discovery    — 4  (wildcard A + AAAA DoH + crt.sh + CertSpotter)
//   dns_bruteforce  — actual checked count (capped at BRUTEFORCE_MAX_NAMES = 15)
//   asset_exposure  — 0  (variable; up to 50×2 HTTP probes; tracked separately from exposure result)
//   admin_surface   — 0  (pure computation, zero I/O)
//   cve_kev         — 2  (NVD + CISA KEV)
//   domain_security_enrichment — 0 (pure computation, zero I/O)
//   Total core: ~65 / 1,000 limit = 6.5% of budget.



// ── Main Scan Engine (runs via ctx.waitUntil) ─────────────────────────────────

// ── Admin Surface Event Insertion ────────────────────────────────────────────
//
// Writes one asset_event per detected admin service per workspace per scan.
// Called after upsertAssetInventory so workspace_assets rows already exist.
// All errors are non-fatal — the scan is already marked completed by this point.

/**
 * upsertVendorRelationships(domainId, relModule, env)
 * Phase 8g: Persists vendor_relationship detections into workspace_vendors
 * with source_module = 'vendor_relationship'.
 *
 * Uses INSERT OR IGNORE + UPDATE to preserve first_seen and refresh last_seen.
 * Does NOT mark undetected vendors inactive — vendor_risk (Phase 8c) handles
 * that sweep for DNS-sourced entries.
 */

// ── Vendor Inventory Upsert ───────────────────────────────────────────────────
//
// Persists the vendor_risk module output to workspace_vendors (D1).
// Called after Phase 7e and after workspace lookup is available.
// All errors are non-fatal — failure here does not affect scan status.

/**
 * upsertVendorInventory
 *
 * For each workspace that owns `domainId`:
 *   1. Upsert active vendors from `vendorRisk.vendors` into workspace_vendors.
 *      - INSERT OR IGNORE to preserve first_seen.
 *      - UPDATE last_seen + status='active' + updated_at on every upsert.
 *   2. Mark any workspace_vendors rows NOT in the current detected set as inactive.
 */

/**
 * sendAssetChangeAlert
 *
 * Called once per scan after upsertAssetInventory completes.
 * Looks up all workspaces that own this domain, queries asset_events for this
 * scan, builds a grouped summary, and sends one email per workspace.
 *
 * Dedup: INSERT OR IGNORE into asset_alert_records prevents re-sends.
 * After sending, the row's status/error (migration 067) record the delivery
 * outcome; a 'failed' row is re-sent by the hourly asset_alert_retry cron
 * (retryFailedAssetAlerts), so a Resend failure inside this heavy scan
 * invocation no longer loses the alert.
 * The whole function is non-fatal — any error is swallowed.
 */
// ── sendTakeoverAlert / sendSslExpiryAlert — REMOVED (PR-B4b) ────────────────
// Two tenant-facing alert senders that were dead code and unsafe if ever revived.
// Both called sendAlertEmail — the OPS-ONLY sender, which falls back to
// env.ALERT_EMAIL_TO when given no recipient. So a single future caller would have
// emailed one tenant's takeover risks or certificate expiry to the OPERATOR's inbox,
// with no entitlement check, no per-user preference, no severity gate, no verified
// recipient resolution, no dedupe key and no delivery ledger — every rule the
// canonical pipeline exists to enforce, bypassed at once.
//
// They had no callers, which is the only reason they never did any of that. Deleting
// them removes the possibility rather than the current symptom. Certificate expiry is
// already owned canonically by certificates_trust.renewal_overdue/.expired
// (certificate-lifecycle.js, PR-B2) and takeover risk by the asset-change path, so
// nothing here is lost — this is a second, ungated copy of alerts the platform
// already sends properly. Do not re-add a tenant sender here: use emitLifecycleAlert
// (engines/alert-consumers.js). validate-alert-recipients.js and
// validate-alert-b4b-legacy-cleanup.js both enforce that boundary.

// ─────────────────────────────────────────────────────────────────────────────
// Executive PDF Report Generator
// Pure-JS PDF/1.4 — no npm packages. Uses built-in Type1 fonts only.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitise a value to printable ASCII and escape PDF literal string delimiters.
 */

// ── Scheduled Scan Helpers ────────────────────────────────────────────────────

/**
 * Return the ISO timestamp for the next run based on frequency.
 * Supported: 'daily' (24 h) and 'weekly' (7 days). Defaults to daily.
 */
function computeNextRunAt(frequency) {
  const hours = frequency === "weekly" ? 7 * 24 : 24;
  return new Date(Date.now() + hours * 60 * 60 * 1_000).toISOString();
}

async function getDueReportSchedules(env, now = new Date().toISOString()) {
  const rows = await env.cybermeters_db
    .prepare(
      `SELECT id, workspace_id, created_by, frequency, enabled, email_recipients,
              last_run_at, next_run_at, created_at, updated_at
       FROM report_schedules rs2
         JOIN workspaces w2 ON w2.id = rs2.workspace_id AND w2.deleted_at IS NULL
       WHERE enabled = 1 AND next_run_at <= ?
       ORDER BY next_run_at ASC`
    )
    .bind(now)
    .all();
  return (rows.results || []).map((row) => ({
    ...row,
    email_recipients: (() => { try { return JSON.parse(row.email_recipients || "[]"); } catch { return []; } })(),
  }));
}

async function executeDueReportSchedules(env, now = new Date().toISOString()) {
  let schedules = [];
  try {
    schedules = await getDueReportSchedules(env, now);
  } catch {
    return { processed: 0, completed: 0, failed: 0 };
  }

  const summary = { processed: 0, completed: 0, failed: 0 };
  for (const schedule of schedules) {
    summary.processed += 1;
    const runId = createId("rsrun");
    const startedAt = new Date().toISOString();
    try {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO report_schedule_runs
             (id, schedule_id, workspace_id, started_at, status, created_at)
           VALUES (?, ?, ?, ?, 'running', ?)`
        )
        .bind(runId, schedule.id, schedule.workspace_id, startedAt, startedAt)
        .run();
      await createAuditEvent(env, {
        workspace_id: schedule.workspace_id,
        user_id: schedule.created_by,
        event_type: "report_schedule_run_started",
        entity_type: "report_schedule",
        entity_id: schedule.id,
        description: `Report schedule run started (${schedule.frequency})`,
        metadata: { run_id: runId, schedule_id: schedule.id, frequency: schedule.frequency },
      });

      const reportType = schedule.frequency === "weekly" ? "weekly_executive" : "monthly_executive";
      const report = await generateWorkspaceExecutiveReport(schedule.workspace_id, env, { report_type: reportType });
      const completedAt = new Date().toISOString();
      const nextRunAt = calculateNextRun(schedule.frequency, completedAt);
      await env.cybermeters_db
        .prepare(
          `UPDATE report_schedule_runs
           SET status = 'completed', completed_at = ?, report_id = ?
           WHERE id = ?`
        )
        .bind(completedAt, report.id, runId)
        .run();
      await env.cybermeters_db
        .prepare(
          `UPDATE report_schedules
           SET last_run_at = ?, next_run_at = ?, updated_at = ?
           WHERE id = ?`
        )
        .bind(completedAt, nextRunAt, completedAt, schedule.id)
        .run();
      await createAuditEvent(env, {
        workspace_id: schedule.workspace_id,
        user_id: schedule.created_by,
        event_type: "report_schedule_run_completed",
        entity_type: "report_schedule",
        entity_id: schedule.id,
        description: `Report schedule run completed (${schedule.frequency})`,
        metadata: { run_id: runId, schedule_id: schedule.id, report_id: report.id, next_run_at: nextRunAt },
      });
      summary.completed += 1;
    } catch (err) {
      const completedAt = new Date().toISOString();
      const nextRunAt = calculateNextRun(schedule.frequency, completedAt);
      const errorMessage = String(err?.message ?? err).slice(0, 500);
      await env.cybermeters_db
        .prepare(
          `UPDATE report_schedule_runs
           SET status = 'failed', completed_at = ?, error_message = ?
           WHERE id = ?`
        )
        .bind(completedAt, errorMessage, runId)
        .run()
        .catch(() => {});
      await env.cybermeters_db
        .prepare(
          `UPDATE report_schedules
           SET last_run_at = ?, next_run_at = ?, updated_at = ?
           WHERE id = ?`
        )
        .bind(completedAt, nextRunAt, completedAt, schedule.id)
        .run()
        .catch(() => {});
      await createAuditEvent(env, {
        workspace_id: schedule.workspace_id,
        user_id: schedule.created_by,
        event_type: "report_schedule_run_failed",
        entity_type: "report_schedule",
        entity_id: schedule.id,
        description: `Report schedule run failed (${schedule.frequency})`,
        metadata: { run_id: runId, schedule_id: schedule.id, error_message: errorMessage, next_run_at: nextRunAt },
      }).catch(() => {});
      summary.failed += 1;
    }
  }
  return summary;
}

/**
 * Create and run a scan for one scheduled_scans row.
 * This function is always called inside ctx.waitUntil() so it is safe to await
 * runScanEngine directly — we are already within the extended Worker lifetime.
 * Never throws — a failure on one schedule must not abort others.
 */
async function triggerScheduledScan(schedule, env) {
  const scanId = createId("scan");
  const now    = new Date().toISOString();

  // Resolve workspace owner. A schedule whose workspace has no live owner is
  // SKIPPED honestly (M5.e) — a fabricated demo identity must never own real
  // customer scans or domains.
  let userId = null;
  if (schedule.workspace_id) {
    const ownerRow = await env.cybermeters_db
      .prepare("SELECT owner_user_id FROM workspaces WHERE id = ? AND deleted_at IS NULL LIMIT 1")
      .bind(schedule.workspace_id)
      .first()
      .catch(() => null);
    if (ownerRow?.owner_user_id) {
      userId = ownerRow.owner_user_id;
    }
  }
  if (!userId) {
    console.log(JSON.stringify({ event: "scheduled_scan_skipped", reason: "no_workspace_owner", schedule_id: schedule.id ?? null, workspace_id: schedule.workspace_id ?? null }));
    return;
  }

  try {

    // ── Reuse existing domain row so inventory stays on one domain_id ─────────
    // Creating a new row on every run fragments history and breaks workspace links.
    let domainId;
    const existingDomain = await env.cybermeters_db
      .prepare(`SELECT id FROM domains WHERE user_id = ? AND domain = ? LIMIT 1`)
      .bind(userId, schedule.domain)
      .first();

    if (existingDomain) {
      domainId = existingDomain.id;
    } else {
      domainId = createId("domain");
      await env.cybermeters_db
        .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
        .bind(domainId, userId, schedule.domain)
        .run();
    }

    // ── Ensure workspace_domains link exists (idempotent) ─────────────────────
    // This allows upsertAssetInventory and sendAssetChangeAlert to find the
    // workspace for this domain, even if the schedule was created before the
    // workspace link was set up.
    if (schedule.workspace_id) {
      await env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
           VALUES (?, ?)`
        )
        .bind(schedule.workspace_id, domainId)
        .run();
    }

    // ── Scheduled-scan eligibility gate (canonical, run-time) ─────────────────
    // A scheduled scan must satisfy the SAME current security/entitlement/quota
    // rules as a manual scan AT EXECUTION TIME — verified link, workspace still
    // accessible, scheduled-scans feature entitled, monthly quota available, and
    // the scan-start rate limit (fail-closed). Reuses the canonical helpers; no
    // plan rules are copied here. On any failure it skips with a stable reason —
    // NO scan row, NO R2 placeholder, NO report/case/telemetry side effect — and
    // never mutates the schedule config (a downgraded account is not charged or
    // counted for a scan that never started).
    const eligibility = await evaluateScheduledScanEligibility(env, {
      workspaceId: schedule.workspace_id,
      domainId,
      ownerUserId: userId,
      consumeRateLimit: ({ billingOwnerId, plan }) => consumeApiRateLimit(
        env,
        [
          { scope: "user", scope_id: billingOwnerId },
          { scope: "workspace", scope_id: schedule.workspace_id },
          { scope: "account", scope_id: billingOwnerId },
        ],
        "scan_start",
        getPlanLimits(plan).scan_starts_per_hour,
        3600,
        { failClosed: true }
      ),
    });
    if (!eligibility.ok) {
      console.log("[scheduled-scan] skipped", JSON.stringify({
        schedule_id: schedule.id ?? null, workspace_id: schedule.workspace_id ?? null,
        domain_id: domainId, domain: schedule.domain, reason: eligibility.reason,
      }));
      return;
    }

    // Create scan row — admission is decided by the database (PR-2): migration
    // 099's partial unique index allows at most one active scan per
    // (workspace_id, domain). If a scan is already in flight for this domain
    // (e.g. a manual scan the customer just started), skip exactly like an
    // eligibility failure — no R2 placeholder, no last_run_at stamp, no engine
    // start — and the schedule stays due, so the next hourly tick retries once
    // the active scan reaches a terminal state.
    try {
      await env.cybermeters_db
        .prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES (?, ?, ?, ?, ?)`)
        .bind(scanId, domainId, schedule.workspace_id ?? null, schedule.domain, "running")
        .run();
    } catch (insertErr) {
      if (!isUniqueConstraintError(insertErr)) throw insertErr;
      console.log("[scheduled-scan] skipped", JSON.stringify({
        schedule_id: schedule.id ?? null, workspace_id: schedule.workspace_id ?? null,
        domain_id: domainId, domain: schedule.domain, reason: ACTIVE_SCAN_CONFLICT_CODE,
      }));
      return;
    }

    // Write placeholder report so GET /report returns 200 immediately
    await env.cybermeters_reports.put(
      `reports/${scanId}.json`,
      JSON.stringify({
        scan_id:             scanId,
        domain_id:           domainId,
        domain:              schedule.domain,
        status:              "running",
        cyber_metrics_score: 0,
        risk_level:          "unknown",
        findings:            [],
        recommendations:     [],
        message:             "Scheduled scan in progress.",
      }, null, 2),
      { httpMetadata: { contentType: "application/json" } }
    );

    // Stamp last_run_at and compute next_run_at before starting the engine
    await env.cybermeters_db
      .prepare(
        `UPDATE scheduled_scans SET last_run_at = ?, next_run_at = ? WHERE id = ?`
      )
      .bind(now, computeNextRunAt(schedule.frequency), schedule.id)
      .run();

    console.log("[scheduled-monitoring]", JSON.stringify({
      schedule_id:  schedule.id,
      workspace_id: schedule.workspace_id ?? null,
      domain:       schedule.domain,
      scan_id:      scanId,
      domain_id:    domainId,
    }));

    await createAuditEvent(env, {
      workspace_id: schedule.workspace_id ?? null,
      user_id:     userId,
      event_type:  "scheduled_scan_triggered",
      entity_type: "scheduled_scan",
      entity_id:   schedule.id,
      description: `Scheduled scan triggered for ${schedule.domain}`,
      metadata:    { scheduled_scan_id: schedule.id, scan_id: scanId, domain: schedule.domain, domain_id: domainId },
    });

    // Run the full scan engine — awaited inside waitUntil context
    // Specific catch so a scan failure updates status and notifies the workspace owner.
    try {
      await runScanEngine(scanId, domainId, schedule.workspace_id ?? null, schedule.domain, env);
    } catch (scanErr) {
      console.error("[scheduled-scan] FAILED", schedule.id, scanErr?.message);
      // Downgrade-safe: runScanEngine's own catch already routes through the
      // canonical finalizeScanResult latch (idempotent, never downgrades a durable
      // 'completed'). This scheduled-path catch is only a redundant safety net, so
      // it must NEVER clobber a completed scan. Guard the D1 write with
      // `status != 'completed'` and skip the R2 overwrite if the report already
      // finalized as completed. scan_quality is never fabricated here.
      await env.cybermeters_db
        .prepare("UPDATE scans SET status = 'failed' WHERE id = ? AND status != 'completed'")
        .bind(scanId)
        .run()
        .catch(() => {});
      // Only overwrite the R2 placeholder if it did not already finalize completed.
      let alreadyCompleted = false;
      try {
        const existingReport = await env.cybermeters_reports.get(`reports/${scanId}.json`);
        if (existingReport) alreadyCompleted = (await existingReport.json())?.status === "completed";
      } catch { /* treat as not-completed → safe to write failure placeholder */ }
      if (!alreadyCompleted) {
        await env.cybermeters_reports.put(
          `reports/${scanId}.json`,
          JSON.stringify({
            scan_id:             scanId,
            domain_id:           domainId,
            domain:              schedule.domain,
            status:              "failed",
            cyber_metrics_score: 0,
            risk_level:          "unknown",
            findings:            [],
            recommendations:     [],
            message:             "Scheduled scan failed. Please check your domain configuration or contact support.",
          }, null, 2),
          { httpMetadata: { contentType: "application/json" } }
        ).catch(() => {});
      }
      // Create in-app notification for workspace owner
      if (schedule.workspace_id) {
        await createNotificationEvent(env, schedule.workspace_id, {
          type:     "scheduled_scan_failed",
          severity: "high",
          title:    "Scheduled scan failed",
          message:  `The scheduled scan for ${schedule.domain} failed to complete. Your next scheduled run will try again automatically.`,
          metadata: { scheduled_scan_id: schedule.id, scan_id: scanId, domain: schedule.domain },
          user_id:  userId,
        }).catch(() => {});
      }
    }

    // ── Update asset counts after scan completes ───────────────────────────────
    if (schedule.workspace_id) {
      try {
        const [eventsResult, totalResult] = await Promise.all([
          env.cybermeters_db
            .prepare(
              `SELECT event_type FROM asset_events
               WHERE scan_id = ? AND workspace_id = ?`
            )
            .bind(scanId, schedule.workspace_id)
            .all(),
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM workspace_assets
               WHERE workspace_id = ? AND status = 'active'`
            )
            .bind(schedule.workspace_id)
            .first(),
        ]);
        const changeCount = (eventsResult.results || []).filter(
          (e) => e.event_type === "new_asset_discovered" || e.event_type === "asset_reappeared"
        ).length;
        await env.cybermeters_db
          .prepare(
            `UPDATE scheduled_scans
             SET last_asset_count = ?, asset_change_count = ?
             WHERE id = ?`
          )
          .bind(totalResult?.n ?? 0, changeCount, schedule.id)
          .run();
        console.log("[scheduled-monitoring]", JSON.stringify({
          schedule_id:        schedule.id,
          workspace_id:       schedule.workspace_id,
          scan_id:            scanId,
          last_asset_count:   totalResult?.n ?? 0,
          asset_change_count: changeCount,
        }));
      } catch (e) {
        console.error("[scheduled-monitoring] asset count update failed:", e?.message);
      }
    }

    // Note: Alert phase is now handled uniformly during scan completion in runScanEngine (Phase 10).
  } catch {
    // Graceful failure — one schedule erroring must not affect the others
  }
}



// ── Executive Report Archive ──────────────────────────────────────────────────
// ── Deletion purge engine ─────────────────────────────────────────────────────
// Approved lifecycle: soft-delete (deleted_at) hides the data immediately; the
// deletion_requests row stays 'pending' for DELETION_PURGE_WINDOW_DAYS during
// which the owner can restore; after the window the hourly cron hard-deletes
// D1 rows and R2 report objects in bounded chunks. audit_events, subscriptions
// and the deletion_requests row itself are retained (audit + accounting).
const DELETION_PURGE_WINDOW_DAYS = 30;
const PURGE_R2_BATCH = 25; // max R2 deletes per cron run — respects subrequest limits

// Pure, testable: has a pending/purging request passed its purge window?
function isDeletionPurgeDue(requestRow, nowMs = Date.now()) {
  if (!requestRow) return false;
  const status = String(requestRow.status || "").toLowerCase();
  if (!["pending", "purging"].includes(status)) return false;
  const created = requestRow.created_at ? new Date(requestRow.created_at).getTime() : NaN;
  if (Number.isNaN(created)) return false;
  return nowMs >= created + DELETION_PURGE_WINDOW_DAYS * 24 * 60 * 60 * 1000;
}

// Tables hard-deleted by workspace_id, children before parents. audit_events,
// subscriptions and deletion_requests are intentionally NOT here.
// Tables with a FOREIGN KEY to scans(id). D1 enforces FKs, so these MUST be
// deleted (by scan_id) BEFORE the scan row, or the scan DELETE fails and the
// purge stalls forever. Kept in sync with the schema by the regression test
// `purge_covers_all_scan_fk_tables`.
const SCAN_CHILD_TABLES = [
  "findings", "hidden_assets", "kev_matches", "remediation_items", "reports",
  "scan_module_telemetry",
];

// Tables hard-deleted by workspace_id, children before parents.
//
// INTENTIONALLY NOT HERE, and each for a stated reason — anything else that is
// absent is a bug, not a decision:
//   • audit_events, subscriptions, deletion_requests — retained (audit/accounting/
//     tracking); see DELETION_PURGE_WINDOW_DAYS above.
//   • scans, workspace_reports, scan_report_snapshots — purged by purgeWorkspaceData
//     itself, ahead of this list, because their R2 objects must go first.
//
// This list is now enforced STRUCTURALLY, not by hand: validate-purge-completeness
// derives every workspace_id-bearing table from the real schema and fails if one is
// neither purged here nor in its explicit exception allowlist.
//
// It previously claimed to be "kept in sync by `purge_covers_all_workspace_fk_tables`".
// That test did not exist — the name appears nowhere in the repository, and neither
// does `purge_covers_all_scan_fk_tables` below. The suite that did exist seeded rows
// only for tables ALREADY in this list, so it could only ever confirm the list purges
// itself; a forgotten table was never seeded and never checked. That is exactly how
// cyber_essentials_answers came to survive a purge the product calls permanent, for
// as long as the table has existed. A comment asserting a guard nobody wrote is worse
// than no comment: it stops the next person looking.
const WORKSPACE_PURGE_TABLES = [
  // email_protection_events holds no FK to either record family it describes
  // (hosted_dns_entries is hard-deleted on removal, and one column carries ids
  // from both), so it is purged on its own workspace_id ahead of them.
  "email_protection_events",
  "dmarc_aggregate_records", "dmarc_aggregate_reports", "email_sender_sources",
  "brand_abuse_campaigns",
  "dmarc_ingest_endpoints", "workspace_brand_assets", "workspace_brand_profiles",
  "asset_events", "asset_alert_records", "workspace_assets",
  "managed_case_events", "brand_evidence_bundles", "managed_cases",
  "certificate_observations", "identity_assets", "historical_scores",
  "vendor_risk_scores", "vendor_risk_scores_history", "workspace_vendors",
  "shadow_it_inventory_events", "shadow_it_inventory",
  "certificate_lifecycle_events", "certificate_lifecycle",
  "identity_exposure_events", "identity_exposure",
  // Website Security lifecycle (mig 089). Events first: they hold no FK to the
  // conditions table (history must outlive the record it describes), so they are
  // purged on their own workspace_id ahead of it.
  "website_security_events", "website_security_conditions",
  // Cyber Essentials lifecycle (mig 090). Events first: no FK to the records table.
  "cyber_essentials_events", "cyber_essentials_control_records",
  // Canonical per-domain Cyber MOT state history (mig 091). Append-only, one row per
  // (workspace, domain, scan, domain_key). Holds no FK to scans — history outlives the
  // scan it describes — so it is purged on its own workspace_id here and never appears
  // in SCAN_CHILD_TABLES.
  "cyber_mot_domain_states",
  // Canonical per-workspace eight-domain maturity ledger (mig 095). Append-only, one row
  // per (workspace, domain, scan, domain_key). Holds no FK to scans — history outlives the
  // scan — so it is purged on its own workspace_id here, never in SCAN_CHILD_TABLES.
  "domain_maturity_ledger",
  // Cyber Essentials questionnaire answers. Customer-entered content — including
  // `note` (free text) and `answered_by` (a user id) — so it is customer data by
  // any reading, and the deletion email tells the owner it has been "permanently
  // removed". It was absent from this list for the table's entire life: it carries
  // no FK to workspaces(id), so D1 could not block the parent delete either, and
  // every row simply outlived the workspace it belonged to.
  "cyber_essentials_answers",
  "workspace_brs_scores", "workspace_brs_score_history",
  "workspace_supply_chain_scores", "workspace_supply_chain_history",
  "alert_deliveries", "alert_activation", "notification_events", "notification_preferences",
  "report_schedule_runs", "report_schedules", "scheduled_reports",
  "workspace_invitations", "workspace_members", "workspace_retention_settings",
  "lifecycle_email_events", "scheduled_scans", "workspace_domains",
  "finding_waivers", "api_tokens", "workspace_alert_channels",
  "hosted_dns_records", "hosted_dns_entries",
  "tlsrpt_aggregate_reports", "tlsrpt_failure_details",
  "dmarc_change_requests",
  // Per-workspace report branding (mig 096). Customer-uploaded logo metadata +
  // display name; its R2 logo objects are deleted in step 1c above before this row.
  "workspace_branding",
  // M6 Phase B1 Related Changes (mig 098). Evidence pointers first (child), then the
  // clusters (parent) — the evidence table FKs the cluster, so a FK-enforcing engine
  // must not see the parent vanish before the child.
  "related_change_evidence", "related_changes",
];

/**
 * purgeWorkspaceData — one bounded chunk of hard deletion for a workspace.
 * Returns { done: true } when nothing remains (the workspaces row itself is
 * left for the caller so it can resolve the owner for notification first).
 * R2 objects are deleted before their D1 pointer rows so a crash between the
 * two can only leave orphan-free state (a missing R2 object is tolerated).
 */
async function purgeWorkspaceData(env, workspaceId) {
  // 1. Executive/PDF reports stored in R2 (workspace_reports.report_key)
  const reports = await env.cybermeters_db
    .prepare("SELECT id, report_key FROM workspace_reports WHERE workspace_id = ? LIMIT ?")
    .bind(workspaceId, PURGE_R2_BATCH).all().catch(() => null);
  if ((reports?.results || []).length > 0) {
    for (const r of reports.results) {
      if (r.report_key) await env.cybermeters_reports.delete(r.report_key).catch(() => {});
      await env.cybermeters_db
        .prepare("DELETE FROM workspace_reports WHERE id = ?").bind(r.id).run().catch(() => {});
    }
    return { done: false }; // more may remain — continue next run
  }

  // 1b. Canonical reporting snapshots (mig 093): R2 JSON objects
  // (scan_report_snapshots.r2_key), then their D1 pointer rows — the same
  // R2-before-pointer ordering as workspace_reports above. No FK to scans, so
  // these rows are pointer-purged here and never appear in SCAN_CHILD_TABLES.
  const snaps = await env.cybermeters_db
    .prepare("SELECT id, r2_key FROM scan_report_snapshots WHERE workspace_id = ? LIMIT ?")
    .bind(workspaceId, PURGE_R2_BATCH).all().catch(() => null);
  if ((snaps?.results || []).length > 0) {
    for (const s of snaps.results) {
      if (s.r2_key) await env.cybermeters_reports.delete(s.r2_key).catch(() => {});
      await env.cybermeters_db
        .prepare("DELETE FROM scan_report_snapshots WHERE id = ?").bind(s.id).run().catch(() => {});
    }
    return { done: false }; // more may remain — continue next run
  }

  // 1c. Per-workspace branding logos in R2 (branding/logos/{workspaceId}/…),
  // including superseded content-addressed objects a workspace uploaded over time.
  // R2 objects first (bounded), then the workspace_branding pointer row via
  // WORKSPACE_PURGE_TABLES below — the same R2-before-pointer ordering as reports.
  const logos = typeof env.cybermeters_reports.list === "function"
    ? await env.cybermeters_reports
        .list({ prefix: `branding/logos/${encodeURIComponent(workspaceId)}/`, limit: PURGE_R2_BATCH })
        .catch(() => null)
    : null;
  if ((logos?.objects || []).length > 0) {
    for (const o of logos.objects) await env.cybermeters_reports.delete(o.key).catch(() => {});
    return { done: false }; // more may remain — continue next run
  }

  // 2. Scan reports stored in R2 (reports/{scan_id}.json), then the scan rows
  const scans = await env.cybermeters_db
    .prepare("SELECT id FROM scans WHERE workspace_id = ? LIMIT ?")
    .bind(workspaceId, PURGE_R2_BATCH).all().catch(() => null);
  if ((scans?.results || []).length > 0) {
    for (const s of scans.results) {
      await env.cybermeters_reports.delete(`reports/${s.id}.json`).catch(() => {});
      // Delete scan children first — D1 enforces the scans FKs, so the scan
      // DELETE below fails (and the purge stalls) if any child row remains.
      for (const child of SCAN_CHILD_TABLES) {
        await env.cybermeters_db
          .prepare(`DELETE FROM ${child} WHERE scan_id = ?`).bind(s.id).run().catch(() => {});
      }
      await env.cybermeters_db
        .prepare("DELETE FROM scans WHERE id = ?").bind(s.id).run().catch(() => {});
    }
    return { done: false };
  }

  // 3. Remaining workspace-scoped D1 rows. Per-table statements (not batch)
  // so a table missing in an older database cannot abort the purge.
  for (const table of WORKSPACE_PURGE_TABLES) {
    await env.cybermeters_db
      .prepare(`DELETE FROM ${table} WHERE workspace_id = ?`)
      .bind(workspaceId).run().catch(() => {});
  }
  return { done: true };
}

// User-scoped rows removed on account purge (after all owned workspaces are
// gone). subscriptions/subscription_events are retained for accounting.
const ACCOUNT_PURGE_TABLES = [
  "user_sessions", "password_reset_tokens", "api_tokens",
  "mfa_challenges", "oauth_states", "customer_profiles",
];

/**
 * processDeletionRequests — hourly cron entry point. Processes at most two
 * due requests per run, each in bounded chunks, so one giant workspace can
 * never starve the cron or blow subrequest limits. Never throws.
 */
async function processDeletionRequests(env) {
  try {
    const rows = await env.cybermeters_db
      .prepare(`SELECT id, request_type, user_id, workspace_id, status, created_at
                FROM deletion_requests
                WHERE status IN ('pending', 'purging')
                ORDER BY created_at ASC
                LIMIT 10`)
      .all().catch(() => null);
    const due = (rows?.results || []).filter((r) => isDeletionPurgeDue(r)).slice(0, 2);

    for (const req of due) {
      if (req.status !== "purging") {
        await env.cybermeters_db
          .prepare("UPDATE deletion_requests SET status = 'purging', updated_at = datetime('now') WHERE id = ?")
          .bind(req.id).run().catch(() => {});
      }
      if (req.request_type === "workspace") {
        await purgeWorkspaceRequest(env, req);
      } else if (req.request_type === "account") {
        await purgeAccountRequest(env, req);
      }
    }
  } catch (e) {
    console.error("[deletion-purge]", String(e?.message ?? e));
  }
}

async function completeDeletionRequest(env, requestId, status = "completed") {
  await env.cybermeters_db
    .prepare("UPDATE deletion_requests SET status = ?, updated_at = datetime('now') WHERE id = ?")
    .bind(status, requestId).run().catch(() => {});
}

/**
 * opsHealthHeartbeat — daily self-check. Runs the read-only ops-health signals
 * (stuck scans, undelivered email/alert backlogs, overdue deletion purges) and
 * emails ops (ALERT_EMAIL_TO) ONLY when a threshold is breached, so a healthy
 * system stays silent. Records a metric every run for trend visibility. Never
 * throws — wrapped by runCronTask, but defensive here too.
 */
async function opsHealthHeartbeat(env) {
  const health = await computeOpsHealth(env);
  const breached = health.signals.filter((s) => s.breached).map((s) => s.key);
  recordMetric(env, "ops_health", {
    blobs: [health.healthy ? "healthy" : "unhealthy", breached.join(",") || "none"],
    doubles: [breached.length],
    indexes: [health.healthy ? "healthy" : "unhealthy"],
  });
  if (health.healthy) return;

  console.error("[ops-health]", JSON.stringify({
    healthy: false, db_reachable: health.dbReachable, breached,
    signals: health.signals.map((s) => ({ key: s.key, count: s.count, threshold: s.threshold })),
  }));

  const mail = formatOpsHealthEmail(health, { version: env.APP_VERSION || "dev" });
  if (mail) {
    await sendAlertEmail(mail.subject, mail.text, mail.html, env, "ALERT_EMAIL_FROM").catch(() => {});
  }
}

async function purgeWorkspaceRequest(env, req) {
  const ws = await env.cybermeters_db
    .prepare("SELECT id, name, deleted_at, owner_user_id FROM workspaces WHERE id = ? LIMIT 1")
    .bind(req.workspace_id).first().catch(() => null);

  // Already gone → complete. Restored without cancelling → cancel, never purge live data.
  if (!ws) return completeDeletionRequest(env, req.id, "completed");
  if (!ws.deleted_at) {
    await createAuditEvent(env, {
      workspace_id: req.workspace_id, user_id: req.user_id,
      event_type: "workspace_purge_cancelled", entity_type: "workspace", entity_id: req.workspace_id,
      description: "Purge skipped: workspace was restored before the purge window elapsed",
      metadata: { request_id: req.id },
    }).catch(() => {});
    return completeDeletionRequest(env, req.id, "cancelled");
  }

  const { done } = await purgeWorkspaceData(env, req.workspace_id);
  if (!done) return; // continue in a later run

  // Resolve owner for notification BEFORE removing the workspace row.
  const owner = await env.cybermeters_db
    .prepare("SELECT email, email_verified FROM users WHERE id = ? LIMIT 1")
    .bind(ws.owner_user_id).first().catch(() => null);

  await env.cybermeters_db
    .prepare("DELETE FROM workspaces WHERE id = ?").bind(req.workspace_id).run().catch(() => {});

  await createAuditEvent(env, {
    workspace_id: req.workspace_id, user_id: req.user_id,
    event_type: "workspace_purged", entity_type: "workspace", entity_id: req.workspace_id,
    description: `Workspace "${ws.name}" permanently deleted after the ${DELETION_PURGE_WINDOW_DAYS}-day window`,
    metadata: { request_id: req.id },
  }).catch(() => {});
  await completeDeletionRequest(env, req.id, "completed");

  if (owner?.email_verified && isValidEmail(String(owner.email || "").toLowerCase())) {
    const text = `Your CyberMeters workspace has been permanently deleted\n\nThe workspace "${ws.name}" and all of its data have now been permanently removed, as requested.\n\nIf you did not expect this, contact CyberMeters support.\n\nCyberMeters`;
    const html = `<p>The workspace <strong>${escapeEmailHtml(ws.name)}</strong> and all of its data have now been permanently removed, as requested.</p><p>If you did not expect this, contact CyberMeters support.</p><p>CyberMeters</p>`;
    await sendCustomerEmail("Your CyberMeters workspace has been permanently deleted", text, html, env, "HELLO_EMAIL_FROM", [String(owner.email).toLowerCase()]).catch(() => {});
  }
}

async function purgeAccountRequest(env, req) {
  const user = await env.cybermeters_db
    .prepare("SELECT id, email, email_verified FROM users WHERE id = ? LIMIT 1")
    .bind(req.user_id).first().catch(() => null);
  if (!user) return completeDeletionRequest(env, req.id, "completed");

  // Never delete a paying account: an active subscription must be cancelled
  // first (protects the customer from losing paid access by accident).
  const activeSub = await env.cybermeters_db
    .prepare(`SELECT id FROM subscriptions WHERE owner_user_id = ?
              AND LOWER(COALESCE(subscription_status, '')) IN ('active', 'trialing', 'past_due') LIMIT 1`)
    .bind(req.user_id).first().catch(() => null);
  if (activeSub) {
    await createAuditEvent(env, {
      user_id: req.user_id, event_type: "account_purge_blocked", entity_type: "user", entity_id: req.user_id,
      description: "Account purge blocked: subscription is not cancelled",
      metadata: { request_id: req.id },
    }).catch(() => {});
    return completeDeletionRequest(env, req.id, "blocked_active_subscription");
  }

  // Purge owned workspaces one chunk at a time; stay 'purging' until all gone.
  const owned = await env.cybermeters_db
    .prepare("SELECT id FROM workspaces WHERE owner_user_id = ? LIMIT 1")
    .bind(req.user_id).first().catch(() => null);
  if (owned) {
    const { done } = await purgeWorkspaceData(env, owned.id);
    if (done) {
      await env.cybermeters_db
        .prepare("DELETE FROM workspaces WHERE id = ?").bind(owned.id).run().catch(() => {});
    }
    return; // more work (this or other workspaces) — continue next run
  }

  // Farewell email BEFORE the user row disappears.
  if (user.email_verified && isValidEmail(String(user.email || "").toLowerCase())) {
    const text = `Your CyberMeters account has been deleted\n\nYour account and all associated data have now been permanently removed, as requested.\n\nThank you for trying CyberMeters.\n\nCyberMeters`;
    const html = `<p>Your account and all associated data have now been permanently removed, as requested.</p><p>Thank you for trying CyberMeters.</p><p>CyberMeters</p>`;
    await sendCustomerEmail("Your CyberMeters account has been deleted", text, html, env, "HELLO_EMAIL_FROM", [String(user.email).toLowerCase()]).catch(() => {});
  }

  for (const table of ACCOUNT_PURGE_TABLES) {
    await env.cybermeters_db
      .prepare(`DELETE FROM ${table} WHERE user_id = ?`).bind(req.user_id).run().catch(() => {});
  }
  await env.cybermeters_db
    .prepare("DELETE FROM workspace_members WHERE user_id = ?").bind(req.user_id).run().catch(() => {});
  await env.cybermeters_db
    .prepare("DELETE FROM users WHERE id = ?").bind(req.user_id).run().catch(() => {});

  await createAuditEvent(env, {
    user_id: req.user_id, event_type: "account_purged", entity_type: "user", entity_id: req.user_id,
    description: `Account permanently deleted after the ${DELETION_PURGE_WINDOW_DAYS}-day window`,
    metadata: { request_id: req.id },
  }).catch(() => {});
  await completeDeletionRequest(env, req.id, "completed");
}

// processScheduledReports — called from scheduled() via ctx.waitUntil().
// Checks the scheduled_reports table for due rows, generates reports, updates timestamps.
async function processScheduledReports(now, env) {
  let rows;
  try {
    const r = await env.cybermeters_db
      .prepare(
        `SELECT sr.id, sr.workspace_id, sr.report_type, sr.frequency
         FROM scheduled_reports sr
         JOIN workspaces w ON w.id = sr.workspace_id AND w.deleted_at IS NULL
         WHERE sr.enabled = 1
           AND (sr.next_run_at IS NULL OR sr.next_run_at <= ?)
         ORDER BY sr.next_run_at ASC
         LIMIT 20`
      )
      .bind(now)
      .all();
    rows = r.results ?? [];
  } catch {
    // Table may not exist yet
    return;
  }

  for (const sr of rows) {
    try {
      const reportRow = await generateWorkspaceExecutiveReport(sr.workspace_id, env, {
        report_type: sr.report_type,
      });

      const nextRunAt = computeScheduledReportNextRunAt(sr.frequency);
      await env.cybermeters_db
        .prepare(
          `UPDATE scheduled_reports
           SET last_run_at = ?, next_run_at = ?
           WHERE id = ?`
        )
        .bind(now, nextRunAt, sr.id)
        .run();

      // Notification + audit ONLY when THIS invocation actually generated the report.
      // A concurrent invocation that lost the occurrence claim (reportRow.claimed ===
      // false) must not emit a duplicate customer notification.
      if (reportRow?.claimed !== false) {
        try {
          await createNotificationEvent(env, sr.workspace_id, {
            type:     "report_schedule_executed",
            severity: "info",
            title:    `Scheduled report generated`,
            message:  `${sr.report_type.replace(/_/g, ' ')} report generated automatically (${sr.frequency})`,
            metadata: { scheduled_report_id: sr.id, report_id: reportRow?.id, report_type: sr.report_type },
          });
        } catch { /* non-fatal */ }

        try {
          await createAuditEvent(env, {
            workspace_id: sr.workspace_id,
            event_type:   "scheduled_report_executed",
            entity_type:  "scheduled_report",
            entity_id:    sr.id,
            description:  `Scheduled ${sr.report_type} report generated automatically (${sr.frequency})`,
            metadata:     { scheduled_report_id: sr.id, report_id: reportRow?.id, report_type: sr.report_type, next_run_at: nextRunAt },
          });
        } catch { /* non-fatal */ }
      }

    } catch {
      // One workspace failing must not abort others
    }
  }
}

async function cleanupExpiredReports(nowIso, env) {
  const now = new Date(nowIso);
  const deadlineMs = Date.now() + 25_000;
  const metrics = { scanned: 0, expired: 0, r2_deleted: 0, metadata_soft_deleted: 0, failed: 0 };
  const skippedIds = new Set();
  const retentionByWorkspace = new Map();

  while (Date.now() < deadlineMs) {
    let candidates;
    try {
      const skipped = [...skippedIds];
      const skipClause = skipped.length > 0
        ? `AND id NOT IN (${skipped.map(() => "?").join(",")})`
        : "";
      const stmt = env.cybermeters_db.prepare(
        `SELECT id, workspace_id, report_type, report_period, report_key, retention_policy,
                COALESCE(generated_at, created_at) AS effective_at
         FROM workspace_reports
         WHERE deleted_at IS NULL
           ${skipClause}
         ORDER BY COALESCE(generated_at, created_at) ASC
         LIMIT 100`
      );
      const rows = skipped.length > 0 ? await stmt.bind(...skipped).all() : await stmt.all();
      candidates = rows.results || [];
    } catch {
      break;
    }

    if (candidates.length === 0) break;
    let expiredInBatch = 0;
    metrics.scanned += candidates.length;

    for (const report of candidates) {
      if (Date.now() >= deadlineMs) break;
      try {
        if (!retentionByWorkspace.has(report.workspace_id)) {
          retentionByWorkspace.set(report.workspace_id, await getWorkspaceRetentionSettings(report.workspace_id, env));
        }
        const retention = retentionByWorkspace.get(report.workspace_id);
        if (!retention.auto_cleanup || retention.retention_days === null) {
          skippedIds.add(report.id);
          continue;
        }
        const cutoff = getRetentionCutoffForDays(retention.retention_days, now);
        if (!cutoff || String(report.effective_at || "") > cutoff) {
          skippedIds.add(report.id);
          continue;
        }

        expiredInBatch += 1;
        metrics.expired += 1;
        await env.cybermeters_reports.delete(report.report_key);
        metrics.r2_deleted += 1;
        const deletedAt = new Date().toISOString();
        const result = await env.cybermeters_db
          .prepare(
            `UPDATE workspace_reports
             SET deleted_at = ?, deleted_reason = ?
             WHERE id = ? AND deleted_at IS NULL`
          )
          .bind(deletedAt, "retention_expired", report.id)
          .run();
        if ((result.meta?.changes ?? 0) > 0) metrics.metadata_soft_deleted += 1;

        await createAuditEvent(env, {
          workspace_id: report.workspace_id,
          event_type:   "report_deleted",
          entity_type:  "report",
          entity_id:    report.id,
          description:  `Report expired by retention policy (${retention.retention_policy})`,
          metadata:     {
            report_id: report.id,
            workspace_id: report.workspace_id,
            user_id: null,
            report_type: report.report_type,
            report_period: report.report_period,
            retention_policy: retention.retention_policy,
            retention_days: retention.retention_days,
            deletion_reason: "retention_expired",
          },
        });
      } catch {
        metrics.failed += 1;
        skippedIds.add(report.id);
      }
    }

    if (expiredInBatch === 0 || skippedIds.size > 500) break;
  }

  return metrics;
}

// generateScheduledReports — called from scheduled() via ctx.waitUntil().
// Generates weekly reports on Mondays, monthly reports on the 1st of the month.
// Skips if a report for the same (workspace, type, period) already exists.

// Weekly (Monday) / monthly (1st) executive report generation, BOUNDED per cron
// invocation. All batching / determinism / idempotency / fairness / entitlement /
// observability lives in engines/scheduled-reports.js so it is unit-testable without
// the Worker runtime. The deferred remainder drains across the report-day's later
// hourly invocations (a completed report drops out of the next selection). No-op on
// non-report days. Never throws (runCronTask also isolates it).
async function generateScheduledReports(now, env) {
  try {
    return await runBoundedScheduledReports(now, env);
  } catch (e) {
    console.error("[scheduled-reports] invocation error:", String(e?.message ?? e));
    return null;
  }
}

// ── CORS ──────────────────────────────────────────────────────────────────────

// ── RBAC Helpers ─────────────────────────────────────────────────────────────

/**
 * Role hierarchy (higher index = more access).
 * A role satisfies any permission level at or below it.
 */
const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2, owner: 3 };

/**
 * Permission → minimum role required.
 */
const PERMISSION_MIN_ROLE = {
  // Workspace management
  "workspace:read":            "viewer",
  "workspace:manage":          "admin",   // rename, general settings — B1
  "workspace:invite":          "admin",
  "workspace:manage_members":  "owner",
  "workspace:delete":          "owner",
  "workspace:transfer":        "owner",
  "billing:manage":            "owner",
  // Domain management
  "domain:add":                "admin",
  "domain:remove":             "admin",
  "domain:import":             "admin",
  "domain:verify":             "admin",
  // Scans
  "scan:create":               "analyst",
  // Reports
  "report:generate":           "admin",
  "report:delete":             "admin",
  "schedule:manage":            "admin",
  // Notifications
  "notification:mark_read":    "viewer",
  // Members (read)
  "member:read":               "viewer",
  // Audit log
  "audit:read":                "admin",
};

/**
 * API Token scope hierarchy.
 * Higher rank = more powerful. read ⊂ write ⊂ admin.
 */
const SCOPE_RANK = { read: 0, write: 1, admin: 2 };

/**
 * Maps workspace permission strings to the minimum API token scope required.
 * Session-authenticated callers (no token_scope) always bypass this check.
 */
const PERMISSION_SCOPE = {
  // read-scope operations
  "workspace:read":           "read",
  "notification:mark_read":   "read",
  "member:read":              "read",
  "audit:read":               "read",
  // write-scope operations
  "workspace:manage":         "write",
  "scan:create":              "write",
  "schedule:manage":          "write",
  "domain:add":               "write",
  "domain:remove":            "write",
  "domain:import":            "write",
  "domain:verify":            "write",
  "report:generate":          "write",
  "report:delete":            "write",
  // admin-scope operations
  "workspace:invite":         "admin",
  "workspace:manage_members": "admin",
  "workspace:delete":         "admin",
  "workspace:transfer":       "admin",
  "billing:manage":           "admin",
};

function hasWorkspacePermission(role, permission, tokenScope = undefined) {
  const minRole = PERMISSION_MIN_ROLE[permission];
  if (!minRole) return false;

  const userRank = ROLE_RANK[role] ?? -1;
  const minRank = ROLE_RANK[minRole] ?? 99;
  if (userRank < minRank) return false;

  if (tokenScope !== undefined) {
    const requiredScope = PERMISSION_SCOPE[permission];
    if (!requiredScope) return false;
    const tokenRank = SCOPE_RANK[tokenScope] ?? -1;
    const neededRank = SCOPE_RANK[requiredScope] ?? 99;
    if (tokenRank < neededRank) return false;
  }

  return true;
}

/**
 * requireWorkspaceAccess(user, workspaceId, env)
 *
 * Resolves the caller's membership in a workspace.
 * Returns { role } if the user is a member or is the workspace owner, null otherwise.
 *
 * Legacy workspaces (created before RBAC, no member rows) are accessible ONLY
 * to the user whose id matches owner_user_id — never to all authenticated users.
 */
async function requireWorkspaceAccess(user, workspaceId, env) {
  if (!user || !workspaceId) return null;

  // ── P0: API token workspace boundary ─────────────────────────────────────
  // If this request was authenticated with a workspace-bound token, it may
  // only access that specific workspace. A mismatch is a hard rejection —
  // the token was issued for a different workspace.
  if (user.token_workspace_id && user.token_workspace_id !== workspaceId) {
    return null;
  }

  try {
    const member = await env.cybermeters_db
      .prepare(
        `SELECT wm.role FROM workspace_members wm
         JOIN workspaces w ON w.id = wm.workspace_id AND w.deleted_at IS NULL
         WHERE wm.workspace_id = ? AND wm.user_id = ? LIMIT 1`
      )
      .bind(workspaceId, user.id)
      .first();

    if (member) return { role: member.role };

    // Legacy fallback: if no members exist, allow only the workspace owner.
    const ws = await env.cybermeters_db
      .prepare(
        `SELECT w.owner_user_id, COUNT(wm.id) AS member_count
         FROM workspaces w
         LEFT JOIN workspace_members wm ON wm.workspace_id = w.id
         WHERE w.id = ? AND w.deleted_at IS NULL
         GROUP BY w.id, w.owner_user_id`
      )
      .bind(workspaceId)
      .first();

    if ((ws?.member_count ?? 0) === 0 && ws?.owner_user_id && ws.owner_user_id === user.id) {
      return { role: "owner" };
    }

    return null; // not a member and not the owner
  } catch {
    return null;
  }
}

/**
 * requireWorkspaceRole(user, workspaceId, permission, env)
 *
 * Returns the member's role if the user has the minimum role required for
 * the given permission, or null otherwise.
 *
 * Usage:
 *   const access = await requireWorkspaceRole(user, wsId, "report:generate", env);
 *   if (!access) return json({ error: "Forbidden" }, 403);
 */
async function requireWorkspaceRole(user, workspaceId, permission, env) {
  const membership = await requireWorkspaceAccess(user, workspaceId, env);
  if (!membership) return null;
  return hasWorkspacePermission(membership.role, permission, user.token_scope)
    ? membership
    : null;
}

async function getAccessibleWorkspaceIds(user, env) {
  if (!user) return [];

  if (user.token_workspace_id) {
    const access = await requireWorkspaceAccess(user, user.token_workspace_id, env);
    return access ? [user.token_workspace_id] : [];
  }

  try {
    const rows = await env.cybermeters_db
      .prepare(
        `SELECT DISTINCT w.id
         FROM workspaces w
         LEFT JOIN workspace_members wm
           ON wm.workspace_id = w.id AND wm.user_id = ?
         WHERE w.deleted_at IS NULL
           AND (
             wm.user_id IS NOT NULL
             OR (
               w.owner_user_id = ?
               AND NOT EXISTS (
                 SELECT 1 FROM workspace_members any_wm
                 WHERE any_wm.workspace_id = w.id
               )
             )
           )`
      )
      .bind(user.id, user.id)
      .all();
    return (rows.results || []).map((row) => row.id).filter(Boolean);
  } catch {
    return [];
  }
}

async function requireDomainRole(user, domainId, permission, env) {
  if (!user || !domainId) return null;
  try {
    const rows = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    for (const row of (rows.results || [])) {
      const access = await requireWorkspaceRole(user, row.workspace_id, permission, env);
      if (access) return { ...access, workspace_id: row.workspace_id };
    }
    return null;
  } catch {
    return null;
  }
}

async function requireScanReadAccess(user, scanId, env) {
  if (!user || !scanId) return null;
  try {
    const scan = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM scans WHERE id = ? LIMIT 1")
      .bind(scanId)
      .first();

    if (!scan) return null;

    if (scan.workspace_id) {
      const access = await requireWorkspaceRole(user, scan.workspace_id, "workspace:read", env);
      return access ? { ...access, workspace_id: scan.workspace_id } : null;
    }

    // Legacy scans created before workspace_id attribution are authorized by
    // domain link only when the scan has no owning workspace.
    const rows = await env.cybermeters_db
      .prepare(
        `SELECT DISTINCT wd.workspace_id
         FROM scans s
         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
         WHERE s.id = ?`
      )
      .bind(scanId)
      .all();
    for (const row of (rows.results || [])) {
      const access = await requireWorkspaceRole(user, row.workspace_id, "workspace:read", env);
      if (access) return { ...access, workspace_id: row.workspace_id };
    }
    return null;
  } catch {
    return null;
  }
}

// ── Notification Helpers ─────────────────────────────────────────────────────


// ── Audit Trail Helper ───────────────────────────────────────────────────────


/**
 * createNotificationsForDomain — fires workspace-level notifications for a
 * completed scan. Looks up all workspace_ids associated with the domain,
 * then creates one notification per workspace.
 *
 * @param {string} domainId     - Domain row ID
 * @param {string} domain       - Domain name (for display)
 * @param {string} scanId       - Completed scan ID
 * @param {number} score        - Final security score
 * @param {string} risk_level   - Risk rating (critical/high/medium/low/info)
 * @param {Array}  findings     - All findings from the scan
 * @param {object} env          - Worker env bindings
 */



// ── Domain verification auto-retry (cron) ───────────────────────────────────
//
// A manual verify often fails only because the DNS TXT record hasn't
// propagated yet (some registrars — GoDaddy notably — take hours). Rather than
// making the customer poll the Verify button, the hourly cron re-checks the
// DNS TXT method for VERIFICATION_WINDOW_HOURS after verification was initiated
// and completes it automatically. Only DNS TXT is retried: it is the
// propagation-bound method; the HTML-file method is instant and gains nothing
// from retrying. Bounded per run; each check is a single DoH subrequest.
//
// ── Why this was rewritten (PR #96) ──────────────────────────────────────────
// This task was dead code, and its deadness was invisible. It selected on
// `domains.verification_token` / `domains.verification_initiated_at`, but since
// migration 079 NOTHING writes those columns: verification initiation moved to the
// workspace_domains link, and the legacy domains.verification_* columns became
// read-only compatibility data. So the WHERE clause matched nothing, forever, and
// the customer-facing promise ("we re-check automatically every hour for 48
// hours") was false for every domain initiated after 079.
//
// Worse, had it matched a pre-079 row it would have written ONLY the legacy
// `domains` table — never the authoritative workspace_domains link the scan gate
// reads — while notifying every linked workspace "ownership verified". The
// customer would have been told they were verified and still been unable to scan.
//
// This is the same class of defect as the manual route's (PR #95): a claim made
// from state that was never proven. It is fixed the same way — the authoritative
// link is the only source and the only target, and persistVerification() is the
// only writer, so the automatic path is held to exactly the proof the manual path
// is: one changed row, confirmed by re-read.
async function retryPendingDomainVerifications(env) {
  try {
    // Candidates come from the AUTHORITATIVE link, never the legacy domains row.
    //
    // Status covers 'pending' AND 'failed': the manual route writes 'failed' when a
    // check does not find the record, which is precisely the customer this task
    // exists for (clicked Verify before propagation). A pending-only filter would
    // skip exactly the rows it is meant to rescue. Matches the pre-079 intent.
    //
    // Soft-deleted workspaces are excluded — they must not receive new scheduled
    // work or notifications. The domains join supplies the hostname; it is NOT
    // consulted for verification state.
    const candidates = await env.cybermeters_db
      .prepare(
        `SELECT wd.workspace_id, wd.domain_id, wd.verification_token, wd.verification_initiated_at,
                d.domain AS domain
         FROM workspace_domains wd
         JOIN domains d    ON d.id = wd.domain_id
         JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
         WHERE wd.verification_status IN ('pending', 'failed')
           AND wd.verification_token IS NOT NULL
           AND wd.verification_initiated_at IS NOT NULL
           AND wd.verification_initiated_at >= datetime('now', ?)
         ORDER BY wd.verification_initiated_at ASC, wd.workspace_id ASC, wd.domain_id ASC
         LIMIT ?`
      )
      .bind(`-${VERIFICATION_WINDOW_HOURS} hours`, VERIFICATION_RECHECK_BATCH)
      .all();

    for (const row of (candidates?.results || [])) {
      const domain = normalizeHostname(row.domain) || row.domain;
      // One terminal record per candidate, whatever happens to it.
      const record = (outcome, extra = {}) => recordVerificationAttempt(env, {
        request_id:   `cron:domain_verify_retry`,
        workspace_id: row.workspace_id,
        domain_id:    row.domain_id,
        domain,
        user_id:      null,
        method:       "dns_txt",
        ...extra,
        outcome,
      });

      try {
        // The SAME proof the manual route uses — one definition of "proven".
        const proof = await checkDnsTxtProof(domain, row.verification_token);
        if (!proof.verified) {
          // No mutation on failure. The row keeps its current status and stays
          // eligible for the next hourly run until the window closes.
          await record(outcomeForDnsCategory(proof.category), {
            dns_result: proof.category, dns_error: proof.error || null,
            resolver_used: "cloudflare_doh",
          });
          continue;
        }

        // Proven. Persist through the SAME gate as the manual route: exactly one
        // changed row, confirmed by a re-read that echoes back the ids and a
        // non-null verified_at. An unconfirmable write is never a verification.
        const persisted = await persistVerification(env, row.workspace_id, row.domain_id, "dns_txt");
        const dnsRecordHash = await hashToken(`cybermeters-verification=${row.verification_token}`);

        if (!persisted.ok) {
          await record(persisted.outcome, {
            dns_result: "found",
            affected_row_count:    persisted.affected_row_count,
            persisted_status:      persisted.persisted_status,
            persisted_verified_at: persisted.persisted_verified_at,
            dns_record_hash: dnsRecordHash, resolver_used: "cloudflare_doh",
          });
          continue;
        }

        // Notify + audit THIS workspace only — the link we just proved, not every
        // workspace that happens to share the domain. Each workspace must prove
        // control independently, so each gets its own candidate row and its own
        // notification when its own proof lands.
        //
        // Idempotency rests on the status transition, not on a dedup check: the
        // candidate query only selects 'pending'/'failed', and persistVerification
        // has just moved this row to 'verified', so no later run can select it
        // again. A repeat run is a no-op. (A notification lost to a failed insert
        // is not retried — it is best-effort telemetry, not the verification.)
        try {
          await createNotificationEvent(env, row.workspace_id, {
            type: "domain_verified", severity: "info",
            title: `${domain} ownership verified`,
            message: `The DNS TXT record at _cybermeters.${domain} has propagated — verification completed automatically.`,
            metadata: { domain, domain_id: row.domain_id, workspace_id: row.workspace_id,
                        method: "dns_txt", auto_retry: true },
          });
          await createAuditEvent(env, {
            workspace_id: row.workspace_id, user_id: null, actor_type: "system",
            event_type: "domain_verified", entity_type: "domain", entity_id: row.domain_id,
            description: `${domain} ownership verified via DNS TXT (automatic re-check)`,
            metadata: { domain, domain_id: row.domain_id, workspace_id: row.workspace_id,
                        method: "dns_txt", auto_retry: true,
                        resolver_used: "cloudflare_doh", dns_record_hash: dnsRecordHash },
          });
        } catch { /* non-fatal */ }

        await record(VERIFICATION_OUTCOMES.VERIFIED_DNS_TXT, {
          dns_result: "found",
          affected_row_count:    persisted.affected_row_count,
          persisted_status:      persisted.persisted_status,
          persisted_verified_at: persisted.persisted_verified_at,
          dns_record_hash: dnsRecordHash, resolver_used: "cloudflare_doh",
        });
      } catch {
        // One bad candidate must not stop the batch.
        try { await record(VERIFICATION_OUTCOMES.INTERNAL_ERROR); } catch { /* never throw */ }
      }
    }

    // ── The end of the promise, observed once ────────────────────────────────
    // Rows that crossed the window boundary during THIS hour. Scoped to a single
    // interval rather than "everything older than the window" so each row's expiry
    // is recorded exactly once — an unbounded `< now-48h` would re-log every dead
    // row on every run, forever. Telemetry only: no mutation, no notification. The
    // customer was promised a 48-hour recheck and this is where it honestly stops.
    const expired = await env.cybermeters_db
      .prepare(
        `SELECT wd.workspace_id, wd.domain_id, wd.verification_status, d.domain AS domain
         FROM workspace_domains wd
         JOIN domains d    ON d.id = wd.domain_id
         JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
         WHERE wd.verification_status IN ('pending', 'failed')
           AND wd.verification_token IS NOT NULL
           AND wd.verification_initiated_at IS NOT NULL
           AND wd.verification_initiated_at <  datetime('now', ?)
           AND wd.verification_initiated_at >= datetime('now', ?)
         ORDER BY wd.verification_initiated_at ASC, wd.workspace_id ASC, wd.domain_id ASC
         LIMIT ?`
      )
      .bind(`-${VERIFICATION_WINDOW_HOURS} hours`, `-${VERIFICATION_WINDOW_HOURS + 1} hours`, VERIFICATION_RECHECK_BATCH)
      .all();

    for (const row of (expired?.results || [])) {
      await recordVerificationAttempt(env, {
        request_id:   `cron:domain_verify_retry`,
        workspace_id: row.workspace_id,
        domain_id:    row.domain_id,
        domain:       normalizeHostname(row.domain) || row.domain,
        user_id:      null,
        method:       "dns_txt",
        persisted_status: row.verification_status,
        outcome: VERIFICATION_OUTCOMES.RECHECK_WINDOW_EXPIRED,
      });
    }
  } catch { /* cron task must never throw */ }
}

// ── canUseFeature ─────────────────────────────────────────────────────────────
// Public alias for hasFeatureEntitlement. Use this in all new route handlers
// and gate checks. The underlying logic is identical; this name is preferred
// for clarity in non-billing contexts.
//
// Example:
//   const plan = await getEffectivePlan(user.id, env);
//   if (!canUseFeature(plan, "scheduled_scans")) return json(featureGated("scheduled_scans"), 403);
//
// Supported gate keys (Sprint 14+):
//   scheduled_scans, alerts, pdf_reports, multi_workspace, team_members
//
// Legacy gate keys (pre-Sprint 14):
//   business_risk_score, cyber_essentials, vendor_risk, executive_dashboard,
//   audit_logs, portfolio_monitoring, white_label, msp_dashboard
function canUseFeature(plan, featureKey) {
  return hasFeatureEntitlement(plan, featureKey);
}

function getRateLimitWindow(windowSeconds = 3600) {
  const now = Date.now();
  const startMs = Math.floor(now / (windowSeconds * 1000)) * windowSeconds * 1000;
  return {
    window_start: new Date(startMs).toISOString(),
    reset_at: new Date(startMs + windowSeconds * 1000).toISOString(),
  };
}

function rateLimitId(scope, scopeId, action, windowStart) {
  const raw = `${scope}:${scopeId}:${action}:${windowStart}`;
  return `rl_${raw.replace(/[^a-zA-Z0-9_-]+/g, "_")}`;
}

function rateLimitExceeded(action, limit, windowSeconds, resetAt) {
  return {
    error: "Rate limit exceeded",
    code: "rate_limit_exceeded",
    action,
    limit,
    window_seconds: windowSeconds,
    reset_at: resetAt,
    upgrade_message: "Upgrade your plan for higher scan limits.",
  };
}

async function rateLimitScopeId(prefix, value) {
  const raw = String(value || "unknown");
  try {
    return `${prefix}_${(await hashToken(raw)).slice(0, 16)}`;
  } catch {
    return `${prefix}_${raw.replace(/[^a-z0-9]/gi, "_").slice(0, 32)}`;
  }
}

async function consumeApiRateLimit(env, scopes, action, limit, windowSeconds = 3600, options = {}) {
  // D1-backed rate limiting is adequate for early launch and intentionally
  // fails open if the table or query is unavailable. The read/update sequence
  // is not fully atomic under high concurrency; a future hardening pass can
  // move this to Durable Objects or a dedicated queue if scan start volume grows.
  if (!Number.isFinite(limit) || limit >= 999999) return null;
  const activeScopes = scopes.filter((s) => s.scope && s.scope_id);
  if (activeScopes.length === 0) return null;

  const { window_start, reset_at } = getRateLimitWindow(windowSeconds);

  try {
    for (const scope of activeScopes) {
      const row = await env.cybermeters_db
        .prepare(
          `SELECT request_count
           FROM api_rate_limits
           WHERE scope = ? AND scope_id = ? AND action = ? AND window_start = ?
           LIMIT 1`
        )
        .bind(scope.scope, scope.scope_id, action, window_start)
        .first();
      if ((row?.request_count ?? 0) >= limit) {
        return { status: 429, body: rateLimitExceeded(action, limit, windowSeconds, reset_at) };
      }
    }

    for (const scope of activeScopes) {
      const id = rateLimitId(scope.scope, scope.scope_id, action, window_start);
      await env.cybermeters_db
        .prepare(
          `INSERT INTO api_rate_limits
             (id, scope, scope_id, action, window_start, window_seconds, request_count, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
           ON CONFLICT(id) DO NOTHING`
        )
        .bind(id, scope.scope, scope.scope_id, action, window_start, windowSeconds)
        .run();
      await env.cybermeters_db
        .prepare(
          `UPDATE api_rate_limits
           SET request_count = request_count + 1,
               updated_at = datetime('now')
           WHERE id = ?`
        )
        .bind(id)
        .run();
    }
    return null;
  } catch (e) {
    console.error(`[rate-limit] ${action} check failed: ${e?.message ?? e}`);
    if (options.failClosed) {
      return { status: 503, body: { error: "Rate limiting is temporarily unavailable. Please try again shortly.", code: "rate_limit_unavailable" } };
    }
    return null; // fail-open for authenticated customer flows to avoid lockout
  }
}

async function isPlatformAdmin(user, env) {
  const allowlist = String(env.ADMIN_EMAILS || "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
  return !!user?.email && allowlist.includes(user.email.toLowerCase());
}

// ── Worker Handler ────────────────────────────────────────────────────────────

// ── Maintenance mode helpers ──────────────────────────────────────────────────
// Toggle via the MAINTENANCE_MODE var (on/1/true). Fail-safe: anything else —
// including unset — reads as OFF, so the API can never be taken down by a typo.
function isMaintenanceMode(env) {
  const v = String(env?.MAINTENANCE_MODE ?? "").trim().toLowerCase();
  return v === "on" || v === "1" || v === "true";
}
// Bypass lets the founder verify a deploy while the flag is still on. Only active
// when MAINTENANCE_BYPASS_TOKEN is set; the request must send it in the header.
function isMaintenanceBypass(request, env) {
  const token = env?.MAINTENANCE_BYPASS_TOKEN;
  if (!token) return false;
  return request.headers.get("X-Maintenance-Bypass") === token;
}

export default {
  async fetch(request, env, ctx) {
    // Build CORS headers once per request, honouring the ALLOWED_ORIGIN binding.
    const corsHeaders = buildCorsHeaders(env);
    const requestId = crypto.randomUUID();
    // Shadow the module-level json() so every route in this handler uses the
    // correct per-request origin without touching individual call sites.
    const json = (data, status = 200) => Response.json(normalizeApiResponseData(data, status), {
      status,
      headers: { ...buildJsonHeaders(corsHeaders), "X-Request-ID": requestId },
    });
    const serverError = (scope, error, message = "Request failed. Please try again.") => {
      console.error("[request-error]", redactedJson({
        request_id: requestId,
        version: env.APP_VERSION || "dev",
        scope,
        error: String(error?.message ?? error),
      }));
      recordMetric(env, "http_5xx", { blobs: [scope || "unknown"], indexes: [scope || "unknown"] });
      return json({ error: message, request_id: requestId }, 500);
    };

    const url = new URL(request.url);

    if (url.pathname.length > 2048) {
      return json({ error: "Request URL is too long" }, 414);
    }
    const contentLength = Number(request.headers.get("Content-Length") || 0);
    if (Number.isFinite(contentLength) && contentLength > 1024 * 1024) {
      return json({ error: "Request body is too large" }, 413);
    }

    // ── OPTIONS preflight ───────────────────────────────────────────────
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { ...corsHeaders, "X-Request-ID": requestId } });
    }

    // ── GET /health ─────────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        status:        "ok",
        service:       "cybermeters-scan-api",
        version:       env.APP_VERSION || "dev",
        deployment_id: env.CF_VERSION_METADATA?.id || null,
        // Exposed so the frontend maintenance overlay can auto-dismiss when the
        // window lifts (both /health and /ready stay reachable during maintenance).
        maintenance:   isMaintenanceMode(env),
      });
    }

    // ── GET /readiness ──────────────────────────────────────────────────
    // Deeper than /health: verifies the D1 and R2 bindings are reachable, so
    // a load balancer / uptime monitor can distinguish "process up" from
    // "dependencies healthy". Each check is fail-open; 200 = ready, 503 = degraded.
    if (request.method === "GET" && url.pathname === "/ready") {
      const checks = { d1: false, r2: false };
      try { await env.cybermeters_db.prepare("SELECT 1").first(); checks.d1 = true; } catch { /* d1 unreachable */ }
      try { await env.cybermeters_reports.head("__readiness_probe__"); checks.r2 = true; } catch { /* r2 unreachable */ }
      const ready = checks.d1 && checks.r2;
      return json({ status: ready ? "ready" : "degraded", checks, version: env.APP_VERSION || "dev" }, ready ? 200 : 503);
    }

    // ── Maintenance mode ────────────────────────────────────────────────
    // When MAINTENANCE_MODE is on, every API route returns a clean 503 so
    // customers see a friendly "back shortly" message instead of half-broken
    // behaviour during a planned window. /health and /ready above are exempt so
    // monitoring keeps working, and a bypass token lets the founder smoke-test
    // the deploy before lifting the flag. Fail-safe: an unset/garbled var reads
    // as OFF, so this can never accidentally take the API down.
    if (isMaintenanceMode(env) && !isMaintenanceBypass(request, env)) {
      return Response.json(
        normalizeApiResponseData({
          error: "maintenance",
          message: "CyberMeters is undergoing scheduled maintenance and will be back shortly. Please try again in a few minutes.",
        }, 503),
        { status: 503, headers: { ...buildJsonHeaders(corsHeaders), "X-Request-ID": requestId, "Retry-After": "300" } },
      );
    }

    // ── Global rate limiting guard ──────────────────────────────────────
    // Coarse per-IP budgets applied to every route below (reads 300/5min,
    // writes 60/5min) so no endpoint is entirely unthrottled. Endpoint-
    // specific limits (signup, login, free-scan, invites, scans) still apply
    // on top and are stricter. Fail-open and wrapped so the guard can never
    // take the API down; OPTIONS and /health above are exempt.
    try {
      const globalClientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const isReadRequest = request.method === "GET" || request.method === "HEAD";
      const globalAction = isReadRequest ? "global_read" : "global_write";
      const globalLimit = isReadRequest ? 300 : 60;
      const globalRl = await consumeApiRateLimit(env,
        [{ scope: "ip", scope_id: await rateLimitScopeId(globalAction, globalClientIp) }],
        globalAction, globalLimit, 300);
      if (globalRl) return json(globalRl.body, globalRl.status);
    } catch {
      // Rate limiting must never break request handling.
    }

    // Shared context for extracted route modules (src/routes/*). The static
    // auth helpers ride along so route modules never import from index.js
    // (which would create a circular module graph).
    const routeCtx = { request, env, ctx, url, json, serverError,
                       requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId,
                       corsHeaders, isActionableFinding, consumeApiRateLimit, ROLE_RANK, requireDomainRole, DELETION_PURGE_WINDOW_DAYS, rateLimitScopeId,
                       requireScanReadAccess, getAccessibleWorkspaceIds, computeNextRunAt,
                       requestId, requireWorkspaceAccess, isPlatformAdmin, evaluateRegressionFixtures, validateFrontendRedirectUrl };

    // ── Global billing routes (plans/ingest/subscription/webhook/checkout) ──
    // Extracted to src/routes/global-billing.js; dispatched at the original
    // position of the plans route, patterns unchanged and mutually disjoint.
    {
      const globalBillingResponse = await globalBillingRoutes(routeCtx);
      if (globalBillingResponse) return globalBillingResponse;
    }

    // ── Auth routes (signup/login/session/verify/SSO/password/MFA) ──────────
    // Extracted to src/routes/auth.js; dispatched at the original position,
    // patterns unchanged and mutually disjoint.
    {
      const authResponse = await authRoutes(routeCtx);
      if (authResponse) return authResponse;
    }

    // ── Account routes (profile/tokens/sessions/export + platform QA) ───────
    // Extracted to src/routes/account.js; dispatched at the original position,
    // patterns unchanged and mutually disjoint.
    {
      const accountResponse = await accountRoutes(routeCtx);
      if (accountResponse) return accountResponse;
    }

    // ── Scan routes (start/list/report/PDF/history + scheduled scans) ───────
    // Extracted to src/routes/scans.js; dispatched at the original position,
    // patterns unchanged and mutually disjoint.
    {
      const scansResponse = await scanRoutes(routeCtx);
      if (scansResponse) return scansResponse;
    }

    // ── Portfolio + workspace list routes ───────────────────────────────────
    // Extracted to src/routes/portfolio.js; dispatched at the original
    // position, patterns unchanged and mutually disjoint.
    {
      const portfolioResponse = await portfolioRoutes(routeCtx);
      if (portfolioResponse) return portfolioResponse;
    }

    // ── Attack surface routes (assets/alerts/posture/vendors) ───────────────
    // Extracted to src/routes/attack-surface.js; dispatched at the original
    // position, patterns unchanged and mutually disjoint.
    {
      const attackSurfaceResponse = await attackSurfaceRoutes(routeCtx);
      if (attackSurfaceResponse) return attackSurfaceResponse;
    }

    // ── Universal managed-cases routes (cross-domain queue + generic transition) ──
    // Pattern /api/workspaces/:id/cases is disjoint from the ASM
    // /api/workspaces/:id/managed-cases and every other route.
    {
      const casesResponse = await managedCasesRoutes(routeCtx);
      if (casesResponse) return casesResponse;
    }

    // ── M6 B1 Related Changes routes (deterministic correlation clusters) ────
    // Pattern /api/workspaces/:id/related-changes is disjoint from /cases and every
    // other route.
    {
      const relatedChangesResponse = await relatedChangesRoutes(routeCtx);
      if (relatedChangesResponse) return relatedChangesResponse;
    }

    // ── Shadow IT approved-inventory routes ─────────────────────────────────
    {
      const shadowItResponse = await shadowItRoutes(routeCtx);
      if (shadowItResponse) return shadowItResponse;
    }

    // ── Certificates Managed Lifecycle routes ───────────────────────────────
    {
      const certLifecycleResponse = await certificatesLifecycleRoutes(routeCtx);
      if (certLifecycleResponse) return certLifecycleResponse;
    }

    // ── Identity Exposure Managed Workflow routes ───────────────────────────
    {
      const identityExposureResponse = await identityExposureRoutes(routeCtx);
      if (identityExposureResponse) return identityExposureResponse;
    }

    // ── Website Security lifecycle read routes (mig 089) ────────────────────
    {
      const websiteSecurityResponse = await websiteSecurityRoutes(routeCtx);
      if (websiteSecurityResponse) return websiteSecurityResponse;
    }

    // ── Cyber Essentials external-evidence control routes (mig 090) ─────────
    // Mounted BEFORE workspace-analytics: that module owns
    // /cyber-essentials/answers and /cyber-essentials-readiness, and this one owns
    // /cyber-essentials/controls. The paths do not overlap, but the ordering makes the
    // ownership explicit rather than incidental.
    {
      const ceControlsResponse = await cyberEssentialsControlsRoutes(routeCtx);
      if (ceControlsResponse) return ceControlsResponse;
    }

    // ── Email Protection lifecycle history routes (mig 088) ─────────────────
    {
      const emailLifecycleResponse = await emailProtectionLifecycleRoutes(routeCtx);
      if (emailLifecycleResponse) return emailLifecycleResponse;
    }

    // ── Report branding routes (per-workspace logo + MSP profiles) ──────────
    {
      const brandingResponse = await workspaceBrandingRoutes(routeCtx);
      if (brandingResponse) return brandingResponse;
    }

    // ── Workspace analytics routes (scorecard, CE readiness, business risk) ──
    // Extracted to src/routes/workspace-analytics.js. All five patterns are
    // mutually disjoint from each other and from every route between the two
    // original positions, so dispatching business-risk earlier than its old
    // position cannot shadow or be shadowed by another route.
    {
      const analyticsResponse = await workspaceAnalyticsRoutes(routeCtx);
      if (analyticsResponse) return analyticsResponse;
    }

    // ── Workspace intelligence routes (identity, vendor-rel, supply-chain) ──
    // Extracted to src/routes/workspace-intel.js; dispatched at the original
    // position, patterns unchanged and mutually disjoint.
    {
      const intelResponse = await workspaceIntelRoutes(routeCtx);
      if (intelResponse) return intelResponse;
    }

    // ── Brand routes (intelligence v1 + legacy monitoring) ──────────────────
    // Extracted to src/routes/brand.js; dispatched at the original position,
    // patterns unchanged and mutually disjoint.
    {
      const brandResponse = await brandRoutes(routeCtx);
      if (brandResponse) return brandResponse;
    }

    // ── Workspace insight routes (validation/usage/summary/health) ──────────
    // Extracted to src/routes/workspace-insights.js; dispatched at the
    // original position, patterns unchanged and mutually disjoint.
    {
      const insightsResponse = await workspaceInsightRoutes(routeCtx);
      if (insightsResponse) return insightsResponse;
    }

    // ── Workspace membership routes (invitations + members) ─────────────────
    // Extracted to src/routes/workspace-members.js; dispatched at the original
    // position, patterns unchanged and mutually disjoint.
    {
      const membersResponse = await workspaceMembersRoutes(routeCtx);
      if (membersResponse) return membersResponse;
    }

    // ── Executive dashboard routes (KPI + activity feed) ─────────────────────
    // Extracted to src/routes/executive-dashboard.js; dispatched at the
    // original position, patterns unchanged and mutually disjoint.
    {
      const execDashResponse = await executiveDashboardRoutes(routeCtx);
      if (execDashResponse) return execDashResponse;
    }

    // ── Workspace activity routes (audit events + notifications) ────────────
    // Extracted to src/routes/workspace-activity.js; dispatched at the original
    // position, patterns unchanged and mutually disjoint.
    {
      const activityResponse = await workspaceActivityRoutes(routeCtx);
      if (activityResponse) return activityResponse;
    }

    // ── Domain routes (import + verification lifecycle + detail) ────────────
    // Extracted to src/routes/domains.js; dispatched at the original position
    // of the import route so /domains/import keeps matching before the
    // workspaces-core :domainId pattern below.
    {
      const domainsResponse = await domainRoutes(routeCtx);
      if (domainsResponse) return domainsResponse;
    }

    // ── Email Protection routes (DMARC/RUA/senders/BEC/hosted DNS/alerts) ───
    // Extracted to src/routes/email-protection.js; dispatched at the original
    // position, patterns unchanged and mutually disjoint.
    {
      const emailProtResponse = await emailProtectionRoutes(routeCtx);
      if (emailProtResponse) return emailProtResponse;
    }

    // ── Workspaces core routes (detail/domains-link/delete-request/restore) ──
    // Extracted to src/routes/workspaces-core.js; dispatched at the original
    // position — MUST stay after the domains dispatcher so /domains/import
    // keeps precedence over the :domainId pattern in this block.
    {
      const wsCoreResponse = await workspacesCoreRoutes(routeCtx);
      if (wsCoreResponse) return wsCoreResponse;
    }

    // ── Workspace report routes (generate/list/download + scheduled reports) ──
    // Extracted to src/routes/workspace-reports.js; dispatched at the original
    // position, patterns unchanged (generate/:reportId ordering preserved inside
    // the module).
    {
      const reportsResponse = await workspaceReportsRoutes(routeCtx);
      if (reportsResponse) return reportsResponse;
    }

    // ── Billing + free-scan routes (public scan, subscription, checkout) ────
    // Extracted to src/routes/billing.js; dispatched at the original position
    // (last route group before the 404 fallback), patterns unchanged.
    {
      const billingResponse = await billingRoutes(routeCtx);
      if (billingResponse) return billingResponse;
    }

    return json({ error: "Not found" }, 404);
  },

  // ── Hourly cron ───────────────────────────────────────────────────────────
  // Orchestration extracted to src/cron/scheduled.js (Sprint 9 phase 1); task
  // bodies stay here and are injected so the module needs no cycle.
  scheduled: (event, env, ctx) => runScheduled(event, env, ctx, {
    cleanupExpiredReports,
    generateScheduledReports,
    opsHealthHeartbeat,
    sendWeeklyDigests,
    processDeletionRequests,
    processScheduledReports,
    retryFailedAssetAlerts,
    retryFailedLifecycleEmails,
    retryPendingDomainVerifications,
    runHostedDnsVerificationSweep,
   retryFailedAlertDeliveries,
    runBrandTakedownFollowupSweep,
    runBrandDnsEnrichmentSweep,
    runBrandPassiveDiscoverySweep,
    runBrandHttpEnrichmentSweep,
    triggerScheduledScan,
    recoverInterruptedScans,
  }),

  // ── Durable scan-dispatch Queue consumer (PR-3A) ──────────────────────────
  // Receives manual-scan dispatch messages (producer: dispatchAdmittedScan,
  // inert until SCAN_DISPATCH_MODE="queue"). The engine is AWAITED inside the
  // queue invocation — full invocation lifetime, never the post-response ~30s
  // waitUntil path this replaces. Claim CAS + terminal no-op semantics live in
  // engines/scan-dispatch.js.
  queue: (batch, env, ctx) => handleScanDispatchBatch(batch, env, ctx),

  // ── Inbound DMARC aggregate (RUA) email handler ──────────────────────────
  // Extracted to src/email/inbound.js (Sprint 9 phase 1). Cloudflare Email Routing
  // invokes this for every message. The rate limiter is injected here (it lives in
  // this module and cannot be imported without a cycle) so the inbound path can bound
  // per-endpoint forged-report floods (Q7); absent deps, the handler is unchanged.
  email: (message, env, ctx) => handleInboundEmail(message, env, ctx, { consumeApiRateLimit, rateLimitScopeId }),
};

// ── Test-only named exports ──────────────────────────────────────────────────
// Consumed exclusively by scripts/validate-*.js (ESM test harnesses). The
// Workers runtime reads only the default export — named exports are inert in
// production. If a symbol moves to another module, re-export it from here so
// the harness import surface stays stable.
export {
  DMARC_RAMP_LADDER,
  REMEDIATION_REGISTRY,
  SCAN_CHILD_TABLES,
  WORKSPACE_PURGE_TABLES,
  // Exported for validate-domain-verification-recheck.js: the cron task bodies are
  // injected into runScheduled rather than exported, so the only other way to reach
  // this one is to drive the whole hourly tick and every unrelated task with it.
  retryPendingDomainVerifications,
  purgeWorkspaceData,
  isMaintenanceMode,
  isMaintenanceBypass,
  _cloudflareRouteFailure,
  alertChannelToApi,
  analyzeSpfChain,
  annotateExposureInfrastructure,
  applyChangeTransition,
  applyEvidenceQuality,
  applyHostedDmarcChange,
  assetFingerprintSignals,
  auditDmarcRouteResult,
  brandCandidateToApi,
  brandClassificationAuditMetadata,
  buildAlertChannelPayload,
  buildAssetAlertEmail,
  buildBrandProfileDomainScope,
  buildBrandProtectionSummary,
  buildCertificateOwnershipAssessment,
  buildDkimDetail,
  buildDmarcBusinessRisk,
  buildDmarcDnsRecommendedValue,
  buildDmarcEnforcementReadiness,
  buildDmarcPolicyJourney,
  buildDmarcPolicyValue,
  buildDmarcReportRemediationActions,
  buildEmailRemediationActions,
  buildEmailTransportDetails,
  buildChangeReviewQueue,
  buildEnforcementReadinessChecks,
  buildExecutiveReportV2,
  composeSnapshot,
  resolveCanonicalScanScore,
  readScanReportSnapshot,
  cfCreateHostedTxt,
  classifyHostedCfError,
  classifyProviderInfrastructure,
  canTransitionChange,
  changeRequestToApi,
  CHANGE_STATES,
  computeBecExposureScore,
  computeBusinessRiskScore,
  computeConcentration,
  computeScore,
  configureDmarcEndpointRoute,
  consolidateInventoryAssetAliases,
  cybermetersRuaPresentInDmarcRecord,
  decryptTotpSecret,
  deduplicateExposureAssets,
  deliverWorkspaceAlert,
  dmarcRampStepIndex,
  dmarcSenderRiskLevel,
  dmarcTagDiff,
  encryptTotpSecret,
  ensureCloudflareEmailRoute,
  evaluateRampReadiness,
  filterBrandCandidatesToProfile,
  filterWildcardBruteforceResults,
  formatAlertEmail,
  generateInboundLocalpart,
  generateIngestToken,
  generateRecoveryCodes,
  generateSessionToken,
  generateTotpSecret,
  getAccessibleWorkspaceIds,
  getEmailVerificationTokenStatus,
  getPaymentGraceState,
  getRemediation,
  hasWorkspacePermission,
  hashIngestToken,
  hashPassword,
  hashToken,
  hostedDmarcSubdomain,
  hostedDnsRecordToApi,
  inferBrandProfileFromDomains,
  ingestEndpointToApi,
  isDeletionPurgeDue,
  isEmailVerificationResendCoolingDown,
  isTerminalChangeState,
  isValidDomain,
  legacyBrandAssetToApi,
  newChangeRequestId,
  newHostedDnsRecordId,
  nextHostedDnsStatus,
  normalizeCertificateSanNames,
  normalizeDiscoveredHostname,
  parseBimiRecord,
  parseBrandCandidateListParams,
  parseDmarcRecord,
  parseSpfRecord,
  pdfUtcDate,
  persistDmarcRouteResult,
  planAllowsHostedPolicyManagement,
  providerForInfrastructureHostname,
  providerMetadataForHostname,
  reconcileHostedIntent,
  remediationToApi,
  requireWorkspaceAccess,
  requireWorkspaceRole,
  resolveRampThresholds,
  retryFailedAssetAlerts,
  revokeCloudflareEmailRoute,
  riskLevelForScore,
  rollbackHostedDmarc,
  runAdminSurfaceModule,
  runCertificateIntelligenceModule,
  runHostedDnsVerificationSweep,
  runSaasExposureModule,
  sanitizeInfraErrorMessage,
  scoreBrandCandidateRisk,
  sendAssetChangeAlert,
  shouldAutoRollback,
  signAlertWebhookBody,
  summarizeEmailSenders,
  validateAlertChannelInput,
  validateBrandProfileInput,
  validateFindingEvidence,
  validateFrontendRedirectUrl,
  validateMicrosoftIdTokenClaims,
  verifyDmarcDnsSetup,
  verifyHostedDmarcRecord,
  verifyPassword,
  verifyRecoveryCode,
  verifyStripeWebhookSignature,
  verifyTotp,
};

// Re-exported for the test harnesses: these moved to the email module.
export {
  deriveInboundReportProvenance,
  extractDmarcXmlFromAttachment,
  extractEmailDomainFromHeader,
  extractInboundLocalpart,
  extractSingleFromDomain,
  gunzipXmlBytes,
  isKnownDmarcReporter,
  normalizeInboundDropReason,
  parseInboundRecipient,
  parseMimeParts,
  selectDmarcAttachment,
  unzipSingleEntryXmlBytes,
} from "./email/inbound.js";

// Re-exported for the test harnesses: these moved to lib modules (Stage A).
export { isValidEmail, normalizeApiResponseData, pageMeta, paginationParams, parseBoundedInteger } from "./lib/util.js";
export { createAuditEvent, createNotificationEvent } from "./lib/events.js";
export { RUA_INBOUND_DOMAIN_DEFAULT, dmarcReportDomainMatches, dmarcReportIdentity, guessEmailSenderProvider, ingestDmarcReport, ingestEndpointIsActive, normalizeInboundRecipientDomain, parseDmarcAggregateXml, parseEmailAuthHeaders, updateEmailSenderSources } from "./lib/dmarc-ingest.js";
export { buildLifecycleEmail, deliverEmail, getEmailFrontendOrigin, lifecycleDedupeKey, normalizeEmailRecipients, resolveEmailSender, retryFailedLifecycleEmails, sendLifecycleEmail } from "./lib/lifecycle-email.js";
