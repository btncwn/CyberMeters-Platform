import { handleInboundEmail } from "./email/inbound.js";
import { runScheduled } from "./cron/scheduled.js";
import { recordMetric } from "./lib/metrics.js";
import { CE_QUESTIONS, CE_QUESTION_SET_VERSION, mergeReadiness } from "./lib/cyber-essentials.js";
import { createId, isValidDomain, isValidEmail, normalizeApiResponseData, pageMeta, paginationParams, parseBoundedInteger } from "./lib/util.js";
import { createAuditEvent, createNotificationEvent, createNotificationsForDomain, sanitizeAuditMetadata } from "./lib/events.js";
import { RUA_INBOUND_DOMAIN_DEFAULT, ingestDmarcReport, ingestEndpointIsActive, normalizeInboundRecipientDomain, parseEmailAuthHeaders, sha256Hex, updateEmailSenderSources } from "./lib/dmarc-ingest.js";
import { buildCorsHeaders, buildJsonHeaders, deliverEmail, escapeEmailHtml, getEmailFrontendOrigin, json, retryFailedLifecycleEmails, sendCustomerEmail, sendLifecycleEmail } from "./lib/lifecycle-email.js";
import { RDAP_UA, safeFetch } from "./lib/http.js";
import { generateTotpSecret, verifyTotp } from "./lib/totp.js";
import { hashPassword, verifyPassword } from "./lib/password.js";
import { validateMicrosoftIdToken, validateMicrosoftIdTokenClaims } from "./lib/microsoft-jwt.js";
import { generateSessionToken, generateApiToken, generateInviteToken, generateEmailVerificationToken, getEmailVerificationTokenStatus, isEmailVerificationResendCoolingDown, generatePasswordResetToken, generateMfaChallengeToken, encryptTotpSecret, decryptTotpSecret, generateRecoveryCodes, verifyRecoveryCode, hashToken } from "./lib/auth-crypto.js";
import { dnsQuery, dnsQueryDnssec, dnsQueryGoogle, dnsQueryQuad9, dnsAnswerValues, computeResolverAgreementScore, buildDnsCrossCheck } from "./engines/dns.js";
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
import { computeScore, isEmailApplicable, riskLevelForScore } from "./engines/scoring.js";
import { fetchMtaSts, runEmailIntelModule } from "./engines/email-intel.js";
import { INTELLIGENCE_ENGINE_REGISTRY, buildExecutiveReportV2, resolveCanonicalScanScore, resolveIntelligenceEngine } from "./engines/executive-report.js";
import { computeWorkspaceVendorRisk, confidenceToScore, normalizeVendorKey, normalizeVendorRiskCategory, recomputeVendorRiskScoresForDomain, signalWeightForVendor } from "./engines/vendor-risk.js";
import { computeConcentration, computeSupplyChainIntelligence, upsertSupplyChainScore } from "./engines/supply-chain.js";
import { clamp, computeSecurityPosture } from "./engines/posture-scoring.js";
import { buildScorecardData } from "./engines/scorecard.js";
import { buildCyberEssentialsReadiness } from "./engines/ce-readiness.js";
import { computeBusinessRiskScore, deriveScanBusinessRisk, expandFindingIds, latestScanBusinessRisk } from "./engines/business-risk.js";
import { computeBecExposureScore } from "./engines/bec.js";
import { upsertAssetInventory } from "./engines/asset-inventory.js";
import { computePortfolioRisk } from "./engines/portfolio-risk.js";
import { _cloudflareEmailRoutingRequest, _cloudflareRouteFailure, auditDmarcRouteResult, buildDmarcEnforcementReadiness, classifyHostedCfError, configureDmarcEndpointRoute, dmarcSenderRiskLevel, emailSenderToApi, ensureCloudflareEmailRoute, extractIngestToken, generateInboundLocalpart, generateIngestToken, hashIngestToken, ingestEndpointToApi, loadEmailSenderSources, persistDmarcRouteResult, resolveWorkspaceDomain, revokeCloudflareEmailRoute, safelyEnsureCloudflareEmailRoute, safelyRevokeCloudflareEmailRoute, summarizeEmailSenders } from "./engines/rua-routing.js";
import { DMARC_RAMP_LADDER, HOSTED_DNS_REMOVAL_GRACE_DAYS, REMEDIATION_REGISTRY, analyzeSpfChain, applyHostedDmarcChange, buildDmarcDnsRecommendedValue, buildDmarcPolicyValue, cfCreateHostedTxt, dmarcRampStepIndex, evaluateRampReadiness, getHostedDmarcPassRate, getRemediation, hostedDmarcSubdomain, hostedDnsRecordToApi, newHostedDnsRecordId, nextHostedDnsStatus, parseServerMsHosted, planAllowsHostedPolicyManagement, reconcileHostedIntent, remediationToApi, rollbackHostedDmarc, runHostedDnsVerificationSweep, shouldAutoRollback, verifyDmarcDnsSetup, verifyHostedDmarcRecord } from "./engines/hosted-dmarc.js";
import { buildDmarcBusinessRisk, buildDmarcReportRemediationActions, buildDmarcSenderIntelligenceEvidence, cybermetersRuaPresentInDmarcRecord, loadBecExposureEvidence } from "./engines/sender-provenance.js";
import { retryFailedAssetAlerts, sendAssetChangeAlert } from "./engines/asset-alert-delivery.js";
import { calculateNextRun, checkReportLimit, checkScanLimit, checkScheduledScanLimit, computeScheduledReportNextRunAt, countEnabledScheduledScans, countReportsThisMonth, countScansThisMonth, generateWorkspaceExecutiveReport, getAccountUsage, getEntitlementUsage, getMonthResetAt, getMonthStart, getOwnedWorkspaceIds, getPlanContext, getPlanLimits, getPlanRetentionDays, getReportExpiresAt, getReportRetentionPolicyForWorkspace, getRetentionCutoff, getRetentionCutoffForDays, getUpgradeRecommendation, getWorkspaceBillingUserId, getWorkspaceOwnerId, getWorkspaceReportStorageMetrics, getWorkspaceRetentionSettings, normalizeReportScheduleFrequency, normalizeReportScheduleRecipients, planLimitExceeded, retentionDaysToPolicy, retentionPolicyToDays } from "./engines/plan-usage.js";
import { workspaceAnalyticsRoutes } from "./routes/workspace-analytics.js";
import { workspaceIntelRoutes } from "./routes/workspace-intel.js";
import { brandRoutes } from "./routes/brand.js";
import { workspaceReportsRoutes } from "./routes/workspace-reports.js";
import { workspaceActivityRoutes } from "./routes/workspace-activity.js";
import { workspaceMembersRoutes } from "./routes/workspace-members.js";
import { executiveDashboardRoutes } from "./routes/executive-dashboard.js";
import { buildCertificateAuthorityConcentrationFromModule, buildScanQuality, computeScanBudget, insertAdminSurfaceEvents, runScanEngine, upsertVendorInventory, upsertVendorRelationships } from "./engines/scan-engine.js";
import { assemblePdf, buildExecutivePdf, buildPdfStreams, buildScanReportPdf, collectPdfData, pdfUtcDate } from "./engines/pdf.js";
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
/**
 * sendScoreDropAlert — fires when the Cyber Metrics Score drops ≥ 10 points
 * compared to the previous scan for the same domain.
 * Sender: ALERT_EMAIL_FROM (alerts@cybermeters.com)
 */
async function sendScoreDropAlert(domain, scanId, scoreDrop, prevScore, currScore, env) {
  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;
  const subject   = `⚠ CyberMeters: ${domain} score dropped ${Math.abs(scoreDrop)} points`;

  const text =
    `Security score drop detected for ${domain}\n\n` +
    `Previous score : ${prevScore}\n` +
    `Current score  : ${currScore}\n` +
    `Change         : ${scoreDrop} points\n\n` +
    `A score drop of this magnitude typically indicates new critical or high-severity\n` +
    `findings on your attack surface. Review the full report immediately.\n\n` +
    `View report: ${reportUrl}`;

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid #EF4444;padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:#EF4444;font-size:18px;">Score Drop Detected</h2>
    <p style="margin:0;color:#555;font-size:14px;">Scheduled scan for <strong>${domain}</strong></p>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
    <tr>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:6px 6px 0 0;color:#555;width:50%;">Previous score</td>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:6px 6px 0 0;font-weight:700;">${prevScore}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#FEF2F2;color:#555;">Current score</td>
      <td style="padding:8px 12px;background:#FEF2F2;font-weight:700;color:#EF4444;">${currScore}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:0 0 6px 6px;color:#555;">Change</td>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:0 0 6px 6px;font-weight:700;color:#EF4444;">${scoreDrop} points</td>
    </tr>
  </table>
  <p style="font-size:14px;color:#555;line-height:1.6;">
    A drop of this magnitude typically indicates new critical or high-severity findings
    on your attack surface. Review the full report immediately.
  </p>
  <p style="margin-top:24px;">
    <a href="${reportUrl}" style="background:#EF4444;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">CyberMeters — Attack Surface Management</p>
</body>
</html>`;

  await sendAlertEmail(subject, text, html, env, "ALERT_EMAIL_FROM");
}

/**
 * sendTakeoverAlert — fires when new subdomain takeover risks are detected
 * that were not present in the previous scan.
 * Sender: SAFE_EMAIL_FROM (safe@cybermeters.com)
 */
async function sendTakeoverAlert(domain, scanId, risks, env) {
  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;
  const count     = risks.length;
  const subject   = `🚨 CyberMeters: ${count} new takeover risk${count !== 1 ? "s" : ""} on ${domain}`;

  const riskLines = risks.map(r => `• ${r.host} (${r.provider || "unknown provider"})`).join("\n");
  const text =
    `Subdomain takeover risk detected for ${domain}\n\n` +
    `${count} new takeover risk${count !== 1 ? "s" : ""} found:\n` +
    riskLines + "\n\n" +
    `These subdomains have dangling CNAME records pointing to unclaimed cloud\n` +
    `resources. An attacker could claim the target and serve malicious content\n` +
    `on your domain.\n\n` +
    `View report: ${reportUrl}`;

  const riskRows = risks
    .map(r => `<tr>
      <td style="padding:8px 12px;font-family:monospace;font-size:13px;">${r.host}</td>
      <td style="padding:8px 12px;color:#555;font-size:13px;">${r.provider || "—"}</td>
    </tr>`)
    .join("\n");

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid #F97316;padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:#F97316;font-size:18px;">Subdomain Takeover Risk</h2>
    <p style="margin:0;color:#555;font-size:14px;">
      ${count} new risk${count !== 1 ? "s" : ""} detected on <strong>${domain}</strong>
    </p>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
    <thead>
      <tr style="background:#FFF7ED;">
        <th style="padding:8px 12px;text-align:left;color:#555;font-weight:600;">Subdomain</th>
        <th style="padding:8px 12px;text-align:left;color:#555;font-weight:600;">Provider</th>
      </tr>
    </thead>
    <tbody>${riskRows}</tbody>
  </table>
  <p style="font-size:14px;color:#555;line-height:1.6;">
    These subdomains have dangling CNAME records pointing to unclaimed cloud resources.
    An attacker could claim the target and serve malicious content on your domain.
    Remove or update the DNS records immediately.
  </p>
  <p style="margin-top:24px;">
    <a href="${reportUrl}" style="background:#F97316;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">CyberMeters — Attack Surface Management</p>
</body>
</html>`;

  await sendAlertEmail(subject, text, html, env, "SAFE_EMAIL_FROM");
}

/**
 * sendSslExpiryAlert — fires when the SSL certificate for a domain expires
 * within 30 days (cert_expiry_days from runSslModule).
 *
 * Sender selection:
 *   ≤ 14 days  → ALERT_EMAIL_FROM (alerts@)   — urgent security alert
 *   15–30 days → SAFE_EMAIL_FROM  (safe@)      — advance security warning
 *   HELLO_EMAIL_FROM is reserved for welcome/contact emails only.
 */
async function sendSslExpiryAlert(domain, scanId, daysUntilExpiry, certNotAfter, env) {
  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;
  const urgency   = daysUntilExpiry <= 7  ? "CRITICAL"
                  : daysUntilExpiry <= 14 ? "URGENT"
                  : "WARNING";
  // Route to appropriate sender based on urgency window
  const fromKey   = daysUntilExpiry <= 14 ? "ALERT_EMAIL_FROM" : "SAFE_EMAIL_FROM";
  const subject   = `[${urgency}] SSL certificate for ${domain} expires in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? "s" : ""}`;

  const expiryStr = certNotAfter
    ? new Date(certNotAfter).toUTCString().slice(0, 22) + " UTC"
    : "unknown";

  const text =
    `SSL certificate expiry warning for ${domain}\n\n` +
    `Days until expiry : ${daysUntilExpiry}\n` +
    `Certificate expires: ${expiryStr}\n\n` +
    `An expired SSL certificate will cause browsers to show security warnings\n` +
    `to all visitors, effectively taking your site offline. Renew immediately.\n\n` +
    `View report: ${reportUrl}`;

  const barColor  = daysUntilExpiry <= 7  ? "#EF4444"
                  : daysUntilExpiry <= 14 ? "#F97316"
                  : "#F59E0B";

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid ${barColor};padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:${barColor};font-size:18px;">SSL Certificate Expiry — ${urgency}</h2>
    <p style="margin:0;color:#555;font-size:14px;"><strong>${domain}</strong></p>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
    <tr>
      <td style="padding:8px 12px;background:#FFFBEB;color:#555;border-radius:6px 6px 0 0;width:50%;">Days remaining</td>
      <td style="padding:8px 12px;background:#FFFBEB;font-weight:700;color:${barColor};font-size:20px;">${daysUntilExpiry}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#F9FAFB;color:#555;border-radius:0 0 6px 6px;">Expiry date</td>
      <td style="padding:8px 12px;background:#F9FAFB;font-weight:600;">${expiryStr}</td>
    </tr>
  </table>
  <p style="font-size:14px;color:#555;line-height:1.6;">
    An expired SSL certificate causes browsers to show security warnings to all visitors,
    effectively taking your site offline. Renew the certificate immediately via your
    hosting provider, Let's Encrypt, or your certificate authority.
  </p>
  <p style="margin-top:24px;">
    <a href="${reportUrl}" style="background:${barColor};color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">CyberMeters — Attack Surface Management</p>
</body>
</html>`;

  await sendAlertEmail(subject, text, html, env, fromKey);
}

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
       FROM report_schedules
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

  // Resolve workspace owner — fall back to user_demo only if workspace has no owner
  let userId = "user_demo";
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

  try {
    // Ensure fallback demo user exists only when needed
    if (userId === "user_demo") {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO users (id, email, name, plan)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(id) DO NOTHING`
        )
        .bind("user_demo", "demo@cybermeters.com", "Demo User", "free")
        .run();
    }

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

    // Create scan row
    await env.cybermeters_db
      .prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES (?, ?, ?, ?, ?)`)
      .bind(scanId, domainId, schedule.workspace_id ?? null, schedule.domain, "running")
      .run();

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
      // Mark scan as failed in D1
      await env.cybermeters_db
        .prepare("UPDATE scans SET status = 'failed' WHERE id = ?")
        .bind(scanId)
        .run()
        .catch(() => {});
      // Update R2 placeholder to reflect failure
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
];

// Tables hard-deleted by workspace_id, children before parents. audit_events,
// subscriptions and deletion_requests are intentionally NOT here (retained /
// tracking). Kept in sync by `purge_covers_all_workspace_fk_tables`.
const WORKSPACE_PURGE_TABLES = [
  "dmarc_aggregate_records", "dmarc_aggregate_reports", "email_sender_sources",
  "dmarc_ingest_endpoints", "workspace_brand_assets", "workspace_brand_profiles",
  "asset_events", "asset_alert_records", "workspace_assets",
  "certificate_observations", "identity_assets", "historical_scores",
  "vendor_risk_scores", "vendor_risk_scores_history", "workspace_vendors",
  "workspace_brs_scores", "workspace_brs_score_history",
  "workspace_supply_chain_scores", "workspace_supply_chain_history",
  "notification_events", "notification_preferences",
  "report_schedule_runs", "report_schedules", "scheduled_reports",
  "workspace_invitations", "workspace_members", "workspace_retention_settings",
  "lifecycle_email_events", "scheduled_scans", "workspace_domains",
  "finding_waivers", "api_tokens", "workspace_alert_channels",
  "hosted_dns_records",
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
        `SELECT id, workspace_id, report_type, frequency
         FROM scheduled_reports
         WHERE enabled = 1
           AND (next_run_at IS NULL OR next_run_at <= ?)
         ORDER BY next_run_at ASC
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

      // Notification
      try {
        await createNotificationEvent(env, sr.workspace_id, {
          type:     "report_schedule_executed",
          severity: "info",
          title:    `Scheduled report generated`,
          message:  `${sr.report_type.replace(/_/g, ' ')} report generated automatically (${sr.frequency})`,
          metadata: { scheduled_report_id: sr.id, report_id: reportRow?.id, report_type: sr.report_type },
        });
      } catch { /* non-fatal */ }

      // Audit
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

async function generateScheduledReports(now, env) {
  const d   = new Date(now);
  const dow = d.getUTCDay();   // 0=Sun … 6=Sat
  const dom = d.getUTCDate();  // 1–31

  const doWeekly  = dow === 1;  // Monday
  const doMonthly = dom === 1;  // 1st of month

  if (!doWeekly && !doMonthly) return;

  let workspaces;
  try {
    const r = await env.cybermeters_db.prepare('SELECT id FROM workspaces').all();
    workspaces = r.results ?? [];
  } catch { return; }

  for (const ws of workspaces) {
    if (doWeekly) {
      try {
        const td = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
        td.setUTCDate(td.getUTCDate() + 4 - (td.getUTCDay() || 7));
        const year = td.getUTCFullYear();
        const wk   = Math.ceil((((td - Date.UTC(year, 0, 1)) / 86400000) + 1) / 7);
        const period = `${year}-W${String(wk).padStart(2, '0')}`;

        const exists = await env.cybermeters_db.prepare(
          `SELECT id FROM workspace_reports
           WHERE workspace_id = ? AND report_type = ? AND report_period = ? AND deleted_at IS NULL LIMIT 1`
        ).bind(ws.id, 'weekly_executive', period).first();
        if (exists) continue;

        await generateWorkspaceExecutiveReport(ws.id, env, {
          report_type:   'weekly_executive',
          report_period: period,
        });
      } catch { /* one workspace failing must not abort others */ }
    }

    if (doMonthly) {
      try {
        const period = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;

        const exists = await env.cybermeters_db.prepare(
          `SELECT id FROM workspace_reports
           WHERE workspace_id = ? AND report_type = ? AND report_period = ? AND deleted_at IS NULL LIMIT 1`
        ).bind(ws.id, 'monthly_executive', period).first();
        if (exists) continue;

        await generateWorkspaceExecutiveReport(ws.id, env, {
          report_type:   'monthly_executive',
          report_period: period,
        });
      } catch { /* one workspace failing must not abort others */ }
    }
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
// DNS TXT method for up to 48h after verification was initiated and completes
// it automatically. Only DNS TXT is retried: it is the propagation-bound
// method; the HTML-file method is instant and gains nothing from retrying.
// Bounded to 10 domains per run; each check is a single DoH subrequest.
async function retryPendingDomainVerifications(env) {
  try {
    const pending = await env.cybermeters_db
      .prepare(
        `SELECT id, domain, verification_token
         FROM domains
         WHERE verification_status IN ('pending', 'failed')
           AND verification_token IS NOT NULL
           AND verification_initiated_at >= datetime('now', '-48 hours')
         ORDER BY verification_initiated_at ASC
         LIMIT 10`
      )
      .all();

    for (const row of (pending?.results || [])) {
      let verified = false;
      try {
        const expected = `cybermeters-verification=${row.verification_token}`;
        const dnsResult = await dnsQuery(`_cybermeters.${row.domain}`, "TXT");
        verified = (dnsResult.Answer || []).some(a =>
          String(a.data || "").replace(/^"|"$/g, "").trim() === expected
        );
      } catch { /* resolver hiccup — the next hourly run retries */ }
      if (!verified) continue;

      await env.cybermeters_db
        .prepare(`UPDATE domains
                  SET verification_status = 'verified',
                      verification_method = 'dns_txt',
                      verified_at = datetime('now')
                  WHERE id = ? AND verification_status != 'verified'`)
        .bind(row.id)
        .run();

      // Mirror the manual-verify success path: notify + audit every linked workspace.
      // Forward telemetry: fingerprint the verified record + record the resolver
      // so a future drift check can prove which record we trusted, and when.
      try {
        const dnsRecordHash = await hashToken(`cybermeters-verification=${row.verification_token}`);
        const wsR = await env.cybermeters_db
          .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
          .bind(row.id).all();
        for (const { workspace_id } of (wsR.results || [])) {
          await createNotificationEvent(env, workspace_id, {
            type: "domain_verified", severity: "info",
            title: `${row.domain} ownership verified`,
            message: `The DNS TXT record at _cybermeters.${row.domain} has propagated — verification completed automatically.`,
            metadata: { domain: row.domain, domain_id: row.id, method: "dns_txt", auto_retry: true },
          });
          await createAuditEvent(env, {
            workspace_id, user_id: null,
            event_type: "domain_verified", entity_type: "domain", entity_id: row.id,
            description: `${row.domain} ownership verified via DNS TXT (automatic re-check)`,
            metadata: { domain: row.domain, domain_id: row.id, method: "dns_txt", auto_retry: true,
                        resolver_used: "cloudflare_doh", dns_record_hash: dnsRecordHash },
          });
        }
      } catch { /* non-fatal */ }
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

// ── Trial engine ──────────────────────────────────────────────────────────────

const TRIAL_PLAN          = "professional"; // plan granted during trial
const TRIAL_DURATION_DAYS = 14;

/**
 * isTrialActive(sub)
 *
 * Returns true if the subscription row represents an active trial.
 * A trial is active when:
 *   - subscription_status is 'trialing'
 *   - trial_end has not passed
 *
 * Handles null/missing gracefully (returns false).
 */
function isTrialActive(sub) {
  if (!sub) return false;
  const status = String(sub.subscription_status || sub.status || "").trim().toLowerCase();
  if (status !== "trialing") return false;
  if (!sub.trial_end) return false;
  const end = new Date(sub.trial_end);
  if (Number.isNaN(end.getTime())) return false;
  return end.getTime() > Date.now();
}

/**
 * isSubscriptionActive(sub)
 *
 * Returns true if the subscription represents a live paid subscription.
 * Excludes trialing status — use isTrialActive() for that case.
 * An active paid subscription requires:
 *   - subscription_status is 'active' (not trialing, past_due, cancelled, etc.)
 *   - current_period_end (or expires_at) has not passed, OR is null (no expiry set yet)
 */
function isSubscriptionActive(sub) {
  if (!sub) return false;
  const status = String(sub.subscription_status || sub.status || "").trim().toLowerCase();
  if (status !== "active") return false;
  // If no period end set, assume active (manual subscription with no expiry)
  const periodEnd = sub.current_period_end || sub.expires_at;
  if (!periodEnd) return true;
  const end = new Date(periodEnd);
  if (Number.isNaN(end.getTime())) return true; // unparseable — assume active
  return end.getTime() > Date.now();
}

/**
 * getTrialRemainingDays(sub)
 *
 * Returns integer days remaining in the trial (0 if not trialing or expired).
 * Rounds up: a trial ending in 30 minutes returns 1 day.
 */
function getTrialRemainingDays(sub) {
  if (!isTrialActive(sub)) return 0;
  const now = Date.now();
  const end = new Date(sub.trial_end).getTime();
  const diffMs = end - now;
  if (diffMs <= 0) return 0;
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * getWorkspaceSubscription(workspaceId, env)
 *
 * Fetches the full subscription row for a workspace.
 * Resolves via workspace.owner_user_id → subscriptions.owner_user_id.
 * Returns null if no subscription row exists.
 *
 * Used by:
 *   - GET /api/workspaces/:id/subscription
 *   - SubscriptionPage.jsx (via the above endpoint)
 */
async function getWorkspaceSubscription(workspaceId, env) {
  if (!workspaceId) return null;
  try {
    const ws = await env.cybermeters_db
      .prepare(`SELECT owner_user_id FROM workspaces WHERE id = ?`)
      .bind(workspaceId)
      .first();
    if (!ws?.owner_user_id) return null;

    const sub = await env.cybermeters_db
      .prepare(
        `SELECT id, owner_user_id, workspace_id, plan, status,
                subscription_status, billing_interval,
                trial_start, trial_end, current_period_start, current_period_end,
                expires_at, stripe_customer_id, stripe_subscription_id,
                cancel_at_period_end, cancelled_at,
                payment_failed_at, payment_retry_count,
                created_at, updated_at
         FROM subscriptions
         WHERE owner_user_id = ?
         ORDER BY COALESCE(updated_at, created_at) DESC
         LIMIT 1`
      )
      .bind(ws.owner_user_id)
      .first();
    return sub ?? null;
  } catch {
    return null;
  }
}

/**
 * createWorkspaceTrialSubscription(workspaceId, ownerUserId, env)
 *
 * Inserts a 14-day Professional trial subscription row when a workspace is created.
 * Also inserts a trial_started event in subscription_events.
 *
 * Called from the POST /api/workspaces route after workspace row is inserted.
 * Fails silently — workspace creation should not be blocked by billing errors.
 */
async function createWorkspaceTrialSubscription(workspaceId, ownerUserId, env) {
  if (!workspaceId || !ownerUserId) return;
  try {
    const now     = new Date();
    const trialEnd = new Date(now.getTime() + TRIAL_DURATION_DAYS * 24 * 60 * 60 * 1000);
    const subId   = createId("sub");

    await env.cybermeters_db
      .prepare(
        `INSERT OR IGNORE INTO subscriptions
           (id, owner_user_id, workspace_id, plan, status, subscription_status,
            trial_start, trial_end, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'trialing', 'trialing', ?, ?, datetime('now'), datetime('now'))`
      )
      .bind(
        subId,
        ownerUserId,
        workspaceId,
        TRIAL_PLAN,
        now.toISOString(),
        trialEnd.toISOString()
      )
      .run();

    // Record trial_started event
    try {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO subscription_events
             (id, subscription_id, event_type, payload_json, created_at)
           VALUES (?, ?, 'trial_started', ?, datetime('now'))`
        )
        .bind(
          createId("sev"),
          subId,
          JSON.stringify({
            workspace_id: workspaceId,
            owner_user_id: ownerUserId,
            plan: TRIAL_PLAN,
            trial_start: now.toISOString(),
            trial_end: trialEnd.toISOString(),
            trial_duration_days: TRIAL_DURATION_DAYS,
          })
        )
        .run();
    } catch { /* event log failure is non-fatal */ }
  } catch { /* billing failure must not block workspace creation */ }
}

function parseCheckoutPlan(plan) {
  const value = String(plan || "").trim().toLowerCase();
  if (!value || !Object.prototype.hasOwnProperty.call(BILLING_PLAN_METADATA, value)) {
    return { ok: false, plan: null };
  }
  return { ok: true, plan: value };
}

function getPublicBillingPlans() {
  return ["free", "starter", "professional", "business", "enterprise"].map((plan) => ({
    key: plan,
    ...BILLING_PLAN_METADATA[plan],
    limits: getPlanLimits(plan),
    features: getPlanFeatures(plan),
  }));
}

async function auditApiTokenSessionRouteDenied(env, user, request) {
  if (!user?.api_token_id) return;
  await createAuditEvent(env, {
    user_id:     user.id,
    event_type:  "api_token_denied_session_required",
    entity_type: "api_token",
    entity_id:   user.api_token_id,
    description: "API token denied for session-only route",
    metadata:    { method: request.method, path: new URL(request.url).pathname },
  });
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
      console.error("[request-error]", JSON.stringify({
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
                       corsHeaders, isActionableFinding, consumeApiRateLimit, ROLE_RANK };

    // ── GET /api/billing/plans ──────────────────────────────────────────
    // Public billing metadata for future pricing/billing UI. Stripe price IDs
    // are intentionally not returned; checkout resolves prices server-side.
    if (request.method === "GET" && url.pathname === "/api/billing/plans") {
      const stripeConfig = validateStripeBillingConfig(env);
      return json({
        currency: "gbp",
        checkout_enabled: stripeConfig.ok,
        plans: getPublicBillingPlans(),
        stripe: {
          configured: stripeConfig.ok,
        },
      });
    }

    // ── POST /api/dmarc-ingest ──────────────────────────────────────────
    // Assisted DMARC Upload v1 — token-authenticated signed upload. No session
    // auth: identity is the per-workspace+domain upload token presented in an
    // Authorization: Bearer header (or X-CM-Ingest-Token fallback). The token
    // hash resolves to exactly one workspace+domain binding; ingestion may only
    // append DMARC report data. Body is raw XML (or JSON { xml }). The global
    // 1 MB request-body guard above caps payload size before this point.
    if (request.method === "POST" && url.pathname === "/api/dmarc-ingest") {
      try {
        const token = extractIngestToken(request);
        if (!token) {
          return json({ imported: false, error: "missing_token",
            message: "Missing upload credentials." }, 401);
        }
        const tokenHash = await hashIngestToken(token);
        const endpoint = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE token_hash = ? LIMIT 1`)
          .bind(tokenHash).first();
        if (!ingestEndpointIsActive(endpoint)) {
          // Customer-safe: do not distinguish unknown vs revoked to the caller.
          await createAuditEvent(env, {
            workspace_id: endpoint?.workspace_id || null, user_id: null,
            event_type: "dmarc_ingest_rejected", entity_type: "domain",
            entity_id: endpoint?.domain_id || null,
            description: "Rejected DMARC signed upload with invalid or revoked key",
            metadata: { source: "signed_upload",
                        reason: endpoint ? "revoked_or_inactive" : "unknown_token",
                        ingest_endpoint_id: endpoint?.id || null },
          });
          return json({ imported: false, error: "invalid_token",
            message: "Upload credentials are invalid or have been revoked." }, 401);
        }

        // Abuse control: per-endpoint and per-workspace hourly caps.
        const rl = await consumeApiRateLimit(env,
          [{ scope: "dmarc_ingest_endpoint", scope_id: endpoint.id },
           { scope: "dmarc_ingest_ws", scope_id: endpoint.workspace_id }],
          "dmarc_ingest", 120, 3600);
        if (rl) {
          return json({ imported: false, error: "rate_limited",
            message: "Too many uploads. Please retry later." }, rl.status);
        }

        // Read body: raw XML by default, or JSON { xml } when so labelled.
        let xmlString = null;
        const ct = (request.headers.get("Content-Type") || "").toLowerCase();
        if (ct.includes("application/json")) {
          const body = await request.json().catch(() => null);
          xmlString = body && typeof body.xml === "string" ? body.xml : null;
        } else {
          xmlString = await request.text().catch(() => null);
        }
        if (!xmlString || !xmlString.trim()) {
          await createAuditEvent(env, {
            workspace_id: endpoint.workspace_id, user_id: null,
            event_type: "dmarc_ingest_rejected", entity_type: "domain", entity_id: endpoint.domain_id,
            description: `Rejected empty DMARC signed upload for ${endpoint.domain}`,
            metadata: { source: "signed_upload", reason: "empty_body", ingest_endpoint_id: endpoint.id },
          });
          return json({ imported: false, error: "missing_xml",
            message: "No report content was provided.", source: "signed_upload" }, 400);
        }

        const result = await ingestDmarcReport(env, {
          workspaceId: endpoint.workspace_id, domain: endpoint.domain, source: "signed_upload",
          xmlString, actorUserId: null, ingestEndpointId: endpoint.id, domainId: endpoint.domain_id,
          enforceDomainMatch: true,
        });

        // Record the authenticated use regardless of dedupe/parse outcome.
        await env.cybermeters_db
          .prepare(`UPDATE dmarc_ingest_endpoints SET last_used_at = datetime('now'), last_signed_upload_at = datetime('now') WHERE id = ?`)
          .bind(endpoint.id).run();

        if (!result.ok) {
          await createAuditEvent(env, {
            workspace_id: endpoint.workspace_id, user_id: null,
            event_type: "dmarc_ingest_rejected", entity_type: "domain", entity_id: endpoint.domain_id,
            description: `Rejected DMARC signed upload for ${endpoint.domain}: ${result.error}`,
            metadata: { source: "signed_upload", reason: result.error, ingest_endpoint_id: endpoint.id },
          });
          return json({ imported: false, error: result.error, message: result.message,
            source: "signed_upload" }, result.status || 422);
        }
        if (result.duplicate) {
          return json({ imported: false, duplicate: true,
            message: "This report was already imported and was not counted again.",
            source: "signed_upload" });
        }
        return json({ imported: true, duplicate: false,
          records: result.records, messages: result.messages, source: "signed_upload" });
      } catch (e) {
        return serverError("dmarc-ingest", e, "Report ingestion failed.");
      }
    }

    // ── GET /api/billing/subscription ───────────────────────────────────
    // Account-scoped subscription state used by the Billing page. Stripe is
    // not queried at request time; webhooks keep D1 as the platform source of
    // truth for plan, status, billing cycle, and renewal period.
    if (request.method === "GET" && url.pathname === "/api/billing/subscription") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const sub = await env.cybermeters_db
          .prepare(
            `SELECT plan,
                    subscription_status AS status,
                    billing_interval AS billing_cycle,
                    current_period_end
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(user.id)
          .first();
        const plan = await getUserPlan(user.id, env);
        return json(sub ? {
          plan,
          status: sub.status || "active",
          billing_cycle: normalizeBillingInterval(sub.billing_cycle),
          current_period_end: sub.current_period_end ?? null,
        } : {
          plan,
          status: "active",
          billing_cycle: "monthly",
          current_period_end: null,
        });
      } catch (e) {
        return serverError("billing/subscription", e, "Unable to load subscription.");
      }
    }

    // ── POST /api/billing/webhook ─────────────────────────────────────────
    // Stripe webhook receiver. Verifies the Stripe-Signature header using
    // HMAC-SHA256, then synchronises subscription lifecycle events into D1.
    // No session auth — identity is established by the webhook signature.
    // Returns 5xx after a valid signature if D1 synchronization fails so
    // Stripe retries transient persistence failures.
    if (request.method === "POST" && (url.pathname === "/api/billing/webhook" || url.pathname === "/api/stripe/webhook")) {
      // Read raw body first — required before any other body consumption so
      // the exact bytes Stripe signed are available for HMAC verification.
      const rawBody = await request.text();

      const webhookConfig = validateStripeWebhookConfig(env);
      if (!webhookConfig.ok) {
        return json({
          error:   webhookConfig.error,
          missing: webhookConfig.missing,
          message: "Stripe webhook secret is not configured.",
        }, 503);
      }

      const sigHeader = request.headers.get("Stripe-Signature") || "";
      const sigResult = await verifyStripeWebhookSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
      if (!sigResult.ok) {
        return json({ error: sigResult.error }, 400);
      }

      let event;
      try { event = JSON.parse(rawBody); } catch {
        return json({ error: "invalid_json" }, 400);
      }

      const eventType = event?.type ?? "unknown";
      const obj       = event?.data?.object;

      try {
        switch (eventType) {

          // ── checkout.session.completed ────────────────────────────────────
          // Customer completed Stripe-hosted checkout. Writes stripe_customer_id
          // and stripe_subscription_id into subscriptions. getEffectivePlan()
          // will return the new plan once subscription_status = 'active'.
          // current_period_end is absent on the session object — it arrives
          // seconds later via customer.subscription.created.
          case "checkout.session.completed": {
            const rowId = await handleCheckoutSessionCompleted(env, obj);
            const metadata = obj?.metadata || {};
            await createAuditEvent(env, {
              user_id:     metadata.user_id || obj?.client_reference_id || null,
              event_type:  "billing_checkout_completed",
              entity_type: "stripe_checkout_session",
              entity_id:   obj?.id || null,
              description: "Stripe checkout completed",
              metadata:    {
                subscription_row_id: rowId,
                stripe_session_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                stripe_subscription_id: getStripeObjectId(obj?.subscription),
                plan: normalizePlan(metadata.plan),
                interval: normalizeBillingInterval(metadata.interval),
              },
            });
            await writeSubscriptionEvent(env, rowId, "checkout_completed", {
              stripe_session_id: obj?.id || null,
              plan: normalizePlan(metadata.plan),
              interval: normalizeBillingInterval(metadata.interval),
            });
            break;
          }

          // ── customer.subscription.created ─────────────────────────────────
          // Fires seconds after checkout.session.completed. Carries the exact
          // Stripe status and current_period_end. Upserts the subscriptions row
          // so getEffectivePlan() reads the correct plan and expiry.
          case "customer.subscription.created": {
            const rowId = await handleStripeSubscriptionUpsert(env, obj);
            const metadata = obj?.metadata || {};
            const price = getStripeSubscriptionPrice(obj);
            await createAuditEvent(env, {
              user_id:     metadata.user_id || null,
              event_type:  "subscription_created",
              entity_type: "subscription",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe subscription created",
              metadata:    {
                subscription_row_id: rowId,
                stripe_subscription_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                plan: getPlanFromStripePriceId(env, price?.id || null, metadata.plan),
                billing_interval: getBillingIntervalFromStripeSubscription(obj, metadata.interval),
                status: normalizeStripeSubscriptionStatus(obj?.status),
                current_period_end: stripeUnixToIso(obj?.current_period_end),
              },
            });
            await writeSubscriptionEvent(env, rowId, "subscription_created", {
              stripe_subscription_id: obj?.id || null,
              plan: getPlanFromStripePriceId(env, price?.id || null, metadata.plan),
              status: normalizeStripeSubscriptionStatus(obj?.status),
              current_period_start: stripeUnixToIso(obj?.current_period_start),
              current_period_end: stripeUnixToIso(obj?.current_period_end),
            });
            break;
          }

          // ── customer.subscription.updated ─────────────────────────────────
          // Plan change, renewal, payment status update, or cancel_at_period_end
          // flag set. Updates plan, billing_interval, subscription_status, and
          // current_period_end in subscriptions.
          case "customer.subscription.updated": {
            const metadata = obj?.metadata || {};
            let previousSubscription = null;
            try {
              const previousRowId = await findSubscriptionRowId(env, {
                ownerUserId: metadata.user_id || null,
                stripeSubscriptionId: obj?.id || null,
                stripeCustomerId: getStripeObjectId(obj?.customer),
              });
              previousSubscription = previousRowId
                ? await env.cybermeters_db
                  .prepare("SELECT plan, billing_interval, subscription_status FROM subscriptions WHERE id = ?")
                  .bind(previousRowId)
                  .first()
                : null;
            } catch { /* audit metadata lookup only */ }
            const rowId = await handleStripeSubscriptionUpsert(env, obj);
            const price = getStripeSubscriptionPrice(obj);
            const newPlan = getPlanFromStripePriceId(env, price?.id || null, metadata.plan);
            const previousPlan = previousSubscription?.plan ? normalizePlan(previousSubscription.plan) : null;
            await createAuditEvent(env, {
              user_id:     metadata.user_id || null,
              event_type:  "subscription_updated",
              entity_type: "subscription",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe subscription updated",
              metadata:    {
                subscription_row_id: rowId,
                stripe_subscription_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                previous_plan: previousPlan,
                plan: newPlan,
                plan_changed: previousPlan ? previousPlan !== newPlan : false,
                billing_interval: getBillingIntervalFromStripeSubscription(obj, metadata.interval),
                previous_billing_interval: previousSubscription?.billing_interval ?? null,
                status: normalizeStripeSubscriptionStatus(obj?.status),
                previous_status: previousSubscription?.subscription_status ?? null,
                current_period_end: stripeUnixToIso(obj?.current_period_end),
              },
            });
            await writeSubscriptionEvent(env, rowId, "subscription_updated", {
              stripe_subscription_id: obj?.id || null,
              plan: newPlan,
              plan_changed: previousPlan ? previousPlan !== newPlan : false,
              status: normalizeStripeSubscriptionStatus(obj?.status),
              cancel_at_period_end: obj?.cancel_at_period_end ?? null,
              current_period_start: stripeUnixToIso(obj?.current_period_start),
              current_period_end: stripeUnixToIso(obj?.current_period_end),
            });
            break;
          }

          // ── customer.subscription.deleted ─────────────────────────────────
          // Subscription has ended. Sets subscription_status = 'canceled'.
          // getEffectivePlan() returns 'free' for any non-active status.
          // Row is never deleted — historical record is preserved.
          case "customer.subscription.deleted": {
            const rowId = await handleStripeSubscriptionDeleted(env, obj);
            const metadata = obj?.metadata || {};
            await createAuditEvent(env, {
              user_id:     metadata.user_id || null,
              event_type:  "subscription_canceled",
              entity_type: "subscription",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe subscription canceled",
              metadata:    {
                subscription_row_id: rowId,
                stripe_subscription_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                status: "canceled",
                current_period_end: stripeUnixToIso(obj?.current_period_end),
              },
            });
            await writeSubscriptionEvent(env, rowId, "subscription_canceled", {
              stripe_subscription_id: obj?.id || null,
              status: "canceled",
              current_period_end: stripeUnixToIso(obj?.current_period_end),
            });
            break;
          }

          // ── invoice.payment_failed ───────────────────────────────────────
          // Payment failure should immediately remove paid entitlements from
          // runtime plan resolution. The row is retained and marked past_due;
          // later customer.subscription.updated events can restore active
          // status after Stripe collects payment.
          case "invoice.payment_failed": {
            const rowId = await handleStripeInvoicePaymentFailed(env, obj);
            await createAuditEvent(env, {
              user_id:     null,
              event_type:  "subscription_payment_failed",
              entity_type: "stripe_invoice",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe invoice payment failed",
              metadata:    {
                subscription_row_id: rowId,
                stripe_invoice_id: obj?.id || null,
                stripe_subscription_id: getStripeObjectId(obj?.subscription),
                stripe_customer_id: getStripeObjectId(obj?.customer),
                attempt_count: obj?.attempt_count ?? null,
              },
            });
            await writeSubscriptionEvent(env, rowId, "payment_failed", {
              stripe_invoice_id: obj?.id || null,
              stripe_subscription_id: getStripeObjectId(obj?.subscription),
              attempt_count: obj?.attempt_count ?? null,
            });

            // Customer trust: a payment failure must never be silent. Email the
            // subscription owner (deduped once per invoice, so Stripe's retry
            // events don't spam) and mirror it in-app. Failures here must not
            // fail the webhook — Stripe would retry the whole event.
            if (rowId) {
              try {
                const subOwner = await env.cybermeters_db
                  .prepare("SELECT owner_user_id, workspace_id FROM subscriptions WHERE id = ? LIMIT 1")
                  .bind(rowId)
                  .first();
                if (subOwner?.owner_user_id) {
                  await sendLifecycleEmail(env, {
                    type: "lifecycle_payment_failed",
                    user_id: subOwner.owner_user_id,
                    workspace_id: subOwner.workspace_id ?? null,
                    ref: obj?.id || null,
                  }).catch(() => {});
                }
                if (subOwner?.workspace_id) {
                  await createNotificationEvent(env, subOwner.workspace_id, {
                    type:     "subscription_payment_failed",
                    severity: "high",
                    title:    "Payment failed",
                    message:  "Your latest subscription payment could not be processed. Update your payment method in Billing to keep your paid plan active.",
                    metadata: { subscription_id: rowId },
                    user_id:  subOwner.owner_user_id ?? null,
                  }).catch(() => {});
                }
              } catch {
                // Notification failure must not affect webhook processing
              }
            }
            break;
          }

          // ── invoice.payment_succeeded ────────────────────────────────────
          // Payment succeeded — clears past_due status and resets retry count.
          // Note: customer.subscription.updated also fires on renewal and is
          // the authoritative source for current_period_end. This handler only
          // clears the payment failure state.
          case "invoice.payment_succeeded": {
            const rowId = await handleStripeInvoicePaymentSucceeded(env, obj);
            await createAuditEvent(env, {
              user_id:     null,
              event_type:  "subscription_payment_succeeded",
              entity_type: "stripe_invoice",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe invoice payment succeeded",
              metadata:    {
                subscription_row_id: rowId,
                stripe_invoice_id: obj?.id || null,
                stripe_subscription_id: getStripeObjectId(obj?.subscription),
                stripe_customer_id: getStripeObjectId(obj?.customer),
                amount_paid: obj?.amount_paid ?? null,
                currency: obj?.currency ?? null,
              },
            });
            await writeSubscriptionEvent(env, rowId, "payment_succeeded", {
              stripe_invoice_id: obj?.id || null,
              stripe_subscription_id: getStripeObjectId(obj?.subscription),
              amount_paid: obj?.amount_paid ?? null,
              currency: obj?.currency ?? null,
            });
            break;
          }

          // All other Stripe events are acknowledged and silently ignored.
          default:
            break;
        }
      } catch (e) {
        // Return 500 so Stripe retries delivery on transient D1 failures.
        // Stripe uses exponential backoff (max 25 attempts over 72 h).
        console.error(`[webhook] handler error [${eventType}]: ${e?.message ?? e}`);
        return json({
          error:      "webhook_sync_failed",
          event_type: eventType,
          message:    "D1 synchronization failed. Stripe will retry.",
        }, 500);
      }

      return json({ received: true, event_type: eventType }, 200);
    }

    // ── POST /api/auth/signup ────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/signup") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email    = (body.email    || "").trim().toLowerCase();
      const password = (body.password || "").trim();
      const name     = (body.name     || "").trim();

      if (!isValidEmail(email))        return json({ error: "A valid email address is required" }, 400);
      if (!password)                   return json({ error: "Password cannot be blank" }, 400);
      if (password.length < 12)        return json({ error: "Password must be at least 12 characters" }, 400);
      if (password.length > 128)       return json({ error: "Password is too long" }, 400);

      const signupClientIp = request.headers.get("CF-Connecting-IP") ||
                             request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                             "unknown";
      const signupRateLimit = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("signup", signupClientIp) }],
        "signup",
        5,
        3600,
        // Abuse-critical: if rate limiting is unavailable, refuse rather than
        // allow unmetered account creation.
        { failClosed: true },
      );
      if (signupRateLimit) {
        return json({ error: "Too many signup attempts. Please wait before trying again.", code: "rate_limit_exceeded" }, signupRateLimit.status);
      }

      try {
        // Check for duplicate email
        const existing = await env.cybermeters_db
          .prepare("SELECT id FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (existing) return json({ error: "An account with this email already exists" }, 409);

        const userId      = createId("usr");
        const passwordHash = await hashPassword(password);

        // Generate a 24-hour email verification token
        const { raw: verificationToken, hash: verificationTokenHash } = await generateEmailVerificationToken();
        const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO users
               (id, email, name, plan, password_hash, status,
                email_verified, verification_token, verification_token_expires_at,
                created_at)
             VALUES (?, ?, ?, 'free', ?, 'active', 0, ?, ?, datetime('now'))`
          )
          .bind(userId, email, name || null, passwordHash, verificationTokenHash, verificationTokenExpires)
          .run();

        // Audit: account created
        await createAuditEvent(env, {
          user_id:     userId,
          event_type:  "USER_REGISTERED",
          entity_type: "user",
          entity_id:   userId,
          description: `New account created for ${email}`,
          metadata:    { email, name: name || null },
        }).catch(() => {});

        // Send verification email (fire-and-forget — signup succeeds even if email fails)
        const frontendUrl    = env.FRONTEND_URL || "https://app.cybermeters.com";
        const workerBase     = url.origin;
        const verifyLink     = `${workerBase}/api/auth/verify-email?token=${verificationToken}`;
        const displayName    = name || email.split("@")[0];
        const displayNameHtml = escapeEmailHtml(displayName);
        const verificationDelivery = await sendCustomerEmail(
          "Verify your CyberMeters email address",
          `Hi ${displayName},\n\nPlease verify your email address by clicking the link below:\n\n${verifyLink}\n\nThis link expires in 24 hours.\n\nIf you did not create a CyberMeters account, you can safely ignore this email.\n\nThe CyberMeters Team`,
          `<!DOCTYPE html><html><body style="font-family:sans-serif;color:#1f2937;max-width:560px;margin:40px auto;padding:0 20px">
            <h2 style="color:#1d4ed8">Verify your email address</h2>
            <p>Hi ${displayNameHtml},</p>
            <p>Thanks for signing up for CyberMeters. Please verify your email address to activate your account.</p>
            <p style="margin:32px 0">
              <a href="${verifyLink}" style="background:#1d4ed8;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Verify email address</a>
            </p>
            <p style="color:#6b7280;font-size:14px">This link expires in 24 hours. If you did not create a CyberMeters account, you can safely ignore this email.</p>
          </body></html>`,
          env,
          "HELLO_EMAIL_FROM",
          [email]
        );

        await createAuditEvent(env, {
          user_id:     userId,
          event_type:  verificationDelivery.sent ? "USER_EMAIL_VERIFICATION_SENT" : "USER_EMAIL_VERIFICATION_DELIVERY_FAILED",
          entity_type: "user",
          entity_id:   userId,
          description: verificationDelivery.sent
            ? `Verification email sent to ${email}`
            : `Verification email delivery failed for ${email}`,
          metadata:    {
            email,
            delivery_status: verificationDelivery.sent ? "accepted" : "failed",
            delivery_reason: verificationDelivery.reason || null,
            provider_id: verificationDelivery.provider_id || null,
          },
        }).catch(() => {});

        return json({ success: true, verification_required: true, email }, 201);
      } catch (e) {
        return serverError("auth/signup", e, "Signup failed. Please try again.");
      }
    }

    // ── POST /api/auth/login ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email    = (body.email    || "").trim().toLowerCase();
      const password = (body.password || "").trim();

      if (!email || !password) return json({ error: "Email and password are required" }, 400);

      // ── Login brute-force protection ──────────────────────────────────────
      // Rate-limit by hashed client IP: 10 attempts per 15-minute window.
      // Fires before any credential check to prevent timing-assisted enumeration
      // at high attempt counts. Generic 429 message does not reveal account state.
      const _loginClientIp = request.headers.get("CF-Connecting-IP") ||
                             request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                             "unknown";
      const _loginIpHash = await (async () => {
        try {
          const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(_loginClientIp));
          return Array.from(new Uint8Array(buf)).slice(0, 8).map(b => b.toString(16).padStart(2, "0")).join("");
        } catch { return _loginClientIp.replace(/[^a-z0-9]/gi, "_").slice(0, 32); }
      })();
      const _loginRlResult = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: `login_${_loginIpHash}` }],
        "login",
        10,
        900, // 15 minutes
        // Abuse-critical: never allow unmetered credential guessing.
        { failClosed: true },
      );
      if (_loginRlResult) {
        return json({ error: "Too many login attempts. Please wait before trying again.", code: "rate_limit_exceeded" }, 429);
      }
      // ─────────────────────────────────────────────────────────────────────

      try {
        const user = await env.cybermeters_db
          .prepare("SELECT id, email, name, plan, password_hash, status, mfa_enabled, email_verified, auth_provider FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();

        // Always run verifyPassword even if user not found to prevent user-enumeration via timing
        const storedHash  = user?.password_hash ?? "pbkdf2:sha256:100000:0000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000";
        const passwordOk  = await verifyPassword(password, storedHash);

        if (!user || !passwordOk || !user.password_hash) {
          // Audit: failed login — provides brute-force visibility
          if (user?.id) {
            await createAuditEvent(env, {
              user_id:     user.id,
              event_type:  "login_failed",
              entity_type: "user",
              entity_id:   user.id,
              description: `Failed login attempt for ${email}`,
              metadata:    { email, ip_address: request.headers.get("CF-Connecting-IP") || null, user_agent: request.headers.get("User-Agent") || null },
            }).catch(() => {});
          }
          return json({ error: "Invalid email or password" }, 401);
        }
        if (user.status === "suspended") {
          return json({ error: "Account suspended. Contact support." }, 403);
        }

        // ── Email verification gate ───────────────────────────────────────────
        // Local-auth accounts must have a verified email before being granted a session.
        // Microsoft OAuth accounts are auto-verified and skip this check.
        const isLocalAccount = !user.auth_provider || user.auth_provider === "local";
        if (isLocalAccount && !user.email_verified) {
          return json({ error: "email_verification_required", email: user.email }, 403);
        }

        // ── MFA gate ─────────────────────────────────────────────────────────
        // If MFA is enabled, do NOT create a session yet.
        // Issue a short-lived challenge token; client must verify TOTP at
        // POST /api/auth/mfa/challenge to receive the real session token.
        if (user.mfa_enabled) {
          const { raw: challengeRaw, hash: challengeHash } = await generateMfaChallengeToken();
          const challengeId = createId("mfach");
          const challengeExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min
          await env.cybermeters_db
            .prepare(
              `INSERT INTO mfa_challenges (id, user_id, challenge_hash, expires_at)
               VALUES (?, ?, ?, ?)`
            )
            .bind(challengeId, user.id, challengeHash, challengeExpiry)
            .run();
          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "mfa_challenge_issued",
            entity_type: "user",
            entity_id:   user.id,
            description: `MFA challenge issued for ${user.email}`,
            metadata:    { challenge_id: challengeId, ip_address: request.headers.get("CF-Connecting-IP") || null, user_agent: request.headers.get("User-Agent") || null },
          }).catch(() => {});
          return json({ mfa_required: true, challenge_token: challengeRaw });
        }

        // Generate session token — raw sent to client, hash stored in D1
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId  = createId("sess");
        const expiresAt  = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

        const _loginIp = request.headers.get("CF-Connecting-IP") || null;
        const _loginUa = request.headers.get("User-Agent") || null;
        await env.cybermeters_db
          .prepare(
            `INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?, ?)`
          )
          .bind(sessionId, user.id, tokenHash, expiresAt, _loginIp, _loginUa)
          .run();

        // Update last_login_at
        await env.cybermeters_db
          .prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?")
          .bind(user.id)
          .run();

        // Audit: login
        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "login",
          entity_type: "user",
          entity_id:   user.id,
          description: `${user.email} signed in`,
          metadata:    { ip_address: _loginIp, user_agent: _loginUa },
        });

        const plan = await getEffectivePlan(user.id, env);
        return json({
          token,
          user: {
            id:    user.id,
            email: user.email,
            name:  user.name,
            plan,
          },
        });
      } catch (e) {
        return serverError("auth/login", e, "Login failed. Please try again.");
      }
    }

    // ── GET /api/auth/me ─────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const plan = await getEffectivePlan(user.id, env);
      return json({
        id:    user.id,
        email: user.email,
        name:  user.name,
        plan,
      });
    }

    // ── POST /api/auth/logout ────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/logout") {
      const authHeader = request.headers.get("Authorization") || "";
      if (authHeader.startsWith("Bearer ")) {
        const rawToken = authHeader.slice(7).trim();
        if (rawToken) {
          try {
            const tokenHash = await hashToken(rawToken);
            // Resolve user before deleting session so we can audit
            const sessionRow = await env.cybermeters_db
              .prepare("SELECT user_id FROM user_sessions WHERE token_hash = ?")
              .bind(tokenHash)
              .first();
            await env.cybermeters_db
              .prepare("DELETE FROM user_sessions WHERE token_hash = ?")
              .bind(tokenHash)
              .run();
            if (sessionRow?.user_id) {
              await createAuditEvent(env, {
                user_id:     sessionRow.user_id,
                event_type:  "logout",
                entity_type: "user",
                entity_id:   sessionRow.user_id,
                description: "User signed out",
              });
            }
          } catch { /* silent — token may already be expired */ }
        }
      }
      return json({ success: true });
    }

    // ── GET /api/auth/verify-email ───────────────────────────────────────
    // Validates the one-time email verification token sent during signup.
    // On success: marks the account as verified, clears the token, redirects to
    //   ${FRONTEND_URL}/verify-email?success=1
    // On failure: redirects to
    //   ${FRONTEND_URL}/verify-email?error=<reason>
    if (request.method === "GET" && url.pathname === "/api/auth/verify-email") {
      const frontendUrl = env.FRONTEND_URL || "https://app.cybermeters.com";
      const token = url.searchParams.get("token") || "";
      const dest = new URL("/verify-email", frontendUrl);

      if (!token) {
        dest.searchParams.set("error", "Missing verification token");
        return Response.redirect(dest.toString(), 302);
      }

      try {
        const tokenHash = await hashToken(token);
        const userRow = await env.cybermeters_db
          .prepare(
            `SELECT id, email, email_verified, verification_token_expires_at
             FROM users
             WHERE verification_token IN (?, ?)
             LIMIT 1`
          )
          .bind(tokenHash, token)
          .first();

        const tokenStatus = getEmailVerificationTokenStatus(userRow);
        if (tokenStatus === "invalid") {
          dest.searchParams.set("error", "Invalid or already used verification link");
          return Response.redirect(dest.toString(), 302);
        }

        if (tokenStatus === "already_verified") {
          // Already verified — just redirect to success
          dest.searchParams.set("success", "1");
          return Response.redirect(dest.toString(), 302);
        }

        if (tokenStatus === "expired") {
          await createAuditEvent(env, {
            user_id:     userRow.id,
            event_type:  "USER_EMAIL_VERIFICATION_EXPIRED",
            entity_type: "user",
            entity_id:   userRow.id,
            description: `Expired email verification attempted for ${userRow.email}`,
            metadata:    { email: userRow.email },
          }).catch(() => {});
          dest.searchParams.set("error", "Verification link has expired. Please request a new one.");
          return Response.redirect(dest.toString(), 302);
        }

        const verificationUpdate = await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET email_verified = 1,
                 email_verified_at = datetime('now'),
                 verification_token = NULL,
                 verification_token_expires_at = NULL
             WHERE id = ?
               AND email_verified = 0
               AND verification_token IN (?, ?)
               AND verification_token_expires_at IS NOT NULL
               AND unixepoch(verification_token_expires_at) > unixepoch('now')`
          )
          .bind(userRow.id, tokenHash, token)
          .run();

        if ((verificationUpdate.meta?.changes ?? 0) !== 1) {
          dest.searchParams.set("error", "Invalid or already used verification link");
          return Response.redirect(dest.toString(), 302);
        }

        await createAuditEvent(env, {
          user_id:     userRow.id,
          event_type:  "USER_EMAIL_VERIFIED",
          entity_type: "user",
          entity_id:   userRow.id,
          description: `Email verified for ${userRow.email}`,
          metadata:    { email: userRow.email },
        }).catch(() => {});

        // Lifecycle: welcome / getting-started (once per user; verified address).
        await sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: userRow.id, to: userRow.email }).catch(() => {});

        dest.searchParams.set("success", "1");
        return Response.redirect(dest.toString(), 302);
      } catch (e) {
        dest.searchParams.set("error", "Verification failed. Please try again.");
        return Response.redirect(dest.toString(), 302);
      }
    }

    // ── POST /api/auth/resend-verification ───────────────────────────────
    // Generates a fresh verification token and re-sends the email.
    // Always returns success to avoid leaking whether an address is registered.
    if (request.method === "POST" && url.pathname === "/api/auth/resend-verification") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      if (!isValidEmail(email)) return json({ success: true }); // silent — don't leak

      const resendClientIp = request.headers.get("CF-Connecting-IP") ||
                             request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                             "unknown";
      const resendRateLimit = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("resend_verification", resendClientIp) }],
        "resend_verification",
        5,
        900,
        { failClosed: true },
      );
      if (resendRateLimit) {
        return json({
          error: "Too many verification email requests. Please wait before trying again.",
          code: resendRateLimit.body.code,
        }, resendRateLimit.status);
      }

      try {
        const userRow = await env.cybermeters_db
          .prepare(
            `SELECT id, name, email_verified, auth_provider, verification_token_expires_at
             FROM users WHERE email = ? LIMIT 1`
          )
          .bind(email)
          .first();

        // Silently succeed for unknown emails or already-verified accounts
        if (!userRow || userRow.email_verified) return json({ success: true });
        // Microsoft accounts are always verified — should never reach here, but guard anyway
        if (userRow.auth_provider && userRow.auth_provider !== "local") return json({ success: true });

        // 60-second resend cooldown: tokens are always issued with a 24-hour TTL.
        // If the existing expiry is still more than (24h - 60s) in the future, the
        // last token was issued less than 60 seconds ago — return success silently.
        if (isEmailVerificationResendCoolingDown(userRow.verification_token_expires_at)) {
          return json({ success: true }); // account cooldown — do not send
        }

        const { raw: newToken, hash: newTokenHash } = await generateEmailVerificationToken();
        const newExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        const cooldownCutoff = new Date(Date.now() + (24 * 60 * 60 * 1000) - (60 * 1000)).toISOString();

        const tokenUpdate = await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET verification_token = ?,
                 verification_token_expires_at = ?
             WHERE id = ?
               AND email_verified = 0
               AND (verification_token_expires_at IS NULL
                    OR unixepoch(verification_token_expires_at) <= unixepoch(?))`
          )
          .bind(newTokenHash, newExpires, userRow.id, cooldownCutoff)
          .run();

        if ((tokenUpdate.meta?.changes ?? 0) !== 1) return json({ success: true });

        const workerBase  = url.origin;
        const verifyLink  = `${workerBase}/api/auth/verify-email?token=${newToken}`;
        const displayName = userRow.name || email.split("@")[0];
        const displayNameHtml = escapeEmailHtml(displayName);
        const verificationDelivery = await sendCustomerEmail(
          "Verify your CyberMeters email address",
          `Hi ${displayName},\n\nPlease verify your email address by clicking the link below:\n\n${verifyLink}\n\nThis link expires in 24 hours.\n\nIf you did not request this email, you can safely ignore it.\n\nThe CyberMeters Team`,
          `<!DOCTYPE html><html><body style="font-family:sans-serif;color:#1f2937;max-width:560px;margin:40px auto;padding:0 20px">
            <h2 style="color:#1d4ed8">Verify your email address</h2>
            <p>Hi ${displayNameHtml},</p>
            <p>Click below to verify your CyberMeters email address and activate your account.</p>
            <p style="margin:32px 0">
              <a href="${verifyLink}" style="background:#1d4ed8;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Verify email address</a>
            </p>
            <p style="color:#6b7280;font-size:14px">This link expires in 24 hours. If you did not request this, you can safely ignore this email.</p>
          </body></html>`,
          env,
          "HELLO_EMAIL_FROM",
          [email]
        );

        await createAuditEvent(env, {
          user_id:     userRow.id,
          event_type:  verificationDelivery.sent ? "USER_EMAIL_VERIFICATION_RESENT" : "USER_EMAIL_VERIFICATION_DELIVERY_FAILED",
          entity_type: "user",
          entity_id:   userRow.id,
          description: verificationDelivery.sent
            ? `Verification email resent to ${email}`
            : `Verification email delivery failed for ${email}`,
          metadata:    {
            email,
            delivery_status: verificationDelivery.sent ? "accepted" : "failed",
            delivery_reason: verificationDelivery.reason || null,
            provider_id: verificationDelivery.provider_id || null,
          },
        }).catch(() => {});

        return json({ success: true });
      } catch (e) {
        // Swallow errors — never reveal internals
        return json({ success: true });
      }
    }

    // ── GET /api/auth/microsoft/login ────────────────────────────────────
    // Initiates the Microsoft Entra OAuth authorization code flow.
    // Generates a CSRF state token, stores it in oauth_states with a 10-minute
    // TTL, and redirects the browser to Microsoft's authorization endpoint.
    //
    // Env vars required: AZURE_CLIENT_ID, AZURE_TENANT_ID
    // Optional: MICROSOFT_REDIRECT_URI (defaults to same-origin /callback)
    if (request.method === "GET" && url.pathname === "/api/auth/microsoft/login") {
      const clientId  = env.AZURE_CLIENT_ID;
      const tenantId  = env.AZURE_TENANT_ID;

      if (!clientId || !tenantId) {
        return json({ error: "Microsoft login is not configured on this instance" }, 503);
      }

      // Generate a cryptographically random state for CSRF protection
      const stateRaw = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0")).join("");
      const nonceRaw = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      // redirect_uri must match exactly what is registered in Azure App Registration
      const redirectUri = env.MICROSOFT_REDIRECT_URI
        || `${url.origin}/api/auth/microsoft/callback`;

      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min

      await env.cybermeters_db
        .prepare(
          `INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
           VALUES (?, 'microsoft', ?, ?)`
        )
        .bind(stateRaw, JSON.stringify({ redirect_uri: redirectUri, nonce: nonceRaw }), expiresAt)
        .run();

      // Purge expired states while we're here (best-effort, non-fatal)
      env.cybermeters_db
        .prepare("DELETE FROM oauth_states WHERE expires_at < datetime('now')")
        .run()
        .catch(() => {});

      const authorizeUrl = new URL(
        `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`
      );
      authorizeUrl.searchParams.set("client_id",     clientId);
      authorizeUrl.searchParams.set("response_type", "code");
      authorizeUrl.searchParams.set("redirect_uri",  redirectUri);
      authorizeUrl.searchParams.set("response_mode", "query");
      authorizeUrl.searchParams.set("scope",         "openid profile email");
      authorizeUrl.searchParams.set("state",         stateRaw);
      authorizeUrl.searchParams.set("nonce",         nonceRaw);

      return Response.redirect(authorizeUrl.toString(), 302);
    }

    // ── GET /api/auth/microsoft/callback ─────────────────────────────────
    // Handles the OAuth callback from Microsoft.
    //   1. Validates the CSRF state from oauth_states (single-use, TTL-checked)
    //   2. Exchanges the authorization code for tokens at Microsoft's token endpoint
    //   3. Validates the id_token JWT (signature + audience + expiry + oid)
    //   4. Finds an existing user by microsoft_oid, falls back to email match,
    //      or creates a new account
    //   5. Creates a 30-day session (same pattern as POST /api/auth/login)
    //   6. Fires USER_LOGIN_MICROSOFT audit event
    //   7. Redirects to the frontend callback page with token + user params
    //
    // Env vars required: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
    // Optional: FRONTEND_URL (defaults to same origin)
    if (request.method === "GET" && url.pathname === "/api/auth/microsoft/callback") {
      const clientId     = env.AZURE_CLIENT_ID;
      const clientSecret = env.AZURE_CLIENT_SECRET;
      const tenantId     = env.AZURE_TENANT_ID;

      if (!clientId || !clientSecret || !tenantId) {
        return json({ error: "Microsoft login is not configured on this instance" }, 503);
      }

      const code  = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const msErr = url.searchParams.get("error");

      // Microsoft returned an error (e.g. user denied consent)
      if (msErr) {
        const frontendUrl = env.FRONTEND_URL || url.origin;
        const dest = new URL("/login", frontendUrl);
        dest.searchParams.set("ms_error", "Microsoft sign-in was cancelled or failed. Please try again.");
        console.warn("[microsoft/callback] provider returned error", { code: msErr });
        return Response.redirect(dest.toString(), 302);
      }

      if (!code || !state) {
        return json({ error: "Missing code or state parameter" }, 400);
      }

      // ── 1. Validate CSRF state ─────────────────────────────────────────
      const stateRow = await env.cybermeters_db
        .prepare(
          `SELECT state, redirect_uri FROM oauth_states
           WHERE state = ? AND provider = 'microsoft'
             AND expires_at > datetime('now')
           LIMIT 1`
        )
        .bind(state)
        .first();

      if (!stateRow) {
        return json({ error: "Invalid or expired OAuth state. Please try signing in again." }, 400);
      }

      // Delete state immediately — single-use CSRF token
      await env.cybermeters_db
        .prepare("DELETE FROM oauth_states WHERE state = ?")
        .bind(state)
        .run();

      let statePayload = null;
      try { statePayload = JSON.parse(stateRow.redirect_uri); } catch { /* legacy state row */ }
      const redirectUri = statePayload?.redirect_uri
        || stateRow.redirect_uri
        || (env.MICROSOFT_REDIRECT_URI || `${url.origin}/api/auth/microsoft/callback`);
      const expectedNonce = statePayload?.nonce || null;

      // ── 2. Exchange authorization code for tokens ──────────────────────
      const tokenRes = await fetch(
        `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id:     clientId,
            client_secret: clientSecret,
            code,
            redirect_uri:  redirectUri,
            grant_type:    "authorization_code",
            scope:         "openid profile email",
          }).toString(),
        }
      );

      if (!tokenRes.ok) {
        console.error("[microsoft/callback] token exchange failed", { status: tokenRes.status });
        return json({ error: "Failed to exchange authorization code" }, 502);
      }

      const tokenData = await tokenRes.json();
      const idToken   = tokenData.id_token;

      if (!idToken) {
        return json({ error: "Microsoft did not return an id_token" }, 502);
      }

      // ── 3. Validate id_token JWT ───────────────────────────────────────
      let claims;
      try {
        claims = await validateMicrosoftIdToken(idToken, clientId, tenantId, expectedNonce);
      } catch (e) {
        console.error("[microsoft/callback] id_token validation failed:", e.message);
        return json({ error: "Microsoft sign-in could not be validated. Please try again." }, 401);
      }

      const msOid   = claims.oid;
      const msEmail = (claims.email || claims.preferred_username || "").toLowerCase().trim();
      const msName  = claims.name || msEmail.split("@")[0] || "Microsoft User";
      const msTid   = claims.tid;

      if (!msEmail) {
        return json({ error: "Microsoft account did not provide an email address. Ensure the email scope is granted." }, 400);
      }

      // ── 4. Find or create user ─────────────────────────────────────────
      // Priority: (a) match by microsoft_oid, (b) match by email, (c) create new
      let user = await env.cybermeters_db
        .prepare("SELECT id, email, name, plan, status FROM users WHERE microsoft_oid = ? LIMIT 1")
        .bind(msOid)
        .first();

      if (!user) {
        // Try to link to an existing email/password account
        user = await env.cybermeters_db
          .prepare("SELECT id, email, name, plan, status FROM users WHERE email = ? LIMIT 1")
          .bind(msEmail)
          .first();

        if (user) {
          // Link existing account to this Microsoft identity.
          // If the local account is unverified / pending, Microsoft OAuth implicitly
          // verifies the email (same address) and activates the account — the user
          // has just proven control of that inbox via their Microsoft identity provider.
          await env.cybermeters_db
            .prepare(
              `UPDATE users
               SET microsoft_oid    = ?,
                   tenant_id        = ?,
                   auth_provider    = 'microsoft',
                   last_login_at    = datetime('now'),
                   email_verified     = CASE WHEN email_verified = 0 THEN 1 ELSE email_verified END,
                   email_verified_at  = CASE WHEN email_verified = 0 THEN datetime('now') ELSE email_verified_at END,
                   status             = CASE WHEN status = 'pending_verification' THEN 'active' ELSE status END
               WHERE id = ?`
            )
            .bind(msOid, msTid, user.id)
            .run();
          // Refresh user object so status/email_verified reflect post-update state
          const refreshed = await env.cybermeters_db
            .prepare("SELECT id, email, name, plan, status FROM users WHERE id = ? LIMIT 1")
            .bind(user.id)
            .first()
            .catch(() => null);
          if (refreshed) user = refreshed;
        }
      }

      if (!user) {
        // No existing account — create one
        const newUserId    = createId("usr");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO users
               (id, email, name, plan, password_hash, status, auth_provider, microsoft_oid, tenant_id,
                email_verified, email_verified_at, created_at)
             VALUES (?, ?, ?, 'free', NULL, 'active', 'microsoft', ?, ?, 1, datetime('now'), datetime('now'))`
          )
          .bind(newUserId, msEmail, msName, msOid, msTid)
          .run();

        user = { id: newUserId, email: msEmail, name: msName, plan: "free", status: "active" };

        await createAuditEvent(env, {
          user_id:     newUserId,
          event_type:  "signup",
          entity_type: "user",
          entity_id:   newUserId,
          description: `New account created via Microsoft login for ${msEmail}`,
          metadata:    { email: msEmail, name: msName, auth_provider: "microsoft" },
        }).catch(() => {});
      } else {
        // Existing account — update last_login_at and auth fields
        await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET microsoft_oid = ?, tenant_id = ?, auth_provider = 'microsoft',
                 last_login_at = datetime('now')
             WHERE id = ?`
          )
          .bind(msOid, msTid, user.id)
          .run();
      }

      if (user.status === "suspended") {
        const frontendUrl = env.FRONTEND_URL || url.origin;
        const dest = new URL("/login", frontendUrl);
        dest.searchParams.set("ms_error", "Account suspended. Contact support.");
        return Response.redirect(dest.toString(), 302);
      }

      // ── 5. Create session ──────────────────────────────────────────────
      const { raw: token, hash: tokenHash } = await generateSessionToken();
      const sessionId = createId("sess");
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
      const loginIp   = request.headers.get("CF-Connecting-IP") || null;
      const loginUa   = request.headers.get("User-Agent") || null;

      await env.cybermeters_db
        .prepare(
          `INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(sessionId, user.id, tokenHash, expiresAt, loginIp, loginUa)
        .run();

      // ── 6. Audit ──────────────────────────────────────────────────────
      const plan = await getEffectivePlan(user.id, env);

      await createAuditEvent(env, {
        user_id:     user.id,
        event_type:  "USER_LOGIN_MICROSOFT",
        entity_type: "user",
        entity_id:   user.id,
        description: `${user.email} signed in via Microsoft`,
        metadata:    {
          ip_address:    loginIp,
          user_agent:    loginUa,
          microsoft_oid: msOid,
          tenant_id:     msTid,
        },
      }).catch(() => {});

      // ── 7. Issue a short-lived one-time code (OTC) and redirect ──────────
      // The bearer token and user metadata MUST NOT appear in URL parameters —
      // they would be captured by CDN access logs, browser history, and
      // Referrer headers. Instead we generate a 30-second single-use OTC,
      // store it in oauth_states (reusing the existing table with
      // provider = 'ms_exchange'), and redirect with only the OTC in the URL.
      // The frontend immediately POSTs the OTC to /api/auth/exchange, which
      // validates it, deletes it, and returns the session data in a JSON body.
      const otcRaw = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      const otcPayload = JSON.stringify({
        token,
        userId: user.id,
        email:  user.email,
        name:   user.name  || "",
        plan,
      });

      // Store expires_at using SQLite's own datetime() to guarantee format
      // consistency with the datetime('now') comparison in the lookup query.
      // ISO format (JavaScript's toISOString()) cannot be compared correctly
      // against datetime('now') — the 'T' separator makes ISO strings always
      // sort as greater than SQLite datetime strings on the same day.
      // TTL is 5 minutes: long enough for slow edge-cached Pages loads, short
      // enough to limit the replay window if an OTC is somehow observed.
      await env.cybermeters_db
        .prepare(
          `INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
           VALUES (?, 'ms_exchange', ?, datetime('now', '+5 minutes'))`
        )
        .bind(otcRaw, otcPayload)
        .run();

      const frontendUrl = env.FRONTEND_URL || url.origin;
      const dest = new URL("/auth/microsoft/callback", frontendUrl);
      dest.searchParams.set("otc", otcRaw);

      return Response.redirect(dest.toString(), 302);
    }

    // ── POST /api/auth/exchange ──────────────────────────────────────────
    // Exchanges a short-lived one-time code (OTC) issued by the Microsoft
    // OAuth callback for the session bearer token and user metadata.
    //
    // The OTC is stored server-side in oauth_states with provider='ms_exchange'
    // and a 30-second TTL. It is single-use: deleted on first successful exchange.
    // The bearer token is returned in the JSON body — it never appears in any URL.
    //
    // Request:  POST /api/auth/exchange
    //           Content-Type: application/json
    //           Body: { "code": "<otc>" }
    //
    // Response: { "token": "...", "id": "...", "email": "...", "name": "...", "plan": "..." }
    // Errors:   400 { "error": "Missing code" }
    //           401 { "error": "Invalid or expired code. Please sign in again." }
    //           500 { "error": "Exchange failed" }
    if (request.method === "POST" && url.pathname === "/api/auth/exchange") {
      let body;
      try { body = await request.json(); } catch {
        console.error("[auth/exchange] invalid JSON body");
        return json({ error: "Invalid JSON body" }, 400);
      }

      const otc = (body.code || "").trim();
      if (!otc) {
        console.error("[auth/exchange] missing code in request body");
        return json({ error: "Missing code" }, 400);
      }

      // Look up and immediately delete the OTC — single-use enforcement.
      const otcRow = await env.cybermeters_db
        .prepare(
          `SELECT redirect_uri AS payload FROM oauth_states
           WHERE state = ? AND provider = 'ms_exchange'
             AND expires_at > datetime('now')
           LIMIT 1`
        )
        .bind(otc)
        .first();

      if (!otcRow) {
        // Log the OTC prefix (first 8 chars) for correlation — never the full value
        console.error(`[auth/exchange] OTC not found or expired. prefix=${otc.slice(0,8)}`);
        return json({ error: "Invalid or expired code. Please sign in again." }, 401);
      }

      // Delete before responding — prevents replay even under concurrent requests.
      await env.cybermeters_db
        .prepare("DELETE FROM oauth_states WHERE state = ? AND provider = 'ms_exchange'")
        .bind(otc)
        .run();

      let payload;
      try {
        payload = JSON.parse(otcRow.payload);
      } catch (e) {
        console.error("[auth/exchange] payload JSON.parse failed:", e.message);
        return json({ error: "Exchange failed" }, 500);
      }

      if (!payload.token || !payload.userId || !payload.email) {
        console.error("[auth/exchange] payload missing required fields:", Object.keys(payload));
        return json({ error: "Exchange failed" }, 500);
      }

      console.log(`[auth/exchange] success for user ${payload.userId.slice(0,8)}...`);

      return json({
        token: payload.token,
        id:    payload.userId,
        email: payload.email,
        name:  payload.name,
        plan:  payload.plan,
      });
    }

    // ── POST /api/auth/forgot-password ──────────────────────────────────
    // Always returns 200 to prevent user enumeration.
    // Sends a reset link via Resend if the email is registered.
    if (request.method === "POST" && url.pathname === "/api/auth/forgot-password") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      if (!email) return json({ success: true }); // silent — no enumeration

      // Rate limit by source IP — 5 requests per 15-minute window.
      // Prevents email flooding and abuse of the email delivery system.
      // Fails open: if D1 is unavailable, the request proceeds normally.
      const _fpIp = request.headers.get("CF-Connecting-IP") ||
                    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                    "unknown";
      const _fpRl = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("forgot_password", _fpIp) }],
        "forgot_password",
        5,
        900, // 15 minutes
        // Abuse-critical: never allow unmetered reset-email generation.
        { failClosed: true },
      );
      if (_fpRl) return json({ error: "Too many password reset requests. Please wait before trying again.", code: "rate_limit_exceeded" }, _fpRl.status);

      try {
        const user = await env.cybermeters_db
          .prepare("SELECT id, email, name FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();

        if (user) {
          // Invalidate any existing unused tokens for this user (one active reset at a time)
          await env.cybermeters_db
            .prepare(
              `UPDATE password_reset_tokens
               SET used_at = datetime('now')
               WHERE user_id = ? AND used_at IS NULL AND expires_at > datetime('now')`
            )
            .bind(user.id)
            .run();

          const { raw: resetToken, hash: tokenHash } = await generatePasswordResetToken();
          const tokenId  = createId("prt");
          const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

          await env.cybermeters_db
            .prepare(
              `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
               VALUES (?, ?, ?, ?, datetime('now'))`
            )
            .bind(tokenId, user.id, tokenHash, expiresAt)
            .run();

          // Send email (non-fatal — token is in DB regardless)
          const appUrl   = getEmailFrontendOrigin(env) || "https://app.cybermeters.com";
          const resetUrl = `${appUrl}/reset-password?token=${resetToken}`;
          const name     = user.name || user.email;
          const nameHtml = escapeEmailHtml(name);
          const subject  = "Reset your CyberMeters password";
          const text =
            `Hi ${name},\n\n` +
            `You requested a password reset for your CyberMeters account.\n\n` +
            `Reset your password here (link expires in 1 hour):\n${resetUrl}\n\n` +
            `If you didn't request this, you can ignore this email — your password won't change.\n\n` +
            `— The CyberMeters team`;
          const html = `<!DOCTYPE html><html lang="en"><body style="font-family:Arial,sans-serif;color:#111;max-width:560px;margin:40px auto;padding:0 20px">` +
            `<div style="margin-bottom:24px"><span style="font-weight:700;font-size:18px;color:#0a7c5c">CyberMeters</span></div>` +
            `<h2 style="font-size:20px;margin-bottom:8px">Reset your password</h2>` +
            `<p style="color:#555;margin-bottom:24px">Hi ${nameHtml},<br><br>` +
            `You requested a password reset. Click the button below to set a new password.<br>` +
            `This link expires in <strong>1 hour</strong>.</p>` +
            `<a href="${resetUrl}" style="display:inline-block;background:#0a7c5c;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px">Reset password</a>` +
            `<p style="margin-top:32px;font-size:13px;color:#999">Or copy this URL into your browser:<br><span style="color:#0a7c5c">${resetUrl}</span></p>` +
            `<p style="margin-top:40px;font-size:12px;color:#bbb">If you didn't request this, ignore this email — your account is safe.</p>` +
            `</body></html>`;

          const resetDelivery = await sendCustomerEmail(subject, text, html, env, "HELLO_EMAIL_FROM", [user.email]);

          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "password_reset_requested",
            entity_type: "user",
            entity_id:   user.id,
            description: `Password reset requested for ${email}`,
            metadata:    {
              email,
              token_id: tokenId,
              delivery_status: resetDelivery.sent ? "accepted" : "failed",
              delivery_reason: resetDelivery.reason || null,
              provider_id: resetDelivery.provider_id || null,
            },
          }).catch(() => {});
        }

        // Always 200 — caller can't tell if account exists
        return json({ success: true, message: "If an account exists for this email, a reset link has been sent." });
      } catch (e) {
        return serverError("auth/forgot-password", e, "Password reset request failed. Please try again.");
      }
    }

    // ── POST /api/auth/reset-password ───────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/reset-password") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const rawToken   = (body.token    || "").trim();
      const newPassword = (body.password || "").trim();

      if (!rawToken)                    return json({ error: "token is required" }, 400);
      if (!newPassword)                 return json({ error: "Password cannot be blank" }, 400);
      if (newPassword.length < 12)      return json({ error: "Password must be at least 12 characters" }, 400);
      if (newPassword.length > 128)     return json({ error: "Password is too long" }, 400);

      try {
        const tokenHash = await hashToken(rawToken);
        const tokenRow  = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, expires_at, used_at
             FROM password_reset_tokens
             WHERE token_hash = ? LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!tokenRow) {
          createAuditEvent(env, {
            event_type:  "password_reset_failed",
            entity_type: "user",
            description: "Password reset attempt with invalid token",
            metadata:    { reason: "invalid" },
          }).catch(() => {});
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }
        if (tokenRow.used_at) {
          createAuditEvent(env, {
            user_id:     tokenRow.user_id,
            event_type:  "password_reset_failed",
            entity_type: "user",
            entity_id:   tokenRow.user_id,
            description: "Password reset attempt with already-used token",
            metadata:    { reason: "used", token_id: tokenRow.id },
          }).catch(() => {});
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }
        if (new Date(tokenRow.expires_at) <= new Date()) {
          createAuditEvent(env, {
            user_id:     tokenRow.user_id,
            event_type:  "password_reset_failed",
            entity_type: "user",
            entity_id:   tokenRow.user_id,
            description: "Password reset attempt with expired token",
            metadata:    { reason: "expired", token_id: tokenRow.id },
          }).catch(() => {});
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }

        const user = await env.cybermeters_db
          .prepare("SELECT id, email FROM users WHERE id = ? LIMIT 1")
          .bind(tokenRow.user_id)
          .first();
        if (!user) return json({ error: "Account not found" }, 404);

        const newHash = await hashPassword(newPassword);

        // Update password + mark token used in a batch
        await env.cybermeters_db.batch([
          env.cybermeters_db
            .prepare("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(newHash, user.id),
          env.cybermeters_db
            .prepare("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?")
            .bind(tokenRow.id),
          // Invalidate all existing sessions — security best practice after password change
          env.cybermeters_db
            .prepare("DELETE FROM user_sessions WHERE user_id = ?")
            .bind(user.id),
        ]);

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "password_reset_completed",
          entity_type: "user",
          entity_id:   user.id,
          description: `Password reset completed for ${user.email}`,
          metadata:    { email: user.email, token_id: tokenRow.id },
        }).catch(() => {});

        // Security notification — the password just changed and every session
        // was revoked. Sent on every reset (no dedupe: each change matters).
        // The reset itself must succeed even if this email cannot be sent.
        try {
          const origin = getEmailFrontendOrigin(env);
          const resetPath = origin ? `${origin}/forgot-password` : null;
          const text = "Your CyberMeters password was changed\n\n"
            + "Your account password was just changed and all active sessions were signed out.\n\n"
            + "If you made this change, no further action is needed.\n\n"
            + `If you did not make this change, reset your password immediately${resetPath ? ` at ${resetPath}` : ""} and contact CyberMeters support.\n\nCyberMeters`;
          const html = "<p>Your CyberMeters account password was just changed and all active sessions were signed out.</p>"
            + "<p>If you made this change, no further action is needed.</p>"
            + `<p>If you did not make this change, ${resetPath ? `<a href="${resetPath}">reset your password</a>` : "reset your password"} immediately and contact CyberMeters support.</p>`
            + "<p>CyberMeters</p>";
          await sendCustomerEmail("Your CyberMeters password was changed", text, html, env, "ALERT_EMAIL_FROM", [user.email]);
        } catch {
          // Never block a successful reset on email delivery
        }

        return json({ success: true, message: "Password updated. Please sign in with your new password." });
      } catch (e) {
        return serverError("auth/reset-password", e, "Password reset failed. Please try again.");
      }
    }

    // ── GET /api/auth/mfa/status ─────────────────────────────────────────
    // Returns current MFA state for the authenticated user.
    if (request.method === "GET" && url.pathname === "/api/auth/mfa/status") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT mfa_enabled, mfa_enabled_at FROM users WHERE id = ? LIMIT 1")
          .bind(user.id)
          .first();
        return json({
          mfa_enabled:    row?.mfa_enabled === 1 || row?.mfa_enabled === true,
          mfa_enabled_at: row?.mfa_enabled_at ?? null,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/setup ─────────────────────────────────────────
    // Generates a new TOTP secret for the user and returns the otpauth URI.
    // Does NOT enable MFA yet — caller must verify a valid code first via
    // POST /api/auth/mfa/verify-setup.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/setup") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      try {
        // Generate secret and encrypt before storing
        const base32Secret  = generateTotpSecret();
        const encryptedSecret = await encryptTotpSecret(base32Secret, env);

        // Store the secret (not yet enabled — pending verify-setup)
        await env.cybermeters_db
          .prepare("UPDATE users SET totp_secret = ? WHERE id = ?")
          .bind(encryptedSecret, user.id)
          .run();

        const issuer    = "CyberMeters";
        const label     = encodeURIComponent(`${issuer}:${user.email}`);
        const otpauthUri = `otpauth://totp/${label}?secret=${base32Secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "mfa_setup_started",
          entity_type: "user",
          entity_id:   user.id,
          description: `MFA setup started for ${user.email}`,
          // Never log the secret
        }).catch(() => {});

        return json({ otpauth_uri: otpauthUri, secret_base32: base32Secret });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/verify-setup ─────────────────────────────────
    // Verifies the first TOTP code after setup, then enables MFA and
    // returns one-time recovery codes.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/verify-setup") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const code = (body.code || "").trim();
      if (!code) return json({ error: "code is required" }, 400);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT totp_secret, mfa_enabled FROM users WHERE id = ? LIMIT 1")
          .bind(user.id)
          .first();

        if (!row?.totp_secret) return json({ error: "MFA setup not started. Call /api/auth/mfa/setup first." }, 400);
        if (row.mfa_enabled)   return json({ error: "MFA is already enabled" }, 409);

        const base32Secret = await decryptTotpSecret(row.totp_secret, env);
        const valid = await verifyTotp(base32Secret, code);
        if (!valid) {
          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "mfa_setup_failed",
            entity_type: "user",
            entity_id:   user.id,
            description: `Invalid TOTP code during MFA setup for ${user.email}`,
          }).catch(() => {});
          return json({ error: "Invalid or expired verification code" }, 400);
        }

        // Generate recovery codes
        const { codes: rawCodes, hashes } = await generateRecoveryCodes();

        await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET mfa_enabled = 1,
                 mfa_enabled_at = datetime('now'),
                 mfa_last_verified_at = datetime('now'),
                 mfa_recovery_codes_hash_json = ?
             WHERE id = ?`
          )
          .bind(JSON.stringify(hashes), user.id)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "mfa_enabled",
          entity_type: "user",
          entity_id:   user.id,
          description: `MFA enabled for ${user.email}`,
        }).catch(() => {});

        // Recovery codes are returned once — never stored in plaintext
        return json({ success: true, recovery_codes: rawCodes });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/challenge ─────────────────────────────────────
    // Second factor of login. Accepts the challenge_token (from POST /api/auth/login
    // when mfa_required: true) and a 6-digit TOTP code.
    // On success: marks challenge used, creates session, returns token + user.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/challenge") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const rawChallenge = (body.challenge_token || "").trim();
      const code         = (body.code || "").trim();
      if (!rawChallenge) return json({ error: "challenge_token is required" }, 400);
      if (!code)         return json({ error: "code is required" }, 400);
      try {
        const challengeHash = await hashToken(rawChallenge);
        const challenge = await env.cybermeters_db
          .prepare(
            `SELECT c.id, c.user_id, c.expires_at, c.used_at,
                    u.id AS uid, u.email, u.name, u.plan, u.status,
                    u.totp_secret, u.mfa_enabled
             FROM mfa_challenges c
             JOIN users u ON u.id = c.user_id
             WHERE c.challenge_hash = ? LIMIT 1`
          )
          .bind(challengeHash)
          .first();

        if (!challenge)                                   return json({ error: "Invalid or expired challenge token" }, 401);
        if (challenge.used_at)                            return json({ error: "Challenge token already used" }, 401);
        if (new Date(challenge.expires_at) <= new Date()) return json({ error: "Challenge token expired. Please sign in again." }, 401);
        if (challenge.status === "suspended")             return json({ error: "Account suspended. Contact support." }, 403);
        if (!challenge.mfa_enabled)                       return json({ error: "MFA is not enabled for this account" }, 400);

        const _mfaIp = request.headers.get("CF-Connecting-IP") || null;
        const _mfaUa = request.headers.get("User-Agent") || null;
        const base32Secret = await decryptTotpSecret(challenge.totp_secret, env);
        const valid = await verifyTotp(base32Secret, code);

        // Mark challenge used regardless of outcome (prevent retry attacks)
        await env.cybermeters_db
          .prepare("UPDATE mfa_challenges SET used_at = datetime('now') WHERE id = ?")
          .bind(challenge.id)
          .run();

        if (!valid) {
          await createAuditEvent(env, {
            user_id:     challenge.user_id,
            event_type:  "mfa_challenge_failed",
            entity_type: "user",
            entity_id:   challenge.user_id,
            description: `Failed MFA challenge for ${challenge.email}`,
            metadata:    { challenge_id: challenge.id, ip_address: _mfaIp, user_agent: _mfaUa },
          }).catch(() => {});
          return json({ error: "Invalid verification code" }, 401);
        }

        // TOTP verified — create session
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId = createId("sess");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db.batch([
          env.cybermeters_db
            .prepare(`INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)`)
            .bind(sessionId, challenge.user_id, tokenHash, expiresAt, _mfaIp, _mfaUa),
          env.cybermeters_db
            .prepare("UPDATE users SET last_login_at = datetime('now'), mfa_last_verified_at = datetime('now') WHERE id = ?")
            .bind(challenge.user_id),
        ]);

        await createAuditEvent(env, {
          user_id:     challenge.user_id,
          event_type:  "mfa_challenge_success",
          entity_type: "user",
          entity_id:   challenge.user_id,
          description: `MFA challenge passed — session created for ${challenge.email}`,
          metadata:    { challenge_id: challenge.id, ip_address: _mfaIp, user_agent: _mfaUa },
        }).catch(() => {});

        const plan = await getEffectivePlan(challenge.user_id, env);
        return json({
          token,
          user: {
            id:    challenge.uid,
            email: challenge.email,
            name:  challenge.name,
            plan,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/recovery-code ────────────────────────────────
    // Recovery path: use a backup recovery code instead of TOTP.
    // Each code is single-use — verified hash is removed from the stored array.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/recovery-code") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const rawChallenge   = (body.challenge_token  || "").trim();
      const submittedCode  = (body.recovery_code    || "").trim();
      if (!rawChallenge)  return json({ error: "challenge_token is required" }, 400);
      if (!submittedCode) return json({ error: "recovery_code is required" }, 400);
      try {
        const challengeHash = await hashToken(rawChallenge);
        const challenge = await env.cybermeters_db
          .prepare(
            `SELECT c.id, c.user_id, c.expires_at, c.used_at,
                    u.id AS uid, u.email, u.name, u.plan, u.status,
                    u.mfa_enabled, u.mfa_recovery_codes_hash_json
             FROM mfa_challenges c
             JOIN users u ON u.id = c.user_id
             WHERE c.challenge_hash = ? LIMIT 1`
          )
          .bind(challengeHash)
          .first();

        if (!challenge)                                   return json({ error: "Invalid or expired challenge token" }, 401);
        if (challenge.used_at)                            return json({ error: "Challenge token already used" }, 401);
        if (new Date(challenge.expires_at) <= new Date()) return json({ error: "Challenge token expired. Please sign in again." }, 401);
        if (challenge.status === "suspended")             return json({ error: "Account suspended. Contact support." }, 403);
        if (!challenge.mfa_enabled)                       return json({ error: "MFA is not enabled for this account" }, 400);

        const { valid, remainingHashes } = await verifyRecoveryCode(submittedCode, challenge.mfa_recovery_codes_hash_json);

        // Mark challenge used regardless of outcome
        await env.cybermeters_db
          .prepare("UPDATE mfa_challenges SET used_at = datetime('now') WHERE id = ?")
          .bind(challenge.id)
          .run();

        if (!valid) {
          await createAuditEvent(env, {
            user_id:     challenge.user_id,
            event_type:  "mfa_challenge_failed",
            entity_type: "user",
            entity_id:   challenge.user_id,
            description: `Invalid recovery code used for ${challenge.email}`,
            metadata:    { challenge_id: challenge.id, method: "recovery_code" },
          }).catch(() => {});
          return json({ error: "Invalid recovery code" }, 401);
        }

        // Consume the used code — update stored hashes
        await env.cybermeters_db
          .prepare("UPDATE users SET mfa_recovery_codes_hash_json = ?, last_login_at = datetime('now'), mfa_last_verified_at = datetime('now') WHERE id = ?")
          .bind(JSON.stringify(remainingHashes), challenge.user_id)
          .run();

        // Create session
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId = createId("sess");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
        const _rcIp = request.headers.get("CF-Connecting-IP") || null;
        const _rcUa = request.headers.get("User-Agent") || null;
        await env.cybermeters_db
          .prepare(`INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)`)
          .bind(sessionId, challenge.user_id, tokenHash, expiresAt, _rcIp, _rcUa)
          .run();

        await createAuditEvent(env, {
          user_id:     challenge.user_id,
          event_type:  "recovery_code_used",
          entity_type: "user",
          entity_id:   challenge.user_id,
          description: `Recovery code used to sign in — ${remainingHashes.length} codes remaining for ${challenge.email}`,
          metadata:    { challenge_id: challenge.id, remaining_codes: remainingHashes.length, ip_address: _rcIp, user_agent: _rcUa },
        }).catch(() => {});

        const plan = await getEffectivePlan(challenge.user_id, env);
        return json({
          token,
          user:    { id: challenge.uid, email: challenge.email, name: challenge.name, plan },
          warning: remainingHashes.length <= 2
            ? `Only ${remainingHashes.length} recovery code(s) remaining. Disable and re-enable MFA to generate new codes.`
            : null,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/disable ───────────────────────────────────────
    // Disables MFA for the authenticated user.
    // Requires the current TOTP code OR current password for verification.
    // Note: does NOT disable on password reset (per sprint spec — MFA survives reset).
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/disable") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const code     = (body.code     || "").trim();  // TOTP code
      const password = (body.password || "").trim();  // alternative: current password
      if (!code && !password) return json({ error: "Either a TOTP code or current password is required" }, 400);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT totp_secret, mfa_enabled, password_hash FROM users WHERE id = ? LIMIT 1")
          .bind(user.id)
          .first();

        if (!row?.mfa_enabled) return json({ error: "MFA is not currently enabled" }, 400);

        let verified = false;
        if (code) {
          const base32Secret = await decryptTotpSecret(row.totp_secret, env);
          verified = await verifyTotp(base32Secret, code);
        } else if (password) {
          verified = await verifyPassword(password, row.password_hash);
        }

        if (!verified) {
          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "mfa_disable_failed",
            entity_type: "user",
            entity_id:   user.id,
            description: `Failed attempt to disable MFA for ${user.email}`,
          }).catch(() => {});
          return json({ error: "Verification failed. Provide a valid TOTP code or current password." }, 403);
        }

        // Clear all MFA fields
        await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET mfa_enabled = 0,
                 mfa_enabled_at = NULL,
                 totp_secret = NULL,
                 mfa_recovery_codes_hash_json = NULL,
                 mfa_last_verified_at = NULL
             WHERE id = ?`
          )
          .bind(user.id)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "mfa_disabled",
          entity_type: "user",
          entity_id:   user.id,
          description: `MFA disabled for ${user.email}`,
          metadata:    { method: code ? "totp_code" : "password" },
        }).catch(() => {});

        return json({ success: true, message: "MFA has been disabled." });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/billing/checkout ──────────────────────────────────────
    // Stripe Checkout Flow v1. Creates a Stripe-hosted Checkout Session via
    // fetch. D1 subscription activation is intentionally deferred to webhooks.
    if (request.method === "POST" && url.pathname === "/api/billing/checkout") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Checkout is an account-control browser flow, not an automation API.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const parsedPlan = parseCheckoutPlan(body.plan);
      if (!parsedPlan.ok) {
        return json({
          error: "invalid_plan",
          message: "plan must be one of: starter, professional, business.",
        }, 400);
      }

      const requestedPlan = parsedPlan.plan;
      const interval = normalizeBillingInterval(body.interval);
      const metadata = BILLING_PLAN_METADATA[requestedPlan];

      if (!metadata?.checkout_enabled) {
        return json({
          error: "plan_not_checkout_eligible",
          plan: requestedPlan,
          message: "This plan is not available through self-service checkout.",
        }, 400);
      }

      const priceResolution = getStripePriceIdForPlan(env, requestedPlan, interval);
      if (!priceResolution.ok) {
        return json({
          error: priceResolution.error,
          ...(priceResolution.missing?.length ? { missing: priceResolution.missing } : {}),
          message: "Stripe billing configuration is not ready for checkout.",
        }, 503);
      }

      let subscription = null;
      try {
        subscription = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id, stripe_subscription_id, stripe_price_id,
                    billing_interval, cancel_at_period_end, current_period_end
             FROM subscriptions
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();
      } catch (e) {
        return serverError("billing/checkout-subscription", e, "Unable to load billing information.");
      }

      // Validate redirect URLs
      const successUrl = validateFrontendRedirectUrl(body.success_url, env);
      const cancelUrl  = validateFrontendRedirectUrl(body.cancel_url, env);
      if (!successUrl) {
        return json({ error: "invalid_success_url", message: "success_url must use the configured CyberMeters frontend origin." }, 400);
      }
      if (!cancelUrl) {
        return json({ error: "invalid_cancel_url", message: "cancel_url must use the configured CyberMeters frontend origin." }, 400);
      }

      // Build Stripe Checkout Session params (Stripe accepts x-www-form-urlencoded only)
      const params = new URLSearchParams();
      params.set("mode",                    "subscription");
      params.set("line_items[0][price]",    priceResolution.price_id);
      params.set("line_items[0][quantity]", "1");
      params.set("success_url",             successUrl);
      params.set("cancel_url",              cancelUrl);
      params.set("metadata[user_id]",       String(user.id));
      params.set("metadata[plan]",          requestedPlan);
      params.set("metadata[interval]",      interval);
      params.set("subscription_data[metadata][user_id]",  String(user.id));
      params.set("subscription_data[metadata][plan]",     requestedPlan);
      params.set("subscription_data[metadata][interval]", interval);
      params.set("allow_promotion_codes", "true");

      // Prefer an existing Stripe customer record; fall back to customer_email
      // so Stripe auto-creates a Customer on checkout completion.
      if (subscription?.stripe_customer_id) {
        params.set("customer", subscription.stripe_customer_id);
      } else {
        params.set("customer_email", user.email);
      }

      // Call Stripe Checkout Sessions API via fetch (no SDK — Cloudflare Workers compatible)
      let stripeSession;
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/checkout/sessions", {
          method:  "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });

        const stripeData = await stripeRes.json();

        if (!stripeRes.ok) {
          console.error("[billing/checkout] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return json({
            error:             "stripe_api_error",
            message:           "Stripe Checkout Session creation failed. Please try again.",
          }, 502);
        }

        stripeSession = stripeData;
      } catch (e) {
        console.error(`[billing/checkout] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      // D1 is intentionally NOT updated here.
      // Plan activation and subscriptions sync happen in the webhook handler
      // when Stripe fires checkout.session.completed.
      await createAuditEvent(env, {
        user_id:     user.id,
        event_type:  "billing_checkout_session_created",
        entity_type: "stripe_checkout_session",
        entity_id:   stripeSession.id,
        description: `Stripe checkout session created for ${requestedPlan} (${interval})`,
        metadata:    { plan: requestedPlan, interval, stripe_session_id: stripeSession.id },
      });
      return json({
        checkout_url: stripeSession.url,
        session_id:   stripeSession.id,
      }, 200);
    }

    // ── POST /api/billing/portal ────────────────────────────────────────
    // Creates a Stripe-hosted Billing Portal Session for the authenticated
    // user's existing Stripe customer. This is read-only for D1; Stripe
    // lifecycle changes still flow back through webhooks.
    if (request.method === "POST" && url.pathname === "/api/billing/portal") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Billing portal grants account-level Stripe access; require a user session.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const returnUrl = validateFrontendRedirectUrl(body.return_url, env);
      if (!returnUrl) {
        return json({
          error: "invalid_return_url",
          message: "return_url must use the configured CyberMeters frontend origin.",
        }, 400);
      }

      const stripeConfig = validateStripeSecretConfig(env);
      if (!stripeConfig.ok) {
        return json({
          error: stripeConfig.error,
          missing: stripeConfig.missing,
          message: "Stripe billing configuration is not ready for Customer Portal.",
        }, 503);
      }

      let subscription = null;
      try {
        subscription = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(user.id)
          .first();
      } catch (e) {
        return serverError("billing/portal-subscription", e, "Unable to load billing information.");
      }

      if (!subscription) {
        return json({ error: "subscription_not_found" }, 404);
      }
      if (!subscription.stripe_customer_id) {
        return json({ error: "stripe_customer_missing" }, 409);
      }

      const params = new URLSearchParams();
      params.set("customer", subscription.stripe_customer_id);
      params.set("return_url", returnUrl);

      let portalSession;
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });

        const stripeData = await stripeRes.json();
        if (!stripeRes.ok) {
          console.error("[billing/portal] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return json({
            error:             "stripe_api_error",
            message:           "Stripe Billing Portal Session creation failed. Please try again.",
          }, 502);
        }

        portalSession = stripeData;
      } catch (e) {
        console.error(`[billing/portal] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      await createAuditEvent(env, {
        user_id:     user.id,
        event_type:  "billing_portal_opened",
        entity_type: "stripe_billing_portal_session",
        entity_id:   portalSession.id,
        description: "Stripe billing portal session created",
        metadata:    { subscription_id: subscription.id, stripe_session_id: portalSession.id },
      });
      return json({
        portal_url: portalSession.url,
        session_id:  portalSession.id,
      }, 200);
	    }
	
	    // ── GET /api/account/onboarding-state ───────────────────────────────
	    // Lightweight first-workspace/first-scan state for session users.
	    // Returns counts and booleans only; no workspace IDs are exposed.
	    if (request.method === "GET" && url.pathname === "/api/account/onboarding-state") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

	      try {
	        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
		        const workspaceCount = workspaceIds.length;
		        let domainCount = 0;
		        let completedScanCount = 0;
		        let reviewedResultsCount = 0;

	        if (workspaceCount > 0) {
	          const wsPlaceholders = workspaceIds.map(() => "?").join(",");
	          const domainRow = await env.cybermeters_db
	            .prepare(
	              `SELECT COUNT(DISTINCT domain_id) AS count
	               FROM workspace_domains
	               WHERE workspace_id IN (${wsPlaceholders})`
	            )
	            .bind(...workspaceIds)
	            .first();
	          domainCount = Number(domainRow?.count ?? 0);

	          const scanRow = await env.cybermeters_db
	            .prepare(
	              `SELECT COUNT(DISTINCT s.id) AS count
	               FROM scans s
	               LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
	               WHERE s.status = 'completed'
	                 AND (
	                   s.workspace_id IN (${wsPlaceholders})
	                   OR (s.workspace_id IS NULL AND wd.workspace_id IN (${wsPlaceholders}))
	                 )`
	            )
	            .bind(...workspaceIds, ...workspaceIds)
		            .first();
		          completedScanCount = Number(scanRow?.count ?? 0);

		          const reportRow = await env.cybermeters_db
		            .prepare(
		              `SELECT COUNT(*) AS count
		               FROM workspace_reports
		               WHERE workspace_id IN (${wsPlaceholders})
		                 AND status = 'completed'`
		            )
		            .bind(...workspaceIds)
		            .first();
		          reviewedResultsCount = Number(reportRow?.count ?? 0);
		        }

	        const hasWorkspaces = workspaceCount > 0;
	        const hasDomains = domainCount > 0;
	        const hasCompletedScan = completedScanCount > 0;
		        const hasReviewedResults = reviewedResultsCount > 0;
	        const nextStep =
	          !hasWorkspaces ? "create_workspace" :
	          !hasDomains ? "add_domain" :
	          !hasCompletedScan ? "run_first_scan" :
	          !hasReviewedResults ? "review_results" : "complete";

	        createAuditEvent(env, {
	          user_id:     user.id,
	          event_type:  "onboarding_state_viewed",
	          entity_type: "user",
	          entity_id:   user.id,
	          description: "User viewed onboarding state",
	          metadata:    {
	            workspace_count: workspaceCount,
	            domain_count: domainCount,
	            completed_scan_count: completedScanCount,
	            next_step: nextStep,
	          },
	        }).catch(() => {});

	        return json({
	          has_workspaces: hasWorkspaces,
	          workspace_count: workspaceCount,
	          has_domains: hasDomains,
	          domain_count: domainCount,
	          has_completed_scan: hasCompletedScan,
	          completed_scan_count: completedScanCount,
	          next_step: nextStep,
	          progress: {
	            create_workspace: hasWorkspaces,
	            add_domain: hasDomains,
	            run_scan: hasCompletedScan,
	            review_results: hasReviewedResults,
	          },
	        });
	      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── POST /api/account/bootstrap ──────────────────────────────────────
	    // Idempotent workspace bootstrap for new users.
	    //
	    // Called by the frontend after login when the user has no workspaces:
	    //   - If the user already has at least one workspace → returns it (no-op).
	    //   - If the user has no workspaces → auto-creates one named from their
	    //     email domain or display name and seeds the owner membership row.
	    //
	    // This gives every beta user a working workspace without requiring a manual
	    // "Create Workspace" step before they can do anything useful.
	    //
	    // Security:
	    //   - Session auth only (no API tokens).
	    //   - Still respects plan limits: free users get 1 workspace, which this
	    //     creates — so bootstrap is always within entitlement for new accounts.
	    if (request.method === "POST" && url.pathname === "/api/account/bootstrap") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

	      try {
	        // Check for existing workspaces the user owns or is a member of.
	        const existingIds = await getAccessibleWorkspaceIds(user, env);
	        if (existingIds.length > 0) {
	          // Already has workspaces — return the first one (no-op).
	          const placeholders = existingIds.map(() => "?").join(",");
	          const first = await env.cybermeters_db
	            .prepare(
	              `SELECT id, name, created_at FROM workspaces
	               WHERE id IN (${placeholders})
	               ORDER BY created_at ASC LIMIT 1`
	            )
	            .bind(...existingIds)
	            .first();
	          return json({ workspace: first, created: false });
	        }

	        // No workspaces — derive a friendly default name.
	        // Use display name if set, otherwise use the email domain capitalised.
	        let bootstrapName = "My Workspace";
	        if (user.name && user.name.trim().length > 0) {
	          bootstrapName = `${user.name.trim()}'s Workspace`;
	        } else if (user.email) {
	          const domain = user.email.split("@")[1] ?? "";
	          const brand  = domain.split(".")[0] ?? "";
	          if (brand.length > 0) {
	            bootstrapName = brand.charAt(0).toUpperCase() + brand.slice(1).toLowerCase() + " Workspace";
	          }
	        }

	        const bsId        = `workspace_${crypto.randomUUID()}`;
	        const bsCreatedAt = new Date().toISOString();

	        await env.cybermeters_db
	          .prepare(`INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)`)
	          .bind(bsId, bootstrapName, user.id, bsCreatedAt)
	          .run();

	        await env.cybermeters_db
	          .prepare(
	            `INSERT OR IGNORE INTO workspace_members (id, workspace_id, user_id, role, created_at)
	             VALUES (?, ?, ?, 'owner', datetime('now'))`
	          )
	          .bind(createId("wm"), bsId, user.id)
	          .run();

	        await createAuditEvent(env, {
	          workspace_id: bsId,
	          user_id:      user.id,
	          event_type:   "workspace_bootstrapped",
	          entity_type:  "workspace",
	          entity_id:    bsId,
	          description:  `Default workspace "${bootstrapName}" auto-created for ${user.email}`,
	          metadata:     { workspace_name: bootstrapName, bootstrap: true },
	        }).catch(() => {});

	        return json({ workspace: { id: bsId, name: bootstrapName, created_at: bsCreatedAt }, created: true }, 201);
	      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── GET /api/account/profile ─────────────────────────────────────────
	    // Returns the authenticated account, company profile, and subscription foundation.
	    if (request.method === "GET" && url.pathname === "/api/account/profile") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const [profile, sub] = await Promise.all([
          env.cybermeters_db
            .prepare(
              `SELECT id, company_name, website, industry, company_size,
                      contact_email, contact_name, created_at, updated_at
               FROM customer_profiles
               WHERE owner_user_id = ?`
            )
            .bind(user.id)
            .first(),
          env.cybermeters_db
            .prepare(
              `SELECT id, plan, subscription_status AS status,
                      'stripe' AS billing_provider,
                      NULL AS billing_email, NULL AS trial_ends_at,
                      current_period_end, created_at, updated_at
               FROM subscriptions
               WHERE owner_user_id = ?
               ORDER BY COALESCE(updated_at, created_at) DESC
               LIMIT 1`
            )
            .bind(user.id)
            .first(),
        ]);
        const plan = await getEffectivePlan(user.id, env);
        return json({
          user: {
            id:    user.id,
            email: user.email,
            name:  user.name,
            plan,
          },
          company: profile ?? null,
          subscription: sub ? { ...sub, plan } : {
            plan,
            status:           "active",
            billing_provider: "manual",
            billing_email:    user.email,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PATCH /api/account/profile ───────────────────────────────────────
    // Updates account profile fields only. Email remains read-only in v1.
    if (request.method === "PATCH" && url.pathname === "/api/account/profile") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Profile mutation is an account-control action; API tokens are data-plane only.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return json({ error: "name is required" }, 400);
      if (name.length > 120) return json({ error: "name is too long" }, 400);

      try {
        await env.cybermeters_db
          .prepare("UPDATE users SET name = ? WHERE id = ?")
          .bind(name, user.id)
          .run();

        const plan = await getEffectivePlan(user.id, env);
        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "account_profile_updated",
          entity_type: "user",
          entity_id:   user.id,
          description: "Account profile updated",
          metadata:    { changed_fields: ["name"] },
        });
        return json({
          user: {
            id:    user.id,
            email: user.email,
            name,
            plan,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/company ─────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/company") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const company = await env.cybermeters_db
          .prepare(
            `SELECT id, company_name, website, industry, company_size,
                    contact_email, contact_name, created_at, updated_at
             FROM customer_profiles
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();
        return json({ company: company ?? null });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PUT /api/account/company ─────────────────────────────────────────
    if (request.method === "PUT" && url.pathname === "/api/account/company") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Company profile mutation is an account-control action; require a session.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const company_name  = (body.company_name  || "").trim();
      const website       = (body.website       || "").trim() || null;
      const industry      = (body.industry      || "").trim() || null;
      const company_size  = (body.company_size  || "").trim() || null;
      const contact_name  = (body.contact_name  || "").trim() || null;
      const contact_email = (body.contact_email || "").trim().toLowerCase() || null;

      if (!company_name) return json({ error: "company_name is required" }, 400);
      if (company_name.length > 200) return json({ error: "company_name is too long" }, 400);
      if (website && website.length > 300) return json({ error: "website is too long" }, 400);
      if (contact_email && !isValidEmail(contact_email)) {
        return json({ error: "contact_email must be a valid email address" }, 400);
      }

      const VALID_SIZES = ["1-10", "11-50", "51-200", "201-1000", "1000+"];
      if (company_size && !VALID_SIZES.includes(company_size)) {
        return json({ error: `company_size must be one of: ${VALID_SIZES.join(", ")}` }, 400);
      }

      try {
        const companyId = createId("cust");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO customer_profiles
               (id, owner_user_id, company_name, website, industry, company_size,
                contact_email, contact_name, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
             ON CONFLICT(owner_user_id) DO UPDATE SET
               company_name  = excluded.company_name,
               website       = excluded.website,
               industry      = excluded.industry,
               company_size  = excluded.company_size,
               contact_email = excluded.contact_email,
               contact_name  = excluded.contact_name,
               updated_at    = datetime('now')`
          )
          .bind(companyId, user.id, company_name, website, industry, company_size, contact_email, contact_name)
          .run();

        const company = await env.cybermeters_db
          .prepare(
            `SELECT id, company_name, website, industry, company_size,
                    contact_email, contact_name, created_at, updated_at
             FROM customer_profiles
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "company_profile_updated",
          entity_type: "customer_profile",
          entity_id:   company?.id ?? companyId,
          description: "Company profile updated",
          metadata:    {
            changed_fields: ["company_name", "website", "industry", "company_size", "contact_email", "contact_name"],
          },
        });
        return json({ company });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/subscription ────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/subscription") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const sub = await env.cybermeters_db
          .prepare(
            `SELECT id, plan, subscription_status AS status,
                    billing_interval AS billing_cycle,
                    'stripe' AS billing_provider,
                    NULL AS billing_email, NULL AS trial_ends_at,
                    current_period_end, created_at, updated_at
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(user.id)
          .first();

        const plan = await getEffectivePlan(user.id, env);
        return json({
          subscription: sub ? { ...sub, plan, billing_cycle: normalizeBillingInterval(sub.billing_cycle) } : {
            plan,
            status:             "active",
            billing_cycle:      "monthly",
            billing_provider:   "manual",
            billing_email:      user.email,
            trial_ends_at:      null,
            current_period_end: null,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/subscription/features ──────────────────────────
    // Read-only feature entitlement metadata. This exposes the static
    // PLAN_FEATURES result for the effective plan; it does not gate features.
    if (request.method === "GET" && url.pathname === "/api/account/subscription/features") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const plan = await getEffectivePlan(user.id, env);
        return json({
          plan,
          features: getPlanFeatures(plan),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/usage ───────────────────────────────────────────
    // Returns: { plan, limits, usage, percentages, upgrade_signals }
    // percentages: per-resource % of plan limit used (omitted for unlimited).
    // upgrade_signals: ordered list of resources at ≥80% capacity.
    if (request.method === "GET" && url.pathname === "/api/account/usage") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const context = await getPlanContext(user, env);
        const percentages = {};
        for (const [key, used] of Object.entries(context.usage)) {
          const limit = context.limits[key];
          if (limit && limit < 999999 && typeof used === "number") {
            percentages[key] = Math.round((used / limit) * 100);
          }
        }
        const upgrade_signals = getUpgradeRecommendation(context.limits, context.usage);
        return json({ ...context, percentages, upgrade_signals });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/subscription/limits ─────────────────────────────
    // Backward-compatible alias for existing v1 screens.
    if (request.method === "GET" && url.pathname === "/api/account/subscription/limits") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const context = await getPlanContext(user, env);
        const entitlementUsage = await getEntitlementUsage(user, env);
        return json({
          plan: context.plan,
          limits: context.limits,
          usage: {
            ...context.usage,
            api_tokens: entitlementUsage.api_tokens,
            // These fields reflect plan limits (maximums), not usage counts.
            // Formerly misnamed: max_domains_in_workspace was set to usage.domains (wrong).
            domains_per_workspace_limit: context.limits.domains,
            scheduled_reports_per_workspace_limit: context.limits.scheduled_reports_per_workspace,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/admin/subscriptions ────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/admin/subscriptions") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (!(await isPlatformAdmin(user, env))) return json({ error: "Forbidden" }, 403);

      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT
               u.id AS user_id,
               u.email AS user_email,
               u.name AS user_name,
               cp.company_name,
               cp.contact_email,
               sa.plan,
               sa.subscription_status AS status,
               sa.created_at,
               sa.current_period_end AS expires_at
             FROM users u
             LEFT JOIN customer_profiles cp ON cp.owner_user_id = u.id
             LEFT JOIN subscriptions sa ON sa.owner_user_id = u.id
             ORDER BY COALESCE(sa.created_at, u.created_at) DESC
             LIMIT 500`
          )
          .all();

        return json({
          subscriptions: (rows.results || []).map((row) => ({
            customer: {
              user_id: row.user_id,
              email: row.user_email,
              name: row.user_name,
              company_name: row.company_name,
              contact_email: row.contact_email,
            },
            plan: normalizePlan(row.plan),
            status: row.status || "active",
            created_at: row.created_at,
            expires_at: row.expires_at,
          })),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/api-tokens ─────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/api-tokens") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Token management is session-only — an API token cannot enumerate tokens.
      if (user.api_token_id) return json({ error: "Token management requires session authentication" }, 403);
      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, name, scope, workspace_id, last_used_at, created_at, expires_at, status
             FROM api_tokens
             WHERE user_id = ?
             ORDER BY created_at DESC`
          )
          .bind(user.id)
          .all();
        return json({ tokens: rows.results || [] });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/account/api-tokens ────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/account/api-tokens") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Token management requires session authentication" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const name        = (body.name || "").trim();
      const scope       = (body.scope || "read").trim();
      const workspaceId = body.workspace_id ? String(body.workspace_id).trim() : null;
      const expiresAt   = body.expires_at   ? String(body.expires_at).trim()   : null;

      if (!name) return json({ error: "name is required" }, 400);
      if (name.length > 120) return json({ error: "name is too long" }, 400);
      if (!["read", "write", "admin"].includes(scope)) {
        return json({ error: "scope must be one of: read, write, admin" }, 400);
      }

      // If a workspace_id is provided, verify the user is a member of that workspace.
      if (workspaceId) {
        const wsAccess = await requireWorkspaceAccess(user, workspaceId, env);
        if (!wsAccess) return json({ error: "Workspace not found or access denied" }, 403);
      }

      try {
        // Entitlement: API token limit
        const plan = await getEffectivePlan(user.id, env);
        const tokUsage  = await getEntitlementUsage(user, env);
        const tokLimits = getPlanLimits(plan);
        if (tokUsage.api_tokens >= tokLimits.api_tokens) {
          return json(planLimitExceeded("api_tokens", tokLimits.api_tokens, tokUsage.api_tokens), 403);
        }

        const { raw, hash } = await generateApiToken();
        const tokenId = createId("apitok");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO api_tokens
               (id, user_id, name, token_hash, scope, workspace_id, expires_at, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'))`
          )
          .bind(tokenId, user.id, name, hash, scope, workspaceId, expiresAt)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "api_token_created",
          entity_type: "api_token",
          entity_id:   tokenId,
          description: `API token "${name}" created (scope: ${scope})`,
          metadata:    { name, scope, workspace_id: workspaceId },
        });

        return json({ token: raw }, 201);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── DELETE /api/account/api-tokens/:id ──────────────────────────────
    const apiTokenDeleteMatch = url.pathname.match(/^\/api\/account\/api-tokens\/([^/]+)$/);
    if (apiTokenDeleteMatch && request.method === "DELETE") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Token management requires session authentication" }, 403);
      const tokenId = apiTokenDeleteMatch[1];

      try {
        const tokenRow = await env.cybermeters_db
          .prepare("SELECT id, name FROM api_tokens WHERE id = ? AND user_id = ?")
          .bind(tokenId, user.id)
          .first();
        if (!tokenRow) return json({ error: "Token not found" }, 404);

        const result = await env.cybermeters_db
          .prepare("UPDATE api_tokens SET status = 'revoked' WHERE id = ? AND user_id = ?")
          .bind(tokenId, user.id)
          .run();
        if (result.meta?.changes === 0) return json({ error: "Token not found" }, 404);

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "api_token_revoked",
          entity_type: "api_token",
          entity_id:   tokenId,
          description: `API token "${tokenRow.name}" revoked`,
          metadata:    { name: tokenRow.name },
        });

        return json({ success: true });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/login-history ──────────────────────────────────
    // Returns recent auth-related audit events for the authenticated user.
    // Reuses audit_events — no duplicate storage.
    // Tenant/user isolation: WHERE user_id = ? enforced.
    if (request.method === "GET" && url.pathname === "/api/account/login-history") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // API tokens may not access personal security history
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

      const HISTORY_TYPES = [
        "login", "USER_LOGIN_MICROSOFT", "login_failed",
        "mfa_challenge_success", "mfa_challenge_failed",
        "recovery_code_used",
        "password_reset_completed", "password_reset_failed",
      ];
      const SUCCESS_TYPES = new Set(["login", "USER_LOGIN_MICROSOFT", "mfa_challenge_success", "recovery_code_used", "password_reset_completed"]);

      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, event_type, description, metadata_json, created_at
             FROM audit_events
             WHERE user_id = ?
               AND event_type IN (${HISTORY_TYPES.map(() => "?").join(",")})
             ORDER BY created_at DESC
             LIMIT 100`
          )
          .bind(user.id, ...HISTORY_TYPES)
          .all();

        const events = (rows.results || []).map(row => {
          let meta = {};
          try { meta = row.metadata_json ? JSON.parse(row.metadata_json) : {}; } catch { /* ignore */ }
          return {
            id:          row.id,
            timestamp:   row.created_at,
            event_type:  row.event_type,
            ip_address:  meta.ip_address || null,
            user_agent:  meta.user_agent || null,
            result:      SUCCESS_TYPES.has(row.event_type) ? "success" : "failed",
            description: row.description || null,
          };
        });

        createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "login_history_viewed",
          entity_type: "user",
          entity_id:   user.id,
          description: "User viewed their login history",
        }).catch(() => {});

        return json({ events });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/sessions ────────────────────────────────────────
    // Returns active (non-expired) sessions for the authenticated user.
    // Marks current session; never exposes token_hash.
    // Tenant/user isolation: WHERE user_id = ? enforced.
    if (request.method === "GET" && url.pathname === "/api/account/sessions") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

      try {
        // Identify current session by hashing the bearer token from this request
        const _authRaw = (request.headers.get("Authorization") || "").slice(7).trim();
        const _currentHash = _authRaw ? await hashToken(_authRaw) : null;

        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, created_at, last_seen_at, ip_address, user_agent, token_hash, expires_at
             FROM user_sessions
             WHERE user_id = ? AND expires_at > datetime('now')
             ORDER BY created_at DESC`
          )
          .bind(user.id)
          .all();

        const sessions = (rows.results || []).map(s => ({
          session_id:  s.id,
          created_at:  s.created_at,
          last_seen_at: s.last_seen_at || null,
          expires_at:  s.expires_at,
          ip_address:  s.ip_address  || null,
          user_agent:  s.user_agent  || null,
          current:     _currentHash !== null && s.token_hash === _currentHash,
          // token_hash intentionally excluded from response
        }));

        createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "active_sessions_viewed",
          entity_type: "user",
          entity_id:   user.id,
          description: "User viewed their active sessions",
        }).catch(() => {});

        return json({ sessions });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/account/sessions/:id/revoke ───────────────────────────
    // Revoke a specific session. Cannot revoke the current session via this
    // endpoint — use POST /api/auth/logout for self-termination.
    // Tenant/user isolation: WHERE user_id = ? enforced.
    const sessionRevokeMatch = url.pathname.match(/^\/api\/account\/sessions\/([^/]+)\/revoke$/);
	    if (sessionRevokeMatch && request.method === "POST") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
      const targetSessionId = sessionRevokeMatch[1];

      try {
        // Verify the session belongs to this user (isolation enforced by AND user_id = ?)
        const target = await env.cybermeters_db
          .prepare("SELECT id, token_hash FROM user_sessions WHERE id = ? AND user_id = ? LIMIT 1")
          .bind(targetSessionId, user.id)
          .first();
        if (!target) return json({ error: "Session not found" }, 404);

        // Prevent accidental current-session revocation — use /api/auth/logout instead
        const _authRaw = (request.headers.get("Authorization") || "").slice(7).trim();
        if (_authRaw) {
          const _currentHash = await hashToken(_authRaw);
          if (target.token_hash === _currentHash) {
            return json({ error: "Use Sign Out to end your current session." }, 400);
          }
        }

        await env.cybermeters_db
          .prepare("DELETE FROM user_sessions WHERE id = ? AND user_id = ?")
          .bind(targetSessionId, user.id)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "session_revoked",
          entity_type: "user",
          entity_id:   user.id,
          description: "User revoked an active session",
          metadata:    { revoked_session_id: targetSessionId },
        }).catch(() => {});

        return json({ success: true, message: "Session revoked." });
      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── GET /api/account/export ─────────────────────────────────────────
	    // GDPR-ready personal data export. Session auth only; explicit columns
	    // avoid secrets such as passwords, MFA material, token hashes, and invite tokens.
	    if (request.method === "GET" && url.pathname === "/api/account/export") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
	      try {
	        const email = String(user.email || "").trim().toLowerCase();
	        const [profile, workspaces, loginHistory, sessions, auditEvents, invitations] = await Promise.all([
	          env.cybermeters_db
	            .prepare("SELECT id, email, name, plan, status, created_at FROM users WHERE id = ?")
	            .bind(user.id)
	            .first(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT w.id, w.name, w.created_at, wm.role,
	                      CASE WHEN w.owner_user_id = ? THEN 1 ELSE 0 END AS owned
	               FROM workspaces w
	               LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
	               WHERE wm.user_id IS NOT NULL
	                  OR (w.owner_user_id = ? AND NOT EXISTS (
	                    SELECT 1 FROM workspace_members any_wm WHERE any_wm.workspace_id = w.id
	                  ))
	               ORDER BY w.created_at DESC`
	            )
	            .bind(user.id, user.id, user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, event_type, description, metadata_json, created_at
	               FROM audit_events
	               WHERE user_id = ?
	                 AND event_type IN ('login', 'login_failed', 'mfa_challenge_success',
	                                    'mfa_challenge_failed', 'recovery_code_used',
	                                    'password_reset_completed', 'password_reset_failed')
	               ORDER BY created_at DESC
	               LIMIT 250`
	            )
	            .bind(user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, created_at, last_seen_at, ip_address, user_agent, expires_at
	               FROM user_sessions
	               WHERE user_id = ?
	               ORDER BY created_at DESC
	               LIMIT 250`
	            )
	            .bind(user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, workspace_id, event_type, entity_type, entity_id,
	                      description, metadata_json, created_at
	               FROM audit_events
	               WHERE user_id = ?
	               ORDER BY created_at DESC
	               LIMIT 500`
	            )
	            .bind(user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, workspace_id, email, role, invited_by, status,
	                      expires_at, accepted_at, created_at
	               FROM workspace_invitations
	               WHERE email = ?
	               ORDER BY created_at DESC
	               LIMIT 250`
	            )
	            .bind(email)
	            .all(),
	        ]);

	        await createAuditEvent(env, {
	          user_id: user.id,
	          event_type: "account_export_requested",
	          entity_type: "user",
	          entity_id: user.id,
	          description: "Account data export requested",
	        }).catch(() => {});

	        return json({
	          exported_at: new Date().toISOString(),
	          user_profile: profile || { id: user.id, email: user.email, name: user.name || null },
	          workspaces: workspaces.results || [],
	          login_history: loginHistory.results || [],
	          sessions: sessions.results || [],
	          audit_events: auditEvents.results || [],
	          invitations: invitations.results || [],
	          excluded: ["password_hash", "totp_secret", "mfa_recovery_codes_hash_json", "session_token_hashes", "api_token_hashes", "invitation_token_hashes", "workspace_scan_data", "reports"],
	        });
	      } catch {
	        return json({ error: "Unable to export account data" }, 500);
	      }
	    }

	    // ── POST /api/account/delete-request ────────────────────────────────
	    if (request.method === "POST" && url.pathname === "/api/account/delete-request") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
	      try {
	        const existing = await env.cybermeters_db
	          .prepare("SELECT id, created_at FROM deletion_requests WHERE request_type = 'account' AND user_id = ? AND status = 'pending' LIMIT 1")
	          .bind(user.id)
	          .first();
	        if (existing) return json({ request_id: existing.id, status: "pending", created_at: existing.created_at, message: "Account deletion request already exists." });

	        const requestId = createId("delreq");
	        const now = new Date().toISOString();
	        await env.cybermeters_db
	          .prepare(
	            `INSERT INTO deletion_requests
	               (id, request_type, user_id, requested_by, status, created_at, updated_at)
	             VALUES (?, 'account', ?, ?, 'pending', ?, ?)`
	          )
	          .bind(requestId, user.id, user.id, now, now)
	          .run();
	        await createAuditEvent(env, {
	          user_id: user.id,
	          event_type: "account_deletion_requested",
	          entity_type: "user",
	          entity_id: user.id,
	          description: "Account deletion requested",
	          metadata: { request_id: requestId },
	        }).catch(() => {});
	        return json({ request_id: requestId, status: "pending", message: "Account deletion request received." }, 202);
	      } catch {
	        return json({ error: "Unable to create deletion request" }, 500);
	      }
	    }
	
	    // ── GET /api/platform/accuracy ───────────────────────────────────────
	    if (request.method === "GET" && url.pathname === "/api/platform/accuracy") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const regression = evaluateRegressionFixtures();

        if (workspaceIds.length === 0) {
          return json({
            accuracy_score:              0,
            findings_total:              0,
            high_confidence_pct:         0,
            low_confidence_pct:          0,
            evidence_complete_pct:       0,
            validation_uncertain_count:  0,
            validation_uncertain_pct:    0,
            resolver_agreement_avg:      null,
            header_validation_score:     75,
            golden_domain_coverage:      Math.min(100, Math.round(((regression.total ?? 0) / 15) * 100)),
            regression_pass_rate:        regression.pass_rate,
            regression_fixture_count:    regression.total ?? 0,
          });
        }

        const placeholders = workspaceIds.map(() => "?").join(",");
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT f.id, f.title, f.confidence, f.evidence_json
             FROM findings f
             JOIN scans s ON s.id = f.scan_id
             LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
             WHERE s.workspace_id IN (${placeholders})
                OR (s.workspace_id IS NULL AND wd.workspace_id IN (${placeholders}))`
          )
          .bind(...workspaceIds, ...workspaceIds)
          .all();

        const findings = rows.results || [];
        const total = findings.length;
        let high = 0;
        let low = 0;
        let complete = 0;
        let uncertain = 0;

        for (const row of findings) {
          const confidence = String(row.confidence || "").toLowerCase();
          if (confidence === "high") high += 1;
          if (confidence === "low") low += 1;

          let evidence = null;
          try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : null; } catch {}
          const quality = validateFindingEvidence({
            title: row.title,
            confidence: row.confidence,
            score_impact: 0,
            evidence,
          }).evidence_quality;
          if (quality === "excellent" || quality === "good") complete += 1;

          const evidenceText = JSON.stringify(evidence || {}).toLowerCase();
          if (
            /validation uncertain/i.test(row.title || "")
            || confidence === "low"
            || evidenceText.includes("validation_uncertain")
          ) {
            uncertain += 1;
          }
        }

        const pct = (n) => total > 0 ? Math.round((n / total) * 100) : 0;

        // Compute resolver_agreement_avg from findings that have the field in evidence
        let raTotal = 0, raCount = 0;
        for (const row of findings) {
          let evidence = null;
          try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : null; } catch {}
          if (evidence?.resolver_agreement_score != null) {
            raTotal += evidence.resolver_agreement_score;
            raCount += 1;
          }
        }
        const resolverAgreementAvg = raCount > 0 ? Math.round(raTotal / raCount) : null;

        // header_validation_score: % of findings with header evidence where strength is "valid"
        // (proxy for how well the scanner can classify header quality)
        let hvValid = 0, hvTotal = 0;
        for (const row of findings) {
          let evidence = null;
          try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : null; } catch {}
          if (evidence?.evidence_type === "http_header_probe") {
            hvTotal += 1;
            const sc = String(evidence?.strength_classification || "");
            if (sc === "valid" || sc === "") hvValid += 1;  // absent = not weak
          }
        }
        const headerValidationScore = hvTotal > 0 ? Math.round((hvValid / hvTotal) * 100) : 75; // default 75 — no header data yet

        // golden_domain_coverage: fixture count / 15 (target fixture count for v5)
        // golden_domain_coverage: regression.total / 15 (v5 fixture target)
        const goldenDomainCoverage = Math.min(100, Math.round(((regression.total ?? 0) / 15) * 100));

        // accuracy_score formula (v5):
        //   35% resolver_agreement_avg      — cross-resolver consistency
        //   25% header_validation_score     — header strength classification accuracy
        //   20% evidence_complete_pct       — finding evidence completeness
        //   10% regression_pass_rate        — regression fixture coverage
        //   10% golden_domain_coverage      — golden domain fixture breadth (15 fixture target)
        const evidenceCompletePct    = pct(complete);
        const highConfidencePct      = pct(high);
        const regressionPassRate     = regression.pass_rate;
        const validationUncertainPct = pct(uncertain);
        const resolverAvgForScore    = resolverAgreementAvg ?? 50;

        const accuracyScore = Math.round(
          resolverAvgForScore    * 0.35
          + headerValidationScore  * 0.25
          + evidenceCompletePct    * 0.20
          + regressionPassRate     * 0.10
          + goldenDomainCoverage   * 0.10
        );

        return json({
          accuracy_score:              accuracyScore,
          findings_total:              total,
          high_confidence_pct:         highConfidencePct,
          low_confidence_pct:          pct(low),
          evidence_complete_pct:       evidenceCompletePct,
          validation_uncertain_count:  uncertain,
          validation_uncertain_pct:    validationUncertainPct,
          resolver_agreement_avg:      resolverAgreementAvg,
          header_validation_score:     headerValidationScore,
          golden_domain_coverage:      goldenDomainCoverage,
          regression_pass_rate:        regressionPassRate,
          regression_fixture_count:    regression.total ?? 0,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/scan ──────────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/scan") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain = body.domain?.trim().toLowerCase();
      let workspaceId = body.workspace_id ? String(body.workspace_id).trim() : null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!workspaceId) {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        for (const id of workspaceIds) {
          const access = await requireWorkspaceRole(user, id, "scan:create", env);
          if (access) {
            workspaceId = id;
            break;
          }
        }
        if (!workspaceId) {
          return json({ error: "No workspace available for scan creation" }, 403);
        }
      }

      const scanAccess = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
      if (!scanAccess) return json({ error: "Forbidden — analyst role required to create scans" }, 403);

      // ── Enforce monthly scan quota ───────────────────────────────────────
      const scanLimitError = await checkScanLimit(user, workspaceId, env);
      if (scanLimitError) return json(scanLimitError.body, scanLimitError.status);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id FROM workspaces WHERE id = ?`)
        .bind(workspaceId)
        .first();
      if (!ws) {
        return json({ error: "Workspace not found" }, 404);
      }

      const burstOwnerId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
      const burstPlan = await getEffectivePlan(burstOwnerId, env);
      const burstLimit = getPlanLimits(burstPlan).scan_starts_per_hour;
      const burstLimitError = await consumeApiRateLimit(
        env,
        [
          { scope: "user", scope_id: user.id },
          { scope: "workspace", scope_id: workspaceId },
          { scope: "account", scope_id: burstOwnerId },
        ],
        "scan_start",
        burstLimit,
        3600
      );
      if (burstLimitError) return json(burstLimitError.body, burstLimitError.status);

      const userId   = user.id;
      const domainId = createId("domain");
      const scanId   = createId("scan");
      const reportKey = `reports/${scanId}.json`;
      const initialScanQuality = {
        status: "complete",
        warnings: [],
        modules_skipped: [],
        subrequest_budget: {
          estimated: 0,
          limit: 1_000,       // Sprint 10B: Workers Paid plan limit
          remaining_estimate: 1_000,
        },
      };

      await createAuditEvent(env, {
        workspace_id: workspaceId ?? null,
        user_id:      userId ?? null,
        event_type:   "scan_requested",
        entity_type:  "scan",
        entity_id:    scanId,
        description:  `Scan requested for ${domain}`,
        metadata:     { scan_id: scanId, domain, workspace_id: workspaceId ?? null },
      });

      // Register domain — reuse existing row for same (user_id, domain) pair.
      // Scoped by user_id to prevent cross-user domain aliasing.
      const existingDomain = await env.cybermeters_db
        .prepare(`SELECT id FROM domains WHERE domain = ? AND user_id = ? LIMIT 1`)
        .bind(domain, userId)
        .first();

      const resolvedDomainId = existingDomain ? existingDomain.id : domainId;

      if (!existingDomain) {
        // Entitlement: per-workspace limit + account-level limit for new domains only.
        // burstOwnerId is already resolved above for the hourly rate-limit check.
        const domScanPlan   = await getEffectivePlan(burstOwnerId, env);
        const domScanUsage  = await getEntitlementUsage(user, env, workspaceId);
        const domScanLimits = getPlanLimits(domScanPlan);
        // (a) Per-workspace limit
        if (domScanUsage.domains_in_workspace >= domScanLimits.domains_per_workspace) {
          return json(planLimitExceeded("domains", domScanLimits.domains, domScanUsage.domains_in_workspace), 403);
        }
        // (b) Account-level limit across all owned workspaces
        const domScanOwnerAcct = await getAccountUsage(burstOwnerId, env);
        if (domScanOwnerAcct.domains >= domScanLimits.domains) {
          return json(planLimitExceeded("domains", domScanLimits.domains, domScanOwnerAcct.domains), 403);
        }

        await env.cybermeters_db
          .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
          .bind(domainId, userId, domain)
          .run();
      }

      await env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
           VALUES (?, ?)`
        )
        .bind(workspaceId, resolvedDomainId)
        .run();

      // Create scan row — status 'running' (engine starts immediately)
      await env.cybermeters_db
        .prepare(
          `INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES (?, ?, ?, ?, ?)`
        )
        .bind(scanId, resolvedDomainId, workspaceId, domain, "running")
        .run();

      // Write placeholder report to R2 so GET /report returns 200 immediately
      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify({
          scan_id:             scanId,
          domain_id:           resolvedDomainId,
          domain,
          status:              "running",
          cyber_metrics_score: 0,
          risk_level:          "unknown",
          findings:            [],
          recommendations:     [],
          scan_quality:         initialScanQuality,
          message:             "Scan engine is running. Poll GET /api/scans/:id for completion.",
        }, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );

      // Audit — scan started. Non-fatal.
      try {
        await createAuditEvent(env, {
          workspace_id: workspaceId ?? null,
          user_id:      userId ?? null,
          event_type:   "scan_started",
          entity_type:  "scan",
          entity_id:    scanId,
          description:  `Scan started for ${domain}`,
          metadata:     { scan_id: scanId, domain, domain_id: resolvedDomainId, workspace_id: workspaceId ?? null },
        });
      } catch { /* non-fatal */ }

      // Fire the scan engine after the response is sent
      ctx.waitUntil(runScanEngine(scanId, resolvedDomainId, workspaceId, domain, env));

      return json(
        {
          status:       "running",
          scan_id:      scanId,
          domain_id:    resolvedDomainId,
          domain,
          report_key:   reportKey,
          scan_quality: initialScanQuality,
          ...(workspaceId ? { workspace_id: workspaceId } : {}),
          message:      "Scan engine started. Poll GET /api/scans/:id until status is completed, then GET /api/scans/:id/report.",
        },
        202
      );
    }

    // ── GET /api/scans ──────────────────────────────────────────────────
    // Supports optional ?workspace_id= to scope results to a single workspace.
    if (request.method === "GET" && url.pathname === "/api/scans") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const wsFilter = url.searchParams.get("workspace_id");

      // If caller scoped the request to a workspace, verify membership first.
      if (wsFilter) {
        const wsAccess = await requireWorkspaceRole(user, wsFilter, "workspace:read", env);
        if (!wsAccess) return json({ error: "Forbidden" }, 403);
      }

      let result;
      if (wsFilter) {
        // Direct attribution: scans.workspace_id = wsFilter.
        // Fallback via domain join for historical scans where workspace_id IS NULL.
        result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT s.id, s.domain, s.status, s.score, s.rating, s.created_at
             FROM scans s
             JOIN domains d ON d.id = s.domain_id
             JOIN workspace_domains wd ON wd.domain_id = d.id
             WHERE (
               s.workspace_id = ?
               OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
             )
             ORDER BY s.created_at DESC
             LIMIT 20`
          )
          .bind(wsFilter, wsFilter)
          .all();
      } else {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) {
          return json({ scans: [] });
        }
        const placeholders = workspaceIds.map(() => "?").join(",");
        // Direct attribution for attributed scans; join fallback for NULL workspace_id.
        result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT s.id, s.domain, s.status, s.score, s.rating, s.created_at
             FROM scans s
             JOIN domains d ON d.id = s.domain_id
             JOIN workspace_domains wd ON wd.domain_id = d.id
             WHERE (
               s.workspace_id IN (${placeholders})
               OR (s.workspace_id IS NULL AND wd.workspace_id IN (${placeholders}))
             )
             ORDER BY s.created_at DESC
             LIMIT 20`
          )
          .bind(...workspaceIds, ...workspaceIds)
          .all();
      }

      // ── Stuck-scan reconciliation ─────────────────────────────────────
      // Edge case: if runScanEngine was killed (Worker CPU timeout, subrequest limit)
      // between the R2 write and the D1 status write, the scan stays 'running' in D1
      // permanently even though R2 has the completed report.
      // For any scan that has been 'running' for > 10 minutes, check R2 and correct D1.
      // Only genuinely old scans are checked — in-flight scans (<10 min) are never touched.
      const STUCK_THRESHOLD_MS = 2 * 60 * 1000; // 2 minutes — scans complete in ~15s; >2min means stuck
      const nowMs = Date.now();
      const stuckScans = (result.results || []).filter(s => {
        if (s.status !== 'running') return false;
        const t = new Date(
          s.created_at.includes('T') ? s.created_at : s.created_at.replace(' ', 'T') + 'Z'
        ).getTime();
        return (nowMs - t) > STUCK_THRESHOLD_MS;
      });

      if (stuckScans.length > 0) {
        const reconResults = await Promise.allSettled(
          stuckScans.map(async (s) => {
            try {
              const obj = await env.cybermeters_reports.get(`reports/${s.id}.json`);
              if (!obj) return null;
              const raw = await obj.json();
              const correctedStatus =
                raw.status === 'completed' ? 'completed' :
                raw.status === 'failed'    ? 'failed'    : null;
              if (!correctedStatus) return null;
              // Correct D1 so future queries also return the right status, score, and rating.
              try {
                await env.cybermeters_db
                  .prepare(`UPDATE scans SET status = ?, score = ?, rating = ? WHERE id = ?`)
                  .bind(
                    correctedStatus,
                    raw.cyber_metrics_score ?? null,
                    raw.risk_level          ?? null,
                    s.id
                  )
                  .run();
              } catch { /* non-fatal — response still returns corrected status */ }
              return {
                id:     s.id,
                status: correctedStatus,
                score:  raw.cyber_metrics_score ?? s.score,
                rating: raw.risk_level          ?? s.rating,
              };
            } catch { return null; }
          })
        );

        const corrections = Object.fromEntries(
          reconResults
            .filter(r => r.status === 'fulfilled' && r.value)
            .map(r => [r.value.id, r.value])
        );

        if (Object.keys(corrections).length > 0) {
          result = {
            ...result,
            results: (result.results || []).map(s =>
              corrections[s.id]
                ? { ...s, status: corrections[s.id].status, score: corrections[s.id].score, rating: corrections[s.id].rating }
                : s
            ),
          };
        }
      }
      // ── End stuck-scan reconciliation ─────────────────────────────────

      return json({ scans: result.results, ...(wsFilter ? { workspace_id: wsFilter } : {}) });
    }

    // ── GET /api/scans/:id/report/pdf ──────────────────────────────────
    // Per-scan PDF export built from the stored V1 report. Read-only, RBAC-
    // scoped via scan access, audited. Never exposes internals.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report\/pdf$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const scan = await env.cybermeters_db
          .prepare("SELECT id, domain, status, score, rating, created_at FROM scans WHERE id = ? LIMIT 1")
          .bind(scanId).first();
        if (!scan) return json({ error: "Scan not found" }, 404);
        if (scan.status !== "completed") return json({ error: "PDF is available only for completed scans" }, 409);

        const reportObject = await env.cybermeters_reports.get(`reports/${scanId}.json`);
        if (!reportObject) return json({ error: "Report not found" }, 404);
        const report = await reportObject.json();
        // Attach Business Risk from the same shared helper the UI uses, so the
        // PDF's score matches the on-screen report exactly.
        report.business_risk = deriveScanBusinessRisk(report);

        const bytes = buildScanReportPdf(scan, report);

        await createAuditEvent(env, {
          workspace_id: access.workspace_id || null,
          user_id:      user.id,
          event_type:   "scan_report_downloaded",
          entity_type:  "scan",
          entity_id:    scanId,
          description:  `Scan report PDF downloaded for ${scan.domain}`,
          metadata:     { scan_id: scanId, domain: scan.domain },
        }).catch(() => {});

        const safeName = String(scan.domain || "scan").toLowerCase().replace(/[^a-z0-9.-]/g, "-");
        return new Response(bytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type":        "application/pdf",
            "Content-Disposition": `attachment; filename="cybermeters-${safeName}-scan.pdf"`,
            "Content-Length":      String(bytes.length),
          },
        });
      } catch (error) {
        return serverError("scan-report-pdf", error, "PDF could not be generated.");
      }
    }

    // ── GET /api/scans/:id/executive-report-v2 ─────────────────────────
    // Additive Executive Intelligence contract built from the stored scan report.
    // V1 report storage and response behavior remain unchanged.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/executive-report-v2$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const scan = await env.cybermeters_db
          .prepare(
            `SELECT id, domain_id, domain, status, score, rating, created_at
             FROM scans WHERE id = ? LIMIT 1`
          )
          .bind(scanId)
          .first();
        if (!scan) return json({ error: "Scan not found" }, 404);
        if (scan.status !== "completed") {
          return json({ error: "Executive report is available only for completed scans" }, 409);
        }

        const reportObject = await env.cybermeters_reports.get(`reports/${scanId}.json`);
        if (!reportObject) return json({ error: "Report not found" }, 404);
        const rawReport = await reportObject.json();

        const workspace = access.workspace_id
          ? await env.cybermeters_db
              .prepare("SELECT id, name FROM workspaces WHERE id = ? LIMIT 1")
              .bind(access.workspace_id)
              .first()
          : null;

        const execReport = buildExecutiveReportV2({ scan, rawReport, workspace });
        // Additive: attach DMARC sender-intelligence evidence to the Business Email
        // engine when imported report data exists. Never alters existing structure.
        try {
          const senderIntel = await buildDmarcSenderIntelligenceEvidence(
            env, access.workspace_id || null, scan.domain || rawReport.domain || null);
          if (senderIntel && execReport?.intelligence_engines?.business_email?.evidence) {
            execReport.intelligence_engines.business_email.evidence.dmarc_sender_intelligence = senderIntel;
          }
        } catch { /* non-fatal — exec report remains unchanged */ }
        return json(execReport);
      } catch (error) {
        return serverError("executive-report-v2", error, "Executive report could not be generated.");
      }
    }

    // ── GET /api/scans/:id/report ───────────────────────────────────────
    // Must be checked BEFORE the generic /api/scans/:id route below.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];

      // Auth before DB — prevents scan ID existence probing by unauthenticated callers.
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      const scan = await env.cybermeters_db
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, created_at
           FROM scans WHERE id = ?`
        )
        .bind(scanId)
        .first();

      if (!scan) {
        return json({ error: "Scan not found" }, 404);
      }

      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (!obj) {
        return json({ error: "Report not found" }, 404);
      }

      const raw = await obj.json();

      // Normalise modules — ensure every module key is present even for reports
      // stored before a module was introduced (backward-compatible defaults).
      const storedModules = raw.modules ?? {};
      const normalisedModules = {
        ...storedModules,
        asset_exposure: storedModules.asset_exposure ?? {
          checked:   0,
          reachable: 0,
          assets:    [],
          source:    "http_probe",
          error:     null,
        },
        subdomain_takeover: storedModules.subdomain_takeover ?? {
          checked:         0,
          potential_risks: 0,
          risks:           [],
          source:          "subdomain_cname_fingerprint",
          error:           null,
        },
        historical_changes: storedModules.historical_changes ?? {
          has_previous:       false,
          previous_scan_id:   null,
          previous_score:     null,
          current_score:      null,
          score_change:       null,
          new_subdomains:     [],
          removed_subdomains: [],
          new_findings:       [],
          resolved_findings:  [],
          new_takeover_risks: [],
          new_exposed_assets: [],
          source:             "previous_scan_comparison",
          error:              null,
        },
      };

      // Sprint 9A: normalise to v2 schema before returning — ensures old R2 reports
      // that pre-date the schema upgrade also expose the full v2 field set.
      const reportFindings = applyEvidenceQuality(
        (Array.isArray(raw.findings) ? raw.findings : []).map(normalizeFindingSchema)
      );

      // Compute Business Risk Score from scan findings + module signals.
      // Shared helper so the scan PDF (which reads the raw report) produces the
      // exact same score as this response.
      const businessRisk = deriveScanBusinessRisk(raw);

      const canonicalScore = resolveCanonicalScanScore(scan.score, raw.cyber_metrics_score);
      const canonicalRiskLevel = riskLevelForScore(canonicalScore);
      const historicalChanges = normalisedModules.historical_changes;
      normalisedModules.historical_changes = {
        ...historicalChanges,
        current_score: canonicalScore,
        score_change: historicalChanges?.previous_score != null
          ? canonicalScore - historicalChanges.previous_score
          : null,
      };

      return json({
        scan_id:             scan.id,
        domain:              scan.domain,
        status:              scan.status,
        cyber_metrics_score: canonicalScore,
        risk_level:          canonicalRiskLevel,
        findings:            reportFindings,
        recommendations:     Array.isArray(raw.recommendations) ? raw.recommendations : [],
        scan_quality:         raw.scan_quality ?? buildScanQuality(normalisedModules),
        modules:             normalisedModules,
        business_risk:       businessRisk,
        ...(raw.started_at   ? { started_at:   raw.started_at   } : {}),
        ...(raw.completed_at ? { completed_at: raw.completed_at } : {}),
        ...(raw.failed_at    ? { failed_at:    raw.failed_at    } : {}),
        ...(raw.message      ? { message:      raw.message      } : {}),
        ...(raw.error        ? { error:        raw.error        } : {}),
      });
    }

    // ── GET /api/scans/:id ──────────────────────────────────────────────
    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/scans/")
    ) {
      const scanId = url.pathname.split("/").pop();

      // Auth before DB — prevents scan ID existence probing by unauthenticated callers.
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let scan = await env.cybermeters_db
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, created_at
           FROM scans WHERE id = ?`
        )
        .bind(scanId)
        .first();

      if (!scan) {
        return json({ error: "Scan not found" }, 404);
      }

      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // ── Stuck-scan reconciliation ────────────────────────────────────────
      // If D1 still shows 'running' but the scan is older than 2 minutes,
      // the Worker was likely CPU-killed between the R2 write and the D1 write.
      // Check R2 for the real status and correct D1 so polling can terminate.
      if (scan.status === "running") {
        const createdMs = new Date(
          scan.created_at.includes("T") ? scan.created_at : scan.created_at + "Z"
        ).getTime();
        if (Date.now() - createdMs > 2 * 60 * 1000) {
          try {
            const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
            if (obj) {
              const raw = await obj.json();
              if (raw.status === "completed" || raw.status === "failed") {
                const correctedScore  = raw.cyber_metrics_score ?? null;
                const correctedRating = raw.risk_level ?? null;
                await env.cybermeters_db
                  .prepare(
                    `UPDATE scans SET status = ?, score = ?, rating = ? WHERE id = ?`
                  )
                  .bind(raw.status, correctedScore, correctedRating, scanId)
                  .run();
                scan = {
                  ...scan,
                  status: raw.status,
                  score:  correctedScore,
                  rating: correctedRating,
                };
              }
            }
          } catch (_) {
            // R2 read failure is non-fatal — return D1 state as-is
          }
        }
      }

      return json({
        scan,
        report_key: `reports/${scan.id}.json`,
      });
    }

    // ── GET /api/domain/:domain/history ────────────────────────────────
    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/domain/") &&
      url.pathname.endsWith("/history")
    ) {
      const parts  = url.pathname.split("/");
      const domain = decodeURIComponent(parts[3]);

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const workspaceIds = await getAccessibleWorkspaceIds(user, env);
      if (workspaceIds.length === 0) return json({ error: "Forbidden" }, 403);
      const placeholders = workspaceIds.map(() => "?").join(",");
      const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);

      const history = await env.cybermeters_db
        .prepare(
          `SELECT DISTINCT s.id, s.domain_id, s.domain, s.status, s.score, s.rating, s.created_at
           FROM scans s
           JOIN workspace_domains wd ON wd.domain_id = s.domain_id
           WHERE s.domain = ? AND wd.workspace_id IN (${placeholders})
           ORDER BY s.created_at DESC
           LIMIT ?`
        )
        .bind(domain, ...workspaceIds, limit)
        .all();

      return json({ domain, scans: history.results });
    }

    // ── POST /api/schedules ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/schedules") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain      = (body.domain || "").trim().toLowerCase();
      const frequency   = (body.frequency || "daily").trim().toLowerCase();
      let workspaceId = (body.workspace_id || "").trim() || null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!["daily", "weekly"].includes(frequency)) {
        return json({ error: "frequency must be 'daily' or 'weekly'" }, 400);
      }
      if (!workspaceId) {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        for (const id of workspaceIds) {
          const access = await requireWorkspaceRole(user, id, "scan:create", env);
          if (access) {
            workspaceId = id;
            break;
          }
        }
        if (!workspaceId) {
          return json({ error: "No workspace available for scheduled scans" }, 403);
        }
      }
      const scheduleAccess = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
      if (!scheduleAccess) return json({ error: "Forbidden — analyst role required to manage scheduled scans" }, 403);

      // ── Enforce scheduled scan count quota ───────────────────────────────
      const schedLimitError = await checkScheduledScanLimit(user, workspaceId, env);
      if (schedLimitError) return json(schedLimitError.body, schedLimitError.status);

      // Create the table if it doesn't exist yet (idempotent — includes new columns)
      await env.cybermeters_db
        .prepare(
          `CREATE TABLE IF NOT EXISTS scheduled_scans (
             id TEXT PRIMARY KEY,
             domain TEXT NOT NULL,
             frequency TEXT NOT NULL DEFAULT 'daily',
             enabled INTEGER NOT NULL DEFAULT 1,
             last_run_at TEXT,
             next_run_at TEXT,
             workspace_id TEXT,
             last_asset_count INTEGER DEFAULT 0,
             asset_change_count INTEGER DEFAULT 0,
             created_at TEXT DEFAULT (datetime('now'))
           )`
        )
        .run();

      const schedId    = createId("sched");
      const nextRunAt  = computeNextRunAt(frequency);
      const createdAt  = new Date().toISOString();

      await env.cybermeters_db
        .prepare(
          `INSERT INTO scheduled_scans (id, domain, frequency, enabled, next_run_at, workspace_id, created_at)
           VALUES (?, ?, ?, 1, ?, ?, ?)`
        )
        .bind(schedId, domain, frequency, nextRunAt, workspaceId, createdAt)
        .run();

      await createAuditEvent(env, {
        workspace_id: workspaceId,
        user_id:      user.id,
        event_type:   "scheduled_scan_created",
        entity_type:  "scheduled_scan",
        entity_id:    schedId,
        description:  `Scheduled scan created for ${domain} (${frequency})`,
        metadata:     { scheduled_scan_id: schedId, domain, frequency, next_run_at: nextRunAt },
      });

      return json({
        schedule: {
          id:                 schedId,
          domain,
          frequency,
          enabled:            1,
          workspace_id:       workspaceId,
          last_asset_count:   0,
          asset_change_count: 0,
          last_run_at:        null,
          next_run_at:        nextRunAt,
          created_at:         createdAt,
        },
      }, 201);
    }

    // ── GET /api/schedules ──────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/schedules") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const workspaceIds = await getAccessibleWorkspaceIds(user, env);
      if (workspaceIds.length === 0) return json({ schedules: [] });
      const placeholders = workspaceIds.map(() => "?").join(",");
      const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);

      // Return empty list if table doesn't exist yet
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, frequency, enabled, workspace_id,
                    last_asset_count, asset_change_count,
                    last_run_at, next_run_at, created_at
             FROM scheduled_scans
             WHERE workspace_id IN (${placeholders})
             ORDER BY created_at DESC
             LIMIT ?`
          )
          .bind(...workspaceIds, limit)
          .all();
        return json({ schedules: result.results });
      } catch {
        return json({ schedules: [] });
      }
    }

    // ── DELETE /api/schedules/:id ───────────────────────────────────────
    if (
      request.method === "DELETE" &&
      url.pathname.startsWith("/api/schedules/")
    ) {
      const schedId = url.pathname.split("/").pop();
      if (!schedId) {
        return json({ error: "Missing schedule id" }, 400);
      }

      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const schedule = await env.cybermeters_db
          .prepare("SELECT id, workspace_id FROM scheduled_scans WHERE id = ?")
          .bind(schedId)
          .first();
        if (!schedule) return json({ error: "Schedule not found" }, 404);
        if (!schedule.workspace_id) return json({ error: "Forbidden" }, 403);
        const scheduleAccess = await requireWorkspaceRole(user, schedule.workspace_id, "scan:create", env);
        if (!scheduleAccess) return json({ error: "Forbidden — analyst role required to manage scheduled scans" }, 403);

        const result = await env.cybermeters_db
          .prepare(`DELETE FROM scheduled_scans WHERE id = ?`)
          .bind(schedId)
          .run();

        if (result.meta?.changes === 0) {
          return json({ error: "Schedule not found" }, 404);
        }
        await createAuditEvent(env, {
          workspace_id: schedule.workspace_id,
          user_id:      user.id,
          event_type:   "scheduled_scan_deleted",
          entity_type:  "scheduled_scan",
          entity_id:    schedId,
          description:  "Scheduled scan deleted",
          metadata:     { scheduled_scan_id: schedId },
        });
      } catch {
        return json({ error: "Schedule not found" }, 404);
      }

      return json({ deleted: schedId });
    }

    // ── Workspace Routes ──────────────────────────────────────────────────

    // GET /api/workspaces/:id/report — executive PDF report
    // Tested before the generic wsMatch so "/report" is never confused with a
    // domain ID.
    const reportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report$/);
    if (reportMatch && request.method === "GET") {
      const wsId = reportMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Workspace row
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces WHERE id = ?`)
          .bind(wsId).first();
      } catch { /* fall through */ }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // 2. Stats (4 parallel D1 queries)
      const [domRow, scanRow, avgRow, latestRow] = await Promise.all([
        env.cybermeters_db.prepare(
          `SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT COUNT(DISTINCT s.id) AS n
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed'`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT AVG(s.score) AS avg
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT s.id, s.domain, s.created_at
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed'
           ORDER BY s.created_at DESC LIMIT 1`
        ).bind(wsId).first(),
      ]).catch(() => [null, null, null, null]);

      const stats = {
        total_domains:        domRow?.n    ?? 0,
        total_scans:          scanRow?.n   ?? 0,
        cyber_score_average:  avgRow?.avg  ?? null,
        latest_scan:          latestRow    ?? null,
      };

      // 3. Domains enriched with latest scan
      let domains = [];
      try {
        const dr = await env.cybermeters_db.prepare(
          `SELECT d.id AS domain_id, d.domain,
                  s.id AS last_scan_id, s.score AS latest_score,
                  s.status AS latest_status, s.created_at AS last_scanned_at
           FROM workspace_domains wd
           JOIN domains d ON d.id = wd.domain_id
           LEFT JOIN scans s ON s.id = (
             SELECT id FROM scans WHERE domain_id = d.id ORDER BY created_at DESC LIMIT 1
           )
           WHERE wd.workspace_id = ?
           ORDER BY d.domain ASC`
        ).bind(wsId).all();
        domains = dr.results || [];
      } catch { /* tolerate */ }

      // 4. Top findings (ordered by severity then recency)
      let findings = [];
      try {
        const fr = await env.cybermeters_db.prepare(
          `SELECT f.title, f.severity, f.recommendation, s.domain
           FROM findings f
           JOIN scans s ON s.id = f.scan_id
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ?
           ORDER BY CASE f.severity
             WHEN 'critical' THEN 1 WHEN 'high' THEN 2
             WHEN 'medium'   THEN 3                ELSE 4 END,
             s.created_at DESC
           LIMIT 30`
        ).bind(wsId).all();
        findings = fr.results || [];
      } catch { /* tolerate */ }

      // 5. Recommendations
      let recommendations = [];
      try {
        const rr = await env.cybermeters_db.prepare(
          `SELECT r.title, r.priority, r.action, r.reason, s.domain
           FROM remediation_items r
           JOIN scans s ON s.id = r.scan_id
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ?
           ORDER BY r.priority ASC
           LIMIT 10`
        ).bind(wsId).all();
        recommendations = rr.results || [];
      } catch { /* tolerate */ }

      // 6. Historical trend — last 2 completed scans per domain
      let trend = [];
      try {
        const tr = await env.cybermeters_db.prepare(
          `SELECT s.domain, s.score AS current_score, s.created_at
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL
           ORDER BY s.created_at DESC
           LIMIT 20`
        ).bind(wsId).all();

        // Group by domain, keep newest two
        const byDomain = {};
        for (const row of (tr.results || [])) {
          if (!byDomain[row.domain]) byDomain[row.domain] = [];
          if (byDomain[row.domain].length < 2) byDomain[row.domain].push(row);
        }
        for (const [domain, rows] of Object.entries(byDomain)) {
          const cur  = rows[0];
          const prev = rows[1] ?? null;
          trend.push({
            domain,
            date: cur.created_at
              ? new Date((cur.created_at || "").replace(" ", "T") + "Z")
                  .toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
              : "—",
            current_score:  cur.current_score,
            previous_score: prev?.current_score ?? null,
            score_change:   prev != null ? cur.current_score - prev.current_score : null,
          });
        }
      } catch { /* tolerate */ }

      // 7. Build PDF
      try {
        const streams = buildPdfStreams({ workspace: ws, stats, domains, findings, recommendations, trend });
        const pdfText = assemblePdf(streams);
        const pdfBytes = new TextEncoder().encode(pdfText);
        const safeName = (ws.name || "workspace").replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase();

        return new Response(pdfBytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type":        "application/pdf",
            "Content-Disposition": `attachment; filename="cybermeters-${safeName}-report.pdf"`,
            "Content-Length":      String(pdfBytes.length),
          },
        });
      } catch (e) {
        return serverError("portfolio/report-pdf", e, "PDF generation failed. Please try again.");
      }
    }

    // ── Portfolio Risk Engine ─────────────────────────────────────────────────
    // GET /api/portfolio/risk — MSP portfolio risk intelligence (see below)

    // ── Portfolio APIs ────────────────────────────────────────────────────────
    // GET /api/portfolio/overview   — aggregate stats across all workspaces
    // GET /api/portfolio/workspaces — per-workspace risk rows, sorted by risk
    // GET /api/portfolio/alerts     — cross-workspace alert feed
    // GET /api/portfolio/trends     — 30-day daily aggregate trend
    // ─────────────────────────────────────────────────────────────────────────

    if (request.method === "GET" && url.pathname === "/api/portfolio/overview") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) {
          return json({
            total_workspaces: 0, total_domains: 0, total_assets: 0,
            total_vendors: 0, total_brand_candidates: 0, total_reports: 0,
            critical_findings: 0, high_findings: 0, new_assets_7d: 0,
            new_reports_30d: 0, average_score: null,
            highest_risk_workspace: null, generated_at: new Date().toISOString(),
          });
        }
        const wsIn = workspaceIds.map(() => "?").join(",");
        const [
          wsRes, domRes, assetRes, vendorRes, brandRes, rptRes,
          findingsRes, newAssetsRes, newRptsRes,
          verifiedDomsRes, unverifiedDomsRes, failedVerifRes,
          avgScoreRes, highRiskRes,
        ] = await Promise.allSettled([
          db.prepare(`SELECT COUNT(*) AS count FROM workspaces WHERE id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_reports WHERE status='completed' AND deleted_at IS NULL AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          // Critical + high findings from the latest completed scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd   ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE f.severity IN ('critical','high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY f.severity
          `).bind(...workspaceIds).all(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_assets WHERE first_seen >= datetime('now','-7 days') AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_reports WHERE status='completed' AND deleted_at IS NULL AND generated_at >= datetime('now','-30 days') AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          // Domain verification counts
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id IN (${wsIn}) AND d.verification_status = 'verified'`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id IN (${wsIn}) AND d.verification_status NOT IN ('verified')`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id IN (${wsIn}) AND d.verification_status = 'failed'`).bind(...workspaceIds).first(),
          // Average score across latest scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT AVG(s.score) AS avg_score
            FROM scans s
            JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
          `).bind(...workspaceIds).first(),
          // Workspace with most critical findings from latest scans
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            ),
            crit AS (
              SELECT s.domain_id, COUNT(*) AS cnt
              FROM findings f
              JOIN scans s ON f.scan_id = s.id
              JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
              WHERE f.severity = 'critical'
              GROUP BY s.domain_id
            ),
            ws_crit AS (
              SELECT wd.workspace_id, SUM(c.cnt) AS total_crit
              FROM crit c
              JOIN workspace_domains wd ON c.domain_id = wd.domain_id
              WHERE wd.workspace_id IN (${wsIn})
              GROUP BY wd.workspace_id
            )
            SELECT w.id, w.name, wc.total_crit
            FROM ws_crit wc
            JOIN workspaces w ON w.id = wc.workspace_id
            ORDER BY wc.total_crit DESC
            LIMIT 1
          `).bind(...workspaceIds).first(),
        ]);

        const findingsBySev = {};
        for (const r of (findingsRes.status === 'fulfilled' ? (findingsRes.value?.results ?? []) : [])) {
          findingsBySev[r.severity] = r.cnt;
        }

        const avgRaw = avgScoreRes.status === 'fulfilled' ? avgScoreRes.value?.avg_score : null;
        const hrw    = highRiskRes.status === 'fulfilled'  ? highRiskRes.value : null;

        return json({
          total_workspaces:       wsRes.status === 'fulfilled'    ? (wsRes.value?.count    ?? 0) : 0,
          total_domains:          domRes.status === 'fulfilled'   ? (domRes.value?.count   ?? 0) : 0,
          total_assets:           assetRes.status === 'fulfilled' ? (assetRes.value?.count ?? 0) : 0,
          total_vendors:          vendorRes.status === 'fulfilled'? (vendorRes.value?.count?? 0) : 0,
          total_brand_candidates: brandRes.status === 'fulfilled' ? (brandRes.value?.count ?? 0) : 0,
          total_reports:          rptRes.status === 'fulfilled'   ? (rptRes.value?.count   ?? 0) : 0,
          critical_findings:      findingsBySev['critical'] ?? 0,
          high_findings:          findingsBySev['high']     ?? 0,
          new_assets_7d:          newAssetsRes.status === 'fulfilled' ? (newAssetsRes.value?.count ?? 0) : 0,
          new_reports_30d:        newRptsRes.status === 'fulfilled'   ? (newRptsRes.value?.count   ?? 0) : 0,
          average_score:          avgRaw != null ? Math.round(avgRaw) : null,
          highest_risk_workspace: hrw ? { id: hrw.id, name: hrw.name, critical_findings: hrw.total_crit } : null,
          verified_domains:       verifiedDomsRes.status === 'fulfilled'   ? (verifiedDomsRes.value?.count   ?? 0) : 0,
          unverified_domains:     unverifiedDomsRes.status === 'fulfilled' ? (unverifiedDomsRes.value?.count ?? 0) : 0,
          verification_failures:  failedVerifRes.status === 'fulfilled'    ? (failedVerifRes.value?.count    ?? 0) : 0,
          generated_at:           new Date().toISOString(),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ workspaces: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");
        const [
          wsRes, domCountRes, assetCountRes, vendorCountRes, brandCountRes,
          findingsRes, scanRes, rptRes,
        ] = await Promise.allSettled([
          db.prepare(`SELECT id, name, created_at FROM workspaces WHERE id IN (${wsIn}) ORDER BY created_at`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          // Critical + high per workspace from latest scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd   ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON s.domain_id = wd.domain_id
            WHERE f.severity IN ('critical','high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY wd.workspace_id, f.severity
          `).bind(...workspaceIds).all(),
          // Latest scan avg score + last_scan_at per workspace
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT wd.workspace_id,
                   AVG(s.score)      AS avg_score,
                   MAX(s.created_at) AS last_scan_at
            FROM scans s
            JOIN lpd              ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON s.domain_id = wd.domain_id
            WHERE s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            GROUP BY wd.workspace_id
          `).bind(...workspaceIds).all(),
          db.prepare(`
            SELECT workspace_id, MAX(generated_at) AS last_report_at
            FROM workspace_reports WHERE status='completed' AND deleted_at IS NULL AND workspace_id IN (${wsIn})
            GROUP BY workspace_id
          `).bind(...workspaceIds).all(),
        ]);

        const workspaces = wsRes.status === 'fulfilled' ? (wsRes.value?.results ?? []) : [];

        // Build lookup maps
        const domMap    = {};
        for (const r of (domCountRes.status    === 'fulfilled' ? (domCountRes.value?.results    ?? []) : [])) domMap[r.workspace_id]    = r.count;
        const assetMap  = {};
        for (const r of (assetCountRes.status  === 'fulfilled' ? (assetCountRes.value?.results  ?? []) : [])) assetMap[r.workspace_id]  = r.count;
        const vendorMap = {};
        for (const r of (vendorCountRes.status === 'fulfilled' ? (vendorCountRes.value?.results ?? []) : [])) vendorMap[r.workspace_id] = r.count;
        const brandMap  = {};
        for (const r of (brandCountRes.status  === 'fulfilled' ? (brandCountRes.value?.results  ?? []) : [])) brandMap[r.workspace_id]  = r.count;

        const findingsMap = {};
        for (const r of (findingsRes.status === 'fulfilled' ? (findingsRes.value?.results ?? []) : [])) {
          if (!findingsMap[r.workspace_id]) findingsMap[r.workspace_id] = { critical: 0, high: 0 };
          findingsMap[r.workspace_id][r.severity] = r.cnt;
        }

        const scanMap = {};
        for (const r of (scanRes.status === 'fulfilled' ? (scanRes.value?.results ?? []) : [])) scanMap[r.workspace_id] = r;

        const rptMap = {};
        for (const r of (rptRes.status === 'fulfilled' ? (rptRes.value?.results ?? []) : [])) rptMap[r.workspace_id] = r.last_report_at;

        const now = Date.now();
        const rows = workspaces.map(ws => {
          const scan    = scanMap[ws.id]    ?? {};
          const findings = findingsMap[ws.id] ?? {};
          const avgScore = scan.avg_score != null ? Math.round(scan.avg_score) : null;

          let risk_rating = null;
          if (avgScore !== null) {
            if      (avgScore >= 80) risk_rating = 'Low';
            else if (avgScore >= 60) risk_rating = 'Medium';
            else if (avgScore >= 40) risk_rating = 'High';
            else                     risk_rating = 'Critical';
          }

          const lastScanAt = scan.last_scan_at ?? null;
          const status = lastScanAt && (now - new Date(lastScanAt).getTime()) < 30 * 24 * 3600 * 1000
            ? 'active' : 'inactive';

          return {
            workspace_id:          ws.id,
            workspace_name:        ws.name,
            domains:               domMap[ws.id]    ?? 0,
            active_assets:         assetMap[ws.id]  ?? 0,
            vendors:               vendorMap[ws.id] ?? 0,
            brand_candidates:      brandMap[ws.id]  ?? 0,
            latest_score:          avgScore,
            security_posture_score: avgScore,
            risk_rating,
            critical_findings:     findings.critical ?? 0,
            high_findings:         findings.high     ?? 0,
            last_scan_at:          lastScanAt,
            last_report_at:        rptMap[ws.id] ?? null,
            status,
          };
        });

        // Sort: critical desc → high desc → score asc (lowest=most risk) → last_scan desc
        rows.sort((a, b) => {
          if (b.critical_findings !== a.critical_findings) return b.critical_findings - a.critical_findings;
          if (b.high_findings     !== a.high_findings)     return b.high_findings     - a.high_findings;
          const sa = a.latest_score ?? 999, sb = b.latest_score ?? 999;
          if (sa !== sb) return sa - sb;
          return (b.last_scan_at ?? '').localeCompare(a.last_scan_at ?? '');
        });

        return json({ workspaces: rows });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/alerts") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db    = env.cybermeters_db;
        const limit = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ alerts: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [eventsRes, brandRes, failedRptsRes] = await Promise.allSettled([
          // Asset events — deduplicated to one row per (workspace, event_type, hostname, day)
          // Uses MAX(created_at) to keep the most recent occurrence of each group.
          db.prepare(`
            SELECT ae.workspace_id, w.name AS workspace_name,
                   ae.event_type,
                   MAX(ae.severity)    AS severity,
                   ae.hostname,
                   ae.description,
                   MAX(ae.created_at) AS created_at
            FROM asset_events ae
            JOIN workspaces w ON w.id = ae.workspace_id
            WHERE ae.workspace_id IN (${wsIn})
            GROUP BY ae.workspace_id, ae.event_type, ae.hostname, date(ae.created_at)
            ORDER BY MAX(ae.created_at) DESC
            LIMIT ?
          `).bind(...workspaceIds, limit).all(),
          // Active brand risks that resolve via DNS
          db.prepare(`
            SELECT ba.workspace_id, w.name AS workspace_name,
                   ba.candidate_domain, ba.risk_level, ba.variant_type, ba.updated_at
            FROM workspace_brand_assets ba
            JOIN workspaces w ON w.id = ba.workspace_id
            WHERE ba.status = 'active' AND ba.dns_resolves = 1
              AND ba.workspace_id IN (${wsIn})
            ORDER BY ba.updated_at DESC
            LIMIT ?
          `).bind(...workspaceIds, Math.ceil(limit / 3)).all(),
          // Failed report generations
          db.prepare(`
            SELECT wr.workspace_id, w.name AS workspace_name,
                   wr.report_type, wr.metadata_json, wr.created_at
            FROM workspace_reports wr
            JOIN workspaces w ON w.id = wr.workspace_id
            WHERE wr.status = 'failed'
              AND wr.deleted_at IS NULL
              AND wr.workspace_id IN (${wsIn})
            ORDER BY wr.created_at DESC
            LIMIT ?
          `).bind(...workspaceIds, Math.ceil(limit / 5)).all(),
        ]);

        const alerts = [];

        for (const r of (eventsRes.status === 'fulfilled' ? (eventsRes.value?.results ?? []) : [])) {
          let title = (r.event_type ?? '').replace(/_/g, ' ');
          const et = r.event_type;
          if      (et === 'new_asset_discovered')      title = `New asset: ${r.hostname ?? ''}`;
          else if (et === 'takeover_risk_detected')    title = `Takeover risk: ${r.hostname ?? ''}`;
          else if (et === 'wildcard_dns_detected')     title = `Wildcard DNS: ${r.hostname ?? ''}`;
          else if (et === 'cloud_storage_detected')    title = `Cloud storage exposed: ${r.hostname ?? ''}`;
          else if (et === 'certificate_expiry_warning')title = `Certificate expiring: ${r.hostname ?? ''}`;
          else if (et === 'certificate_expired')       title = `Certificate expired: ${r.hostname ?? ''}`;
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           et ?? 'unknown',
            severity:       r.severity ?? 'info',
            title,
            description:    r.description ?? null,
            created_at:     r.created_at,
          });
        }

        for (const r of (brandRes.status === 'fulfilled' ? (brandRes.value?.results ?? []) : [])) {
          const sev = (r.risk_level === 'critical' || r.risk_level === 'high') ? r.risk_level : 'medium';
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'brand_risk',
            severity:       sev,
            title:          `Brand risk: ${r.candidate_domain}`,
            description:    `Active typosquat candidate (${r.variant_type ?? 'unknown variant'}) resolving via DNS`,
            created_at:     r.updated_at,
          });
        }

        for (const r of (failedRptsRes.status === 'fulfilled' ? (failedRptsRes.value?.results ?? []) : [])) {
          let errMsg = null;
          try { errMsg = JSON.parse(r.metadata_json)?.error ?? null; } catch {}
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'report_generation_failed',
            severity:       'high',
            title:          `Report generation failed (${r.report_type})`,
            description:    errMsg ?? 'Report generation failed',
            created_at:     r.created_at,
          });
        }

        // Unified sort by created_at desc, then trim to limit
        alerts.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''));

        return json({ alerts: alerts.slice(0, limit) });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/trends") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ trend: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [scanTrendRes, findingsTrendRes, assetTrendRes] = await Promise.allSettled([
          // Score aggregates per day from all completed scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at)     AS day,
                   COUNT(DISTINCT s.id)   AS scans,
                   ROUND(AVG(s.score), 1) AS average_score,
                   MIN(s.score)           AS lowest_score,
                   MAX(s.score)           AS highest_score
            FROM scans s
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.created_at >= datetime('now', '-30 days')
              AND s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            GROUP BY date(s.created_at)
            ORDER BY day
          `).bind(...workspaceIds).all(),
          // Critical + high finding counts per day from scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at) AS day, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.created_at >= datetime('now', '-30 days')
              AND f.severity IN ('critical', 'high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY date(s.created_at), f.severity
            ORDER BY day
          `).bind(...workspaceIds).all(),
          // New assets discovered per day in last 30 days
          db.prepare(`
            SELECT date(first_seen) AS day, COUNT(*) AS new_assets
            FROM workspace_assets
            WHERE first_seen >= datetime('now', '-30 days')
              AND workspace_id IN (${wsIn})
            GROUP BY date(first_seen)
            ORDER BY day
          `).bind(...workspaceIds).all(),
        ]);

        // Merge into a single map keyed by day
        const dayMap = {};

        for (const r of (scanTrendRes.status === 'fulfilled' ? (scanTrendRes.value?.results ?? []) : [])) {
          dayMap[r.day] = {
            date:             r.day,
            scans:            r.scans,
            average_score:    r.average_score,
            lowest_score:     r.lowest_score,
            highest_score:    r.highest_score,
            critical_findings: 0,
            high_findings:    0,
            new_assets:       0,
          };
        }

        for (const r of (findingsTrendRes.status === 'fulfilled' ? (findingsTrendRes.value?.results ?? []) : [])) {
          if (!dayMap[r.day]) dayMap[r.day] = { date: r.day, scans: 0, average_score: null, lowest_score: null, highest_score: null, critical_findings: 0, high_findings: 0, new_assets: 0 };
          if (r.severity === 'critical') dayMap[r.day].critical_findings = r.cnt;
          else if (r.severity === 'high') dayMap[r.day].high_findings   = r.cnt;
        }

        for (const r of (assetTrendRes.status === 'fulfilled' ? (assetTrendRes.value?.results ?? []) : [])) {
          if (!dayMap[r.day]) dayMap[r.day] = { date: r.day, scans: 0, average_score: null, lowest_score: null, highest_score: null, critical_findings: 0, high_findings: 0, new_assets: 0 };
          dayMap[r.day].new_assets = r.new_assets;
        }

        const trend = Object.values(dayMap).sort((a, b) => a.date.localeCompare(b.date));
        return json({ trend });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // GET /api/portfolio/risk — MSP Portfolio Risk Engine v1
    //   Aggregates BRS, supply chain, and vendor intelligence across all workspaces
    //   accessible to the authenticated user. Returns ranked workspace list,
    //   portfolio-level alerts, shared vendor dependencies, and executive summary.
    //   Persists a snapshot to portfolio_risk_snapshots (append-only).
    if (request.method === 'GET' && url.pathname === '/api/portfolio/risk') {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      {
        const plan = await getEffectivePlan(user.id, env);
        if (!hasFeatureEntitlement(plan, 'portfolio_monitoring')) {
          return json({ error: 'plan_feature_required', feature: 'portfolio_monitoring', required_plan: 'business', upgrade_url: '/billing' }, 403);
        }
      }
      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const result = await computePortfolioRisk(user.id, workspaceIds, env);
        return json(result);
      } catch (err) {
        console.error('[portfolio/risk] error:', err);
        return json({ error: 'Internal server error' }, 500);
      }
    }

    // GET /api/workspaces — list all workspaces
    if (request.method === "GET" && url.pathname === "/api/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        // Return only workspaces the caller owns or is a member of. Workspace-
        // bound API tokens are collapsed by getAccessibleWorkspaceIds() to the
        // single token workspace.
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ workspaces: [], default_workspace_id: null });
        const placeholders = workspaceIds.map(() => "?").join(",");
        const result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT w.id, w.name, w.created_at,
                    wm.role
             FROM workspaces w
             LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
             WHERE w.id IN (${placeholders})
             ORDER BY w.created_at ASC`
          )
          .bind(user.id, ...workspaceIds)
          .all();
        const workspaces = result.results ?? [];
        // default_workspace_id: prefer the workspace where the user is owner
        // (earliest-created), falling back to first accessible workspace.
        const ownerWs  = workspaces.find(w => w.role === "owner");
        const defaultWs = ownerWs ?? workspaces[0] ?? null;
        return json({ workspaces, default_workspace_id: defaultWs?.id ?? null });
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // POST /api/workspaces — create a workspace
    if (request.method === "POST" && url.pathname === "/api/workspaces") {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const name = (body.name || "").trim();
      if (!name) {
        return json({ error: "name is required" }, 400);
      }
      if (name.length > 100) return json({ error: "name must be 100 characters or fewer" }, 400);
      const id         = `workspace_${crypto.randomUUID()}`;
      const created_at = new Date().toISOString();
      try {
        // Creator must be authenticated — no anonymous workspace creation.
        const creator = await requireAuth(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401);
        // Workspace creation establishes a new tenant and owner membership;
        // require an interactive user session rather than an API token.
        if (creator.api_token_id) {
          await auditApiTokenSessionRouteDenied(env, creator, request);
          return json({ error: "Session authentication required" }, 403);
        }
        // A workspace must always have an owner. Reject rather than silently
        // writing owner_user_id = NULL, which would create an orphan workspace
        // that no one can access via the UI (see tenant-isolation invariants).
        if (!creator.id) {
          return serverError("workspaces/create", new Error("authenticated session has no user id"),
            "Could not create workspace. Please sign in again and retry.");
        }

        // Entitlement: workspace limit
        const creatorPlan = await getEffectivePlan(creator.id, env);
        const wsUsage = await getEntitlementUsage(creator, env);
        const wsLimits = getPlanLimits(creatorPlan);
        if (wsUsage.workspaces >= wsLimits.workspaces) {
          return json(planLimitExceeded("workspaces", wsLimits.workspaces, wsUsage.workspaces), 403);
        }

        await env.cybermeters_db
          .prepare(`INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)`)
          .bind(id, name, creator.id, created_at)
          .run();
        // Seed owner membership row if creator is authenticated
        if (creator) {
          await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_members (id, workspace_id, user_id, role, created_at)
               VALUES (?, ?, ?, 'owner', datetime('now'))`
            )
            .bind(createId("wm"), id, creator.id)
            .run();
        }
        // Audit: workspace created
        await createAuditEvent(env, {
          workspace_id: id,
          user_id:      creator?.id ?? null,
          event_type:   "workspace_created",
          entity_type:  "workspace",
          entity_id:    id,
          description:  `Workspace "${name}" created`,
          metadata:     { workspace_name: name },
        });
        // Lifecycle: workspace created (once per workspace; owner's verified address).
        await sendLifecycleEmail(env, { type: "lifecycle_workspace_created", user_id: creator?.id ?? null, workspace_id: id, wsName: name }).catch(() => {});
        // Billing: auto-create 14-day Professional trial for the new workspace
        await createWorkspaceTrialSubscription(id, creator.id, env);
        return json({ workspace: { id, name, created_at } }, 201);
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // ── /api/workspaces/:id/assets/* ────────────────────────────────────────
    // Handles list, events, summary, timeline, and per-asset detail.
    const assetsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/assets(\/[^/]*)?$/);
    if (assetsMatch && request.method === "GET") {
      const wsId  = assetsMatch[1];
      const sub   = assetsMatch[2] ?? "";   // "", "/events", "/summary", "/timeline", "/:assetId"

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/assets ───────────────────────────────────
      if (sub === "") {
        const statusFilter = url.searchParams.get("status");
        const limit        = parseBoundedInteger(url.searchParams.get("limit"), 200, 1, 500);
        try {
          const where = statusFilter ? "AND status = ?" : "";
          const binds = statusFilter ? [wsId, statusFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, hostname, asset_type, source,
                      first_seen, last_seen, status, wildcard_dns,
                      ip_addresses, cname, redirect_to, cloud_provider,
                      risk_level, metadata_json, created_at, updated_at
               FROM workspace_assets
               WHERE workspace_id = ? ${where}
               ORDER BY last_seen DESC LIMIT ?`
            )
            .bind(...binds)
            .all();
          return json({ workspace_id: wsId, count: result.results.length, assets: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/events ────────────────────────────
      if (sub === "/events") {
        const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE workspace_id = ?
               ORDER BY created_at DESC LIMIT ?`
            )
            .bind(wsId, limit)
            .all();
          return json({ workspace_id: wsId, count: result.results.length, events: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/summary ───────────────────────────
      if (sub === "/summary") {
        try {
          const [all, active, inactive, rootDomains, subdomains, exposedSvcs, cloudStorage, wildcardAssets, takeoverRisks] =
            await env.cybermeters_db.batch([
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'inactive'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'root_domain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'subdomain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'exposed_service'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'cloud_storage'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND wildcard_dns = 1`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND risk_level IN ('high','critical')`).bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total_assets:       all.results[0]?.n         ?? 0,
            active_assets:      active.results[0]?.n      ?? 0,
            inactive_assets:    inactive.results[0]?.n    ?? 0,
            root_domains:       rootDomains.results[0]?.n ?? 0,
            subdomains:         subdomains.results[0]?.n  ?? 0,
            exposed_services:   exposedSvcs.results[0]?.n ?? 0,
            cloud_storage_assets: cloudStorage.results[0]?.n ?? 0,
            wildcard_assets:    wildcardAssets.results[0]?.n ?? 0,
            takeover_risks:     takeoverRisks.results[0]?.n  ?? 0,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/timeline ──────────────────────────
      if (sub === "/timeline") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT date(created_at) AS day, event_type, COUNT(*) AS count
               FROM asset_events
               WHERE workspace_id = ?
               GROUP BY day, event_type
               ORDER BY day ASC`
            )
            .bind(wsId)
            .all();

          // Pivot rows into { day, new_asset_discovered, asset_reappeared, ... }
          const dayMap = new Map();
          const EVENT_TYPES = [
            "new_asset_discovered", "asset_reappeared", "asset_no_longer_seen",
            "takeover_risk_detected", "wildcard_dns_detected", "cloud_storage_detected",
          ];
          for (const row of result.results) {
            if (!dayMap.has(row.day)) {
              const entry = { day: row.day };
              for (const t of EVENT_TYPES) entry[t] = 0;
              dayMap.set(row.day, entry);
            }
            if (EVENT_TYPES.includes(row.event_type)) {
              dayMap.get(row.day)[row.event_type] = row.count;
            }
          }
          return json({ workspace_id: wsId, timeline: [...dayMap.values()] });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/:assetId ──────────────────────────
      {
        const assetId = sub.slice(1);   // strip leading "/"
        try {
          const asset = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, hostname, asset_type, source,
                      first_seen, last_seen, status, wildcard_dns,
                      ip_addresses, cname, redirect_to, cloud_provider,
                      risk_level, metadata_json, created_at, updated_at
               FROM workspace_assets
               WHERE id = ? AND workspace_id = ?`
            )
            .bind(assetId, wsId)
            .first();
          if (!asset) return json({ error: "Asset not found" }, 404);

          const eventsResult = await env.cybermeters_db
            .prepare(
              `SELECT id, scan_id, event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE asset_id = ? AND workspace_id = ?
               ORDER BY created_at DESC LIMIT 50`
            )
            .bind(assetId, wsId)
            .all();

          return json({ asset, events: eventsResult.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── /api/workspaces/:id/alerts/* ────────────────────────────────────────
    // GET /api/workspaces/:id/alerts          — list alerts, filterable by severity
    // GET /api/workspaces/:id/alerts/summary  — severity counts + last alert timestamp
    const alertsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/alerts(\/[^/]*)?$/);
    if (alertsMatch && request.method === "GET") {
      const wsId = alertsMatch[1];
      const sub  = alertsMatch[2] ?? "";   // "" or "/summary"

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/alerts/summary ─────────────────────────────
      if (sub === "/summary") {
        try {
          const [total, critical, high, medium, low, latest] =
            await env.cybermeters_db.batch([
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ?`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'critical'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'high'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'medium'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'low'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT sent_at FROM asset_alert_records WHERE workspace_id = ? ORDER BY sent_at DESC LIMIT 1`)
                .bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total:              total.results[0]?.n    ?? 0,
            critical:           critical.results[0]?.n ?? 0,
            high:               high.results[0]?.n     ?? 0,
            medium:             medium.results[0]?.n   ?? 0,
            low:                low.results[0]?.n      ?? 0,
            last_alert_at:      latest.results[0]?.sent_at ?? null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/alerts ─────────────────────────────────────
      if (sub === "") {
        const severityFilter = url.searchParams.get("severity");
        const limit          = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

        if (severityFilter && !VALID_SEVERITIES.has(severityFilter)) {
          return json({ error: "Invalid severity value" }, 400);
        }

        try {
          const where  = severityFilter ? "AND severity = ?" : "";
          const binds  = severityFilter ? [wsId, severityFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, scan_id, domain, severity,
                      event_counts, top_hostnames, sent_at
               FROM asset_alert_records
               WHERE workspace_id = ? ${where}
               ORDER BY sent_at DESC
               LIMIT ?`
            )
            .bind(...binds)
            .all();

          // Parse JSON columns so consumers don't have to
          const alerts = (result.results || []).map((row) => ({
            ...row,
            event_counts:  row.event_counts  ? JSON.parse(row.event_counts)  : {},
            top_hostnames: row.top_hostnames ? JSON.parse(row.top_hostnames) : [],
          }));

          return json({ workspace_id: wsId, count: alerts.length, alerts });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // Unknown sub-resource
      return json({ error: "Not found" }, 404);
    }

    // ── /api/workspaces/:id/posture[/timeline] ──────────────────────────────
    // GET /api/workspaces/:id/posture          — current attack surface posture snapshot
    // GET /api/workspaces/:id/posture/timeline — daily metric series (last 90 days)
    //
    // Both routes use existing data only (workspace_assets, asset_events, scans,
    // findings, workspace_domains).  No new scanning modules, no scoring changes.
    const postureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/posture(\/timeline)?$/);
    if (postureMatch && request.method === "GET") {
      const wsId    = postureMatch[1];
      const isTimeline = !!postureMatch[2];   // true → /posture/timeline

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── Attack Surface Size classification ────────────────────────────────
      // 0-10 = Small, 11-50 = Medium, 51-200 = Large, 201+ = Very Large
      function classifyAttackSurface(assetCount) {
        if (assetCount <= 10)  return "Small";
        if (assetCount <= 50)  return "Medium";
        if (assetCount <= 200) return "Large";
        return "Very Large";
      }

      // ── Risk trend helper ─────────────────────────────────────────────────
      // Higher score = safer. Score drop = risk going up.
      function scoreTrend(avgLast, avgPrev) {
        if (avgLast === null || avgPrev === null) return "stable";
        const delta = avgLast - avgPrev;
        if (delta >= 3)  return "down";   // score improved → risk down
        if (delta <= -3) return "up";     // score fell → risk up
        return "stable";
      }

      // ── GET /api/workspaces/:id/posture ───────────────────────────────────
      if (!isTimeline) {
        try {
          const [
            totalRow,
            activeRow,
            newAssets30dRow,
            removedAssets30dRow,
            criticalNow30dRow,
            criticalPrev30dRow,
            avgScoreLast30dRow,
            avgScorePrev30dRow,
          ] = await env.cybermeters_db.batch([

            // Total assets ever tracked in this workspace
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`)
              .bind(wsId),

            // Currently active assets
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Assets first discovered in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND first_seen >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Assets removed (no-longer-seen events) in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = ? AND event_type = 'asset_no_longer_seen' AND created_at >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Critical findings from scans in the last 30 days (via workspace_domains join)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Critical findings from scans in the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the last 30 days (for risk trend)
            env.cybermeters_db
              .prepare(
                `SELECT AVG(s.score) AS avg_score
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT AVG(s.score) AS avg_score
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),
          ]);

          const totalAssets    = totalRow.results[0]?.n          ?? 0;
          const activeAssets   = activeRow.results[0]?.n         ?? 0;
          const newAssets30d   = newAssets30dRow.results[0]?.n   ?? 0;
          const removedAssets30d = removedAssets30dRow.results[0]?.n ?? 0;
          const criticalNow    = criticalNow30dRow.results[0]?.n    ?? 0;
          const criticalPrev   = criticalPrev30dRow.results[0]?.n   ?? 0;
          const avgScoreLast30d = avgScoreLast30dRow.results[0]?.avg_score ?? null;
          const avgScorePrev30d = avgScorePrev30dRow.results[0]?.avg_score ?? null;

          const trend = scoreTrend(avgScoreLast30d, avgScorePrev30d);

          return json({
            workspace_id:                wsId,
            attack_surface_size:         classifyAttackSurface(totalAssets),
            total_assets:                totalAssets,
            active_assets:               activeAssets,
            new_assets_30d:              newAssets30d,
            removed_assets_30d:          removedAssets30d,
            asset_growth_30d:            newAssets30d - removedAssets30d,
            critical_findings:           criticalNow,
            critical_findings_change_30d: criticalNow - criticalPrev,
            risk_trend:                  trend,
            score_trend:                 trend,   // same signal; both exposed for consumer flexibility
            avg_score_last_30d:          avgScoreLast30d !== null ? Math.round(avgScoreLast30d) : null,
            avg_score_prev_30d:          avgScorePrev30d !== null ? Math.round(avgScorePrev30d) : null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/posture/timeline ──────────────────────────
      // Returns one entry per day for the last 90 days.
      // asset_count is derived by applying daily deltas backward from today's total.
      if (isTimeline) {
        try {
          const [totalActiveRow, eventRows, findingRows] = await env.cybermeters_db.batch([

            // Current active asset count — used as the anchor for backward derivation
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Per-day new / removed event counts for the last 90 days
            env.cybermeters_db
              .prepare(
                `SELECT date(created_at) AS day,
                        SUM(CASE WHEN event_type = 'new_asset_discovered'   THEN 1 ELSE 0 END) AS new_assets,
                        SUM(CASE WHEN event_type = 'asset_no_longer_seen'   THEN 1 ELSE 0 END) AS removed_assets
                 FROM asset_events
                 WHERE workspace_id = ?
                   AND created_at >= datetime('now', '-90 days')
                 GROUP BY day
                 ORDER BY day ASC`
              )
              .bind(wsId),

            // Per-day critical findings count (from scans run that day)
            env.cybermeters_db
              .prepare(
                `SELECT date(s.created_at) AS day, COUNT(f.id) AS critical_findings
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-90 days')
                 GROUP BY day
                 ORDER BY day ASC`
              )
              .bind(wsId),
          ]);

          // Build day-keyed maps from query results
          const eventMap    = new Map();
          const findingMap  = new Map();

          for (const row of (eventRows.results || [])) {
            eventMap.set(row.day, { new_assets: row.new_assets ?? 0, removed_assets: row.removed_assets ?? 0 });
          }
          for (const row of (findingRows.results || [])) {
            findingMap.set(row.day, row.critical_findings ?? 0);
          }

          // Collect every day that appears in either dataset
          const daySet = new Set([...eventMap.keys(), ...findingMap.keys()]);
          const days   = [...daySet].sort();

          // Derive asset_count by walking forward from the earliest day.
          // anchor = total active assets today; walk backward from end → start to seed the
          // starting count, then walk forward to fill in each day's snapshot.
          let runningCount = totalActiveRow.results[0]?.n ?? 0;

          // First pass: walk backward from today to compute the count at the start of `days`
          for (let i = days.length - 1; i >= 0; i--) {
            const d = days[i];
            const ev = eventMap.get(d) ?? { new_assets: 0, removed_assets: 0 };
            runningCount -= ev.new_assets;
            runningCount += ev.removed_assets;
          }

          // Second pass: walk forward, incrementally updating the running count per day
          const timeline = [];
          for (const day of days) {
            const ev = eventMap.get(day) ?? { new_assets: 0, removed_assets: 0 };
            runningCount += ev.new_assets;
            runningCount -= ev.removed_assets;
            timeline.push({
              day,
              asset_count:       Math.max(0, runningCount),
              new_assets:        ev.new_assets,
              removed_assets:    ev.removed_assets,
              critical_findings: findingMap.get(day) ?? 0,
            });
          }

          return json({ workspace_id: wsId, days: timeline.length, timeline });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── Certificate Intelligence routes ────────────────────────────────────
    // GET /api/workspaces/:id/certificates
    //   Returns latest certificate_intelligence per domain in workspace.
    //   Each entry: { domain, certificate_risk_level, days_until_expiry,
    //     expires_at, total_certificates_seen, issued_for_sensitive_hosts,
    //     wildcard_dns, suspicious_certificate_signals, ct_sources }
    //
    // GET /api/workspaces/:id/certificates/timeline
    //   Returns certificate-related asset_events from the last 90 days,
    //   grouped by day: [{ day, events:[{event_type, severity, description}] }]
    const certMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/certificates(\/timeline)?$/
    );
    if (certMatch && request.method === "GET") {
      const wsId        = certMatch[1];
      const isTimeline  = !!certMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // ── /certificates/timeline ──────────────────────────────────────────
      if (isTimeline) {
        if (domainIds.length === 0) {
          return json({ workspace_id: wsId, days: 90, timeline: [] });
        }

        // Query asset_events for cert-related event types in this workspace
        let events;
        try {
          const cutoff = new Date(Date.now() - 90 * 86_400_000).toISOString();
          const r = await env.cybermeters_db
            .prepare(
              `SELECT event_type, severity, description, hostname,
                      DATE(created_at) AS day
               FROM asset_events
               WHERE workspace_id = ?
                 AND event_type IN (
                       'certificate_sensitive_host_detected',
                       'certificate_expiring_soon',
                       'certificate_growth_detected',
                       'certificate_new_detected',
                       'certificate_new_san_detected',
                       'certificate_new_issuer_detected'
                     )
                 AND created_at >= ?
               ORDER BY created_at DESC`
            )
            .bind(wsId, cutoff)
            .all();
          events = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        // Group by day
        const dayMap = new Map();
        for (const ev of events) {
          if (!dayMap.has(ev.day)) dayMap.set(ev.day, []);
          dayMap.get(ev.day).push({
            event_type:  ev.event_type,
            severity:    ev.severity,
            description: ev.description,
            hostname:    ev.hostname || null,
          });
        }

        const timeline = [...dayMap.entries()]
          .sort(([a], [b]) => b.localeCompare(a))
          .map(([day, evts]) => ({ day, events: evts }));

	        let issuer_history = [];
	        let certificate_timeline = [];
	        let ca_concentration = buildCaConcentrationAnalytics([], {
	          source: "historical_certificate_observations",
	        });
	        let churn = {
	          certificates_last_30_days: 0,
	          certificates_last_90_days: 0,
	          classification: "low",
        };
        try {
          const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
          const ninetyDaysAgo = new Date(Date.now() - 90 * 86_400_000).toISOString();

          const [issuerRows, certRows, churn30, churn90] = await Promise.all([
            env.cybermeters_db
              .prepare(
                `SELECT issuer, MIN(first_seen) AS first_seen,
                        MAX(last_seen) AS last_seen, COUNT(*) AS certificates
                 FROM certificate_observations
                 WHERE workspace_id = ?
                 GROUP BY issuer
                 ORDER BY first_seen ASC`
              )
              .bind(wsId)
              .all(),
            env.cybermeters_db
              .prepare(
                `SELECT subject, issuer, san_count, expires_at,
                        first_seen, last_seen
                 FROM certificate_observations
                 WHERE workspace_id = ?
                 ORDER BY first_seen DESC`
              )
              .bind(wsId)
              .all(),
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(*) AS n FROM certificate_observations
                 WHERE workspace_id = ? AND first_seen >= ?`
              )
              .bind(wsId, thirtyDaysAgo)
              .first(),
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(*) AS n FROM certificate_observations
                 WHERE workspace_id = ? AND first_seen >= ?`
              )
              .bind(wsId, ninetyDaysAgo)
              .first(),
          ]);

	          issuer_history = issuerRows.results || [];
	          certificate_timeline = certRows.results || [];
	          ca_concentration = buildCaConcentrationAnalytics(certificate_timeline, {
	            source: "historical_certificate_observations",
	          });
	          const count30 = churn30?.n ?? 0;
	          const count90 = churn90?.n ?? 0;
          const classification =
            count90 >= 25 ? "unusual" :
            count90 >= 10 ? "high" :
            count90 >= 3  ? "medium" : "low";
          churn = {
            certificates_last_30_days: count30,
            certificates_last_90_days: count90,
            classification,
          };
        } catch { /* v2 migration may not be applied yet */ }

	        return json({ workspace_id: wsId, days: 90, timeline, certificate_timeline, issuer_history, churn, ca_concentration });
	      }

      // ── /certificates ───────────────────────────────────────────────────
      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, certificates: [] });
      }

      // Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id, domain_id FROM scans WHERE domain_id = ? " +
              "AND status = 'completed' ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanRows = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value : null))
        .filter(Boolean);

      // Fetch R2 reports in parallel
	      const r2Results = await Promise.allSettled(
	        scanRows.map((s) => env.cybermeters_reports.get(`reports/${s.id}.json`))
	      );

	      const caConcentrationByDomain = new Map();
	      try {
	        const observed = await env.cybermeters_db
	          .prepare(
	            `SELECT domain_id, issuer, first_seen, last_seen
	             FROM certificate_observations
	             WHERE workspace_id = ?`
	          )
	          .bind(wsId)
	          .all();
	        const byDomain = new Map();
	        for (const row of (observed.results || [])) {
	          if (!row.domain_id) continue;
	          if (!byDomain.has(row.domain_id)) byDomain.set(row.domain_id, []);
	          byDomain.get(row.domain_id).push(row);
	        }
	        for (const [domainId, rows] of byDomain.entries()) {
	          caConcentrationByDomain.set(domainId, buildCaConcentrationAnalytics(rows, {
	            source: "historical_certificate_observations",
	          }));
	        }
	      } catch { /* certificate_observations may not exist in older environments */ }

	      const certificates = [];
	      for (let i = 0; i < r2Results.length; i++) {
        if (r2Results[i].status !== "fulfilled" || !r2Results[i].value) continue;
        let report;
        try { report = await r2Results[i].value.json(); } catch { continue; }

        const ci = report?.modules?.certificate_intelligence;
        if (!ci) continue;

        certificates.push({
          domain:                       report.domain || null,
          certificate_risk_level:       ci.certificate_risk_level,
	          certificate_status:           ci.certificate_status,
	          issuer:                       ci.issuer || null,
	          issuer_normalized:            ci.issuer_normalized || normalizeCertificateIssuer(ci.issuer || null),
	          ca_owner:                     ci.ca_owner || mapCertificateAuthorityOwner(normalizeCertificateIssuer(ci.issuer || null)),
	          subject:                      ci.subject || null,
	          san_count:                    ci.san_count || 0,
	          san_hostnames:                ci.san_hostnames || [],
	          days_until_expiry:            ci.days_until_expiry,
	          expires_at:                   ci.expires_at,
	          lifecycle:                    ci.lifecycle || buildCertificateLifecycleIntelligence(ci),
	          key_algorithm:                ci.key_algorithm || "unknown",
	          key_size_bits:                ci.key_size_bits || "unknown",
	          signature_algorithm:          ci.signature_algorithm || "unknown",
	          crypto_metadata:              ci.crypto_metadata || {
	            key_algorithm: ci.key_algorithm || "unknown",
	            key_size_bits: ci.key_size_bits || "unknown",
	            signature_algorithm: ci.signature_algorithm || "unknown",
	          },
	          self_signed:                  ci.self_signed ?? detectSelfSignedCertificate(ci.issuer || null, ci.subject || null),
	          ca_concentration:             caConcentrationByDomain.get(scanRows[i]?.domain_id) || ci.ca_concentration || buildCaConcentrationAnalytics(ci.issuer ? [ci.issuer] : []),
	          total_certificates_seen:      ci.total_certificates_seen,
	          issued_for_sensitive_hosts:   ci.issued_for_sensitive_hosts || [],
          wildcard_dns:                 ci.wildcard_dns,
          wildcard_warning:             ci.wildcard_warning || null,
          ct_sources:                   ci.ct_sources || {},
          suspicious_certificate_signals: ci.suspicious_certificate_signals || [],
          scan_id:                      scanRows[i]?.id || null,
        });
      }

      // Sort: critical first, then high, medium, low
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      certificates.sort(
        (a, b) => (riskOrder[a.certificate_risk_level] ?? 5) - (riskOrder[b.certificate_risk_level] ?? 5)
      );

      return json({
        workspace_id: wsId,
        total:        certificates.length,
        certificates,
      });
    }

    // ── SaaS Exposure Discovery route ─────────────────────────────────────
    // GET /api/workspaces/:id/saas-exposure
    //   Filters: ?exposure_type=login_portal|email_gateway|saas_tenant|
    //                           support_portal|crm_portal|dev_portal|ecommerce_portal
    //            ?risk_level=low|medium|high
    //            ?category=email_identity|collaboration|crm|support|ecommerce
    //   Returns: { workspace_id, total, high_risk, exposures: [...] }
    const saasExpMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/saas-exposure$/
    );
    if (saasExpMatch && request.method === "GET") {
      const wsId = saasExpMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, high_risk: 0, exposures: [] });
      }

      // 2. Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge saas_exposure.exposures across all reports (dedup by name)
      const seen      = new Set();
      const exposures = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const mod = report?.modules?.saas_exposure;
        if (!mod?.exposures?.length) continue;

        for (const exp of mod.exposures) {
          if (seen.has(exp.name)) continue;
          seen.add(exp.name);
          exposures.push({
            name:           exp.name,
            category:       exp.category,
            exposure_type:  exp.exposure_type,
            risk_level:     exp.risk_level,
            portal_url:     exp.portal_url     || null,
            admin_url:      exp.admin_url      || null,
            tenant_hint:    exp.tenant_hint    || null,
            tenant_url:     exp.tenant_url     || null,
            attack_surface: exp.attack_surface || null,
            confidence:     exp.confidence,
            domain:         report.domain      || null,
          });
        }
      }

      // Sort high → medium → low
      const riskOrder = { high: 0, medium: 1, low: 2 };
      exposures.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      // Apply filters
      const filterExpType  = url.searchParams.get("exposure_type");
      const filterRisk     = url.searchParams.get("risk_level");
      const filterCategory = url.searchParams.get("category");

      const filtered = exposures.filter((e) => {
        if (filterExpType  && e.exposure_type !== filterExpType)  return false;
        if (filterRisk     && e.risk_level    !== filterRisk)     return false;
        if (filterCategory && e.category      !== filterCategory) return false;
        return true;
      });

      return json({
        workspace_id: wsId,
        total:     filtered.length,
        high_risk: filtered.filter((e) => e.risk_level === "high").length,
        exposures: filtered,
      });
    }

    // ── Cloud Asset Discovery routes ───────────────────────────────────────
    // GET /api/workspaces/:id/cloud-assets
    //   Filters: ?category=storage|cdn|serverless|paas|hosting
    //            ?provider=<name>  ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/cloud-assets/summary
    //   Returns: { workspace_id, total, by_category:{storage,cdn,serverless,paas,hosting},
    //              high_risk, medium_risk, low_risk, providers:[{name,count}] }
    const cloudAssetsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cloud-assets(\/summary)?$/
    );
    if (cloudAssetsMatch && request.method === "GET") {
      const wsId      = cloudAssetsMatch[1];
      const isSummary = !!cloudAssetsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        const empty = isSummary
          ? { workspace_id: wsId, total: 0,
              by_category: { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 },
              high_risk: 0, medium_risk: 0, low_risk: 0, providers: [] }
          : { workspace_id: wsId, total: 0, assets: [] };
        return json(empty);
      }

      // 2. Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge cloud_storage_discovery.findings across all reports (dedup by asset+provider)
      const seen   = new Set();
      const assets = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const cloudMod = report?.modules?.cloud_storage_discovery;
        if (!cloudMod?.findings?.length) continue;

        for (const f of cloudMod.findings) {
          const key = `${f.asset}::${f.provider}`;
          if (seen.has(key)) continue;
          seen.add(key);
          assets.push({
            asset:        f.asset,
            provider:     f.provider,
            category:     f.category     || "storage",  // backward-compat for old reports
            service_type: f.service_type || "unknown",
            evidence:     f.evidence,
            risk_level:   f.risk_level,
            domain:       report.domain  || null,
          });
        }
      }

      // Sort: high first
      const riskOrder = { high: 0, medium: 1, low: 2 };
      assets.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      if (isSummary) {
        const by_category = { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 };
        const providerCount = {};
        let high_risk = 0, medium_risk = 0, low_risk = 0;

        for (const a of assets) {
          const cat = a.category;
          if (cat in by_category) by_category[cat]++;
          if (a.risk_level === "high")        high_risk++;
          else if (a.risk_level === "medium") medium_risk++;
          else if (a.risk_level === "low")    low_risk++;
          providerCount[a.provider] = (providerCount[a.provider] || 0) + 1;
        }

        const providers = Object.entries(providerCount)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count);

        return json({
          workspace_id: wsId,
          total: assets.length,
          by_category,
          high_risk,
          medium_risk,
          low_risk,
          providers,
        });
      }

      // Apply optional filters
      const filterCategory = url.searchParams.get("category");
      const filterProvider = url.searchParams.get("provider");
      const filterRisk     = url.searchParams.get("risk_level");

      const filtered = assets.filter((a) => {
        if (filterCategory && a.category   !== filterCategory) return false;
        if (filterProvider && a.provider   !== filterProvider) return false;
        if (filterRisk     && a.risk_level !== filterRisk)     return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Admin Surfaces route ───────────────────────────────────────────────
    // GET /api/workspaces/:id/admin-surfaces
    //   Filters: ?severity=critical|high|medium|low
    //            ?category=admin_panel|monitoring|vpn|collaboration|infrastructure|source_control
    //            ?confidence=confirmed|high|medium
    //   Returns: { workspace_id, total, critical, high, medium, services: [...] }
    //
    // Reads the admin_surface_detection module from the latest completed scan
    // R2 report for each domain in the workspace, then merges and deduplicates.
    const adminSurfacesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/admin-surfaces$/
    );
    if (adminSurfacesMatch && request.method === "GET") {
      const wsId = adminSurfacesMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get all domain IDs for this workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({
          workspace_id: wsId,
          total: 0, critical: 0, high: 0, medium: 0, services: [],
        });
      }

      // 2. Latest completed scan per domain (parallel D1 queries)
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Extract and merge admin_surface_detection.services across reports
      const seen     = new Set();
      const services = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const adminMod = report?.modules?.admin_surface_detection;
        if (!adminMod?.services?.length) continue;

        for (const svc of adminMod.services) {
          const key = `${svc.hostname}::${svc.product}`;
          if (seen.has(key)) continue;
          seen.add(key);
          services.push({
            hostname:   svc.hostname,
            url:        svc.url        || `https://${svc.hostname}`,
            product:    svc.product,
            category:   svc.category,
            severity:   svc.severity   || svc.risk_level,
            confidence: svc.confidence,
            risk_level: svc.risk_level,
            ip_address: svc.ip_address || null,
            server:     svc.server     || null,
            title:      svc.title      || null,
            domain:     report.domain  || null,
          });
        }
      }

      // 5. Apply query-string filters
      const filterSeverity   = url.searchParams.get("severity");
      const filterCategory   = url.searchParams.get("category");
      const filterConfidence = url.searchParams.get("confidence");

      const filtered = services.filter((s) => {
        if (filterSeverity   && s.severity   !== filterSeverity)   return false;
        if (filterCategory   && s.category   !== filterCategory)   return false;
        if (filterConfidence && s.confidence !== filterConfidence)  return false;
        return true;
      });

      // Sort: confirmed+critical first
      const confOrder = { confirmed: 0, high: 1, medium: 2, low: 3 };
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      filtered.sort((a, b) => {
        const cd = (confOrder[a.confidence] ?? 4) - (confOrder[b.confidence] ?? 4);
        if (cd !== 0) return cd;
        return (riskOrder[a.risk_level] ?? 4) - (riskOrder[b.risk_level] ?? 4);
      });

      return json({
        workspace_id: wsId,
        total:    filtered.length,
        critical: filtered.filter((s) => s.risk_level === "critical").length,
        high:     filtered.filter((s) => s.risk_level === "high").length,
        medium:   filtered.filter((s) => s.risk_level === "medium").length,
        services: filtered,
      });
    }

    // ── Third-Party Asset Discovery routes ────────────────────────────────
    // GET /api/workspaces/:id/third-party-assets
    //   Filters: ?category=email|crm|support|collaboration|marketing|ecommerce
    //            ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/third-party-assets/summary
    //   Returns: { workspace_id, total, email, crm, support, collaboration,
    //              marketing, ecommerce, high_risk, medium_risk, low_risk }
    const tpaMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/third-party-assets(\/summary)?$/
    );
    if (tpaMatch && request.method === "GET") {
      const wsId      = tpaMatch[1];
      const isSummary = !!tpaMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Read all workspace_vendors for this workspace; remap + filter in JS.
      // workspace_vendors uses the vendor-risk category taxonomy; we remap here.
      let rows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name, category, source, evidence, confidence,
                    risk_level, status, first_seen, last_seen
             FROM workspace_vendors
             WHERE workspace_id = ? AND status = 'active'`
          )
          .bind(wsId)
          .all();
        rows = r.results || [];
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // Remap to third-party taxonomy; skip infrastructure/cloud/hosting
      const assets = [];
      for (const row of rows) {
        const tpCategory = remapToThirdPartyCategory(row.vendor_name, row.category);
        if (!tpCategory) continue;

        let parsedEvidence = [];
        try { parsedEvidence = JSON.parse(row.evidence); } catch { /* ignore */ }

        assets.push({
          name:       row.vendor_name,
          category:   tpCategory,
          source:     row.source,
          evidence:   parsedEvidence,
          confidence: row.confidence,
          risk_level: row.risk_level,
          first_seen: row.first_seen,
          last_seen:  row.last_seen,
        });
      }

      // Sort: email → crm → collaboration → support → marketing → ecommerce
      const catOrder = {
        email: 0, crm: 1, collaboration: 2, support: 3, marketing: 4, ecommerce: 5,
      };
      assets.sort((a, b) => (catOrder[a.category] ?? 9) - (catOrder[b.category] ?? 9));

      if (isSummary) {
        const summary = {
          workspace_id:  wsId,
          total:         assets.length,
          email:         0,
          crm:           0,
          support:       0,
          collaboration: 0,
          marketing:     0,
          ecommerce:     0,
          high_risk:     0,
          medium_risk:   0,
          low_risk:      0,
        };
        for (const a of assets) {
          if (a.category in summary) summary[a.category]++;
          if (a.risk_level === "high")        summary.high_risk++;
          else if (a.risk_level === "medium") summary.medium_risk++;
          else if (a.risk_level === "low")    summary.low_risk++;
        }
        return json(summary);
      }

      // Apply optional filters from query string
      const filterCategory = url.searchParams.get("category");
      const filterRisk     = url.searchParams.get("risk_level");
      const filtered = assets.filter((a) => {
        if (filterCategory && a.category !== filterCategory) return false;
        if (filterRisk     && a.risk_level !== filterRisk)   return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Vendor Inventory routes ────────────────────────────────────────────
    // GET /api/workspaces/:id/vendors
    //   Filters: ?status=active|inactive  ?risk_level=low|medium|high
    //            ?category=infrastructure|cloud|email_identity|hosting|saas|
    //                      support|collaboration|ecommerce|certificate_authority
    //   Returns: { workspace_id, count, vendors: [...] }
    //
    // GET /api/workspaces/:id/vendors/summary
    //   Returns: { total_vendors, active_vendors, inactive_vendors,
    //              infrastructure, cloud, email_identity, hosting, saas,
    //              support, ecommerce, certificate_authority,
    //              high_risk, medium_risk, low_risk }
    const vendorsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/vendors(\/summary)?$/);
    if (vendorsMatch && request.method === "GET") {
      const wsId      = vendorsMatch[1];
      const isSummary = !!vendorsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      if (isSummary) {
        // Aggregate counts directly from D1 — one query
        let rows;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT status, category, risk_level, COUNT(*) AS cnt
               FROM workspace_vendors
               WHERE workspace_id = ?
               GROUP BY status, category, risk_level`
            )
            .bind(wsId)
            .all();
          rows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        const summary = {
          workspace_id:    wsId,
          total_vendors:   0,
          active_vendors:  0,
          inactive_vendors:0,
          infrastructure:  0,
          cloud:           0,
          email_identity:  0,
          hosting:         0,
          saas:            0,
          support:         0,
          ecommerce:       0,
          certificate_authority: 0,
          // vendor_relationship categories (Phase 7k)
          analytics:       0,
          payments:        0,
          crm:             0,
          identity:        0,
          collaboration:   0,
          cdn:             0,
          security:        0,
          // identity cross-population (Phase 8f)
          identity_provider: 0,
          high_risk:       0,
          medium_risk:     0,
          low_risk:        0,
        };

        // We need unique vendor counts, not row counts (a vendor appears once).
        // First collect unique vendor names per bucket using a Set approach via JS.
        // Re-query for unique vendor names with their attributes.
        let vendorRows;
        try {
          const r2 = await env.cybermeters_db
            .prepare(
              `SELECT vendor_name, category, risk_level, status
               FROM workspace_vendors
               WHERE workspace_id = ?`
            )
            .bind(wsId)
            .all();
          vendorRows = r2.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        for (const v of vendorRows) {
          summary.total_vendors++;
          if (v.status === "active")   summary.active_vendors++;
          else                         summary.inactive_vendors++;
          const cat = v.category;
          if (cat in summary) summary[cat]++;
          const rl = v.risk_level;
          if (rl === "high")   summary.high_risk++;
          else if (rl === "medium") summary.medium_risk++;
          else if (rl === "low")    summary.low_risk++;
        }

        // Backward-compatible aliases used by the current frontend.
        summary.active = summary.active_vendors;
        summary.by_risk = {
          high: summary.high_risk,
          medium: summary.medium_risk,
          low: summary.low_risk,
        };

        return json(summary);
      }

      // ── GET /api/workspaces/:id/vendors ──
      const params    = url.searchParams;
      const filterStatus   = params.get("status");
      const filterRisk     = params.get("risk_level");
      const filterCategory = params.get("category");

      // Build WHERE clause dynamically
      const whereClauses = ["workspace_id = ?"];
      const binds        = [wsId];

      if (filterStatus)   { whereClauses.push("status = ?");     binds.push(filterStatus); }
      if (filterRisk)     { whereClauses.push("risk_level = ?"); binds.push(filterRisk); }
      if (filterCategory) { whereClauses.push("category = ?");   binds.push(filterCategory); }

      const whereSQL = whereClauses.join(" AND ");
      const scoredWhereSQL = whereSQL
        .replace(/\bworkspace_id\b/g, "wv.workspace_id")
        .replace(/\bstatus\b/g, "wv.status")
        .replace(/\brisk_level\b/g, "wv.risk_level")
        .replace(/\bcategory\b/g, "wv.category");

      let vendorRows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT wv.id, wv.vendor_name, wv.vendor_name AS name, wv.category,
                    wv.source, wv.evidence, wv.confidence,
                    wv.risk_level, wv.status, wv.first_seen, wv.last_seen,
                    wv.metadata_json,
                    vrs.score AS persisted_score,
                    vrs.category_multiplier,
                    vrs.concentration_penalty
             FROM workspace_vendors wv
             LEFT JOIN vendor_risk_scores vrs
               ON vrs.vendor_id = wv.id
              AND vrs.workspace_id = wv.workspace_id
             WHERE ${scoredWhereSQL}
             ORDER BY
               COALESCE(vrs.score, 0) DESC,
               CASE wv.risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               wv.vendor_name`
          )
          .bind(...binds)
          .all();
        vendorRows = r.results || [];
      } catch {
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT id, vendor_name, vendor_name AS name, category, source,
                      evidence, confidence, risk_level, status, first_seen,
                      last_seen, metadata_json
               FROM workspace_vendors
               WHERE ${whereSQL}
               ORDER BY
                 CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                 vendor_name`
            )
            .bind(...binds)
            .all();
          vendorRows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      const aggregate = computeWorkspaceVendorRisk(vendorRows);
      const vendors = aggregate.scored_vendors
        .slice()
        .sort((a, b) => b.score - a.score || String(a.vendor_name || a.name).localeCompare(String(b.vendor_name || b.name)))
        .map((row) => {
        const evidence = (() => { try { return JSON.parse(row.evidence); } catch { return []; } })();
        const sources = [...new Set([...(row._sources || []), ...getVendorSources(row)].filter(Boolean))];
        return {
          id: row.id,
          name: row.name || row.vendor_name,
          vendor_name: row.name || row.vendor_name,
          vendor_key: row.vendor_key || normalizeVendorKey(row.name || row.vendor_name),
          category: row.normalized_category || normalizeVendorRiskCategory(row.category, row.name || row.vendor_name, row.source),
          normalized_category: row.normalized_category || normalizeVendorRiskCategory(row.category, row.name || row.vendor_name, row.source),
          raw_category: row.category,
          source: row.source,
          sources,
          confidence: row.confidence,
          confidence_score: row.confidence_score ?? confidenceToScore(row.confidence),
          signal_weight: row.signal_weight ?? signalWeightForVendor(row),
          score: row.score ?? row.persisted_score ?? 0,
          category_multiplier: row.category_multiplier ?? 1,
          concentration_penalty: row.concentration_penalty ?? 0,
          risk_level: row.risk_level,
          status: row.status,
          first_seen: row.first_seen,
          last_seen: row.last_seen,
          evidence,
          metadata: (() => { try { return JSON.parse(row.metadata_json || "{}"); } catch { return {}; } })(),
        };
      });

      return json({
        workspace_id: wsId,
        count: vendors.length,
        vendors,
        top_vendors: aggregate.top_vendors.map((v) => ({
          id: v.id,
          name: v.vendor_name,
          vendor_key: v.vendor_key,
          category: v.normalized_category,
          score: v.score,
          risk_level: v.risk_level,
        })),
        concentration_risk: aggregate.concentration_risk,
        workspace_vendor_risk_score: aggregate.workspace_vendor_risk_score,
      });
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

    // ── GET /api/validation/benchmark — QA-only, no frontend ────────────
    //
    // Enterprise Validation Dataset — expected behaviour for mature domains.
    // Used as regression check: if header or email scoring findings appear
    // on these domains, validation_status = "regression_detected".
    //
    // Subrequest budget: headers module may use 2 subrequests (GET + HEAD
    // fallback) when bot protection is detected, so limit to 1 domain per call.
    //   1 domain × (5 DNS + 3 SSL + 2 headers + 15 email) ≈ 25 subrequests.
    //
    // Usage:
    //   GET /api/validation/benchmark              → test google.com (default)
    //   GET /api/validation/benchmark?domain=X     → test domain X
    //   GET /api/validation/benchmark?all=1        → meta: list all benchmark domains

    // ENTERPRISE_BENCHMARK and ENTERPRISE_DOMAINS are module-level constants
    // (defined near the top of this file, after SECURITY_HEADERS).

    if (url.pathname === "/api/validation/benchmark" && request.method === "GET") {
      // QA-only diagnostic that runs live scan modules against an arbitrary
      // domain — authenticated + rate-limited so anonymous traffic can't use
      // it to burn Worker CPU/subrequests (it was previously fully public).
      const bmUser = await requireAuth(request, env);
      if (!bmUser) return json({ error: "Unauthorized" }, 401);
      const bmRl = await consumeApiRateLimit(
        env, [{ scope: "user", scope_id: bmUser.id }], "validation_benchmark", 10, 3600
      );
      if (bmRl) return json(bmRl.body, bmRl.status);
      try {
        // ?all=1 → return the benchmark domain list without running scans
        if (url.searchParams.get("all") === "1") {
          return json({ benchmark_domains: ENTERPRISE_BENCHMARK, note: "Use ?domain=X to test a specific domain." });
        }

        const targetDomain = url.searchParams.get("domain") ?? "google.com";
        const baseline     = ENTERPRISE_BENCHMARK.find(b => b.domain === targetDomain) ?? null;

        // Run core modules — parallel, within subrequest budget
        const [dnsR, sslR, headersR, emailR] = await Promise.allSettled([
          runDnsModule(targetDomain),
          runSslModule(targetDomain),
          runHeadersModule(targetDomain),
          runEmailModule(targetDomain),
        ]);

        const mods = {
          dns:            dnsR.status     === "fulfilled" ? dnsR.value     : { error: "module failed" },
          ssl:            sslR.status     === "fulfilled" ? sslR.value     : { error: "module failed" },
          headers:        headersR.status === "fulfilled" ? headersR.value : { error: "module failed" },
          email_security: emailR.status   === "fulfilled" ? emailR.value   : { error: "module failed" },
          brand_monitoring: null, // opt-out: brand findings not applicable to lightweight public scan
        };

        const { score, risk_level, findings } = computeScore(mods, targetDomain);

        const scoringFindings  = findings.filter(f => f.score_impact < 0);
        const headerFindings   = scoringFindings.filter(f => f.module === "headers");
        const emailFindings    = scoringFindings.filter(f => f.module === "email_security");
        const infoFindings     = findings.filter(f => f.score_impact === 0);
        const emailApp         = isEmailApplicable(targetDomain, mods.dns);

        // ── Regression check ─────────────────────────────────────────────
        const regressionViolations = [];
        if (baseline) {
          if (headerFindings.length > baseline.max_header_findings) {
            regressionViolations.push(
              `header_findings: got ${headerFindings.length}, max allowed ${baseline.max_header_findings}`
            );
          }
          if (emailFindings.length > baseline.max_email_findings) {
            regressionViolations.push(
              `email_findings: got ${emailFindings.length}, max allowed ${baseline.max_email_findings}`
            );
          }
          // Only fail the redirect check when:
          //   • the redirect chain was observable (not blocked by firewall/bot protection)
          //   • the scoring engine did NOT downgrade the finding to info/low-confidence
          //     (which happens for enterprise edge uncertain domains where the HTTP probe
          //     returned a non-redirecting response but HTTPS headers probed successfully)
          //   • validation_uncertain is false
          // If any of these conditions apply, we cannot conclude the redirect is missing.
          const redirectValidated   = mods.ssl?.http_redirect_chain?.http_redirect_validated !== false;
          const redirectDowngraded  = findings.some(f =>
            f.id           === "ssl_no_http_redirect" &&
            f.severity     === "info"                 &&
            f.confidence   === "low"                  &&
            Number(f.score_impact ?? 0) === 0
          );
          const validationUncertain = !!mods.headers?.validation_uncertain;
          if (
            baseline.expect_https_redirect &&
            redirectValidated              &&
            !mods.ssl?.http_redirects_to_https &&
            !redirectDowngraded            &&
            !validationUncertain
          ) {
            regressionViolations.push("expected http_redirects_to_https = true (chain was observable)");
          }
        }

        const passed             = regressionViolations.length === 0;
        const regressionDetected = !passed;

        return json({
          domain:                     targetDomain,
          score,
          risk_level,
          passed,
          regression_detected:        regressionDetected,
          regression_violations:      regressionViolations,
          baseline:                   baseline ?? "no baseline — custom domain",
          email_applicable:           emailApp.applicable,
          email_applicability_reason: emailApp.reason ?? null,
          http_redirects_to_https:    mods.ssl?.http_redirects_to_https ?? null,
          http_redirect_chain:        mods.ssl?.http_redirect_chain ?? null,
          http_redirect_validated:    mods.ssl?.http_redirect_chain?.http_redirect_validated ?? null,
          headers_final_https:        mods.headers?.final_https ?? null,
          headers_status_code:        mods.headers?.status_code ?? null,
          validation_uncertain:       mods.headers?.validation_uncertain ?? false,
          bot_protection_signals:     mods.headers?.bot_protection_signals ?? [],
          raw_capture:                mods.headers?.raw_capture ?? null,
          finding_count:              scoringFindings.length,
          header_findings:            headerFindings.length,   // renamed from header_finding_count
          email_findings:             emailFindings.length,    // renamed from email_finding_count
          info_count:                 infoFindings.length,
          findings: findings.map(f => ({
            id:           f.id,
            module:       f.module,
            severity:     f.severity,
            confidence:   f.confidence ?? null,
            title:        f.title,
            score_impact: f.score_impact,
          })),
          note: "One domain per call (subrequest budget). Use ?domain=X to target a specific domain.",
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

	    // ── GET /api/workspaces/:id/usage ────────────────────────────────────────
	    const workspaceUsageMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/usage$/);
	    if (workspaceUsageMatch && request.method === "GET") {
	      const workspaceId = workspaceUsageMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const periodStart = getMonthStart();
	        const billingUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
	        const plan = await getEffectivePlan(billingUserId, env);
	        const limits = getPlanLimits(plan);
	        const [
	          scansUsed,
	          scansCompleted,
	          reportsGenerated,
	          scheduledReportsGenerated,
	          reportRuns,
	          reportCount,
	          activeAssets,
	        ] = await Promise.all([
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(DISTINCT s.id) AS n
	             FROM scans s
	             LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
	             WHERE s.created_at >= ?
	               AND (s.workspace_id = ? OR (s.workspace_id IS NULL AND wd.workspace_id = ?))`
	          ).bind(periodStart, workspaceId, workspaceId).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(DISTINCT s.id) AS n
	             FROM scans s
	             LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
	             WHERE s.status = 'completed' AND s.created_at >= ?
	               AND (s.workspace_id = ? OR (s.workspace_id IS NULL AND wd.workspace_id = ?))`
	          ).bind(periodStart, workspaceId, workspaceId).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_reports
	             WHERE workspace_id = ? AND status = 'completed'
	               AND deleted_at IS NULL AND created_at >= ?`
	          ).bind(workspaceId, periodStart).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_reports
	             WHERE workspace_id = ? AND status = 'completed'
	               AND deleted_at IS NULL AND report_type IN ('weekly_executive', 'monthly_executive')
	               AND created_at >= ?`
	          ).bind(workspaceId, periodStart).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM report_schedule_runs
	             WHERE workspace_id = ? AND created_at >= ?`
	          ).bind(workspaceId, periodStart).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_reports
	             WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL`
	          ).bind(workspaceId).first(),
	          env.cybermeters_db.prepare(
	            `SELECT COUNT(*) AS n FROM workspace_assets
	             WHERE workspace_id = ? AND status = 'active'`
	          ).bind(workspaceId).first(),
	        ]);
	        const completedReportCount = Number(reportCount?.n ?? 0);
	        const estimatedReportBytes = 250_000;
	        const storageBytes = completedReportCount * estimatedReportBytes;

	        createAuditEvent(env, {
	          workspace_id: workspaceId,
	          user_id: user.id,
	          event_type: "usage_viewed",
	          entity_type: "workspace",
	          entity_id: workspaceId,
	          description: "Workspace usage metering viewed",
	          metadata: { period_start: periodStart },
	        }).catch(() => {});

	        return json({
	          workspace_id: workspaceId,
	          plan,
	          period_start: periodStart,
	          current_period: {
	            scans_used: Number(scansUsed?.n ?? 0),
	            scans_completed: Number(scansCompleted?.n ?? 0),
	            reports_generated: Number(reportsGenerated?.n ?? 0),
	            scheduled_reports_generated: Number(scheduledReportsGenerated?.n ?? 0),
	            report_schedule_runs: Number(reportRuns?.n ?? 0),
	            storage_bytes: storageBytes,
	            storage_estimated: true,
	            active_assets: Number(activeAssets?.n ?? 0),
	            workspace_report_count: completedReportCount,
	          },
	          limits,
	        });
	      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── GET /api/workspaces/:id/summary ──────────────────────────────────────
	    const summaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/summary$/);
    if (summaryMatch && request.method === "GET") {
      const workspaceId = summaryMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id, name FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        const [
          domainsResult,
          assetsResult,
          vendorsResult,
          scoreResult,
          findingsResult,
          lastScanResult,
          lastReportResult,
          reportsCountResult,
        ] = await Promise.allSettled([
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare(`
              WITH lpd AS (
                SELECT domain_id, MAX(created_at) AS mx
                FROM scans
                WHERE workspace_id = ? AND status = 'completed'
                GROUP BY domain_id
              )
              SELECT AVG(s.score) AS avg_score
              FROM scans s JOIN lpd ON lpd.domain_id = s.domain_id AND lpd.mx = s.created_at
            `)
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare(`
              WITH lpd AS (
                SELECT domain_id, MAX(created_at) AS mx
                FROM scans
                WHERE workspace_id = ? AND status = 'completed'
                GROUP BY domain_id
              )
              SELECT
                SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings,
                SUM(CASE WHEN f.severity = 'high'     THEN 1 ELSE 0 END) AS high_findings
              FROM findings f
              JOIN scans s ON s.id = f.scan_id
              JOIN lpd ON lpd.domain_id = s.domain_id AND lpd.mx = s.created_at
            `)
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(created_at) AS last_scan_at FROM scans WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(generated_at) AS last_report_at FROM workspace_reports WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_reports WHERE workspace_id = ? AND deleted_at IS NULL")
            .bind(workspaceId)
            .first(),
        ]);

        const v = (r) => (r.status === "fulfilled" ? r.value : null);

        return json({
          workspace_id:      ws.id,
          workspace_name:    ws.name,
          domains:           v(domainsResult)?.cnt          ?? 0,
          active_assets:     v(assetsResult)?.cnt           ?? 0,
          vendors:           v(vendorsResult)?.cnt          ?? 0,
          latest_score:      v(scoreResult)?.avg_score != null ? Math.round(v(scoreResult).avg_score) : null,
          critical_findings: v(findingsResult)?.critical_findings ?? 0,
          high_findings:     v(findingsResult)?.high_findings     ?? 0,
          last_scan_at:      v(lastScanResult)?.last_scan_at      ?? null,
          last_report_at:    v(lastReportResult)?.last_report_at  ?? null,
          reports_count:     v(reportsCountResult)?.cnt           ?? 0,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/health ────────────────────────────────────────
    const healthMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/health$/);
    if (healthMatch && request.method === "GET") {
      const workspaceId = healthMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        const [domR, assetR, reportR, scanR] = await Promise.allSettled([
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_reports WHERE workspace_id = ? AND deleted_at IS NULL")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(created_at) AS last_scan_at FROM scans WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
        ]);

        const v = (r) => (r.status === "fulfilled" ? r.value : null);

        const domains_monitored  = v(domR)?.cnt    ?? 0;
        const assets_discovered  = v(assetR)?.cnt  ?? 0;
        const reports_generated  = v(reportR)?.cnt ?? 0;
        const lastScanAt         = v(scanR)?.last_scan_at ?? null;

        let latest_scan_age_hours = null;
        if (lastScanAt) {
          const ageMs = Date.now() - new Date(lastScanAt.includes("T") ? lastScanAt : lastScanAt + "Z").getTime();
          latest_scan_age_hours = Math.round(ageMs / 3_600_000);
        }

        // workspace_status
        let workspace_status;
        if (domains_monitored === 0) {
          workspace_status = "no_domains";
        } else if (!lastScanAt) {
          workspace_status = "no_scans";
        } else if (latest_scan_age_hours !== null && latest_scan_age_hours > 168) {
          workspace_status = "stale"; // older than 7 days
        } else {
          workspace_status = "active";
        }

        // monitoring_health
        let monitoring_health;
        if (workspace_status === "no_domains" || workspace_status === "no_scans") {
          monitoring_health = "stale";
        } else if (latest_scan_age_hours !== null && latest_scan_age_hours > 72) {
          monitoring_health = "warning";
        } else {
          monitoring_health = "healthy";
        }

        return json({
          workspace_status,
          domains_monitored,
          assets_discovered,
          reports_generated,
          latest_scan_age_hours,
          latest_report_age_hours: null, // reserved — not critical path
          monitoring_health,
        });
      } catch (e) {
        return serverError("api", e);
      }
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

    // ── POST /api/workspaces/:id/domains/import ───────────────────────────────
    const importMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/import$/);
    if (importMatch && request.method === "POST") {
      const workspaceId = importMatch[1];
      // RBAC: admin or above required to import domains
      const importUser = await requireAuth(request, env);
      if (!importUser) return json({ error: "Unauthorized" }, 401);
      const importAccess = await requireWorkspaceRole(importUser, workspaceId, "domain:import", env);
      if (!importAccess) return json({ error: "Forbidden — admin role required to import domains" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

        const rawList = Array.isArray(body.domains) ? body.domains : [];
        if (rawList.length === 0) return json({ error: "domains array is required and must not be empty" }, 400);
        if (rawList.length > 500) return json({ error: "Maximum 500 domains per import" }, 400);

        // Normalize + validate
        const invalid  = [];
        const valid    = [];
        const seen     = new Set();
        for (const raw of rawList) {
          if (typeof raw !== "string") { invalid.push(String(raw)); continue; }
          const d = normalizeHostname(raw.trim().toLowerCase());
          if (!d || !isValidDomain(d)) { invalid.push(raw.trim()); continue; }
          if (seen.has(d)) continue; // input-level dup
          seen.add(d);
          valid.push(d);
        }

        if (valid.length === 0) {
          return json({ imported: 0, skipped: 0, invalid: invalid.length, total: rawList.length });
        }

        // Entitlement: per-workspace limit + account-level limit — check before touching DB
        const importBillingUserId = await getWorkspaceBillingUserId(workspaceId, importUser.id, env);
        const impPlan = await getEffectivePlan(importBillingUserId, env);
        const impUsage  = await getEntitlementUsage(importUser, env, workspaceId);
        const impLimits = getPlanLimits(impPlan);
        // (a) Per-workspace headroom
        const wsRemaining = impLimits.domains_per_workspace - impUsage.domains_in_workspace;
        if (wsRemaining <= 0) {
          return json(planLimitExceeded("domains", impLimits.domains, impUsage.domains_in_workspace), 403);
        }
        // (b) Account-level headroom across all owned workspaces
        const impOwnerAcct = await getAccountUsage(importBillingUserId, env);
        const acctRemaining = impLimits.domains - impOwnerAcct.domains;
        if (acctRemaining <= 0) {
          return json(planLimitExceeded("domains", impLimits.domains, impOwnerAcct.domains), 403);
        }
        // Trim to whichever headroom is smaller
        const remaining = Math.min(wsRemaining, acctRemaining);
        // Trim valid list to what fits
        const validTrimmed = valid.slice(0, remaining);
        const trimmedCount = valid.length - validTrimmed.length;
        const validToImport = validTrimmed;

        // Find existing domains in this workspace
        const existingRows = await env.cybermeters_db
          .prepare("SELECT d.domain FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ?")
          .bind(workspaceId)
          .all();
        const existingSet = new Set((existingRows.results || []).map((r) => r.domain));

        let imported = 0;
        let skipped  = 0;

        for (const domain of validToImport) {
          if (existingSet.has(domain)) { skipped++; continue; }

          // Find or create domain record.
          // domains.domain has no UNIQUE constraint in D1, so ON CONFLICT(domain) is invalid.
          // Use a safe SELECT-then-INSERT pattern instead.
          let domainId;
          const existingDom = await env.cybermeters_db
            .prepare("SELECT id FROM domains WHERE domain = ? AND user_id = ? LIMIT 1")
            .bind(domain, importUser.id)
            .first();
          if (existingDom) {
            domainId = existingDom.id;
          } else {
            domainId = createId("dom");
            await env.cybermeters_db
              .prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)")
              .bind(domainId, importUser.id, domain)
              .run();
          }

          // Link to workspace
          const already = await env.cybermeters_db
            .prepare("SELECT workspace_id FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
            .bind(workspaceId, domainId)
            .first();

          if (already) { skipped++; continue; }

          await env.cybermeters_db
            .prepare("INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)")
            .bind(workspaceId, domainId)
            .run();

          imported++;
        }

        // Audit: domain import completed
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      importUser?.id ?? null,
          event_type:   "domain_imported",
          entity_type:  "domain",
          description:  `Imported ${imported} domain${imported !== 1 ? "s" : ""} (${skipped} skipped, ${invalid.length} invalid)`,
          metadata:     { imported, skipped, invalid: invalid.length, total: rawList.length },
        });

        return json({ imported, skipped, invalid: invalid.length, trimmed: trimmedCount, total: rawList.length }, 200);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ════════════════════════════════════════════════════════════════════════
    // DMARC Report Ingestion & Sender Intelligence v1 — manual import + reads.
    // All routes are workspace-scoped and validate domain ownership. Additive.
    // ════════════════════════════════════════════════════════════════════════

    // ── POST /api/workspaces/:wsid/domains/:domain/dmarc-reports/import ───────
    const dmarcImportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-reports\/import$/);
    if (dmarcImportMatch && request.method === "POST") {
      const workspaceId = dmarcImportMatch[1];
      const domain = decodeURIComponent(dmarcImportMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const body = await request.json().catch(() => null);
        if (!body || typeof body.xml !== "string") {
          return json({ imported: false, error: "missing_xml", message: "Request must include an 'xml' string." }, 400);
        }

        // Shared ingestion pipeline (parse → dedupe → insert → rollup → audit).
        // Manual paste keeps its existing response shape and is NOT subject to
        // strict policy-domain matching (interactive source, user owns context).
        const result = await ingestDmarcReport(env, {
          workspaceId, domain, source: "manual_paste", xmlString: body.xml,
          filename: body.filename, actorUserId: user.id, domainId,
          enforceDomainMatch: false,
        });
        if (!result.ok) {
          return json({ imported: false, error: result.error, message: result.message }, result.status || 422);
        }
        if (result.duplicate) {
          return json({ imported: false, duplicate: true, message: "Report already imported" });
        }
        return json({ imported: true, duplicate: false, report_id: result.reportId,
          records_imported: result.records, messages_imported: result.messages,
          sources_updated: result.sourcesUpdated });
      } catch (e) {
        return serverError("dmarc-import", e, "DMARC report import failed.");
      }
    }

    // ── DMARC signed-upload endpoint (token) management ───────────────────────
    // One active upload key per workspace+domain. Raw token shown once on
    // create/rotate; only the SHA-256 hash is ever stored. Min permission:
    // scan:create (same as manual import — no stronger workspace-admin
    // permission exists in this codebase for domain-scoped data writes).
    const ingestEpRotateMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-ingest-endpoint\/rotate$/);
    const ingestEpRevokeMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-ingest-endpoint\/revoke$/);
    const ingestEpMatch       = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-ingest-endpoint$/);
    const dmarcDnsCheckMatch  = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-dns-check$/);

    // GET .../dmarc-dns-check — live, read-only DMARC RUA verification.
    if (dmarcDnsCheckMatch && request.method === "GET") {
      const workspaceId = dmarcDnsCheckMatch[1];
      const domain = decodeURIComponent(dmarcDnsCheckMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({
          domain, status: "unauthorized", message: "Authentication is required.",
        }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({
          domain, status: "unauthorized", message: "Workspace access is required.",
        }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({
          domain, status: "domain_not_in_workspace",
          message: "Domain not found in this workspace.",
        }, 404);
        return json(await verifyDmarcDnsSetup(env, workspaceId, domain));
      } catch {
        return json({
          domain, status: "dns_lookup_failed",
          message: "The DMARC DNS lookup could not be completed.",
        }, 502);
      }
    }

    // GET .../spf-analysis — live, read-only SPF chain health ("SPF surgeon").
    // Walks include:/redirect= targets, counts the RFC 7208 10-lookup budget,
    // flags void includes, and suggests a flattened record.
    // ── Remediation Registry (plug-and-play auto-fixes) ──────────────────────
    //   GET  .../remediations              → every gap + live detection (read role)
    //   GET  .../remediations/:id          → detail + the exact generated fix
    //   GET  .../remediations/:id/verify    → live re-check (is the fix live now?)
    // 'hosted' actions (DMARC today) point at their dedicated managed flow; the
    // 'apply' execution tier for other hosted records lands with the record_type
    // generalisation. This surface is read-only, so it is safe and low-risk.
    const remediationsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/remediations(?:\/([a-z0-9_]+)(\/verify)?)?$/);
    if (remediationsMatch && request.method === "GET") {
      const workspaceId = remediationsMatch[1];
      const domain = decodeURIComponent(remediationsMatch[2]).toLowerCase();
      const actionId = remediationsMatch[3] || null;
      const wantVerify = Boolean(remediationsMatch[4]);
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const ctx = { workspaceId, domain, env };

        if (!actionId) {
          // Detect every registered action in parallel; one slow/failing probe
          // never sinks the list.
          const items = await Promise.all(REMEDIATION_REGISTRY.map(async (action) => {
            try { return remediationToApi(action, await action.detect(ctx)); }
            catch { return remediationToApi(action, { applicable: true, present: false, ok: false, evidence: { error: "probe_failed" } }); }
          }));
          return json({ domain, remediations: items });
        }

        const action = getRemediation(actionId);
        if (!action) return json({ error: "Unknown remediation" }, 404);

        if (wantVerify) {
          let ok = false;
          try { ok = await action.verify(ctx); } catch { ok = false; }
          return json({ id: action.id, verified: ok });
        }

        let detection = null;
        try { detection = await action.detect(ctx); } catch { detection = null; }
        return json({
          remediation: remediationToApi(action, detection),
          fix: action.generate(ctx),
        });
      } catch (e) {
        return serverError("remediations", e, "Could not evaluate remediations.");
      }
    }

    const spfAnalysisMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/spf-analysis$/);
    if (spfAnalysisMatch && request.method === "GET") {
      const workspaceId = spfAnalysisMatch[1];
      const domain = decodeURIComponent(spfAnalysisMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({
          domain, status: "unauthorized", message: "Authentication is required.",
        }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({
          domain, status: "unauthorized", message: "Workspace access is required.",
        }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({
          domain, status: "domain_not_in_workspace",
          message: "Domain not found in this workspace.",
        }, 404);
        return json(await analyzeSpfChain(domain));
      } catch {
        return json({
          domain, status: "dns_lookup_failed",
          message: "The SPF analysis could not be completed.",
        }, 502);
      }
    }

    // ── Hosted DMARC (Hosted Records Engine — Phase A + B) ────────────────────
    //   POST   .../hosted-dmarc           → create the managed record (manage role)
    //   GET    .../hosted-dmarc           → state + ramp readiness
    //   GET    .../hosted-dmarc/verify    → live two-sided verification
    //   PUT    .../hosted-dmarc           → policy change {policy, pct, confirm} (manage + paid)
    //   POST   .../hosted-dmarc/rollback  → restore previous value (manage; never paywalled)
    //   PUT    .../hosted-dmarc/autopilot → {enabled} self-driving ramp (manage + paid)
    //   DELETE .../hosted-dmarc           → request removal (grace-protected)
    const hostedDmarcMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/hosted-dmarc(?:\/(verify|rollback|autopilot))?$/);
    if (hostedDmarcMatch) {
      const workspaceId = hostedDmarcMatch[1];
      const domain = decodeURIComponent(hostedDmarcMatch[2]).toLowerCase();
      const sub = hostedDmarcMatch[3] || null;
      const isVerify = sub === "verify";
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM hosted_dns_records
                    WHERE workspace_id = ? AND domain = ? AND record_type = 'dmarc' LIMIT 1`)
          .bind(workspaceId, domain).first();

        // Workspace plan (owner's plan) gates policy management; create,
        // monitoring, verification and rollback stay free.
        const planRow = await env.cybermeters_db
          .prepare(`SELECT u.plan FROM workspaces w JOIN users u ON u.id = w.owner_user_id WHERE w.id = ?`)
          .bind(workspaceId).first();
        const policyAllowed = planAllowsHostedPolicyManagement(planRow?.plan);

        if (request.method === "GET" && !sub) {
          if (!existing) return json({ record: null, policy_management_available: policyAllowed });
          const rate = await getHostedDmarcPassRate(env, workspaceId, domain);
          const changeMs = parseServerMsHosted(existing.last_change_at);
          const readiness = evaluateRampReadiness({
            pass_rate: rate.pass_rate,
            total_messages: rate.total,
            days_since_change: changeMs != null ? Math.floor((Date.now() - changeMs) / 86400000) : null,
          });
          return json({
            record: hostedDnsRecordToApi(existing),
            policy_management_available: policyAllowed,
            compliance: { pass_rate: rate.pass_rate, total_messages: rate.total, window_days: 7 },
            readiness,
          });
        }

        if (request.method === "PUT" && !sub) {
          if (!existing) return json({ error: "No hosted DMARC record for this domain yet." }, 404);
          if (!policyAllowed) return json({
            error: "Managed policy changes are available on paid plans. Monitoring stays free.",
            code: "upgrade_required",
          }, 403);
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const policy = String(body.policy || "").trim().toLowerCase();
          const pct = body.pct == null ? 100 : Number(body.pct);
          const targetIdx = DMARC_RAMP_LADDER.findIndex((s) => s.policy === policy
            && (policy === "none" || s.pct === pct));
          if (targetIdx < 0) {
            return json({ error: "Choose a ladder step: none, quarantine (pct 5/25/50/100), or reject." }, 400);
          }
          const currentIdx = dmarcRampStepIndex(existing.current_value);
          const tightening = targetIdx > currentIdx;
          if (tightening && body.confirm !== true) {
            const rate = await getHostedDmarcPassRate(env, workspaceId, domain);
            const changeMs = parseServerMsHosted(existing.last_change_at);
            const readiness = evaluateRampReadiness({
              pass_rate: rate.pass_rate,
              total_messages: rate.total,
              days_since_change: changeMs != null ? Math.floor((Date.now() - changeMs) / 86400000) : null,
            });
            if (!readiness.ready) {
              return json({
                error: "Compliance is not ready for a stricter policy yet.",
                code: "readiness_check_failed",
                readiness,
              }, 409);
            }
          }
          const rateNow = await getHostedDmarcPassRate(env, workspaceId, domain);
          const applied = await applyHostedDmarcChange(env, existing, {
            policy, pct, userId: user.id, source: "manual", passRateNow: rateNow.pass_rate,
          });
          if (!applied.ok) {
            const msg = applied.reason === "change_budget_exceeded"
              ? "Daily policy-change limit reached for this record. Try again tomorrow."
              : applied.reason === "not_published"
                ? "The managed record is not published yet — wait for setup to complete."
                : applied.reason === "no_change"
                  ? "The record already has this policy."
                  : applied.reason === "change_in_progress"
                    ? "Another change is still being confirmed for this record. It settles automatically within the hour."
                    : applied.reason === "verify_mismatch"
                      ? "The change was submitted but could not be confirmed yet. It will settle automatically — check back shortly."
                      : "The policy change could not be applied. Please try again shortly.";
            return json({ error: msg, code: applied.reason }, 409);
          }
          const row = await env.cybermeters_db
            .prepare(`SELECT * FROM hosted_dns_records WHERE id = ?`).bind(existing.id).first();
          return json({ record: hostedDnsRecordToApi(row) });
        }

        if (request.method === "POST" && sub === "rollback") {
          if (!existing) return json({ error: "No hosted DMARC record for this domain." }, 404);
          const rolled = await rollbackHostedDmarc(env, existing, { userId: user.id, source: "manual" });
          if (!rolled.ok) {
            const msg = rolled.reason === "nothing_to_roll_back"
              ? "There is no previous value to restore."
              : "The rollback could not be applied. Please try again shortly.";
            return json({ error: msg, code: rolled.reason }, 409);
          }
          const row = await env.cybermeters_db
            .prepare(`SELECT * FROM hosted_dns_records WHERE id = ?`).bind(existing.id).first();
          return json({ record: hostedDnsRecordToApi(row) });
        }

        if (request.method === "PUT" && sub === "autopilot") {
          if (!existing) return json({ error: "No hosted DMARC record for this domain yet." }, 404);
          if (!policyAllowed) return json({
            error: "Self-driving DMARC is available on paid plans.",
            code: "upgrade_required",
          }, 403);
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const enabled = body.enabled === true ? 1 : 0;
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_records SET autopilot = ?, updated_at = ? WHERE id = ?`)
            .bind(enabled, new Date().toISOString(), existing.id).run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: enabled ? "hosted_dmarc_autopilot_enabled" : "hosted_dmarc_autopilot_disabled",
            entity_type: "hosted_dns_record", entity_id: existing.id,
            description: `Self-driving DMARC ${enabled ? "enabled" : "disabled"} for ${domain}`,
          });
          return json({ record: hostedDnsRecordToApi({ ...existing, autopilot: enabled }) });
        }

        if (request.method === "GET" && isVerify) {
          if (!existing) return json({ error: "No hosted DMARC record for this domain yet." }, 404);
          const checks = await verifyHostedDmarcRecord(existing);
          const next = nextHostedDnsStatus(existing, checks);
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_records SET status = ?, last_verified_at = ?, updated_at = ? WHERE id = ?`)
            .bind(next, nowIso, nowIso, existing.id).run();
          return json({
            record: hostedDnsRecordToApi({ ...existing, status: next, last_verified_at: nowIso }),
            checks,
          });
        }

        if (request.method === "POST" && !sub) {
          if (existing) return json({ record: hostedDnsRecordToApi(existing), already_exists: true });

          // The managed record must keep reporting flowing: a CyberMeters RUA
          // address is required before we take over the value.
          const endpoint = await env.cybermeters_db
            .prepare(`SELECT address_local FROM dmarc_ingest_endpoints
                      WHERE workspace_id = ? AND domain = ? AND status = 'active' AND revoked_at IS NULL
                      ORDER BY created_at DESC LIMIT 1`)
            .bind(workspaceId, domain).first();
          if (!endpoint?.address_local) {
            return json({ error: "Create a CyberMeters reporting address for this domain first." }, 400);
          }
          const inboundDomain = normalizeInboundRecipientDomain(env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT)
            || RUA_INBOUND_DOMAIN_DEFAULT;
          const recommendedRua = `mailto:${endpoint.address_local}@${inboundDomain}`;

          // Mirror the customer's live record (merged with our RUA); default to
          // monitor-only when none exists. Phase A never changes policy.
          let liveRecord = null;
          try {
            const res = await dnsQuery(`_dmarc.${domain}`, "TXT");
            if (Number(res?.Status ?? 1) === 0) {
              liveRecord = (res?.Answer || [])
                .map((a) => normalizeDnsTxtValue(a?.data))
                .find((v) => /^v=DMARC1(?:\s*;|$)/i.test(v)) || null;
            }
          } catch { /* fall through to the default value */ }
          const value = buildDmarcDnsRecommendedValue(liveRecord, recommendedRua);
          const parsed = parseDmarcRecord(value, 1);
          if (!parsed.valid) return json({ error: "A valid managed record could not be produced for this domain." }, 422);

          const id = newHostedDnsRecordId();
          const hostedName = `${id}.${hostedDmarcSubdomain(env)}`;
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`INSERT INTO hosted_dns_records
                        (id, workspace_id, domain, record_type, hosted_name, current_value,
                         status, created_by, created_at, updated_at)
                      VALUES (?, ?, ?, 'dmarc', ?, ?, 'pending_dns', ?, ?, ?)`)
            .bind(id, workspaceId, domain, hostedName, value, user.id, nowIso, nowIso).run();

          // Try the Cloudflare create immediately; the sweep retries on failure.
          let row = { id, workspace_id: workspaceId, domain, record_type: "dmarc",
            hosted_name: hostedName, current_value: value, status: "pending_dns",
            last_verified_at: null, created_at: nowIso };
          const created = await cfCreateHostedTxt(env, hostedName, value);
          if (created.ok) {
            await env.cybermeters_db
              .prepare(`UPDATE hosted_dns_records SET cf_record_id = ?, status = 'awaiting_cname', updated_at = ? WHERE id = ?`)
              .bind(created.cf_record_id, nowIso, id).run();
            row = { ...row, status: "awaiting_cname" };
          }

          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "hosted_dmarc_created", entity_type: "hosted_dns_record", entity_id: id,
            description: `Hosted DMARC record created for ${domain}`,
          });

          return json({
            record: hostedDnsRecordToApi(row),
            instructions: {
              step: `Replace any existing TXT at _dmarc.${domain} with this CNAME`,
              cname_name: `_dmarc.${domain}`,
              cname_target: hostedName,
              note: "After the CNAME resolves, CyberMeters manages the record value for you. Reporting keeps flowing to your CyberMeters address.",
            },
          }, 201);
        }

        if (request.method === "DELETE" && !sub) {
          if (!existing) return json({ error: "No hosted DMARC record for this domain." }, 404);
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_records SET status = 'pending_removal', updated_at = ? WHERE id = ?`)
            .bind(nowIso, existing.id).run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "hosted_dmarc_removal_requested", entity_type: "hosted_dns_record", entity_id: existing.id,
            description: `Hosted DMARC removal requested for ${domain}`,
          });
          return json({
            record: hostedDnsRecordToApi({ ...existing, status: "pending_removal" }),
            message: `Remove the CNAME at _dmarc.${domain} (or replace it with your own TXT record). The hosted value stays live until your DNS no longer depends on it, for up to ${HOSTED_DNS_REMOVAL_GRACE_DAYS} days.`,
          });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("hosted-dmarc", e, "Could not update the hosted DMARC record.");
      }
    }

    // POST .../dmarc-ingest-endpoint — create (idempotent; never duplicates).
    if (ingestEpMatch && request.method === "POST") {
      const workspaceId = ingestEpMatch[1];
      const domain = decodeURIComponent(ingestEpMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const inboundDomain = env.RUA_INBOUND_DOMAIN || "reports.cybermeters.com";

        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? AND status = 'active'
                    ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        if (existing) {
          // Idempotent: never re-issue a token. Backfill an inbound RUA address
          // for endpoints created before Phase 2 so they can also receive email.
          if (!existing.address_local) {
            const local = generateInboundLocalpart();
            await env.cybermeters_db
              .prepare(`UPDATE dmarc_ingest_endpoints SET address_local = ? WHERE id = ?`)
              .bind(local, existing.id).run();
            existing.address_local = local;
            await createAuditEvent(env, {
              workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_inbound_activated",
              entity_type: "domain", entity_id: domainId,
              description: `Activated inbound DMARC reporting address for ${domain}`,
              metadata: { domain, ingest_endpoint_id: existing.id },
            });
          }
          // Route automation is deliberately non-blocking for endpoint creation.
          // Missing config or Cloudflare rejection is persisted as safe status.
          await configureDmarcEndpointRoute(env, existing, user.id);
          const current = await env.cybermeters_db
            .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(existing.id).first();
          return json({ created: false, endpoint: ingestEndpointToApi(current || existing, { inboundDomain }),
            message: "An active upload key already exists. Rotate it to issue a new token." });
        }

        const raw = generateIngestToken();
        const tokenHash = await hashIngestToken(raw);
        const addressLocal = generateInboundLocalpart();
        const id = createId("dmaringest");
        await env.cybermeters_db
          .prepare(`INSERT INTO dmarc_ingest_endpoints
                    (id, workspace_id, domain_id, domain, token_hash, address_local, status, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'))`)
          .bind(id, workspaceId, domainId, domain, tokenHash, addressLocal, user.id).run();
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(id).first();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_created",
          entity_type: "domain", entity_id: domainId,
          description: `Created DMARC ingestion endpoint (signed upload + inbound RUA) for ${domain}`,
          metadata: { domain, ingest_endpoint_id: id },
        });
        await configureDmarcEndpointRoute(env, row, user.id);
        const routedRow = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(id).first();
        return json({ created: true, endpoint: ingestEndpointToApi(routedRow || row, { rawToken: raw, inboundDomain }) });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-create", e, "Could not create upload key.");
      }
    }

    // GET .../dmarc-ingest-endpoint — metadata only (never the token or hash).
    if (ingestEpMatch && request.method === "GET") {
      const workspaceId = ingestEpMatch[1];
      const domain = decodeURIComponent(ingestEpMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const inboundDomain = env.RUA_INBOUND_DOMAIN || "reports.cybermeters.com";
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        return json({ endpoint: row ? ingestEndpointToApi(row, { inboundDomain }) : null });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-get", e, "Could not load upload key.");
      }
    }

    // POST .../dmarc-ingest-endpoint/rotate — new token, same endpoint id.
    if (ingestEpRotateMatch && request.method === "POST") {
      const workspaceId = ingestEpRotateMatch[1];
      const domain = decodeURIComponent(ingestEpRotateMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        if (!existing) return json({ error: "No upload key exists to rotate. Create one first." }, 404);

        const raw = generateIngestToken();
        const tokenHash = await hashIngestToken(raw);
        const candidateLocal = generateInboundLocalpart();
        const inboundDomain = env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT;
        // Create the replacement exact route before changing address_local. If
        // automation is unavailable, retain the current localpart so an existing
        // manual exact route continues to work while the signed token rotates.
        const routeResult = await safelyEnsureCloudflareEmailRoute(env, candidateLocal, inboundDomain);
        await persistDmarcRouteResult(env, existing.id, routeResult);
        await auditDmarcRouteResult(env, { ...existing, address_local: candidateLocal }, user.id, routeResult, "ensure");
        const nextLocal = routeResult.ok ? candidateLocal : (existing.address_local || candidateLocal);
        await env.cybermeters_db
          .prepare(`UPDATE dmarc_ingest_endpoints
                    SET token_hash = ?, address_local = ?, status = 'active',
                        rotated_at = datetime('now'), revoked_at = NULL
                    WHERE id = ?`)
          .bind(tokenHash, nextLocal, existing.id).run();
        if (routeResult.ok && existing.cloudflare_route_id &&
            existing.cloudflare_route_id !== routeResult.route_id) {
          const oldRouteResult = await safelyRevokeCloudflareEmailRoute(env, existing.cloudflare_route_id);
          await auditDmarcRouteResult(env, existing, user.id, oldRouteResult, "revoke");
        }
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(existing.id).first();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_rotated",
          entity_type: "domain", entity_id: domainId,
          description: `Rotated DMARC signed-upload key for ${domain}`,
          metadata: { domain, ingest_endpoint_id: existing.id },
        });
        return json({ rotated: true, endpoint: ingestEndpointToApi(row, { rawToken: raw, inboundDomain }) });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-rotate", e, "Could not rotate upload key.");
      }
    }

    // POST .../dmarc-ingest-endpoint/revoke — disables the token immediately.
    if (ingestEpRevokeMatch && request.method === "POST") {
      const workspaceId = ingestEpRevokeMatch[1];
      const domain = decodeURIComponent(ingestEpRevokeMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        if (!existing) return json({ error: "No upload key exists to revoke." }, 404);
        await env.cybermeters_db
          .prepare(`UPDATE dmarc_ingest_endpoints SET status = 'revoked', revoked_at = datetime('now') WHERE id = ?`)
          .bind(existing.id).run();
        // Endpoint revocation remains authoritative even if Cloudflare route
        // deletion is unavailable or rejected.
        const routeResult = await safelyRevokeCloudflareEmailRoute(env, existing.cloudflare_route_id);
        await persistDmarcRouteResult(env, existing.id, routeResult);
        await auditDmarcRouteResult(env, existing, user.id, routeResult, "revoke");
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(existing.id).first();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_revoked",
          entity_type: "domain", entity_id: domainId,
          description: `Revoked DMARC signed-upload key for ${domain}`,
          metadata: { domain, ingest_endpoint_id: existing.id },
        });
        const inboundDomain = env.RUA_INBOUND_DOMAIN || "reports.cybermeters.com";
        return json({ revoked: true, endpoint: ingestEndpointToApi(row, { inboundDomain }) });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-revoke", e, "Could not revoke upload key.");
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/email-senders ──────────────
    const emailSendersMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/email-senders$/);
    if (emailSendersMatch && request.method === "GET") {
      const workspaceId = emailSendersMatch[1];
      const domain = decodeURIComponent(emailSendersMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const senders = await loadEmailSenderSources(env, workspaceId, domain);
        return json({ domain, senders: senders.map(emailSenderToApi), summary: summarizeEmailSenders(senders) });
      } catch (e) {
        return serverError("email-senders", e, "Could not load email senders.");
      }
    }

    // ── POST /api/workspaces/:wsid/domains/:domain/email-senders/:source_id/classify ──
    const classifyMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/email-senders\/([^/]+)\/classify$/);
    if (classifyMatch && request.method === "POST") {
      const workspaceId = classifyMatch[1];
      const domain = decodeURIComponent(classifyMatch[2]).toLowerCase();
      const sourceId = classifyMatch[3];
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const body = await request.json().catch(() => null);
        const classification = body?.classification;
        const ALLOWED = ["trusted", "suspicious", "threat", "ignored", "unknown"];
        if (!ALLOWED.includes(classification)) {
          return json({ error: `classification must be one of: ${ALLOWED.join(", ")}` }, 400);
        }
        const notes = typeof body?.notes === "string" ? body.notes.slice(0, 1000) : null;

        const sender = await env.cybermeters_db
          .prepare(`SELECT * FROM email_sender_sources WHERE id = ? AND workspace_id = ? AND domain = ? LIMIT 1`)
          .bind(sourceId, workspaceId, domain).first();
        if (!sender) return json({ error: "Sender not found for this workspace/domain" }, 404);

        await env.cybermeters_db
          .prepare(`UPDATE email_sender_sources SET classification = ?, notes = ?, updated_at = datetime('now') WHERE id = ?`)
          .bind(classification, notes, sourceId).run();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "email_sender_classified",
          entity_type: "email_sender", entity_id: sourceId,
          description: `Classified sender ${sender.source_ip} as ${classification} for ${domain}`,
          metadata: { domain, source_ip: sender.source_ip, classification },
        });
        return json({ sender: emailSenderToApi({ ...sender, classification, notes }) });
      } catch (e) {
        return serverError("email-sender-classify", e, "Could not classify sender.");
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/bec-exposure ──────────────
    const becExposureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/bec-exposure$/);
    if (becExposureMatch && request.method === "GET") {
      const workspaceId = becExposureMatch[1];
      const domain = decodeURIComponent(becExposureMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const evidence = await loadBecExposureEvidence(env, workspaceId, domain);
        return json(computeBecExposureScore(evidence));
      } catch {
        return json({ error: "BEC exposure score could not be calculated" }, 500);
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/dmarc-summary?days=30 ───────
    const dmarcSummaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-summary$/);
    if (dmarcSummaryMatch && request.method === "GET") {
      const workspaceId = dmarcSummaryMatch[1];
      const domain = decodeURIComponent(dmarcSummaryMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const days = Math.min(365, Math.max(1, parseInt(url.searchParams.get("days") || "30", 10) || 30));
        const cutoff = Math.floor(Date.now() / 1000) - days * 86400;

        const senders = await loadEmailSenderSources(env, workspaceId, domain);
        const sSummary = summarizeEmailSenders(senders);

        const dispoRows = await env.cybermeters_db
          .prepare(`SELECT r.disposition AS disposition, SUM(r.message_count) AS msgs,
                           SUM(CASE WHEN r.spf_aligned_result='pass' OR r.dkim_aligned_result='pass'
                                    THEN r.message_count ELSE 0 END) AS aligned
                    FROM dmarc_aggregate_records r
                    JOIN dmarc_aggregate_reports rep ON rep.id = r.report_id
                    WHERE r.workspace_id = ? AND r.domain = ? AND (rep.date_range_end IS NULL OR rep.date_range_end >= ?)
                    GROUP BY r.disposition`)
          .bind(workspaceId, domain, cutoff).all();
        const disposition = { none: 0, quarantine: 0, reject: 0 };
        let totalMsgs = 0, alignedMsgs = 0;
        for (const row of (dispoRows.results || [])) {
          const d = row.disposition || "none";
          const msgs = row.msgs || 0;
          totalMsgs += msgs; alignedMsgs += row.aligned || 0;
          if (d === "quarantine") disposition.quarantine += msgs;
          else if (d === "reject") disposition.reject += msgs;
          else disposition.none += msgs;
        }
        const failedMsgs = Math.max(0, totalMsgs - alignedMsgs);
        const passRate = totalMsgs > 0 ? Math.round((alignedMsgs / totalMsgs) * 1000) / 10 : sSummary.overall_pass_rate;

        const window = await env.cybermeters_db
          .prepare(`SELECT COUNT(*) AS c, MIN(date_range_begin) AS minb, MAX(date_range_end) AS maxe
                    FROM dmarc_aggregate_reports WHERE workspace_id = ? AND domain = ?`)
          .bind(workspaceId, domain).first();
        const daysWithData = (window?.minb && window?.maxe) ? Math.max(1, Math.round((window.maxe - window.minb) / 86400)) : 0;
        const highVolFailed = senders.filter((s) => (s.total_messages || 0) >= 50 && (typeof s.pass_rate === "number" ? s.pass_rate : 100) < 90).length;
        const readiness = buildDmarcEnforcementReadiness({
          days_with_data: daysWithData, total_messages: totalMsgs || sSummary.total_messages,
          pass_rate: passRate, unknown_senders: sSummary.unknown_senders, high_volume_failed_senders: highVolFailed,
        });

        const businessRisk = buildDmarcBusinessRisk({
          threat_senders: sSummary.threat_senders,
          suspicious_senders: sSummary.suspicious_senders,
          unknown_senders: sSummary.unknown_senders,
          failed_messages: failedMsgs,
          pass_rate: passRate,
        });

        return json({
          domain, period_days: days,
          traffic: { total_messages: totalMsgs, aligned_messages: alignedMsgs, failed_messages: failedMsgs, pass_rate: passRate },
          senders: { total: sSummary.total_senders, trusted: sSummary.trusted_senders, unknown: sSummary.unknown_senders,
                     suspicious: sSummary.suspicious_senders, threat: sSummary.threat_senders, ignored: sSummary.ignored_senders },
          disposition,
          readiness,
          business_risk: businessRisk,
          cybermeters_correlation: {
            external_attack_surface_note: "Email impersonation risk should be reviewed alongside exposed assets, SaaS exposure, and third-party dependencies.",
            linked_modules: ["assets", "saas_exposure", "vendors", "business_risk"],
            correlation_status: "placeholder",
          },
          report_remediation_actions: buildDmarcReportRemediationActions(senders, readiness),
        });
      } catch (e) {
        return serverError("dmarc-summary", e, "Could not build DMARC summary.");
      }
    }

    // ── POST /api/workspaces/:wsid/domains/:domain/validate-source ───────────
    // Instant sender validation from pasted email headers — no waiting for DMARC
    // aggregate reports. Parses Authentication-Results and decides if the message
    // is authenticated and aligned to the domain. Stateless: headers are parsed
    // and discarded, never stored.
    const validateSourceMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/validate-source$/);
    if (validateSourceMatch && request.method === "POST") {
      const workspaceId = validateSourceMatch[1];
      const domain = decodeURIComponent(validateSourceMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
        const headers = String(body.headers || "").slice(0, 100_000); // bounded
        if (!headers.trim()) return json({ error: "Paste the email headers to validate." }, 400);

        const p = parseEmailAuthHeaders(headers, domain);
        const MESSAGES = {
          authenticated_aligned: "This message is authenticated and aligned to your domain — a legitimate sender for it. If you don't recognise it, confirm the service is yours.",
          passes_not_aligned:    "This message passes SPF or DKIM, but for a different domain than yours, so it would fail DMARC alignment. If it is a service you use, add its SPF include or DKIM selector; otherwise treat it as impersonation.",
          fails:                 "This message fails both SPF and DKIM. It would be blocked once you enforce DMARC. If you did not send it, this is a spoofing attempt.",
          unparseable:           "No authentication results were found in what you pasted. Paste the full raw headers (in Gmail: ⋮ menu → Show original; in Outlook: File → Properties → Internet headers).",
        };
        return json({
          domain,
          verdict: p.verdict,
          message: MESSAGES[p.verdict] || MESSAGES.unparseable,
          spf: p.spf, dkim: p.dkim, dmarc: p.dmarc, aligned: p.aligned,
          source_ip: p.source_ip, from_domain: p.from_domain,
          dkim_domain: p.dkim_domain, dkim_selector: p.dkim_selector,
        });
      } catch (e) {
        return serverError("validate-source", e, "Could not validate the pasted headers.");
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/dmarc-reports?limit=50 ──────
    // Read-only DMARC report history: one row per imported aggregate report
    // (reporter org, covered period, message volume, aligned share, policy
    // applied). Never exposes raw XML, source IPs, hashes, or internal errors.
    const dmarcReportsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-reports$/);
    if (dmarcReportsMatch && request.method === "GET") {
      const workspaceId = dmarcReportsMatch[1];
      const domain = decodeURIComponent(dmarcReportsMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "50", 10) || 50));

        const totals = await env.cybermeters_db
          .prepare(`SELECT COUNT(*) AS reports, COUNT(DISTINCT org_name) AS reporters,
                           MIN(date_range_begin) AS first_seen, MAX(date_range_end) AS last_seen,
                           SUM(message_count) AS total_messages
                    FROM dmarc_aggregate_reports WHERE workspace_id = ? AND domain = ?`)
          .bind(workspaceId, domain).first();

        const rows = await env.cybermeters_db
          .prepare(`SELECT rep.id, rep.org_name, rep.date_range_begin, rep.date_range_end,
                           rep.message_count, rep.record_count, rep.policy_p, rep.created_at,
                           COALESCE(SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                                             THEN r.message_count ELSE 0 END), 0) AS aligned_messages
                    FROM dmarc_aggregate_reports rep
                    LEFT JOIN dmarc_aggregate_records r ON r.report_id = rep.id
                    WHERE rep.workspace_id = ? AND rep.domain = ?
                    GROUP BY rep.id
                    ORDER BY COALESCE(rep.date_range_end, 0) DESC, rep.created_at DESC
                    LIMIT ?`)
          .bind(workspaceId, domain, limit).all();

        const reports = (rows.results || []).map((r) => {
          const msgs = Math.max(0, Number(r.message_count || 0));
          const aligned = Math.min(msgs, Math.max(0, Number(r.aligned_messages || 0)));
          return {
            id: r.id,
            reporter: r.org_name || "Unknown reporter",
            date_range_begin: r.date_range_begin || null,
            date_range_end: r.date_range_end || null,
            message_count: msgs,
            record_count: Math.max(0, Number(r.record_count || 0)),
            aligned_messages: aligned,
            pass_rate: msgs > 0 ? Math.round((aligned / msgs) * 1000) / 10 : null,
            policy_applied: r.policy_p || null,
            received_at: r.created_at || null,
          };
        });

        return json({
          domain,
          totals: {
            reports: Number(totals?.reports || 0),
            reporters: Number(totals?.reporters || 0),
            first_seen: totals?.first_seen || null,
            last_seen: totals?.last_seen || null,
            total_messages: Number(totals?.total_messages || 0),
          },
          reports,
        });
      } catch (e) {
        return serverError("dmarc-reports", e, "Could not load DMARC report history.");
      }
    }

    // ── Workspace alert channels (Slack / Teams / signed webhooks) ────────────
    //   GET    .../alert-channels           → list (read role)
    //   POST   .../alert-channels           → create {channel_type, webhook_url} (manage role)
    //   POST   .../alert-channels/:cid/test → send a test event (manage role)
    //   DELETE .../alert-channels/:cid      → remove (manage role)
    const alertChannelsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/alert-channels(?:\/([^/]+)(\/test)?)?$/);
    if (alertChannelsMatch) {
      const workspaceId = alertChannelsMatch[1];
      const channelId   = alertChannelsMatch[2] ? decodeURIComponent(alertChannelsMatch[2]) : null;
      const isTest      = Boolean(alertChannelsMatch[3]);
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);

        if (request.method === "GET" && !channelId) {
          const rows = await env.cybermeters_db
            .prepare(`SELECT * FROM workspace_alert_channels WHERE workspace_id = ? ORDER BY created_at ASC`)
            .bind(workspaceId).all();
          return json({ channels: (rows.results || []).map(alertChannelToApi) });
        }

        if (request.method === "POST" && !channelId) {
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const channelType = String(body.channel_type || "").trim().toLowerCase();
          const checked = validateAlertChannelInput(channelType, body.webhook_url);
          if (!checked.ok) return json({ error: checked.error }, 400);

          const countRow = await env.cybermeters_db
            .prepare(`SELECT COUNT(*) AS cnt FROM workspace_alert_channels WHERE workspace_id = ?`)
            .bind(workspaceId).first();
          if (Number(countRow?.cnt || 0) >= ALERT_CHANNEL_MAX_PER_WORKSPACE) {
            return json({ error: `A workspace can have at most ${ALERT_CHANNEL_MAX_PER_WORKSPACE} alert channels.` }, 400);
          }

          const id = createId("alch");
          const secret = channelType === "webhook"
            ? `whsec_${crypto.randomUUID().replace(/-/g, "")}` : null;
          const createdAt = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`INSERT INTO workspace_alert_channels
                        (id, workspace_id, channel_type, webhook_url, secret, enabled, created_by, created_at)
                      VALUES (?, ?, ?, ?, ?, 1, ?, ?)`)
            .bind(id, workspaceId, channelType, checked.url, secret, user.id, createdAt)
            .run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "alert_channel_created", entity_type: "alert_channel", entity_id: id,
            description: `Alert channel added (${channelType})`,
          });
          const row = await env.cybermeters_db
            .prepare(`SELECT * FROM workspace_alert_channels WHERE id = ?`).bind(id).first();
          // The signing secret is returned exactly once, at creation.
          return json({ channel: alertChannelToApi(row), secret }, 201);
        }

        if (request.method === "POST" && channelId && isTest) {
          const frontendOrigin = getEmailFrontendOrigin(env);
          const result = await deliverWorkspaceAlert(env, workspaceId, {
            kind: "test",
            severity: "info",
            title: "CyberMeters test alert",
            summary: "Your alert channel is connected. Scan, asset and certificate alerts will arrive here.",
            workspace_name: access.workspace_name || null,
            link: frontendOrigin ? `${frontendOrigin}/ws/alerts` : null,
          }, { channelId });
          if (result.attempted === 0) return json({ error: "Channel not found or disabled." }, 404);
          return json({ delivered: result.delivered === 1 });
        }

        if (request.method === "DELETE" && channelId && !isTest) {
          const del = await env.cybermeters_db
            .prepare(`DELETE FROM workspace_alert_channels WHERE id = ? AND workspace_id = ?`)
            .bind(channelId, workspaceId).run();
          if (!del.meta || del.meta.changes === 0) return json({ error: "Channel not found." }, 404);
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "alert_channel_deleted", entity_type: "alert_channel", entity_id: channelId,
            description: "Alert channel removed",
          });
          return json({ ok: true });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("alert-channels", e, "Could not update alert channels.");
      }
    }

    // ── Finding waivers (risk acceptance) ─────────────────────────────────────
    // A workspace can explicitly accept the risk of a recurring finding for a
    // domain. Waivers never hide data silently: the UI moves the finding to an
    // "Accepted risks" section, and every waive/restore is audited.
    //   GET    .../finding-waivers                → list waivers for the domain
    //   POST   .../finding-waivers {finding_id, reason?} → upsert (manage role)
    //   DELETE .../finding-waivers/:findingId     → restore (manage role)
    const findingWaiversMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/finding-waivers(?:\/([^/]+))?$/);
    if (findingWaiversMatch) {
      const workspaceId = findingWaiversMatch[1];
      const domain = decodeURIComponent(findingWaiversMatch[2]).toLowerCase();
      const pathFindingId = findingWaiversMatch[3] ? decodeURIComponent(findingWaiversMatch[3]) : null;
      const FINDING_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,99}$/;
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        if (request.method === "GET" && !pathFindingId) {
          const rows = await env.cybermeters_db
            .prepare(`SELECT fw.finding_id, fw.reason, fw.created_at, fw.updated_at, u.name AS waived_by_name
                      FROM finding_waivers fw
                      LEFT JOIN users u ON u.id = fw.waived_by
                      WHERE fw.workspace_id = ? AND fw.domain = ?
                      ORDER BY fw.created_at DESC`)
            .bind(workspaceId, domain).all();
          return json({ domain, waivers: rows.results || [] });
        }

        if (request.method === "POST" && !pathFindingId) {
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const findingId = String(body.finding_id || "").trim().toLowerCase();
          if (!FINDING_ID_RE.test(findingId)) return json({ error: "finding_id is required (letters, digits, _ . -)" }, 400);
          const reason = String(body.reason || "").trim().slice(0, 500) || null;

          await env.cybermeters_db
            .prepare(`INSERT INTO finding_waivers (id, workspace_id, domain, finding_id, reason, waived_by, created_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                      ON CONFLICT(workspace_id, domain, finding_id)
                      DO UPDATE SET reason = excluded.reason, waived_by = excluded.waived_by, updated_at = datetime('now')`)
            .bind(createId("waiver"), workspaceId, domain, findingId, reason, user.id)
            .run();

          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "finding_risk_accepted", entity_type: "finding", entity_id: findingId,
            description: `Risk accepted for finding "${findingId}" on ${domain}`,
            metadata: { domain, finding_id: findingId, reason },
          }).catch(() => {});
          return json({ waived: true, domain, finding_id: findingId, reason }, 201);
        }

        if (request.method === "DELETE" && pathFindingId) {
          const findingId = pathFindingId.toLowerCase();
          if (!FINDING_ID_RE.test(findingId)) return json({ error: "Invalid finding id" }, 400);
          const res = await env.cybermeters_db
            .prepare("DELETE FROM finding_waivers WHERE workspace_id = ? AND domain = ? AND finding_id = ?")
            .bind(workspaceId, domain, findingId)
            .run();
          if ((res.meta?.changes ?? 0) > 0) {
            await createAuditEvent(env, {
              workspace_id: workspaceId, user_id: user.id,
              event_type: "finding_risk_restored", entity_type: "finding", entity_id: findingId,
              description: `Risk acceptance removed for finding "${findingId}" on ${domain}`,
              metadata: { domain, finding_id: findingId },
            }).catch(() => {});
          }
          return json({ restored: true, domain, finding_id: findingId });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("finding-waivers", e, "Could not update risk acceptance.");
      }
    }

    // ── POST /api/domains/:id/verification ───────────────────────────────────
    // Generate a cryptographically secure token and return DNS + HTML instructions.
    // Idempotent: calling again resets to a new pending token.
    const domVerInitMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/verification$/);
    if (domVerInitMatch && request.method === "POST") {
      const domainId = domVerInitMatch[1];
      try {
        // Auth BEFORE any lookup — an unauthenticated caller must never learn
        // whether a domain id exists (404 vs 401 is an existence oracle).
        const dviUser = await requireAuth(request, env);
        if (!dviUser) return json({ error: "Unauthorized" }, 401);

        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain, verification_status FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);

        // RBAC: resolve all linked workspaces for this domain, then check domain:verify permission
        const dviAccess = await requireDomainRole(dviUser, domainId, "domain:verify", env);
        if (!dviAccess) return json({ error: "Forbidden — admin role required to initiate domain verification" }, 403);

        // Already verified — don't reset
        if (domRow.verification_status === "verified") {
          return json({
            already_verified: true,
            domain: domRow.domain,
            verification_status: "verified",
          });
        }

        // Generate a cryptographically secure 48-char hex token
        const tokenBytes = new Uint8Array(24);
        crypto.getRandomValues(tokenBytes);
        const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, "0")).join("");

        await env.cybermeters_db
          .prepare(`UPDATE domains
                    SET verification_status = 'pending',
                        verification_token  = ?,
                        verification_method = NULL,
                        verified_at         = NULL,
                        verification_initiated_at = datetime('now')
                    WHERE id = ?`)
          .bind(token, domainId)
          .run();

        const domain = domRow.domain;
        await createAuditEvent(env, {
          workspace_id: dviAccess.workspace_id ?? null,
          user_id:      dviUser.id,
          event_type:   "domain_verification_token_generated",
          entity_type:  "domain",
          entity_id:    domainId,
          description:  `Verification token generated for ${domain}`,
          metadata:     { domain, domain_id: domainId, method_options: ["dns_txt", "html_file"] },
        });
        return json({
          domain,
          domain_id:          domainId,
          verification_status: "pending",
          token,
          dns: {
            record_type: "TXT",
            host:        `_cybermeters.${domain}`,
            value:       `cybermeters-verification=${token}`,
            instructions: [
              `Add a DNS TXT record to your domain:`,
              `  Host:  _cybermeters.${domain}`,
              `  Type:  TXT`,
              `  Value: cybermeters-verification=${token}`,
              `DNS changes can take up to 48 hours to propagate globally.`,
            ],
          },
          html: {
            url:      `https://${domain}/cybermeters-verification-${token}.html`,
            content:  token,
            instructions: [
              `Create a publicly accessible HTML file at your domain:`,
              `  URL:     https://${domain}/cybermeters-verification-${token}.html`,
              `  Content: ${token}`,
              `The file must be accessible without authentication.`,
            ],
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/domains/:id/verify ─────────────────────────────────────────
    // Perform the actual check: DNS TXT or HTML file.
    // Tries DNS first, then HTML. First passing method wins.
    const domVerCheckMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/verify$/);
    if (domVerCheckMatch && request.method === "POST") {
      const domainId = domVerCheckMatch[1];
      try {
        // Auth BEFORE any lookup — see domVerInitMatch above (existence oracle).
        const dvcUser = await requireAuth(request, env);
        if (!dvcUser) return json({ error: "Unauthorized" }, 401);

        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain, verification_status, verification_token FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);

        // RBAC: resolve all linked workspaces for this domain, then check domain:verify permission
        const dvcAccess = await requireDomainRole(dvcUser, domainId, "domain:verify", env);
        if (!dvcAccess) return json({ error: "Forbidden — admin role required to verify domain ownership" }, 403);

        if (domRow.verification_status === "verified") {
          return json({
            success: true,
            domain: domRow.domain,
            verification_status: "verified",
            verification_method: "already_verified",
            message: "Domain is already verified.",
          });
        }

        if (!domRow.verification_token) {
          return json({
            error: "No verification token found. Call POST /api/domains/:id/verification first.",
          }, 400);
        }

        const domain = domRow.domain;
        const token  = domRow.verification_token;
        const expectedTxtValue = `cybermeters-verification=${token}`;
        const htmlUrl          = `https://${domain}/cybermeters-verification-${token}.html`;

        // ── Method 1: DNS TXT ─────────────────────────────────────────────
        let dnsVerified = false;
        let dnsError    = null;
        try {
          const txtHost = `_cybermeters.${domain}`;
          const dnsResult = await dnsQuery(txtHost, "TXT");
          const answers = dnsResult.Answer || [];
          dnsVerified = answers.some(a => {
            // RFC 1035: TXT data arrives with surrounding quotes stripped by DoH JSON
            const val = String(a.data || "").replace(/^"|"$/g, "").trim();
            return val === expectedTxtValue;
          });
        } catch (e) {
          dnsError = customerSafeFailure("domain-verification/dns", e, "DNS lookup could not be completed");
        }

        if (dnsVerified) {
          await env.cybermeters_db
            .prepare(`UPDATE domains
                      SET verification_status = 'verified',
                          verification_method = 'dns_txt',
                          verified_at = datetime('now')
                      WHERE id = ?`)
            .bind(domainId)
            .run();
          // Forward telemetry: fingerprint the exact TXT value we trusted + note
          // the resolver, so a later drift check can prove what was verified.
          const dnsRecordHash = await hashToken(expectedTxtValue);
          // Notifications + audit — fire-and-forget for all linked workspaces
          try {
            const wsR = await env.cybermeters_db
              .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
              .bind(domainId).all();
            for (const { workspace_id } of (wsR.results || [])) {
              await createNotificationEvent(env, workspace_id, {
                type: "domain_verified", severity: "info",
                title: `${domain} ownership verified`,
                message: `Domain verified via DNS TXT record at _cybermeters.${domain}.`,
                metadata: { domain, domain_id: domainId, method: "dns_txt" },
              });
              await createAuditEvent(env, {
                workspace_id,
                user_id:     dvcUser?.id ?? null,
                event_type:  "domain_verified",
                entity_type: "domain",
                entity_id:   domainId,
                description: `${domain} ownership verified via DNS TXT`,
                metadata:    { domain, domain_id: domainId, method: "dns_txt",
                               resolver_used: "cloudflare_doh", dns_record_hash: dnsRecordHash },
              });
            }
          } catch { /* non-fatal */ }
          return json({
            success: true,
            domain,
            verification_status: "verified",
            verification_method: "dns_txt",
            message: `DNS TXT record verified at _cybermeters.${domain}.`,
          });
        }

        // ── Method 2: HTML file ───────────────────────────────────────────
        let htmlVerified = false;
        let htmlError    = null;
        try {
          const htmlRes = await fetch(htmlUrl, {
            headers: { "User-Agent": "CyberMeters-Verification/1.0" },
            signal: AbortSignal.timeout(8_000),
            redirect: "follow",
          });
          if (htmlRes.ok) {
            const body = (await htmlRes.text()).trim();
            htmlVerified = body === token;
          } else {
            htmlError = `HTTP ${htmlRes.status}`;
          }
        } catch (e) {
          htmlError = customerSafeFailure("domain-verification/html", e, "HTML verification request could not be completed");
        }

        if (htmlVerified) {
          await env.cybermeters_db
            .prepare(`UPDATE domains
                      SET verification_status = 'verified',
                          verification_method = 'html_file',
                          verified_at = datetime('now')
                      WHERE id = ?`)
            .bind(domainId)
            .run();
          // Notifications + audit — fire-and-forget for all linked workspaces
          try {
            const wsR = await env.cybermeters_db
              .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
              .bind(domainId).all();
            for (const { workspace_id } of (wsR.results || [])) {
              await createNotificationEvent(env, workspace_id, {
                type: "domain_verified", severity: "info",
                title: `${domain} ownership verified`,
                message: `Domain verified via HTML file at ${htmlUrl}.`,
                metadata: { domain, domain_id: domainId, method: "html_file" },
              });
              await createAuditEvent(env, {
                workspace_id,
                user_id:     dvcUser?.id ?? null,
                event_type:  "domain_verified",
                entity_type: "domain",
                entity_id:   domainId,
                description: `${domain} ownership verified via HTML file`,
                metadata:    { domain, domain_id: domainId, method: "html_file" },
              });
            }
          } catch { /* non-fatal */ }
          return json({
            success: true,
            domain,
            verification_status: "verified",
            verification_method: "html_file",
            message: `HTML verification file found at ${htmlUrl}.`,
          });
        }

        // ── Both failed ───────────────────────────────────────────────────
        await env.cybermeters_db
          .prepare(`UPDATE domains SET verification_status = 'failed' WHERE id = ?`)
          .bind(domainId)
          .run();

        try {
          const wsR = await env.cybermeters_db
            .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
            .bind(domainId)
            .all();
          for (const { workspace_id } of (wsR.results || [])) {
            await createAuditEvent(env, {
              workspace_id,
              user_id:     dvcUser?.id ?? null,
              event_type:  "domain_verification_failed",
              entity_type: "domain",
              entity_id:   domainId,
              description: `${domain} ownership verification failed`,
              metadata:    {
                domain,
                domain_id: domainId,
                dns_txt_result: dnsVerified ? "found" : "not_found",
                html_file_result: htmlVerified ? "found" : "not_found",
                dns_error: dnsError || null,
                html_error: htmlError || null,
              },
            });
          }
        } catch { /* non-fatal */ }

        return json({
          success: false,
          domain,
          verification_status: "failed",
          token,
          checks: {
            dns_txt: {
              checked: true,
              host:    `_cybermeters.${domain}`,
              expected: expectedTxtValue,
              result: dnsVerified ? "found" : "not_found",
              error:  dnsError || null,
            },
            html_file: {
              checked: true,
              url:    htmlUrl,
              result: htmlVerified ? "found" : "not_found",
              error:  htmlError || null,
            },
          },
          message: "Verification not confirmed yet — DNS changes can take a while to propagate. We re-check automatically every hour for 48 hours from when you generated this verification code, and will notify you when it succeeds.",
          auto_recheck: { enabled: true, method: "dns_txt", interval: "hourly", window_hours: 48 },
        }, 200);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/domains/:id ─────────────────────────────────────────────────
    // Returns domain row including verification fields. RBAC via domain→workspace link.
    const domGetMatch = url.pathname.match(/^\/api\/domains\/([^/]+)$/);
    if (domGetMatch && request.method === "GET") {
      const domainId = domGetMatch[1];
      const domGetUser = await requireAuth(request, env);
      if (!domGetUser) return json({ error: "Unauthorized" }, 401);
      const domGetAccess = await requireDomainRole(domGetUser, domainId, "workspace:read", env);
      if (!domGetAccess) return json({ error: "Forbidden" }, 403);
      try {
        const domRow = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, verification_status, verification_method,
                    verification_token, verified_at, verification_initiated_at, created_at
             FROM domains WHERE id = ?`
          )
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);
        const token = domRow.verification_token;
        return json({
          domain: {
            ...domRow,
            dns: token ? {
              host:  `_cybermeters.${domRow.domain}`,
              value: `cybermeters-verification=${token}`,
            } : null,
            html: token ? {
              url:     `https://${domRow.domain}/cybermeters-verification-${token}.html`,
              content: token,
            } : null,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/domains/:id/check-verification ──────────────────────────────
    // DNS TXT probe only — does NOT mark domain as verified.
    // Returns { found, value, matches } so the user can check propagation
    // before committing to the full POST /api/domains/:id/verify call.
    const domCheckMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/check-verification$/);
    if (domCheckMatch && request.method === "POST") {
      const domainId = domCheckMatch[1];
      const chkUser = await requireAuth(request, env);
      if (!chkUser) return json({ error: "Unauthorized" }, 401);
      const chkAccess = await requireDomainRole(chkUser, domainId, "domain:verify", env);
      if (!chkAccess) return json({ error: "Forbidden — admin role required" }, 403);
      try {
        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain, verification_token FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);
        if (!domRow.verification_token) {
          return json({
            error: "No verification token. Call POST /api/domains/:id/verification first.",
          }, 400);
        }
        const domain   = domRow.domain;
        const token    = domRow.verification_token;
        const expected = `cybermeters-verification=${token}`;
        let found   = false;
        let value   = null;
        let matches = false;
        let error   = null;
        try {
          const txtHost  = `_cybermeters.${domain}`;
          const dnsResult = await dnsQuery(txtHost, "TXT");
          const answers   = dnsResult.Answer || [];
          for (const a of answers) {
            const v = String(a.data || "").replace(/^"|"$/g, "").trim();
            if (!found) { found = true; value = v; }
            if (v === expected) { matches = true; value = v; break; }
          }
        } catch (e) {
          error = customerSafeFailure("domain-verification/check", e, "DNS lookup could not be completed");
        }
        return json({ found, value, matches, expected, error });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // Routes that carry a workspace ID
    // Matches:  /api/workspaces/:id
    //           /api/workspaces/:id/domains
    //           /api/workspaces/:id/domains/:domainId
    //           /api/workspaces/:id/stats
    const wsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)(\/domains(?:\/([^/]+))?|\/stats)?$/
    );

    if (wsMatch) {
      const workspaceId   = wsMatch[1];
      const subResource   = wsMatch[2];          // "/domains", "/domains/:id", "/stats", or undefined
      const linkedDomainId = wsMatch[3];         // domain ID component if present

      // Authenticate and authorize before looking up the workspace so callers
      // cannot distinguish inaccessible workspace IDs from nonexistent ones.
      const wsUser = await requireAuth(request, env);
      if (!wsUser) return json({ error: "Unauthorized" }, 401);
      const wsAccess = await requireWorkspaceRole(wsUser, workspaceId, "workspace:read", env);
      if (!wsAccess) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists for all sub-routes
      let workspace;
      try {
        workspace = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces WHERE id = ?`)
          .bind(workspaceId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!workspace) {
        return json({ error: "Workspace not found" }, 404);
      }

      // ── GET /api/workspaces/:id ── (with inline statistics) ──────────
      if (request.method === "GET" && !subResource) {
        try {
          const [domainsRow, scansRow, avgRow, latestRow] = await Promise.all([
            // total_domains
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`)
              .bind(workspaceId).first(),

            // total_scans — prefer direct workspace_id attribution; fallback via
            // domain join for historical scans where workspace_id IS NULL.
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(DISTINCT s.id) AS n
                 FROM scans s
                 JOIN domains d ON d.id = s.domain_id
                 JOIN workspace_domains wd ON wd.domain_id = d.id
                 WHERE (
                   s.workspace_id = ?
                   OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
                 )`
              )
              .bind(workspaceId, workspaceId).first(),

            // cyber_score_average — direct attribution + fallback for NULL workspace_id
            env.cybermeters_db
              .prepare(
                `SELECT ROUND(AVG(s.score), 1) AS avg
                 FROM scans s
                 JOIN domains d ON d.id = s.domain_id
                 JOIN workspace_domains wd ON wd.domain_id = d.id
                 WHERE (
                   s.workspace_id = ?
                   OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
                 )
                   AND s.status = 'completed'
                   AND s.score  IS NOT NULL`
              )
              .bind(workspaceId, workspaceId).first(),

            // latest_scan — direct attribution + fallback for NULL workspace_id
            env.cybermeters_db
              .prepare(
                `SELECT s.id, s.domain, s.status, s.score, s.rating, s.created_at
                 FROM scans s
                 JOIN domains d ON d.id = s.domain_id
                 JOIN workspace_domains wd ON wd.domain_id = d.id
                 WHERE (
                   s.workspace_id = ?
                   OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
                 )
                 ORDER BY s.created_at DESC
                 LIMIT 1`
              )
              .bind(workspaceId, workspaceId).first(),
          ]);

          return json({
            workspace: {
              id:         workspace.id,
              name:       workspace.name,
              created_at: workspace.created_at,
            },
            stats: {
              total_domains:       domainsRow?.n ?? 0,
              total_scans:         scansRow?.n  ?? 0,
              cyber_score_average: avgRow?.avg   ?? null,
              latest_scan:         latestRow     ?? null,
            },
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── PATCH /api/workspaces/:id ─────────────────────────────────────────
      // Renames the workspace. Requires admin role or above.
      if (request.method === "PATCH" && !subResource) {
        const patchAccess = await requireWorkspaceRole(wsUser, workspaceId, "workspace:manage", env);
        if (!patchAccess) return json({ error: "Forbidden — admin role required to rename workspace" }, 403);
        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
        const newName = (body?.name ?? "").trim();
        if (!newName) return json({ error: "name is required" }, 400);
        if (newName.length > 100) return json({ error: "name must be 100 characters or fewer" }, 400);
        const oldName = workspace.name;
        try {
          await env.cybermeters_db
            .prepare(`UPDATE workspaces SET name = ?, updated_at = datetime('now') WHERE id = ? AND deleted_at IS NULL`)
            .bind(newName, workspaceId)
            .run();
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "workspace_renamed",
            entity_type:  "workspace",
            entity_id:    workspaceId,
            description:  `Workspace renamed from "${oldName}" to "${newName}"`,
            metadata:     { name: newName, old_name: oldName },
          });
          return json({ workspace: { id: workspaceId, name: newName } });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── DELETE /api/workspaces/:id/domains/:domainId ──────────────────
      // Removes the workspace↔domain link only. Domain row is untouched.
      if (request.method === "DELETE" && subResource && linkedDomainId) {
        const delAccess = await requireWorkspaceRole(wsUser, workspaceId, "domain:remove", env);
        if (!delAccess) return json({ error: "Forbidden — admin role required to remove domains" }, 403);
        try {
          let domainRow = null;
          try {
            domainRow = await env.cybermeters_db
              .prepare("SELECT d.id, d.domain FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ? AND wd.domain_id = ? LIMIT 1")
              .bind(workspaceId, linkedDomainId)
              .first();
          } catch { /* audit metadata lookup only */ }
          const del = await env.cybermeters_db
            .prepare(
              `DELETE FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?`
            )
            .bind(workspaceId, linkedDomainId)
            .run();
          if (del.meta.changes === 0) {
            return json({ error: "Domain link not found" }, 404);
          }

          // ── Cascade cleanup ─────────────────────────────────────────────
          // Disable scheduled scans and deactivate assets/brand candidates
          // for this domain within this workspace. Use fire-and-forget so
          // cascade failures never block the 200 response.
          if (domainRow?.domain) {
            env.cybermeters_db
              .prepare(`UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = ? AND domain = ?`)
              .bind(workspaceId, domainRow.domain)
              .run()
              .catch(e => console.error("[domain_remove_cascade] scheduled_scans:", e?.message));
            env.cybermeters_db
              .prepare(`UPDATE workspace_brand_assets SET status = 'inactive', updated_at = datetime('now') WHERE workspace_id = ? AND domain = ?`)
              .bind(workspaceId, domainRow.domain)
              .run()
              .catch(e => console.error("[domain_remove_cascade] brand_assets:", e?.message));
          }
          env.cybermeters_db
            .prepare(`UPDATE workspace_assets SET status = 'inactive', updated_at = datetime('now') WHERE workspace_id = ? AND domain_id = ?`)
            .bind(workspaceId, linkedDomainId)
            .run()
            .catch(e => console.error("[domain_remove_cascade] workspace_assets:", e?.message));

          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "domain_removed",
            entity_type:  "domain",
            entity_id:    linkedDomainId,
            description:  `Domain ${domainRow?.domain || linkedDomainId} removed from workspace`,
            metadata:     { domain: domainRow?.domain || null, domain_id: linkedDomainId },
          });
          return json({ success: true, workspace_id: workspaceId, domain_id: linkedDomainId });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/domains ───────────────────────────────
      // Returns linked domains enriched with latest scan data per domain.
      if (request.method === "GET" && subResource === "/domains") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT
                 d.id                        AS domain_id,
                 d.domain,
                 d.verification_status,
                 d.verification_method,
                 d.verification_token,
                 d.verified_at,
                 d.verification_initiated_at,
                 s.id                        AS last_scan_id,
                 s.score                     AS latest_score,
                 s.status                    AS latest_status,
                 s.created_at               AS last_scanned_at
               FROM workspace_domains wd
               JOIN   domains d ON d.id = wd.domain_id
               LEFT JOIN scans s ON s.id = (
                 SELECT id FROM scans
                 WHERE  domain_id = d.id
                 ORDER  BY created_at DESC LIMIT 1
               )
               WHERE wd.workspace_id = ?
               ORDER BY d.domain ASC`
            )
            .bind(workspaceId)
            .all();
          return json({ workspace_id: workspaceId, domains: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── POST /api/workspaces/:id/domains ─────────────────────────────
      // Reuse existing domain row if present; create new one otherwise.
      // Idempotent link via INSERT OR IGNORE.
      if (request.method === "POST" && subResource === "/domains") {
        // RBAC: admin or above required to add domains
        // wsUser is already authenticated by the wsMatch guard above
        const addDomAccess = await requireWorkspaceRole(wsUser, workspaceId, "domain:add", env);
        if (!addDomAccess) return json({ error: "Forbidden — admin role required to add domains" }, 403);
        let body;
        try { body = await request.json(); } catch { body = {}; }
        const raw = (body.domain || "").trim().toLowerCase();
        if (!isValidDomain(raw)) {
          return json({ error: "domain is required and must be a valid domain" }, 400);
        }
        try {
          // Entitlement: per-workspace limit + account-level cross-workspace limit
          const domainBillingUserId = await getWorkspaceBillingUserId(workspaceId, wsUser.id, env);
          const domPlan = await getEffectivePlan(domainBillingUserId, env);
          const domUsage  = await getEntitlementUsage(wsUser, env, workspaceId);
          const domLimits = getPlanLimits(domPlan);
          // (a) Per-workspace limit
          if (domUsage.domains_in_workspace >= domLimits.domains_per_workspace) {
            return json(planLimitExceeded("domains", domLimits.domains, domUsage.domains_in_workspace), 403);
          }
          // (b) Account-level limit: total unique domains across all owned workspaces.
          //     Uses the billing owner's workspace set so non-owner members are scoped correctly.
          const domOwnerAcct = await getAccountUsage(domainBillingUserId, env);
          if (domOwnerAcct.domains >= domLimits.domains) {
            return json(planLimitExceeded("domains", domLimits.domains, domOwnerAcct.domains), 403);
          }

          // Scoped by user_id to prevent cross-user domain aliasing.
          let domainRow = await env.cybermeters_db
            .prepare(`SELECT id, domain FROM domains WHERE domain = ? AND user_id = ? LIMIT 1`)
            .bind(raw, wsUser.id)
            .first();

          if (!domainRow) {
            const newId = createId("domain");
            await env.cybermeters_db
              .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
              .bind(newId, wsUser.id, raw)
              .run();
            domainRow = { id: newId, domain: raw };
          }

          const linkRes = await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)`
            )
            .bind(workspaceId, domainRow.id)
            .run();
          // A genuinely new workspace↔domain link (not a duplicate/no-op add).
          const newlyLinked = (linkRes.meta?.changes ?? 0) > 0;

          // Audit: domain added
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "domain_added",
            entity_type:  "domain",
            entity_id:    domainRow.id,
            description:  `Domain ${domainRow.domain} added to workspace`,
            metadata:     { domain: domainRow.domain, domain_id: domainRow.id },
          });

          // Lifecycle: domain added — only on a real new link; deduped once per
          // workspace+domain; delivered to the workspace owner's verified email.
          // Non-blocking via waitUntil; never throws.
          if (newlyLinked) {
            ctx.waitUntil(sendLifecycleEmail(env, {
              type: "lifecycle_domain_added",
              workspace_id: workspaceId,
              domain: domainRow.domain,
            }).catch(() => {}));
          }

          return json(
            { domain: { domain_id: domainRow.id, domain: domainRow.domain, workspace_id: workspaceId } },
            201
          );
        } catch {
          return json({ error: "Database error" }, 500);
        }
	      }
	    }
	
	    // ── POST /api/workspaces/:id/delete-request ─────────────────────────
	    const workspaceDeleteRequestMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/delete-request$/);
	    if (workspaceDeleteRequestMatch && request.method === "POST") {
	      const workspaceId = workspaceDeleteRequestMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
	      const access = await requireWorkspaceRole(user, workspaceId, "workspace:delete", env);
	      if (!access) return json({ error: "Forbidden — owner role required to request workspace deletion" }, 403);
	      try {
	        const workspace = await env.cybermeters_db
	          .prepare("SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL LIMIT 1")
	          .bind(workspaceId)
	          .first();
	        if (!workspace) return json({ error: "Workspace not found" }, 404);

	        const now = new Date().toISOString();

	        // Soft-delete the workspace
	        await env.cybermeters_db
	          .prepare("UPDATE workspaces SET deleted_at = ? WHERE id = ?")
	          .bind(now, workspaceId)
	          .run();

	        // Disable all scheduled scans for this workspace
	        await env.cybermeters_db
	          .prepare("UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = ?")
	          .bind(workspaceId)
	          .run();

	        // Archive active assets for this workspace (preserve history per Rule 5)
	        await env.cybermeters_db
	          .prepare("UPDATE workspace_assets SET status = 'inactive' WHERE workspace_id = ? AND status = 'active'")
	          .bind(workspaceId)
	          .run();

	        // Schedule the hard purge: one pending request per workspace. The
	        // purge cron only acts DELETION_PURGE_WINDOW_DAYS after created_at,
	        // so the owner can restore any time before then.
	        const existingReq = await env.cybermeters_db
	          .prepare("SELECT id FROM deletion_requests WHERE request_type = 'workspace' AND workspace_id = ? AND status IN ('pending', 'purging') LIMIT 1")
	          .bind(workspaceId)
	          .first()
	          .catch(() => null);
	        if (!existingReq) {
	          await env.cybermeters_db
	            .prepare(`INSERT INTO deletion_requests
	                        (id, request_type, user_id, workspace_id, requested_by, status, created_at, updated_at)
	                      VALUES (?, 'workspace', ?, ?, ?, 'pending', ?, ?)`)
	            .bind(createId("delreq"), user.id, workspaceId, user.id, now, now)
	            .run()
	            .catch(() => {});
	        }
	        const purgeAfter = new Date(Date.now() + DELETION_PURGE_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();

	        await createAuditEvent(env, {
	          workspace_id: workspaceId,
	          user_id: user.id,
	          event_type: "workspace_deleted",
	          entity_type: "workspace",
	          entity_id: workspaceId,
	          description: `Workspace "${workspace.name}" soft-deleted; permanent deletion scheduled`,
	          metadata: { deleted_at: now, purge_after: purgeAfter },
	        }).catch(() => {});

	        // Confirmation email — states the restore window honestly.
	        try {
	          if (user.email && isValidEmail(String(user.email).toLowerCase())) {
	            const wsName = escapeEmailHtml(workspace.name);
	            const untilDay = new Date(purgeAfter).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
	            const text = `Your CyberMeters workspace was deleted\n\nThe workspace "${workspace.name}" has been deleted and is no longer visible in CyberMeters.\n\nIts data will be permanently removed after ${untilDay}. Until then you can restore the workspace by contacting support or using the restore option.\n\nCyberMeters`;
	            const html = `<p>The workspace <strong>${wsName}</strong> has been deleted and is no longer visible in CyberMeters.</p><p>Its data will be permanently removed after <strong>${untilDay}</strong>. Until then you can restore the workspace by contacting support or using the restore option.</p><p>CyberMeters</p>`;
	            await sendCustomerEmail("Your CyberMeters workspace was deleted", text, html, env, "HELLO_EMAIL_FROM", [String(user.email).toLowerCase()]);
	          }
	        } catch { /* deletion must succeed even if the email cannot be sent */ }

	        return json({ deleted: true, workspace_id: workspaceId, deleted_at: now, purge_after: purgeAfter, restorable_until: purgeAfter });
	      } catch {
	        return json({ error: "Unable to delete workspace" }, 500);
	      }
	    }

	    // ── POST /api/workspaces/:id/restore ─────────────────────────────────────
    // Undo a soft-delete inside the purge window. Owner-only; authorized
    // directly against the workspaces row because role resolution may exclude
    // deleted workspaces. Once purging has started, restore is refused.
    const workspaceRestoreMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/restore$/);
    if (workspaceRestoreMatch && request.method === "POST") {
      const workspaceId = workspaceRestoreMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id, name, owner_user_id, deleted_at FROM workspaces WHERE id = ? LIMIT 1")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);
        if (ws.owner_user_id !== user.id) return json({ error: "Forbidden — owner role required to restore a workspace" }, 403);
        if (!ws.deleted_at) return json({ error: "Workspace is not deleted" }, 400);

        const delReq = await env.cybermeters_db
          .prepare("SELECT id, status, created_at FROM deletion_requests WHERE request_type = 'workspace' AND workspace_id = ? AND status IN ('pending', 'purging') ORDER BY created_at DESC LIMIT 1")
          .bind(workspaceId)
          .first()
          .catch(() => null);
        if (delReq?.status === "purging") {
          return json({ error: "This workspace can no longer be restored — permanent deletion has already started." }, 409);
        }
        const deletedAtMs = new Date(ws.deleted_at).getTime();
        if (!Number.isNaN(deletedAtMs) && Date.now() > deletedAtMs + DELETION_PURGE_WINDOW_DAYS * 24 * 60 * 60 * 1000) {
          return json({ error: "The restore window for this workspace has passed." }, 409);
        }

        await env.cybermeters_db
          .prepare("UPDATE workspaces SET deleted_at = NULL WHERE id = ?")
          .bind(workspaceId)
          .run();
        if (delReq?.id) {
          await env.cybermeters_db
            .prepare("UPDATE deletion_requests SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?")
            .bind(delReq.id)
            .run()
            .catch(() => {});
        }

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id: user.id,
          event_type: "workspace_restored",
          entity_type: "workspace",
          entity_id: workspaceId,
          description: `Workspace "${ws.name}" restored within the deletion window`,
          metadata: { deletion_request_id: delReq?.id ?? null },
        }).catch(() => {});

        // Schedules stay disabled and archived assets stay inactive — the
        // owner re-enables what they still need.
        return json({ restored: true, workspace_id: workspaceId, note: "Scheduled scans remain paused and archived assets remain inactive; re-enable them as needed." });
      } catch {
        return json({ error: "Unable to restore workspace" }, 500);
      }
    }

    // ── Workspace report routes (generate/list/download + scheduled reports) ──
    // Extracted to src/routes/workspace-reports.js; dispatched at the original
    // position, patterns unchanged (generate/:reportId ordering preserved inside
    // the module).
    {
      const reportsResponse = await workspaceReportsRoutes(routeCtx);
      if (reportsResponse) return reportsResponse;
    }

    // ── POST /api/free-scan ──────────────────────────────────────────────────
    // Public endpoint — no authentication required.
    // Runs a lightweight 4-module scan (DNS, SSL, headers, email) and returns a
    // preview payload suitable for the /free-scan landing page.
    //
    // Rate limit: 5 free scans per IP per hour (IP stored hashed in api_rate_limits).
    // No D1 persistence — results are returned inline and discarded.
    // No R2 writes — no report is stored.
    //
    // Response shape:
    //   { domain, score, risk_level, severity_counts, total_findings,
    //     preview_findings[5], hidden_count, scanned_at }
    //
    // Each preview_finding: { id, title, severity, description, academy_slug }
    // Evidence, confidence, and remediation are intentionally omitted (gated).
    if (request.method === "POST" && url.pathname === "/api/free-scan") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const domain = (body.domain ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!isValidDomain(domain)) {
        return json({ error: "Please enter a valid domain (e.g. example.com)" }, 400);
      }

      // Block obviously internal / reserved domains
      const BLOCKED_DOMAINS = ["localhost", "127.0.0.1", "0.0.0.0", "local"];
      if (BLOCKED_DOMAINS.some(b => domain === b || domain.endsWith("." + b))) {
        return json({ error: "That domain cannot be scanned" }, 400);
      }

      // IP-based rate limit: 5 free scans per hour
      const clientIp = request.headers.get("CF-Connecting-IP") ||
                       request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                       "unknown";

      const rateLimitResult = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("freescan", clientIp) }],
        "free_scan",
        5,
        3600,
        { failClosed: true },
      );
      if (rateLimitResult) {
        // Honest copy: a free account raises limits and saves results — it is
        // not unlimited (free plan has monthly caps). Never overpromise here.
        return json({
          error: "Too many checks from this connection. Please wait an hour, or create a free account to save your results and monitor your domain.",
          code: "rate_limit_exceeded",
        }, 429);
      }

      // Run 4 core modules in parallel — no subdomains, no brute-force, no tech, no WHOIS
      const scannedAt = new Date().toISOString();
      const [dnsR, sslR, headersR, emailR] = await Promise.allSettled([
        runDnsModule(domain),
        runSslModule(domain),
        runHeadersModule(domain),
        runEmailModule(domain),
      ]);

      const modules = {
        dns:              dnsR.status === "fulfilled"     ? dnsR.value     : { error: "DNS check failed" },
        ssl:              sslR.status === "fulfilled"     ? sslR.value     : { error: "SSL check failed" },
        headers:          headersR.status === "fulfilled" ? headersR.value : { error: "Headers check failed" },
        email_security:   emailR.status === "fulfilled"   ? emailR.value   : { error: "Email check failed" },
        // Stub the remaining modules — computeScore handles missing gracefully
        subdomains:        { count: 0, items: [] },
        subdomain_takeover:{ risks: [] },
        asset_exposure:    { assets: [] },
        technology_detection: {},
        whois_intelligence:   {},
        dns_bruteforce:       { items: [] },
        brand_monitoring:     null, // opt-out: brand findings not applicable to quick domain preview
      };

      const { score, risk_level, findings } = computeScore(modules, domain);
      const normalised = findings.map(normalizeFindingSchema);

      // Sort by severity weight — critical first
      const SEV_WEIGHT = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      normalised.sort((a, b) =>
        (SEV_WEIGHT[a.severity] ?? 5) - (SEV_WEIGHT[b.severity] ?? 5)
      );

      // Count by severity
      const severity_counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of normalised) {
        if (severity_counts[f.severity] !== undefined) severity_counts[f.severity]++;
      }

      // Academy slug mapping — same logic as frontend getAcademyArticleForFinding
      // We resolve it server-side so the API response is self-contained.
      const FINDING_ACADEMY_MAP = {
        email_missing_spf:                       "spf-explained",
        email_intel_spf_missing:                 "spf-explained",
        email_intel_spf_permissive:              "spf-explained",
        email_missing_dmarc:                     "dmarc-explained",
        email_intel_dmarc_missing:               "dmarc-explained",
        email_intel_dmarc_reporting_only:        "dmarc-explained",
        email_dmarc_policy_none:                 "dmarc-explained",
        email_weak_dmarc:                        "dmarc-explained",
        email_dkim_not_detected:                 "dkim-explained",
        email_intel_dkim_not_found:              "dkim-explained",
        dnssec_not_enabled:                      "dnssec-explained",
        dnssec_misconfigured:                    "dnssec-explained",
        header_missing_strict_transport_security:"hsts-explained",
        header_weak_hsts:                        "hsts-explained",
        dse_hsts_short_maxage:                   "hsts-explained",
        header_missing_content_security_policy:  "csp-explained",
        csp_weak_policy:                         "csp-explained",
        security_headers_not_observed:           "csp-explained",
        subdomain_takeover:                      "what-is-subdomain-takeover",
        subdomain_takeover_risk:                 "what-is-subdomain-takeover",
        cloud_storage_exposure_observed:         "public-cloud-storage-risks",
        cloud_storage_public_listing:            "public-cloud-storage-risks",
        admin_surface_critical:                  "what-is-attack-surface-management",
        admin_surface_high:                      "what-is-attack-surface-management",
      };

      function resolveAcademySlug(findingId) {
        if (!findingId) return null;
        if (FINDING_ACADEMY_MAP[findingId]) return FINDING_ACADEMY_MAP[findingId];
        // prefix match (strip trailing _segments one at a time)
        const parts = findingId.split("_");
        for (let len = parts.length - 1; len >= 1; len--) {
          const prefix = parts.slice(0, len).join("_");
          if (FINDING_ACADEMY_MAP[prefix]) return FINDING_ACADEMY_MAP[prefix];
        }
        return null;
      }

      // Build preview_findings — top 5, limited fields, no evidence/remediation
      const PREVIEW_LIMIT = 5;
      const preview_findings = normalised.slice(0, PREVIEW_LIMIT).map(f => ({
        id:          f.id,
        title:       f.title,
        severity:    f.severity,
        description: f.description,
        academy_slug: resolveAcademySlug(f.id),
      }));

      return json({
        domain,
        score:            Math.max(0, Math.min(100, score)),
        risk_level,
        severity_counts,
        total_findings:   normalised.length,
        preview_findings,
        hidden_count:     Math.max(0, normalised.length - PREVIEW_LIMIT),
        modules_scanned:  ["dns", "ssl", "headers", "email_security"],
        scanned_at:       scannedAt,
      });
    }

    // ── GET /api/workspaces/:id/subscription ─────────────────────────────────
    // Returns the full subscription state for a workspace, including trial
    // status, plan, and computed fields useful for the Billing/Subscription UI.
    //
    // Response:
    //   { subscription_active, plan, status, trial_active, trial_remaining_days,
    //     trial_start, trial_end, current_period_start, current_period_end,
    //     billing_interval, cancel_at_period_end, stripe_subscription_id }
    const wsSubMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/subscription$/);
    if (wsSubMatch && request.method === "GET") {
      const wsId = wsSubMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const sub = await getWorkspaceSubscription(wsId, env);
        const trialActive       = isTrialActive(sub);
        const subscriptionActive = isSubscriptionActive(sub);
        const trialRemainingDays = getTrialRemainingDays(sub);
        const grace             = getPaymentGraceState(sub);

        // Effective plan: trial plan if trialing, paid plan while active OR
        // inside the payment grace window (matches getUserPlan so the billing
        // UI and runtime entitlements never disagree), else free.
        let effectivePlan = "free";
        if (sub) {
          if (trialActive) {
            effectivePlan = normalizePlan(sub.plan ?? TRIAL_PLAN);
          } else if (subscriptionActive || grace.active) {
            effectivePlan = normalizePlan(sub.plan);
          }
        }

        const limits   = getPlanLimits(effectivePlan);
        const features = getPlanFeatures(effectivePlan);

        return json({
          plan:                 effectivePlan,
          status:               sub?.subscription_status ?? (sub ? sub.status : "free"),
          subscription_active:  trialActive || subscriptionActive || grace.active,
          trial_active:         trialActive,
          trial_remaining_days: trialRemainingDays,
          trial_start:          sub?.trial_start ?? null,
          trial_end:            sub?.trial_end ?? null,
          current_period_start: sub?.current_period_start ?? null,
          current_period_end:   sub?.current_period_end ?? sub?.expires_at ?? null,
          billing_interval:     sub?.billing_interval ?? "monthly",
          cancel_at_period_end: sub?.cancel_at_period_end === 1 || sub?.cancel_at_period_end === true,
          cancelled_at:         sub?.cancelled_at ?? null,
          grace_period_active:  grace.active,
          grace_period_ends_at: grace.ends_at,
          stripe_subscription_id: sub?.stripe_subscription_id ?? null,
          limits,
          features,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/plans ────────────────────────────────────────────────────────
    // Public static plan metadata — pricing, limits, feature sets.
    // Alias for GET /api/billing/plans with a cleaner path.
    // No auth required.
    if (request.method === "GET" && url.pathname === "/api/plans") {
      return json({ plans: getPublicBillingPlans() });
    }

    // ── POST /api/workspaces/:id/billing/checkout ─────────────────────────────
    // Workspace-scoped Stripe Checkout Session. Workspace owner only.
    // Body: { "plan": "starter|professional|business", "interval": "monthly|annual" }
    // interval defaults to "monthly". success_url and cancel_url are hardcoded.
    // Returns: { "url": "https://checkout.stripe.com/..." }
    const wsCheckoutMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/billing\/checkout$/);
    if (wsCheckoutMatch && request.method === "POST") {
      const wsId = wsCheckoutMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      // Workspace owner check: only the workspace owner may initiate billing.
      const access = await requireWorkspaceRole(user, wsId, "billing:manage", env);
      if (!access) return json({ error: "Forbidden", message: "Workspace owner required for billing." }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      // Enterprise plan requires sales contact — never self-serve checkout.
      const rawPlan = String(body.plan || "").trim().toLowerCase();
      if (rawPlan === "enterprise") {
        return json({
          error: "contact_sales",
          message: "Enterprise plans require a sales conversation. Contact us at sales@cybermeters.com.",
          contact_url: "mailto:sales@cybermeters.com",
        }, 400);
      }

      const parsedPlan = parseCheckoutPlan(rawPlan);
      if (!parsedPlan.ok) {
        return json({
          error: "invalid_plan",
          message: "plan must be one of: starter, professional, business.",
        }, 400);
      }

      const requestedPlan = parsedPlan.plan;
      const interval = normalizeBillingInterval(body.interval);
      const metadata = BILLING_PLAN_METADATA[requestedPlan];

      if (!metadata?.checkout_enabled) {
        return json({
          error: "plan_not_checkout_eligible",
          plan: requestedPlan,
          message: "This plan is not available through self-service checkout.",
        }, 400);
      }

      const priceResolution = getStripePriceIdForPlan(env, requestedPlan, interval);
      if (!priceResolution.ok) {
        return json({
          error: priceResolution.error,
          ...(priceResolution.missing?.length ? { missing: priceResolution.missing } : {}),
          message: "Stripe billing configuration is not ready for checkout.",
        }, 503);
      }

      // Resolve the billing owner for this workspace (workspace.owner_user_id).
      const ownerUserId = await getWorkspaceBillingUserId(wsId, user.id, env);

      // Lookup existing subscription for this owner to reuse Stripe customer if present.
      let existingSub = null;
      try {
        existingSub = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(ownerUserId)
          .first();
      } catch { /* continue without existing customer */ }

      // Hardcoded success/cancel URLs — prevents open redirect via client-supplied URLs.
      const origin = new URL(request.url).origin;
      // Use FRONTEND_URL env var if set (Cloudflare Pages URL), else derive from Worker origin.
      const frontendOrigin = env.FRONTEND_URL || origin.replace("cybermeters-platform.ttrnn47.workers.dev", "cybermeters.com");
      const successUrl = `${frontendOrigin}/billing?success=true`;
      const cancelUrl  = `${frontendOrigin}/billing?canceled=true`;

      const params = new URLSearchParams();
      params.set("mode",                    "subscription");
      params.set("line_items[0][price]",    priceResolution.price_id);
      params.set("line_items[0][quantity]", "1");
      params.set("success_url",             successUrl);
      params.set("cancel_url",              cancelUrl);
      params.set("metadata[user_id]",       String(ownerUserId));
      params.set("metadata[plan]",          requestedPlan);
      params.set("metadata[interval]",      interval);
      params.set("metadata[workspace_id]",  wsId);
      params.set("subscription_data[metadata][user_id]",    String(ownerUserId));
      params.set("subscription_data[metadata][plan]",       requestedPlan);
      params.set("subscription_data[metadata][interval]",   interval);
      params.set("subscription_data[metadata][workspace_id]", wsId);
      params.set("allow_promotion_codes", "true");

      if (existingSub?.stripe_customer_id) {
        params.set("customer", existingSub.stripe_customer_id);
      } else {
        params.set("customer_email", user.email);
      }

      let stripeSession;
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/checkout/sessions", {
          method:  "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });

        const stripeData = await stripeRes.json();
        if (!stripeRes.ok) {
          console.error("[workspace-billing/checkout] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return json({
            error:             "stripe_api_error",
            message:           "Stripe Checkout Session creation failed. Please try again.",
          }, 502);
        }
        stripeSession = stripeData;
      } catch (e) {
        console.error(`[workspace-billing/checkout] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      await createAuditEvent(env, {
        user_id:     user.id,
        workspace_id: wsId,
        event_type:  "billing_checkout_session_created",
        entity_type: "stripe_checkout_session",
        entity_id:   stripeSession.id,
        description: `Workspace checkout session created for ${requestedPlan} (${interval})`,
        metadata:    { plan: requestedPlan, interval, stripe_session_id: stripeSession.id, workspace_id: wsId },
      });

      return json({ url: stripeSession.url, session_id: stripeSession.id }, 200);
    }

    // ── POST /api/workspaces/:id/billing/portal ───────────────────────────────
    // Opens a Stripe Billing Portal for workspace subscription management.
    // Workspace owner only. Requires an existing Stripe customer.
    // Returns: { "url": "https://billing.stripe.com/..." }
    const wsPortalMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/billing\/portal$/);
    if (wsPortalMatch && request.method === "POST") {
      const wsId = wsPortalMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      const access = await requireWorkspaceRole(user, wsId, "billing:manage", env);
      if (!access) return json({ error: "Forbidden", message: "Workspace owner required for billing." }, 403);

      const stripeConfig = validateStripeSecretConfig(env);
      if (!stripeConfig.ok) {
        return json({
          error: stripeConfig.error,
          missing: stripeConfig.missing,
          message: "Stripe billing configuration is not ready for Customer Portal.",
        }, 503);
      }

      const ownerUserId = await getWorkspaceBillingUserId(wsId, user.id, env);

      let subscription = null;
      try {
        subscription = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(ownerUserId)
          .first();
      } catch (e) {
        return serverError("workspace-billing/portal-subscription", e, "Unable to load billing information.");
      }

      if (!subscription) {
        return json({ error: "subscription_not_found", message: "No active subscription found for this workspace." }, 404);
      }
      if (!subscription.stripe_customer_id) {
        return json({ error: "stripe_customer_missing", message: "No Stripe customer on file. Complete a checkout first." }, 409);
      }

      const origin = new URL(request.url).origin;
      const frontendOrigin = env.FRONTEND_URL || origin.replace("cybermeters-platform.ttrnn47.workers.dev", "cybermeters.com");
      const returnUrl = `${frontendOrigin}/billing`;

      const params = new URLSearchParams();
      params.set("customer",   subscription.stripe_customer_id);
      params.set("return_url", returnUrl);

      let portalSession;
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });

        const stripeData = await stripeRes.json();
        if (!stripeRes.ok) {
          console.error("[workspace-billing/portal] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return json({
            error:             "stripe_api_error",
            message:           "Stripe Billing Portal Session creation failed. Please try again.",
          }, 502);
        }
        portalSession = stripeData;
      } catch (e) {
        console.error(`[workspace-billing/portal] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      await createAuditEvent(env, {
        user_id:      user.id,
        workspace_id: wsId,
        event_type:   "billing_portal_opened",
        entity_type:  "stripe_billing_portal_session",
        entity_id:    portalSession.id,
        description:  "Workspace Stripe billing portal session created",
        metadata:     { subscription_id: subscription.id, stripe_session_id: portalSession.id, workspace_id: wsId },
      });

      return json({ url: portalSession.url, session_id: portalSession.id }, 200);
    }

    return json({ error: "Not found" }, 404);
  },

  // ── Hourly cron ───────────────────────────────────────────────────────────
  // Orchestration extracted to src/cron/scheduled.js (Sprint 9 phase 1); task
  // bodies stay here and are injected so the module needs no cycle.
  scheduled: (event, env, ctx) => runScheduled(event, env, ctx, {
    cleanupExpiredReports,
    generateScheduledReports,
    processDeletionRequests,
    processScheduledReports,
    retryFailedAssetAlerts,
    retryFailedLifecycleEmails,
    retryPendingDomainVerifications,
    runHostedDnsVerificationSweep,
    triggerScheduledScan,
  }),

  // ── Inbound DMARC aggregate (RUA) email handler ──────────────────────────
  // Extracted to src/email/inbound.js (Sprint 9 phase 1). Same behaviour,
  // same signature — Cloudflare Email Routing invokes this for every message.
  email: handleInboundEmail,
};

// ── Test-only named exports ──────────────────────────────────────────────────
// Consumed exclusively by scripts/validate-*.js (ESM test harnesses). The
// Workers runtime reads only the default export — named exports are inert in
// production. If a symbol moves to another module, re-export it from here so
// the harness import surface stays stable.
export {
  DMARC_RAMP_LADDER,
  INTELLIGENCE_ENGINE_REGISTRY,
  REMEDIATION_REGISTRY,
  SCAN_CHILD_TABLES,
  WORKSPACE_PURGE_TABLES,
  _cloudflareRouteFailure,
  alertChannelToApi,
  analyzeSpfChain,
  annotateExposureInfrastructure,
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
  buildExecutiveReportV2,
  cfCreateHostedTxt,
  classifyHostedCfError,
  classifyProviderInfrastructure,
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
  isValidDomain,
  legacyBrandAssetToApi,
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
  resolveCanonicalScanScore,
  resolveIntelligenceEngine,
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
