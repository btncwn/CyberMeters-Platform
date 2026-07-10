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

function buildCertificateAuthorityConcentrationFromModule(certMod) {
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

function computeScanBudget(bruteforceChecked) {
  const moduleEstimates = {
    dns:                        17,
    ssl:                        4,
    headers:                    2,
    email_security:             23,
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

function buildScanQuality(modules = {}) {
  // Sprint 10B: Workers Paid plan limit is 1,000 subrequests.
  // Previous value of 50 (free plan) caused every scan to report false "skipped" warnings.
  const SUBREQUEST_LIMIT = 1_000;

  const budget = modules.scan_budget || computeScanBudget();
  const estimated = budget.estimated_subrequests_total ?? 0;
  const warnings = [];
  const modulesSkipped = [];

  // Sprint 10C: "subdomains" is NOT a core module.
  // CT log lookup (crt.sh + CertSpotter) is an external enrichment query against
  // third-party services. When those services are rate-limited (CertSpotter HTTP 429
  // on shared Worker IPs) or slow, it is an external service failure — not a domain
  // security failure. DNS, SSL, Headers, Email directly assess the domain's own config.
  const coreModules = ["dns", "ssl", "headers", "email_security"];
  const coreIncomplete = coreModules.filter((name) => modules[name]?.error);

  // Classify modules that actually timed out or were skipped via the CAA budget sentinel.
  // Exclude "subdomains" — CT lookup failures are external service issues, not core
  // scan failures; they do not degrade scan_quality status.
  for (const [name, value] of Object.entries(modules)) {
    if (name === "subdomains") continue;
    const error = String(value?.error || "").toLowerCase();
    if (error.includes("skipped_due_to_subrequest_budget") || error.includes("timed out")) {
      modulesSkipped.push(name);
    }
  }

  // Only warn on real core module failures.
  for (const name of coreIncomplete) {
    warnings.push(`Core module incomplete: ${name}`);
  }

  const status = coreIncomplete.length > 0
    ? "partial"
    : (warnings.length > 0 || modulesSkipped.length > 0 ? "degraded" : "complete");

  return {
    status,
    warnings,
    modules_skipped: modulesSkipped,
    subrequest_budget: {
      estimated,
      limit:             SUBREQUEST_LIMIT,
      remaining_estimate: Math.max(0, SUBREQUEST_LIMIT - estimated),
    },
  };
}

// ── Main Scan Engine (runs via ctx.waitUntil) ─────────────────────────────────

async function runScanEngine(scanId, domainId, workspaceId, domain, env) {
  const startedAt = new Date().toISOString();

  try {
    // Mark scan as running in D1
    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'running' WHERE id = ?`)
      .bind(scanId)
      .run();

    // Phase 1: Run the 8 core modules in parallel.
    // • Subdomain discovery: 15s hard cap (parallel crt.sh 12s + CertSpotter 8s + wildcard DNS)
    // • DNS brute-force: 8s hard cap, runs concurrently — results merged after phase completes
    // • WHOIS uses RDAP (HTTP+JSON) — 12s timeout, fully non-blocking.
    const [dnsSettled, sslSettled, headersSettled, emailSettled, subdomainsSettled, techSettled, whoisSettled, bruteforceSettled] =
      await Promise.allSettled([
        runDnsModule(domain),
        runSslModule(domain),
        runHeadersModule(domain),
        runEmailModule(domain),
        runSubdomainsModule(domain),
        runTechModule(domain),
        runWhoisModule(domain),
        runBruteforceModule(domain),
      ]);

    const subdomainsResult = subdomainsSettled.status === "fulfilled"
      ? subdomainsSettled.value
      : { count: 0, items: [], sensitive: [], source: "certificate_transparency_multi_source",
          sources: { crt_sh: { count: 0, error: "module rejected" }, certspotter: { count: 0, error: "module rejected" } },
          wildcard_dns: false, wildcard_dns_addresses: [], wildcard_test_host: null, wildcard_warning: null,
          error: customerSafeFailure("scan/subdomains", subdomainsSettled.reason, "Subdomain module failed") };

    const rawBruteforceResult = bruteforceSettled.status === "fulfilled"
      ? bruteforceSettled.value
      : { checked: 0, found: 0, items: [], source: "dns_bruteforce",
          error: customerSafeFailure("scan/dns-bruteforce", bruteforceSettled.reason, "Brute-force module failed") };
    const bruteforceResult = filterWildcardBruteforceResults(
      rawBruteforceResult,
      subdomainsResult.wildcard_dns_addresses
    );

    // Merge brute-force finds into the subdomain item list (deduplicated).
    // Takeover and exposure modules receive the enriched list.
    const ctHostnames = new Set(subdomainsResult.items);
    const bruteNewItems = (bruteforceResult.items || [])
      .filter((item) => item.wildcard_match !== true)
      .map((i) => i.hostname)
      .filter((h) => h && !ctHostnames.has(h));
    const mergedSubdomainItems = [...subdomainsResult.items, ...bruteNewItems];

    // Phase 2: Takeover detection — uses merged (CT + brute-force) subdomain list.
    let takeoverResult;
    try {
      takeoverResult = await runTakeoverModule(domain, mergedSubdomainItems);
    } catch (err) {
      takeoverResult = { checked: 0, potential_risks: 0, risks: [], source: "subdomain_cname_fingerprint", error: customerSafeFailure("scan/takeover", err, "Takeover module failed") };
    }

    // Phase 3: Asset exposure probing — HTTP/HTTPS reachability + metadata.
    // Runs after takeover (sequential) to bound total concurrent I/O.
    let assetExposureResult;
    try {
      assetExposureResult = await runExposureModule(domain, mergedSubdomainItems);
      assetExposureResult = annotateExposureInfrastructure(
        assetExposureResult,
        takeoverResult.cname_observations
      );
      assetExposureResult = deduplicateExposureAssets(assetExposureResult, domain);
    } catch (err) {
      assetExposureResult = {
        checked:   0,
        reachable: 0,
        assets:    [],
        source:    "http_probe",
        error:     customerSafeFailure("scan/asset-exposure", err, "Asset exposure module failed"),
      };
    }

    const modules = {
      dns: dnsSettled.status === "fulfilled"
        ? dnsSettled.value
        : { error: customerSafeFailure("scan/dns", dnsSettled.reason, "DNS module failed") },

      ssl: sslSettled.status === "fulfilled"
        ? sslSettled.value
        : { error: customerSafeFailure("scan/ssl", sslSettled.reason, "SSL module failed") },

      headers: headersSettled.status === "fulfilled"
        ? headersSettled.value
        : { error: customerSafeFailure("scan/headers", headersSettled.reason, "Headers module failed") },

      email_security: emailSettled.status === "fulfilled"
        ? emailSettled.value
        : { error: customerSafeFailure("scan/email", emailSettled.reason, "Email module failed") },

      subdomains: subdomainsResult,

      subdomain_takeover: takeoverResult,

      asset_exposure: assetExposureResult,

      technology_detection: techSettled.status === "fulfilled"
        ? techSettled.value
        : { error: customerSafeFailure("scan/technology", techSettled.reason, "Technology module failed") },

      whois_intelligence: whoisSettled.status === "fulfilled"
        ? whoisSettled.value
        : { error: customerSafeFailure("scan/whois", whoisSettled.reason, "WHOIS module failed") },

      dns_bruteforce: bruteforceResult,

      // Phase 7i: pure computation, zero network I/O — must run before computeScore
      // so brand findings are included in the scored findings array.
      brand_monitoring: runTyposquatModule(domain),
    };
    const emailApplicability = isEmailApplicable(domain, modules.dns);
    if (!modules.email_security.error) {
      modules.email_security.applicability = emailApplicability;
      if (!emailApplicability.applicable) modules.email_security.remediation_actions = [];
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

    // Append admin surface detection findings (score_impact: 0 — no scoring changes in Phase 1)
    const adminMod = modules.admin_surface_detection;
    if (adminMod && !adminMod.error && adminMod.detected && adminMod.total > 0) {
      const criticalSvcs = adminMod.services.filter((s) => s.risk_level === "critical");
      const highSvcs     = adminMod.services.filter((s) => s.risk_level === "high");
      const mediumSvcs   = adminMod.services.filter((s) => s.risk_level === "medium");

      if (criticalSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_critical",
          module:       "admin_surface_detection",
          severity:     "critical",
          score_impact: 0,
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
          score_impact: 0,
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
          score_impact: 0,
          title:        `Collaboration Tool${mediumSvcs.length > 1 ? "s" : ""} Publicly Accessible`,
          description:  `${mediumSvcs.length} collaboration or source-control service${mediumSvcs.length > 1 ? "s are" : " is"} publicly accessible: ${mediumSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}. Verify these require authentication and enforce MFA.`,
          recommendation: `Ensure ${mediumSvcs.map((s) => s.hostname).join(", ")} enforce MFA and are patched to the latest version.`,
        });
      }
    }

    // Append domain security enrichment findings (score_impact: 0 — no major scoring changes)
    const enrichMod = modules.domain_security_enrichment;
    if (enrichMod && !enrichMod.error) {
      // ── CAA ──────────────────────────────────────────────────────────────
      if (enrichMod.caa && !enrichMod.caa.error) {
        if (!enrichMod.caa.present) {
          findings.push({
            id:             "dse_missing_caa",
            module:         "domain_security_enrichment",
            severity:       "medium",
            score_impact:   0,
            title:          "No CAA DNS Record",
            description:    "This domain has no CAA (Certification Authority Authorization) record. Without CAA, any publicly trusted CA can issue TLS certificates for this domain, increasing the risk of mis-issuance.",
            recommendation: `Add a DNS CAA record to restrict which CAs may issue certificates. Example: \`0 issue "letsencrypt.org"\`, \`0 issue "pki.goog"\`. Add \`0 iodef "mailto:security@${domain}"\` to receive mis-issuance reports.`,
          });
        } else if (enrichMod.caa.issuers.length === 0 && enrichMod.caa.records.length > 0) {
          findings.push({
            id:             "dse_caa_no_issuers",
            module:         "domain_security_enrichment",
            severity:       "low",
            score_impact:   0,
            title:          "CAA Record Present But No Issuers Listed",
            description:    `A CAA record exists but contains no \`issue\` or \`issuewild\` tags, which effectively blocks all certificate issuance for this domain.`,
            recommendation: `Add at least one \`0 issue "<ca>"\` tag to allow your CA to issue certificates.`,
          });
        }
      }

      // ── HSTS ─────────────────────────────────────────────────────────────
      if (enrichMod.hsts && !enrichMod.hsts.error && enrichMod.hsts.present) {
        const h = enrichMod.hsts;
        if (h.max_age !== null && h.max_age < 31_536_000) {
          findings.push({
            id:             "dse_hsts_short_maxage",
            module:         "domain_security_enrichment",
            severity:       "low",
            score_impact:   0,
            title:          "HSTS max-age Below Recommended Minimum",
            description:    `The HSTS header specifies max-age=${h.max_age} seconds (${Math.round(h.max_age / 86400)} days). The recommended minimum is 31,536,000 (365 days) to qualify for the HSTS preload list and ensure robust protection.`,
            recommendation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          });
        }
        if (!h.preload_eligible && h.present) {
          const missing = [];
          if (!h.include_subdomains)   missing.push("includeSubDomains");
          if (!h.preload_directive)    missing.push("preload directive");
          if (h.max_age === null || h.max_age < 31_536_000) missing.push("max-age ≥ 31536000");
          if (missing.length > 0) {
            findings.push({
              id:             "dse_hsts_not_preload_eligible",
              module:         "domain_security_enrichment",
              severity:       "low",
              score_impact:   0,
              title:          "HSTS Not Eligible for Preload List",
              description:    `This domain's HSTS configuration is missing the following preload requirements: ${missing.join(", ")}. Preloaded HSTS protects users on their very first visit before any HSTS header is seen.`,
              recommendation: "Update to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — then submit to https://hstspreload.org",
            });
          }
        }
      }

      // ── Cookies ───────────────────────────────────────────────────────────
      if (enrichMod.cookies && !enrichMod.cookies.error && enrichMod.cookies.found > 0) {
        const c = enrichMod.cookies;
        if (c.insecure_count > 0) {
          findings.push({
            id:             "dse_cookie_no_secure",
            module:         "domain_security_enrichment",
            severity:       "high",
            score_impact:   0,
            title:          `${c.insecure_count} Cookie${c.insecure_count > 1 ? "s" : ""} Missing Secure Flag`,
            description:    `${c.insecure_count} of ${c.found} cookie${c.found > 1 ? "s" : ""} set by ${domain} lack the Secure flag. These cookies may be transmitted over unencrypted HTTP connections, exposing session tokens to network interception.`,
            recommendation: "Add the Secure attribute to all session and authentication cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
          });
        }
        if (c.no_httponly > 0) {
          findings.push({
            id:             "dse_cookie_no_httponly",
            module:         "domain_security_enrichment",
            severity:       "medium",
            score_impact:   0,
            title:          `${c.no_httponly} Cookie${c.no_httponly > 1 ? "s" : ""} Missing HttpOnly Flag`,
            description:    `${c.no_httponly} cookie${c.no_httponly > 1 ? "s are" : " is"} accessible via JavaScript. If an XSS vulnerability exists, these cookies can be exfiltrated by injected scripts.`,
            recommendation: "Add HttpOnly to all cookies that do not need to be accessed by JavaScript (session tokens, auth cookies).",
          });
        }
        if (c.no_samesite > 0) {
          findings.push({
            id:             "dse_cookie_no_samesite",
            module:         "domain_security_enrichment",
            severity:       "low",
            score_impact:   0,
            title:          `${c.no_samesite} Cookie${c.no_samesite > 1 ? "s" : ""} Missing SameSite Attribute`,
            description:    `${c.no_samesite} cookie${c.no_samesite > 1 ? "s do" : " does"} not specify a SameSite attribute. Without SameSite, browsers may send these cookies in cross-site requests, enabling CSRF attacks.`,
            recommendation: "Set SameSite=Strict or SameSite=Lax on all cookies. Use SameSite=None; Secure only for cookies that must be sent in cross-site contexts.",
          });
        }
      }
    }

    // Phase 4: Historical Change Detection — runs after computeScore so current
    // score and findings are known. Mutates modules in place before R2 write.
    try {
      modules.historical_changes = await runHistoricalModule(
        scanId, domain, score, findings, modules, env
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
        new_takeover_risks: [],
        new_exposed_assets: [],
        source:             "previous_scan_comparison",
        error:              customerSafeFailure("scan/history", err, "Historical module failed"),
      };
    }

    // Phase 5: CVE + KEV + Email Intelligence (all parallel)
    // • CVE: queries NVD for high/critical CVEs per detected technology
    // • KEV: fetches CISA catalog and matches by technology keyword
    // • EmailIntel: enriches SPF/DMARC/DKIM, adds MTA-STS + TLS-RPT, computes email score
    const [cveSettled, kevSettled, emailIntelSettled] = await Promise.allSettled([
      runCveModule(modules.technology_detection),
      runKevModule(modules.technology_detection),
      runEmailIntelModule(domain, modules.email_security, modules.dns),
    ]);

    modules.cve_intelligence = cveSettled.status === "fulfilled"
      ? cveSettled.value
      : { technologies_checked: [], results: {}, total_cves: 0, critical_count: 0, high_count: 0,
          source: "nvd_api", error: customerSafeFailure("scan/cve", cveSettled.reason, "CVE module failed") };

    modules.known_exploited_vulnerabilities = kevSettled.status === "fulfilled"
      ? kevSettled.value
      : { matches: [], checked: 0, matched: 0,
          source: "cisa_kev", error: customerSafeFailure("scan/kev", kevSettled.reason, "KEV module failed") };

    modules.email_security_intelligence = emailIntelSettled.status === "fulfilled"
      ? emailIntelSettled.value
      : { error: customerSafeFailure("scan/email-intelligence", emailIntelSettled.reason, "Email intelligence module failed") };
    if (!modules.email_security_intelligence.error && emailApplicability.applicable) {
      const transportDetails = buildEmailTransportDetails(modules.email_security_intelligence);
      Object.assign(modules.email_security, transportDetails);
      modules.email_security.remediation_actions = buildEmailRemediationActions(
        domain,
        modules.email_security,
        modules.email_security_intelligence
      );
    }

    // Phase 6: Risk intelligence + Remediation plan (pure computation — no I/O)
    // Risk module enriches all findings with business-impact language and risk categories.
    // Remediation module converts findings + KEV matches into P1/P2/P3 roadmap.
    modules.risk_intelligence = runRiskModule(findings, modules);
    modules.remediation_plan  = runRemediationModule(
      findings,
      modules.known_exploited_vulnerabilities,
      modules.subdomain_takeover,
    );

    // Phase 7: Cloud storage discovery — validates only evidence-backed storage
    // candidates from observed ASM/CNAME/header signals. No guessing or listing
    // enumeration; response bodies are only inspected for listing indicators.
    modules.cloud_storage_discovery = await runCloudStorageModule(domain, modules);
    for (const f of modules.cloud_storage_discovery.findings || []) {
      findings.push(f);
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
  const httpsAvailable = ssl.https_available === true;
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
    note:                    headers.validation_uncertain
      ? "Response may be from bot-protection layer — headers not reliable"
      : httpsAvailable ? "HTTPS available" : "HTTPS unavailable",
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
  let consistencyScore = 100;
  if (!httpsAvailable)                          consistencyScore -= 25;  // no HTTPS at all
  if (headers.validation_uncertain)             consistencyScore -= 20;  // bot-protection interference
  if (!httpChain.http_redirect_validated)       consistencyScore -= 15;  // HTTP probe failed
  if (canonical_confidence === "low")           consistencyScore -= 15;  // low confidence canonical
  if (isWwwRedirect && !httpsAvailable)         consistencyScore -= 10;  // www redirect but no HTTPS
  if (!canonical_url)                           consistencyScore -= 15;  // cannot determine canonical
  consistencyScore = Math.max(0, consistencyScore);

  return {
    canonical_url,
    canonical_confidence,
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
    modules.admin_surface_detection = runAdminSurfaceModule(modules);

    // Phase 7b-ii: Canonical URL profile — pure computation from existing SSL/headers data.
    modules._domain = domain;
    modules.canonical_url_profile = buildCanonicalUrlProfile(modules);

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

    // Phase 7d: Scan budget — pure computation, zero I/O.
    // Estimates subrequest usage across all modules and warns if close to the
    // Cloudflare Worker free-plan 50-subrequest limit.
    modules.scan_budget = computeScanBudget(bruteforceResult.checked);
    const scanQuality = buildScanQuality(modules);

    // Phase 7e: Vendor Risk — pure computation, zero I/O.
    // Detects third-party vendors from signals already captured in modules:
    // SPF, MX, NS, DKIM, CSP, Server header, CNAME targets, tech detection.
    modules.vendor_risk = detectVendorsFromModules(modules);

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
    // Correlates modules.ssl + modules.subdomains (CT data) to produce
    // expiry status, sensitive-host inventory, and suspicious signal list.
    modules.certificate_intelligence = runCertificateIntelligenceModule(modules, domain);
    if (modules.dns) {
      modules.dns.operational_resilience = buildDnsOperationalResilience({
        nameservers: modules.dns.nameservers || [],
        dnssec: modules.dns.dnssec || null,
        certificateAuthority: buildCertificateAuthorityConcentrationFromModule(modules.certificate_intelligence),
      });
    }

    // Phase 7i: brand_monitoring already populated in modules before computeScore —
    // see module initialisation block above. No re-run needed here.

    // Phase 7j: Identity Asset Discovery — pure computation, zero network I/O.
    // Identifies authentication surfaces, login portals, SSO/OAuth/SAML endpoints
    // and identity provider relationships from signals already captured in Phases 1–7i.
    // Detects Okta, Auth0, Entra ID, Ping Identity, OneLogin, Duo, JumpCloud, Keycloak,
    // ADFS, and Google Workspace IdP from CNAME/SPF/MX/CSP/server signals.
    // Also classifies discovered subdomains with identity-related hostname prefixes.
    modules.identity_discovery = runIdentityDiscoveryModule(modules, domain);

    // Phase 7k: Vendor Relationship Discovery — pure computation, zero network I/O.
    // Parses CSP directives (script-src, connect-src, frame-src, img-src) to identify
    // third-party vendor relationships from JavaScript, API, and iframe dependencies.
    // Uses CNAME signals for high-confidence DNS-level confirmation.
    // 10-category taxonomy: analytics | payments | crm | support | identity |
    //   collaboration | cloud | cdn | security | certificate_authority
    modules.vendor_relationships = runVendorRelationshipModule(modules);

    const completedAt = new Date().toISOString();

    // Sprint 9A: Normalise all findings to v2 schema before report assembly.
    // Additive only — existing fields are preserved; missing fields default to
    // null / [] so every finding exposes a consistent shape to consumers.
    const normalizedFindings = findings.map(normalizeFindingSchema);

    // Build full structured report
    const report = {
      scan_id:             scanId,
      domain_id:           domainId,
      domain,
      status:              "completed",
      cyber_metrics_score: score,
      risk_level,
      started_at:          startedAt,
      completed_at:        completedAt,
      findings:            normalizedFindings,
      recommendations,
      scan_quality:         scanQuality,
      modules,
    };

    // Write completed report to R2
    await env.cybermeters_reports.put(
      `reports/${scanId}.json`,
      JSON.stringify(report, null, 2),
      { httpMetadata: { contentType: "application/json" } }
    );

    // Update D1 scans row
    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'completed', score = ?, rating = ? WHERE id = ?`)
      .bind(score, risk_level, scanId)
      .run();

    if (workspaceId) {
      // Compute BRS using scan findings + workspace intelligence data
      let brsScore = null;
      try {
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
        });
        brsScore = brs.brs;
      } catch { /* non-fatal — BRS unavailable for this scan */ }

      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO historical_scores
               (id, workspace_id, domain_id, scan_id, domain, score, rating, brs_score, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(createId("hscore"), workspaceId, domainId, scanId, domain, score, risk_level, brsScore, completedAt)
          .run();
      } catch { /* non-fatal — scan completion remains source of truth */ }
    }

    // Persist findings to D1
    for (const f of findings) {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO findings (id, scan_id, severity, title, recommendation, evidence_json, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          createId("finding"),
          scanId,
          f.severity,
          f.title,
          f.description,
          f.evidence ? JSON.stringify(f.evidence) : null,
          f.confidence ?? null
        )
        .run();
    }

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

    // Phase 8: Asset Inventory Upsert — runs AFTER completion status is written.
    // Failure here cannot leave the scan stuck in "running".
    // Uses D1 batch() to minimise round-trips.
    try {
      await upsertAssetInventory(scanId, domainId, domain, modules, env);
    } catch { /* non-fatal — inventory update will catch up on next scan */ }

    // Phase 8b: Admin Surface Events — one asset_event per detected service per workspace.
    // Runs after upsertAssetInventory so workspace_assets rows are already present,
    // allowing asset_id FK resolution.
    try {
      await insertAdminSurfaceEvents(scanId, domainId, modules.admin_surface_detection, env);
    } catch { /* non-fatal */ }

    // Phase 8c: Vendor Inventory Upsert — persists vendor_risk detections to D1.
    // Uses workspace lookup internally. Preserves first_seen; marks unseen vendors inactive.
    try {
      await upsertVendorInventory(domainId, modules.vendor_risk, env);
    } catch { /* non-fatal */ }

    // Phase 8d: Certificate Events — fires asset_events for sensitive CT hosts,
    // expiry warnings, and growth signals.
    try {
      await insertCertificateEvents(scanId, domainId, modules.certificate_intelligence, env);
    } catch { /* non-fatal */ }

    // Phase 8d.1: Certificate Timeline — persists cross-scan certificate
    // observations and emits alerts for new certs, SANs, and issuers.
    try {
      await upsertCertificateObservation(scanId, domainId, modules.certificate_intelligence, env);
    } catch { /* non-fatal */ }

    // Phase 8e: Brand Asset Upsert — persists generated typosquat candidates to
    // workspace_brand_assets as 'unverified'.  DNS validation happens separately
    // via POST /brand-monitoring/refresh to stay within subrequest budget.
    try {
      await upsertBrandAssets(domainId, modules.brand_monitoring, env);
    } catch { /* non-fatal */ }

    // Phase 8f: Identity Asset Upsert — persists identity_discovery results into
    // identity_assets table. Also upserts detected IdP providers into workspace_vendors.
    try {
      await upsertIdentityAssets(domainId, scanId, modules.identity_discovery, env);
    } catch { /* non-fatal */ }

    // Phase 8g: Vendor Relationship Upsert — persists CSP-derived vendor relationships
    // into workspace_vendors with source_module='vendor_relationship'. Additive to
    // Phase 8c (DNS-sourced vendor_risk entries) — no inactive sweep here.
    try {
      await upsertVendorRelationships(domainId, modules.vendor_relationships, env);
    } catch { /* non-fatal */ }

    // Phase 8h: Vendor Risk Score Upsert — calculates workspace-level vendor
    // exposure scores from current workspace_vendors rows.
    try {
      await recomputeVendorRiskScoresForDomain(domainId, env);
    } catch { /* non-fatal */ }

    // Phase 8i: Supply Chain Intelligence — computes and persists supply chain
    // risk scores, concentration analysis, and cascading risk scenarios per workspace.
    // Runs after all vendor phases so it sees the full vendor picture.
    try {
      const scWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (scWsRows.results || [])) {
        const scPayload = await computeSupplyChainIntelligence(workspace_id, env);
        await upsertSupplyChainScore(workspace_id, scPayload, env);
      }
    } catch { /* non-fatal */ }

    // Phase 9: Asset Change Alert — one grouped email per workspace per scan.
    // Reads asset_events written by Phase 8, deduped via asset_alert_records.
    // Fully non-fatal — swallows all errors.
    try {
      await sendAssetChangeAlert(domainId, domain, scanId, env);
    } catch { /* non-fatal */ }

    // Phase 10: Notification Events — create in-app notifications for scan
    // completion and any critical/high findings. Non-fatal.
    try {
      await createNotificationsForDomain(domainId, domain, scanId, score, risk_level, findings, env);
      
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
          score,
          findings,
          modules,
          startedAt,
          env
        );
      }
    } catch { /* non-fatal */ }

    // Phase 11: Audit — scan completed. Fire per-workspace. Non-fatal.
    try {
      const wsRows = await env.cybermeters_db
        .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
        .bind(domainId)
        .all();
      for (const { workspace_id } of (wsRows.results || [])) {
        await createAuditEvent(env, {
          workspace_id,
          event_type:  "scan_completed",
          entity_type: "scan",
          entity_id:   scanId,
          description: `Scan completed for ${domain} — score ${score}, risk ${risk_level}`,
          metadata:    { scan_id: scanId, domain, domain_id: domainId, score, risk_level },
        });
        // Lifecycle: first scan completed (once per workspace+domain via dedupe).
        await sendLifecycleEmail(env, { type: "lifecycle_first_scan_completed", workspace_id, domain }).catch(() => {});
      }
      // Also fire a workspace-agnostic event if domain has no workspaces
      if ((wsRows.results || []).length === 0) {
        await createAuditEvent(env, {
          event_type:  "scan_completed",
          entity_type: "scan",
          entity_id:   scanId,
          description: `Scan completed for ${domain} — score ${score}, risk ${risk_level}`,
          metadata:    { scan_id: scanId, domain, domain_id: domainId, score, risk_level },
        });
      }
    } catch { /* non-fatal */ }

  } catch (err) {
    // Best-effort: write failure state to R2 and D1.
    // Each write is individually guarded so one failure cannot prevent the other.
    // The D1 status write is the most critical — it stops the UI polling loop.
    const failedAt = new Date().toISOString();

    try {
      await env.cybermeters_reports.put(
        `reports/${scanId}.json`,
        JSON.stringify({
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
        }, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );
    } catch { /* R2 write failure — non-fatal */ }

    try {
      await env.cybermeters_db
        .prepare(`UPDATE scans SET status = 'failed' WHERE id = ?`)
        .bind(scanId)
        .run();
    } catch { /* D1 write failure — scan will remain 'running' but we cannot do more */ }

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
      for (const { workspace_id } of wsRows) {
        await createAuditEvent(env, {
          workspace_id: workspace_id ?? null,
          event_type:  "scan_failed",
          entity_type: "scan",
          entity_id:   scanId,
          description: `Scan failed for ${domain}`,
          metadata:    { scan_id: scanId, domain, domain_id: domainId, error: err?.message ?? "Unknown scan engine error" },
        });
      }
      if (wsRows.length === 0) {
        await createAuditEvent(env, {
          event_type:  "scan_failed",
          entity_type: "scan",
          entity_id:   scanId,
          description: `Scan failed for ${domain}`,
          metadata:    { scan_id: scanId, domain, domain_id: domainId, error: err?.message ?? "Unknown scan engine error" },
        });
      }
    } catch { /* non-fatal */ }
  }
}

// ── Admin Surface Event Insertion ────────────────────────────────────────────
//
// Writes one asset_event per detected admin service per workspace per scan.
// Called after upsertAssetInventory so workspace_assets rows already exist.
// All errors are non-fatal — the scan is already marked completed by this point.

async function insertAdminSurfaceEvents(scanId, domainId, adminModule, env) {
  const actionableServices = (adminModule?.services || [])
    .filter((service) => service.finding_type !== "observation");
  if (!adminModule || !adminModule.detected || actionableServices.length === 0) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare(`SELECT workspace_id FROM workspace_domains WHERE domain_id = ?`)
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();

  for (const { workspace_id } of wsRows) {
    for (const svc of actionableServices) {
      try {
        // Resolve asset_id if the asset was already upserted by upsertAssetInventory
        const assetRow = await env.cybermeters_db
          .prepare(`SELECT id FROM workspace_assets WHERE workspace_id = ? AND hostname = ?`)
          .bind(workspace_id, svc.hostname)
          .first();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, asset_id, scan_id,
                event_type, hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            createId("evt"),
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
    workspaces:   wsRows.length,
  }));
}

/**
 * upsertVendorRelationships(domainId, relModule, env)
 * Phase 8g: Persists vendor_relationship detections into workspace_vendors
 * with source_module = 'vendor_relationship'.
 *
 * Uses INSERT OR IGNORE + UPDATE to preserve first_seen and refresh last_seen.
 * Does NOT mark undetected vendors inactive — vendor_risk (Phase 8c) handles
 * that sweep for DNS-sourced entries.
 */
async function upsertVendorRelationships(domainId, relModule, env) {
  if (!relModule?.detected || !relModule.vendors?.length) return;

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

  for (const { workspace_id } of wsRows) {
    for (const v of relModule.vendors) {
      try {
        const id           = createId("vendor");
        const evidenceJson = JSON.stringify(v.source_signals || []);

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
  }
}

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
async function upsertVendorInventory(domainId, vendorRisk, env) {
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

/**
 * Compute next_run_at for a scheduled_reports row.
 * weekly   → next Monday 00:00 UTC
 * monthly  → 1st of next month 00:00 UTC
 * quarterly→ 1st of next calendar quarter 00:00 UTC
 */
function computeScheduledReportNextRunAt(frequency) {
  const now = new Date();
  const y   = now.getUTCFullYear();
  const m   = now.getUTCMonth(); // 0-based

  if (frequency === "weekly") {
    // Next Monday
    const d = new Date(Date.UTC(y, m, now.getUTCDate()));
    const dow = d.getUTCDay(); // 0=Sun
    const daysUntilMonday = dow === 0 ? 1 : (8 - dow);
    d.setUTCDate(d.getUTCDate() + daysUntilMonday);
    return d.toISOString();
  }
  if (frequency === "monthly") {
    // 1st of next month
    return new Date(Date.UTC(y, m + 1, 1)).toISOString();
  }
  if (frequency === "quarterly") {
    // 1st of next calendar quarter
    const nextQ = Math.floor(m / 3) + 1;
    const nextQYear  = y + Math.floor(nextQ / 4);
    const nextQMonth = (nextQ % 4) * 3; // 0, 3, 6, 9
    return new Date(Date.UTC(nextQYear, nextQMonth, 1)).toISOString();
  }
  // fallback: 30 days
  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000).toISOString();
}

function calculateNextRun(frequency, from = new Date()) {
  const base = new Date(from);
  if (frequency === "weekly") {
    return new Date(base.getTime() + 7 * 24 * 60 * 60 * 1_000).toISOString();
  }
  if (frequency === "monthly") {
    return new Date(Date.UTC(
      base.getUTCFullYear(),
      base.getUTCMonth() + 1,
      base.getUTCDate(),
      base.getUTCHours(),
      base.getUTCMinutes(),
      base.getUTCSeconds()
    )).toISOString();
  }
  return null;
}

function normalizeReportScheduleFrequency(value) {
  const frequency = typeof value === "string" ? value.trim().toLowerCase() : "";
  return ["weekly", "monthly"].includes(frequency) ? frequency : null;
}

function normalizeReportScheduleRecipients(value) {
  if (!Array.isArray(value)) return null;
  const recipients = [...new Set(value.map((v) => String(v || "").trim().toLowerCase()).filter(Boolean))];
  const emailPattern = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
  if (recipients.length === 0 || recipients.length > 20) return null;
  if (!recipients.every((email) => emailPattern.test(email))) return null;
  return recipients;
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
// generateWorkspaceExecutiveReport — collect data, build PDF, upload to R2,
// write a workspace_reports row.  Returns the completed row on success.
// Throws on fatal error (the row is marked failed before throwing).

async function generateWorkspaceExecutiveReport(workspaceId, env, options = {}) {
  const {
    report_type   = 'manual',
    report_period = null,
    scan_id       = null,
  } = options;

  const now = new Date();

  // ── Derive report_period when not supplied ────────────────────────────────
  const period = report_period ?? (() => {
    if (report_type === 'weekly_executive') {
      // ISO 8601 week: YYYY-Www (Thursday-anchored)
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));  // move to Thursday
      const year = d.getUTCFullYear();
      const wk   = Math.ceil((((d - Date.UTC(year, 0, 1)) / 86400000) + 1) / 7);
      return `${year}-W${String(wk).padStart(2, '0')}`;
    }
    if (report_type === 'monthly_executive') {
      return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    }
    if (report_type === 'quarterly_executive') {
      const q = Math.floor(now.getUTCMonth() / 3) + 1;
      return `${now.getUTCFullYear()}-Q${q}`;
    }
    if (report_type === 'scan_snapshot' && scan_id) {
      return `scan-${scan_id}`;
    }
    // manual: timestamp-based period so re-runs don't collide
    const ts = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
    return `manual-${ts}`;
  })();

  const reportId  = createId('rpt');
  const createdAt = now.toISOString();
  const r2Key     = `reports/executive/${workspaceId}/${report_type}/${period}/executive-report.pdf`;
  const retentionPolicy = await getReportRetentionPolicyForWorkspace(workspaceId, env);

  // Insert a pending row first so we can always flip it to failed on error
  await env.cybermeters_db.prepare(
    `INSERT INTO workspace_reports
       (id, workspace_id, report_type, report_period, report_key, status, created_at, retention_policy)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`
  ).bind(reportId, workspaceId, report_type, period, r2Key, createdAt, retentionPolicy).run();

  let pdfData, bytes;
  try {
    pdfData = await collectPdfData(workspaceId, env);
    if (!pdfData) throw new Error('Workspace not found');
    pdfData.report_id = reportId;
    bytes   = buildExecutivePdf(pdfData);
  } catch (genErr) {
    await env.cybermeters_db.prepare(
      `UPDATE workspace_reports
         SET status = 'failed', generated_at = ?, metadata_json = ?
       WHERE id = ?`
    ).bind(new Date().toISOString(), JSON.stringify({ error: String(genErr?.message ?? genErr) }), reportId).run();
    throw genErr;
  }

  const generatedAt = new Date().toISOString();

  await env.cybermeters_reports.put(r2Key, bytes, {
    httpMetadata: { contentType: 'application/pdf' },
    customMetadata: {
      workspace_id:  workspaceId,
      report_type,
      report_period: period,
      generated_at:  generatedAt,
    },
  });

  const reportSizeBytes = typeof bytes?.byteLength === "number"
    ? bytes.byteLength
    : (typeof bytes?.length === "number" ? bytes.length : null);

  await env.cybermeters_db.prepare(
    `UPDATE workspace_reports
     SET status = 'completed', generated_at = ?, report_size_bytes = ?
     WHERE id = ?`
  ).bind(generatedAt, reportSizeBytes, reportId).run();

  // Notification + audit — report generated. Non-fatal: report generation must not fail
  // if notification or audit persistence is unavailable.
  try {
    await createNotificationEvent(env, workspaceId, {
      type:     "report_generated",
      severity: "info",
      title:    `Executive report ready`,
      message:  `${report_type.replace(/_/g, " ")} report for period ${period} is available for download.`,
      metadata: { report_id: reportId, report_type, report_period: period },
    });
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      event_type:   "report_generated",
      entity_type:  "report",
      entity_id:    reportId,
      description:  `Executive report generated (${report_type}, period ${period})`,
      metadata:     { report_id: reportId, report_type, report_period: period },
    });
  } catch { /* non-fatal */ }

  return {
    id:            reportId,
    workspace_id:  workspaceId,
    report_type,
    report_period: period,
    report_key:    r2Key,
    status:        'completed',
    generated_at:  generatedAt,
    created_at:    createdAt,
    retention_policy: retentionPolicy,
  };
}

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


function getPlanLimits(plan) {
  const normalized = normalizePlan(plan);
  const limits = PLAN_LIMITS[normalized] ?? PLAN_LIMITS.free;
  return {
    ...limits,
    // Backward-compatible aliases for existing v1 screens/checks.
    domains_per_workspace: limits.domains,
    members_per_workspace: limits.users,
    users_per_workspace: limits.users,
  };
}

function getPlanRetentionDays(plan) {
  const normalized = normalizePlan(plan);
  if (normalized === "enterprise") return null;
  if (normalized === "business") return 730;
  if (normalized === "professional") return 365;
  if (normalized === "starter") return 90;
  return 30;
}

function retentionDaysToPolicy(days) {
  if (days === null || days === undefined) return "forever";
  const n = Number(days);
  if (n <= 30) return "30_days";
  if (n <= 90) return "90_days";
  if (n <= 365) return "1_year";
  return "2_years";
}

function retentionPolicyToDays(policy) {
  if (policy === "forever") return null;
  if (policy === "30_days") return 30;
  if (policy === "90_days") return 90;
  if (policy === "1_year") return 365;
  if (policy === "2_years") return 730;
  if (policy === "7_years") return 2555;
  return 730;
}

function getRetentionCutoffForDays(days, now = new Date()) {
  if (days === null || days === undefined) return null;
  const n = Number(days);
  if (!Number.isFinite(n) || n <= 0) return null;
  const date = new Date(now.getTime());
  date.setUTCDate(date.getUTCDate() - n);
  return date.toISOString();
}

async function getWorkspaceRetentionSettings(workspaceId, env) {
  const ownerId = await getWorkspaceOwnerId(workspaceId, env);
  const plan = await getEffectivePlan(ownerId, env);
  const planDefaultDays = getPlanRetentionDays(plan);
  let row = null;
  try {
    row = await env.cybermeters_db
      .prepare("SELECT retention_days, auto_cleanup, updated_at FROM workspace_retention_settings WHERE workspace_id = ?")
      .bind(workspaceId)
      .first();
  } catch { /* migration may not be applied yet */ }
  const configuredDays = row ? (row.retention_days === null ? null : Number(row.retention_days)) : undefined;
  const effectiveDays = configuredDays === undefined ? planDefaultDays : configuredDays;
  return {
    plan,
    retention_days: effectiveDays,
    plan_default_retention_days: planDefaultDays,
    retention_policy: retentionDaysToPolicy(effectiveDays),
    auto_cleanup: row ? row.auto_cleanup !== 0 : true,
    source: row ? "workspace_setting" : "plan_default",
    updated_at: row?.updated_at ?? null,
  };
}

async function getWorkspaceReportStorageMetrics(workspaceId, env) {
  const retention = await getWorkspaceRetentionSettings(workspaceId, env);
  let row;
  try {
    row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(*) AS reports_count,
                COALESCE(SUM(report_size_bytes), 0) AS stored_bytes,
                SUM(CASE WHEN report_size_bytes IS NULL THEN 1 ELSE 0 END) AS estimated_reports
         FROM workspace_reports
         WHERE workspace_id = ? AND deleted_at IS NULL`
      )
      .bind(workspaceId)
      .first();
  } catch {
    row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(*) AS reports_count
         FROM workspace_reports
         WHERE workspace_id = ? AND deleted_at IS NULL`
      )
      .bind(workspaceId)
      .first();
  }
  const reportsCount = Number(row?.reports_count ?? 0);
  const estimatedReports = Number(row?.estimated_reports ?? reportsCount);
  const estimatedReportBytes = 250_000;
  const storageBytes = Number(row?.stored_bytes ?? 0) + (estimatedReports * estimatedReportBytes);
  return {
    reports_count: reportsCount,
    storage_bytes: storageBytes,
    storage_estimated: estimatedReports > 0,
    retention_days: retention.retention_days,
    retention_policy: retention.retention_policy,
    auto_cleanup: retention.auto_cleanup,
  };
}

async function getReportRetentionPolicyForWorkspace(workspaceId, env) {
  return (await getWorkspaceRetentionSettings(workspaceId, env)).retention_policy;
}

function getRetentionCutoff(policy, now = new Date()) {
  if (policy === "forever") return null;
  const date = new Date(now.getTime());
  if (policy === "30_days") date.setUTCDate(date.getUTCDate() - 30);
  else if (policy === "90_days") date.setUTCDate(date.getUTCDate() - 90);
  else if (policy === "1_year") date.setUTCFullYear(date.getUTCFullYear() - 1);
  else if (policy === "2_years") date.setUTCFullYear(date.getUTCFullYear() - 2);
  else if (policy === "7_years") date.setUTCFullYear(date.getUTCFullYear() - 7);
  else date.setUTCFullYear(date.getUTCFullYear() - 2);
  return date.toISOString();
}

function getReportExpiresAt(policy, effectiveAt) {
  if (!effectiveAt || policy === "forever") return null;
  const date = new Date(effectiveAt);
  if (Number.isNaN(date.getTime())) return null;
  if (policy === "30_days") date.setUTCDate(date.getUTCDate() + 30);
  else if (policy === "90_days") date.setUTCDate(date.getUTCDate() + 90);
  else if (policy === "1_year") date.setUTCFullYear(date.getUTCFullYear() + 1);
  else if (policy === "2_years") date.setUTCFullYear(date.getUTCFullYear() + 2);
  else if (policy === "7_years") date.setUTCFullYear(date.getUTCFullYear() + 7);
  else date.setUTCFullYear(date.getUTCFullYear() + 2);
  return date.toISOString();
}

function planLimitExceeded(resource, limit, usage = null) {
  return {
    error: "plan_limit_exceeded",
    resource,
    limit,
    ...(usage === null ? {} : { usage }),
  };
}

async function getOwnedWorkspaceIds(userId, env) {
  const rows = await env.cybermeters_db
    .prepare("SELECT id FROM workspaces WHERE owner_user_id = ? AND deleted_at IS NULL")
    .bind(userId)
    .all();
  return (rows.results || []).map((row) => row.id).filter(Boolean);
}

async function getAccountUsage(userId, env) {
  const workspaceIds = await getOwnedWorkspaceIds(userId, env);
  let domains = 0;
  let users = 0;

  if (workspaceIds.length > 0) {
    const placeholders = workspaceIds.map(() => "?").join(",");
    const [domainRow, userRow] = await Promise.all([
      env.cybermeters_db
        .prepare(
          `SELECT COUNT(DISTINCT domain_id) AS cnt
           FROM workspace_domains
           WHERE workspace_id IN (${placeholders})`
        )
        .bind(...workspaceIds)
        .first(),
      env.cybermeters_db
        .prepare(
          `SELECT COUNT(DISTINCT user_id) AS cnt
           FROM workspace_members
           WHERE workspace_id IN (${placeholders})`
        )
        .bind(...workspaceIds)
        .first(),
    ]);
    domains = domainRow?.cnt ?? 0;
    users = userRow?.cnt ?? 0;
  }

  return {
    workspaces: workspaceIds.length,
    domains,
    users,
  };
}

async function getEntitlementUsage(user, env, workspaceId = null) {
  const [accountUsage, tokRow] = await Promise.all([
    getAccountUsage(user.id, env),
    env.cybermeters_db
      .prepare("SELECT COUNT(*) AS cnt FROM api_tokens WHERE user_id = ? AND status = 'active'")
      .bind(user.id)
      .first(),
  ]);

  const usage = {
    ...accountUsage,
    api_tokens: tokRow?.cnt ?? 0,
    domains_in_workspace: null,
    scheduled_reports_in_workspace: null,
    scans_this_month: null,
    reports_this_month: null,
    scheduled_scans_in_workspace: null,
  };

  if (workspaceId) {
    const [domRow, srRow, schedScanRow, rptRow] = await Promise.all([
      env.cybermeters_db
        .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
        .bind(workspaceId)
        .first(),
      env.cybermeters_db
        .prepare("SELECT COUNT(*) AS cnt FROM scheduled_reports WHERE workspace_id = ? AND enabled = 1")
        .bind(workspaceId)
        .first(),
      env.cybermeters_db
        .prepare("SELECT COUNT(*) AS cnt FROM scheduled_scans WHERE workspace_id = ? AND enabled = 1")
        .bind(workspaceId)
        .first(),
      env.cybermeters_db
        .prepare(
          `SELECT COUNT(*) AS cnt FROM workspace_reports
           WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL AND created_at >= ?`
        )
        .bind(workspaceId, getMonthStart())
        .first(),
    ]);
    usage.domains_in_workspace             = domRow?.cnt       ?? 0;
    usage.scheduled_reports_in_workspace   = srRow?.cnt        ?? 0;
    usage.scheduled_scans_in_workspace     = schedScanRow?.cnt ?? 0;
    usage.reports_this_month               = rptRow?.cnt       ?? 0;
  }

  // Scans-this-month is scoped to the billing owner, not a workspace
  const ownerUserId = workspaceId
    ? await getWorkspaceBillingUserId(workspaceId, user.id, env)
    : user.id;
  usage.scans_this_month = await countScansThisMonth(ownerUserId, env);

  return usage;
}

async function getPlanContext(user, env) {
  const plan = await getEffectivePlan(user.id, env);
  const limits = getPlanLimits(plan);
  const usage = await getAccountUsage(user.id, env);
  return { plan, limits, usage };
}

// ── Upgrade Recommendation Engine ────────────────────────────────────────────
// Evaluates account-level usage against plan limits and emits upgrade signals
// at three severity thresholds: warning (≥80%), danger (≥90%), critical (=100%).
// Returns an array sorted by descending percentage so the most urgent signal
// is first. Returns [] for unlimited (enterprise) resources.

function getUpgradeRecommendation(limits, usage) {
  const RESOURCES = [
    { key: "workspaces", label: "workspace" },
    { key: "domains",    label: "domain"    },
    { key: "users",      label: "user"      },
  ];

  const signals = [];

  for (const { key, label } of RESOURCES) {
    const limit = limits[key];
    const used  = usage[key];
    if (!limit || limit >= 999999 || used === null || used === undefined) continue;

    const pct = Math.round((used / limit) * 100);

    if (pct >= 100) {
      signals.push({
        resource:    key,
        level:       "critical",
        pct:         100,
        used,
        limit,
        message:     `You have reached your ${label} limit. Upgrade your plan to add more.`,
        upgrade_url: "/billing",
      });
    } else if (pct >= 90) {
      signals.push({
        resource:    key,
        level:       "danger",
        pct,
        used,
        limit,
        message:     `You are close to your ${label} limit (${pct}% used). Consider upgrading soon.`,
        upgrade_url: "/billing",
      });
    } else if (pct >= 80) {
      signals.push({
        resource:    key,
        level:       "warning",
        pct,
        used,
        limit,
        message:     `You are approaching your ${label} limit (${pct}% used).`,
        upgrade_url: "/billing",
      });
    }
  }

  // Sort highest percentage first
  signals.sort((a, b) => b.pct - a.pct);
  return signals;
}

async function getWorkspaceOwnerId(workspaceId, env) {
  const row = await env.cybermeters_db
    .prepare("SELECT owner_user_id FROM workspaces WHERE id = ?")
    .bind(workspaceId)
    .first();
  return row?.owner_user_id || null;
}

async function getWorkspaceBillingUserId(workspaceId, fallbackUserId, env) {
  return (await getWorkspaceOwnerId(workspaceId, env)) || fallbackUserId;
}

// ── Usage counting helpers (derived from source tables, no extra migration) ──

/** ISO timestamp for the first moment of the current calendar month (UTC). */
function getMonthStart() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-01T00:00:00.000Z`;
}

/**
 * Count scans created this calendar month across all workspaces owned by ownerUserId.
 * Uses workspace ownership to scope correctly across multi-workspace accounts.
 */
async function countScansThisMonth(ownerUserId, env) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(s.id) AS cnt
         FROM scans s
         JOIN workspaces w ON w.id = s.workspace_id
         WHERE w.owner_user_id = ?
           AND s.created_at >= ?`
      )
      .bind(ownerUserId, getMonthStart())
      .first();
    return row?.cnt ?? 0;
  } catch {
    return 0;
  }
}

/**
 * Count completed workspace_reports created this calendar month for a specific workspace.
 */
async function countReportsThisMonth(wsId, env) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(id) AS cnt
         FROM workspace_reports
         WHERE workspace_id = ?
           AND status = 'completed'
           AND deleted_at IS NULL
           AND created_at >= ?`
      )
      .bind(wsId, getMonthStart())
      .first();
    return row?.cnt ?? 0;
  } catch {
    return 0;
  }
}

/**
 * Count enabled scheduled_scans for a workspace (cumulative, not per-month).
 * Scheduled scans are persistent config objects, not consumed resources.
 */
async function countEnabledScheduledScans(wsId, env) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(id) AS cnt
         FROM scheduled_scans
         WHERE workspace_id = ?
           AND enabled = 1`
      )
      .bind(wsId)
      .first();
    return row?.cnt ?? 0;
  } catch {
    return 0;
  }
}

// ── Plan enforcement helpers ─────────────────────────────────────────────────

/**
 * Returns the next month reset ISO timestamp (first moment of next month, UTC).
 */
function getMonthResetAt() {
  const d = new Date();
  d.setUTCMonth(d.getUTCMonth() + 1, 1);
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString();
}

/**
 * Check scan monthly quota for the billing owner of workspaceId.
 * Returns null when quota is available, or { status, body } when blocked.
 * Fails open — quota check errors never block scans.
 */
async function checkScanLimit(user, workspaceId, env) {
  try {
    const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const plan   = await getEffectivePlan(ownerUserId, env);
    const limits = getPlanLimits(plan);
    const used   = await countScansThisMonth(ownerUserId, env);
    if (used >= limits.scans_per_month) {
      return {
        status: 403,
        body: {
          ...planLimitExceeded("scans_per_month", limits.scans_per_month, used),
          upgrade_message: `You have used ${used} of ${limits.scans_per_month} scans this month. Upgrade your plan for more scans.`,
          reset_at: getMonthResetAt(),
        },
      };
    }
    return null;
  } catch {
    return null; // fail-open: counting errors must never block legitimate scans
  }
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

/**
 * Check report generation monthly quota for workspaceId.
 * Returns null when quota is available, or { status, body } when blocked.
 * Fails open.
 */
async function checkReportLimit(user, workspaceId, env) {
  try {
    const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const plan   = await getEffectivePlan(ownerUserId, env);
    const limits = getPlanLimits(plan);
    const used   = await countReportsThisMonth(workspaceId, env);
    if (used >= limits.reports_per_month) {
      return {
        status: 403,
        body: {
          ...planLimitExceeded("reports_per_month", limits.reports_per_month, used),
          upgrade_message: `You have generated ${used} of ${limits.reports_per_month} reports this month. Upgrade your plan for more reports.`,
          reset_at: getMonthResetAt(),
        },
      };
    }
    return null;
  } catch {
    return null; // fail-open
  }
}

/**
 * Check whether workspaceId can add another enabled scheduled scan.
 * Returns null when quota is available, or { status, body } when blocked.
 * Fails open.
 */
async function checkScheduledScanLimit(user, workspaceId, env) {
  try {
    const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const plan   = await getEffectivePlan(ownerUserId, env);
    const limits = getPlanLimits(plan);
    const used   = await countEnabledScheduledScans(workspaceId, env);
    if (used >= limits.scheduled_scans) {
      return {
        status: 403,
        body: {
          ...planLimitExceeded("scheduled_scans", limits.scheduled_scans, used),
          upgrade_message: `You have ${used} of ${limits.scheduled_scans} scheduled scans configured. Upgrade your plan to add more.`,
        },
      };
    }
    return null;
  } catch {
    return null; // fail-open
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

    // ── GET /api/workspaces/:id/scorecard/pdf ─────────────────────────────────
    // Returns a downloadable PDF executive security report.
    // Uses the same data as /scorecard/pdf-data via collectPdfData().
    const pdfMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scorecard\/pdf$/);
    if (pdfMatch && request.method === 'GET') {
      const wsId = pdfMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'business_risk_score')) {
          return json({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter', upgrade_url: '/billing' }, 403);
        }
      }
      try {
        const pdfData = await collectPdfData(wsId, env);
        if (!pdfData) return json({ error: 'Workspace not found' }, 404);
        const bytes    = buildExecutivePdf(pdfData);
        const wsSlug   = String(pdfData.workspace?.name ?? 'report')
          .toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        const dateSlug = pdfData.generated_at.slice(0, 10);
        const filename = `cybermeters-executive-report-${wsSlug}-${dateSlug}.pdf`;
        return new Response(bytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type':        'application/pdf',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length':      String(bytes.length),
          },
        });
      } catch (err) {
        return json({
          error:     'PDF generation failed',
          message:   String(err?.message ?? err),
          endpoint:  url.pathname,
          timestamp: new Date().toISOString(),
        }, 500);
      }
    }

    // ── GET /api/workspaces/:id/scorecard/pdf-data ──────────────────────────
    // Board-level executive security report — pure JSON for frontend / export.
    const pdfDataMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scorecard\/pdf-data$/);
    if (pdfDataMatch && request.method === 'GET') {
      const wsId = pdfDataMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'business_risk_score')) {
          return json({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter', upgrade_url: '/billing' }, 403);
        }
      }
      try {
        const pdfData = await collectPdfData(wsId, env);
        if (!pdfData) return json({ error: 'Workspace not found' }, 404);
        return json(pdfData);
      } catch (err) {
        return serverError("scorecard/pdf-data", err, "PDF data could not be generated.");
      }
    }

    // ── Cyber Essentials Readiness — self-attestation answers ────────────────
    // GET returns the question set + stored answers; PUT upserts answers. The
    // questionnaire covers the INTERNAL controls we cannot observe externally;
    // the readiness endpoint merges these with measured signal (measured wins).
    const ceAnswersMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cyber-essentials\/answers$/
    );
    if (ceAnswersMatch && (request.method === 'GET' || request.method === 'PUT')) {
      const wsId = ceAnswersMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, request.method === 'PUT' ? "workspace:manage" : "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'cyber_essentials')) {
          return json({ error: 'plan_feature_required', feature: 'cyber_essentials', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      const validKeys = new Map(CE_QUESTIONS.map((c) => [c.control_key, new Set(c.questions.map((q) => q.key))]));
      const validAnswers = new Set(['yes', 'partial', 'no', 'unknown']);

      if (request.method === 'PUT') {
        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
        const items = Array.isArray(body?.answers) ? body.answers : [];
        for (const it of items) {
          const ck = String(it?.control_key ?? '');
          const qk = String(it?.question_key ?? '');
          const ans = String(it?.answer ?? '');
          // Ignore unknown control/question/answer keys — never trust client input.
          if (!validKeys.has(ck) || !validKeys.get(ck).has(qk) || !validAnswers.has(ans)) continue;
          try {
            await env.cybermeters_db
              .prepare(`INSERT INTO cyber_essentials_answers (id, workspace_id, control_key, question_key, answer, note, answered_by, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                        ON CONFLICT(workspace_id, control_key, question_key)
                        DO UPDATE SET answer = excluded.answer, note = excluded.note, answered_by = excluded.answered_by, updated_at = datetime('now')`)
              .bind(createId(), wsId, ck, qk, ans, it?.note ? String(it.note).slice(0, 500) : null, user.id)
              .run();
          } catch { /* skip a bad row, keep going — never surface raw DB errors */ }
        }
      }

      let answerRows = { results: [] };
      try {
        answerRows = await env.cybermeters_db
          .prepare(`SELECT control_key, question_key, answer, note, updated_at FROM cyber_essentials_answers WHERE workspace_id = ?`)
          .bind(wsId).all();
      } catch { /* empty answer set */ }
      const answers = {};
      for (const r of (answerRows.results || [])) {
        if (!answers[r.control_key]) answers[r.control_key] = {};
        answers[r.control_key][r.question_key] = r.answer;
      }
      return json({ question_set_version: CE_QUESTION_SET_VERSION, questions: CE_QUESTIONS, answers });
    }

    // ── GET /api/workspaces/:id/cyber-essentials-readiness ───────────────────
    // Cyber Essentials readiness guidance only. Dynamically calculated from
    // existing CyberMeters scan/report/workspace intelligence data.
    const cyberEssentialsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cyber-essentials-readiness$/
    );
    if (cyberEssentialsMatch && request.method === 'GET') {
      const wsId = cyberEssentialsMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'cyber_essentials')) {
          return json({ error: 'plan_feature_required', feature: 'cyber_essentials', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      const readiness = await buildCyberEssentialsReadiness(wsId, env);
      if (!readiness) return json({ error: 'Database error' }, 500);
      // Additive: merge self-attestation answers with the measured categories
      // (measured wins on contradiction). Never break base readiness if this fails.
      try {
        const arows = await env.cybermeters_db
          .prepare(`SELECT control_key, question_key, answer FROM cyber_essentials_answers WHERE workspace_id = ?`)
          .bind(wsId).all();
        const answers = {};
        for (const r of (arows.results || [])) {
          if (!answers[r.control_key]) answers[r.control_key] = {};
          answers[r.control_key][r.question_key] = r.answer;
        }
        const measured = (readiness.categories || []).map((c) => ({
          control_key: c.key, measured_score: c.score, measured_gaps: c.gaps || [],
        }));
        readiness.self_assessment = {
          question_set_version: CE_QUESTION_SET_VERSION,
          controls: mergeReadiness(measured, answers),
        };
      } catch { /* self-assessment is additive; base readiness stands */ }
      return json(readiness);
    }

    // ── Executive Security Scorecard Routes ──────────────────────────────────
    // GET /api/workspaces/:id/scorecard         — business scorecard
    // GET /api/workspaces/:id/scorecard/report  — PDF-ready structured JSON
    const scorecardMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/scorecard(\/report)?$/
    );
    if (scorecardMatch && request.method === 'GET') {
      const wsId     = scorecardMatch[1];
      const isReport = !!scorecardMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id, name FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      const scorecard = await buildScorecardData(wsId, env);
      if (!scorecard) return json({ error: 'Database error' }, 500);

      // ── GET /scorecard ────────────────────────────────────────────────────
      if (!isReport) return json(scorecard);

      // ── GET /scorecard/report — structured for PDF rendering ─────────────
      const generatedAt = new Date().toISOString();

      // Derive per-section status: 'ok' | 'warning' | 'critical' | 'unknown'
      const sections = [
        {
          title:   'Asset Inventory',
          status:  scorecard.active_assets === 0 ? 'unknown'
                 : scorecard.new_assets_30d > 0  ? 'warning' : 'ok',
          summary: scorecard.active_assets > 0
            ? `${scorecard.active_assets} active assets monitored.` +
              (scorecard.new_assets_30d > 0
                ? ` ${scorecard.new_assets_30d} new in the last 30 days.`
                : ' No new assets in the last 30 days.')
            : 'No assets have been inventoried yet. Run a scan to begin discovery.',
          data: {
            active_assets:    scorecard.active_assets,
            new_assets_30d:   scorecard.new_assets_30d,
            asset_events_30d: scorecard.asset_events_30d,
          },
        },
        {
          title:   'Vendor Risk',
          status:  scorecard.vendor_risk.high   > 0 ? 'critical'
                 : scorecard.vendor_risk.medium > 0 ? 'warning' : 'ok',
          summary: scorecard.vendors_detected > 0
            ? `${scorecard.vendors_detected} vendor${scorecard.vendors_detected !== 1 ? 's' : ''} detected.` +
              (scorecard.vendor_risk.high > 0
                ? ` ${scorecard.vendor_risk.high} high-risk.`
                : ' No high-risk vendors.')
            : 'No third-party vendors detected in this scan.',
          data: {
            total:  scorecard.vendors_detected,
            ...scorecard.vendor_risk,
          },
        },
        {
          title:   'Third-Party Assets',
          status:  scorecard.third_party_assets > 0 ? 'warning' : 'ok',
          summary: scorecard.third_party_assets > 0
            ? `${scorecard.third_party_assets} third-party SaaS service${scorecard.third_party_assets !== 1 ? 's' : ''} in use (email, CRM, support, marketing).`
            : 'No third-party SaaS dependencies detected.',
          data: { count: scorecard.third_party_assets },
        },
        {
          title:   'SaaS Exposure',
          status:  scorecard.saas_exposures > 0 ? 'warning' : 'ok',
          summary: scorecard.saas_exposures > 0
            ? `${scorecard.saas_exposures} exposed SaaS portal${scorecard.saas_exposures !== 1 ? 's' : ''} or login surface${scorecard.saas_exposures !== 1 ? 's' : ''} detected.`
            : 'No externally exposed SaaS portals detected.',
          data: { count: scorecard.saas_exposures },
        },
        {
          title:   'Admin Surfaces',
          status:  scorecard.admin_surfaces > 0 ? 'critical' : 'ok',
          summary: scorecard.admin_surfaces > 0
            ? `${scorecard.admin_surfaces} admin or management interface${scorecard.admin_surfaces !== 1 ? 's' : ''} publicly exposed.`
            : 'No exposed admin surfaces detected.',
          data: { count: scorecard.admin_surfaces },
        },
        {
          title:   'Brand Monitoring',
          status:  scorecard.brand_risks.high   > 0 ? 'critical'
                 : scorecard.brand_risks.active > 0 ? 'warning' : 'ok',
          summary: scorecard.brand_risks.active > 0
            ? `${scorecard.brand_risks.active} active typosquat domain${scorecard.brand_risks.active !== 1 ? 's' : ''} detected.` +
              (scorecard.brand_risks.high > 0
                ? ` ${scorecard.brand_risks.high} high-risk.`
                : '')
            : `${scorecard.brand_risks.total} candidate domain${scorecard.brand_risks.total !== 1 ? 's' : ''} generated — none currently resolving.`,
          data: scorecard.brand_risks,
        },
        {
          title:   'Certificate Intelligence',
          status:  scorecard.certificate_risks.risk_level === 'critical' ? 'critical'
                 : scorecard.certificate_risks.risk_level === 'high'     ? 'warning'
                 : scorecard.certificate_risks.signals > 0               ? 'warning'
                 : scorecard.certificate_risks.risk_level === null        ? 'unknown' : 'ok',
          summary: scorecard.certificate_risks.risk_level
            ? `Certificate risk is ${scorecard.certificate_risks.risk_level}.` +
              (scorecard.certificate_risks.signals > 0
                ? ` ${scorecard.certificate_risks.signals} suspicious signal${scorecard.certificate_risks.signals !== 1 ? 's' : ''} detected.`
                : ' No suspicious signals.')
            : 'Certificate data not yet available from the latest scan.',
          data: scorecard.certificate_risks,
        },
        {
          title:   'Security Findings',
          status:  scorecard.critical_findings > 0 ? 'critical'
                 : scorecard.high_findings     > 0 ? 'warning' : 'ok',
          summary: (scorecard.critical_findings + scorecard.high_findings) === 0
            ? `No critical or high findings.` +
              (scorecard.medium_findings + scorecard.low_findings > 0
                ? ` ${scorecard.medium_findings + scorecard.low_findings} lower-severity finding${(scorecard.medium_findings + scorecard.low_findings) !== 1 ? 's' : ''} noted.`
                : ' Clean scan.')
            : `${scorecard.critical_findings} critical, ${scorecard.high_findings} high, ${scorecard.medium_findings} medium, ${scorecard.low_findings} low findings.`,
          data: {
            critical: scorecard.critical_findings,
            high:     scorecard.high_findings,
            medium:   scorecard.medium_findings,
            low:      scorecard.low_findings,
          },
        },
      ];

      // security_posture_chart — flat array for radar/bar chart rendering
      const sp = scorecard.security_posture;
      const security_posture_chart = sp
        ? [
            { category: 'Email Security',    score: sp.email_security?.score    ?? null, status: sp.email_security?.status    ?? 'unknown' },
            { category: 'SSL & Certificates',score: sp.ssl_certificates?.score  ?? null, status: sp.ssl_certificates?.status  ?? 'unknown' },
            { category: 'Attack Surface',    score: sp.attack_surface?.score    ?? null, status: sp.attack_surface?.status    ?? 'unknown' },
            { category: 'Third-Party Risk',  score: sp.third_party_risk?.score  ?? null, status: sp.third_party_risk?.status  ?? 'unknown' },
            { category: 'Admin Exposure',    score: sp.admin_exposure?.score    ?? null, status: sp.admin_exposure?.status    ?? 'unknown' },
          ]
        : [];

      return json({
        generated_at:           generatedAt,
        workspace:              { id: wsId, name: scorecard.workspace_name },
        scorecard,
        executive_summary:      scorecard.executive_summary,
        recommendations:        scorecard.top_recommendations,
        sections,
        security_posture:       scorecard.security_posture ?? null,
        security_posture_chart,
      });
    }

    // ── Identity Asset Discovery Routes ─────────────────────────────────────
    // GET /api/workspaces/:id/identity-assets         — full inventory
    // GET /api/workspaces/:id/identity-assets/summary — aggregated counts

    const identityListMatch    = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-assets$/);
    const identitySummaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-assets\/summary$/);

    if ((identityListMatch || identitySummaryMatch) && request.method === "GET") {
      const wsId = (identityListMatch ?? identitySummaryMatch)[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id, name FROM workspaces WHERE id = ?`).bind(wsId).first();
      if (!ws) return json({ error: "Workspace not found" }, 404);

      if (identitySummaryMatch) {
        try {
          const [totalRow, typeRows, providerRows, highRiskRow] = await env.cybermeters_db.batch([
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),
            env.cybermeters_db
              .prepare(`SELECT identity_type, COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' GROUP BY identity_type`)
              .bind(wsId),
            env.cybermeters_db
              .prepare(`SELECT provider, COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND provider IS NOT NULL GROUP BY provider ORDER BY n DESC`)
              .bind(wsId),
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND risk_score >= 15`)
              .bind(wsId),
          ]);
          return json({
            workspace_id:       wsId,
            total:              totalRow.n ?? 0,
            high_risk_count:    highRiskRow.n ?? 0,
            by_type:            Object.fromEntries((typeRows.results ?? []).map(r => [r.identity_type, r.n])),
            providers_detected: (providerRows.results ?? []).map(r => ({ provider: r.provider, count: r.n })),
            generated_at:       new Date().toISOString(),
          });
        } catch (err) {
          return serverError("identity/summary", err, "Identity summary could not be loaded.");
        }
      }

      // Full list
      try {
        const filterType     = url.searchParams.get("identity_type");
        const filterProvider = url.searchParams.get("provider");
        const filterRisk     = url.searchParams.get("min_risk_score");

        let query = `SELECT * FROM identity_assets WHERE workspace_id = ? AND status = 'active'`;
        const params = [wsId];
        if (filterType)     { query += ` AND identity_type = ?`;  params.push(filterType); }
        if (filterProvider) { query += ` AND provider = ?`;       params.push(filterProvider); }
        if (filterRisk)     { query += ` AND risk_score >= ?`;    params.push(parseInt(filterRisk, 10) || 0); }
        query += ` ORDER BY risk_score DESC, first_seen DESC LIMIT 200`;

        const rows = await env.cybermeters_db.prepare(query).bind(...params).all();
        const assets = (rows.results ?? []).map(r => ({
          id:               r.id,
          hostname:         r.hostname,
          asset_type:       r.asset_type,
          identity_type:    r.identity_type,
          provider:         r.provider,
          internet_exposed: r.internet_exposed === 1,
          source:           r.source,
          risk_score:       r.risk_score,
          evidence:         r.evidence ? (() => { try { return JSON.parse(r.evidence); } catch { return []; } })() : [],
          first_seen:       r.first_seen,
          last_seen:        r.last_seen,
        }));

        return json({
          workspace_id:    wsId,
          workspace_name:  ws.name,
          total:           assets.length,
          high_risk_count: assets.filter(a => a.risk_score >= 15).length,
          assets,
          generated_at:    new Date().toISOString(),
        });
      } catch (err) {
        return serverError("identity/assets", err, "Identity assets could not be loaded.");
      }
    }

    // ── Vendor Relationship Routes ────────────────────────────────────────────
    // GET /api/workspaces/:id/vendor-relationships
    //   Returns vendors detected via CSP/JS analysis (source_module='vendor_relationship').
    //   Supports ?category=analytics|payments|crm|support|identity|collaboration|cloud|cdn|security
    //             ?confidence=high|medium|low
    //   Returns: { workspace_id, total, high_confidence, by_category, vendors: [...] }
    const vendorRelMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/vendor-relationships$/);
    if (vendorRelMatch && request.method === "GET") {
      const wsId = vendorRelMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'vendor_risk')) {
          return json({ error: 'plan_feature_required', feature: 'vendor_risk', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      const filterCat  = url.searchParams.get("category");
      const filterConf = url.searchParams.get("confidence");

      const whereClauses = ["workspace_id = ?", "source_module = 'vendor_relationship'", "status = 'active'"];
      const binds        = [wsId];
      if (filterCat)  { whereClauses.push("category = ?");    binds.push(filterCat); }
      if (filterConf) { whereClauses.push("confidence = ?");  binds.push(filterConf); }
      const whereSQL = whereClauses.join(" AND ");

      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name AS name, category, source, evidence, confidence,
                    risk_level, first_seen, last_seen
             FROM workspace_vendors
             WHERE ${whereSQL}
             ORDER BY
               CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               category, vendor_name`
          )
          .bind(...binds)
          .all();

        const vendors = (r.results || []).map(row => ({
          name:       row.name,
          category:   row.category,
          source:     row.source,
          confidence: row.confidence,
          risk_level: row.risk_level,
          first_seen: row.first_seen,
          last_seen:  row.last_seen,
          source_signals: (() => { try { return JSON.parse(row.evidence); } catch { return []; } })(),
        }));

        const byCategory = {};
        for (const v of vendors) {
          byCategory[v.category] = (byCategory[v.category] || 0) + 1;
        }
        const highConfidence = vendors.filter(v => v.confidence === "high").length;

        return json({
          workspace_id:    wsId,
          total:           vendors.length,
          high_confidence: highConfidence,
          by_category:     byCategory,
          vendors,
          generated_at:    new Date().toISOString(),
        });
      } catch (err) {
        return serverError("vendor-relationships", err);
      }
    }

    // GET /api/workspaces/:id/supply-chain
    //   Returns the latest supply chain intelligence for the workspace.
    //   Computed post-scan (Phase 8i) and read from workspace_supply_chain_scores.
    //   Falls back to on-demand computation if no persisted row exists.
    //   Returns: { supply_chain_score, operational_resilience_score, concentration_level,
    //              critical_vendor_count, tier1_count, tier2_count, tier3_count, spof_count,
    //              critical_vendors, dependency_graph, cascading_risks, concentration,
    //              compliance_readiness, asm_maturity, vendor_summary, brs_score, calculated_at }
    const supplyChainMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/supply-chain$/);
    if (supplyChainMatch && request.method === 'GET') {
      const wsId = supplyChainMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const access = await requireWorkspaceRole(user, wsId, 'workspace:read', env);
      if (!access) return json({ error: 'Forbidden' }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'vendor_risk')) {
          return json({ error: 'plan_feature_required', feature: 'vendor_risk', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      try {
        // Try reading from persisted score first
        const persisted = await env.cybermeters_db
          .prepare('SELECT payload_json FROM workspace_supply_chain_scores WHERE workspace_id = ?')
          .bind(wsId)
          .first();

        if (persisted?.payload_json) {
          try {
            return json(JSON.parse(persisted.payload_json));
          } catch { /* fall through to on-demand */ }
        }

        // On-demand computation (no scan has run yet or table not migrated)
        const payload = await computeSupplyChainIntelligence(wsId, env);
        if (!payload) return json({ error: 'No supply chain data available. Run a scan first.' }, 404);
        return json(payload);
      } catch (err) {
        console.error('[supply-chain] GET error:', err);
        return json({ error: 'Internal server error' }, 500);
      }
    }

    // ── Brand Protection Intelligence v1 ──────────────────────────────────────
    // Persistent workflow APIs. These are additive; the legacy Brand Monitoring
    // routes below retain their response contracts for the existing frontend.
    const brandProfileMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/brand\/profile$/);
    const brandSummaryV1Match = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/brand\/summary$/);
    const brandCandidatesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/brand\/candidates(?:\/([^/]+)(?:\/(classify))?)?$/
    );
    if (brandProfileMatch || brandSummaryV1Match || brandCandidatesMatch) {
      const wsId = (brandProfileMatch || brandSummaryV1Match || brandCandidatesMatch)[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const isProfileWrite = Boolean(brandProfileMatch && request.method === "POST");
      const isClassificationWrite = Boolean(brandCandidatesMatch?.[3] === "classify" && request.method === "POST");
      const permission = isProfileWrite ? "workspace:manage"
        : isClassificationWrite ? "workspace:manage" : "workspace:read";
      const access = await requireWorkspaceRole(user, wsId, permission, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const workspace = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ? LIMIT 1").bind(wsId).first();
        if (!workspace) return json({ error: "Workspace not found" }, 404);

        // GET /brand/profile — persisted profile or explicitly low-confidence
        // inference from real workspace domains. Inference is never persisted.
        if (brandProfileMatch && request.method === "GET") {
          return json({ profile: await loadWorkspaceBrandProfile(env, wsId) });
        }

        // POST /brand/profile — admin-managed protected brand scope.
        if (brandProfileMatch && request.method === "POST") {
          const body = await request.json().catch(() => null);
          const domainRows = await env.cybermeters_db
            .prepare(`SELECT d.domain FROM workspace_domains wd
                      JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id = ?`)
            .bind(wsId).all();
          const workspaceDomains = (domainRows.results || []).map((row) => row.domain);
          const validated = validateBrandProfileInput(body, workspaceDomains);
          if (!validated.ok) return json({ error: validated.error }, 400);
          const value = validated.value;
          const existing = await env.cybermeters_db
            .prepare("SELECT id FROM workspace_brand_profiles WHERE workspace_id = ? LIMIT 1")
            .bind(wsId).first();
          const profileId = existing?.id || createId("brandprof");
          await env.cybermeters_db
            .prepare(`INSERT INTO workspace_brand_profiles
                        (id, workspace_id, brand_name, primary_domain, keywords_json,
                         protected_domains_json, created_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                      ON CONFLICT(workspace_id) DO UPDATE SET
                        brand_name = excluded.brand_name,
                        primary_domain = excluded.primary_domain,
                        keywords_json = excluded.keywords_json,
                        protected_domains_json = excluded.protected_domains_json,
                        updated_at = datetime('now')`)
            .bind(profileId, wsId, value.brand_name, value.primary_domain,
              JSON.stringify(value.keywords), JSON.stringify(value.protected_domains)).run();
          await env.cybermeters_db
            .prepare("UPDATE workspace_brand_assets SET brand_profile_id = ? WHERE workspace_id = ?")
            .bind(profileId, wsId).run();
          const row = await env.cybermeters_db
            .prepare(`SELECT id, workspace_id, brand_name, primary_domain, keywords_json,
                             protected_domains_json, created_at, updated_at
                      FROM workspace_brand_profiles WHERE workspace_id = ? LIMIT 1`)
            .bind(wsId).first();
          await createAuditEvent(env, {
            workspace_id: wsId, user_id: user.id, event_type: "brand_profile_updated",
            entity_type: "brand_profile", entity_id: profileId,
            description: `Updated protected brand profile for ${value.brand_name}`,
            metadata: { brand_name: value.brand_name, primary_domain: value.primary_domain,
              keyword_count: value.keywords.length, protected_domain_count: value.protected_domains.length },
          });
          return json({ profile: brandProfileToApi(row) });
        }

        // GET /brand/summary — use the same normalized risk pipeline as the
        // candidate table so stale stored risk_level values cannot skew counts.
        if (brandSummaryV1Match && request.method === "GET") {
          const profile = await loadWorkspaceBrandProfile(env, wsId);
          const domainScope = buildBrandProfileDomainScope(profile);
          const rows = await env.cybermeters_db
            .prepare(`SELECT id, domain, candidate_domain, variant_type, similarity_score,
                             risk_level, risk_reasons, dns_resolves, https_available,
                             status, classification, first_seen, last_seen, last_checked_at,
                             mx_present, registrar_or_whois_summary, evidence_json,
                             created_at, updated_at
                      FROM workspace_brand_assets
                      WHERE workspace_id = ? AND ${domainScope.clause}`)
            .bind(wsId, ...domainScope.bindings).all();
          const candidates = (rows.results || []).map((row) => brandCandidateToApi(row, profile));
          return json(buildBrandProtectionSummary(candidates));
        }

        if (brandCandidatesMatch) {
          const candidateId = brandCandidatesMatch[2] || null;
          const action = brandCandidatesMatch[3] || null;
          if (candidateId && !/^[a-zA-Z0-9_-]{1,100}$/.test(candidateId)) {
            return json({ error: "Invalid candidate id" }, 400);
          }

          // GET /brand/candidates — bounded, allow-listed filters only.
          if (!candidateId && !action && request.method === "GET") {
            const params = parseBrandCandidateListParams(url.searchParams);
            const profile = await loadWorkspaceBrandProfile(env, wsId);
            const domainScope = buildBrandProfileDomainScope(profile);
            const where = ["workspace_id = ?"];
            const binds = [wsId];
            where.push(domainScope.clause);
            binds.push(...domainScope.bindings);
            if (params.risk) { where.push("risk_level = ?"); binds.push(params.risk); }
            if (params.status) { where.push("status = ?"); binds.push(params.status); }
            if (params.classification) {
              where.push("COALESCE(classification, 'unreviewed') = ?"); binds.push(params.classification);
            }
            const [rows, totalRow] = await Promise.all([
              env.cybermeters_db
                .prepare(`SELECT id, domain, candidate_domain, variant_type, similarity_score,
                                 risk_level, risk_reasons, dns_resolves, https_available,
                                 status, classification, first_seen, last_seen, last_checked_at,
                                 mx_present, registrar_or_whois_summary, evidence_json,
                                 created_at, updated_at
                          FROM workspace_brand_assets
                          WHERE ${where.join(" AND ")}
                          ORDER BY
                            -- Registered/live candidates first: a domain that
                            -- actually resolves (and can send mail) is the real
                            -- threat, ahead of theoretical permutations.
                            (COALESCE(mx_present, 0) + COALESCE(dns_resolves, 0)) DESC,
                            CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                              WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                            CASE COALESCE(classification, 'unreviewed')
                              WHEN 'confirmed_abuse' THEN 0 WHEN 'suspicious' THEN 1
                              WHEN 'unreviewed' THEN 2 ELSE 3 END,
                            candidate_domain
                          LIMIT ? OFFSET ?`)
                .bind(...binds, params.limit, params.offset).all(),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE ${where.join(" AND ")}`)
                .bind(...binds).first(),
            ]);
            const candidates = (rows.results || []).map((row) => brandCandidateToApi(row, profile));
            return json({ workspace_id: wsId, total: Number(totalRow?.n || 0),
              limit: params.limit, offset: params.offset, candidates });
          }

          const profile = await loadWorkspaceBrandProfile(env, wsId);
          const domainScope = buildBrandProfileDomainScope(profile);
          const row = await env.cybermeters_db
            .prepare(`SELECT id, workspace_id, domain, candidate_domain, variant_type,
                             similarity_score, risk_level, risk_reasons, dns_resolves,
                             https_available, status, classification, first_seen, last_seen,
                             last_checked_at, mx_present, registrar_or_whois_summary,
                             evidence_json, created_at, updated_at
                      FROM workspace_brand_assets
                      WHERE id = ? AND workspace_id = ? AND ${domainScope.clause} LIMIT 1`)
            .bind(candidateId, wsId, ...domainScope.bindings).first();
          if (!row) return json({ error: "Brand candidate not found" }, 404);

          // GET /brand/candidates/:id
          if (!action && request.method === "GET") {
            return json({ candidate: brandCandidateToApi(row, profile) });
          }

          // POST /brand/candidates/:id/classify
          if (action === "classify" && request.method === "POST") {
            const body = await request.json().catch(() => null);
            const classification = String(body?.classification || "").toLowerCase();
            const allowed = new Set(["owned", "ignored", "suspicious", "confirmed_abuse", "false_positive", "monitoring"]);
            if (!allowed.has(classification)) return json({ error: "Invalid classification" }, 400);
            const previous = BRAND_CLASSIFICATIONS.has(row.classification) ? row.classification : "unreviewed";
            const updatedAt = new Date().toISOString();
            const candidate = brandCandidateToApi({ ...row, classification, updated_at: updatedAt }, profile);
            await env.cybermeters_db
              .prepare(`UPDATE workspace_brand_assets
                        SET classification = ?, similarity_score = ?, risk_level = ?,
                            risk_reasons = ?, evidence_json = ?, updated_at = ?
                        WHERE id = ? AND workspace_id = ?`)
              .bind(classification, candidate.similarity_score, candidate.risk_level,
                JSON.stringify(candidate.risk_reasons), JSON.stringify(candidate.evidence),
                updatedAt, candidateId, wsId).run();
            const eventType = classification === "ignored" ? "brand_candidate_ignored"
              : classification === "owned" ? "brand_candidate_marked_owned"
                : classification === "suspicious" ? "brand_candidate_marked_suspicious"
                  : "brand_candidate_classified";
            await createAuditEvent(env, {
              workspace_id: wsId, user_id: user.id, event_type: eventType,
              entity_type: "brand_candidate", entity_id: candidateId,
              description: `Classified brand candidate ${row.candidate_domain} as ${classification}`,
              metadata: brandClassificationAuditMetadata(row, previous, classification, candidate.risk_level),
            });
            return json({ candidate });
          }
        }

        return json({ error: "Method not allowed" }, 405);
      } catch {
        return json({ error: "Brand protection request could not be completed" }, 500);
      }
    }

    // ── Brand Monitoring Routes ───────────────────────────────────────────────
    // GET  /api/workspaces/:id/brand-monitoring              — candidate list
    // GET  /api/workspaces/:id/brand-monitoring/summary      — risk summary
    // POST /api/workspaces/:id/brand-monitoring/refresh      — DNS validation pass
    //      (runs DoH A-record checks on top candidates; separate subrequest budget)
    const brandMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/brand-monitoring(\/summary|\/refresh)?$/
    );
    if (brandMatch && (request.method === 'GET' || request.method === 'POST')) {
      const wsId      = brandMatch[1];
      const subPath   = brandMatch[2];       // undefined | '/summary' | '/refresh'
      const isSummary = subPath === '/summary';
      const isRefresh = subPath === '/refresh';

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // refresh requires analyst+; plain read requires viewer
      const minPerm = isRefresh ? "domain:add" : "workspace:read";
      const access = await requireWorkspaceRole(user, wsId, minPerm, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      // ── POST /brand-monitoring/refresh ─────────────────────────────────────
      // Validates candidates via DNS (DoH A-record). Capped at 20 lookups
      // so this endpoint's own subrequest budget stays well within 50.
      if (isRefresh && request.method === 'POST') {
        const MAX_BRAND_DNS_CHECKS = 20;

        // Get primary (oldest-added) domain for this workspace
        let primaryDomain;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT d.domain FROM workspace_domains wd
               JOIN domains d ON d.id = wd.domain_id
               WHERE wd.workspace_id = ?
               ORDER BY d.created_at ASC LIMIT 1`
            )
            .bind(wsId)
            .first();
          primaryDomain = r?.domain;
        } catch {
          return json({ error: 'Database error' }, 500);
        }
        if (!primaryDomain) return json({ error: 'No domains in workspace' }, 404);

        const { brand, tld } = extractBrandParts(primaryDomain);
        const allCandidates   = generateTyposquatCandidates(brand, tld);
        const toValidate      = allCandidates.slice(0, MAX_BRAND_DNS_CHECKS);

        const now               = new Date().toISOString();
        const validationResults = [];

        for (const c of toValidate) {
          let dnsResolves = false;
          let ipAddress   = null;

          try {
            const dohResp = await dnsQuery(c.candidate_domain, 'A');
            if (dohResp.Answer?.length > 0) {
              dnsResolves = true;
              ipAddress   = dohResp.Answer[0]?.data || null;
            }
          } catch { /* treat as not resolving */ }

          const status = dnsResolves ? 'active' : 'inactive';
          const similarity = brandSimilarityScore(c.candidate_domain, brand);
          const candidateSld = c.candidate_domain.split('.')[0];
          const risk = scoreBrandCandidateRisk({
            variant_type: c.variant_type,
            similarity_score: similarity,
            dns_active: dnsResolves,
            contains_brand_keyword: candidateSld.includes(brand),
            suspicious_tld: BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop()),
            looks_like_login: HIGH_RISK_BRAND_KEYWORDS.some((keyword) => candidateSld.includes(keyword)),
            classification: "unreviewed",
          });
          const evidence = [
            { signal: "similar_to_brand", value: similarity },
            { signal: "variant_type", value: normalizeBrandVariantType(c.variant_type) },
            { signal: "dns_active", value: dnsResolves },
          ];
          if (candidateSld.includes(brand)) evidence.push({ signal: "contains_brand_keyword", value: true });
          if (BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop())) evidence.push({ signal: "suspicious_tld", value: true });
          if (HIGH_RISK_BRAND_KEYWORDS.some((keyword) => candidateSld.includes(keyword))) evidence.push({ signal: "looks_like_login", value: true });
          // Sprint 9D: confidence and validation_quality based on DNS probe outcome
          const brandConf = dnsResolves ? 80 : 40;
          const brandVQ   = dnsResolves ? "good" : "weak";
          validationResults.push({
            ...c,
            similarity_score:   similarity,
            risk_level:         risk.risk_level,
            risk_reasons:       risk.reasons,
            dns_resolves:       dnsResolves,
            ip_address:         ipAddress,
            status,
            confidence:         brandConf,
            validation_quality: brandVQ,
          });

          // Upsert validated result into D1
          try {
            await env.cybermeters_db
              .prepare(
                `INSERT INTO workspace_brand_assets
                   (id, workspace_id, domain, candidate_domain, variant_type,
                    similarity_score, risk_level, risk_reasons, evidence_json, dns_resolves, https_available,
                    ip_address, status, first_seen, last_seen, last_checked_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (workspace_id, domain, candidate_domain) DO UPDATE SET
                   similarity_score = excluded.similarity_score,
                   risk_level   = CASE WHEN workspace_brand_assets.classification IN ('owned','ignored','false_positive')
                                       THEN 'info' ELSE excluded.risk_level END,
                   risk_reasons = excluded.risk_reasons,
                   evidence_json = excluded.evidence_json,
                   dns_resolves = excluded.dns_resolves,
                   ip_address   = excluded.ip_address,
                   status       = excluded.status,
                   last_seen    = excluded.last_seen,
                   last_checked_at = excluded.last_checked_at,
                   updated_at   = excluded.updated_at`
              )
              .bind(
                createId('bra'),
                wsId,
                primaryDomain,
                c.candidate_domain,
                c.variant_type,
                similarity,
                risk.risk_level,
                JSON.stringify(risk.reasons),
                JSON.stringify(evidence),
                dnsResolves ? 1 : 0,
                ipAddress,
                status,
                now,  // first_seen
                now,  // last_seen
                now,  // last_checked_at
                now,  // created_at
                now   // updated_at
              )
              .run();
          } catch { /* non-fatal */ }

          // Fire asset events for resolving (active) typosquat domains
          if (dnsResolves) {
            try {
              const domRows = await env.cybermeters_db
                .prepare('SELECT domain_id FROM workspace_domains WHERE workspace_id = ? LIMIT 1')
                .bind(wsId)
                .first();
              const evDomainId = domRows?.domain_id || null;

              const evType = ['high', 'critical'].includes(risk.risk_level)
                ? 'high_risk_typosquat_detected'
                : 'brand_domain_detected';

              await env.cybermeters_db
                .prepare(
                  `INSERT OR IGNORE INTO asset_events
                     (id, workspace_id, domain_id, scan_id, event_type,
                      hostname, severity, description, created_at)
                   VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)`
                )
                .bind(
                  createId('asev'),
                  wsId,
                  evDomainId,
                  evType,
                  c.candidate_domain,
                  ['high', 'critical'].includes(risk.risk_level) ? risk.risk_level : 'medium',
                  `Typosquat domain ${c.candidate_domain} resolves (${c.variant_type}).` +
                    (risk.reasons.length > 0 ? ' ' + risk.reasons.join('; ') + '.' : ''),
                  now
                )
                .run();
            } catch { /* non-fatal */ }
          }
        }

        try {
          await env.cybermeters_db
            .prepare(`UPDATE workspace_brand_assets
                      SET brand_profile_id = (SELECT id FROM workspace_brand_profiles WHERE workspace_id = ?)
                      WHERE workspace_id = ? AND brand_profile_id IS NULL`)
            .bind(wsId, wsId).run();
        } catch { /* profile is optional */ }

        const activeResults  = validationResults.filter(v => v.dns_resolves);
        const highRiskActive = activeResults.filter(v => ['high', 'critical'].includes(v.risk_level)).length;

        return json({
          workspace_id:       wsId,
          brand,
          primary_domain:     primaryDomain,
          candidates_checked: toValidate.length,
          active_domains:     activeResults.length,
          high_risk_active:   highRiskActive,
          validated_at:       now,
          results:            activeResults,
        });
      }

      // ── GET /brand-monitoring/summary ───────────────────────────────────────
      if (isSummary && request.method === 'GET') {
        try {
          const [totalRow, byRiskRows, byStatusRows, highActiveRows] = await Promise.all([
            env.cybermeters_db
              .prepare('SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE workspace_id = ?')
              .bind(wsId).first(),

            env.cybermeters_db
              .prepare(
                `SELECT risk_level, COUNT(*) AS n
                 FROM workspace_brand_assets WHERE workspace_id = ?
                 GROUP BY risk_level`
              )
              .bind(wsId).all(),

            env.cybermeters_db
              .prepare(
                `SELECT status, COUNT(*) AS n
                 FROM workspace_brand_assets WHERE workspace_id = ?
                 GROUP BY status`
              )
              .bind(wsId).all(),

            env.cybermeters_db
              .prepare(
                `SELECT candidate_domain, variant_type, risk_level, risk_reasons,
                        ip_address, status, first_seen, last_seen
                 FROM workspace_brand_assets
                 WHERE workspace_id = ? AND risk_level IN ('critical', 'high') AND status = 'active'
                 ORDER BY last_seen DESC LIMIT 10`
              )
              .bind(wsId).all(),
          ]);

          const byRisk   = Object.fromEntries((byRiskRows.results   || []).map(r => [r.risk_level, r.n]));
          const byStatus = Object.fromEntries((byStatusRows.results || []).map(r => [r.status, r.n]));

          return json({
            workspace_id:     wsId,
            total_candidates: totalRow?.n ?? 0,
            by_risk:          { critical: byRisk.critical ?? 0, high: byRisk.high ?? 0, medium: byRisk.medium ?? 0, low: byRisk.low ?? 0 },
            by_status:        { active: byStatus.active ?? 0, inactive: byStatus.inactive ?? 0, unverified: byStatus.unverified ?? 0 },
            high_risk_active: (highActiveRows.results || []).map(r => ({
              ...r,
              risk_reasons: (() => { try { return JSON.parse(r.risk_reasons); } catch { return []; } })(),
            })),
          });
        } catch {
          return json({ error: 'Database error' }, 500);
        }
      }

      // ── GET /brand-monitoring ────────────────────────────────────────────────
      if (!isSummary && !isRefresh && request.method === 'GET') {
        const filterStatus = url.searchParams.get('status');       // active|inactive|unverified
        const filterRisk   = url.searchParams.get('risk_level');   // high|medium|low
        const filterType   = url.searchParams.get('variant_type'); // substitution|omission|…

        const whereClauses = ['workspace_id = ?'];
        const binds        = [wsId];

        if (filterStatus) { whereClauses.push('status = ?');       binds.push(filterStatus); }
        if (filterRisk)   { whereClauses.push('risk_level = ?');   binds.push(filterRisk); }
        if (filterType)   { whereClauses.push('variant_type = ?'); binds.push(filterType); }

        const whereSQL = whereClauses.join(' AND ');

        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT candidate_domain, domain, variant_type, risk_level, risk_reasons,
                      dns_resolves, https_available, ip_address, status, first_seen, last_seen
               FROM workspace_brand_assets
               WHERE ${whereSQL}
               ORDER BY
                 CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 CASE status     WHEN 'active'   THEN 0 WHEN 'unverified' THEN 1 ELSE 2 END,
                 candidate_domain`
            )
            .bind(...binds)
            .all();

          const assets = (r.results || []).map(legacyBrandAssetToApi);

          return json({ workspace_id: wsId, count: assets.length, candidates: assets });
        } catch {
          return json({ error: 'Database error' }, 500);
        }
      }
    }

    // ── GET /api/workspaces/:id/business-risk ────────────────────────────────
    // Returns current BRS + trend data from historical_scores.
    const businessRiskMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/business-risk$/
    );
    if (businessRiskMatch && request.method === 'GET') {
      const wsId = businessRiskMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'business_risk_score')) {
          return json({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter', upgrade_url: '/billing' }, 403);
        }
      }

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id, name FROM workspaces WHERE id = ?')
          .bind(wsId).first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      try {
        const [latestScanRow, historicalRows, assetRow] = await Promise.all([
          env.cybermeters_db
            .prepare(
              `SELECT s.id AS scan_id, s.score, s.rating, s.created_at
               FROM scans s
               WHERE s.workspace_id = ? AND s.status = 'completed'
               ORDER BY s.created_at DESC LIMIT 1`
            ).bind(wsId).first(),
          env.cybermeters_db
            .prepare(
              `SELECT brs_score, score, rating, created_at
               FROM historical_scores
               WHERE workspace_id = ? AND brs_score IS NOT NULL
               ORDER BY created_at DESC LIMIT 30`
            ).bind(wsId).all(),
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n
               FROM workspace_assets
               WHERE workspace_id = ? AND status = 'active'`
            ).bind(wsId).first(),
        ]);

        let vendorRows = [];
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT wv.id, wv.workspace_id, wv.vendor_name, wv.category,
                      wv.source, wv.evidence, wv.confidence, wv.risk_level,
                      wv.status, wv.first_seen, wv.last_seen,
                      vrs.score AS persisted_score,
                      vrs.category_multiplier,
                      vrs.concentration_penalty
               FROM workspace_vendors wv
               LEFT JOIN vendor_risk_scores vrs
                 ON vrs.vendor_id = wv.id
                AND vrs.workspace_id = wv.workspace_id
               WHERE wv.workspace_id = ? AND wv.status = 'active'
                 AND wv.source_module = 'vendor_risk'`
            )
            .bind(wsId)
            .all();
          vendorRows = r.results || [];
        } catch {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, vendor_name, category, source, evidence,
                      confidence, risk_level, status, first_seen, last_seen
               FROM workspace_vendors
               WHERE workspace_id = ? AND status = 'active'
                 AND source_module = 'vendor_risk'`
            )
            .bind(wsId)
            .all();
          vendorRows = r.results || [];
        }

        const vendorAggregate = computeWorkspaceVendorRisk(vendorRows);
        const topVendors = vendorAggregate.top_vendors.map((v) => ({
          id: v.id,
          name: v.vendor_name,
          vendor_name: v.vendor_name,
          category: v.normalized_category,
          score: v.persisted_score ?? v.score,
          risk_level: v.risk_level,
        }));

        let findingIds = new Set();
        let criticalFindings = 0;
        let highFindings = 0;
        if (latestScanRow?.scan_id) {
          try {
            const obj = await env.cybermeters_reports.get(`reports/${latestScanRow.scan_id}.json`);
            if (obj) {
              const report = await obj.json();
              const findings = Array.isArray(report.findings) ? report.findings : [];
              findingIds = expandFindingIds(findings.filter(isActionableFinding));
              criticalFindings = findings.filter((f) => f.severity === "critical").length;
              highFindings = findings.filter((f) => f.severity === "high").length;
            }
          } catch { /* tolerate missing report */ }
          if (criticalFindings === 0 && highFindings === 0) {
            try {
              const severityRows = await env.cybermeters_db
                .prepare(`SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity`)
                .bind(latestScanRow.scan_id)
                .all();
              const severityMap = Object.fromEntries((severityRows.results || []).map((r) => [r.severity, r.n]));
              criticalFindings = severityMap.critical || 0;
              highFindings = severityMap.high || 0;
            } catch { /* non-fatal */ }
          }
        }

        const workspaceModel = {
          workspace_id: wsId,
          vendor_risk: {
            workspace_vendor_risk_score: vendorAggregate.workspace_vendor_risk_score,
            top_vendors: topVendors,
            concentration_risk: vendorAggregate.concentration_risk,
          },
          asm_security: {
            critical_findings: criticalFindings,
            high_findings: highFindings,
            missing_https: findingIds.has("ssl_no_certificate") || findingIds.has("no_https_redirect"),
            weak_email_security:
              findingIds.has("email_missing_spf") ||
              findingIds.has("email_missing_dmarc") ||
              findingIds.has("email_dmarc_policy_none"),
            header_misconfig:
              findingIds.has("header_missing_strict_transport_security") ||
              findingIds.has("header_weak_hsts") ||
              findingIds.has("header_missing_content_security_policy") ||
              findingIds.has("csp_weak_policy"),
          },
          asset_exposure: {
            asset_count: assetRow?.n || 0,
          },
        };

        const brs = computeBusinessRiskScore(workspaceModel);
        const narrative = brs.summary.primary_risks.length > 0
          ? `Business risk is ${brs.risk_band}. Primary concerns: ${brs.summary.primary_risks.slice(0, 2).join("; ")}.`
          : `Business risk is ${brs.risk_band}. No major business-risk drivers were detected from current ASM and vendor data.`;
        const grade =
          brs.business_risk_score >= 76 ? "A" :
          brs.business_risk_score >= 51 ? "B" :
          brs.business_risk_score >= 31 ? "C" : "F";

        try {
          await env.cybermeters_db
            .prepare(
              `INSERT OR REPLACE INTO workspace_brs_scores
                 (workspace_id, score, risk_band, calculated_at)
               VALUES (?, ?, ?, ?)`
            )
            .bind(wsId, brs.business_risk_score, brs.risk_band, brs.calculated_at)
            .run();
        } catch { /* migration may not be applied yet */ }

        try {
          await env.cybermeters_db
            .prepare(
              `INSERT INTO workspace_brs_score_history
                 (id, workspace_id, score, risk_band, calculated_at)
               VALUES (?, ?, ?, ?, ?)`
            )
            .bind(createId("brshist"), wsId, brs.business_risk_score, brs.risk_band, brs.calculated_at)
            .run();
        } catch { /* history migration may not be applied yet */ }

        const trend = (historicalRows.results ?? []).reverse().map(r => ({
          date:      r.created_at,
          brs_score: r.brs_score,
          asm_score: r.score,
        }));

        return json({
          ...brs,
          workspace_name: ws.name,
          // Backward-compatible aliases used by existing UI.
          score: brs.business_risk_score,
          brs: brs.business_risk_score,
          band: brs.risk_band,
          grade,
          grade_label: brs.risk_band,
          narrative,
          top_concerns: brs.summary.primary_risks.map((risk) => ({
            title: risk,
            impact: risk,
            recommendation: brs.recommendations[0] || "Review this risk with the responsible business owner.",
            severity: brs.risk_band === "critical" ? "critical" : brs.risk_band === "high" ? "high" : "medium",
          })),
          latest_scan: latestScanRow ? {
            scan_id:    latestScanRow.scan_id,
            asm_score:  latestScanRow.score,
            asm_rating: latestScanRow.rating,
            scanned_at: latestScanRow.created_at,
          } : null,
          workspace_context: {
            vendor_total: vendorAggregate.scored_vendors.length,
            asset_count: workspaceModel.asset_exposure.asset_count,
            critical_findings: criticalFindings,
            high_findings: highFindings,
          },
          trend,
        });
      } catch (err) {
        return serverError("business-risk", err);
      }
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

    // ── GET /api/workspaces/:id/invitations ─────────────────────────────────
    const invitationsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/invitations$/);
    if (invitationsMatch && request.method === "GET") {
      const workspaceId = invitationsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage invitations" }, 403);
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT wi.id, wi.workspace_id, wi.email, wi.role, wi.invited_by,
                    wi.status, wi.expires_at, wi.accepted_at, wi.created_at,
                    u.email AS invited_by_email, u.name AS invited_by_name
             FROM workspace_invitations wi
             LEFT JOIN users u ON u.id = wi.invited_by
             WHERE wi.workspace_id = ?
             ORDER BY wi.created_at DESC
             LIMIT 100`
          )
          .bind(workspaceId)
          .all();
        return json({ invitations: result.results || [] });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/workspaces/:id/invitations ────────────────────────────────
    if (invitationsMatch && request.method === "POST") {
      const workspaceId = invitationsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to invite members" }, 403);

      // ── Task 1: Rate limiting — 10/hour, 25/day per workspace ────────────
      // Uses the shared D1-backed consumeApiRateLimit helper. Fails open if the
      // rate_limit table is unavailable so a transient DB hiccup never blocks invites.
      const inviteScopes = [{ scope: "workspace", scope_id: workspaceId }];
      const rlHourly = await consumeApiRateLimit(env, inviteScopes, "invite_send", 10, 3600);
      if (rlHourly) {
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "invitation_rate_limit_hit",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  "Invitation rate limit hit (hourly)",
          metadata:     { action: "invite_send", window: "hourly", limit: 10 },
        });
        return json({ error: "Too many invitations sent. Please try again later.", code: "rate_limit_exceeded" }, 429);
      }
      const rlDaily = await consumeApiRateLimit(env, inviteScopes, "invite_send_daily", 25, 86400);
      if (rlDaily) {
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "invitation_rate_limit_hit",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  "Invitation rate limit hit (daily)",
          metadata:     { action: "invite_send", window: "daily", limit: 25 },
        });
        return json({ error: "Too many invitations sent. Please try again later.", code: "rate_limit_exceeded" }, 429);
      }

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      const role  = (body.role || "viewer").trim().toLowerCase();
      const VALID_INVITE_ROLES = new Set(["viewer", "analyst", "admin"]);

      if (!email) return json({ error: "email is required" }, 400);
      if (!isValidEmail(email)) return json({ error: "email must be valid" }, 400);
      if (!VALID_INVITE_ROLES.has(role)) return json({ error: "role must be one of: viewer, analyst, admin" }, 400);

      // ── Admin invite ceiling — admins cannot grant their own privilege level ──
      // owner → may invite viewer | analyst | admin
      // admin → may invite viewer | analyst only
      if (access.role === "admin" && role === "admin") {
        return json({ error: "Admins can only invite viewers and analysts. Only owners can invite admins." }, 403);
      }

      // ── Task 4a: Self-invitation guard ───────────────────────────────────
      if (email === (user.email || "").toLowerCase()) {
        return json({ error: "You cannot invite yourself to this workspace." }, 400);
      }

      try {
        const workspace = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!workspace) return json({ error: "Workspace not found" }, 404);

        const billingUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
        const invitePlan    = await getEffectivePlan(billingUserId, env);
        const inviteLimits  = getPlanLimits(invitePlan);

        // Member seat limit (existing)
        const memberCount = await env.cybermeters_db
          .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ?")
          .bind(workspaceId)
          .first();
        if ((memberCount?.cnt ?? 0) >= inviteLimits.users) {
          return json(planLimitExceeded("users", inviteLimits.users, memberCount?.cnt ?? 0), 403);
        }

        // ── Task 2: Pending invitation limit (plan-gated) ─────────────────
        // free=10, starter=25, professional=50, business=250, enterprise=unlimited
        const pendingRow = await env.cybermeters_db
          .prepare(
            `SELECT COUNT(*) AS cnt FROM workspace_invitations
             WHERE workspace_id = ? AND status = 'pending'
               AND expires_at > datetime('now')`
          )
          .bind(workspaceId)
          .first();
        const pendingLimit = inviteLimits.pending_invitations ?? 10;
        if (pendingLimit < 999999 && (pendingRow?.cnt ?? 0) >= pendingLimit) {
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      user.id,
            event_type:   "invitation_limit_reached",
            entity_type:  "workspace",
            entity_id:    workspaceId,
            description:  "Pending invitation limit reached",
            metadata:     { plan: invitePlan, pending_count: pendingRow?.cnt ?? 0, limit: pendingLimit },
          });
          return json({ error: "Invitation limit reached for your plan.", code: "invitation_limit_reached" }, 403);
        }

        // ── Task 4b: Existing member check (hardened — no role/status leakage) ─
        const existingUser = await env.cybermeters_db
          .prepare("SELECT id FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (existingUser) {
          const existingMember = await env.cybermeters_db
            .prepare("SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
            .bind(workspaceId, existingUser.id)
            .first();
          // Generic message — does not reveal whether address is a registered user
          if (existingMember) return json({ error: "This address cannot be invited to this workspace." }, 409);
        }

        // ── Task 4c: Active (pending) invitation check — hardened message ──
        const existingInvite = await env.cybermeters_db
          .prepare(
            `SELECT id FROM workspace_invitations
             WHERE workspace_id = ? AND email = ? AND status = 'pending'
               AND expires_at > datetime('now')
             LIMIT 1`
          )
          .bind(workspaceId, email)
          .first();
        // Generic message — does not reveal whether a token or invite exists
        if (existingInvite) return json({ error: "This address cannot be invited to this workspace." }, 409);

        // ── Task 3: Cooldown — 24 h between sends to the same address ─────
        // Exceptions: if the previous invite is already cancelled, expired, or
        // accepted the cooldown does not apply — re-inviting is permitted.
        const cooldownRow = await env.cybermeters_db
          .prepare(
            `SELECT id FROM workspace_invitations
             WHERE workspace_id = ? AND email = ?
               AND created_at > datetime('now', '-24 hours')
               AND status NOT IN ('cancelled', 'expired', 'accepted')
             LIMIT 1`
          )
          .bind(workspaceId, email)
          .first();
        if (cooldownRow) {
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      user.id,
            event_type:   "invitation_cooldown_blocked",
            entity_type:  "workspace",
            entity_id:    workspaceId,
            description:  "Invitation cooldown — duplicate send within 24 h",
            // No email or token in metadata — safe to store
            metadata:     { workspace_id: workspaceId },
          });
          return json({ error: "This address was recently invited. Please wait before sending another invitation.", code: "invitation_cooldown" }, 429);
        }

        // ── All checks passed — create invitation ─────────────────────────
        const { raw: token, hash: tokenHash } = await generateInviteToken();
        const inviteId  = createId("wsi");
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_invitations
               (id, workspace_id, email, role, token_hash, invited_by, status, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`
          )
          .bind(inviteId, workspaceId, email, role, tokenHash, user.id, expiresAt)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_invitation_created",
          entity_type:  "workspace_invitation",
          entity_id:    inviteId,
          description:  `${user.email} invited ${email} as ${role}`,
          metadata:     { invitation_id: inviteId, email, role, expires_at: expiresAt },
        });

        return json({
          invitation: {
            id: inviteId, workspace_id: workspaceId, email, role,
            status: "pending", expires_at: expiresAt,
          },
          token,
        }, 201);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/members ──────────────────────────────────────
    const membersListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/members$/);
    if (membersListMatch && request.method === "GET") {
      const workspaceId = membersListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "member:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.created_at,
                    u.email, u.name
             FROM workspace_members wm
             JOIN users u ON u.id = wm.user_id
             WHERE wm.workspace_id = ?
             ORDER BY
               CASE wm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'analyst' THEN 2 ELSE 3 END,
               wm.created_at ASC`
          )
          .bind(workspaceId)
          .all();
        return json({
          workspace_id: workspaceId,
          caller_role:  access.role,
          members:      result.results || [],
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/workspaces/:id/members — add member ─────────────────────────
    if (membersListMatch && request.method === "POST") {
      const workspaceId = membersListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:manage_members", env);
      if (!access) return json({ error: "Forbidden — owner role required to manage members" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email   = (body.email || "").trim().toLowerCase();
      const rawRole = (body.role  || "viewer").trim().toLowerCase();

      if (!email)                          return json({ error: "email is required" }, 400);
      if (!ROLE_RANK.hasOwnProperty(rawRole)) return json({ error: `role must be one of: ${Object.keys(ROLE_RANK).join(", ")}` }, 400);
      if (rawRole === "owner")             return json({ error: "Cannot assign owner role via invite. Transfer ownership instead." }, 400);

      try {
        // Resolve target user by email
        const target = await env.cybermeters_db
          .prepare("SELECT id, email, name FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (!target) return json({ error: `No account found for ${email}. The user must sign up first.` }, 404);

        // Prevent demoting an owner via this route
        const existing = await env.cybermeters_db
          .prepare("SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
          .bind(workspaceId, target.id)
          .first();
        if (existing?.role === "owner") return json({ error: "Cannot change the owner's role via this endpoint." }, 409);

        if (!existing) {
          const billingUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
          const memberPlan = await getEffectivePlan(billingUserId, env);
          const memberLimits = getPlanLimits(memberPlan);
          const memberCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ?")
            .bind(workspaceId)
            .first();
          if ((memberCount?.cnt ?? 0) >= memberLimits.users) {
            return json(planLimitExceeded("users", memberLimits.users, memberCount?.cnt ?? 0), 403);
          }
        }

        const memberId = createId("wm");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by, created_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role`
          )
          .bind(memberId, workspaceId, target.id, rawRole, user.id)
          .run();

        const memberAuditType = existing ? "workspace_member_role_changed" : "workspace_member_added";
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   memberAuditType,
          entity_type:  "member",
          entity_id:    target.id,
          description:  existing
            ? `${user.email} changed ${target.email} role from ${existing.role} to ${rawRole}`
            : `${user.email} added ${target.email} as ${rawRole}`,
          metadata:     {
            user_id: target.id,
            email: target.email,
            role: rawRole,
            previous_role: existing?.role ?? null,
          },
        });

        return json({
          member: {
            workspace_id: workspaceId,
            user_id:      target.id,
            email:        target.email,
            name:         target.name,
            role:         rawRole,
          },
        }, 201);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── DELETE /api/workspaces/:id/members/:memberId ──────────────────────────
    const memberDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/members\/([^/]+)$/);
    if (memberDeleteMatch && request.method === "DELETE") {
      const workspaceId = memberDeleteMatch[1];
      const memberId    = memberDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Admin+ can remove members, but admins are limited to analyst/viewer targets.
      // Owner can remove any non-last-owner member.
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to remove members" }, 403);

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, user_id, role FROM workspace_members WHERE id = ? AND workspace_id = ?")
          .bind(memberId, workspaceId)
          .first();
        if (!row) return json({ error: "Member not found" }, 404);

        // Admin ceiling: admins can only remove analyst or viewer members.
        if (access.role === "admin" && row.role !== "analyst" && row.role !== "viewer") {
          return json({ error: "Admins can only remove analyst and viewer members. Only owners can remove admins." }, 403);
        }
        // Owner cannot remove themselves
        if (row.role === "owner" && row.user_id === user.id) {
          return json({ error: "Owner cannot remove themselves. Transfer ownership first." }, 409);
        }
        // Cannot remove the last owner
        if (row.role === "owner") {
          const ownerCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ? AND role = 'owner'")
            .bind(workspaceId)
            .first();
          if ((ownerCount?.cnt ?? 0) <= 1) {
            return json({ error: "Cannot remove the only owner of a workspace." }, 409);
          }
        }

        await env.cybermeters_db
          .prepare("DELETE FROM workspace_members WHERE id = ?")
          .bind(memberId)
          .run();

        // Audit: member removed
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_member_removed",
          entity_type:  "member",
          entity_id:    row.user_id,
          description:  `${user.email} removed member with role ${row.role}`,
          metadata:     { removed_member_id: memberId, removed_user_id: row.user_id, role: row.role },
        });

        return json({ success: true, removed_id: memberId });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PATCH /api/workspaces/:id/members/:memberId — change role ────────────
    const memberRoleMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/members\/([^\/]+)$/);
    if (memberRoleMatch && request.method === "PATCH") {
      const workspaceId = memberRoleMatch[1];
      const targetMemberId = memberRoleMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Admin+ can change roles; admins are limited to analyst/viewer targets and
      // cannot promote anyone to admin. Owners have no ceiling.
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to change member roles" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const newRole = (body.role || "").trim().toLowerCase();
      // Admins can only assign viewer or analyst; owners can assign viewer, analyst, or admin.
      const CHANGEABLE_ROLES = access.role === "owner"
        ? new Set(["viewer", "analyst", "admin"])
        : new Set(["viewer", "analyst"]);
      if (!CHANGEABLE_ROLES.has(newRole)) {
        return json({
          error: access.role === "owner"
            ? "role must be one of: viewer, analyst, admin"
            : "Admins can only assign viewer or analyst roles.",
        }, 400);
      }

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, user_id, role FROM workspace_members WHERE id = ? AND workspace_id = ?")
          .bind(targetMemberId, workspaceId)
          .first();
        if (!row) return json({ error: "Member not found" }, 404);
        if (row.role === "owner") return json({ error: "Cannot change the owner's role. Transfer ownership instead." }, 409);
        if (row.user_id === user.id) return json({ error: "Cannot change your own role." }, 409);
        // Admin ceiling: cannot change roles of other admins.
        if (access.role === "admin" && row.role === "admin") {
          return json({ error: "Admins cannot change the role of other admins. Only owners can do this." }, 403);
        }

        const prevRole = row.role;
        await env.cybermeters_db
          .prepare("UPDATE workspace_members SET role = ? WHERE id = ?")
          .bind(newRole, targetMemberId)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_role_changed",
          entity_type:  "member",
          entity_id:    row.user_id,
          description:  `${user.email} changed member role from ${prevRole} to ${newRole}`,
          metadata:     { member_id: targetMemberId, user_id: row.user_id, previous_role: prevRole, new_role: newRole },
        });

        return json({ success: true, member_id: targetMemberId, role: newRole, previous_role: prevRole });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── DELETE /api/workspaces/:id/invitations/:invId — cancel invitation ──────
    const invitationCancelMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/invitations\/([^\/]+)$/);
    if (invitationCancelMatch && request.method === "DELETE") {
      const workspaceId    = invitationCancelMatch[1];
      const invitationId   = invitationCancelMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to cancel invitations" }, 403);

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, email, role, status FROM workspace_invitations WHERE id = ? AND workspace_id = ?")
          .bind(invitationId, workspaceId)
          .first();
        if (!row) return json({ error: "Invitation not found" }, 404);
        if (row.status !== "pending") return json({ error: `Invitation is already ${row.status}` }, 409);

        await env.cybermeters_db
          .prepare("UPDATE workspace_invitations SET status = 'cancelled' WHERE id = ?")
          .bind(invitationId)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_invitation_cancelled",
          entity_type:  "workspace_invitation",
          entity_id:    invitationId,
          description:  `${user.email} cancelled invitation for ${row.email}`,
          metadata:     { invitation_id: invitationId, email: row.email, role: row.role },
        });

        return json({ success: true, cancelled_id: invitationId });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/invitations/:token — public preview (no auth required) ─────
    const invitationPreviewMatch = url.pathname.match(/^\/api\/invitations\/([^/]+)$/);
    if (invitationPreviewMatch && request.method === "GET") {
      const rawToken = invitationPreviewMatch[1];
      try {
        const tokenHash = await hashToken(rawToken);
        const invite = await env.cybermeters_db
          .prepare(`
            SELECT wi.role, wi.status, wi.expires_at,
                   w.name AS workspace_name,
                   u.name AS invited_by_name, u.email AS invited_by_email
            FROM workspace_invitations wi
            JOIN workspaces w ON w.id = wi.workspace_id
            LEFT JOIN users u ON u.id = wi.invited_by
            WHERE wi.token_hash = ?
            LIMIT 1
          `)
          .bind(tokenHash)
          .first();

        if (!invite) return json({ error: "Invitation not found" }, 404);

        return json({
          workspace_name:   invite.workspace_name,
          invited_by_name:  invite.invited_by_name || invite.invited_by_email || "A team member",
          role:             invite.role,
          expires_at:       invite.expires_at,
          status:           invite.status,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/invitations/:token/accept ─────────────────────────────────
    const invitationAcceptMatch = url.pathname.match(/^\/api\/invitations\/([^/]+)\/accept$/);
    if (invitationAcceptMatch && request.method === "POST") {
      const rawToken = invitationAcceptMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      try {
        const tokenHash = await hashToken(rawToken);
        const invite = await env.cybermeters_db
          .prepare(
            `SELECT id, workspace_id, email, role, invited_by, status, expires_at
             FROM workspace_invitations
             WHERE token_hash = ?
             LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!invite) return json({ error: "Invitation not found" }, 404);
        if (invite.status !== "pending") return json({ error: `Invitation is ${invite.status}` }, 409);

        const expiresAt = new Date(invite.expires_at);
        if (!invite.expires_at || Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
          await env.cybermeters_db
            .prepare("UPDATE workspace_invitations SET status = 'expired' WHERE id = ?")
            .bind(invite.id)
            .run();
          await createAuditEvent(env, {
            workspace_id: invite.workspace_id,
            user_id:      user.id,
            event_type:   "workspace_invitation_expired",
            entity_type:  "workspace_invitation",
            entity_id:    invite.id,
            description:  `Workspace invitation for ${invite.email} expired`,
            metadata:     { invitation_id: invite.id, invited_email: invite.email, role: invite.role, expires_at: invite.expires_at },
          });
          return json({ error: "Invitation expired" }, 410);
        }

        if ((user.email || "").trim().toLowerCase() !== invite.email) {
          return json({ error: "Invitation email does not match authenticated user" }, 403);
        }

        const existingMember = await env.cybermeters_db
          .prepare("SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
          .bind(invite.workspace_id, user.id)
          .first();
        if (!existingMember) {
          const billingUserId = await getWorkspaceBillingUserId(invite.workspace_id, invite.invited_by, env);
          const acceptPlan = await getEffectivePlan(billingUserId, env);
          const acceptLimits = getPlanLimits(acceptPlan);
          const memberCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ?")
            .bind(invite.workspace_id)
            .first();
          if ((memberCount?.cnt ?? 0) >= acceptLimits.users) {
            return json(planLimitExceeded("users", acceptLimits.users, memberCount?.cnt ?? 0), 403);
          }
        }

        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by, created_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role`
          )
          .bind(createId("wm"), invite.workspace_id, user.id, invite.role, invite.invited_by)
          .run();

        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_invitations
             SET status = 'accepted', accepted_at = datetime('now')
             WHERE id = ?`
          )
          .bind(invite.id)
          .run();

        await createAuditEvent(env, {
          workspace_id: invite.workspace_id,
          user_id:      user.id,
          event_type:   "workspace_invitation_accepted",
          entity_type:  "workspace_invitation",
          entity_id:    invite.id,
          description:  `${user.email} accepted workspace invitation as ${invite.role}`,
          metadata:     { invitation_id: invite.id, invited_email: invite.email, role: invite.role },
        });

        return json({
          success: true,
          workspace_id: invite.workspace_id,
          role: invite.role,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/executive-dashboard ──────────────────────────
    // Single-call aggregation for the Executive Risk Intelligence Dashboard.
    // Returns summary, score_trend, risk_distribution, top_risks, changes,
    // remediation priorities, and KPI bar — all in one response.
    const execDashMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/executive-dashboard$/);
    if (execDashMatch && request.method === "GET") {
      const wsId = execDashMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // ── Feature gate: executive_dashboard — professional+ only ─────────────
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan    = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, "executive_dashboard")) {
          return json({
            error:         "plan_feature_required",
            feature:       "executive_dashboard",
            required_plan: "professional",
            upgrade_url:   "/billing",
          }, 403);
        }
      }

      try {
        const [
          domainRow,
          latestScanRow,
          activeAssetsRow,
          criticalRow,
          highRow,
          scoreTrendRows,
          riskDistRows,
          topRisksRows,
          scoreHistoryRows,
          newAssetsRow,
          remediationRows,
          reportsRow,
        ] = await env.cybermeters_db.batch([

          // 1. Domain summary — total + verified count
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(d.id) AS total,
                      SUM(CASE WHEN d.verification_status = 'verified' THEN 1 ELSE 0 END) AS verified
               FROM workspace_domains wd
               JOIN domains d ON d.id = wd.domain_id
               WHERE wd.workspace_id = ?`
            )
            .bind(wsId),

          // 2. Latest completed scan in workspace.
          // Executive Dashboard security_score intentionally uses this latest
          // completed scan; /summary may use average latest score across domains.
          env.cybermeters_db
            .prepare(
              `SELECT s.id, s.domain, s.score, s.rating, s.created_at
               FROM scans s
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL
               ORDER BY s.created_at DESC LIMIT 1`
            )
            .bind(wsId),

          // 3. Active assets
          env.cybermeters_db
            .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
            .bind(wsId),

          // 4. Critical findings across the workspace in the last 30 days.
          // This is a 30-day workspace metric, not latest-scan-only.
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(f.id) AS n
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND f.severity = 'critical'
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')`
            )
            .bind(wsId),

          // 5. High findings across the workspace in the last 30 days.
          // This is a 30-day workspace metric, not latest-scan-only.
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(f.id) AS n
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND f.severity = 'high'
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')`
            )
            .bind(wsId),

          // 6. Score trend — last 30 historical_scores ordered oldest→newest for chart
          env.cybermeters_db
            .prepare(
              `SELECT score, rating, domain, created_at
               FROM (SELECT score, rating, domain, created_at
                     FROM historical_scores WHERE workspace_id = ?
                     ORDER BY created_at DESC LIMIT 30)
               ORDER BY created_at ASC`
            )
            .bind(wsId),

          // 7. Risk distribution — severity counts from last 30 days.
          env.cybermeters_db
            .prepare(
              `SELECT f.severity, COUNT(*) AS n
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')
               GROUP BY f.severity`
            )
            .bind(wsId),

          // 8. Top risks — top 10 by severity from last 30 days.
          // This is finding-based over the 30-day window, not latest-scan-only.
          env.cybermeters_db
            .prepare(
              `SELECT f.title, f.severity, f.created_at, s.domain
               FROM findings f
               JOIN scans s ON f.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND s.status = 'completed'
                 AND f.severity IN ('critical', 'high', 'medium')
                 AND s.created_at >= datetime('now', '-30 days')
               ORDER BY CASE f.severity
                 WHEN 'critical' THEN 1
                 WHEN 'high'     THEN 2
                 WHEN 'medium'   THEN 3
                 ELSE 4 END ASC,
                 f.created_at DESC
               LIMIT 10`
            )
            .bind(wsId),

          // 9. Last 2 historical scores for score delta
          env.cybermeters_db
            .prepare(
              `SELECT score, created_at, domain
               FROM historical_scores WHERE workspace_id = ?
               ORDER BY created_at DESC LIMIT 2`
            )
            .bind(wsId),

          // 10. New assets discovered in last 7 days
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM asset_events
               WHERE workspace_id = ?
                 AND event_type IN ('asset_discovered', 'new_asset_discovered')
                 AND created_at >= datetime('now', '-7 days')`
            )
            .bind(wsId),

          // 11. Remediation items from last 30 days scans
          env.cybermeters_db
            .prepare(
              `SELECT ri.priority, ri.title, ri.reason, s.domain, ri.created_at
               FROM remediation_items ri
               JOIN scans s ON ri.scan_id = s.id
               JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')
               ORDER BY CAST(ri.priority AS INTEGER) ASC
               LIMIT 30`
            )
            .bind(wsId),

          // 12. Workspace reports generated
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM workspace_reports
               WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL`
            )
            .bind(wsId),
        ]);

        // ── Assemble response ───────────────────────────────────────────────

        const domainData    = domainRow.results[0]       ?? { total: 0, verified: 0 };
        const latestScan    = latestScanRow.results[0]   ?? null;
        const activeAssets  = activeAssetsRow.results[0]?.n ?? 0;
        const criticalCount = criticalRow.results[0]?.n  ?? 0;
        const highCount     = highRow.results[0]?.n      ?? 0;

        const trendPoints = (scoreTrendRows.results || []).map(r => ({
          score:      r.score,
          rating:     r.rating,
          domain:     r.domain,
          scanned_at: r.created_at,
        }));

        const riskDist = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        for (const r of (riskDistRows.results || [])) {
          const sev = r.severity?.toLowerCase();
          if (sev in riskDist) riskDist[sev] += r.n;
          riskDist.total += r.n;
        }

        const topRisks = (topRisksRows.results || []).map(r => ({
          title:       r.title,
          severity:    r.severity,
          domain:      r.domain,
          detected_at: r.created_at,
        }));

        const scoreHistory  = scoreHistoryRows.results || [];
        const scoreCurrent  = scoreHistory[0]?.score  ?? null;
        const scorePrevious = scoreHistory[1]?.score  ?? null;
        const scoreDelta    = (scoreCurrent != null && scorePrevious != null)
          ? scoreCurrent - scorePrevious : null;

        const newAssets7d = newAssetsRow.results[0]?.n ?? 0;

        const remItems = remediationRows.results || [];
        const fixNow  = remItems.filter(r => String(r.priority) === "1");
        const fixNext = remItems.filter(r => String(r.priority) === "2");
        const monitor = remItems.filter(r => parseInt(r.priority, 10) >= 3);

        const totalDomains     = domainData.total   ?? 0;
        const verifiedCount    = domainData.verified ?? 0;
        const verificationRate = totalDomains > 0
          ? Math.round((verifiedCount / totalDomains) * 100) : 0;

        const avgScore = trendPoints.length > 0
          ? Math.round(trendPoints.reduce((s, p) => s + (p.score ?? 0), 0) / trendPoints.length)
          : (latestScan?.score ?? null);

        return json({
          workspace_id: wsId,
          generated_at: new Date().toISOString(),

          summary: {
            security_score:    latestScan?.score   ?? null,
            risk_level:        latestScan?.rating  ?? null,
            domains:           totalDomains,
            verified_domains:  verifiedCount,
            verification_rate: verificationRate,
            active_assets:     activeAssets,
            critical_findings: criticalCount,
            high_findings:     highCount,
            last_scan_at:      latestScan?.created_at ?? null,
            last_scan_domain:  latestScan?.domain     ?? null,
          },

          score_trend:       trendPoints,
          risk_distribution: riskDist,
          top_risks:         topRisks,

          changes: {
            score_current:  scoreCurrent,
            score_previous: scorePrevious,
            score_delta:    scoreDelta,
            score_direction: scoreDelta == null ? null
              : scoreDelta > 0 ? "up" : scoreDelta < 0 ? "down" : "flat",
            new_assets_7d:  newAssets7d,
          },

          remediation: {
            fix_now:  fixNow.map(r  => ({ title: r.title, reason: r.reason, domain: r.domain })),
            fix_next: fixNext.map(r => ({ title: r.title, reason: r.reason, domain: r.domain })),
            monitor:  monitor.slice(0, 10).map(r => ({ title: r.title, reason: r.reason, domain: r.domain })),
          },

          kpis: {
            verification_rate: verificationRate,
            average_score:     avgScore,
            critical_risks:    criticalCount,
            reports_generated: reportsRow.results[0]?.n ?? 0,
            assets_discovered: activeAssets,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

        // ── GET /api/workspaces/:id/activity ─────────────────────────────────────
    // Returns paginated audit events for a workspace.
    // Query params: ?limit=N (max 100) &event_type=X &offset=N
    const activityMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/activity$/);
    if (activityMatch && request.method === "GET") {
      const workspaceId = activityMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const limit     = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 100);
        const offset    = parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 100000);
        const eventType = url.searchParams.get("event_type") || null;

        let query, binds;
        if (eventType) {
          query = `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
                   FROM audit_events
                   WHERE workspace_id = ? AND event_type = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?`;
          binds = [workspaceId, eventType, limit, offset];
        } else {
          query = `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
                   FROM audit_events
                   WHERE workspace_id = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?`;
          binds = [workspaceId, limit, offset];
        }

        const result = await env.cybermeters_db.prepare(query).bind(...binds).all();
        const events = (result.results || []).map(r => ({
          ...r,
          metadata: r.metadata_json ? JSON.parse(r.metadata_json) : null,
          metadata_json: undefined,
        }));

        // Enrich with actor email from users table (best-effort JOIN avoided via batch)
        const userIds = [...new Set(events.map(e => e.user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const placeholders = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, name, email FROM users WHERE id IN (${placeholders})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { name: u.name, email: u.email };
        }

        const enriched = events.map(e => ({
          ...e,
          actor: e.user_id ? (userMap[e.user_id] ?? { name: null, email: null }) : null,
        }));

        return json({ events: enriched, limit, offset, count: enriched.length });
      } catch (e) {
        return serverError("api", e);
      }
    }


    // ── GET /api/workspaces/:id/audit-events ─────────────────────────────────
    // Customer-facing compliance endpoint. Returns filtered, paginated audit events.
    // Access: admin or owner only (audit:read permission).
    // Metadata is sanitized — no secrets, tokens, or credentials returned.
    const auditEventsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/audit-events$/);
    if (auditEventsMatch && request.method === "GET") {
      const workspaceId = auditEventsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "audit:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // ── Feature gate: audit_logs — professional+ only ──────────────────────
      {
        const ownerId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
        const plan    = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, "audit_logs")) {
          return json({
            error:         "plan_feature_required",
            feature:       "audit_logs",
            required_plan: "professional",
            upgrade_url:   "/billing",
          }, 403);
        }
      }

      try {
        const limit       = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 100);
        const offset      = parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 100000);
        const eventType   = url.searchParams.get("event_type")   || null;
        const actorUserId = url.searchParams.get("actor_user_id") || null;
        const entityType  = url.searchParams.get("entity_type")  || null;
        const entityId    = url.searchParams.get("entity_id")    || null;
        const dateFrom    = url.searchParams.get("date_from")    || null;
        const dateTo      = url.searchParams.get("date_to")      || null;
        const search      = url.searchParams.get("search")       || null;

        // Build dynamic WHERE clauses
        const conditions = ["workspace_id = ?"];
        const binds      = [workspaceId];

        if (eventType)   { conditions.push("event_type = ?");   binds.push(eventType);   }
        if (actorUserId) { conditions.push("user_id = ?");      binds.push(actorUserId); }
        if (entityType)  { conditions.push("entity_type = ?");  binds.push(entityType);  }
        if (entityId)    { conditions.push("entity_id = ?");    binds.push(entityId);    }
        if (dateFrom)    { conditions.push("created_at >= ?");  binds.push(dateFrom);    }
        if (dateTo)      { conditions.push("created_at <= ?");  binds.push(dateTo + "T23:59:59.999Z"); }
        if (search) {
          conditions.push(
            "(event_type LIKE ? OR entity_type LIKE ? OR entity_id LIKE ? OR description LIKE ?)"
          );
          const q = `%${search.replace(/[%_]/g, "\$&")}%`;
          binds.push(q, q, q, q);
        }

        const whereClause = conditions.join(" AND ");

        // Count total matching rows
        const countRow = await env.cybermeters_db
          .prepare(`SELECT COUNT(*) AS total FROM audit_events WHERE ${whereClause}`)
          .bind(...binds)
          .first();
        const total = countRow?.total ?? 0;

        // Fetch page
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
             FROM audit_events
             WHERE ${whereClause}
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?`
          )
          .bind(...binds, limit, offset)
          .all();

        const events = (rows.results || []).map(r => ({
          id:            r.id,
          created_at:    r.created_at,
          event_type:    r.event_type,
          actor_user_id: r.user_id,
          workspace_id:  workspaceId,
          entity_type:   r.entity_type,
          entity_id:     r.entity_id,
          description:   r.description,
          metadata:      r.metadata_json ? sanitizeAuditMetadata(JSON.parse(r.metadata_json)) : null,
        }));

        // Enrich actor emails (batch lookup — no N+1)
        const userIds = [...new Set(events.map(e => e.actor_user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const ph = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, email, name FROM users WHERE id IN (${ph})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { email: u.email, name: u.name };
        }

        const enriched = events.map(e => ({
          ...e,
          actor_email: e.actor_user_id ? (userMap[e.actor_user_id]?.email ?? null) : null,
          actor_name:  e.actor_user_id ? (userMap[e.actor_user_id]?.name  ?? null) : null,
        }));

        // Non-fatal meta-audit event
        createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "audit_log_viewed",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  `Audit log viewed`,
          metadata:     { limit, offset, filters: { event_type: eventType, entity_type: entityType, search } },
        }).catch(() => {});

        return json({
          events: enriched,
          pagination: pageMeta({ items: enriched, limit, offset, total }),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/audit-events/export ──────────────────────────
    // CSV or JSON export of audit events. Same filters as the list endpoint.
    // Max 10,000 rows. Default 1,000.
    const auditExportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/audit-events\/export$/);
    if (auditExportMatch && request.method === "GET") {
      const workspaceId = auditExportMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "audit:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const format      = (url.searchParams.get("format") || "csv").toLowerCase();
        if (format !== "csv" && format !== "json") return json({ error: "format must be csv or json" }, 400);

        const exportLimit = parseBoundedInteger(url.searchParams.get("limit"), 1000, 1, 10000);
        const eventType   = url.searchParams.get("event_type")   || null;
        const actorUserId = url.searchParams.get("actor_user_id") || null;
        const entityType  = url.searchParams.get("entity_type")  || null;
        const entityId    = url.searchParams.get("entity_id")    || null;
        const dateFrom    = url.searchParams.get("date_from")    || null;
        const dateTo      = url.searchParams.get("date_to")      || null;
        const search      = url.searchParams.get("search")       || null;

        const conditions = ["workspace_id = ?"];
        const binds      = [workspaceId];

        if (eventType)   { conditions.push("event_type = ?");   binds.push(eventType);   }
        if (actorUserId) { conditions.push("user_id = ?");      binds.push(actorUserId); }
        if (entityType)  { conditions.push("entity_type = ?");  binds.push(entityType);  }
        if (entityId)    { conditions.push("entity_id = ?");    binds.push(entityId);    }
        if (dateFrom)    { conditions.push("created_at >= ?");  binds.push(dateFrom);    }
        if (dateTo)      { conditions.push("created_at <= ?");  binds.push(dateTo + "T23:59:59.999Z"); }
        if (search) {
          conditions.push(
            "(event_type LIKE ? OR entity_type LIKE ? OR entity_id LIKE ? OR description LIKE ?)"
          );
          const q = `%${search.replace(/[%_]/g, "\$&")}%`;
          binds.push(q, q, q, q);
        }

        const whereClause = conditions.join(" AND ");
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
             FROM audit_events
             WHERE ${whereClause}
             ORDER BY created_at DESC
             LIMIT ?`
          )
          .bind(...binds, exportLimit)
          .all();

        // Enrich with actor emails
        const rawEvents = rows.results || [];
        const userIds   = [...new Set(rawEvents.map(r => r.user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const ph = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, email, name FROM users WHERE id IN (${ph})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { email: u.email, name: u.name };
        }

        const events = rawEvents.map(r => ({
          id:            r.id,
          created_at:    r.created_at,
          event_type:    r.event_type,
          actor_user_id: r.user_id,
          actor_email:   r.user_id ? (userMap[r.user_id]?.email ?? null) : null,
          actor_name:    r.user_id ? (userMap[r.user_id]?.name  ?? null) : null,
          workspace_id:  workspaceId,
          entity_type:   r.entity_type,
          entity_id:     r.entity_id,
          description:   r.description,
          metadata:      r.metadata_json ? sanitizeAuditMetadata(JSON.parse(r.metadata_json)) : null,
        }));

        // Non-fatal meta-audit event
        createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "audit_log_exported",
          entity_type:  "workspace",
          entity_id:    workspaceId,
          description:  `Audit log exported as ${format.toUpperCase()} (${events.length} rows)`,
          metadata:     { format, rows: events.length },
        }).catch(() => {});

        if (format === "json") {
          const filters = { event_type: eventType, actor_user_id: actorUserId, entity_type: entityType,
                            entity_id: entityId, date_from: dateFrom, date_to: dateTo, search };
          return new Response(
            JSON.stringify({ exported_at: new Date().toISOString(), workspace_id: workspaceId, filters, events }, null, 2),
            { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="audit-log-${workspaceId}.json"` } }
          );
        }

        // CSV output
        function csvCell(v) {
          if (v === null || v === undefined) return "";
          const s = typeof v === "object" ? JSON.stringify(sanitizeAuditMetadata(v)) : String(v);
          if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
            return `"${s.replace(/"/g, '""')}"`;
          }
          return s;
        }
        const header = ["id", "created_at", "event_type", "actor_user_id", "actor_email", "actor_name",
                         "entity_type", "entity_id", "description", "metadata"];
        const csvRows = [header.join(",")];
        for (const e of events) {
          csvRows.push([
            csvCell(e.id), csvCell(e.created_at), csvCell(e.event_type),
            csvCell(e.actor_user_id), csvCell(e.actor_email), csvCell(e.actor_name),
            csvCell(e.entity_type), csvCell(e.entity_id), csvCell(e.description),
            csvCell(e.metadata),
          ].join(","));
        }
        return new Response(csvRows.join("\r\n"), {
          headers: {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": `attachment; filename="audit-log-${workspaceId}.csv"`,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/notifications ────────────────────────────────
    const notifListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notifications$/);
    if (notifListMatch && request.method === "GET") {
      const workspaceId = notifListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      // If the user is authenticated but not a member of this workspace
      // (e.g. stale localStorage workspace ID, invited workspace that no longer
      // exists, or first login before any workspace is created), return an empty
      // notification list rather than 403. A 403 here is never actionable by the
      // client and causes noisy console errors with no user-visible explanation.
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) {
        return json({
          workspace_id:  workspaceId,
          unread_count:  0,
          count:         0,
          notifications: [],
        });
      }
      try {
        const limit  = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const status = url.searchParams.get("status") || null; // 'unread' | 'read' | null (all)
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        let query, binds;
        if (status) {
          query  = `SELECT id, type, severity, title, message, metadata_json, status, created_at, read_at
                    FROM notification_events
                    WHERE workspace_id = ? AND status = ?
                    ORDER BY created_at DESC LIMIT ?`;
          binds  = [workspaceId, status, limit];
        } else {
          query  = `SELECT id, type, severity, title, message, metadata_json, status, created_at, read_at
                    FROM notification_events
                    WHERE workspace_id = ?
                    ORDER BY created_at DESC LIMIT ?`;
          binds  = [workspaceId, limit];
        }

        const [rows, unreadRow] = await env.cybermeters_db.batch([
          env.cybermeters_db.prepare(query).bind(...binds),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM notification_events WHERE workspace_id = ? AND status = 'unread'")
            .bind(workspaceId),
        ]);

        const notifications = (rows.results || []).map(n => ({
          ...n,
          metadata: n.metadata_json ? (() => { try { return JSON.parse(n.metadata_json); } catch { return null; } })() : null,
          metadata_json: undefined,
        }));

        return json({
          workspace_id:   workspaceId,
          unread_count:   unreadRow.results?.[0]?.cnt ?? 0,
          count:          notifications.length,
          notifications,
          pagination:     pageMeta({ items: notifications, limit, offset: 0 }),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/workspaces/:id/notifications/:notifId/read ─────────────────
    const notifReadMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notifications\/([^/]+)\/read$/);
    if (notifReadMatch && request.method === "POST") {
      const workspaceId  = notifReadMatch[1];
      const notifId      = notifReadMatch[2];
      const notifUser = await requireAuth(request, env);
      if (!notifUser) return json({ error: "Unauthorized" }, 401);
      const notifAccess = await requireWorkspaceRole(notifUser, workspaceId, "notification:mark_read", env);
      if (!notifAccess) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        if (notifId === "all") {
          // Mark all unread notifications for this workspace as read
          await env.cybermeters_db
            .prepare(`UPDATE notification_events SET status = 'read', read_at = datetime('now')
                      WHERE workspace_id = ? AND status = 'unread'`)
            .bind(workspaceId)
            .run();
          // Audit: bulk mark read
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      notifUser?.id ?? null,
            event_type:   "notification_read",
            entity_type:  "notification",
            description:  "All notifications marked as read",
            metadata:     { bulk: true },
          });
          return json({ success: true, marked: "all" });
        }
        // Mark a specific notification as read
        const row = await env.cybermeters_db
          .prepare("SELECT id FROM notification_events WHERE id = ? AND workspace_id = ?")
          .bind(notifId, workspaceId)
          .first();
        if (!row) return json({ error: "Notification not found" }, 404);
        await env.cybermeters_db
          .prepare(`UPDATE notification_events SET status = 'read', read_at = datetime('now') WHERE id = ?`)
          .bind(notifId)
          .run();
        // Audit: single notification read
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      notifUser?.id ?? null,
          event_type:   "notification_read",
          entity_type:  "notification",
          entity_id:    notifId,
          description:  "Notification marked as read",
        });
        return json({ success: true, id: notifId });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/workspaces/:id/notification-preferences ────────────────────
    // Returns the current user's notification preferences for this workspace.
    // Defaults (no rows) are treated as "all_alerts" enabled.
    //
    // Response: {
    //   workspace_id, user_id,
    //   email_frequency: 'all_alerts' | 'critical_only' | 'daily_digest' | 'disabled'
    // }
    //
    // email_frequency is derived from notification_preferences rows:
    //   all_alerts    — no rows, or critical_finding + high_finding both enabled
    //   critical_only — critical_finding enabled, high_finding disabled
    //   daily_digest  — daily_digest enabled, critical_finding disabled
    //   disabled      — all channels disabled
    const notifPrefsGetMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notification-preferences$/);
    if (notifPrefsGetMatch && request.method === "GET") {
      const workspaceId = notifPrefsGetMatch[1];
      const prefUser = await requireAuth(request, env);
      if (!prefUser) return json({ error: "Unauthorized" }, 401);
      const prefAccess = await requireWorkspaceRole(prefUser, workspaceId, "workspace:read", env);
      if (!prefAccess) return json({ error: "Forbidden" }, 403);
      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT event_type, enabled, channel
             FROM notification_preferences
             WHERE workspace_id = ? AND (user_id = ? OR user_id IS NULL)
             ORDER BY user_id DESC` // user-level rows win over workspace-level
          )
          .bind(workspaceId, prefUser.id)
          .all();

        // Derive email_frequency from stored rows
        const byType = {};
        for (const row of (rows.results || [])) {
          byType[`${row.event_type}:${row.channel}`] = row.enabled;
        }

        let email_frequency = "all_alerts"; // default — no preferences stored
        const criticalEmail  = byType["critical_finding:email"];
        const highEmail      = byType["high_finding:email"];
        const digestEmail    = byType["daily_digest:email"];
        const disabledEmail  = byType["email_alerts:email"];

        if (disabledEmail === 0) {
          email_frequency = "disabled";
        } else if (digestEmail === 1 && criticalEmail !== 1) {
          email_frequency = "daily_digest";
        } else if (criticalEmail === 1 && highEmail === 0) {
          email_frequency = "critical_only";
        } else if (criticalEmail !== undefined || highEmail !== undefined || digestEmail !== undefined) {
          // Explicitly stored — determine from stored values
          email_frequency = (criticalEmail === 1 && highEmail === 1) ? "all_alerts" : "all_alerts";
        }

        return json({
          workspace_id:    workspaceId,
          user_id:         prefUser.id,
          email_frequency,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PUT /api/workspaces/:id/notification-preferences ────────────────────
    // Updates the current user's notification email frequency preference.
    //
    // Body: { email_frequency: 'all_alerts' | 'critical_only' | 'daily_digest' | 'disabled' }
    //
    // Upserts rows into notification_preferences — one per tracked event_type.
    if (notifPrefsGetMatch && request.method === "PUT") {
      const workspaceId = notifPrefsGetMatch[1];
      const prefPutUser = await requireAuth(request, env);
      if (!prefPutUser) return json({ error: "Unauthorized" }, 401);
      const prefPutAccess = await requireWorkspaceRole(prefPutUser, workspaceId, "workspace:read", env);
      if (!prefPutAccess) return json({ error: "Forbidden" }, 403);
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

        const VALID_FREQUENCIES = ["all_alerts", "critical_only", "daily_digest", "disabled"];
        const { email_frequency } = body;
        if (!VALID_FREQUENCIES.includes(email_frequency)) {
          return json({ error: `email_frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` }, 400);
        }

        // Map frequency choice to per-event-type enabled values
        // critical_finding:email, high_finding:email, daily_digest:email, email_alerts:email
        const prefs = {
          critical_finding: email_frequency !== "disabled" ? 1 : 0,
          high_finding:     email_frequency === "all_alerts" ? 1 : 0,
          daily_digest:     email_frequency === "daily_digest" ? 1 : 0,
          email_alerts:     email_frequency !== "disabled" ? 1 : 0,
        };

        const now = new Date().toISOString();
        const upserts = Object.entries(prefs).map(([event_type, enabled]) =>
          env.cybermeters_db
            .prepare(
              `INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
               VALUES (?, ?, ?, ?, ?, 'email', ?)
               ON CONFLICT (workspace_id, user_id, event_type, channel)
               DO UPDATE SET enabled = excluded.enabled`
            )
            .bind(createId("np"), workspaceId, prefPutUser.id, event_type, enabled, now)
        );

        await env.cybermeters_db.batch(upserts);

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      prefPutUser.id,
          event_type:   "notification_preferences_updated",
          entity_type:  "notification_preferences",
          description:  `Email notification frequency set to ${email_frequency}`,
          metadata:     { email_frequency },
        });

        return json({ success: true, workspace_id: workspaceId, email_frequency });
      } catch (e) {
        return serverError("api", e);
      }
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

    // ── POST /api/workspaces/:id/reports/generate ────────────────────────────
	    // Generates a new executive PDF report and stores it in R2 + workspace_reports.
    // Body: { "report_type": "manual" | "weekly_executive" | "monthly_executive" | "scan_snapshot" }
    //       Optional: { "report_period": "...", "scan_id": "..." }
    const rptGenMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/generate$/);
    if (rptGenMatch && request.method === 'POST') {
      const wsId = rptGenMatch[1];
      // RBAC: admin or above required to generate reports — auth is mandatory
      const rptUser = await requireAuth(request, env);
      if (!rptUser) return json({ error: "Unauthorized" }, 401);
      const rptAccess = await requireWorkspaceRole(rptUser, wsId, "report:generate", env);
      if (!rptAccess) return json({ error: "Forbidden — admin role required to generate reports" }, 403);
      try {
        // ── Enforce monthly report quota ────────────────────────────────────
        const reportLimitError = await checkReportLimit(rptUser, wsId, env);
        if (reportLimitError) return json(reportLimitError.body, reportLimitError.status);

        let body = {};
        try { body = await request.json(); } catch { /* body is optional */ }
        const VALID_TYPES = ['manual', 'scan_snapshot', 'weekly_executive', 'monthly_executive', 'quarterly_executive'];
        const report_type = VALID_TYPES.includes(body.report_type) ? body.report_type : 'manual';
        const row = await generateWorkspaceExecutiveReport(wsId, env, {
          report_type,
          report_period: body.report_period ?? null,
          scan_id:       body.scan_id       ?? null,
        });
        return json({ report: row }, 201);
      } catch (err) {
        return serverError("api", err);
      }
    }

	    // ── GET /api/workspaces/:id/report-retention ────────────────────────────
	    const storageMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/storage$/);
	    if (storageMatch && request.method === "GET") {
	      const wsId = storageMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        return json(await getWorkspaceReportStorageMetrics(wsId, env));
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const retentionMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/retention$/);
	    if (retentionMatch && request.method === "GET") {
	      const wsId = retentionMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const retention = await getWorkspaceRetentionSettings(wsId, env);
	        const storage = await getWorkspaceReportStorageMetrics(wsId, env);
	        return json({ ...retention, storage });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    if (retentionMatch && request.method === "PUT") {
	      const wsId = retentionMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage retention" }, 403);
	      try {
	        let body = {};
	        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
	        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
	        const plan = await getEffectivePlan(ownerId, env);
	        const planDefaultDays = getPlanRetentionDays(plan);
	        const requestedDays = body.retention_days === null ? null : Number(body.retention_days);
	        const allowedDays = [30, 90, 365, 730];
	        if (requestedDays !== null && (!Number.isFinite(requestedDays) || !allowedDays.includes(requestedDays))) {
	          return json({ error: "retention_days must be one of 30, 90, 365, 730, or null for enterprise." }, 400);
	        }
	        if (requestedDays === null && normalizePlan(plan) !== "enterprise") {
	          return json({ error: "Unlimited retention requires enterprise plan." }, 403);
	        }
	        if (planDefaultDays !== null && requestedDays !== null && requestedDays > planDefaultDays) {
	          return json({ error: "retention_days exceeds current plan entitlement.", max_retention_days: planDefaultDays }, 403);
	        }
	        const autoCleanup = body.auto_cleanup === false ? 0 : 1;
	        const now = new Date().toISOString();
	        await env.cybermeters_db
	          .prepare(
	            `INSERT INTO workspace_retention_settings
	               (workspace_id, retention_days, auto_cleanup, updated_by, created_at, updated_at)
	             VALUES (?, ?, ?, ?, ?, ?)
	             ON CONFLICT(workspace_id) DO UPDATE SET
	               retention_days = excluded.retention_days,
	               auto_cleanup = excluded.auto_cleanup,
	               updated_by = excluded.updated_by,
	               updated_at = excluded.updated_at`
	          )
	          .bind(wsId, requestedDays, autoCleanup, user.id, now, now)
	          .run();
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "retention_policy_updated",
	          entity_type: "workspace",
	          entity_id: wsId,
	          description: "Workspace retention settings updated",
	          metadata: { retention_days: requestedDays, auto_cleanup: autoCleanup === 1 },
	        }).catch(() => {});
	        return json(await getWorkspaceRetentionSettings(wsId, env));
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const rptRetentionMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-retention$/);
    if (rptRetentionMatch && request.method === 'GET') {
      const wsId = rptRetentionMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const retentionPolicy = await getReportRetentionPolicyForWorkspace(wsId, env);
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, status, retention_policy, generated_at, created_at, report_key
             FROM workspace_reports
             WHERE workspace_id = ? AND deleted_at IS NULL`
          )
          .bind(wsId)
          .all();

        const nowMs = Date.now();
        const in30Ms = nowMs + 30 * 86_400_000;
        const in90Ms = nowMs + 90 * 86_400_000;
        let expiring30 = 0;
        let expiring90 = 0;

        for (const report of (rows.results || [])) {
          const effectiveAt = report.generated_at || report.created_at;
          const expiresAt = getReportExpiresAt(report.retention_policy || retentionPolicy, effectiveAt);
          if (!expiresAt) continue;
          const expiresMs = new Date(expiresAt).getTime();
          if (Number.isNaN(expiresMs) || expiresMs <= nowMs) continue;
          if (expiresMs <= in30Ms) expiring30 += 1;
          if (expiresMs <= in90Ms) expiring90 += 1;
        }

        const activeReports = rows.results || [];
        return json({
          total_reports: activeReports.length,
          storage_reports: activeReports.filter((r) => r.report_key && r.status === "completed").length,
          reports_expiring_30_days: expiring30,
          reports_expiring_90_days: expiring90,
          retention_policy: retentionPolicy,
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/reports ──────────────────────────────────────
    // List archived reports for a workspace.
    // Query params: ?report_type=  ?status=
    const rptListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports$/);
    if (rptListMatch && request.method === 'GET') {
      const wsId         = rptListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      const typeFilter   = url.searchParams.get('report_type');
      const statusFilter = url.searchParams.get('status');
      try {
        const { limit, offset } = paginationParams(url, { defaultLimit: 100, maxLimit: 100 });
        let sql    = `SELECT id, workspace_id, report_type, report_period,
                             status, generated_at, created_at, metadata_json, retention_policy
                      FROM workspace_reports WHERE workspace_id = ? AND deleted_at IS NULL`;
        const params = [wsId];
        if (typeFilter)   { sql += ' AND report_type = ?'; params.push(typeFilter); }
        if (statusFilter) { sql += ' AND status = ?';      params.push(statusFilter); }
        sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        const { results } = await env.cybermeters_db.prepare(sql).bind(...params).all();
        const reports = results ?? [];
        return json({ reports, pagination: pageMeta({ items: reports, limit, offset }) });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── DELETE /api/workspaces/:id/reports/:reportId ─────────────────────────
    // Permanently deletes the archived PDF from R2 and soft-deletes the D1 row.
    const rptDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)$/);
    if (rptDeleteMatch && request.method === 'DELETE') {
      const wsId     = rptDeleteMatch[1];
      const reportId = rptDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "report:delete", env);
      if (!access) return json({ error: "Forbidden — admin role required to delete reports" }, 403);

      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT id, workspace_id, report_type, report_period, report_key, status,
                  retention_policy
           FROM workspace_reports
           WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(reportId, wsId).first();
        if (!row) return json({ error: 'Report not found' }, 404);

        await env.cybermeters_reports.delete(row.report_key);

        const deletedAt = new Date().toISOString();
        const del = await env.cybermeters_db.prepare(
          `UPDATE workspace_reports
           SET deleted_at = ?, deleted_by = ?
           WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(deletedAt, user.id, reportId, wsId).run();
        if (del.meta?.changes === 0) return json({ error: 'Report not found' }, 404);

        await createAuditEvent(env, {
          workspace_id: wsId,
          user_id:      user.id,
          event_type:   "report_deleted",
          entity_type:  "report",
          entity_id:    reportId,
          description:  `Executive report deleted (${row.report_type})`,
          metadata:     {
            report_id: reportId,
            workspace_id: wsId,
            user_id: user.id,
            report_type: row.report_type,
            report_period: row.report_period,
            report_key: row.report_key,
            retention_policy: row.retention_policy,
            deletion_reason: "user_deleted",
          },
        });

        return json({ success: true, deleted_id: reportId });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/reports/:reportId/download ────────────────────
    // Stream the PDF from R2.  Must be tested before the bare /:reportId route.
    const rptDownloadMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)\/download$/);
    if (rptDownloadMatch && request.method === 'GET') {
      const wsId     = rptDownloadMatch[1];
      const reportId = rptDownloadMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT report_key, report_type, report_period, status
           FROM workspace_reports WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(reportId, wsId).first();
        if (!row)                       return json({ error: 'Report not found' }, 404);
        if (row.status !== 'completed') return json({ error: `Report not ready: ${row.status}` }, 409);

        const obj = await env.cybermeters_reports.get(row.report_key);
        if (!obj) return json({ error: 'Report file missing from storage' }, 404);

        await createAuditEvent(env, {
          workspace_id: wsId,
          user_id:      user.id,
          event_type:   "report_downloaded",
          entity_type:  "report",
          entity_id:    reportId,
          description:  `Executive report downloaded (${row.report_type})`,
          metadata:     { report_id: reportId, report_type: row.report_type, report_period: row.report_period },
        });

        const slug     = `${row.report_type}-${row.report_period ?? reportId}`;
        const filename = `cybermeters-report-${slug}.pdf`;
        return new Response(obj.body, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type':        'application/pdf',
            'Content-Disposition': `attachment; filename="${filename}"`,
          },
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/workspaces/:id/reports/:reportId ─────────────────────────────
    // Fetch metadata for a single report.
    const rptGetMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)$/);
    if (rptGetMatch && request.method === 'GET') {
      const wsId     = rptGetMatch[1];
      const reportId = rptGetMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT id, workspace_id, report_type, report_period,
                  status, generated_at, created_at, metadata_json, retention_policy
           FROM workspace_reports WHERE id = ? AND workspace_id = ? AND deleted_at IS NULL`
        ).bind(reportId, wsId).first();
        if (!row) return json({ error: 'Report not found' }, 404);
        return json({ report: row });
      } catch (err) {
        return serverError("api", err);
      }
	    }
	
	    // ── Executive Report Scheduling v1 ──────────────────────────────────
	    const reportScheduleRunsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-schedule-runs$/);
	    if (reportScheduleRunsMatch && request.method === "GET") {
	      const wsId = reportScheduleRunsMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const { results } = await env.cybermeters_db
	          .prepare(
	            `SELECT id, schedule_id, workspace_id, started_at, completed_at,
	                    status, report_id, error_message, created_at
	             FROM report_schedule_runs
	             WHERE workspace_id = ?
	             ORDER BY created_at DESC
	             LIMIT 100`
	          )
	          .bind(wsId)
	          .all();
	        return json({ runs: results || [] });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const reportScheduleListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-schedules$/);
	    if (reportScheduleListMatch && request.method === "GET") {
	      const wsId = reportScheduleListMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
	      if (!access) return json({ error: "Forbidden" }, 403);
	      try {
	        const { results } = await env.cybermeters_db
	          .prepare(
	            `SELECT id, workspace_id, created_by, frequency, enabled, email_recipients,
	                    last_run_at, next_run_at, created_at, updated_at
		             FROM report_schedules
		             WHERE workspace_id = ?
		             ORDER BY created_at DESC
		             LIMIT 100`
	          )
	          .bind(wsId)
	          .all();
	        const schedules = (results || []).map((row) => ({
	          ...row,
	          enabled: row.enabled === 1,
	          email_recipients: (() => { try { return JSON.parse(row.email_recipients || "[]"); } catch { return []; } })(),
	        }));
	        return json({ schedules });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    if (reportScheduleListMatch && request.method === "POST") {
	      const wsId = reportScheduleListMatch[1];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
	      try {
	        let body = {};
	        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
	        const frequency = normalizeReportScheduleFrequency(body.frequency);
	        if (!frequency) return json({ error: "Invalid frequency. Use weekly or monthly." }, 400);
	        const recipients = normalizeReportScheduleRecipients(body.email_recipients);
	        if (!recipients) return json({ error: "email_recipients must contain 1-20 valid email addresses." }, 400);
	        const now = new Date().toISOString();
	        const scheduleId = createId("rs");
	        const nextRunAt = calculateNextRun(frequency, now);
	        await env.cybermeters_db
	          .prepare(
	            `INSERT INTO report_schedules
	               (id, workspace_id, created_by, frequency, enabled, email_recipients,
	                next_run_at, created_at, updated_at)
	             VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)`
	          )
	          .bind(scheduleId, wsId, user.id, frequency, JSON.stringify(recipients), nextRunAt, now, now)
	          .run();
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "report_schedule_created",
	          entity_type: "report_schedule",
	          entity_id: scheduleId,
	          description: `Executive report schedule created (${frequency})`,
	          metadata: { frequency, recipient_count: recipients.length, next_run_at: nextRunAt },
	        });
	        return json({
	          schedule: { id: scheduleId, workspace_id: wsId, created_by: user.id, frequency, enabled: true, email_recipients: recipients, last_run_at: null, next_run_at: nextRunAt, created_at: now, updated_at: now },
	        }, 201);
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    const reportScheduleItemMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report-schedules\/([^/]+)$/);
	    if (reportScheduleItemMatch && request.method === "PUT") {
	      const wsId = reportScheduleItemMatch[1];
	      const scheduleId = reportScheduleItemMatch[2];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
	      try {
	        const existing = await env.cybermeters_db
	          .prepare("SELECT id FROM report_schedules WHERE id = ? AND workspace_id = ? LIMIT 1")
	          .bind(scheduleId, wsId)
	          .first();
	        if (!existing) return json({ error: "Schedule not found" }, 404);
	        let body = {};
	        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
	        const frequency = normalizeReportScheduleFrequency(body.frequency);
	        if (!frequency) return json({ error: "Invalid frequency. Use weekly or monthly." }, 400);
	        const recipients = normalizeReportScheduleRecipients(body.email_recipients);
	        if (!recipients) return json({ error: "email_recipients must contain 1-20 valid email addresses." }, 400);
	        const enabled = body.enabled === false ? 0 : 1;
	        const now = new Date().toISOString();
	        const nextRunAt = calculateNextRun(frequency, now);
	        await env.cybermeters_db
	          .prepare(
	            `UPDATE report_schedules
	             SET frequency = ?, enabled = ?, email_recipients = ?, next_run_at = ?, updated_at = ?
	             WHERE id = ? AND workspace_id = ?`
	          )
	          .bind(frequency, enabled, JSON.stringify(recipients), nextRunAt, now, scheduleId, wsId)
	          .run();
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "report_schedule_updated",
	          entity_type: "report_schedule",
	          entity_id: scheduleId,
	          description: `Executive report schedule updated (${frequency})`,
	          metadata: { frequency, enabled: enabled === 1, recipient_count: recipients.length, next_run_at: nextRunAt },
	        });
	        return json({ updated: true, schedule: { id: scheduleId, workspace_id: wsId, frequency, enabled: enabled === 1, email_recipients: recipients, next_run_at: nextRunAt, updated_at: now } });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    if (reportScheduleItemMatch && request.method === "DELETE") {
	      const wsId = reportScheduleItemMatch[1];
	      const scheduleId = reportScheduleItemMatch[2];
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
	      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
	      try {
	        const now = new Date().toISOString();
	        const result = await env.cybermeters_db
	          .prepare("UPDATE report_schedules SET enabled = 0, updated_at = ? WHERE id = ? AND workspace_id = ?")
	          .bind(now, scheduleId, wsId)
	          .run();
	        if ((result.meta?.changes ?? 0) === 0) return json({ error: "Schedule not found" }, 404);
	        await createAuditEvent(env, {
	          workspace_id: wsId,
	          user_id: user.id,
	          event_type: "report_schedule_deleted",
	          entity_type: "report_schedule",
	          entity_id: scheduleId,
	          description: "Executive report schedule disabled",
	          metadata: { schedule_id: scheduleId },
	        });
	        return json({ deleted: true, enabled: false });
	      } catch (err) {
	        return serverError("api", err);
	      }
	    }

	    // ── GET /api/workspaces/:id/scheduled-reports ────────────────────────────
	    // List all scheduled report configs for a workspace.
	    const srListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scheduled-reports$/);
    if (srListMatch && request.method === 'GET') {
      const wsId = srListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const { results } = await env.cybermeters_db
          .prepare(
            `SELECT id, workspace_id, report_type, frequency, enabled, last_run_at, next_run_at, created_at
             FROM scheduled_reports
             WHERE workspace_id = ?
             ORDER BY created_at DESC`
          )
          .bind(wsId)
          .all();
        return json({ scheduled_reports: results ?? [] });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── POST /api/workspaces/:id/scheduled-reports ────────────────────────────
    // Create a new scheduled report. Body: { report_type, frequency }
    // Frequencies: weekly | monthly | quarterly
    if (srListMatch && request.method === 'POST') {
      const wsId = srListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* optional */ }

        const VALID_TYPES = ['weekly_executive', 'monthly_executive', 'quarterly_executive', 'manual'];
        const VALID_FREQS = ['weekly', 'monthly', 'quarterly'];
        const report_type = VALID_TYPES.includes(body.report_type) ? body.report_type : 'monthly_executive';
        const frequency   = VALID_FREQS.includes(body.frequency)   ? body.frequency   : 'monthly';

        // Prevent duplicate active schedules for same type+frequency
        const existing = await env.cybermeters_db
          .prepare(
            `SELECT id FROM scheduled_reports
             WHERE workspace_id = ? AND report_type = ? AND frequency = ? AND enabled = 1 LIMIT 1`
          )
          .bind(wsId, report_type, frequency)
          .first();
        if (existing) return json({ error: "A schedule for this report type and frequency already exists" }, 409);

        // Entitlement: scheduled report limit per workspace
        const scheduleBillingUserId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const srPlan = await getEffectivePlan(scheduleBillingUserId, env);
        const srUsage  = await getEntitlementUsage(user, env, wsId);
        const srLimits = getPlanLimits(srPlan);
        if (srUsage.scheduled_reports_in_workspace >= srLimits.scheduled_reports_per_workspace) {
          return json(planLimitExceeded("scheduled_reports", srLimits.scheduled_reports_per_workspace, srUsage.scheduled_reports_in_workspace), 403);
        }

        const srId      = createId("sr");
        const nextRunAt = computeScheduledReportNextRunAt(frequency);
        const now       = new Date().toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO scheduled_reports (id, workspace_id, report_type, frequency, enabled, next_run_at, created_at)
             VALUES (?, ?, ?, ?, 1, ?, ?)`
          )
          .bind(srId, wsId, report_type, frequency, nextRunAt, now)
          .run();

        // Audit
        try {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_created",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  `Scheduled report created: ${report_type} (${frequency})`,
            metadata:     { scheduled_report_id: srId, report_type, frequency },
          });
        } catch { /* non-fatal */ }

        return json({
          scheduled_report: { id: srId, workspace_id: wsId, report_type, frequency, enabled: 1, next_run_at: nextRunAt, created_at: now }
        }, 201);
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── DELETE /api/workspaces/:id/scheduled-reports/:srId ───────────────────
    const srDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scheduled-reports\/([^/]+)$/);
    if (srDeleteMatch && request.method === 'DELETE') {
      const wsId = srDeleteMatch[1];
      const srId = srDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id FROM scheduled_reports WHERE id = ? AND workspace_id = ? LIMIT 1")
          .bind(srId, wsId)
          .first();
        if (!row) return json({ error: "Schedule not found" }, 404);

        await env.cybermeters_db
          .prepare("DELETE FROM scheduled_reports WHERE id = ?")
          .bind(srId)
          .run();

        try {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_deleted",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  "Scheduled report deleted",
            metadata:     { scheduled_report_id: srId },
          });
        } catch { /* non-fatal */ }

        return json({ deleted: true });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── PATCH /api/workspaces/:id/scheduled-reports/:srId ────────────────────
    // Toggle enabled. Body: { enabled: true|false }
    if (srDeleteMatch && request.method === 'PATCH') {
      const wsId = srDeleteMatch[1];
      const srId = srDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* optional */ }
        const enabled = body.enabled === false ? 0 : 1;
        const update = await env.cybermeters_db
          .prepare("UPDATE scheduled_reports SET enabled = ? WHERE id = ? AND workspace_id = ?")
          .bind(enabled, srId, wsId)
          .run();
        if ((update.meta?.changes ?? 0) > 0) {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_updated",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  `Scheduled report ${enabled ? "enabled" : "disabled"}`,
            metadata:     { scheduled_report_id: srId, enabled: enabled === 1 },
          });
        }
        return json({ updated: true, enabled: enabled === 1 });
      } catch (err) {
        return serverError("api", err);
      }
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
