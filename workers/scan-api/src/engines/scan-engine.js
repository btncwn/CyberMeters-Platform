// ── Scan pipeline orchestrator ──
// The main scan engine (runs via ctx.waitUntil): sequences every scan/analysis/persistence
// module through all phases, computes the score + report, and persists results + fires alerts.
// Plus the scan-budget/quality helpers, CA-concentration, admin-surface event insertion, and
// vendor inventory/relationship persistence. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). buildCanonicalUrlProfile is a nested function inside runScanEngine.
import { customerSafeFailure } from "../lib/errors.js";
import { createAuditEvent, createNotificationsForDomain } from "../lib/events.js";
import { json, sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { createId } from "../lib/util.js";
import { processAlertsForWorkspace } from "./alerts.js";
import { sendAssetChangeAlert } from "./asset-alert-delivery.js";
import { annotateExposureInfrastructure, deduplicateExposureAssets, runAdminSurfaceModule, runExposureModule, runRemediationModule, runRiskModule } from "./asset-intel.js";
import { upsertAssetInventory } from "./asset-inventory.js";
import { upsertBrandAssets, upsertIdentityAssets } from "./asset-persistence.js";
import { runTyposquatModule } from "./brand-typosquat.js";
import { computeBusinessRiskScore, expandFindingIds } from "./business-risk.js";
import { buildCaConcentrationAnalytics } from "./cert-analysis.js";
import { insertCertificateEvents, upsertCertificateObservation } from "./cert-events.js";
import { runCertificateIntelligenceModule } from "./cert-intel.js";
import { runCloudStorageModule } from "./cloud-storage-scan.js";
import { runSaasExposureModule, runThirdPartyDiscoveryModule } from "./discovery-scan.js";
import { buildDnsOperationalResilience } from "./dns-resilience.js";
import { runDnsModule } from "./dns-scan.js";
import { runDomainSecurityEnrichmentModule } from "./domain-enrichment.js";
import { buildEmailRemediationActions, buildEmailTransportDetails } from "./email-analysis.js";
import { runEmailIntelModule } from "./email-intel.js";
import { runEmailModule } from "./email-scan.js";
import { isActionableFinding, normalizeFindingSchema } from "./findings.js";
import { runHeadersModule } from "./headers-scan.js";
import { runHistoricalModule } from "./historical-scan.js";
import { runIdentityDiscoveryModule } from "./identity-scan.js";
import { recordPostureEvents } from "./posture-events.js";
import { computeScore, isEmailApplicable } from "./scoring.js";
import { runSslModule } from "./ssl-scan.js";
import { BRUTEFORCE_MAX_NAMES, filterWildcardBruteforceResults, runBruteforceModule, runSubdomainsModule } from "./subdomains-scan.js";
import { computeSupplyChainIntelligence, upsertSupplyChainScore } from "./supply-chain.js";
import { runTakeoverModule } from "./takeover-scan.js";
import { runTechModule } from "./tech-scan.js";
import { runVendorRelationshipModule } from "./vendor-relationship.js";
import { recomputeVendorRiskScoresForDomain } from "./vendor-risk.js";
import { detectVendorsFromModules } from "./vendor-signatures.js";
import { runCveModule, runKevModule } from "./vuln-intel.js";
import { runWhoisModule } from "./whois-scan.js";

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

export function buildScanQuality(modules = {}) {
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

export async function runScanEngine(scanId, domainId, workspaceId, domain, env) {
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

    // Phase 8a.1: Posture Timeline Events — cross-scan email-auth and exposed
    // service diffs. Uses previous completed scan report from R2 as baseline.
    try {
      await recordPostureEvents(scanId, domainId, domain, modules, env);
    } catch { /* non-fatal — posture events catch up on next scan */ }

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

export async function insertAdminSurfaceEvents(scanId, domainId, adminModule, env) {
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

export async function upsertVendorRelationships(domainId, relModule, env) {
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
