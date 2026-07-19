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
import { redactedJson } from "../lib/redact.js";
import { processAlertsForWorkspace } from "./alerts.js";
import { createManagedAsmCasesForScan, verifyManagedAsmCasesForScan } from "./asm-cases.js";
import { sendAssetChangeAlert } from "./asset-alert-delivery.js";
import { annotateExposureInfrastructure, deduplicateExposureAssets, runAdminSurfaceModule, runExposureModule, runRemediationModule, runRiskModule } from "./asset-intel.js";
import { buildDseFindings } from "./dse-findings.js";
import { upsertAssetInventory } from "./asset-inventory.js";
import { upsertBrandAssets, upsertIdentityAssets } from "./asset-persistence.js";
import { runTyposquatModule } from "./brand-typosquat.js";
import { computeAndPersistWorkspaceBrs, computeBusinessRiskScore, expandFindingIds } from "./business-risk.js";
import { getCyberEssentialsSnapshot } from "./ce-readiness.js";
import { buildCaConcentrationAnalytics } from "./cert-analysis.js";
import { persistCyberMotDomainStates } from "./cyber-mot-state-history.js";
import { persistDomainMaturity } from "./domain-maturity.js";
import { buildScanReportSnapshot } from "./report-snapshot.js";
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
import { buildAssetTimelineTrustMetadata, loadTimelineComparisonContext } from "./timeline-trust.js";
import { runReservedScan } from "./reserved-scan.js";
import { createModuleTelemetry, createScanDeadline, markDeadlineDeferred, MODULE_SUBREQUEST_COST, raceModuleDeadline, resolveScanCapacity, skippedModuleResult } from "./scan-budget.js";
import { computeScore, isEmailApplicable } from "./scoring.js";
import { runSslModule } from "./ssl-scan.js";
import { BRUTEFORCE_MAX_NAMES, filterWildcardBruteforceResults, runBruteforceModule, runSubdomainsModule } from "./subdomains-scan.js";
import { computeSupplyChainIntelligence, upsertSupplyChainScore } from "./supply-chain.js";
import { correlateShadowItInventory } from "./shadow-it-inventory.js";
import { correlateCertificateLifecycle } from "./certificate-lifecycle.js";
import { correlateIdentityExposure } from "./identity-lifecycle.js";
import { evaluateWebsiteSecurityForScan } from "./website-security-lifecycle.js";
import { evaluateCyberEssentialsLifecycle } from "./ce-lifecycle.js";
import { correlateRelatedChanges } from "./related-changes.js";
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

  // Trust: a module that self-reports incomplete evidence (e.g. exposure probes
  // starved by the Worker subrequest budget) did not actually execute. Treat it as
  // incomplete — list it as skipped and force scan_quality "partial" — so absence of
  // findings is never presented as a clean result and downstream verification /
  // managed-case resolution defers. This does not change module order/estimator.
  const incompleteModules = Object.entries(modules)
    .filter(([, value]) => value?.incomplete === true)
    .map(([name]) => name);
  for (const name of incompleteModules) {
    if (!modulesSkipped.includes(name)) modulesSkipped.push(name);
    warnings.push(`Module incomplete: ${name}`);
  }

  // Reserved mode: a module explicitly skipped because exposure consumed its reserved
  // subrequest budget ({skipped:true, skip_reason:"subrequest_budget"}) is honest
  // absence, never a clean result. List it as skipped + warn; a skipped CORE module
  // (dns/ssl/headers/email) degrades the scan to "partial". Legacy never sets skipped.
  const budgetSkippedModules = Object.entries(modules)
    .filter(([, value]) => value?.skipped === true)
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

  const status = (coreIncomplete.length > 0 || incompleteModules.length > 0 || coreBudgetSkipped.length > 0)
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
  return { state: "open", status: null, at: null, r2Written: false, d1Written: false, score: null, rating: null, quality: null };
}

export async function finalizeScanResult(latch, { scanId, report, score = null, rating = null, status, env }) {
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
  }
  const effStatus  = latch.status;
  const effScore   = latch.score;
  const effRating  = latch.rating;
  const effQuality = latch.quality;

  const errors = {};
  // Terminal R2 report — skipped when the completed report is already durable
  // (guardCompleted) so a failed report can never overwrite it.
  if (!latch.r2Written && !guardCompleted) {
    try {
      await env.cybermeters_reports.put(
        `reports/${scanId}.json`,
        JSON.stringify(report, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );
      latch.r2Written = true;
    } catch (e) { errors.r2 = e?.message || String(e); }
  }
  // Terminal D1 status — a 'completed' status is written ONLY once its R2 report is
  // durable (never claim completed in D1 while R2 still holds the running placeholder;
  // the reconciler trusts R2). A 'failed' terminal is written regardless, so a scan
  // whose report could not be persisted still ends 'failed', never silently 'running'.
  if (!latch.d1Written && (latch.r2Written || effStatus === "failed")) {
    try {
      await env.cybermeters_db
        .prepare(`UPDATE scans SET status = ?, score = ?, rating = ?, scan_quality = ? WHERE id = ?`)
        .bind(effStatus, effScore, effRating, effQuality, scanId)
        .run();
      latch.d1Written = true;
    } catch (e) { errors.d1 = e?.message || String(e); }
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

// The network/enrichment modules we expect a telemetry row for. Backfilled at
// finalization from the modules object for any not captured by the live wrapper
// (reserved-mode results, deferred phases) so both scan modes get full coverage.
const TELEMETRY_TRACKED_MODULES = Object.freeze([
  "dns", "ssl", "headers", "email_security", "subdomains", "technology_detection",
  "whois_intelligence", "dns_bruteforce", "subdomain_takeover", "asset_exposure",
  "cve_intelligence", "known_exploited_vulnerabilities", "email_security_intelligence",
  "cloud_storage_discovery",
]);

export async function runScanEngine(scanId, domainId, workspaceId, domain, env, opts = {}) {
  const startedAt = new Date().toISOString();
  // Injectable clock (tests drive it deterministically); production uses Date.now.
  const now = typeof opts.now === "function" ? opts.now : Date.now;
  // Wall-clock budget below the ~30s waitUntil-cancellation cliff. Expensive network
  // phases refuse to launch once spent, reserving headroom to finalize honestly.
  const deadline = createScanDeadline(env, now);
  // Finalize-once latch shared by the success and failure paths.
  const latch = createFinalizeLatch();
  // Per-module telemetry collector (persisted at finalization; non-fatal).
  const telemetry = createModuleTelemetry(now);

  try {
    // Mark scan as running in D1
    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'running' WHERE id = ?`)
      .bind(scanId)
      .run();

    // Capacity mode (default "legacy" — the legacy branch below is byte-for-byte the
    // prior behaviour). "reserved" runs the separated exposure-first flow.
    const capacity = resolveScanCapacity(env);
    const reservedMode = capacity.mode === "reserved";

    // Network module results — set by whichever path runs; both produce the same shape
    // so the modules object and everything downstream are identical.
    let dnsResult, sslResult, headersResult, emailResult, subdomainsResult,
        techResult, whoisResult, bruteforceResult, takeoverResult, assetExposureResult;
    let criticalPrefixResult = null;
    let reservedBudget = null;

    if (reservedMode) {
      // ── Reserved path (isolated in reserved-scan.js): customer-critical ASSET
      // EXPOSURE runs FIRST within a live-metered budget; the remaining modules run
      // only if the runtime budget permits and are otherwise SKIPPED honestly. Never
      // starves exposure. admin_surface is derived downstream (zero network). ──
      const reserved = await runReservedScan(domain, { capacity });
      const m = reserved.modules;
      dnsResult = m.dns; sslResult = m.ssl; headersResult = m.headers; emailResult = m.email_security;
      subdomainsResult = m.subdomains; techResult = m.technology_detection; whoisResult = m.whois_intelligence;
      bruteforceResult = m.dns_bruteforce; takeoverResult = m.subdomain_takeover;
      assetExposureResult = m.asset_exposure; criticalPrefixResult = m.critical_prefix_discovery;
      reservedBudget = reserved.budget;
    } else {
      // ── Legacy path (unchanged): 8 core modules in parallel, then takeover, then
      // asset exposure over the merged (CT + brute-force) subdomain list. ──
      const [dnsSettled, sslSettled, headersSettled, emailSettled, subdomainsSettled, techSettled, whoisSettled, bruteforceSettled] =
        await Promise.allSettled([
          telemetry.run("dns",                  () => runDnsModule(domain)),
          telemetry.run("ssl",                  () => runSslModule(domain)),
          telemetry.run("headers",              () => runHeadersModule(domain)),
          telemetry.run("email_security",       () => runEmailModule(domain)),
          telemetry.run("subdomains",           () => runSubdomainsModule(domain)),
          telemetry.run("technology_detection", () => runTechModule(domain)),
          telemetry.run("whois_intelligence",   () => runWhoisModule(domain)),
          telemetry.run("dns_bruteforce",       () => runBruteforceModule(domain)),
        ]);

      dnsResult = dnsSettled.status === "fulfilled" ? dnsSettled.value : { error: customerSafeFailure("scan/dns", dnsSettled.reason, "DNS module failed") };
      sslResult = sslSettled.status === "fulfilled" ? sslSettled.value : { error: customerSafeFailure("scan/ssl", sslSettled.reason, "SSL module failed") };
      headersResult = headersSettled.status === "fulfilled" ? headersSettled.value : { error: customerSafeFailure("scan/headers", headersSettled.reason, "Headers module failed") };
      emailResult = emailSettled.status === "fulfilled" ? emailSettled.value : { error: customerSafeFailure("scan/email", emailSettled.reason, "Email module failed") };
      subdomainsResult = subdomainsSettled.status === "fulfilled"
        ? subdomainsSettled.value
        : { count: 0, items: [], sensitive: [], source: "certificate_transparency_multi_source",
            sources: { crt_sh: { count: 0, error: "module rejected" }, certspotter: { count: 0, error: "module rejected" } },
            wildcard_dns: false, wildcard_dns_addresses: [], wildcard_test_host: null, wildcard_warning: null,
            error: customerSafeFailure("scan/subdomains", subdomainsSettled.reason, "Subdomain module failed") };
      techResult = techSettled.status === "fulfilled" ? techSettled.value : { error: customerSafeFailure("scan/technology", techSettled.reason, "Technology module failed") };
      whoisResult = whoisSettled.status === "fulfilled" ? whoisSettled.value : { error: customerSafeFailure("scan/whois", whoisSettled.reason, "WHOIS module failed") };

      const rawBruteforceResult = bruteforceSettled.status === "fulfilled"
        ? bruteforceSettled.value
        : { checked: 0, found: 0, items: [], source: "dns_bruteforce",
            error: customerSafeFailure("scan/dns-bruteforce", bruteforceSettled.reason, "Brute-force module failed") };
      bruteforceResult = filterWildcardBruteforceResults(rawBruteforceResult, subdomainsResult.wildcard_dns_addresses);

      const ctHostnames = new Set(subdomainsResult.items);
      const bruteNewItems = (bruteforceResult.items || [])
        .filter((item) => item.wildcard_match !== true)
        .map((i) => i.hostname)
        .filter((h) => h && !ctHostnames.has(h));
      const mergedSubdomainItems = [...subdomainsResult.items, ...bruteNewItems];

      // Takeover: canRun() gates the launch; raceModuleDeadline BOUNDS the run so an
      // overrun cannot cross the ~30s cliff. On the bound it defers honestly.
      if (deadline.canRun(4_000)) {
        try {
          takeoverResult = await raceModuleDeadline(
            deadline,
            () => runTakeoverModule(domain, mergedSubdomainItems),
            () => markDeadlineDeferred({ checked: 0, potential_risks: 0, risks: [], cname_observations: [], source: "subdomain_cname_fingerprint" }),
          );
        } catch (err) {
          takeoverResult = { checked: 0, potential_risks: 0, risks: [], source: "subdomain_cname_fingerprint", error: customerSafeFailure("scan/takeover", err, "Takeover module failed") };
        }
      } else {
        takeoverResult = markDeadlineDeferred({ checked: 0, potential_risks: 0, risks: [], cname_observations: [], source: "subdomain_cname_fingerprint" });
      }
      telemetry.record("subdomain_takeover", { outcome: telemetry.outcomeOf(takeoverResult), timeout: takeoverResult?.outcome === "deadline_exceeded" });

      // Asset exposure (admin-surface signal): customer-critical, so it runs before the
      // cheaper enrichment phases — but its probes time out at 8-10s each, exceeding the
      // 6s launch estimate, so the run is hard-bounded to the remaining budget. On the
      // bound it defers honestly rather than orphaning the scan.
      if (deadline.canRun(6_000)) {
        try {
          assetExposureResult = await raceModuleDeadline(
            deadline,
            () => runExposureModule(domain, mergedSubdomainItems),
            () => markDeadlineDeferred({ checked: 0, reachable: 0, assets: [], source: "http_probe" }),
          );
          if (!assetExposureResult.incomplete) {
            assetExposureResult = annotateExposureInfrastructure(assetExposureResult, takeoverResult.cname_observations);
            assetExposureResult = deduplicateExposureAssets(assetExposureResult, domain);
          }
        } catch (err) {
          // A thrown exposure module never assessed the HTTP attack surface. Mark it
          // incomplete (not just error) so buildScanQuality goes partial and the
          // completion gate defers admin-surface verification — a failed probe must
          // never read as a completed clean assessment. asset_exposure is non-core, so
          // without this flag the scan would still certify "complete".
          assetExposureResult = { checked: 0, reachable: 0, assets: [], source: "http_probe", incomplete: true, incomplete_reason: "exposure_probe_failed", error: customerSafeFailure("scan/asset-exposure", err, "Asset exposure module failed") };
        }
      } else {
        assetExposureResult = markDeadlineDeferred({ checked: 0, reachable: 0, assets: [], source: "http_probe" });
      }
      telemetry.record("asset_exposure", { outcome: telemetry.outcomeOf(assetExposureResult), timeout: assetExposureResult?.outcome === "deadline_exceeded" });
    }

    const modules = {
      dns:                       dnsResult,
      ssl:                       sslResult,
      headers:                   headersResult,
      email_security:            emailResult,
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
    // Heartbeat: discovery + exposure done. An orphan cancelled after this point
    // died in scoring/enrichment/finalization, not discovery.
    await heartbeatScan(env, scanId, "discovery_complete", telemetry.rows.filter((r) => r.outcome === "ok").length);

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
    // In reserved mode these are budget-permitting enrichment: skipped honestly (no fetch
    // attempted) when the exposure-first budget is already spent.
    const phase5Cost = MODULE_SUBREQUEST_COST.cve + MODULE_SUBREQUEST_COST.kev + 4;
    // Deadline first: if the enrichment trio can't finish in budget, defer it honestly
    // (partial scan) rather than risk the whole invocation being cancelled mid-write.
    const phase5DeadlineBlocked = !deadline.canRun(8_000);
    await heartbeatScan(env, scanId, "phase5_intelligence", telemetry.rows.filter((r) => r.outcome === "ok").length);
    if (phase5DeadlineBlocked) {
      modules.cve_intelligence = markDeadlineDeferred({ technologies_checked: [], results: {}, total_cves: 0, critical_count: 0, high_count: 0, source: "nvd_api" });
      modules.known_exploited_vulnerabilities = markDeadlineDeferred({ matches: [], checked: 0, matched: 0, source: "cisa_kev" });
      modules.email_security_intelligence = markDeadlineDeferred({ source: "email_intelligence" });
      telemetry.record("cve_intelligence", { outcome: "deadline_exceeded" });
      telemetry.record("known_exploited_vulnerabilities", { outcome: "deadline_exceeded" });
      telemetry.record("email_security_intelligence", { outcome: "deadline_exceeded" });
    } else if (reservedMode && reservedBudget && reservedBudget.wouldExceed(phase5Cost)) {
      modules.cve_intelligence = skippedModuleResult("cve", { technologies_checked: [], results: {}, total_cves: 0, critical_count: 0, high_count: 0 });
      modules.known_exploited_vulnerabilities = skippedModuleResult("kev", { matches: [], checked: 0, matched: 0 });
      modules.email_security_intelligence = skippedModuleResult("email_intelligence");
    } else {
    if (reservedMode && reservedBudget) reservedBudget.spend("phase5", phase5Cost);
    // Bound the enrichment trio to the remaining budget — even launched, it cannot
    // overrun toward the ~30s cliff. On the bound, all three defer honestly. (No
    // telemetry.run wrapper here: an abandoned late promise must not push a second
    // row; a single coarse row per module is recorded from the resolved outcome.)
    const PHASE5_DEADLINE = "__phase5_deadline__";
    const settled = await raceModuleDeadline(
      deadline,
      () => Promise.allSettled([
        runCveModule(modules.technology_detection),
        runKevModule(modules.technology_detection, env),
        runEmailIntelModule(domain, modules.email_security, modules.dns),
      ]),
      () => PHASE5_DEADLINE,
    );
    if (settled === PHASE5_DEADLINE) {
      modules.cve_intelligence = markDeadlineDeferred({ technologies_checked: [], results: {}, total_cves: 0, critical_count: 0, high_count: 0, source: "nvd_api" });
      modules.known_exploited_vulnerabilities = markDeadlineDeferred({ matches: [], checked: 0, matched: 0, source: "cisa_kev" });
      modules.email_security_intelligence = markDeadlineDeferred({ source: "email_intelligence" });
    } else {
      const [cveSettled, kevSettled, emailIntelSettled] = settled;
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
    }
    telemetry.record("cve_intelligence", { outcome: telemetry.outcomeOf(modules.cve_intelligence), timeout: modules.cve_intelligence?.outcome === "deadline_exceeded" });
    telemetry.record("known_exploited_vulnerabilities", { outcome: telemetry.outcomeOf(modules.known_exploited_vulnerabilities), timeout: modules.known_exploited_vulnerabilities?.outcome === "deadline_exceeded" });
    telemetry.record("email_security_intelligence", { outcome: telemetry.outcomeOf(modules.email_security_intelligence), timeout: modules.email_security_intelligence?.outcome === "deadline_exceeded" });
    }
    if (!modules.email_security_intelligence.error && !modules.email_security_intelligence.skipped && emailApplicability.applicable) {
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
    // Reserved mode: cloud-storage validation is budget-permitting enrichment.
    if (!deadline.canRun(4_000)) {
      modules.cloud_storage_discovery = markDeadlineDeferred({ total: 0, checked: 0, findings: [] });
    } else if (reservedMode && reservedBudget && reservedBudget.wouldExceed(MODULE_SUBREQUEST_COST.cloud_storage)) {
      modules.cloud_storage_discovery = skippedModuleResult("cloud_storage", { total: 0, checked: 0, findings: [] });
    } else {
      if (reservedMode && reservedBudget) reservedBudget.spend("cloud_storage", MODULE_SUBREQUEST_COST.cloud_storage);
      // Bound the run so a slow validation cannot cross the cliff; defer honestly on the bound.
      modules.cloud_storage_discovery = await raceModuleDeadline(
        deadline,
        () => runCloudStorageModule(domain, modules),
        () => markDeadlineDeferred({ total: 0, checked: 0, findings: [] }),
      );
    }
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

    // Trend eligibility (partial-scan honesty): only a COMPLETE assessment is a
    // comparable trend point. A partial/degraded/unknown current scan must never
    // produce a score delta (improved/declined/+N), so suppress its own report's
    // score_change here — the single central gate feeding the report, scan-detail,
    // and the executive-report trend direction.
    if (modules.historical_changes) {
      const comparable = scanQuality.status === "complete";
      modules.historical_changes.comparable   = comparable;
      if (!comparable) modules.historical_changes.score_change = null;
    }

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
      timeline_trust:       buildAssetTimelineTrustMetadata(),
      modules,
    };

    // Backfill telemetry rows for tracked modules not captured by the live wrapper
    // (reserved-mode results, cloud-storage, deferred phases) so both scan modes get
    // full per-module coverage; derive a coarse outcome from the final module value.
    for (const name of TELEMETRY_TRACKED_MODULES) {
      if (!telemetry.has(name)) telemetry.record(name, { outcome: telemetry.outcomeOf(modules[name]) });
    }

    // Heartbeat: entering finalization. A cancellation after this is a finalize-time
    // failure (the reconciler is the backstop), not a mid-scan orphan.
    await heartbeatScan(env, scanId, "finalizing", telemetry.rows.filter((r) => r.outcome === "ok").length);

    // Finalize: write the completed report to R2 and flip the D1 status. report.status
    // stays "completed"; scan_quality.status carries "partial" when the deadline
    // deferred any module (honest partial finalization). finalizeScanResult never
    // throws and only reaches "finalized" when BOTH writes are durable.
    const finalized = await finalizeScanResult(latch, {
      scanId, report, score, rating: risk_level, status: "completed", env,
    });
    if (!finalized.finalized) {
      // A terminal write did not durably land. Do NOT silently continue with a
      // half-written state — throw into the failure path, which (downgrade-safe)
      // preserves a durable completed R2 report and retries the D1 status, or writes
      // a consistent 'failed' terminal if the report never persisted. Either way the
      // scan never remains 'running'.
      throw new Error(`scan finalization incomplete: ${JSON.stringify(finalized.errors || {})}`);
    }

    // Persist per-module telemetry (non-fatal; after the terminal status is written
    // so a telemetry failure can never leave the scan 'running').
    await persistModuleTelemetry(scanId, telemetry, env);

    // Shared by the 091 state persistence below AND the M5.c snapshot build
    // (Phase 8o): both must resolve the eight domains from the SAME Cyber
    // Essentials snapshot, or the snapshot could disagree with the persisted
    // per-domain state rows for the same scan.
    let ceSnap = null;

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
               (id, workspace_id, domain_id, scan_id, domain, score, rating, brs_score, scan_quality, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(createId("hscore"), workspaceId, domainId, scanId, domain, score, risk_level, brsScore, scanQuality?.status ?? null, completedAt)
          .run();
      } catch { /* non-fatal — scan completion remains source of truth */ }

      // Canonical workspace Business Risk (M5.e): computed + persisted here —
      // at scan cadence, never page-view cadence — so GET /business-risk is a
      // pure read that can never diverge from the persisted canonical value.
      // Non-fatal by the 091 doctrine.
      try {
        await computeAndPersistWorkspaceBrs(env, workspaceId);
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
        await persistCyberMotDomainStates(env, {
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
      await upsertAssetInventory(scanId, domainId, domain, modules, env, { currentReport: report });
    } catch { /* non-fatal — inventory update will catch up on next scan */ }

    // Phase 8a.0: Managed ASM cases — opens cases for new exposure findings,
    // verifies customer-completed fixes against the fresh scan, and reopens
    // resolved cases when the same finding returns. Reuses scan evidence only.
    try {
      await createManagedAsmCasesForScan(scanId, domainId, domain, normalizedFindings, recommendations, env);
      await verifyManagedAsmCasesForScan(scanId, domainId, domain, normalizedFindings, env, { modules, scanQuality });
    } catch { /* non-fatal — managed cases catch up on the next scan */ }

    // Phase 8a.1: Posture Timeline Events — cross-scan email-auth and exposed
    // service diffs. Uses previous completed scan report from R2 as baseline.
    try {
      await recordPostureEvents(scanId, domainId, domain, modules, env, { currentReport: report });
    } catch { /* non-fatal — posture events catch up on next scan */ }

    // Phase 8b: Admin Surface Events — one asset_event per detected service per workspace.
    // Runs after upsertAssetInventory so workspace_assets rows are already present,
    // allowing asset_id FK resolution.
    try {
      await insertAdminSurfaceEvents(scanId, domainId, modules.admin_surface_detection, env, { currentReport: report });
    } catch { /* non-fatal */ }

    // Phase 8c: Vendor Inventory Upsert — persists vendor_risk detections to D1.
    // Uses workspace lookup internally. Preserves first_seen; marks unseen vendors inactive.
    try {
      await upsertVendorInventory(domainId, modules.vendor_risk, env);
    } catch { /* non-fatal */ }

    // Phase 8d: Certificate Events — fires asset_events for sensitive CT hosts,
    // expiry warnings, and growth signals.
    try {
      await insertCertificateEvents(scanId, domainId, modules.certificate_intelligence, env, { currentReport: report });
    } catch { /* non-fatal */ }

    // Phase 8d.1: Certificate Timeline — persists cross-scan certificate
    // observations and emits alerts for new certs, SANs, and issuers.
    try {
      await upsertCertificateObservation(scanId, domainId, modules.certificate_intelligence, env, { currentReport: report });
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

    // Phase 8j: Shadow IT approved inventory — correlate the workspace's active
    // vendor observations (+ ephemeral SaaS portal URLs) into the canonical
    // externally-observed technology inventory. Soft-deleted workspaces are
    // skipped inside correlateShadowItInventory. Non-fatal.
    try {
      const siWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (siWsRows.results || [])) {
        await correlateShadowItInventory(env, workspace_id, { saasExposure: modules.saas_exposure });
      }
    } catch { /* non-fatal — inventory catches up on the next scan */ }

    // Phase 8k: Certificate Managed Lifecycle — correlate the raw certificate
    // observations (mig 031) into the canonical managed lifecycle record: pick
    // the current cert per host, detect replacement (old evidence preserved),
    // assess renewal readiness + coverage, and run the monitoring evaluator.
    // Soft-deleted workspaces are skipped inside correlateCertificateLifecycle.
    try {
      const clWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (clWsRows.results || [])) {
        await correlateCertificateLifecycle(env, workspace_id);
      }
    } catch { /* non-fatal — lifecycle catches up on the next scan */ }

    // Phase 8l: Identity Exposure Managed Workflow — correlate the raw
    // identity_assets (mig 030) into the canonical managed identity-exposure
    // record: one record per external identity surface, provider/endpoint change
    // detection (old evidence preserved), externally-observable risk + the
    // monitoring evaluator. Soft-deleted workspaces are skipped inside
    // correlateIdentityExposure. Non-fatal.
    try {
      const ieWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (ieWsRows.results || [])) {
        await correlateIdentityExposure(env, workspace_id);
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
      const wsWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (wsWsRows.results || [])) {
        await evaluateWebsiteSecurityForScan(env, {
          workspace_id, domain_id: domainId, domain, scan_id: scanId,
          findings: normalizedFindings, modules, scanQuality,
        });
      }
    } catch { /* non-fatal — lifecycle catches up on the next scan */ }

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
      const ceWsRows = await env.cybermeters_db
        .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
        .bind(domainId)
        .all();
      for (const { workspace_id } of (ceWsRows.results || [])) {
        await evaluateCyberEssentialsLifecycle(env, workspace_id, { scanId });
      }
    } catch { /* non-fatal — readiness catches up on the next scan */ }

    // Phase 8x: M6 Phase B1 Related Changes — deterministic same-entity/same-window
    // correlation over the change-event producers written by the phases above. Runs
    // AFTER the lifecycle/case phases (8a, 8k–8n) so it sees this scan's producer rows,
    // and BEFORE Phase 8o so its clusters are frozen into the snapshot. It reads only
    // existing producer rows (adapter, no table moves), correlates with the registered
    // deterministic rules, and persists clusters + evidence POINTERS (mig 098). No
    // automatic case or alert is created (design §8) — the rule decides, the customer
    // confirms. Runs only on a complete scan with a complete previous scan (the
    // posture-events evidence floor). Non-fatal.
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

    // Phase 8o: Canonical reporting snapshot (M5.c) — one completed Cyber MOT →
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
    // If a terminal state was already DURABLY finalized (completed or partial), a
    // later error — e.g. a post-completion persistence phase throwing — must NEVER
    // downgrade it. Refuse to touch it.
    if (latch.state === "finalized") return;

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
    };
    await finalizeScanResult(latch, {
      scanId, report: failedReport, score: 0, rating: "unknown", status: "failed", env,
    });

    // Clean outcome: durably finalized as completed (original or recovered) → no
    // failure audit needed. Otherwise emit an auditable event for the terminal state:
    //   • "failed"    — the scan genuinely failed (results could not be persisted);
    //   • "completed" but not durably finalized — a DEGRADED finalize: the completed
    //     R2 report is durable, D1 convergence is pending (the reconciler backstops).
    // Both are recorded so the outcome is never silent.
    if (latch.state === "finalized" && latch.status === "completed") return;
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
  }
}

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
