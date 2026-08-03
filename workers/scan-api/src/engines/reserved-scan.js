// ── Reserved-mode scan orchestration (Tier-1, SCAN_CAPACITY_MODE=reserved) ─────
// A separated flow that reserves the customer-critical DMARC core before the
// exposure envelope and before heavy DNS-posture / DKIM-sweep / CT /
// brute-force modules can consume the ~50-class Worker subrequest budget. The
// legacy path (default) does not import or execute any of this.
//
// Order:  minimal root/www DNS → RESERVED DMARC CORE → critical-prefix A
//         lookups → dedupe + prioritise → RESERVED ASSET EXPOSURE (SSRF-safe
//         prober, live-metered) → admin_surface (derived downstream, zero
//         network) → remaining modules only if budget permits.
//
// A module that does not fit is SKIPPED before issuing any fetch and reported honestly
// ({skipped:true, skip_reason:"subrequest_budget"}) — never a fake clean / zero result.
// Design: docs/SCAN-SUBREQUEST-CAPACITY-FIX-BRIEF.md (f226790).
import { customerSafeFailure } from "../lib/errors.js";
import { annotateExposureInfrastructure, deduplicateExposureAssets, runExposureModule } from "./asset-intel.js";
import { dnsResolveACached } from "./dns.js";
import { runDnsModule } from "./dns-scan.js";
import { runEmailModule } from "./email-scan.js";
import { runDmarcbisCore } from "./dmarcbis-production.js";
import { runHeadersModule } from "./headers-scan.js";
import { makeReservedProbeFetch } from "./reserved-probe.js";
import { createCertificateTransparencyCache } from "./ct-provider-cache.js";
import {
  CRITICAL_PREFIXES_MANDATORY, MODULE_SUBREQUEST_COST, SubrequestBudget,
  computeExposureCap, deferredCapacityAsset, makeDnsCache, skippedModuleResult,
} from "./scan-budget.js";
import { runSslModule } from "./ssl-scan.js";
import { filterWildcardBruteforceResults, runBruteforceModule, runSubdomainsModule } from "./subdomains-scan.js";
import { runTakeoverModule } from "./takeover-scan.js";
import { runTechModule } from "./tech-scan.js";
import { runWhoisModule } from "./whois-scan.js";

function hasAnswer(ans) { return !!ans && Array.isArray(ans.Answer) && ans.Answer.length > 0; }

const RESERVED_PLATFORM_ABORT_WORDING =
  "CyberMeters did not observe the provider result within the scan's global execution window.";

function combineConsumerSignals(...signals) {
  const active = signals.filter(Boolean);
  if (active.length === 0) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => {
    const source = active.find((candidate) => candidate.aborted);
    if (!controller.signal.aborted) controller.abort(source?.reason);
  };
  for (const signal of active) {
    if (signal.aborted) { abort(); break; }
    signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

export async function runReservedCtConsumer(domain, module, {
  ctCache,
  ctOverlap = null,
  signal = null,
  globalDeadlineProvenance = null,
  budgetMs,
  run,
  fallback,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (!ctCache || typeof run !== "function" || typeof fallback !== "function") {
    throw new TypeError("Reserved CT consumer requires cache, run and fallback");
  }
  const controller = new AbortController();
  const consumerSignal = combineConsumerSignals(signal, controller.signal);
  let released = false;
  const release = (cause) => {
    if (released) return;
    released = true;
    ctCache.releaseConsumer?.(domain, module, cause);
    if (module === "subdomains") {
      ctOverlap?.freeze?.({
        global_deadline: globalDeadlineProvenance?.() || null,
      });
    }
  };
  const boundaryValue = (cause) => {
    release(cause);
    if (!controller.signal.aborted) controller.abort(cause);
    return { boundary: true, value: fallback(cause) };
  };
  const work = Promise.resolve()
    .then(() => run(consumerSignal))
    .then((value) => ({ boundary: false, value }), (error) => ({ boundary: false, error }));
  let timer = null;
  let removeGlobalAbort = null;
  const boundary = new Promise((resolve) => {
    timer = setTimer(
      () => resolve(boundaryValue("module_budget_exhausted")),
      Math.max(1, Number(budgetMs) || 1),
    );
    const globalAbort = () => resolve(boundaryValue("scan_global_deadline"));
    if (signal?.aborted) globalAbort();
    else if (signal?.addEventListener) {
      signal.addEventListener("abort", globalAbort, { once: true });
      removeGlobalAbort = () => signal.removeEventListener?.("abort", globalAbort);
    }
  });
  const winner = await Promise.race([work, boundary]);
  if (timer != null) clearTimer(timer);
  removeGlobalAbort?.();
  if (!winner.boundary) release(winner.error ? "consumer_error" : "consumer_completed");
  if (winner.error) throw winner.error;
  return winner.value;
}

// ── Discovery + priority helpers (also unit-tested directly) ──────────────────
export async function runCriticalPrefixDiscovery(domain, cache, prefixes = CRITICAL_PREFIXES_MANDATORY) {
  const items = [];
  for (const prefix of prefixes) {
    const host = `${prefix}.${domain}`;
    const ans = await dnsResolveACached(host, cache);
    if (hasAnswer(ans)) items.push(host);
  }
  return { source: "critical_prefix_dns", checked: prefixes.length, found: items.length, items };
}

export function prioritiseExposureHosts(domain, { knownHosts = [], criticalHits = [], ctHosts = [], bruteHosts = [] } = {}) {
  const ordered = [];
  const seen = new Set();
  const add = (host, src) => {
    const key = String(host || "").toLowerCase();
    if (key && !seen.has(key)) { seen.add(key); ordered.push({ host, src }); }
  };
  add(domain, "root");
  add(`www.${domain}`, "www");
  for (const h of knownHosts) add(h, "known_asset");
  for (const h of criticalHits) add(h, "critical_prefix");
  for (const h of ctHosts) add(h, "ct");
  for (const h of bruteHosts) add(h, "brute");
  return ordered;
}

// Reserved exposure: probe up to the dynamic cap by priority; overflow → deferred_capacity.
export async function runReservedExposureModule(domain, orderedHosts, {
  cap,
  fetcher,
  cache = null,
  signal = null,
  dnsAccounting = null,
}) {
  const safeCap = Math.max(0, cap | 0);
  const toProbe = orderedHosts.slice(0, safeCap);
  const overflow = orderedHosts.slice(safeCap);

  const probed = await runExposureModule(domain, toProbe.map((h) => h.host), {
    fetcher,
    cache,
    signal,
    dnsAccounting,
  });
  const deferred = overflow.map((h) => deferredCapacityAsset(h.host, "projected_subrequest_budget"));
  const deferredObservations = overflow.map((row) => ({
    host: row.host,
    signal_states: {
      dns_resolution: { state: "not_assessed", reason: "projected_subrequest_budget" },
      http_https_service: { state: "not_assessed", reason: "projected_subrequest_budget" },
    },
    active_sources: ["dns_resolution", "http_https_service"],
    passive_sources: [],
  }));
  const assets = [...(probed.assets || []), ...deferred];
  const incompleteFromProbe = probed.incomplete === true;
  const incomplete = incompleteFromProbe || deferred.length > 0;

  return {
    ...probed,
    assets,
    removal_observations: [
      ...(probed.removal_observations || []),
      ...deferredObservations,
    ],
    checked: orderedHosts.length,
    reachable: assets.filter((a) => a.reachable === true).length,
    host_cap: safeCap,
    deferred_capacity_count: deferred.length,
    ...(incomplete ? {
      incomplete: true,
      incomplete_reason: incompleteFromProbe ? (probed.incomplete_reason || "subrequest_budget_exhausted") : "projected_subrequest_budget",
      notice: probed.notice || "Some external exposure checks could not complete. Results may be incomplete.",
    } : {}),
  };
}

// Gate a post-exposure module: run it only if its estimated cost fits the remaining
// budget; otherwise SKIP it before any fetch and report honestly.
async function gateModule(budget, name, run, skipExtra = {}) {
  const cost = MODULE_SUBREQUEST_COST[name] ?? 8;
  if (budget.wouldExceed(cost)) return skippedModuleResult(name, skipExtra);
  budget.spend(name, cost);
  try { return await run(); }
  catch (err) { return { error: customerSafeFailure(`scan/${name}`, err, `${name} module failed`) }; }
}

// ── Full reserved scan: produces the complete network-module set (real or skipped) ──
export async function runReservedScan(domain, {
  capacity,
  ctCache = null,
  ctOverlap = null,
  dnsCache: suppliedDnsCache = null,
  knownAssetHosts = [],
  signal = null,
  globalDeadlineProvenance = null,
  ctConsumerBudgets = null,
  now = Date.now,
} = {}) {
  const budget = new SubrequestBudget({ limit: capacity.limit, safetyMargin: capacity.safetyMargin });
  const dnsCache = suppliedDnsCache || makeDnsCache();
  const sharedCtCache = ctCache || createCertificateTransparencyCache({
    signal,
    globalDeadlineProvenance,
  });
  const reservedCtBudgets = {
    ssl: Math.max(1, Number(ctConsumerBudgets?.ssl) || 9_000),
    subdomains: Math.max(1, Number(ctConsumerBudgets?.subdomains) || 12_000),
  };

  // Stage 1: minimal root/www discovery (A only) — enough to know the domain resolves
  // and to seed the exposure list + the shared cache. ~2 calls.
  const rootA = await dnsResolveACached(domain, dnsCache);           budget.spend("discovery");
  await dnsResolveACached(`www.${domain}`, dnsCache);                budget.spend("discovery");
  const resolves = hasAnswer(rootA);

  // Stage 2: reserve and execute the guaranteed DMARC core BEFORE exposure.
  // Reservation is the conservative logical maximum; cache hits reduce physical
  // provider attempts but never increase exposure capacity optimistically.
  budget.spend("dmarc_core", MODULE_SUBREQUEST_COST.dmarc_core);
  const dmarcCore = await runDmarcbisCore(domain, {
    cache: dnsCache,
    signal,
    now,
  });

  // Stage 3: critical-prefix discovery (deterministic, CT-independent). 8 A lookups.
  const criticalPrefixResult = await runCriticalPrefixDiscovery(domain, dnsCache);
  budget.spend("critical_prefix", criticalPrefixResult.checked);

  // Stage 4: prioritise (root → www → critical). CT is NOT here — it is post-exposure.
  const ordered = prioritiseExposureHosts(domain, {
    knownHosts: knownAssetHosts,
    criticalHits: criticalPrefixResult.items,
  });

  // Stage 5: RESERVED EXPOSURE, live-metered (each real prober fetch decrements budget).
  const consumedBeforeExposure = budget.consumed;
  const cap = computeExposureCap({ limit: capacity.limit, safetyMargin: capacity.safetyMargin, consumed: consumedBeforeExposure, perHostCost: capacity.perHostCost });
  const fetcher = makeReservedProbeFetch({ cache: dnsCache, maxHops: capacity.maxProbeRedirectHops, onOutbound: () => budget.spend("exposure") });
  let assetExposureResult = await runReservedExposureModule(domain, ordered, {
    cap,
    fetcher,
    cache: dnsCache,
    signal,
    dnsAccounting: {
      signal,
      assertCanIssue: () => {
        if (budget.wouldExceed(1)) {
          throw new Error("Projected subrequest budget exhausted");
        }
      },
      recordAttempt: () => budget.spend("exposure"),
      recordCompleted: () => {},
      recordError: () => {},
    },
  });

  // Stage 6: remaining modules, budget-gated (customer-critical exposure already done).
  const dns                  = await gateModule(budget, "dns", () => runDnsModule(domain, { cache: dnsCache }), { resolves });
  const ssl                  = await gateModule(budget, "ssl", () => runReservedCtConsumer(domain, "ssl", {
    ctCache: sharedCtCache,
    signal,
    globalDeadlineProvenance,
    budgetMs: reservedCtBudgets.ssl,
    run: (consumerSignal) => runSslModule(domain, { ctCache: sharedCtCache, signal: consumerSignal }),
    fallback: (cause) => ({
      incomplete: true,
      incomplete_reason: cause,
      outcome: "deadline_exceeded",
      ct_sources: {
        crt_sh: { count: 0, error: cause === "scan_global_deadline" ? RESERVED_PLATFORM_ABORT_WORDING : "module deadline exceeded" },
        certspotter: { count: 0, error: cause === "scan_global_deadline" ? RESERVED_PLATFORM_ABORT_WORDING : "module deadline exceeded" },
      },
      source: "tls_probe",
    }),
  }));
  const headers              = await gateModule(budget, "headers", () => runHeadersModule(domain));
  const email_security       = await gateModule(budget, "email_security", () => runEmailModule(domain, {
    cache: dnsCache,
    dmarcOwnedByCore: true,
  }));
  const subdomains           = await gateModule(budget, "subdomains", () => runReservedCtConsumer(domain, "subdomains", {
    ctCache: sharedCtCache,
    ctOverlap,
    signal,
    globalDeadlineProvenance,
    budgetMs: reservedCtBudgets.subdomains,
    run: (consumerSignal) => runSubdomainsModule(domain, {
      cache: dnsCache,
      ctCache: sharedCtCache,
      ctOverlap,
      signal: consumerSignal,
      globalSignal: signal,
      globalDeadlineProvenance,
    }),
    fallback: (cause) => ({
      count: 0,
      items: [],
      sensitive: [],
      sources: {
        crt_sh: { count: 0, error: cause === "scan_global_deadline" ? RESERVED_PLATFORM_ABORT_WORDING : "module deadline exceeded" },
        certspotter: { count: 0, error: cause === "scan_global_deadline" ? RESERVED_PLATFORM_ABORT_WORDING : "module deadline exceeded" },
      },
      wildcard_dns: false,
      wildcard_dns_addresses: [],
      incomplete: true,
      incomplete_reason: cause,
      error: null,
    }),
  }), { count: 0, items: [], wildcard_dns: false, wildcard_dns_addresses: [] });
  const technology_detection = await gateModule(budget, "technology_detection", () => runTechModule(domain));
  const whois_intelligence   = await gateModule(budget, "whois_intelligence", () => runWhoisModule(domain));

  // Takeover + brute-force use the discovered host list.
  const ctItems = Array.isArray(subdomains?.items) ? subdomains.items : [];
  const ctSet = new Set(ctItems.map((h) => String(h).toLowerCase()));
  const mergedSubdomainItems = [
    ...ctItems,
    ...criticalPrefixResult.items.filter((h) => !ctSet.has(String(h).toLowerCase())),
  ];
  const subdomain_takeover = await gateModule(budget, "subdomain_takeover", () => runTakeoverModule(domain, mergedSubdomainItems, { cache: dnsCache }), { checked: 0, potential_risks: 0, risks: [] });
  const dns_bruteforce = await gateModule(budget, "dns_bruteforce", async () => {
    const raw = await runBruteforceModule(domain, { cache: dnsCache });
    return filterWildcardBruteforceResults(raw, subdomains?.wildcard_dns_addresses || []);
  }, { checked: 0, found: 0, items: [] });

  // Annotate + dedupe exposure now that takeover cname_observations are available.
  assetExposureResult = annotateExposureInfrastructure(assetExposureResult, subdomain_takeover?.cname_observations);
  assetExposureResult = deduplicateExposureAssets(assetExposureResult, domain);
  assetExposureResult.projected_consumed = consumedBeforeExposure;
  assetExposureResult.exposure_budget = Math.max(0, budget.usable() - consumedBeforeExposure);

  return {
    resolves,
    modules: {
      dns, ssl, headers, email_security, dmarc_core: dmarcCore,
      subdomains, technology_detection, whois_intelligence,
      subdomain_takeover, dns_bruteforce,
      asset_exposure: assetExposureResult,
      critical_prefix_discovery: criticalPrefixResult,
    },
    mergedSubdomainItems,
    budget,
    dnsCache,
  };
}
