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
import { runDmarcbisCore, unavailableDmarcbisCore } from "./dmarcbis-production.js";
import { runHeadersModule } from "./headers-scan.js";
import { makeReservedProbeFetch } from "./reserved-probe.js";
import { createCertificateTransparencyCache } from "./ct-provider-cache.js";
import {
  CRITICAL_PREFIXES_MANDATORY, MODULE_SUBREQUEST_COST, PhysicalSubrequestCounter,
  SubrequestBudget, isSubrequestBudgetExhaustedError,
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

function reservedSslCtFallback(cause) {
  const error = cause === "scan_global_deadline"
    ? RESERVED_PLATFORM_ABORT_WORDING
    : "module deadline exceeded";
  return {
    incomplete: true,
    incomplete_reason: cause,
    outcome: "deadline_exceeded",
    ct_sources: {
      crt_sh: { count: 0, error },
      certspotter: { count: 0, error },
    },
    source: "tls_probe",
  };
}

function reservedSubdomainsCtFallback(cause) {
  const error = cause === "scan_global_deadline"
    ? RESERVED_PLATFORM_ABORT_WORDING
    : "module deadline exceeded";
  return {
    count: 0,
    items: [],
    sensitive: [],
    sources: {
      crt_sh: { count: 0, error },
      certspotter: { count: 0, error },
    },
    wildcard_dns: false,
    wildcard_dns_addresses: [],
    incomplete: true,
    incomplete_reason: cause,
    error: null,
  };
}

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
export async function runCriticalPrefixDiscovery(
  domain,
  cache,
  prefixes = CRITICAL_PREFIXES_MANDATORY,
  { accounting = null } = {},
) {
  const items = [];
  let checked = 0;
  let unavailableReason = null;
  for (const prefix of prefixes) {
    if (accounting?.budgetExhausted?.() || accounting?.cancelled?.()) break;
    const host = `${prefix}.${domain}`;
    const ans = await dnsResolveACached(host, cache, {
      accounting,
      onUnavailable(observation) {
        if (observation?.reason === "redirect_refused") {
          unavailableReason = "redirect_refused";
        }
      },
    });
    // dnsResolveACached deliberately converts provider failures to null. Budget
    // refusal is different: this prefix was never assessed, so stop and expose
    // the remaining work instead of reporting all prefixes checked.
    if (unavailableReason) break;
    if (accounting?.budgetExhausted?.() || accounting?.cancelled?.()) break;
    checked += 1;
    if (hasAnswer(ans)) items.push(host);
  }
  const deferred = Math.max(0, prefixes.length - checked);
  return {
    source: "critical_prefix_dns",
    checked,
    requested: prefixes.length,
    found: items.length,
    items,
    ...(deferred > 0 ? {
      incomplete: true,
      incomplete_reason: unavailableReason
        || (accounting?.cancelled?.() ? "scan_deadline_exhausted" : "subrequest_budget_exhausted"),
      deferred_count: deferred,
    } : {}),
  };
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
  for (const h of criticalHits) add(h, "critical_prefix");
  // Critical-prefix hits are the customer-critical AS-B6 signal. Known-asset
  // rechecks remain ahead of passive/expansive CT and brute-force candidates but
  // cannot consume the critical-prefix envelope before a new hit is probed.
  for (const h of knownHosts) add(h, "known_asset");
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
    recheckHosts: toProbe.filter((row) => row.src === "known_asset").map((row) => row.host),
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

function physicalBudgetIncomplete(name, value, fallback, accounting) {
  const issued = accounting?.issuedDuringContext?.() || 0;
  if (issued === 0) {
    return skippedModuleResult(name, {
      ...fallback,
      executed: false,
      incomplete: true,
      outcome: "not_run",
      reason: "subrequest_budget_exhausted",
      incomplete_reason: "subrequest_budget_exhausted",
      physical_attempts_issued: 0,
    });
  }
  return {
    ...fallback,
    ...(value && typeof value === "object" ? value : {}),
    incomplete: true,
    outcome: "subrequest_budget_exhausted",
    reason: "subrequest_budget_exhausted",
    incomplete_reason: "subrequest_budget_exhausted",
    physical_attempts_issued: issued,
  };
}

function deadlineIncomplete(name, value, fallback, accounting) {
  const issued = accounting?.issuedDuringContext?.() || 0;
  return {
    ...fallback,
    ...(value && typeof value === "object" ? value : {}),
    executed: false,
    incomplete: true,
    outcome: "deadline_exceeded",
    reason: "scan_deadline_exhausted",
    incomplete_reason: "scan_deadline_exhausted",
    physical_attempts_issued: issued,
    source: value?.source || fallback?.source || name,
  };
}

// Gate a post-exposure module: run it only if its estimated cost fits the remaining
// admission budget; the independent physical counter still guards every leaf in
// case redirects, fallbacks or response-driven fan-out exceed that estimate.
async function gateModule(
  budget,
  physicalCounter,
  name,
  run,
  skipExtra = {},
  signal = null,
  deadlineExtra = skipExtra,
) {
  // Deadline cancellation outranks projected admission. Calling a cancelled
  // module "subrequest_budget" would hide the real loss of observation.
  if (signal?.aborted) {
    return deadlineIncomplete(
      name,
      null,
      deadlineExtra,
      physicalCounter.contextFor(name, { signal }),
    );
  }
  const cost = MODULE_SUBREQUEST_COST[name] ?? 8;
  if (budget.wouldExceed(cost) || physicalCounter.wouldExceed(cost)) {
    return skippedModuleResult(name, skipExtra);
  }
  budget.spend(name, cost);
  const accounting = physicalCounter.contextFor(name, { signal });
  if (accounting.cancelled()) return deadlineIncomplete(name, null, deadlineExtra, accounting);
  try {
    const value = await run(accounting);
    if (accounting.cancelled()) return deadlineIncomplete(name, value, deadlineExtra, accounting);
    return accounting.budgetExhausted()
      ? physicalBudgetIncomplete(name, value, skipExtra, accounting)
      : value;
  } catch (err) {
    if (accounting.cancelled() || err?.code === "scan_deadline_exhausted") {
      return deadlineIncomplete(name, null, deadlineExtra, accounting);
    }
    if (accounting.budgetExhausted() || isSubrequestBudgetExhaustedError(err)) {
      return physicalBudgetIncomplete(name, null, skipExtra, accounting);
    }
    return { ...skipExtra, incomplete: true, error: customerSafeFailure(`scan/${name}`, err, `${name} module failed`) };
  }
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
  const physicalCounter = new PhysicalSubrequestCounter({
    limit: capacity.limit,
    safetyMargin: capacity.safetyMargin,
  });
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
  // and to seed the exposure list + the shared cache. Exactly two admitted questions.
  const discoveryAccounting = physicalCounter.contextFor("discovery", { signal });
  let rootA = null;
  let wwwA = null;
  if (!discoveryAccounting.cancelled()
      && !budget.wouldExceed(2) && !physicalCounter.wouldExceed(2)) {
    budget.spend("discovery", 2);
    rootA = await dnsResolveACached(domain, dnsCache, { accounting: discoveryAccounting });
    if (!discoveryAccounting.budgetExhausted() && !discoveryAccounting.cancelled()) {
      wwwA = await dnsResolveACached(`www.${domain}`, dnsCache, { accounting: discoveryAccounting });
    }
  }
  const discoveryIncomplete = discoveryAccounting.budgetExhausted()
    || discoveryAccounting.cancelled()
    || rootA == null
    || wwwA == null;
  const resolves = discoveryIncomplete ? null : hasAnswer(rootA);

  // Stage 2: reserve and execute the guaranteed DMARC core BEFORE exposure.
  // Reservation is the conservative logical maximum; cache hits reduce physical
  // provider attempts but never increase exposure capacity optimistically.
  const dmarcAccounting = physicalCounter.contextFor("dmarc_core", { signal });
  let dmarcCore;
  if (dmarcAccounting.cancelled()) {
    dmarcCore = deadlineIncomplete(
      "dmarc_core",
      null,
      unavailableDmarcbisCore(domain, "scan_deadline_exhausted"),
      dmarcAccounting,
    );
  } else if (budget.wouldExceed(MODULE_SUBREQUEST_COST.dmarc_core)
      || physicalCounter.wouldExceed(MODULE_SUBREQUEST_COST.dmarc_core)) {
    dmarcCore = {
      ...unavailableDmarcbisCore(domain, "subrequest_budget"),
      skipped: true,
      skip_reason: "subrequest_budget",
    };
  } else {
    budget.spend("dmarc_core", MODULE_SUBREQUEST_COST.dmarc_core);
    dmarcCore = await runDmarcbisCore(domain, {
      accounting: dmarcAccounting,
      cache: dnsCache,
      signal,
      now,
    });
    if (dmarcAccounting.cancelled()) {
      dmarcCore = deadlineIncomplete(
        "dmarc_core",
        dmarcCore,
        unavailableDmarcbisCore(domain, "scan_deadline_exhausted"),
        dmarcAccounting,
      );
    } else if (dmarcAccounting.budgetExhausted()) {
      dmarcCore = physicalBudgetIncomplete(
        "dmarc_core",
        dmarcCore,
        unavailableDmarcbisCore(domain, "subrequest_budget"),
        dmarcAccounting,
      );
    }
  }

  // Stage 3: critical-prefix discovery (deterministic, CT-independent). 8 A lookups.
  let criticalPrefixResult;
  const criticalCost = CRITICAL_PREFIXES_MANDATORY.length;
  if (signal?.aborted) {
    criticalPrefixResult = {
      source: "critical_prefix_dns",
      checked: 0,
      requested: criticalCost,
      found: 0,
      items: [],
      executed: false,
      incomplete: true,
      outcome: "deadline_exceeded",
      reason: "scan_deadline_exhausted",
      incomplete_reason: "scan_deadline_exhausted",
      deferred_count: criticalCost,
    };
  } else if (budget.wouldExceed(criticalCost) || physicalCounter.wouldExceed(criticalCost)) {
    criticalPrefixResult = {
      source: "critical_prefix_dns",
      checked: 0,
      requested: criticalCost,
      found: 0,
      items: [],
      incomplete: true,
      incomplete_reason: "subrequest_budget_exhausted",
      deferred_count: criticalCost,
    };
  } else {
    budget.spend("critical_prefix", criticalCost);
    const criticalAccounting = physicalCounter.contextFor("critical_prefix", { signal });
    criticalPrefixResult = await runCriticalPrefixDiscovery(
      domain,
      dnsCache,
      CRITICAL_PREFIXES_MANDATORY,
      { accounting: criticalAccounting },
    );
  }

  // Stage 4: prioritise (root → www → critical). CT is NOT here — it is post-exposure.
  const ordered = prioritiseExposureHosts(domain, {
    knownHosts: knownAssetHosts,
    criticalHits: criticalPrefixResult.items,
  });

  // Stage 5: RESERVED EXPOSURE, live-metered (each real prober fetch decrements budget).
  const consumedBeforeExposure = budget.consumed;
  const cap = computeExposureCap({ limit: capacity.limit, safetyMargin: capacity.safetyMargin, consumed: consumedBeforeExposure, perHostCost: capacity.perHostCost });
  const exposureAccounting = physicalCounter.contextFor("asset_exposure", { signal });
  // One shared accounting context reaches BOTH physical DNS cache misses and GET
  // hops. Do not also provide onOutbound: that would double-charge the same leaf.
  const fetcher = makeReservedProbeFetch({
    cache: dnsCache,
    maxHops: capacity.maxProbeRedirectHops,
    accounting: exposureAccounting,
  });
  let assetExposureResult = await runReservedExposureModule(domain, ordered, {
    cap,
    fetcher,
    cache: dnsCache,
    signal,
    dnsAccounting: exposureAccounting,
  });
  const physicalExposureAttempts = exposureAccounting.issuedDuringContext();
  budget.spend("exposure", physicalExposureAttempts);
  if (exposureAccounting.cancelled()) {
    assetExposureResult = deadlineIncomplete(
      "asset_exposure",
      assetExposureResult,
      { checked: ordered.length, reachable: 0, assets: [], removal_observations: [], source: "http_probe" },
      exposureAccounting,
    );
  } else if (exposureAccounting.budgetExhausted()) {
    assetExposureResult = physicalBudgetIncomplete(
      "asset_exposure",
      assetExposureResult,
      { checked: ordered.length, reachable: 0, assets: [], removal_observations: [], source: "http_probe" },
      exposureAccounting,
    );
  }

  // Stage 6: remaining modules, budget-gated (customer-critical exposure already done).
  const dns                  = await gateModule(budget, physicalCounter, "dns", (accounting) => runDnsModule(domain, { accounting, cache: dnsCache }), { resolves }, signal);
  const ssl                  = await gateModule(budget, physicalCounter, "ssl", (accounting) => runReservedCtConsumer(domain, "ssl", {
    ctCache: sharedCtCache,
    signal,
    globalDeadlineProvenance,
    budgetMs: reservedCtBudgets.ssl,
    run: (consumerSignal) => runSslModule(domain, { accounting, ctCache: sharedCtCache, signal: consumerSignal }),
    fallback: reservedSslCtFallback,
  }), {}, signal, reservedSslCtFallback("scan_global_deadline"));
  const headers              = await gateModule(budget, physicalCounter, "headers", (accounting) => runHeadersModule(domain, { accounting, signal }), {}, signal);
  const email_security       = await gateModule(budget, physicalCounter, "email_security", (accounting) => runEmailModule(domain, {
    accounting,
    cache: dnsCache,
    dmarcOwnedByCore: true,
  }), {}, signal);
  const subdomains           = await gateModule(budget, physicalCounter, "subdomains", (accounting) => runReservedCtConsumer(domain, "subdomains", {
    ctCache: sharedCtCache,
    ctOverlap,
    signal,
    globalDeadlineProvenance,
    budgetMs: reservedCtBudgets.subdomains,
    run: (consumerSignal) => runSubdomainsModule(domain, {
      accounting,
      cache: dnsCache,
      ctCache: sharedCtCache,
      ctOverlap,
      signal: consumerSignal,
      globalSignal: signal,
      globalDeadlineProvenance,
    }),
    fallback: reservedSubdomainsCtFallback,
  }), { count: 0, items: [], wildcard_dns: false, wildcard_dns_addresses: [] }, signal,
  reservedSubdomainsCtFallback("scan_global_deadline"));
  const technology_detection = await gateModule(budget, physicalCounter, "technology_detection", (accounting) => runTechModule(domain, { accounting, signal }), {}, signal);
  const whois_intelligence   = await gateModule(budget, physicalCounter, "whois_intelligence", (accounting) => runWhoisModule(domain, { accounting, signal }), {}, signal);

  // Takeover + brute-force use the discovered host list.
  const ctItems = Array.isArray(subdomains?.items) ? subdomains.items : [];
  const ctSet = new Set(ctItems.map((h) => String(h).toLowerCase()));
  const mergedSubdomainItems = [
    ...ctItems,
    ...criticalPrefixResult.items.filter((h) => !ctSet.has(String(h).toLowerCase())),
  ];
  const subdomain_takeover = await gateModule(budget, physicalCounter, "subdomain_takeover", (accounting) => runTakeoverModule(domain, mergedSubdomainItems, { accounting, cache: dnsCache, signal }), { checked: 0, potential_risks: 0, risks: [] }, signal);
  const dns_bruteforce = await gateModule(budget, physicalCounter, "dns_bruteforce", async (accounting) => {
    const raw = await runBruteforceModule(domain, { accounting, cache: dnsCache, signal });
    return filterWildcardBruteforceResults(raw, subdomains?.wildcard_dns_addresses || []);
  }, { checked: 0, found: 0, items: [] }, signal);

  // Annotate + dedupe exposure now that takeover cname_observations are available.
  assetExposureResult = annotateExposureInfrastructure(assetExposureResult, subdomain_takeover?.cname_observations);
  assetExposureResult = deduplicateExposureAssets(assetExposureResult, domain);
  assetExposureResult.projected_consumed = consumedBeforeExposure;
  assetExposureResult.exposure_budget = Math.max(0, budget.usable() - consumedBeforeExposure);
  assetExposureResult.physical_attempts = physicalExposureAttempts;

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
    physicalCounter,
    physicalBudget: physicalCounter.snapshot(),
    dnsCache,
  };
}
