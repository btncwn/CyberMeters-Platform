#!/usr/bin/env node
//
// Deterministic scan subrequest-budget harness (Tier-1 safety net).
//
// This is the FIRST artefact of the capacity fix and must be green before any
// orchestration change (per docs/SCAN-SUBREQUEST-CAPACITY-FIX-BRIEF.md, commit
// f226790). It provides:
//   (1) SubrequestCounter — counts every external fetch, each redirect hop, DoH
//       calls, CT requests, exposure requests, HTTP fallbacks, and optional
//       enrichment calls, and throws "Too many subrequests…" past the limit
//       (mirroring the Cloudflare runtime).
//   (2) classifyRequest(url) — categorises an outbound URL (doh/ct/kev/nvd/rdap/
//       exposure) so the ledger is auditable.
//   (3) computeExposurePlan(...) — the dynamic-cap reference model:
//       usable = limit - safety_margin
//       exposure_budget = max(0, usable - projected_consumed)
//       host_cap = floor(exposure_budget / per_host_cost)
//       with priority ordering and deferred_capacity overflow.
//
// Fixtures assert the approved ledger for CT hit / miss / unavailable, 1/5/25
// assets, redirecting hosts, and configured limits 50 and 1000.
//
// Tier-2/3 will replace the reference model here with imports from the production
// budget primitives; these ledger assertions are the fixed contract those
// primitives must satisfy. Node 24+. CI-blocking.
//

import {
  resolveScanCapacity, computeExposureCap, SubrequestBudget,
  CRITICAL_PREFIXES_MANDATORY, CRITICAL_PREFIXES_OPTIONAL, deferredCapacityAsset,
  makeDnsCache, dnsCacheKey, CAPACITY_DEFAULTS,
} from "../workers/scan-api/src/engines/scan-budget.js";

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { cond ? pass++ : fail++; if (!cond) console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); };
const eq = (name, got, want) => ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

// ── Approved design constants (must match the brief) ──────────────────────────
const DEFAULT_LIMIT          = 50;
const SAFETY_MARGIN          = 5;
const PER_HOST_COST          = 2;   // C_h = 1 GET + 1 budgeted redirect hop
const MAX_PROBE_REDIRECT_HOPS = 3;  // a single host consumes <= 4 external subrequests
// CT-independent core reservation (single-hop): DNS 9 + critical-prefix 8 + SSL 4 + Headers 4 + Email 10
const CORE_CT_INDEPENDENT    = 9 + 8 + 4 + 4 + 10; // = 35
const CT_COST                = { hit: 0, unavailable: 0, miss: 4 };

// ── (2) URL classifier ────────────────────────────────────────────────────────
function classifyRequest(url) {
  let host;
  try { host = new URL(url).hostname; } catch { return "other"; }
  if (/(^|\.)cloudflare-dns\.com$|(^|\.)dns\.google$|(^|\.)dns\.quad9\.net$/.test(host)) return "doh";
  if (/(^|\.)crt\.sh$|(^|\.)certspotter\.com$/.test(host)) return "ct";
  if (/(^|\.)cisa\.gov$/.test(host)) return "kev";
  if (/(^|\.)nvd\.nist\.gov$/.test(host)) return "nvd";
  if (/(^|\.)rdap\./.test(host) || /(^|\.)rdap\.org$/.test(host)) return "rdap";
  return "exposure"; // any other http(s) origin probe
}

// ── (1) Subrequest counter ────────────────────────────────────────────────────
class SubrequestCounter {
  constructor(limit = DEFAULT_LIMIT) {
    this.limit = limit;
    this.total = 0;
    this.redirectHops = 0;
    this.httpFallbacks = 0;
    this.byCategory = {};
  }
  // Record one external subrequest. redirect=true marks a redirect hop;
  // httpFallback=true marks an HTTP-after-HTTPS retry. Throws past the limit.
  record(category, { redirect = false, httpFallback = false } = {}) {
    this.total += 1;
    this.byCategory[category] = (this.byCategory[category] || 0) + 1;
    if (redirect) this.redirectHops += 1;
    if (httpFallback) this.httpFallbacks += 1;
    if (this.total > this.limit) {
      const e = new Error("Too many subrequests by single Worker invocation.");
      e.subrequestLimit = true;
      throw e;
    }
    return this.total;
  }
  // Record a logical probe of `url` that follows `hops` redirects (hard-capped).
  recordProbe(url, { hops = 0, httpFallback = false } = {}) {
    const cat = classifyRequest(url);
    const capped = Math.min(hops, MAX_PROBE_REDIRECT_HOPS);
    this.record(cat, { httpFallback });                 // the GET itself
    for (let i = 0; i < capped; i++) this.record(cat, { redirect: true });
    return capped;
  }
}

// ── (3) Dynamic exposure-cap reference model ──────────────────────────────────
// hosts: array in PRIORITY order — [root, www, ...critical-prefix, ...ct/mx, ...brute]
function computeExposurePlan({ limit = DEFAULT_LIMIT, safetyMargin = SAFETY_MARGIN, consumed, perHostCost = PER_HOST_COST, hosts }) {
  const usable = limit - safetyMargin;
  const exposureBudget = Math.max(0, usable - consumed);
  const hostCap = Math.floor(exposureBudget / perHostCost);
  const probed = [], deferred = [];
  hosts.forEach((h, i) => (i < hostCap ? probed : deferred).push(h));
  return {
    usable, exposureBudget, hostCap,
    probed,
    deferred: deferred.map((h) => ({ host: h.host ?? h, reachable: null, probe_status: "deferred_capacity" })),
  };
}

// Standard-profile projected consumption before exposure, by CT state.
function projectedConsumed(ctState) {
  return CORE_CT_INDEPENDENT + (CT_COST[ctState] ?? 0);
}

// BBB host set (priority order). admin/root/www are CT-independent; email hosts are CT-only.
const BBB_ALL = [
  { host: "blackbullbarbers.co.uk", src: "root" },
  { host: "www.blackbullbarbers.co.uk", src: "www" },
  { host: "admin.blackbullbarbers.co.uk", src: "critical_prefix" },
  { host: "email.blackbullbarbers.co.uk", src: "ct" },
  { host: "www.email.blackbullbarbers.co.uk", src: "ct" },
];
const BBB_DETERMINISTIC = BBB_ALL.filter((h) => h.src !== "ct"); // discoverable without CT

// Only run the fixtures when executed directly (so later commits can import the
// counter/classifier/model without side effects).
import { pathToFileURL } from "node:url";
const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;
if (isMain) runFixtures();

function runFixtures() {
console.log("── ledger constants ──");
eq("core CT-independent reservation = 35", CORE_CT_INDEPENDENT, 35);
eq("usable budget = 45", DEFAULT_LIMIT - SAFETY_MARGIN, 45);

// ── Fixture A: CT cache hit → cap 5, all 5 BBB probed ─────────────────────────
{
  const consumed = projectedConsumed("hit");
  const plan = computeExposurePlan({ consumed, hosts: BBB_ALL });
  eq("CT hit: consumed", consumed, 35);
  eq("CT hit: exposure_budget", plan.exposureBudget, 10);
  eq("CT hit: host_cap", plan.hostCap, 5);
  eq("CT hit: probed count", plan.probed.length, 5);
  eq("CT hit: deferred count", plan.deferred.length, 0);
  ok("CT hit: admin probed", plan.probed.some((h) => h.host === "admin.blackbullbarbers.co.uk"));
}

// ── Fixture B: CT fresh miss (fetched) → cap 3, admin+root+www probed, 2 deferred ─
{
  const consumed = projectedConsumed("miss");
  const plan = computeExposurePlan({ consumed, hosts: BBB_ALL });
  eq("CT miss: consumed", consumed, 39);
  eq("CT miss: exposure_budget", plan.exposureBudget, 6);
  eq("CT miss: host_cap", plan.hostCap, 3);
  eq("CT miss: probed count", plan.probed.length, 3);
  eq("CT miss: deferred count", plan.deferred.length, 2);
  ok("CT miss: admin still probed (critical priority)", plan.probed.some((h) => h.host === "admin.blackbullbarbers.co.uk"));
  ok("CT miss: deferred are CT-only hosts", plan.deferred.every((h) => h.host.includes("email")));
  ok("CT miss: deferred marked deferred_capacity + reachable null",
     plan.deferred.every((h) => h.probe_status === "deferred_capacity" && h.reachable === null));
}

// ── Fixture C: CT unavailable → only deterministic hosts discovered, all probed ─
{
  const consumed = projectedConsumed("unavailable");
  const plan = computeExposurePlan({ consumed, hosts: BBB_DETERMINISTIC });
  eq("CT unavailable: consumed", consumed, 35);
  eq("CT unavailable: host_cap", plan.hostCap, 5);
  eq("CT unavailable: discovered+probed", plan.probed.length, 3);
  eq("CT unavailable: deferred", plan.deferred.length, 0);
  ok("CT unavailable: admin discovered without CT", plan.probed.some((h) => h.host === "admin.blackbullbarbers.co.uk"));
}

// ── Fixture D: 1 / 5 / 25 assets (CT hit) with actual remaining budget ────────
function nHosts(n) {
  // priority: root, www, then critical/ct/brute fillers
  const hosts = [{ host: "root", src: "root" }, { host: "www", src: "www" }, { host: "admin", src: "critical_prefix" }];
  for (let i = hosts.length; i < n; i++) hosts.push({ host: `h${i}`, src: "brute" });
  return hosts.slice(0, n);
}
{
  const consumed = projectedConsumed("hit");
  const p1 = computeExposurePlan({ consumed, hosts: nHosts(1) });
  eq("1 asset: probed", p1.probed.length, 1);
  eq("1 asset: deferred", p1.deferred.length, 0);

  const p5 = computeExposurePlan({ consumed, hosts: nHosts(5) });
  eq("5 assets: probed", p5.probed.length, 5);
  eq("5 assets: deferred", p5.deferred.length, 0);

  const p25 = computeExposurePlan({ consumed, hosts: nHosts(25) });
  eq("25 assets: probed (cap)", p25.probed.length, 5);
  eq("25 assets: deferred_capacity", p25.deferred.length, 20);
  ok("25 assets: critical host in probed set", p25.probed.some((h) => h.host === "admin"));
  ok("25 assets: all deferred are deferred_capacity", p25.deferred.every((h) => h.probe_status === "deferred_capacity"));
}

// ── Fixture E: redirecting hosts counted (hops + hard cap) ────────────────────
{
  const c = new SubrequestCounter(DEFAULT_LIMIT);
  c.recordProbe("https://blackbullbarbers.co.uk", { hops: 1 });         // www->root style: 1 GET + 1 hop = 2
  eq("redirect host: 1 hop counts 2 subrequests", c.total, 2);
  eq("redirect host: redirectHops tallied", c.redirectHops, 1);

  const c2 = new SubrequestCounter(DEFAULT_LIMIT);
  const capped = c2.recordProbe("https://loop.example", { hops: 9 });   // pathological: capped at 3
  eq("redirect host: hops hard-capped", capped, MAX_PROBE_REDIRECT_HOPS);
  eq("redirect host: total = 1 + 3", c2.total, 4);

  const c3 = new SubrequestCounter(DEFAULT_LIMIT);
  c3.recordProbe("https://up.example", { hops: 0 });
  c3.recordProbe("http://up.example", { hops: 0, httpFallback: true });  // HTTP fallback
  eq("http fallback counted", c3.httpFallbacks, 1);
  eq("http fallback: 2 exposure subrequests", c3.byCategory.exposure, 2);
}

// ── Fixture F: classifier + category tally ────────────────────────────────────
{
  eq("classify DoH", classifyRequest("https://cloudflare-dns.com/dns-query?name=x"), "doh");
  eq("classify DoH google", classifyRequest("https://dns.google/resolve?name=x"), "doh");
  eq("classify CT crt.sh", classifyRequest("https://crt.sh/?q=x"), "ct");
  eq("classify KEV", classifyRequest("https://www.cisa.gov/feeds/known_exploited_vulnerabilities.json"), "kev");
  eq("classify NVD", classifyRequest("https://services.nvd.nist.gov/rest/json/x"), "nvd");
  eq("classify exposure host", classifyRequest("https://admin.blackbullbarbers.co.uk"), "exposure");

  const c = new SubrequestCounter(DEFAULT_LIMIT);
  for (let i = 0; i < 9; i++) c.record("doh");
  for (let i = 0; i < 8; i++) c.record("doh");       // critical-prefix pass also DoH
  c.recordProbe("https://admin.blackbullbarbers.co.uk", { hops: 0 });
  eq("category tally: doh", c.byCategory.doh, 17);
  eq("category tally: exposure", c.byCategory.exposure, 1);
}

// ── Fixture G: configured limit 50 vs 1000 ────────────────────────────────────
{
  // Under 50: 25 assets are capped to 5.
  const p50 = computeExposurePlan({ limit: 50, consumed: projectedConsumed("hit"), hosts: nHosts(25) });
  eq("limit 50: 25 assets capped", p50.probed.length, 5);

  // Under 1000: cap is large enough to probe all 25.
  const p1000 = computeExposurePlan({ limit: 1000, consumed: projectedConsumed("hit"), hosts: nHosts(25) });
  ok("limit 1000: 25 assets all probed", p1000.probed.length === 25 && p1000.deferred.length === 0,
     `probed ${p1000.probed.length}`);

  // The counter enforces the configured limit (throws past it).
  const c = new SubrequestCounter(50);
  let threw = false;
  try { for (let i = 0; i < 60; i++) c.record("doh"); } catch (e) { threw = e.subrequestLimit === true; }
  ok("counter throws past limit 50", threw);

  const c1000 = new SubrequestCounter(1000);
  let threw1000 = false;
  try { for (let i = 0; i < 60; i++) c1000.record("doh"); } catch { threw1000 = true; }
  ok("counter does NOT throw at 60 under limit 1000", threw1000 === false);
}

// ── Fixture H: managed-verification profile ≈ 3 subrequests (BBB admin) ────────
{
  const c = new SubrequestCounter(DEFAULT_LIMIT);
  c.record("doh");                                                     // resolve admin (1)
  c.recordProbe("https://admin.blackbullbarbers.co.uk", { hops: 0 });  // exposure probe (1)
  // admin_surface derived from exposure evidence → 0 additional
  eq("verification profile: ~3 subrequests (resolve + probe, C_h budget)", c.total <= 3, true);
  eq("verification: no CT/KEV/NVD/enrichment", (c.byCategory.ct || 0) + (c.byCategory.kev || 0) + (c.byCategory.nvd || 0), 0);
}

// ── Fixture I: production primitives satisfy the contract (Commit 2) ──────────
{
  const def = resolveScanCapacity({});
  eq("prod: default limit 50", def.limit, 50);
  eq("prod: default mode legacy", def.mode, "legacy");
  eq("prod: safety margin 5", def.safetyMargin, 5);
  eq("prod: per-host cost 2", def.perHostCost, PER_HOST_COST);
  eq("prod: max redirect hops 3", def.maxProbeRedirectHops, MAX_PROBE_REDIRECT_HOPS);

  const over = resolveScanCapacity({ SCAN_SUBREQUEST_LIMIT: "1000", SCAN_CAPACITY_MODE: "reserved" });
  eq("prod: env limit override 1000", over.limit, 1000);
  eq("prod: env mode reserved", over.mode, "reserved");
  eq("prod: junk limit falls back to 50", resolveScanCapacity({ SCAN_SUBREQUEST_LIMIT: "abc" }).limit, 50);
  eq("prod: unknown mode falls back to legacy", resolveScanCapacity({ SCAN_CAPACITY_MODE: "wild" }).mode, "legacy");

  // computeExposureCap matches the reference plan for every CT state.
  const c = resolveScanCapacity({});
  eq("prod: cap CT hit = 5", computeExposureCap({ limit: c.limit, safetyMargin: c.safetyMargin, consumed: 35, perHostCost: c.perHostCost }), 5);
  eq("prod: cap CT miss = 3", computeExposureCap({ limit: c.limit, safetyMargin: c.safetyMargin, consumed: 39, perHostCost: c.perHostCost }), 3);
  eq("prod: cap over budget = 0", computeExposureCap({ limit: 50, safetyMargin: 5, consumed: 45, perHostCost: 2 }), 0);
  eq("prod: cap limit 1000 large", computeExposureCap({ limit: 1000, safetyMargin: 5, consumed: 35, perHostCost: 2 }) >= 25, true);

  // critical-prefix list is exactly the 8 mandatory.
  eq("prod: 8 mandatory prefixes", CRITICAL_PREFIXES_MANDATORY.length, 8);
  ok("prod: admin/login/portal/dashboard/manage/vpn/remote/api",
     ["admin","login","portal","dashboard","manage","vpn","remote","api"].every((p) => CRITICAL_PREFIXES_MANDATORY.includes(p)));
  ok("prod: optional prefixes present", CRITICAL_PREFIXES_OPTIONAL.includes("management") && CRITICAL_PREFIXES_OPTIONAL.includes("staging"));

  // deferred_capacity state shape.
  const d = deferredCapacityAsset("admin.example.com");
  ok("prod: deferred_capacity is not-checked (reachable null, not false)",
     d.reachable === null && d.probe_status === "deferred_capacity");

  // SubrequestBudget ledger.
  const b = new SubrequestBudget({ limit: 50, safetyMargin: 5 });
  eq("prod: budget usable 45", b.usable(), 45);
  b.spend("doh", 35);
  eq("prod: budget remaining after core", b.remaining(), 10);
  ok("prod: wouldExceed guards a 12-cost batch at 35 consumed", b.wouldExceed(12) === true);
  ok("prod: 10-cost batch fits", b.wouldExceed(10) === false);

  // DNS cache: resolve once.
  const cache = makeDnsCache();
  cache.set(dnsCacheKey("WWW.Example.com", "a"), { cached: true });
  ok("prod: dns cache key is case-normalised", cache.has(dnsCacheKey("www.example.com", "A")));
}

console.log(`\nscan-subrequest-budget: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
}

// Exported for later commits' harness reuse (kept side-effect free on import via guard).
export { SubrequestCounter, classifyRequest, computeExposurePlan, projectedConsumed,
         DEFAULT_LIMIT, SAFETY_MARGIN, PER_HOST_COST, MAX_PROBE_REDIRECT_HOPS, CORE_CT_INDEPENDENT };
