#!/usr/bin/env node
//
// Reserved-mode two-stage discovery + dynamic exposure proof (Tier-1 Commit 3).
//
// Proves the reserved orchestration: the DMARC core reservation precedes
// exposure, critical-prefix discovery is CT-independent, the dynamic exposure
// cap remains final authority, deferred capacity is honest, and the invocation
// DNS cache is shared. Legacy remains the default. Node 24+.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);

const { runCriticalPrefixDiscovery, prioritiseExposureHosts, runReservedExposureModule } = await eng("reserved-scan.js");
const { resolveScanCapacity, computeExposureCap, makeDnsCache, dnsCacheKey } = await eng("scan-budget.js");
const { dnsResolveACached } = await eng("dns.js");
const { runAdminSurfaceModule } = await eng("asset-intel.js");
const { buildScanQuality } = await eng("scan-engine.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const realFetch = globalThis.fetch;
const html200 = () => new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html" } });
const dohAnswer = (recs) => new Response(JSON.stringify({ Answer: recs.map((d) => ({ data: d })) }), { status: 200, headers: { "content-type": "application/dns-json" } });
function mockFetch(handler) {
  const calls = [];
  globalThis.fetch = async (url, opts) => { calls.push(String(url)); return handler(String(url), opts); };
  return calls;
}

// ── 0. legacy is the default ──────────────────────────────────────────────────
eq("default capacity mode is legacy", resolveScanCapacity({}).mode, "legacy");

// ── 1. reserved discovers admin.<domain> with CT disabled ─────────────────────
{
  const cache = makeDnsCache();
  const calls = mockFetch((url) => url.includes("cloudflare-dns.com") ? dohAnswer(/name=admin\./.test(url) ? ["1.2.3.4"] : []) : html200());
  const cp = await runCriticalPrefixDiscovery("example.com", cache);
  ok("critical-prefix discovers admin.example.com", cp.items.includes("admin.example.com"));
  ok("critical-prefix single-resolver only (no google/quad9)", calls.every((u) => !u.includes("dns.google") && !u.includes("quad9")));
  eq("critical-prefix checks 8 mandatory prefixes", cp.checked, 8);
  const ordered = prioritiseExposureHosts("example.com", { criticalHits: cp.items, ctHosts: [] });
  ok("admin discoverable/ordered without any CT host", ordered.some((h) => h.host === "admin.example.com" && h.src === "critical_prefix"));
}

// ── 2. DNS cache: no duplicate admin|A or www|A lookup ────────────────────────
{
  const cache = makeDnsCache();
  const calls = mockFetch((url) => url.includes("cloudflare-dns.com") ? dohAnswer(/name=admin\./.test(url) ? ["1.2.3.4"] : []) : html200());
  await runCriticalPrefixDiscovery("example.com", cache);
  const adminBefore = calls.filter((u) => /name=admin\.example\.com/.test(u)).length;
  await dnsResolveACached("admin.example.com", cache);   // must be a cache hit
  eq("no duplicate admin|A lookup", calls.filter((u) => /name=admin\.example\.com/.test(u)).length, adminBefore);
  cache.set(dnsCacheKey("www.example.com", "A"), { Answer: [{ data: "1.1.1.1" }] });
  const wwwBefore = calls.filter((u) => /name=www\.example\.com/.test(u)).length;
  const reused = await dnsResolveACached("www.example.com", cache);
  eq("no duplicate www|A lookup (core DNS answer reused)", calls.filter((u) => /name=www\.example\.com/.test(u)).length, wwwBefore);
  ok("reused www answer is the cached one", reused && reused.Answer[0].data === "1.1.1.1");
}

// ── 3. exposure fits after root/www + guaranteed DMARC core + critical ──────
{
  // Reserved-mode conservative ledger: root(1) + www(1) + DMARC core(10)
  // + eight critical-prefix A questions = 20 before exposure.
  const consumedBeforeExposure = 20;
  const cap = computeExposureCap({ limit: 50, safetyMargin: 5, consumed: consumedBeforeExposure, perHostCost: 2 });
  eq("DMARC-first reserved ledger leaves a 12-host projected cap", cap, 12);
  const ord = prioritiseExposureHosts("bbb.co.uk", { criticalHits: ["admin.bbb.co.uk"], ctHosts: ["email.bbb.co.uk", "www.email.bbb.co.uk"] });
  ok("priority order: root, www first", ord[0].host === "bbb.co.uk" && ord[1].host === "www.bbb.co.uk");
  ok("critical-prefix (admin) ordered before CT-only hosts", ord.findIndex((h) => h.src === "critical_prefix") < ord.findIndex((h) => h.src === "ct"));
  ok("CT-only hosts are last in priority", ord.slice(-2).every((h) => h.src === "ct"));
}

// ── 4. 25 assets → honest deferred_capacity; cap is the final authority ────────
{
  mockFetch(() => html200());
  const ordered = [
    { host: "example.com", src: "root" }, { host: "www.example.com", src: "www" }, { host: "admin.example.com", src: "critical_prefix" },
  ];
  for (let i = 3; i < 25; i++) ordered.push({ host: `h${i}.example.com`, src: "brute" });
  const ex = await runReservedExposureModule("example.com", ordered, { cap: 5 });
  eq("25 assets: all represented", ex.assets.length, 25);
  eq("25 assets: host_cap = 5 (final authority)", ex.host_cap, 5);
  eq("25 assets: 20 deferred_capacity", ex.deferred_capacity_count, 20);
  ok("overflow → probe_status deferred_capacity", ex.assets.filter((a) => a.probe_status === "deferred_capacity").length === 20);
  ok("overflow → reason projected_subrequest_budget", ex.assets.filter((a) => a.probe_status === "deferred_capacity").every((a) => a.reason === "projected_subrequest_budget"));
  ok("overflow → reachable null (not clean, not false)", ex.assets.filter((a) => a.probe_status === "deferred_capacity").every((a) => a.reachable === null));
  ok("25 assets: module incomplete", ex.incomplete === true);
  eq("25 assets: incomplete_reason", ex.incomplete_reason, "projected_subrequest_budget");
  ok("critical host (admin) probed, not deferred", ex.assets.some((a) => a.host === "admin.example.com" && a.probe_status !== "deferred_capacity"));
}

// ── 5. runtime exhaustion still maps to not_executed ──────────────────────────
{
  mockFetch(() => { throw new Error("Too many subrequests by single Worker invocation."); });
  const ordered = [{ host: "example.com", src: "root" }, { host: "www.example.com", src: "www" }, { host: "admin.example.com", src: "critical_prefix" }];
  const ex = await runReservedExposureModule("example.com", ordered, { cap: 3 });
  ok("runtime exhaustion → probed hosts not_executed", ex.assets.some((a) => a.probe_status === "not_executed"));
  eq("runtime exhaustion → incomplete_reason", ex.incomplete_reason, "subrequest_budget_exhausted");
  ok("runtime exhaustion → module incomplete", ex.incomplete === true);
}

// ── 6. admin_surface adds zero HTTP requests ──────────────────────────────────
{
  const calls = mockFetch(() => html200());
  const modules = { asset_exposure: { assets: [
    { host: "admin.example.com", url: "https://admin.example.com", reachable: true, status: 200, title: "Admin Login", server: "nginx", content_type: "text/html", tech: [] },
  ] } };
  const before = calls.length;
  const surface = runAdminSurfaceModule(modules);
  eq("admin_surface makes zero HTTP requests", calls.length, before);
  ok("admin_surface returned a result from evidence", surface && typeof surface === "object");
}

// ── 7. scan_quality is partial when any host is deferred ───────────────────────
{
  const exposureWithDeferred = { checked: 25, reachable: 3, incomplete: true, incomplete_reason: "projected_subrequest_budget", assets: [] };
  const q = buildScanQuality({ dns: { resolves: true }, ssl: {}, headers: { accessible: true }, email_security: {}, asset_exposure: exposureWithDeferred });
  eq("scan_quality partial when exposure incomplete (deferred)", q.status, "partial");
  ok("asset_exposure listed as skipped", q.modules_skipped.includes("asset_exposure"));
}

globalThis.fetch = realFetch;
console.log(`\nreserved-scan: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
