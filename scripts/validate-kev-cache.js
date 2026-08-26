#!/usr/bin/env node
//
// CISA KEV catalogue R2 cache (Tier 1: wall-time reduction).
//
// The KEV feed is a multi-MB, domain-independent download re-fetched on every scan
// — a prime contributor to the wall-clock that triggers waitUntil cancellation.
// getKevCatalogue caches it in R2 with a TTL. This suite proves:
//   • cache HIT (fresh)  → no origin fetch, served from R2
//   • cache MISS         → origin fetched once AND written back to R2
//   • cache STALE + origin OK    → refreshed from origin
//   • cache STALE + origin FAIL  → stale served, flagged honestly (never clean)
//   • no cache + origin FAIL     → unavailable (honest), runKevModule → error, not clean
//   • cache read/write FAILURE   → degrades to origin, never throws
//   • runKevModule still matches technologies against the catalogue
//
// Node 24+. CI-blocking.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { getKevCatalogue, runKevModule, KEV_CACHE_KEY, KEV_CACHE_TTL_MS } = await eng("vuln-intel.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const CATALOGUE = { vulnerabilities: [
  { cveID: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j2", vulnerabilityName: "Log4Shell", dateAdded: "2021-12-10" },
  { cveID: "CVE-2019-0708", vendorProject: "Microsoft", product: "Remote Desktop Services", vulnerabilityName: "BlueKeep", dateAdded: "2019-05-14" },
] };

// A fake R2 bucket recording get/put; content is a Map of key → string body.
function fakeR2(seed = {}) {
  const store = new Map(Object.entries(seed));
  const calls = { get: 0, put: 0 };
  return {
    _store: store, _calls: calls,
    async get(key) { calls.get++; return store.has(key) ? { text: async () => store.get(key) } : null; },
    async put(key, body) { calls.put++; store.set(key, body); },
  };
}
// A fetcher returning 200 + the catalogue; counts calls. failing:true → throws.
function fakeFetcher({ failing = false } = {}) {
  const calls = { n: 0 };
  const fetcher = async () => { calls.n++; if (failing) throw new Error("network down"); return { status: 200, json: async () => CATALOGUE }; };
  return { fetcher, calls };
}
const clock = (t) => () => t;
const serviceableTech = (technologies) => ({
  technologies,
  technology_fingerprints: technologies.map((technology) => ({
    technology, source: "server", confidence: 90,
  })),
  serviceability_contract: {
    serviceable: true,
    conclusion_class: "conclusive",
    reason: "origin_response_serviceable",
  },
});

// ── 1. Cache HIT (fresh) → served from R2, no origin fetch ──
{
  const nowMs = 2_000_000_000_000;
  const r2 = fakeR2({ [KEV_CACHE_KEY]: JSON.stringify({ fetched_at_ms: nowMs - 1000, vulnerabilities: CATALOGUE.vulnerabilities }) });
  const { fetcher, calls } = fakeFetcher();
  const res = await getKevCatalogue({ cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("fresh hit: source r2_cache", res.source, "r2_cache");
  eq("fresh hit: not stale", res.stale, false);
  eq("fresh hit: origin NOT fetched", calls.n, 0);
  eq("fresh hit: catalogue returned", res.vulnerabilities.length, 2);
}

// ── 2. Cache MISS → origin fetched once and written back ──
{
  const nowMs = 2_000_000_000_000;
  const r2 = fakeR2();
  const { fetcher, calls } = fakeFetcher();
  const res = await getKevCatalogue({ cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("miss: source origin", res.source, "origin");
  eq("miss: origin fetched once", calls.n, 1);
  eq("miss: cache written back", r2._calls.put, 1);
  const stored = JSON.parse(r2._store.get(KEV_CACHE_KEY));
  eq("miss: stored fetched_at_ms recorded", stored.fetched_at_ms, nowMs);
  eq("miss: stored catalogue", stored.vulnerabilities.length, 2);
}

// ── 3. Cache STALE + origin OK → refreshed from origin ──
{
  const nowMs = 2_000_000_000_000;
  const staleAt = nowMs - (KEV_CACHE_TTL_MS + 60_000); // just past TTL
  const r2 = fakeR2({ [KEV_CACHE_KEY]: JSON.stringify({ fetched_at_ms: staleAt, vulnerabilities: [] }) });
  const { fetcher, calls } = fakeFetcher();
  const res = await getKevCatalogue({ cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("stale+ok: refreshed from origin", res.source, "origin");
  eq("stale+ok: origin fetched", calls.n, 1);
  eq("stale+ok: fresh catalogue (2 entries, not the empty stale)", res.vulnerabilities.length, 2);
}

// ── 4. Cache STALE + origin FAIL → stale served, flagged stale (never clean) ──
{
  const nowMs = 2_000_000_000_000;
  const staleAt = nowMs - (KEV_CACHE_TTL_MS + 60_000);
  const r2 = fakeR2({ [KEV_CACHE_KEY]: JSON.stringify({ fetched_at_ms: staleAt, vulnerabilities: CATALOGUE.vulnerabilities }) });
  const { fetcher } = fakeFetcher({ failing: true });
  const res = await getKevCatalogue({ cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("stale+fail: source r2_cache_stale", res.source, "r2_cache_stale");
  eq("stale+fail: flagged stale", res.stale, true);
  ok("stale+fail: still returns catalogue (better than nothing)", res.vulnerabilities.length === 2);
  ok("stale+fail: age reported", typeof res.age_ms === "number" && res.age_ms > KEV_CACHE_TTL_MS);
}

// ── 5. No cache + origin FAIL → unavailable; runKevModule → honest error, not clean ──
{
  const nowMs = 2_000_000_000_000;
  const r2 = fakeR2();
  const { fetcher } = fakeFetcher({ failing: true });
  const res = await getKevCatalogue({ cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("no-cache+fail: unavailable", res.source, "unavailable");
  eq("no-cache+fail: vulnerabilities null", res.vulnerabilities, null);

  const mod = await runKevModule(serviceableTech(["log4j"]), { cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("unavailable → module reports error (honest)", mod.error, "KEV catalog unavailable");
  eq("unavailable → checked 0", mod.checked, 0);
  ok("unavailable → NOT presented as clean zero-match", mod.error !== undefined && mod.matched === 0);
}

// ── 6. Cache read/write FAILURE → degrades to origin, never throws ──
{
  const nowMs = 2_000_000_000_000;
  const brokenR2 = { get: async () => { throw new Error("R2 down"); }, put: async () => { throw new Error("R2 down"); } };
  const { fetcher, calls } = fakeFetcher();
  const res = await getKevCatalogue({ cybermeters_reports: brokenR2 }, { fetcher, now: clock(nowMs) });
  eq("broken cache: falls back to origin", res.source, "origin");
  eq("broken cache: origin fetched", calls.n, 1);
  ok("broken cache: returns catalogue without throwing", res.vulnerabilities.length === 2);
}

// ── 7. runKevModule matches technologies against the catalogue (hit path) ──
{
  const nowMs = 2_000_000_000_000;
  const r2 = fakeR2({ [KEV_CACHE_KEY]: JSON.stringify({ fetched_at_ms: nowMs - 1000, vulnerabilities: CATALOGUE.vulnerabilities }) });
  const { fetcher, calls } = fakeFetcher();
  const mod = await runKevModule(serviceableTech(["Log4j2"]), { cybermeters_reports: r2 }, { fetcher, now: clock(nowMs) });
  eq("match: source cisa_kev", mod.source, "cisa_kev");
  eq("match: catalogue_source r2_cache", mod.catalogue_source, "r2_cache");
  eq("match: checked = full catalogue size", mod.checked, 2);
  ok("match: Log4Shell matched by keyword", mod.matches.some((m) => m.cve_id === "CVE-2021-44228"));
  eq("match: no origin fetch on cache hit", calls.n, 0);
}

// ── 8. No env (non-worker context) → direct fetch, no cache, still works ──
{
  const nowMs = 2_000_000_000_000;
  const { fetcher, calls } = fakeFetcher();
  const res = await getKevCatalogue(null, { fetcher, now: clock(nowMs) });
  eq("no env: source origin", res.source, "origin");
  eq("no env: fetched once", calls.n, 1);
}

console.log(`\nkev-cache: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
