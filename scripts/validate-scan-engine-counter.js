#!/usr/bin/env node
//
// Faithful scan-engine subrequest counter + legacy-probe-shape proof.
//
// The model harness (validate-scan-subrequest-budget.js) checks the budget math in
// isolation. This fixture is different: it runs the ACTUAL runScanEngine against a
// mocked fetch / D1 / R2 and a counter that observes EVERY real outbound call — so
// the instrumentation is proven against the engine, not against a self-agreeing model.
//
// It also proves that with SCAN_CAPACITY_MODE=legacy the pre-existing probeAsset call
// shape (native redirect:"follow") and result shape are unchanged. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { runScanEngine } = await eng("scan-engine.js");
const { probeAsset } = await eng("asset-intel.js");
const { classifyRequest } = await import(pathToFileURL(path.join(root, "scripts", "validate-scan-subrequest-budget.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);
const realFetch = globalThis.fetch;

// ── Section A: legacy probeAsset call + result shape unchanged ─────────────────
{
  let lastOpts = null;
  globalThis.fetch = async (_url, opts) => { lastOpts = opts; return new Response("<title>x</title>", { status: 200, headers: { "content-type": "text/html" } }); };
  const r = await probeAsset("up.example");
  eq("legacy probeAsset uses native redirect:\"follow\"", lastOpts.redirect, "follow");
  eq("legacy probeAsset method GET", lastOpts.method, "GET");
  ok("legacy probeAsset keeps AbortSignal timeout", !!lastOpts.signal);
  ok("legacy probeAsset does NOT set redirect:\"manual\"", lastOpts.redirect !== "manual");
  eq("legacy probeAsset success result shape unchanged",
     Object.keys(r).sort().join(","), "content_type,host,reachable,server,status,tech,title,url");
  globalThis.fetch = realFetch;
}

// ── Section B: faithful engine-integration counter ────────────────────────────
// Counter observes every outbound fetch the real engine makes, classified.
const counter = { total: 0, byCategory: {}, sampleUrls: [] };
function respond(url) {
  const cat = classifyRequest(url);
  if (cat === "doh") {
    let name = "", type = "A";
    try { const u = new URL(url); name = u.searchParams.get("name") || ""; type = u.searchParams.get("type") || "A"; } catch {}
    // Resolve the root A so the domain "resolves"; a CT-style host for one label so the
    // exposure module has a target; everything else empty (bounds brute-force).
    if (type === "A" && name === "example.com") return new Response(JSON.stringify({ Answer: [{ data: "93.184.216.34" }] }), { status: 200, headers: { "content-type": "application/dns-json" } });
    return new Response(JSON.stringify({ Answer: [] }), { status: 200, headers: { "content-type": "application/dns-json" } });
  }
  if (cat === "ct") return new Response(JSON.stringify([{ name_value: "admin.example.com" }]), { status: 200, headers: { "content-type": "application/json" } });
  if (cat === "exposure") return new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html", server: "nginx" } });
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } }); // rdap/nvd/kev/other
}
globalThis.fetch = async (url, _opts) => {
  const s = String(url);
  counter.total += 1;
  const cat = classifyRequest(s);
  counter.byCategory[cat] = (counter.byCategory[cat] || 0) + 1;
  if (counter.sampleUrls.length < 6) counter.sampleUrls.push(s);
  return respond(s);
};

// Chainable D1 + R2 mocks — sufficient for runScanEngine to complete without real I/O.
const stmt = { bind: () => stmt, run: async () => ({ meta: {}, success: true }), all: async () => ({ results: [] }), first: async () => null };
const dbMock = { prepare: () => stmt, batch: async () => [] };
const r2Mock = { put: async () => ({}), get: async () => null, delete: async () => ({}) };
const env = { cybermeters_db: dbMock, cybermeters_reports: r2Mock, SCAN_CAPACITY_MODE: "legacy", APP_VERSION: "test" };

let engineThrew = null;
try {
  await runScanEngine("scan_test", "dom_test", "ws_test", "example.com", env);
} catch (e) {
  engineThrew = e; // late persistence errors don't invalidate the counter — discovery already ran
}

console.log(`engine outbound ledger: total=${counter.total} ${JSON.stringify(counter.byCategory)}`);
if (engineThrew) console.log(`(engine returned an error after discovery — counter still valid: ${String(engineThrew).slice(0, 80)})`);

ok("counter observed the real engine making outbound calls", counter.total > 0, `total ${counter.total}`);
ok("counter observed DNS-over-HTTPS calls (real DNS module fan-out)", (counter.byCategory.doh || 0) > 0, JSON.stringify(counter.byCategory));
ok("counter observed HTTP(S) probe calls (headers/ssl/exposure hitting the origin)", (counter.byCategory.exposure || 0) > 0, JSON.stringify(counter.byCategory));
ok("counter observed >= 2 distinct outbound categories (diverse real traffic, not a model)", Object.keys(counter.byCategory).length >= 2, JSON.stringify(counter.byCategory));
// Legacy fan-out signature: DNS module alone issues many DoH lookups; legacy also runs
// brute-force + DKIM sweeps concurrently — so a legacy run makes a substantial number of calls.
ok("legacy engine makes the expected substantial DoH fan-out (>= 10)", (counter.byCategory.doh || 0) >= 10, `doh ${counter.byCategory.doh}`);
ok("every recorded call was counted (total === sum of categories)", counter.total === Object.values(counter.byCategory).reduce((a, b) => a + b, 0));

globalThis.fetch = realFetch;

console.log(`\nscan-engine-counter: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
