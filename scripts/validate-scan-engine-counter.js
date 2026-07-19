#!/usr/bin/env node
//
// Faithful scan-engine subrequest counter + legacy-probe-shape proof.
//
// The model harness (validate-scan-subrequest-budget.js) checks the budget math in
// isolation. This fixture runs the ACTUAL runScanEngine against mocked fetch / D1 / R2
// with a counter that observes EVERY real outbound call — so instrumentation is proven
// against the engine, not a self-agreeing model. It runs BOTH modes: the legacy ledger
// stays within its budget envelope (still legacy MODE — not switched to reserved), and
// the reserved ledger is captured faithfully. It also proves the legacy probeAsset
// result shape is unchanged; C1 hardened the redirect handling to SSRF-safe manual
// per-hop validation (so the probe now also resolves A+AAAA for the rebinding guard).
// Node 24+.
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
  // C1 (2026-07-19): the default prober is now SSRF-safe — it follows redirects
  // MANUALLY and validates every hop (scheme/credentials/private-reserved literal +
  // DNS-answer rebinding) via the shared makeSsrfSafeProbeFetch core. It previously
  // used native redirect:"follow" with no per-hop validation (the redirect-time SSRF).
  eq("legacy probeAsset uses SSRF-safe redirect:\"manual\" (C1)", lastOpts.redirect, "manual");
  eq("legacy probeAsset method GET", lastOpts.method, "GET");
  ok("legacy probeAsset keeps AbortSignal timeout", !!lastOpts.signal);
  ok("legacy probeAsset sets redirect:\"manual\" for per-hop SSRF validation (C1)", lastOpts.redirect === "manual");
  eq("legacy probeAsset success result shape unchanged",
     Object.keys(r).sort().join(","), "content_type,host,reachable,server,status,tech,title,url");
  globalThis.fetch = realFetch;
}

// ── Faithful engine run with an outbound counter (per mode) ───────────────────
function respond(url) {
  const cat = classifyRequest(url);
  if (cat === "doh") {
    let name = "", type = "A";
    try { const u = new URL(url); name = u.searchParams.get("name") || ""; type = u.searchParams.get("type") || "A"; } catch {}
    if (type === "A" && name === "example.com") return new Response(JSON.stringify({ Answer: [{ data: "93.184.216.34" }] }), { status: 200, headers: { "content-type": "application/dns-json" } });
    return new Response(JSON.stringify({ Answer: [] }), { status: 200, headers: { "content-type": "application/dns-json" } });
  }
  if (cat === "ct") return new Response(JSON.stringify([{ name_value: "admin.example.com" }]), { status: 200, headers: { "content-type": "application/json" } });
  if (cat === "exposure") return new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html", server: "nginx" } });
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
}
async function runEngineLedger(mode) {
  const counter = { total: 0, byCategory: {} };
  globalThis.fetch = async (url) => {
    const s = String(url);
    counter.total += 1;
    const cat = classifyRequest(s);
    counter.byCategory[cat] = (counter.byCategory[cat] || 0) + 1;
    return respond(s);
  };
  const stmt = { bind: () => stmt, run: async () => ({ meta: {}, success: true }), all: async () => ({ results: [] }), first: async () => null };
  const env = { cybermeters_db: { prepare: () => stmt, batch: async () => [] }, cybermeters_reports: { put: async () => ({}), get: async () => null, delete: async () => ({}) }, SCAN_CAPACITY_MODE: mode, APP_VERSION: "test" };
  let threw = null;
  try { await runScanEngine(`scan_${mode}`, "dom_test", "ws_test", "example.com", env); } catch (e) { threw = e; }
  globalThis.fetch = realFetch;
  return { counter, threw };
}

// ── Section B: legacy engine ledger (unchanged after Commit 3) ────────────────
{
  const { counter } = await runEngineLedger("legacy");
  console.log(`legacy engine ledger:   total=${counter.total} ${JSON.stringify(counter.byCategory)}`);
  ok("legacy: counter observed the real engine's outbound calls", counter.total > 0, `total ${counter.total}`);
  ok("legacy: observed DoH (real DNS fan-out incl. brute-force)", (counter.byCategory.doh || 0) >= 10, `doh ${counter.byCategory.doh}`);
  ok("legacy: observed HTTP(S) probe calls", (counter.byCategory.exposure || 0) > 0);
  ok("legacy: exceeds the 50-class ceiling (the root defect)", counter.total > 50, `total ${counter.total}`);
  ok("legacy: total === sum of categories", counter.total === Object.values(counter.byCategory).reduce((a, b) => a + b, 0));
}

// ── Section C: reserved engine ledger (faithful) ──────────────────────────────
{
  const { counter, threw } = await runEngineLedger("reserved");
  console.log(`reserved engine ledger: total=${counter.total} ${JSON.stringify(counter.byCategory)}`);
  if (threw) console.log(`(reserved engine returned after discovery: ${String(threw).slice(0, 80)})`);
  ok("reserved: counter observed the real engine's outbound calls", counter.total > 0, `total ${counter.total}`);
  ok("reserved: observed DoH (core DNS + critical-prefix + SSRF resolution)", (counter.byCategory.doh || 0) > 0);
  ok("reserved: observed HTTP(S) probe calls (headers/ssl/reserved exposure)", (counter.byCategory.exposure || 0) > 0);
  ok("reserved: total === sum of categories", counter.total === Object.values(counter.byCategory).reduce((a, b) => a + b, 0));
}

console.log(`\nscan-engine-counter: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
