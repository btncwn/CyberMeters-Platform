#!/usr/bin/env node
//
// Hard-50 faithful engine test (Tier-1 Commit 3 — SOURCE OF TRUTH).
//
// Runs the ACTUAL runScanEngine with a fetch mock that behaves like the real Worker:
// it THROWS "Too many subrequests by single Worker invocation." on outbound call 51.
// Proves that under SCAN_CAPACITY_MODE=reserved the scan completes exposure for the
// reserved priority hosts WITHIN 50 calls, skips modules that don't fit BEFORE fetching,
// and never triggers the runtime exception — while legacy still attempts ~80 and is
// unchanged. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { runScanEngine } = await eng("scan-engine.js");
const { classifyRequest } = await import(pathToFileURL(path.join(root, "scripts", "validate-scan-subrequest-budget.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);
const realFetch = globalThis.fetch;

const RESOLVES = new Set(["example.com", "www.example.com", "admin.example.com"]); // A-record hosts
function respond(url) {
  const cat = classifyRequest(url);
  if (cat === "doh") {
    let name = "", type = "A";
    try { const u = new URL(url); name = u.searchParams.get("name") || ""; type = u.searchParams.get("type") || "A"; } catch {}
    if (type === "A" && RESOLVES.has(name)) return new Response(JSON.stringify({ Answer: [{ data: "93.184.216.34" }] }), { status: 200, headers: { "content-type": "application/dns-json" } });
    return new Response(JSON.stringify({ Answer: [] }), { status: 200, headers: { "content-type": "application/dns-json" } }); // AAAA + non-resolving prefixes → empty (public)
  }
  if (cat === "ct") return new Response(JSON.stringify([]), { status: 200, headers: { "content-type": "application/json" } });
  if (cat === "exposure") return new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html", server: "nginx" } });
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
}

async function runHard50(mode) {
  const calls = [];            // { n, url, cat }
  let exceptionThrown = false; // did the runtime "Too many subrequests" fire?
  globalThis.fetch = async (url) => {
    const s = String(url);
    const n = calls.length + 1;
    if (n > 50) { exceptionThrown = true; throw new Error("Too many subrequests by single Worker invocation."); }
    calls.push({ n, url: s, cat: classifyRequest(s) });
    return respond(s);
  };
  let report = null;
  const stmt = { bind: () => stmt, run: async () => ({}), all: async () => ({ results: [] }), first: async () => null };
  const env = {
    cybermeters_db: { prepare: () => stmt, batch: async () => [] },
    cybermeters_reports: { put: async (_k, body) => { try { report = JSON.parse(body); } catch {} return {}; }, get: async () => null, delete: async () => ({}) },
    SCAN_CAPACITY_MODE: mode,
  };
  let engineErr = null;
  try { await runScanEngine(`scan_${mode}`, "dom", "ws", "example.com", env); } catch (e) { engineErr = e; }
  globalThis.fetch = realFetch;
  return { calls, exceptionThrown, report, engineErr };
}

// helper: first call number whose url matches
const callNo = (calls, pred) => (calls.find(pred) || {}).n ?? null;

// ── RESERVED under a hard 50 ceiling ──────────────────────────────────────────
{
  const { calls, exceptionThrown, report } = await runHard50("reserved");
  const m = report?.modules || report || {};
  const ae = m.asset_exposure || {};
  const sq = report?.scan_quality || {};

  const rootDns  = callNo(calls, (c) => c.cat === "doh" && /name=example\.com&type=A/.test(c.url));
  const adminDns = callNo(calls, (c) => c.cat === "doh" && /name=admin\.example\.com&type=A/.test(c.url));
  const rootExp  = callNo(calls, (c) => c.cat === "exposure" && c.url === "https://example.com");
  const wwwExp   = callNo(calls, (c) => c.cat === "exposure" && c.url === "https://www.example.com");
  const adminExp = callNo(calls, (c) => c.cat === "exposure" && c.url === "https://admin.example.com");

  console.log(`reserved: total=${calls.length} exception=${exceptionThrown} exposure.reachable=${ae.reachable}`);
  console.log(`  call#  rootDNS=${rootDns} adminDNS=${adminDns} rootExp=${rootExp} wwwExp=${wwwExp} adminExp=${adminExp}`);
  console.log(`  modules_skipped=${JSON.stringify(sq.modules_skipped)} scan_quality=${sq.status}`);

  ok("reserved: total attempted external calls <= 50", calls.length <= 50, `total ${calls.length}`);
  ok("reserved: NO 'Too many subrequests' exception", exceptionThrown === false);
  ok("reserved: admin.example.com discovered before exposure (adminDNS < adminExp)", adminDns && adminExp && adminDns < adminExp);
  ok("reserved: root HTTPS probe before call 51", rootExp !== null && rootExp <= 50);
  ok("reserved: www HTTPS probe before call 51", wwwExp !== null && wwwExp <= 50);
  ok("reserved: admin HTTPS probe before call 51", adminExp !== null && adminExp <= 50);
  ok("reserved: all three priority hosts reachable (real result)", ae.reachable >= 3, `reachable ${ae.reachable}`);
  ok("reserved: exposure not deferred/incomplete for priority hosts", ae.incomplete !== true);
  ok("reserved: some modules skipped (subrequest_budget), reported honestly", Array.isArray(sq.modules_skipped) && sq.modules_skipped.length > 0);
  ok("reserved: skipped modules carry skip_reason=subrequest_budget", (sq.modules_skipped || []).some((name) => m[name]?.skip_reason === "subrequest_budget"));
  ok("reserved: skipped modules are NOT fake clean (no reachable/zero-findings masquerade)",
     (sq.modules_skipped || []).every((name) => m[name]?.skipped === true || m[name]?.incomplete === true || m[name]?.error));
  ok("reserved: scan_quality is partial (honest incomplete posture)", sq.status === "partial");

  // exact call numbers reported for the record
  globalThis.__reservedCallNums = { rootDns, adminDns, rootExp, wwwExp, adminExp, total: calls.length };
}

// ── LEGACY unchanged: attempts ~80 and would hit the ceiling (proves it is NOT gated) ─
{
  const { calls } = await runHard50("legacy");
  console.log(`legacy: attempted ${calls.length} calls (capped at 50 by the mock; real engine wants ~80)`);
  ok("legacy: attempts to exceed 50 (unchanged, ungated)", calls.length >= 50);
}

console.log(`\nscan-engine-hard50: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
