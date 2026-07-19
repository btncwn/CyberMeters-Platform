#!/usr/bin/env node
//
// App-Probe Reliability validator.
//
// Core rule: a failed / timed-out / blocked / unavailable probe is NEVER a healthy
// result, and transport failure is not confused with confirmed application absence.
// This exercises the REAL production functions (no toy reimplementation) across the
// HTTP-exposure probe, the admin-surface verdict, scan-quality/completion-gate, and
// the DNS-resolution honesty path.
//
// Distinctions proven:
//   probeAsset        timeout (started, no answer) → reachable:null / probe_status
//                     "timed_out";  connection refused → reachable:false (authoritative
//                     "no web service");  budget → reachable:null / "not_executed";
//                     2xx/3xx/401/403/404/429 → reachable:true (app EXISTS);  5xx →
//                     reachable:false.
//   runExposureModule any timed_out OR budget host → incomplete;  all-refused → NOT
//                     incomplete (a real negative);  success → complete.
//   runAdminSurface   exposure error/incomplete → "unavailable";  empty → "not_assessed";
//                     hosts probed + zero admin → "assessed_healthy";  admin → "issue".
//   buildScanQuality  incomplete exposure → scan_quality "partial".
//   moduleCompletionGate  a partial scan can never verify/resolve a case.
//   runDnsModule      NXDOMAIN(0/3 authoritative, no A) → resolution_assessed, !resolves_any;
//                     SERVFAIL / DoH timeout → resolution NOT assessed → incomplete;
//                     NOERROR+records → resolves_any.
//   scoring           dns_no_resolution CRITICAL fires ONLY on authoritative absence,
//                     never on a resolver failure/timeout.
//
// Pure/mock-fetch harness: no live D1/R2/network. Node 24+. CI-blocking.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const ASSET_SRC = path.join(ENG, "asset-intel.js");
const SCANENG_SRC = path.join(ENG, "scan-engine.js");
const DNS_SRC = path.join(ENG, "dns-scan.js");
const SCORING_SRC = path.join(ENG, "scoring.js");

const { probeAsset, runExposureModule, runAdminSurfaceModule } = await import(pathToFileURL(ASSET_SRC).href);
const { buildScanQuality } = await import(pathToFileURL(SCANENG_SRC).href);
const { moduleCompletionGate } = await import(pathToFileURL(path.join(ENG, "asm-cases.js")).href);
const { runDnsModule } = await import(pathToFileURL(DNS_SRC).href);
const { computeScore } = await import(pathToFileURL(SCORING_SRC).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

// ── fetch mocks ──────────────────────────────────────────────────────────────
const realFetch = globalThis.fetch;
const setFetch = (fn) => { globalThis.fetch = fn; };
const htmlResponse = (status, body = "") =>
  new Response(body, { status, headers: { "content-type": "text/html" } });
const timeoutError = () => { const e = new Error("The operation was aborted due to timeout"); e.name = "TimeoutError"; throw e; };
// A simulated DoH outage makes the DNS module's own (internally-caught, non-fatal)
// DNSSEC lookup log to stderr — suppress that benign noise so CI output stays clean.
const quiet = async (fn) => { const e = console.error; console.error = () => {}; try { return await fn(); } finally { console.error = e; } };
const refusedError = () => { throw new TypeError("Network connection lost: connection refused"); };
const budgetError  = () => { throw new Error("Too many subrequests by single Worker invocation."); };

// DoH mock: routes by the `type=` query param; A/AAAA controllable, everything else
// NOERROR-empty. `throwTypes` simulates a DoH transport failure (fetch rejects).
function dohFetch({ a = { Status: 0, Answer: [] }, aaaa = { Status: 0, Answer: [] }, throwTypes = [] } = {}) {
  return async (url) => {
    const type = new URL(url).searchParams.get("type") || "";
    if (throwTypes.includes(type)) throw new TypeError("DoH network failure");
    const payload = type === "A" ? a : type === "AAAA" ? aaaa : { Status: 0, Answer: [] };
    return { ok: true, status: 200, json: async () => payload };
  };
}
const aAnswer = [{ type: 1, data: "203.0.113.10", TTL: 300 }];

// ── SECTION A — probeAsset transport classification ──────────────────────────
setFetch(timeoutError);
let p = await probeAsset("slow.example.com");
ok("A1 timeout → reachable:null (started, not assessed)", p.reachable === null);
ok("A2 timeout → probe_status timed_out", p.probe_status === "timed_out" && p.reason === "probe_timeout");
setFetch(refusedError);
p = await probeAsset("mail.example.com");
ok("A3 connection refused → reachable:false (authoritative no web service)", p.reachable === false);
ok("A4 connection refused → NO timed_out/not_executed marker", p.probe_status === undefined);
setFetch(budgetError);
p = await probeAsset("starved.example.com");
ok("A5 budget exhaustion → reachable:null / not_executed", p.reachable === null && p.probe_status === "not_executed");
setFetch(() => htmlResponse(200, "<title>Admin Panel</title>"));
p = await probeAsset("up.example.com");
ok("A6 HTTP 200 → reachable:true, status 200", p.reachable === true && p.status === 200);
setFetch(() => htmlResponse(401));
p = await probeAsset("gated.example.com");
ok("A7 HTTP 401 → reachable:true (application EXISTS)", p.reachable === true && p.status === 401);
setFetch(() => htmlResponse(403));
p = await probeAsset("forbidden.example.com");
ok("A8 HTTP 403 → reachable:true (application EXISTS)", p.reachable === true && p.status === 403);
setFetch(() => htmlResponse(404));
p = await probeAsset("missing.example.com");
ok("A9 HTTP 404 → reachable:true (route resolved authoritatively)", p.reachable === true && p.status === 404);
setFetch(() => htmlResponse(429));
p = await probeAsset("throttled.example.com");
ok("A10 HTTP 429 → reachable:true, never a confirmed-absent", p.reachable === true && p.status === 429);
setFetch(() => htmlResponse(503));
p = await probeAsset("erroring.example.com");
ok("A11 HTTP 503 → reachable:false + server_error marker (answered, not content-assessed)",
  p.reachable === false && p.status === 503 && p.probe_status === "server_error");
setFetch(() => htmlResponse(500));
p = await probeAsset("crash.example.com");
ok("A12 HTTP 500 → reachable:false + server_error marker", p.reachable === false && p.probe_status === "server_error");

// ── SECTION B — runExposureModule aggregation ────────────────────────────────
setFetch(timeoutError);
let mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("B1 all timed out → incomplete", mod.incomplete === true && mod.incomplete_reason === "probe_timeout");
ok("B2 all timed out → reachable 0 but NOT a clean result", mod.reachable === 0 && mod.incomplete === true);
setFetch(budgetError);
mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("B3 all budget-starved → incomplete (subrequest_budget_exhausted)", mod.incomplete === true && mod.incomplete_reason === "subrequest_budget_exhausted");
setFetch(refusedError);
mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("B4 all refused (authoritative no web) → NOT incomplete", !mod.incomplete && mod.reachable === 0);
setFetch(() => htmlResponse(200, "<title>x</title>"));
mod = await runExposureModule("example.com", ["a.example.com"]);
ok("B5 success → reachable>0, not incomplete", mod.reachable === 1 && !mod.incomplete);
setFetch(() => htmlResponse(503));
mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("B5b all 5xx (answered, not content-assessed) → incomplete (server_error), reachable 0",
  mod.incomplete === true && mod.incomplete_reason === "server_error" && mod.reachable === 0);
// mix: one reachable, one timed out → incomplete (the timed-out host was NOT assessed).
// Route by hostname (probeAsset issues https+http per host and allSettled interleaves).
setFetch((url) => (new URL(url).hostname === "slow.example.com" ? timeoutError() : htmlResponse(200, "<title>x</title>")));
mod = await runExposureModule("example.com", ["ok.example.com", "slow.example.com"]);
ok("B6 mixed reachable+timeout → incomplete (a probed host was not assessed)", mod.incomplete === true && mod.reachable === 1);
setFetch(realFetch);
// empty input → clean zero, no incomplete (nothing was asked)
mod = await runExposureModule("example.com", []);
ok("B7 empty target set → checked 0, not incomplete", mod.checked === 0 && !mod.incomplete);

// ── SECTION C — runAdminSurfaceModule evidence_status ────────────────────────
const adminEv = (exposure) => runAdminSurfaceModule({ asset_exposure: exposure }).evidence_status;
ok("C1 exposure incomplete → unavailable",
  adminEv({ assets: [{ host: "h", reachable: false }], incomplete: true }) === "unavailable");
ok("C2 exposure error → unavailable",
  adminEv({ assets: [], error: "boom" }) === "unavailable");
ok("C3 no exposure module → not_assessed",
  runAdminSurfaceModule({}).evidence_status === "not_assessed");
ok("C4 exposure ran, zero hosts probed (empty) → not_assessed",
  adminEv({ assets: [] }) === "not_assessed");
ok("C5 exposure complete, host reachable, no admin → assessed_healthy",
  adminEv({ assets: [{ host: "h", reachable: true, title: "Home", server: "nginx" }] }) === "assessed_healthy");
ok("C6 exposure with a verified admin surface → issue_detected",
  adminEv({ assets: [{ host: "grafana.example.com", reachable: true, title: "Grafana", server: "nginx" }] }) === "issue_detected");
// A timed-out-only pass, once run through the module producer, is incomplete → unavailable
setFetch(timeoutError);
const timedOutMod = await runExposureModule("example.com", ["a.example.com"]);
setFetch(realFetch);
ok("C7 end-to-end: all-timeout exposure → admin unavailable (never healthy)",
  runAdminSurfaceModule({ asset_exposure: timedOutMod }).evidence_status === "unavailable");
setFetch(() => htmlResponse(503));
const err5xxMod = await runExposureModule("example.com", ["a.example.com"]);
setFetch(realFetch);
ok("C8 end-to-end: all-5xx exposure → admin unavailable (server error is not clean)",
  runAdminSurfaceModule({ asset_exposure: err5xxMod }).evidence_status === "unavailable");

// ── SECTION D — buildScanQuality + moduleCompletionGate ──────────────────────
const qIncomplete = buildScanQuality({ asset_exposure: { checked: 5, reachable: 0, incomplete: true, incomplete_reason: "probe_timeout" } });
ok("D1 incomplete exposure → scan_quality partial", qIncomplete.status === "partial");
const qComplete = buildScanQuality({ dns: { resolves: true }, ssl: {}, headers: {}, email_security: {}, asset_exposure: { checked: 5, reachable: 2 } });
ok("D2 complete exposure (+clean core) → scan_quality complete", qComplete.status === "complete");
const gatePartial = moduleCompletionGate({ asset_exposure: { incomplete: true } }, { status: "partial" });
ok("D3 partial scan → gate.canVerify false (case defers, never resolves on a failed probe)",
  gatePartial.canVerify("admin_surface_detection") === false);
const gateComplete = moduleCompletionGate({ admin_surface_detection: {} }, { status: "complete" });
ok("D4 complete scan, module ran → gate.canVerify true", gateComplete.canVerify("admin_surface_detection") === true);
const gateIncompleteMod = moduleCompletionGate({ asset_exposure: { incomplete: true } }, { status: "complete" });
ok("D5 module flagged incomplete → gate.canVerify false for that module",
  gateIncompleteMod.canVerify("asset_exposure") === false);

// ── SECTION E — runDnsModule resolution honesty ──────────────────────────────
setFetch(dohFetch({ a: { Status: 3, Answer: [] }, aaaa: { Status: 3, Answer: [] } })); // NXDOMAIN
let dns = await runDnsModule("nx.example.com");
ok("E1 NXDOMAIN → resolution_assessed true (authoritative)", dns.resolution_assessed === true);
ok("E2 NXDOMAIN → resolves_any false, not incomplete", dns.resolves_any === false && dns.incomplete === undefined);
setFetch(dohFetch({ a: { Status: 2, Answer: [] }, aaaa: { Status: 2, Answer: [] } })); // SERVFAIL
dns = await runDnsModule("servfail.example.com");
ok("E3 SERVFAIL → resolution_assessed false (resolver failure, not authoritative)", dns.resolution_assessed === false);
ok("E4 SERVFAIL → incomplete:true (unavailable, never 'does not resolve')", dns.incomplete === true && dns.incomplete_reason === "dns_resolution_unavailable");
setFetch(dohFetch({ throwTypes: ["A", "AAAA"] })); // DoH transport failure on A/AAAA
dns = await quiet(() => runDnsModule("outage.example.com"));
ok("E5 DoH A/AAAA transport failure → resolution_assessed false → incomplete", dns.resolution_assessed === false && dns.incomplete === true);
setFetch(dohFetch({ a: { Status: 0, Answer: aAnswer } })); // NOERROR + records
dns = await runDnsModule("live.example.com");
ok("E6 NOERROR+A records → resolves_any true, resolution_assessed true, not incomplete",
  dns.resolves_any === true && dns.resolution_assessed === true && dns.incomplete === undefined);
setFetch(realFetch);

// ── SECTION F — scoring dns_no_resolution gate ───────────────────────────────
const hasNoResolution = (dnsMod) =>
  computeScore({ dns: dnsMod }, "example.com").findings.some((f) => f.id === "dns_no_resolution");
ok("F1 authoritative no-resolution (assessed, no records) → CRITICAL fires",
  hasNoResolution({ resolves: false, resolves_any: false, resolution_assessed: true }) === true);
ok("F2 resolution unavailable (assessed false) → NO false critical",
  hasNoResolution({ resolves: false, resolves_any: false, resolution_assessed: false }) === false);
ok("F3 single-resolver timeout but another found records → NO false critical",
  hasNoResolution({ resolves: false, resolves_any: true, resolution_assessed: true }) === false);
ok("F4 genuinely resolving domain → no finding",
  hasNoResolution({ resolves: true, resolves_any: true, resolution_assessed: true }) === false);
ok("F5 legacy report (no new fields) + !resolves → finding preserved (back-compat)",
  hasNoResolution({ resolves: false }) === true);

// ── Mutation harness — every guard must be load-bearing ──────────────────────
async function mutant(srcPath, from, to) {
  const src = fs.readFileSync(srcPath, "utf8");
  if (!src.includes(from)) return { anchor: false };
  const srcUrl = pathToFileURL(srcPath);
  const rewritten = src.replace(from, to)
    .replace(/from "(\.\.?\/[^"]+)"/g, (_m, rel) => `from ${JSON.stringify(new URL(rel, srcUrl).href)}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "apr-"));
  const file = path.join(dir, "m.mjs");
  fs.writeFileSync(file, rewritten);
  let mod = null;
  try { mod = await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
  return { anchor: true, mod };
}
const mfetch = (fn, run) => { const prev = globalThis.fetch; globalThis.fetch = fn; return run().finally(() => { globalThis.fetch = prev; }); };

// M1: timeout no longer classified → a timed-out host reads reachable:false (clean).
{
  const m = await mutant(ASSET_SRC, "else if (isProbeTimeout(err)) timedOut = true;", "else if (false) timedOut = true;");
  const r = m.anchor ? await mfetch(timeoutError, () => m.mod.probeAsset("slow.example.com")) : null;
  ok("mutation M1 (timeout classification removed) → timeout falsely reachable:false — CAUGHT",
    m.anchor && r.reachable === false && r.probe_status === undefined);
}
// M2: the timed_out return branch dropped → timeout falls through to reachable:false.
{
  const m = await mutant(ASSET_SRC, "  if (timedOut) {", "  if (false) {");
  const r = m.anchor ? await mfetch(timeoutError, () => m.mod.probeAsset("slow.example.com")) : null;
  ok("mutation M2 (timed_out branch removed) → timeout reachable:false — CAUGHT",
    m.anchor && r.reachable === false);
}
// M3: exposure incomplete only counts budget again → a timeout pass reads complete.
{
  const m = await mutant(ASSET_SRC,
    'const NOT_ASSESSED = new Set(["not_executed", "timed_out", "server_error"]);',
    'const NOT_ASSESSED = new Set(["not_executed", "server_error"]);');
  const r = m.anchor ? await mfetch(timeoutError, () => m.mod.runExposureModule("example.com", ["a.example.com"])) : null;
  ok("mutation M3 (exposure ignores timeouts) → all-timeout pass falsely complete — CAUGHT",
    m.anchor && !r.incomplete);
}
// M4: admin no longer treats exposure.incomplete as unavailable → false healthy.
{
  const m = await mutant(ASSET_SRC,
    "} else if (exposure.error || exposure.incomplete === true) {",
    "} else if (exposure.error) {");
  const r = m.anchor ? m.mod.runAdminSurfaceModule({ asset_exposure: { assets: [{ host: "h", reachable: false }], incomplete: true } }).evidence_status : null;
  ok("mutation M4 (admin ignores exposure.incomplete) → incomplete falsely assessed_healthy — CAUGHT",
    m.anchor && r === "assessed_healthy");
}
// M5: exposure throw catch no longer marks incomplete → scan_quality stays complete.
{
  const m = await mutant(SCANENG_SRC,
    'incomplete: true, incomplete_reason: "exposure_probe_failed", error: customerSafeFailure("scan/asset-exposure", err, "Asset exposure module failed")',
    'error: customerSafeFailure("scan/asset-exposure", err, "Asset exposure module failed")');
  ok("mutation M5 (throw catch drops incomplete) → anchor present (throw path un-flagged)", m.anchor);
  // buildScanQuality proof: without incomplete, a non-core exposure error does not go partial.
  const qNoFlag = buildScanQuality({ dns: { resolves: true }, ssl: {}, headers: {}, email_security: {}, asset_exposure: { checked: 0, reachable: 0, error: "Asset exposure module failed" } });
  ok("mutation M5 corollary → exposure error WITHOUT incomplete leaves scan_quality non-partial — CAUGHT",
    qNoFlag.status !== "partial");
}
// M6: DNS resolution_assessed drops the rcode-authority check → SERVFAIL reads assessed.
{
  const m = await mutant(DNS_SRC,
    "(r) => r.status === \"fulfilled\" && DNS_AUTHORITATIVE_RCODES.has(r.value?.Status)",
    "(r) => r.status === \"fulfilled\"");
  const r = m.anchor ? await mfetch(dohFetch({ a: { Status: 2, Answer: [] }, aaaa: { Status: 2, Answer: [] } }), () => m.mod.runDnsModule("servfail.example.com")) : null;
  ok("mutation M6 (rcode-authority removed) → SERVFAIL falsely 'assessed' (not incomplete) — CAUGHT",
    m.anchor && r.resolution_assessed === true && r.incomplete === undefined);
}
// M7: DNS incomplete-on-outage removed → total resolver outage reads complete.
{
  const m = await mutant(DNS_SRC,
    "...(resolutionAssessed ? {} : { incomplete: true, incomplete_reason: \"dns_resolution_unavailable\" }),",
    "");
  const r = m.anchor ? await mfetch(dohFetch({ throwTypes: ["A", "AAAA"] }), () => quiet(() => m.mod.runDnsModule("outage.example.com"))) : null;
  ok("mutation M7 (DNS outage not flagged incomplete) → resolver outage falsely complete — CAUGHT",
    m.anchor && r.incomplete === undefined);
}
// M8: scoring gate reverts to raw !resolves → SERVFAIL/timeout fires a false critical.
{
  const m = await mutant(SCORING_SRC,
    "  if (dnsAuthoritativelyUnresolved) {",
    "  if (!modules.dns?.resolves) {");
  const fired = m.anchor
    ? m.mod.computeScore({ dns: { resolves: false, resolves_any: false, resolution_assessed: false } }, "example.com").findings.some((f) => f.id === "dns_no_resolution")
    : false;
  ok("mutation M8 (scoring uses raw !resolves) → resolver failure falsely CRITICAL — CAUGHT",
    m.anchor && fired === true);
}
// M9: scoring gate drops the resolves_any check → single-resolver timeout false critical.
{
  const m = await mutant(SCORING_SRC,
    "    && dnsResolutionModule.resolves_any !== true\n",
    "");
  const fired = m.anchor
    ? m.mod.computeScore({ dns: { resolves: false, resolves_any: true, resolution_assessed: true } }, "example.com").findings.some((f) => f.id === "dns_no_resolution")
    : false;
  ok("mutation M9 (scoring ignores resolves_any) → contradicted timeout falsely CRITICAL — CAUGHT",
    m.anchor && fired === true);
}
// M10: scoring gate drops the resolution_assessed check → DNS outage false critical.
{
  const m = await mutant(SCORING_SRC,
    "    && dnsResolutionModule.resolution_assessed !== false;",
    ";");
  const fired = m.anchor
    ? m.mod.computeScore({ dns: { resolves: false, resolves_any: false, resolution_assessed: false } }, "example.com").findings.some((f) => f.id === "dns_no_resolution")
    : false;
  ok("mutation M10 (scoring ignores resolution_assessed) → outage falsely CRITICAL — CAUGHT",
    m.anchor && fired === true);
}
// M11: exposure incomplete_reason mutated → still incomplete but proves the flag path is live.
{
  const m = await mutant(ASSET_SRC, "const incomplete = notAssessed.length > 0;", "const incomplete = false;");
  const r = m.anchor ? await mfetch(timeoutError, () => m.mod.runExposureModule("example.com", ["a.example.com"])) : null;
  ok("mutation M11 (exposure incomplete forced false) → timeout pass falsely complete — CAUGHT",
    m.anchor && !r.incomplete);
}
// M12: admin empty-assets no longer not_assessed (would leak healthy on empty) — guard the ladder order.
{
  const m = await mutant(ASSET_SRC,
    "} else if (exposureAssets.length === 0) {\n    evidence_status = \"not_assessed\";",
    "} else if (false) {\n    evidence_status = \"not_assessed\";");
  const r = m.anchor ? m.mod.runAdminSurfaceModule({ asset_exposure: { assets: [] } }).evidence_status : null;
  ok("mutation M12 (empty-assets not_assessed removed) → empty exposure falsely assessed_healthy — CAUGHT",
    m.anchor && r === "assessed_healthy");
}

// M13: 5xx dropped from the not-assessed set → an all-5xx pass reads complete/clean.
{
  const m = await mutant(ASSET_SRC,
    'const NOT_ASSESSED = new Set(["not_executed", "timed_out", "server_error"]);',
    'const NOT_ASSESSED = new Set(["not_executed", "timed_out"]);');
  const r = m.anchor ? await mfetch(() => htmlResponse(503), () => m.mod.runExposureModule("example.com", ["a.example.com"])) : null;
  ok("mutation M13 (5xx not counted not-assessed) → all-5xx pass falsely complete — CAUGHT",
    m.anchor && !r.incomplete);
}
// M14: 5xx no longer marked server_error in probeAsset → module can't see it.
{
  const m = await mutant(ASSET_SRC,
    '...(status >= 500 ? { probe_status: "server_error", reason: "server_error" } : {}),',
    "");
  const r = m.anchor ? await mfetch(() => htmlResponse(503), () => m.mod.runExposureModule("example.com", ["a.example.com"])) : null;
  ok("mutation M14 (5xx server_error marker removed) → all-5xx pass falsely complete — CAUGHT",
    m.anchor && !r.incomplete);
}

console.log(`\napp-probe-reliability: ${pass}/${pass + fail} passed`);
if (fail) { console.error("app-probe-reliability validation FAILED"); process.exit(1); }
console.log("app-probe-reliability validation passed");
