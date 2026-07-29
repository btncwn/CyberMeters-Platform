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
//                     reachable:false;  genuine origin 5xx → "server_error" (not
//                     assessed);  Cloudflare-edge-synthesised 52x/530 (Server:
//                     cloudflare — no origin answered, e.g. a mail-only subdomain
//                     fetched from a Worker returns synthetic 530, never a thrown DNS
//                     error) → "origin_unreachable", an AUTHORITATIVE negative that
//                     never degrades the module/scan.
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
// The Cloudflare-edge rule moved into this shared module (PR-A) and is consumed by
// BOTH asset-intel.js and ssl-scan.js — mutating it proves the CLASS, not one caller.
const FETCHOBS_SRC = path.join(ENG, "..", "lib", "fetch-observation.js");
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
// A Cloudflare-edge-synthesised error page (520–530 always carry `Server: cloudflare`).
const edgeResponse = (status) =>
  new Response("error page", { status, headers: { "content-type": "text/html", server: "cloudflare" } });
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
// Cloudflare-edge-synthesised statuses: 530 = origin DNS error (a mail-only/DNS-only
// name fetched from a Worker), 522 = origin connection timed out, 526 = invalid origin
// SSL. No origin answered — an authoritative negative, never "not assessed".
setFetch(() => edgeResponse(530));
p = await probeAsset("reports.example.com");
ok("A13 CF edge 530 (origin DNS error) → reachable:false + origin_unreachable (authoritative negative)",
  p.reachable === false && p.status === 530 && p.probe_status === "origin_unreachable" && p.reason === "cloudflare_edge_error");
setFetch(() => edgeResponse(522));
p = await probeAsset("api.example.com");
ok("A14 CF edge 522 (origin connection timeout) → origin_unreachable", p.reachable === false && p.probe_status === "origin_unreachable");
setFetch(() => edgeResponse(526));
p = await probeAsset("email.example.com");
ok("A15 CF edge 526 (invalid origin SSL) → origin_unreachable", p.reachable === false && p.probe_status === "origin_unreachable");
// A 52x WITHOUT the Cloudflare edge signature stays server_error (fail toward strict).
setFetch(() => htmlResponse(530));
p = await probeAsset("odd.example.com");
ok("A16 530 without Server:cloudflare → server_error (strict not-assessed reading kept)",
  p.reachable === false && p.probe_status === "server_error");
// A proxied origin's own 5xx keeps its real status (outside 520-530) → server_error
// even though Cloudflare rewrites the Server header on proxied responses.
setFetch(() => edgeResponse(502));
p = await probeAsset("brokenapp.example.com");
ok("A17 origin 502 behind Cloudflare proxy → server_error (genuine origin error preserved)",
  p.reachable === false && p.probe_status === "server_error");

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
// Production-regression repro (P1, 19-20 Jul 2026): a real domain whose subdomain list
// contains mail-only / no-origin names — reachable sites plus CF-edge 522/530 answers.
// The pass is COMPLETE: every host got an authoritative disposition.
setFetch((url) => {
  const h = new URL(url).hostname;
  if (h === "www.example.com" || h === "app.example.com") return htmlResponse(200, "<title>x</title>");
  if (h === "api.example.com") return edgeResponse(522);
  return edgeResponse(530); // reports./send. — mail-only names, synthetic origin DNS error
});
mod = await runExposureModule("example.com", ["www.example.com", "api.example.com", "app.example.com", "reports.example.com", "send.example.com"]);
ok("B8 CF-edge 52x/530 hosts (no origin serves there) → NOT incomplete, reachable counts real sites",
  !mod.incomplete && mod.reachable === 2 && mod.checked === 5);
// A genuine origin 5xx mixed in still degrades the pass — the #185 contract holds.
setFetch((url) => (new URL(url).hostname === "dead.example.com" ? edgeResponse(530) : htmlResponse(503)));
mod = await runExposureModule("example.com", ["dead.example.com", "sick.example.com"]);
ok("B9 mixed edge-530 + genuine 503 → incomplete (server_error) — origin 5xx contract preserved",
  mod.incomplete === true && mod.incomplete_reason === "server_error");
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
// An all-CF-edge pass is an authoritative negative (same class as all-refused B4):
// the module completed, nothing serves content, no admin surface is publicly exposed.
setFetch(() => edgeResponse(530));
const edgeMod = await runExposureModule("example.com", ["reports.example.com"]);
setFetch(realFetch);
ok("C9 end-to-end: all-CF-edge exposure → module complete, admin assessed (never unavailable)",
  !edgeMod.incomplete && runAdminSurfaceModule({ asset_exposure: edgeMod }).evidence_status === "assessed_healthy");

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
// End-to-end P1 repro: an exposure pass over CF-edge-answered hosts must yield a
// COMPLETE scan_quality (clean core), never a permanent platform-wide "partial".
setFetch(() => edgeResponse(530));
const edgeOnlyMod = await runExposureModule("example.com", ["reports.example.com", "send.example.com"]);
setFetch(realFetch);
const qEdge = buildScanQuality({ dns: { resolves: true }, ssl: {}, headers: {}, email_security: {}, asset_exposure: edgeOnlyMod });
ok("D6 CF-edge-only exposure pass (+clean core) → scan_quality complete (P1 regression repro)",
  qEdge.status === "complete" && !qEdge.modules_skipped.includes("asset_exposure"));

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
// F5 CHANGED DELIBERATELY (DNS absence-as-evidence P1). This previously asserted that
// a legacy report carrying only `resolves:false` still produced the CRITICAL finding,
// "preserving back-compat". That back-compat is exactly the defect: the same
// missing-contract shape is what a deadline-deferred module produces, so honouring it
// scored -30 for a scan that performed no lookup. Historical compatibility cannot
// outrank evidence honesty — an old report that never recorded the resolution
// contract does not support a critical verdict, and the honest reading is "unknown".
ok("F5 legacy report (no contract fields) + !resolves → NO critical finding (fallback REMOVED)",
  hasNoResolution({ resolves: false }) === false);
ok("F5b an empty/absent dns module likewise produces NO critical finding",
  hasNoResolution({}) === false);

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
// Mutate a DEPENDENCY of the module under test. The Cloudflare-edge rule now lives
// in lib/fetch-observation.js and is shared by asset-intel.js and ssl-scan.js, so
// mutating it into a temp directory would leave the real entry module importing the
// unmutated original — the mutation would silently no-op. Both the mutated dep and a
// rewritten entry module are therefore written BESIDE their originals, so every other
// relative import still resolves, and both are always removed afterwards.
let depSeq = 0;
async function mutantDep(depPath, entryPath, from, to) {
  const depSrc = fs.readFileSync(depPath, "utf8");
  if (!depSrc.includes(from)) return { anchor: false };
  const entrySrc = fs.readFileSync(entryPath, "utf8");
  const n = `${process.pid}.${++depSeq}`;
  const depName = `.${path.basename(depPath, ".js")}.mutant.${n}.js`;
  const entryName = `.${path.basename(entryPath, ".js")}.mutant.${n}.js`;
  const depFile = path.join(path.dirname(depPath), depName);
  const entryFile = path.join(path.dirname(entryPath), entryName);
  // Point the entry module's import of the dep at the mutated copy. The dep is
  // referenced as "../lib/fetch-observation.js" from engines/.
  const relOriginal = `../${path.basename(path.dirname(depPath))}/${path.basename(depPath)}`;
  const relMutant = `../${path.basename(path.dirname(depPath))}/${depName}`;
  if (!entrySrc.includes(relOriginal)) return { anchor: false };
  fs.writeFileSync(depFile, depSrc.replace(from, to));
  fs.writeFileSync(entryFile, entrySrc.split(relOriginal).join(relMutant));
  let mod = null;
  try { mod = await import(`${pathToFileURL(entryFile).href}?t=${Date.now()}-${Math.random()}`); }
  finally { fs.rmSync(depFile, { force: true }); fs.rmSync(entryFile, { force: true }); }
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
  // Re-pointed: the gate is now the canonical Attack Surface DNS signal. Ignoring
  // resolves_any means restoring a hand-rolled predicate without it.
  const m = await mutant(SCORING_SRC,
    "  const dnsAuthoritativelyUnresolved =\n    dnsResolutionSignal.state === \"absent\" &&\n    dnsResolutionSignal.reason === \"authoritative_dns_absence\";",
    "  const dnsAuthoritativelyUnresolved =\n    !modules.dns?.resolves && modules.dns?.resolution_assessed !== false;");
  const fired = m.anchor
    ? m.mod.computeScore({ dns: { resolves: false, resolves_any: true, resolution_assessed: true } }, "example.com").findings.some((f) => f.id === "dns_no_resolution")
    : false;
  ok("mutation M9 (scoring ignores resolves_any) → contradicted timeout falsely CRITICAL — CAUGHT",
    m.anchor && fired === true);
}
// M10: scoring gate drops the resolution_assessed check → DNS outage false critical.
{
  // Re-pointed for the same reason: ignoring resolution_assessed.
  const m = await mutant(SCORING_SRC,
    "  const dnsAuthoritativelyUnresolved =\n    dnsResolutionSignal.state === \"absent\" &&\n    dnsResolutionSignal.reason === \"authoritative_dns_absence\";",
    "  const dnsAuthoritativelyUnresolved =\n    !modules.dns?.resolves && modules.dns?.resolves_any !== true;");
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
    "...(status >= 500 ? classifyServerErrorStatus(status, server) : {}),",
    "");
  const r = m.anchor ? await mfetch(() => htmlResponse(503), () => m.mod.runExposureModule("example.com", ["a.example.com"])) : null;
  ok("mutation M14 (5xx server_error marker removed) → all-5xx pass falsely complete — CAUGHT",
    m.anchor && !r.incomplete);
}
// M15: classifier treats EVERY 5xx as edge-synthesised → a genuine all-503 origin
// error pass falsely reads complete (breaks the #185 contract → B5b/A11 would fail).
{
  // PR-A1 re-point: the range test moved into `inEdgeSet` when the predicate was
  // narrowed to (520..527)||530. Widening it to every 5xx must still be caught.
  const m = await mutantDep(FETCHOBS_SRC, ASSET_SRC,
    "  const inEdgeSet = (code >= CF_EDGE_STATUS_MIN && code <= CF_EDGE_STATUS_MAX) ||\n    code === CF_EDGE_STATUS_EXTRA;",
    "  const inEdgeSet = code >= 500;");
  const r = m.anchor ? await mfetch(() => edgeResponse(503), () => m.mod.runExposureModule("example.com", ["a.example.com"])) : null;
  ok("mutation M15 (edge range widened to all 5xx) → genuine origin 503 falsely complete — CAUGHT",
    m.anchor && !r.incomplete);
}
// M16: classifier drops the Server:cloudflare signature requirement → a bare 530 from
// a non-Cloudflare host falsely reads authoritative (A16 would fail).
{
  const m = await mutantDep(FETCHOBS_SRC, ASSET_SRC,
    '    String(server || "").trim().toLowerCase() === "cloudflare";',
    "    true;");
  const r = m.anchor ? await mfetch(() => htmlResponse(530), () => m.mod.probeAsset("odd.example.com")) : null;
  ok("mutation M16 (edge signature check removed) → unsigned 530 falsely origin_unreachable — CAUGHT",
    m.anchor && r.probe_status === "origin_unreachable");
}
// M17: edge branch removed (revert to blanket server_error) → REINTRODUCES the P1:
// a mail-only-subdomain pass (synthetic CF 530) marks the module incomplete and every
// scan permanently partial (A13/B8/D6 would fail).
{
  const m = await mutantDep(FETCHOBS_SRC, ASSET_SRC,
    "  if (isCloudflareEdgeSynthesised(status, server)) {",
    "  if (false) {");
  const r = m.anchor ? await mfetch(() => edgeResponse(530), () => m.mod.runExposureModule("example.com", ["reports.example.com"])) : null;
  ok("mutation M17 (edge branch removed — the 19 Jul P1 reintroduced) → edge-530 pass falsely incomplete — CAUGHT",
    m.anchor && r.incomplete === true && r.incomplete_reason === "server_error");
}

console.log(`\napp-probe-reliability: ${pass}/${pass + fail} passed`);
if (fail) { console.error("app-probe-reliability validation FAILED"); process.exit(1); }
console.log("app-probe-reliability validation passed");
