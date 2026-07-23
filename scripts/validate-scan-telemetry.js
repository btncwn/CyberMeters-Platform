#!/usr/bin/env node
//
// Additive scan observability (Tier 1: make waitUntil-cancellation diagnosable).
//
// Heartbeat (scans.last_heartbeat_at / current_stage / completed_modules) + a
// per-module telemetry collector persisted to scan_module_telemetry. This suite
// proves the collector's contracts and that persistence/heartbeat are non-fatal:
//   • run() times a module, classifies its outcome, returns the value unchanged
//   • run() re-throws a rejection but still records an 'error' row (+ timeout flag)
//   • record() adds coarse rows (deferred / reserved / pure-compute)
//   • outcomeOf() maps error/incomplete/skipped/ok/missing correctly
//   • persistModuleTelemetry inserts one row per collected module, non-fatal
//   • heartbeatScan writes stage/heartbeat/count, and never throws on a DB error
//   • the migration is additive (columns nullable, table create-if-not-exists)
//
// Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { createModuleTelemetry, createOutboundAccounting, createScanDeadline, raceModuleDeadline, buildExecutionDiagnostics, SCAN_EXECUTION_DIAGNOSTICS_VERSION } = await eng("scan-budget.js");
const { persistModuleTelemetry, heartbeatScan } = await eng("scan-engine.js");
const { safeFetch } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "http.js")).href);
const { dnsQuery } = await eng("dns.js");
const { makeReservedProbeFetch } = await eng("reserved-probe.js");
const { getKevCatalogue } = await eng("vuln-intel.js");
const { runWhoisModule } = await eng("whois-scan.js");
const { runHeadersModule } = await eng("headers-scan.js");
const { runSslModule } = await eng("ssl-scan.js");
const { runSubdomainsModule, runBruteforceModule } = await eng("subdomains-scan.js");
const { runCloudStorageModule } = await eng("cloud-storage-scan.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// A monotonic fake clock — each read advances by `step` ms so durations are > 0.
function steppingClock(start = 1_000_000, step = 25) {
  let t = start;
  return () => { const v = t; t += step; return v; };
}

async function withMockFetch(fn, impl) {
  const prior = globalThis.fetch;
  globalThis.fetch = impl;
  try { return await fn(); }
  finally { globalThis.fetch = prior; }
}

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), { status: init.status || 200, headers: { "content-type": "application/json", ...(init.headers || {}) } });
}

// ── 1. run() times a module, classifies ok, returns value unchanged ──
{
  const telem = createModuleTelemetry(steppingClock());
  const value = { resolves: true };
  const returned = await telem.run("dns", async () => value);
  eq("run returns the module value unchanged", returned, value);
  eq("one row recorded", telem.rows.length, 1);
  eq("row module", telem.rows[0].module, "dns");
  eq("row outcome ok", telem.rows[0].outcome, "ok");
  ok("row duration_ms > 0", telem.rows[0].duration_ms > 0);
  ok("row has started_at + completed_at ISO", typeof telem.rows[0].started_at === "string" && typeof telem.rows[0].completed_at === "string");
}

// ── 2. run() re-throws a rejection but records an error row (timeout classified) ──
{
  const telem = createModuleTelemetry(steppingClock());
  let threw = false;
  try {
    await telem.run("subdomains", async () => { const e = new Error("Subdomain discovery timed out (15s hard cap)"); throw e; });
  } catch { threw = true; }
  ok("run re-throws the rejection (allSettled semantics preserved)", threw);
  eq("error row recorded", telem.rows.length, 1);
  eq("error row outcome", telem.rows[0].outcome, "error");
  eq("error row timeout flag set from message", telem.rows[0].timeout, true);
  ok("error row records error_class", telem.rows[0].error_class === "Error");
}

// ── 3. run() classifies incomplete / skipped from the module result ──
{
  const telem = createModuleTelemetry(steppingClock());
  await telem.run("asset_exposure", async () => ({ incomplete: true, outcome: "deadline_exceeded" }));
  await telem.run("cloud_storage_discovery", async () => ({ skipped: true, skip_reason: "subrequest_budget" }));
  eq("incomplete → deadline_exceeded outcome", telem.rows[0].outcome, "deadline_exceeded");
  eq("skipped → skipped outcome", telem.rows[1].outcome, "skipped");
}

// ── 4. record() + outcomeOf() coarse classification ──
{
  const telem = createModuleTelemetry(steppingClock());
  eq("outcomeOf error", telem.outcomeOf({ error: "x" }), "error");
  eq("outcomeOf incomplete", telem.outcomeOf({ incomplete: true, outcome: "deadline_exceeded" }), "deadline_exceeded");
  eq("outcomeOf skipped", telem.outcomeOf({ skipped: true }), "skipped");
  eq("outcomeOf ok", telem.outcomeOf({ matches: [] }), "ok");
  eq("outcomeOf missing", telem.outcomeOf(null), "missing");
  telem.record("known_exploited_vulnerabilities", { outcome: "deadline_exceeded" });
  ok("record adds a coarse row", telem.has("known_exploited_vulnerabilities"));
  eq("coarse row has null duration", telem.rows[0].duration_ms, null);
}

// A D1 stub that records inserts/updates; `fail:true` makes every run() throw.
function d1Stub({ fail = false } = {}) {
  const calls = [];
  return {
    _calls: calls,
    cybermeters_db: {
      prepare: (sql) => ({ bind: (...args) => ({ run: async () => { if (fail) throw new Error("D1 down"); calls.push({ sql, args }); } }) }),
    },
  };
}

// ── 5. persistModuleTelemetry inserts one row per module; non-fatal on DB error ──
{
  const telem = createModuleTelemetry(steppingClock());
  await telem.run("dns", async () => ({ resolves: true }));
  telem.record("known_exploited_vulnerabilities", { outcome: "deadline_exceeded" });

  const env = d1Stub();
  await persistModuleTelemetry("scan_z", telem, env);
  eq("one INSERT per collected row", env._calls.length, 2);
  ok("inserts into scan_module_telemetry", /INSERT INTO\s+scan_module_telemetry/i.test(env._calls[0].sql));
  ok("binds scan_id", env._calls[0].args.includes("scan_z"));
  ok("timeout bound as 0/1 integer", env._calls[0].args.some((a) => a === 0 || a === 1));

  // DB failure must not throw out of persistence.
  let threw = false;
  try { await persistModuleTelemetry("scan_z", telem, d1Stub({ fail: true })); } catch { threw = true; }
  ok("persistModuleTelemetry is non-fatal on DB error", threw === false);
}

// ── 6. heartbeatScan writes stage/count and is non-fatal on DB error ──
{
  const env = d1Stub();
  await heartbeatScan(env.cybermeters_db ? env : env, "scan_h", "discovery_complete", 7);
  eq("heartbeat issues one UPDATE", env._calls.length, 1);
  ok("heartbeat UPDATEs scans", /UPDATE\s+scans\s+SET\s+last_heartbeat_at/i.test(env._calls[0].sql));
  ok("heartbeat binds stage", env._calls[0].args.includes("discovery_complete"));
  ok("heartbeat binds completed count", env._calls[0].args.includes(7));

  let threw = false;
  try { await heartbeatScan(d1Stub({ fail: true }), "scan_h", "finalizing", 3); } catch { threw = true; }
  ok("heartbeatScan is non-fatal on DB error", threw === false);
}

// ── 7. Migration 078 is additive (nullable columns, create-if-not-exists) ──
{
  const mig = fs.readFileSync(path.join(root, "database", "migrations", "078-scan-observability.sql"), "utf8");
  ok("adds last_heartbeat_at column", /ALTER TABLE scans ADD COLUMN last_heartbeat_at/i.test(mig));
  ok("adds current_stage column", /ALTER TABLE scans ADD COLUMN current_stage/i.test(mig));
  ok("adds completed_modules column", /ALTER TABLE scans ADD COLUMN completed_modules/i.test(mig));
  ok("creates scan_module_telemetry if not exists", /CREATE TABLE IF NOT EXISTS scan_module_telemetry/i.test(mig));
  ok("telemetry table has all required columns", ["scan_id", "module", "started_at", "completed_at", "duration_ms", "outbound_calls", "outcome", "timeout", "error_class"].every((c) => new RegExp("\\b" + c + "\\b").test(mig)));
  ok("no destructive statement", !/\b(DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM|TRUNCATE)\b/i.test(mig.replace(/--[^\n]*/g, "")));
}

// ═══ PR-A1: additive execution timing telemetry ═══════════════════════════════

// ── 8. record() carries allocated_ms / timeout_source; defaults stay null ──
{
  const telem = createModuleTelemetry(steppingClock());
  telem.record("subdomain_takeover", { outcome: "deadline_exceeded", timeout: true, duration_ms: 1200, allocated_ms: 1500, timeout_source: "module_race" });
  telem.record("dns", { outcome: "ok" });
  eq("record carries allocated_ms", telem.rows[0].allocated_ms, 1500);
  eq("record carries timeout_source", telem.rows[0].timeout_source, "module_race");
  eq("allocated_ms defaults null", telem.rows[1].allocated_ms, null);
  eq("timeout_source defaults null", telem.rows[1].timeout_source, null);
}

// ── 9. raceModuleDeadline onStart reports the EXACT applied cap ──
{
  // Non-advancing fake clock: time moves only via tick().
  let t = 0;
  const clock = () => t;
  const dl = createScanDeadline({}, clock); // 19_000 executable budget from t=0
  t = 1_000; // 18_000 remaining

  let reported = null;
  const v = await raceModuleDeadline(dl, async () => "done", () => "deferred", {
    onStart: (capMs) => { reported = capMs; },
    setTimer: () => null, clearTimer: () => {},
  });
  eq("race resolves module value with onStart present", v, "done");
  eq("onStart reports remaining budget as the cap", reported, 18_000);

  // hardMs narrows the cap — onStart must report the NARROWED value (mutation
  // direction: a call-site re-computation of remainingMs would report 18_000).
  reported = null;
  await raceModuleDeadline(dl, async () => "done", () => "deferred", {
    hardMs: 5_000, onStart: (capMs) => { reported = capMs; },
    setTimer: () => null, clearTimer: () => {},
  });
  eq("onStart reports min(hardMs, remaining)", reported, 5_000);

  // Exhausted budget: onStart still reports (0 or negative cap) and the race
  // defers without launching the thunk.
  t = 30_000;
  reported = "unset";
  let launched = false;
  const d = await raceModuleDeadline(dl, async () => { launched = true; return "ran"; }, () => "deferred", {
    onStart: (capMs) => { reported = capMs; },
  });
  eq("exhausted budget defers", d, "deferred");
  ok("exhausted budget never launches the thunk", launched === false);
  eq("onStart reports 0 on exhausted budget", reported, 0);

  // A throwing onStart must never affect the race (observational only).
  t = 1_000;
  const v2 = await raceModuleDeadline(dl, async () => "done", () => "deferred", {
    onStart: () => { throw new Error("telemetry hook exploded"); },
    setTimer: () => null, clearTimer: () => {},
  });
  eq("throwing onStart never affects the race", v2, "done");

  // Omitting onStart is byte-identical behaviour (the pre-PR-A1 call shape).
  const v3 = await raceModuleDeadline(dl, async () => "done", () => "deferred", { setTimer: () => null, clearTimer: () => {} });
  eq("onStart omitted → unchanged behaviour", v3, "done");
}

// ── 10. buildExecutionDiagnostics contract ──
{
  let t = 0;
  const clock = () => t;
  const dl = createScanDeadline({}, clock);
  t = 4_321;

  const telem = createModuleTelemetry(clock);
  telem.record("ssl", { outcome: "ok", duration_ms: 812 });
  telem.record("headers", { outcome: "error", timeout: true, error_class: "TimeoutError", duration_ms: 10_000 });
  telem.record("subdomain_takeover", { outcome: "deadline_exceeded", timeout: true, duration_ms: 900, allocated_ms: 950, timeout_source: "module_race" });
  telem.record("cve_intelligence", { outcome: "ok", duration_ms: 400, outbound_calls: 2 });

  const diag = buildExecutionDiagnostics({ executionContext: "queue", deadline: dl, telemetry: telem });
  eq("diagnostics version stamped", diag.version, SCAN_EXECUTION_DIAGNOSTICS_VERSION);
  eq("execution_context passthrough", diag.execution_context, "queue");
  eq("deadline budget surfaced", diag.deadline_budget_ms, 19_000);
  eq("total ceiling surfaced", diag.total_ceiling_ms, 24_000);
  eq("finalization reserve surfaced", diag.finalization_reserve_ms, 5_000);
  eq("engine_wall_ms from deadline elapsed", diag.engine_wall_ms, 4_321);
  eq("one diagnostics row per telemetry row", diag.modules.length, 4);
  eq("wall_ms mirrors duration_ms", diag.modules[0].wall_ms, 812);
  // per_fetch derivation: timeout flag without an explicit source = the module's
  // own fetch timeout (mutation direction: dropping the derivation yields null).
  eq("timeout without explicit source derives per_fetch", diag.modules[1].timeout_source, "per_fetch");
  // explicit source always wins over the derivation
  eq("explicit timeout_source wins", diag.modules[2].timeout_source, "module_race");
  eq("allocated_ms surfaced", diag.modules[2].allocated_ms, 950);
  eq("outbound_calls surfaced", diag.modules[3].outbound_calls, 2);
  eq("no timeout → timeout_source null", diag.modules[0].timeout_source, null);

  // PR-B1A: advisory trigger origin — additive, passthrough, fail-safe null.
  const trigDiag = buildExecutionDiagnostics({ executionContext: "queue", trigger: "scheduled", deadline: dl, telemetry: telem });
  eq("trigger passthrough (scheduled)", trigDiag.trigger, "scheduled");
  eq("trigger does not alter execution_context", trigDiag.execution_context, "queue");

  const empty = buildExecutionDiagnostics({});
  eq("missing context fails safe to null", empty.execution_context, null);
  eq("missing trigger fails safe to null (PR-B1A)", empty.trigger, null);
  eq("missing deadline → null budget", empty.deadline_budget_ms, null);
  eq("missing telemetry → empty modules", empty.modules.length, 0);
}

// ── 11. D1 persistence is SCHEMA-UNCHANGED: new fields are never bound ──
{
  const telem = createModuleTelemetry(steppingClock());
  telem.record("subdomain_takeover", { outcome: "deadline_exceeded", timeout: true, duration_ms: 1200, allocated_ms: 1500, timeout_source: "module_race" });
  const env = d1Stub();
  await persistModuleTelemetry("scan_a1", telem, env);
  eq("still one INSERT per row", env._calls.length, 1);
  // 10 bound columns exactly (id, scan_id, module, started_at, completed_at,
  // duration_ms, outbound_calls, outcome, timeout, error_class) — a migration-100
  // column addition would change this count. Mutation proof: binding
  // allocated_ms/timeout_source into D1 without a migration must fail here.
  eq("exactly 10 bound parameters (existing 078 schema)", env._calls[0].args.length, 10);
  ok("allocated_ms value never bound into D1", !env._calls[0].args.includes(1500));
  ok("timeout_source value never bound into D1", !env._calls[0].args.includes("module_race"));
}

// ── 12. Engine + call-site wiring (source contracts, PR-A1) ──
{
  const src = (...p) => fs.readFileSync(path.join(root, ...p), "utf8");
  const engineSrc   = src("workers", "scan-api", "src", "engines", "scan-engine.js");
  const dispatchSrc = src("workers", "scan-api", "src", "engines", "scan-dispatch.js");
  const indexSrc    = src("workers", "scan-api", "src", "index.js");
  const scansSrc    = src("workers", "scan-api", "src", "routes", "scans.js");

  ok("engine whitelists execution contexts (fail-safe null)",
    /opts\.executionContext === "queue" \|\| opts\.executionContext === "cron" \|\| opts\.executionContext === "waituntil"/.test(engineSrc));
  // PR-B1A: advisory origin is validated with the same fail-safe pattern.
  ok("engine whitelists trigger origins (fail-safe null)",
    /opts\.trigger === "manual" \|\| opts\.trigger === "scheduled"/.test(engineSrc));
  ok("completed report embeds execution_diagnostics (with trigger, PR-B1A)",
    /report\.execution_diagnostics = buildExecutionDiagnostics\(\{ executionContext, trigger, deadline, telemetry \}\)/.test(engineSrc));
  ok("failed report embeds execution_diagnostics (with trigger, PR-B1A)",
    /execution_diagnostics: buildExecutionDiagnostics\(\{ executionContext, trigger, deadline, telemetry \}\)/.test(engineSrc));
  ok("finalisation wall time recorded as D1 pseudo-row",
    /telemetry\.record\("scan_finalisation", \{ outcome: "ok", duration_ms: now\(\) - finalizeStartedMs \}\)/.test(engineSrc));
  ok("queue call site passes executionContext queue (+ advisory trigger, PR-B1A)",
    /doRunScanEngine\([^)]*\{ executionContext: "queue", trigger \}\)/.test(dispatchSrc));
  ok("cron call site passes executionContext cron",
    /runScanEngine\([^)]*\{ executionContext: "cron" \}\)/.test(indexSrc));
  ok("waituntil call site passes executionContext waituntil",
    /runScanEngine\([^)]*\{ executionContext: "waituntil" \}\)/.test(scansSrc));
  ok("old CVE technologies_checked outbound estimate removed",
    !/outbound_calls: Array\.isArray\(modules\.cve_intelligence\?\.technologies_checked\) \? modules\.cve_intelligence\.technologies_checked\.length : null/.test(engineSrc));
  ok("CVE outbound_calls now derives from measured outbound snapshot",
    /cveOutboundSnapshot\.outbound_measurement_complete \? cveOutboundSnapshot\.outbound_attempts_observed : null/.test(engineSrc));

  // Behaviour-neutrality direction proofs: diagnostics must remain write-only in
  // the engine (assigned into reports, never read back into any decision), and
  // scan_finalisation must never join the tracked-module backfill set.
  const readsBack = engineSrc.split("execution_diagnostics").length - 1;
  eq("engine references execution_diagnostics exactly twice (both writes)", readsBack, 2);
  const trackedArr = engineSrc.slice(engineSrc.indexOf("TELEMETRY_TRACKED_MODULES = Object.freeze(["));
  ok("scan_finalisation is not a tracked module", !trackedArr.slice(0, trackedArr.indexOf("])")).includes("scan_finalisation"));
  ok("buildScanQuality never reads diagnostics", !/buildScanQuality[\s\S]{0,2000}execution_diagnostics/.test(engineSrc.slice(engineSrc.indexOf("export function buildScanQuality"), engineSrc.indexOf("export function buildScanQuality") + 3000)));
}

// ── 13. Outbound accounting leaf helpers and D1/null semantics (PR-C1A) ──
{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("technology_detection");
  await withMockFetch(async () => {
    const res = await safeFetch("https://example.com", { accounting: ctx });
    eq("C1A one successful HTTP response", res.status, 200);
  }, async () => new Response("ok", { status: 200 }));
  ctx.markSettled();
  const snap = acct.snapshot("technology_detection");
  eq("C1A one successful HTTP attempt", snap.outbound_attempts_observed, 1);
  eq("C1A one successful HTTP completed", snap.outbound_completed_observed, 1);
  eq("C1A settled leaf measurement complete", snap.outbound_measurement_complete, true);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  const seen = [];
  await withMockFetch(async () => {
    const res = await safeFetch("https://example.com", { redirect: "follow", accounting: ctx });
    eq("C1A redirect final response", res.status, 200);
  }, async (url) => {
    seen.push(String(url));
    if (seen.length === 1) return new Response("", { status: 302, headers: { location: "https://example.com/final" } });
    return new Response("ok", { status: 200 });
  });
  ctx.markSettled();
  eq("C1A manual redirect counts both hops", acct.snapshot("headers").outbound_attempts_observed, 2);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  let n = 0;
  await withMockFetch(async () => {
    await runHeadersModule("www.example.com", { accounting: ctx });
  }, async () => {
    n += 1;
    if (n === 1) return new Response("", { status: 503, headers: { "retry-after": "30" } });
    return new Response("", { status: 200, headers: { server: "origin", "content-type": "text/html" } });
  });
  ctx.markSettled();
  eq("C1A headers bot-protection HEAD fallback counted", acct.snapshot("headers").outbound_attempts_observed, 2);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  await withMockFetch(async () => {
    await runHeadersModule("example.com", { accounting: ctx });
  }, async () => new Response("", { status: 200, headers: { server: "origin", "content-type": "text/html" } }));
  ctx.markSettled();
  eq("C1A headers www-variant HEAD counted", acct.snapshot("headers").outbound_attempts_observed, 2);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  let n = 0;
  await withMockFetch(async () => {
    await runHeadersModule("www.example.com", { accounting: ctx });
  }, async () => {
    n += 1;
    if (n === 1) return new Response("", { status: 302, headers: { location: "https://www.example.com/final" } });
    return new Response("", { status: 200, headers: { server: "origin", "content-type": "text/html" } });
  });
  ctx.markSettled();
  eq("C1A headers redirect hops still counted physically", acct.snapshot("headers").outbound_attempts_observed, 2);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("dns");
  await withMockFetch(async () => {
    await dnsQuery("example.com", "A", { accounting: ctx });
  }, async () => jsonResponse({ Status: 0, Answer: [{ data: "203.0.113.10", type: 1 }] }));
  ctx.markSettled();
  eq("C1A DNS DoH attempt counted", acct.snapshot("dns").outbound_attempts_observed, 1);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("dns");
  await withMockFetch(async () => {
    await Promise.allSettled([
      dnsQuery("example.com", "A", { accounting: ctx }),
      dnsQuery("example.com", "AAAA", { accounting: ctx }),
      dnsQuery("example.com", "MX", { accounting: ctx }),
    ]);
  }, async () => jsonResponse({ Status: 0, Answer: [] }));
  ctx.markSettled();
  eq("C1A parallel DNS calls counted individually", acct.snapshot("dns").outbound_attempts_observed, 3);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("whois_intelligence");
  let n = 0;
  await withMockFetch(async () => {
    await runWhoisModule("example.com", { accounting: ctx });
  }, async () => {
    n += 1;
    return n === 1 ? new Response("missing", { status: 404 }) : jsonResponse({ events: [], entities: [], nameservers: [] });
  });
  ctx.markSettled();
  eq("C1A provider fallback counts both RDAP attempts", acct.snapshot("whois_intelligence").outbound_attempts_observed, 2);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  await withMockFetch(async () => {
    await safeFetch("https://example.com", { signal: AbortSignal.abort(), accounting: ctx });
  }, async () => { throw new DOMException("aborted", "AbortError"); });
  ctx.markSettled();
  eq("C1A abort observed without changing safeFetch contract", acct.snapshot("headers").outbound_aborted_observed, 1);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  await withMockFetch(async () => {
    await safeFetch("https://example.com", { accounting: ctx });
  }, async () => { throw new DOMException("timed out", "TimeoutError"); });
  ctx.markSettled();
  eq("C1A timeout attempt counted", acct.snapshot("headers").outbound_attempts_observed, 1);
  eq("C1A timeout observed", acct.snapshot("headers").outbound_timed_out_observed, 1);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("known_exploited_vulnerabilities");
  const env = { cybermeters_reports: { get: async () => ({ text: async () => JSON.stringify({ fetched_at_ms: Date.now(), vulnerabilities: [] }) }) } };
  await withMockFetch(async () => {
    const cat = await getKevCatalogue(env, { accounting: ctx });
    eq("C1A KEV cache source", cat.source, "r2_cache");
  }, async () => { throw new Error("origin fetch should not happen on cache hit"); });
  ctx.markSettled();
  eq("C1A provider cache hit excluded from outbound attempts", acct.snapshot("known_exploited_vulnerabilities").outbound_attempts_observed, 0);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("asset_exposure");
  await withMockFetch(async () => {
    const fetcher = makeReservedProbeFetch({ cache: new Map(), accounting: ctx });
    await fetcher("https://example.com");
  }, async (url) => {
    if (String(url).includes("dns-query")) return jsonResponse({ Status: 0, Answer: [] });
    return new Response("ok", { status: 200 });
  });
  ctx.markSettled();
  eq("C1A nested SSRF helper avoids caller+leaf double count", acct.snapshot("asset_exposure").outbound_attempts_observed, 3);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("ssl");
  await withMockFetch(async () => {
    await runSslModule("example.com", { accounting: ctx });
  }, async (url) => {
    const u = String(url);
    if (u.startsWith("https://crt.sh/")) {
      return jsonResponse([{ not_after: "2999-01-01T00:00:00Z", not_before: "2026-01-01T00:00:00Z", common_name: "example.com", name_value: "example.com" }]);
    }
    if (u === "https://example.com") return new Response("", { status: 200 });
    if (u === "http://example.com") return new Response("", { status: 301, headers: { location: "https://example.com" } });
    return new Response("", { status: 200 });
  });
  ctx.markSettled();
  eq("C1B SSL CT + HTTPS + HTTP attempts counted", acct.snapshot("ssl").outbound_attempts_observed, 3);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("ssl");
  await withMockFetch(async () => {
    await runSslModule("example.com", { accounting: ctx });
  }, async (url) => {
    const u = String(url);
    if (u.startsWith("https://crt.sh/")) return jsonResponse([]);
    if (u.startsWith("https://api.certspotter.com/")) {
      return jsonResponse([{ not_after: "2999-01-01T00:00:00Z", not_before: "2026-01-01T00:00:00Z", dns_names: ["example.com"], issuer: { name: "Test CA" } }]);
    }
    if (u === "https://example.com") return new Response("", { status: 200 });
    if (u === "http://example.com") return new Response("", { status: 301, headers: { location: "http://www.example.com" } });
    if (u === "http://www.example.com/") return new Response("", { status: 301, headers: { location: "https://www.example.com" } });
    return new Response("", { status: 200 });
  });
  ctx.markSettled();
  eq("C1B SSL CT fallback and explicit redirect hop counted", acct.snapshot("ssl").outbound_attempts_observed, 5);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("subdomains");
  await withMockFetch(async () => {
    await runSubdomainsModule("example.com", { accounting: ctx });
  }, async (url) => {
    const u = String(url);
    if (u.includes("dns-query")) return jsonResponse({ Status: 0, Answer: [] });
    if (u.startsWith("https://crt.sh/")) return jsonResponse([{ name_value: "www.example.com\napi.example.com", common_name: "www.example.com" }]);
    if (u.startsWith("https://api.certspotter.com/")) return jsonResponse([{ dns_names: ["app.example.com"] }]);
    return jsonResponse([]);
  });
  ctx.markSettled();
  eq("C1B subdomain wildcard DNS + both CT providers counted", acct.snapshot("subdomains").outbound_attempts_observed, 4);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("dns_bruteforce");
  await withMockFetch(async () => {
    await runBruteforceModule("example.com", { accounting: ctx });
  }, async () => jsonResponse({ Status: 0, Answer: [] }));
  ctx.markSettled();
  eq("C1B DNS brute-force A + MX calls counted", acct.snapshot("dns_bruteforce").outbound_attempts_observed, 23);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("cloud_storage_discovery");
  await withMockFetch(async () => {
    await runCloudStorageModule("example.com", { subdomains: { items: ["assets.s3.amazonaws.com"] } }, { accounting: ctx });
  }, async (url, init) => {
    if (init?.method === "HEAD") return new Response("", { status: 200, headers: { "x-amz-request-id": "req-1" } });
    return new Response("<ListBucketResult><Contents /></ListBucketResult>", { status: 200, headers: { "x-amz-request-id": "req-2" } });
  });
  ctx.markSettled();
  eq("C1B cloud-storage HEAD + GET validation counted", acct.snapshot("cloud_storage_discovery").outbound_attempts_observed, 2);
}

{
  const telem = createModuleTelemetry(steppingClock());
  const acct = createOutboundAccounting();
  const sslCtx = acct.contextFor("ssl");
  const subCtx = acct.contextFor("subdomains");
  sslCtx.recordAttempt();
  sslCtx.markSettled();
  subCtx.recordAttempt();
  subCtx.markSettled();
  const sslSnap = acct.snapshot("ssl");
  const subSnap = acct.snapshot("subdomains");
  telem.record("ssl", { outcome: "ok", outbound: sslSnap, outbound_calls: sslSnap.outbound_measurement_complete ? sslSnap.outbound_attempts_observed : null });
  telem.record("subdomains", { outcome: "ok", outbound: subSnap, outbound_calls: subSnap.outbound_measurement_complete ? subSnap.outbound_attempts_observed : null });
  const env = d1Stub();
  await persistModuleTelemetry("scan_c1b_isolation", telem, env);
  eq("C1B SSL measured integer persists independently", env._calls[0].args[6], 1);
  eq("C1B subdomains measured integer persists independently", env._calls[1].args[6], 1);
}

{
  const telem = createModuleTelemetry(steppingClock());
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("cve_intelligence");
  ctx.markSettled();
  const snap = acct.snapshot("cve_intelligence");
  telem.record("cve_intelligence", { outcome: "ok", outbound: snap, outbound_calls: snap.outbound_measurement_complete ? snap.outbound_attempts_observed : null });
  const env = d1Stub();
  await persistModuleTelemetry("scan_zero", telem, env);
  eq("C1A launched measured-zero persists D1 0", env._calls[0].args[6], 0);
}

{
  const telem = createModuleTelemetry(steppingClock());
  const acct = createOutboundAccounting();
  const okCtx = acct.contextFor("dns");
  const rejectedCtx = acct.contextFor("headers");
  okCtx.recordAttempt();
  rejectedCtx.recordAttempt();
  okCtx.markSettled();
  rejectedCtx.markIncomplete("module_error");
  const okSnap = acct.snapshot("dns");
  const rejectedSnap = acct.snapshot("headers");
  telem.record("dns", { outcome: "ok", outbound: okSnap, outbound_calls: okSnap.outbound_measurement_complete ? okSnap.outbound_attempts_observed : null });
  telem.record("headers", { outcome: "error", outbound: rejectedSnap, outbound_calls: rejectedSnap.outbound_measurement_complete ? rejectedSnap.outbound_attempts_observed : null });
  const diag = buildExecutionDiagnostics({ telemetry: telem });
  const env = d1Stub();
  await persistModuleTelemetry("scan_rejected", telem, env);
  eq("C1A successful sibling persists measured D1 integer", env._calls[0].args[6], 1);
  eq("C1A rejected module observed attempts retained in R2", diag.modules[1].outbound_attempts_observed, 1);
  eq("C1A rejected module measurement incomplete", diag.modules[1].outbound_measurement_complete, false);
  eq("C1A rejected module persists D1 null", env._calls[1].args[6], null);
  eq("C1A no cross-module attempt contamination", diag.modules[0].outbound_attempts_observed, 1);
}

{
  const telem = createModuleTelemetry(steppingClock());
  const acct = createOutboundAccounting();
  const snap = acct.snapshot("cve_intelligence");
  telem.record("cve_intelligence", { outcome: "deadline_exceeded", outbound: snap, outbound_calls: snap.outbound_measurement_complete ? snap.outbound_attempts_observed : null });
  const env = d1Stub();
  await persistModuleTelemetry("scan_never", telem, env);
  eq("C1A never-launched module persists D1 null", env._calls[0].args[6], null);
}

{
  const telem = createModuleTelemetry(steppingClock());
  telem.record("cloud_storage_discovery", { outcome: "ok" });
  const env = d1Stub();
  await persistModuleTelemetry("scan_uninstrumented", telem, env);
  eq("C1A uninstrumented module persists D1 null", env._calls[0].args[6], null);
}

{
  const telem = createModuleTelemetry(steppingClock());
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("asset_exposure");
  ctx.recordAttempt();
  ctx.markAbandoned("module_race");
  const snap = acct.snapshot("asset_exposure");
  telem.record("asset_exposure", { outcome: "deadline_exceeded", outbound: snap, outbound_calls: snap.outbound_measurement_complete ? snap.outbound_attempts_observed : null });
  const diag = buildExecutionDiagnostics({ telemetry: telem });
  const env = d1Stub();
  await persistModuleTelemetry("scan_abandoned", telem, env);
  eq("C1A abandoned observed count preserved in R2 diagnostics", diag.modules[0].outbound_attempts_observed, 1);
  eq("C1A abandoned measurement marked incomplete", diag.modules[0].outbound_measurement_complete, false);
  eq("C1A abandoned partial count never written to D1", env._calls[0].args[6], null);
}

// ── B2. Leaf cancellation preserves caller signal and stops new attempts ──
{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  const caller = new AbortController();
  let seenSignal = null;
  await withMockFetch(async () => {
    const res = await safeFetch("https://example.com", { signal: caller.signal, accounting: ctx });
    eq("B2 caller-signal fetch succeeds", res.status, 200);
  }, async (_url, init) => {
    seenSignal = init.signal;
    caller.abort("caller_abort");
    ok("B2 combined signal observes caller abort", seenSignal.aborted === true);
    return new Response("ok", { status: 200 });
  });
  eq("B2 caller-signal attempt counted once", acct.snapshot("headers").outbound_attempts_observed, 1);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("headers");
  const controller = new AbortController();
  controller.abort("module_budget_exhausted");
  ctx.signal = controller.signal;
  ctx.assertCanIssue = () => { if (ctx.signal.aborted) throw new DOMException("Module budget exhausted", "AbortError"); };
  let launched = false;
  await withMockFetch(async () => {
    const res = await safeFetch("https://example.com", { accounting: ctx });
    eq("B2 cancelled leaf returns null", res, null);
  }, async () => { launched = true; return new Response("unexpected"); });
  eq("B2 cancellation prevents physical fetch launch", launched, false);
  eq("B2 cancelled leaf does not count a new attempt", acct.snapshot("headers").outbound_attempts_observed, 0);
}

{
  const acct = createOutboundAccounting();
  const ctx = acct.contextFor("dns");
  const controller = new AbortController();
  controller.abort("scan_deadline_exhausted");
  ctx.signal = controller.signal;
  ctx.assertCanIssue = () => { if (ctx.signal.aborted) throw new DOMException("Scan deadline exhausted", "AbortError"); };
  let launched = false;
  await withMockFetch(async () => {
    let threw = false;
    try { await dnsQuery("example.com", "A", { accounting: ctx }); }
    catch (err) { threw = err?.name === "AbortError"; }
    ok("B2 DNS cancellation propagates AbortError", threw);
  }, async () => { launched = true; return jsonResponse({ Answer: [] }); });
  eq("B2 DNS cancellation prevents physical DoH launch", launched, false);
  eq("B2 DNS cancelled leaf does not count a new attempt", acct.snapshot("dns").outbound_attempts_observed, 0);
}

{
  const src = (...p) => fs.readFileSync(path.join(root, ...p), "utf8");
  const engineSrc = src("workers", "scan-api", "src", "engines", "scan-engine.js");
  const budgetSrc = src("workers", "scan-api", "src", "engines", "scan-budget.js");
  const dispatchSrc = src("workers", "scan-api", "src", "engines", "scan-dispatch.js");
  const indexSrc = src("workers", "scan-api", "src", "index.js");
  ok("C1A D1/R2/Queue operations are not leaf-counted", !/cybermeters_(?:db|reports)|SCAN_QUEUE/.test(budgetSrc.slice(budgetSrc.indexOf("createOutboundAccounting"), budgetSrc.indexOf("// ── Per-module telemetry"))));
  ok("C1A diagnostics include observed attempts", /outbound_attempts_observed/.test(budgetSrc));
  ok("C1A diagnostics include measurement complete", /outbound_measurement_complete/.test(budgetSrc));
  ok("C1A incomplete measurement keeps D1 outbound_calls null", /outbound_measurement_complete \? .*outbound_attempts_observed : null/.test(engineSrc));
  ok("C1A manual queue path still passes trigger only", /doRunScanEngine\([^)]*\{ executionContext: "queue", trigger \}\)/.test(dispatchSrc));
  ok("C1A scheduled queue consumer remains shared", /queue: \(batch, env, ctx\) => handleScanDispatchBatch/.test(indexSrc));
  const headersSrc = src("workers", "scan-api", "src", "engines", "headers-scan.js");
  function sourceGuard(name, source, predicate, mutate) {
    ok(`${name} — holds on current source`, predicate(source) === true);
    const mutated = mutate(source);
    ok(`${name} — mutation changed source`, mutated !== source);
    ok(`${name} — CAUGHT when defect reintroduced`, predicate(mutated) === false);
  }
  sourceGuard("C1A headers bot HEAD carries accounting", headersSrc,
    (s) => /const headRes = await safeFetch\(probeUrl, \{[\s\S]{0,180}accounting,[\s\S]{0,180}\}\);/.test(s),
    (s) => s.replace(/(const headRes = await safeFetch\(probeUrl, \{[\s\S]{0,180})\s*accounting,\n/, "$1"));
  sourceGuard("C1A headers www HEAD carries accounting", headersSrc,
    (s) => /const wwwRes = await safeFetch\(wwwUrl, \{[\s\S]{0,180}accounting,[\s\S]{0,180}\}\);/.test(s),
    (s) => s.replace(/(const wwwRes = await safeFetch\(wwwUrl, \{[\s\S]{0,180})\s*accounting,\n/, "$1"));
  sourceGuard("C1A rejected modules cannot be marked complete", engineSrc,
    (s) => /settled\?\.status === "fulfilled" && telemetry\.outcomeOf\(settled\.value\) === "ok"[\s\S]{0,220}ctx\.markIncomplete/.test(s),
    (s) => s.replace('settled?.status === "fulfilled" && telemetry.outcomeOf(settled.value) === "ok"', "true"));
  const sslSrc = src("workers", "scan-api", "src", "engines", "ssl-scan.js");
  const subdomainsSrc = src("workers", "scan-api", "src", "engines", "subdomains-scan.js");
  const cloudSrc = src("workers", "scan-api", "src", "engines", "cloud-storage-scan.js");
  sourceGuard("C1B SSL safeFetch leaves carry accounting", sslSrc,
    (s) => /safeFetch\(`https:\/\/\$\{domain\}`,[\s\S]{0,140}accounting/.test(s) && /safeFetch\(httpOrigUrl,[\s\S]{0,120}accounting/.test(s) && /safeFetch\(loc1,[\s\S]{0,120}accounting/.test(s),
    (s) => s.replace(/,\s*accounting/g, ""));
  sourceGuard("C1B SSL CT native fetches are counted", sslSrc,
    (s) => /countedFetch\(\s*`https:\/\/crt\.sh\/\?q=/.test(s) && /countedFetch\(\s*`https:\/\/api\.certspotter\.com\/v1\/issuances/.test(s),
    (s) => s.replace(/countedFetch\(/g, "fetch("));
  sourceGuard("C1B subdomain CT and wildcard DNS carry accounting", subdomainsSrc,
    (s) => /dnsQuery\(wildcardHost, "A", \{ accounting \}\)/.test(s) && /dnsQuery\(wildcardHost, "AAAA", \{ accounting \}\)/.test(s) && /countedFetch\(\s*`https:\/\/crt\.sh\/\?q=/.test(s) && /countedFetch\(\s*`https:\/\/api\.certspotter\.com\/v1\/issuances/.test(s),
    (s) => s.replace('dnsQuery(wildcardHost, "A", { accounting })', 'dnsQuery(wildcardHost, "A")'));
  sourceGuard("C1B brute-force DNS leaves carry accounting", subdomainsSrc,
    (s) => /dnsQuery\(host, "A", \{ accounting \}\)/.test(s) && /dnsQuery\(host, "MX", \{ accounting \}\)/.test(s),
    (s) => s.replace('dnsQuery(host, "MX", { accounting })', 'dnsQuery(host, "MX")'));
  sourceGuard("C1B cloud-storage validation fetches are counted", cloudSrc,
    (s) => /headRes = await countedFetch\(headUrl,[\s\S]{0,120}accounting/.test(s) && /getRes = await countedFetch\(listUrl,[\s\S]{0,120}accounting/.test(s),
    (s) => s.replace(/countedFetch\(listUrl,/, "fetch(listUrl,"));
  sourceGuard("C1B scan-engine threads module contexts", engineSrc,
    (s) => /runSslModule\(domain, \{ accounting, signal \}\)/.test(s) && /runSubdomainsModule\(domain, \{ accounting, signal \}\)/.test(s) && /runBruteforceModule\(domain, \{ accounting, signal \}\)/.test(s) && /runCloudStorageModule\(domain, modules, \{ accounting, signal \}\)/.test(s),
    (s) => s.replace('runSslModule(domain, { accounting, signal })', "runSslModule(domain)"));
  sourceGuard("C1B complete-set includes newly covered modules", budgetSrc,
    (s) => ["ssl", "subdomains", "dns_bruteforce", "cloud_storage_discovery"].every((m) => s.includes(`"${m}"`)),
    (s) => s.replace('"cloud_storage_discovery",', ""));
  sourceGuard("B2 measured module caps exist", budgetSrc,
    (s) => /SCAN_MODULE_BUDGETS/.test(s) && /ssl:\s*9_000/.test(s) && /subdomains:\s*12_000/.test(s) && /asset_exposure:\s*2_500/.test(s),
    (s) => s.replace("asset_exposure:              2_500", "asset_exposure:              8_000"));
  sourceGuard("B2 finalization reserve is explicit in diagnostics", budgetSrc,
    (s) => /finalizationReserveMs:\s*5_000/.test(s) && /finalization_reserve_ms: deadline\?\.finalizationReserveMs/.test(s),
    (s) => s.replace(/finalization_reserve_ms: deadline\?\.finalizationReserveMs \?\? null,\n/, ""));
  sourceGuard("B2 capped runner aborts module child signal", engineSrc,
    (s) => /controller\.abort\("module_budget_exhausted"\)/.test(s) && /ctx\.assertCanIssue/.test(s),
    (s) => s.replace(/controller\.abort\("module_budget_exhausted"\);/g, ""));
  sourceGuard("B2 sequential capped module errors preserve module-shaped results", engineSrc,
    (s) => /takeoverThrown[\s\S]{0,260}takeover_probe_failed/.test(s) && /exposureThrown[\s\S]{0,260}exposure_probe_failed/.test(s) && /cloudThrown[\s\S]{0,260}cloud_storage_probe_failed/.test(s),
    (s) => s.replace("cloud_storage_probe_failed", "cloud_storage_probe_missing"));
  sourceGuard("B2 sequential capped module errors mark outbound incomplete", engineSrc,
    (s) => /takeoverOutbound\?\.markIncomplete\?\.\("module_error"\)/.test(s) && /exposureOutbound\?\.markIncomplete\?\.\("module_error"\)/.test(s) && /cloudOutbound\?\.markIncomplete\?\.\("module_error"\)/.test(s),
    (s) => s.replace('cloudOutbound?.markIncomplete?.("module_error");', ""));
  sourceGuard("B2 incomplete outbound counts remain D1 null", budgetSrc,
    (s) => /outbound_measurement_complete \? snap\.outbound_attempts_observed : null/.test(s),
    (s) => s.replace("outbound_measurement_complete ? snap.outbound_attempts_observed : null", "outbound_attempts_observed"));
  sourceGuard("B2 native counted fetches preserve caller and module signals", subdomainsSrc + "\n" + cloudSrc,
    (s) => (s.match(/function combineSignals\(/g) || []).length >= 2 && !/accounting\?\.signal \|\| init\?\.signal/.test(s),
    (s) => s.replace(/combineSignals\(init\?\.signal, accounting\?\.signal\)/g, "accounting?.signal || init?.signal"));
  sourceGuard("B2 reserved mode is explicitly documented as not B2-covered", engineSrc,
    (s) => /SCAN_CAPACITY_MODE=reserved experiment[\s\S]{0,260}not be treated as[\s\S]{0,120}B2 cancellation\/accounting guarantees/.test(s),
    (s) => s.replace("not be treated as", "be treated as"));
  const frontendFiles = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else frontendFiles.push(p);
    }
  };
  walk(path.join(root, "frontend", "src"));
  const frontendUsesDiagnostics = frontendFiles.some((p) => /outbound_attempts_observed|outbound_measurement_complete/.test(fs.readFileSync(p, "utf8")));
  ok("C1A no customer reader consumes outbound diagnostics", !frontendUsesDiagnostics);
}

console.log(`\nscan-telemetry: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
