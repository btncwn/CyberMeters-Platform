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
const { createModuleTelemetry, createScanDeadline, raceModuleDeadline, buildExecutionDiagnostics, SCAN_EXECUTION_DIAGNOSTICS_VERSION } = await eng("scan-budget.js");
const { persistModuleTelemetry, heartbeatScan } = await eng("scan-engine.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// A monotonic fake clock — each read advances by `step` ms so durations are > 0.
function steppingClock(start = 1_000_000, step = 25) {
  let t = start;
  return () => { const v = t; t += step; return v; };
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
  const dl = createScanDeadline({}, clock); // 21_000 budget from t=0
  t = 1_000; // 20_000 remaining

  let reported = null;
  const v = await raceModuleDeadline(dl, async () => "done", () => "deferred", {
    onStart: (capMs) => { reported = capMs; },
    setTimer: () => null, clearTimer: () => {},
  });
  eq("race resolves module value with onStart present", v, "done");
  eq("onStart reports remaining budget as the cap", reported, 20_000);

  // hardMs narrows the cap — onStart must report the NARROWED value (mutation
  // direction: a call-site re-computation of remainingMs would report 20_000).
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
  eq("deadline budget surfaced", diag.deadline_budget_ms, 21_000);
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

  const empty = buildExecutionDiagnostics({});
  eq("missing context fails safe to null", empty.execution_context, null);
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
  ok("completed report embeds execution_diagnostics",
    /report\.execution_diagnostics = buildExecutionDiagnostics\(\{ executionContext, deadline, telemetry \}\)/.test(engineSrc));
  ok("failed report embeds execution_diagnostics",
    /execution_diagnostics: buildExecutionDiagnostics\(\{ executionContext, deadline, telemetry \}\)/.test(engineSrc));
  ok("finalisation wall time recorded as D1 pseudo-row",
    /telemetry\.record\("scan_finalisation", \{ outcome: "ok", duration_ms: now\(\) - finalizeStartedMs \}\)/.test(engineSrc));
  ok("queue call site passes executionContext queue",
    /doRunScanEngine\([^)]*\{ executionContext: "queue" \}\)/.test(dispatchSrc));
  ok("cron call site passes executionContext cron",
    /runScanEngine\([^)]*\{ executionContext: "cron" \}\)/.test(indexSrc));
  ok("waituntil call site passes executionContext waituntil",
    /runScanEngine\([^)]*\{ executionContext: "waituntil" \}\)/.test(scansSrc));
  ok("cve outbound_calls from technologies_checked (reliable 1:1 counter)",
    /outbound_calls: Array\.isArray\(modules\.cve_intelligence\?\.technologies_checked\) \? modules\.cve_intelligence\.technologies_checked\.length : null/.test(engineSrc));

  // Behaviour-neutrality direction proofs: diagnostics must remain write-only in
  // the engine (assigned into reports, never read back into any decision), and
  // scan_finalisation must never join the tracked-module backfill set.
  const readsBack = engineSrc.split("execution_diagnostics").length - 1;
  eq("engine references execution_diagnostics exactly twice (both writes)", readsBack, 2);
  const trackedArr = engineSrc.slice(engineSrc.indexOf("TELEMETRY_TRACKED_MODULES = Object.freeze(["));
  ok("scan_finalisation is not a tracked module", !trackedArr.slice(0, trackedArr.indexOf("])")).includes("scan_finalisation"));
  ok("buildScanQuality never reads diagnostics", !/buildScanQuality[\s\S]{0,2000}execution_diagnostics/.test(engineSrc.slice(engineSrc.indexOf("export function buildScanQuality"), engineSrc.indexOf("export function buildScanQuality") + 3000)));
}

console.log(`\nscan-telemetry: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
