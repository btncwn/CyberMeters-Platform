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
const { createModuleTelemetry } = await eng("scan-budget.js");
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

console.log(`\nscan-telemetry: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
