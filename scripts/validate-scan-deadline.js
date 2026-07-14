#!/usr/bin/env node
//
// Scan deadline + honest partial finalization (Tier 1: waitUntil-cancellation guard).
//
// Proven root cause: the scan engine runs inside ctx.waitUntil(); Cloudflare cancels
// that background promise ~30s after the response is sent (invocation record:
// wallTime 31170ms / cpuTime 40ms / outcome "ok" / log "waitUntil() tasks did not
// complete ... have been cancelled"). This suite proves the fix's contracts:
//
//   1. the deadline math is a wall-clock budget below the ~30s cliff
//   2. a deadline-deferred module is reported HONESTLY (never a fake clean result)
//      and forces scan_quality "partial"
//   3. completed-module results SURVIVE alongside deferred ones
//   4. finalization writes R2 + flips D1 status EXACTLY ONCE (latched, idempotent)
//   5. a LATE promise cannot overwrite a finalized result
//   6. a post-completion error cannot DOWNGRADE a completed scan to failed
//   7. the fast path (elapsed < budget) defers nothing → scan_quality "complete"
//
// Node 24+. CI-blocking.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { createScanDeadline, markDeadlineDeferred, SCAN_DEADLINE_DEFAULTS } = await eng("scan-budget.js");
const { createFinalizeLatch, finalizeScanResult, buildScanQuality } = await eng("scan-engine.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// A controllable fake clock (ms). tick() advances it; the deadline reads it via now().
function fakeClock(start = 1_000_000) {
  let t = start;
  const now = () => t;
  return { now, tick: (ms) => { t += ms; } };
}

// A minimal env stub recording every R2 put and D1 status write.
function stubEnv() {
  const r2 = [];
  const d1 = [];
  return {
    _r2: r2, _d1: d1,
    cybermeters_reports: { put: async (key, body) => { r2.push({ key, body }); } },
    cybermeters_db: {
      prepare: (sql) => ({
        bind: (...args) => ({ run: async () => { d1.push({ sql, args }); } }),
      }),
    },
  };
}

// ── 1. Deadline math: budget clamps below the ~30s cliff; exceeded()/canRun() ──
{
  const c = fakeClock();
  const dl = createScanDeadline({}, c.now);
  eq("default budget = 21s", dl.budgetMs, 21_000);
  ok("default budget is below the 30s waitUntil cliff", dl.budgetMs <= SCAN_DEADLINE_DEFAULTS.maxBudgetMs && dl.budgetMs < 30_000);
  ok("fresh deadline not exceeded", dl.exceeded() === false);
  ok("fresh deadline can run a 6s phase", dl.canRun(6_000) === true);
  c.tick(16_000); // 16s elapsed
  ok("at 16s, an 8s phase can NOT fit 21s budget", dl.canRun(8_000) === false);
  ok("at 16s, a 4s phase still fits", dl.canRun(4_000) === true);
  c.tick(6_000); // 22s elapsed → past budget
  ok("at 22s, deadline exceeded", dl.exceeded() === true);
  ok("at 22s, remaining is 0", dl.remainingMs() === 0);
}

// ── 1b. Env override is clamped into the safe band ──
{
  const c = fakeClock();
  eq("over-cliff override clamps to max", createScanDeadline({ SCAN_DEADLINE_MS: 90_000 }, c.now).budgetMs, SCAN_DEADLINE_DEFAULTS.maxBudgetMs);
  eq("tiny override clamps to min", createScanDeadline({ SCAN_DEADLINE_MS: 100 }, c.now).budgetMs, SCAN_DEADLINE_DEFAULTS.minBudgetMs);
  eq("garbage override → default", createScanDeadline({ SCAN_DEADLINE_MS: "nonsense" }, c.now).budgetMs, SCAN_DEADLINE_DEFAULTS.budgetMs);
}

// ── 2. Deferred module is honest, never a clean result ──
{
  const kev = markDeadlineDeferred({ matches: [], checked: 0, matched: 0, source: "cisa_kev" });
  eq("deferred: executed false", kev.executed, false);
  eq("deferred: incomplete true", kev.incomplete, true);
  eq("deferred: outcome deadline_exceeded", kev.outcome, "deadline_exceeded");
  eq("deferred: reason scan_deadline_exhausted", kev.reason, "scan_deadline_exhausted");
  ok("deferred: base empty shape preserved (no fake findings)", Array.isArray(kev.matches) && kev.matches.length === 0);
  ok("deferred: has NO clean/ok signal", kev.outcome !== "ok" && kev.error === undefined);
}

// ── 3. Deferred module forces scan_quality 'partial'; completed modules survive ──
{
  const modules = {
    dns:            { resolves: true },                       // completed, healthy
    ssl:            { grade: "A" },                            // completed, healthy
    headers:        { present: true },                        // completed, healthy
    email_security: { spf: true },                            // completed, healthy
    known_exploited_vulnerabilities: markDeadlineDeferred({ matches: [], checked: 0, matched: 0, source: "cisa_kev" }),
  };
  const q = buildScanQuality(modules);
  eq("deferred non-core module → scan_quality partial", q.status, "partial");
  ok("deferred module listed as skipped", q.modules_skipped.includes("known_exploited_vulnerabilities"));
  ok("a warning names the incomplete module", q.warnings.some((w) => /known_exploited_vulnerabilities/.test(w)));
  // Completed modules are untouched and still present with their real values.
  eq("completed dns survives", modules.dns.resolves, true);
  eq("completed ssl survives", modules.ssl.grade, "A");
}

// ── 4/5/6. Finalization latch: exactly-once, late-write drop, no downgrade ──
{
  const env = stubEnv();
  const latch = createFinalizeLatch();
  const report = { scan_id: "scan_x", status: "completed", scan_quality: { status: "partial" } };

  const first = await finalizeScanResult(latch, { scanId: "scan_x", report, score: 72, rating: "high", status: "completed", env });
  ok("first finalize writes", first.written === true);
  eq("R2 written once", env._r2.length, 1);
  eq("D1 written once", env._d1.length, 1);
  ok("R2 report body carries partial quality", /"status": "partial"|"status":"partial"/.test(env._r2[0].body) || JSON.parse(env._r2[0].body).scan_quality.status === "partial");
  ok("D1 status arg = completed", env._d1[0].args[0] === "completed");
  ok("D1 score/rating bound", env._d1[0].args[1] === 72 && env._d1[0].args[2] === "high");

  // 5. A LATE promise tries to finalize again → dropped, nothing re-written.
  const late = await finalizeScanResult(latch, { scanId: "scan_x", report: { status: "completed", late: true }, score: 0, rating: "x", status: "completed", env });
  ok("late finalize is refused", late.written === false && late.reason === "already_finalized");
  eq("R2 still written exactly once after late attempt", env._r2.length, 1);
  eq("D1 still written exactly once after late attempt", env._d1.length, 1);

  // 6. A failed-state finalize after completion is refused (no downgrade).
  const downgrade = await finalizeScanResult(latch, { scanId: "scan_x", report: { status: "failed" }, status: "failed", env });
  ok("post-completion failed finalize refused (no downgrade)", downgrade.written === false);
  eq("D1 never got a 'failed' write", env._d1.filter((w) => w.args[0] === "failed").length, 0);
  eq("latch status stays completed", latch.status, "completed");
}

// ── 6b. Failed-first path: latch closes to failed, and a later completed write is dropped ──
// (mirrors the engine ordering: catch closes the latch to 'failed'; nothing overwrites it.)
{
  const env = stubEnv();
  const latch = createFinalizeLatch();
  const failed = await finalizeScanResult(latch, { scanId: "scan_y", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
  ok("failed finalize writes once", failed.written === true && env._d1[0].args[0] === "failed");
  const resurrect = await finalizeScanResult(latch, { scanId: "scan_y", report: { status: "completed" }, status: "completed", env });
  ok("cannot resurrect a failed scan to completed via a late write", resurrect.written === false);
  eq("D1 written exactly once for failed scan", env._d1.length, 1);
}

// ── 7. Fast path: elapsed < budget → no deferral → scan_quality complete ──
{
  const c = fakeClock();
  const dl = createScanDeadline({}, c.now);
  c.tick(13_000); // a healthy 13s scan
  ok("fast path: takeover (4s) still fits", dl.canRun(4_000) === true);
  ok("fast path: exposure (6s) still fits", dl.canRun(6_000) === true);
  ok("fast path: deadline not exceeded", dl.exceeded() === false);
  // With every module completing normally, scan_quality is 'complete'.
  const modules = {
    dns: { resolves: true }, ssl: { grade: "A" }, headers: { present: true }, email_security: { spf: true },
    known_exploited_vulnerabilities: { matches: [], checked: 1638, matched: 0, source: "cisa_kev" },
  };
  eq("fast path: scan_quality complete", buildScanQuality(modules).status, "complete");
}

console.log(`\nscan-deadline: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
