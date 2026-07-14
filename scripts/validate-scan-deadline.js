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
const { createScanDeadline, markDeadlineDeferred, raceModuleDeadline, SCAN_DEADLINE_DEFAULTS } = await eng("scan-budget.js");
const { createFinalizeLatch, finalizeScanResult, buildScanQuality } = await eng("scan-engine.js");
import fs from "node:fs";

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// A controllable fake clock (ms). tick() advances it; the deadline reads it via now().
function fakeClock(start = 1_000_000) {
  let t = start;
  const now = () => t;
  return { now, tick: (ms) => { t += ms; } };
}

// An env stub recording every R2 put and D1 status write, with injectable failure
// flags (mutable mid-test to simulate transient outages).
function stubEnv(flags = {}) {
  const f = { r2Fail: false, d1Fail: false, ...flags };
  const r2 = [];
  const d1 = [];
  return {
    _r2: r2, _d1: d1, flags: f,
    cybermeters_reports: { put: async (key, body) => { if (f.r2Fail) throw new Error("R2 down"); r2.push({ key, body }); } },
    cybermeters_db: {
      prepare: (sql) => ({
        bind: (...args) => ({ run: async () => { if (f.d1Fail) throw new Error("D1 down"); d1.push({ sql, args }); } }),
      }),
    },
  };
}
// Terminal D1 status of the last scans-UPDATE (the arg bound as `status`).
const lastD1Status = (env) => { const w = env._d1[env._d1.length - 1]; return w ? w.args[0] : null; };

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

// ── 4. Happy path: finalize exactly once; a late promise cannot re-write it ──
{
  const env = stubEnv();
  const latch = createFinalizeLatch();
  const report = { scan_id: "scan_x", status: "completed", scan_quality: { status: "partial" } };

  const first = await finalizeScanResult(latch, { scanId: "scan_x", report, score: 72, rating: "high", status: "completed", env });
  ok("first finalize is durable", first.finalized === true && first.wrote === true);
  eq("latch state finalized", latch.state, "finalized");
  eq("R2 written once", env._r2.length, 1);
  eq("D1 written once", env._d1.length, 1);
  ok("R2 body carries partial quality", JSON.parse(env._r2[0].body).scan_quality.status === "partial");
  eq("D1 status = completed", env._d1[0].args[0], "completed");
  ok("D1 score/rating bound", env._d1[0].args[1] === 72 && env._d1[0].args[2] === "high");

  // A LATE promise re-finalizes → no-op, nothing re-written, state unchanged.
  const late = await finalizeScanResult(latch, { scanId: "scan_x", report: { status: "completed", late: true }, status: "completed", env });
  ok("late finalize is a no-op", late.finalized === true && late.wrote === false && late.reason === "already_finalized");
  eq("R2 still exactly once", env._r2.length, 1);
  eq("D1 still exactly once", env._d1.length, 1);

  // A failed finalize after a durable completion is refused (no downgrade).
  const downgrade = await finalizeScanResult(latch, { scanId: "scan_x", report: { status: "failed" }, status: "failed", env });
  ok("post-completion failed finalize refused", downgrade.wrote === false);
  eq("D1 never got a failed write", env._d1.filter((w) => w.args[0] === "failed").length, 0);
  eq("latch status stays completed", latch.status, "completed");
}

// ── 5 (Issue 1). R2 failure cannot leave the scan silently 'running' ──
// The completed report fails to persist; the engine's failure path then writes a
// consistent 'failed' terminal — D1 is never left non-terminal.
{
  // Model the engine: try completed; if not durable, route to the failed path.
  async function runFinalizeFlow(env) {
    const latch = createFinalizeLatch();
    const completed = { status: "completed" };
    const fin = await finalizeScanResult(latch, { scanId: "scan_r2", report: completed, score: 50, rating: "medium", status: "completed", env });
    if (!fin.finalized) {
      // failure path (mirrors the engine catch): downgrade-safe failed finalize
      await finalizeScanResult(latch, { scanId: "scan_r2", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
    }
    return latch;
  }
  // 5a. R2 permanently down for the big completed report but the small failed report
  //     also cannot be written (R2 fully down) → D1 still ends 'failed', not running.
  {
    const env = stubEnv({ r2Fail: true });
    const latch = await runFinalizeFlow(env);
    ok("R2 down: no completed report persisted", env._r2.length === 0);
    ok("R2 down: D1 still received a terminal write", env._d1.length >= 1);
    eq("R2 down: D1 terminal status is failed (never left running)", lastD1Status(env), "failed");
    eq("R2 down: latch status failed", latch.status, "failed");
  }
  // 5b. The big completed report fails transiently; the small failed report succeeds
  //     → consistent failed terminal in BOTH R2 and D1.
  {
    const env = stubEnv({ r2Fail: true });
    const latch = createFinalizeLatch();
    const fin = await finalizeScanResult(latch, { scanId: "scan_r2b", report: { status: "completed" }, score: 50, rating: "medium", status: "completed", env });
    ok("completed report did not persist", fin.finalized === false && env._r2.length === 0);
    env.flags.r2Fail = false; // R2 recovers for the small failed report
    await finalizeScanResult(latch, { scanId: "scan_r2b", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
    eq("recovered: R2 has a failed report", JSON.parse(env._r2[0].body).status, "failed");
    eq("recovered: D1 terminal status failed", lastD1Status(env), "failed");
    eq("recovered: durably finalized", latch.state, "finalized");
  }
}

// ── 6 (Issue 1). D1 failure after a successful R2 completed report is recoverable ──
// The completed report IS durable; D1 write flakes. Recovery must NOT downgrade (never
// overwrite the good R2 report with a failed one) and must converge D1 to completed.
{
  // 6a. D1 stays down: completed R2 report is preserved (reconciler backstop), D1 not
  //     forced to 'failed', and the outcome is auditable (latch keeps completed intent).
  {
    const env = stubEnv({ d1Fail: true });
    const latch = createFinalizeLatch();
    const fin = await finalizeScanResult(latch, { scanId: "scan_d1", report: { status: "completed", scan_quality: { status: "complete" } }, score: 88, rating: "low", status: "completed", env });
    ok("completed R2 report is durable", latch.r2Written === true && env._r2.length === 1);
    ok("D1 write did not land", fin.finalized === false && latch.d1Written === false);
    // failure path with the downgrade guard:
    await finalizeScanResult(latch, { scanId: "scan_d1", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
    eq("R2 completed report was NOT overwritten with a failed one", env._r2.length, 1);
    eq("R2 still holds the completed report", JSON.parse(env._r2[0].body).status, "completed");
    ok("D1 never written to 'failed'", env._d1.filter((w) => w.args[0] === "failed").length === 0);
    eq("latch intent stays completed (auditable, reconciler-recoverable)", latch.status, "completed");
  }
  // 6b. D1 recovers on the recovery attempt → converges to completed (not failed).
  {
    const env = stubEnv({ d1Fail: true });
    const latch = createFinalizeLatch();
    await finalizeScanResult(latch, { scanId: "scan_d1b", report: { status: "completed" }, score: 88, rating: "low", status: "completed", env });
    env.flags.d1Fail = false; // D1 recovers
    const rec = await finalizeScanResult(latch, { scanId: "scan_d1b", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
    ok("recovery converges to durable finalized", rec.finalized === true && latch.state === "finalized");
    eq("D1 terminal status is completed (never downgraded)", lastD1Status(env), "completed");
    eq("R2 has exactly one (completed) report", env._r2.length, 1);
    eq("R2 report is the completed one", JSON.parse(env._r2[0].body).status, "completed");
  }
}

// ── 6c (Issue 1). A failed first finalization does not permanently block recovery ──
// The old latch set closed=true before the writes, so a throwing first attempt made the
// catch's `if (closed) return` suppress the failure path → orphan. Prove that's gone.
{
  const env = stubEnv({ r2Fail: true, d1Fail: true });
  const latch = createFinalizeLatch();
  const first = await finalizeScanResult(latch, { scanId: "scan_blk", report: { status: "completed" }, score: 10, rating: "high", status: "completed", env });
  ok("first attempt not finalized (both writes down)", first.finalized === false);
  ok("latch NOT stuck 'finalized' after a failed attempt", latch.state !== "finalized");
  // Everything recovers; the failure path must still be able to write a terminal state.
  env.flags.r2Fail = false; env.flags.d1Fail = false;
  const recovery = await finalizeScanResult(latch, { scanId: "scan_blk", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
  ok("failure path was NOT suppressed by the earlier attempt", recovery.finalized === true);
  eq("terminal D1 status written on recovery", lastD1Status(env), "failed");
  eq("durably finalized after recovery", latch.state, "finalized");
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

// A synchronous fake timer: firing the deadline immediately models "cap reached"
// deterministically (no real wall-clock). clearTimer is a no-op sink.
const syncTimer = { setTimer: (fn) => { fn(); return {}; }, clearTimer: () => {} };
// A never-firing timer: models "the phase finished before the cap".
let neverCleared = 0;
const neverTimer = { setTimer: () => ({}), clearTimer: () => { neverCleared++; } };

// ── 8 (Issue 2). raceModuleDeadline BOUNDS a launched phase, not just its start ──
{
  // 8a. Phase completes before the cap → its real value passes through; cap cleared.
  {
    const dl = createScanDeadline({}, fakeClock().now);
    const res = await raceModuleDeadline(dl, async () => ({ checked: 5, real: true }), () => markDeadlineDeferred({}), neverTimer);
    ok("completes in budget → real value returned", res.real === true && res.checked === 5);
    ok("the timer was cleared (no leak)", neverCleared >= 1);
  }
  // 8b. Phase OVERRUNS the cap → honest deferred result, underlying promise abandoned.
  {
    const dl = createScanDeadline({}, fakeClock().now);
    let lateSideEffect = 0;
    const overrun = () => new Promise(() => {}).then(() => { lateSideEffect++; }); // never settles
    const res = await raceModuleDeadline(dl, overrun, () => markDeadlineDeferred({ checked: 0, assets: [], source: "http_probe" }), syncTimer);
    eq("overrun → deferred outcome", res.outcome, "deadline_exceeded");
    eq("overrun → incomplete (never a clean result)", res.incomplete, true);
    eq("overrun → underlying side effect did not run", lateSideEffect, 0);
  }
  // 8c. No budget left → defers immediately WITHOUT launching (setTimer never called).
  {
    const c = fakeClock();
    const dl = createScanDeadline({}, c.now);
    c.tick(25_000); // past the 21s budget
    let launched = 0;
    const res = await raceModuleDeadline(dl, async () => { launched++; return { real: true }; }, () => markDeadlineDeferred({}), { setTimer: () => { throw new Error("must not schedule"); }, clearTimer: () => {} });
    eq("no budget → deferred", res.outcome, "deadline_exceeded");
    eq("no budget → phase not even launched via timer path", launched, 0);
  }
  // 8d. A phase that REJECTS propagates its error (caller's try/catch still works).
  {
    const dl = createScanDeadline({}, fakeClock().now);
    let threw = false;
    try { await raceModuleDeadline(dl, async () => { throw new Error("module boom"); }, () => markDeadlineDeferred({}), neverTimer); }
    catch (e) { threw = e.message === "module boom"; }
    ok("module rejection propagates through the race", threw);
  }
}

// ── 9 (Issue 2). A late underlying promise cannot mutate finalized state ──
// Models the exposure race timing out, the engine finalizing, THEN the abandoned probe
// promise resolving — it must not touch R2/D1 or the latch.
{
  const env = stubEnv();
  const latch = createFinalizeLatch();
  let resolveLate;
  const lateProbe = new Promise((r) => { resolveLate = r; });
  const dl = createScanDeadline({}, fakeClock().now);

  // Exposure launched but overruns → deferred; underlying probe still pending.
  const exposure = await raceModuleDeadline(dl, () => lateProbe, () => markDeadlineDeferred({ checked: 0, reachable: 0, assets: [], source: "http_probe" }), syncTimer);
  eq("exposure deferred", exposure.outcome, "deadline_exceeded");

  // Engine finalizes partial (exposure deferred) — terminal, durable.
  const modules = { dns: { resolves: true }, asset_exposure: exposure };
  const report = { status: "completed", scan_quality: buildScanQuality(modules) };
  await finalizeScanResult(latch, { scanId: "scan_late", report, score: 40, rating: "medium", status: "completed", env });
  eq("finalized once", env._d1.length, 1);
  eq("terminal status completed", lastD1Status(env), "completed");
  eq("scan_quality partial (exposure deferred)", report.scan_quality.status, "partial");

  // NOW the abandoned probe resolves late — it must not re-write R2/D1 or reopen the latch.
  resolveLate({ assets: [{ host: "late.example" }] });
  await Promise.resolve();
  eq("late promise did NOT add an R2 write", env._r2.length, 1);
  eq("late promise did NOT add a D1 write", env._d1.length, 1);
  eq("latch still finalized", latch.state, "finalized");
}

// ── 10 (Issue 2, REQUIRED). Phase 1 eats most of the budget; a later module overruns;
//     the engine still reaches terminal finalization; the scan finishes partial, not running.
{
  const c = fakeClock();
  const dl = createScanDeadline({}, c.now);          // 21s budget, measured from entry (t=0)
  c.tick(14_000);                                    // Phase 1 + discovery consumed 14s

  // Asset exposure launches (canRun true at 14s: 14+6<21) but its probes need ~8s and
  // would finish at ~22s — past the deadline. The race bounds it to the 7s remaining.
  ok("exposure is allowed to START at 14s", dl.canRun(6_000) === true);
  const exposure = await raceModuleDeadline(dl, () => new Promise(() => {}), () => markDeadlineDeferred({ checked: 0, reachable: 0, assets: [], source: "http_probe" }), syncTimer);
  eq("overrunning exposure is bounded → deferred", exposure.outcome, "deadline_exceeded");

  // Finalization runs within the reserved window and writes a terminal state.
  const env = stubEnv();
  const latch = createFinalizeLatch();
  const modules = {
    dns: { resolves: true }, ssl: { grade: "A" }, headers: { present: true }, email_security: { spf: true },
    asset_exposure: exposure,   // deferred
  };
  const scanQuality = buildScanQuality(modules);
  const report = { status: "completed", scan_quality: scanQuality, modules };
  const fin = await finalizeScanResult(latch, { scanId: "scan_req", report, score: 55, rating: "medium", status: "completed", env });

  ok("engine reached DURABLE terminal finalization", fin.finalized === true && latch.state === "finalized");
  eq("D1 terminal status written (never left running)", lastD1Status(env), "completed");
  eq("R2 terminal report written", env._r2.length, 1);
  eq("scan finished PARTIAL (honest), not clean", scanQuality.status, "partial");
  ok("the overran module is reported incomplete, not clean", modules.asset_exposure.incomplete === true);
  // Reserved finalization headroom exists: budget 21s leaves >=6s to the ~30s cliff.
  ok("finalization reserve >= 6s under the cliff", 30_000 - dl.budgetMs >= 6_000);
}

// ── 11. Source wiring: the deadline is created at engine entry and BOUNDS each network
//     phase (not merely gates its start); finalization is latched + durable. ──
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
  ok("deadline created from injected clock at engine entry", /const deadline = createScanDeadline\(env, now\)/.test(src));
  ok("now() seam defaults to Date.now (true engine entry)", /opts\.now === "function" \? opts\.now : Date\.now/.test(src));
  const raceCount = (src.match(/raceModuleDeadline\(/g) || []).length;
  ok(`network phases are bounded by raceModuleDeadline (found ${raceCount} >= 4: takeover/exposure/phase5/cloud-storage)`, raceCount >= 4);
  ok("finalize checks durable state, not a pre-write flag", /latch\.state === "finalized"/.test(src) && !/latch\.closed/.test(src));
  ok("success path throws to recovery when not durably finalized", /if \(!finalized\.finalized\)/.test(src));
}

console.log(`\nscan-deadline: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
