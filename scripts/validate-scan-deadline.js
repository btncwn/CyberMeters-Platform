#!/usr/bin/env node
//
// Scan deadline + honest partial finalization (Tier 1: invocation safety guard).
//
// Proven root cause: the scan engine runs inside ctx.waitUntil(); Cloudflare cancels
// that background promise ~30s after the response is sent (invocation record:
// wallTime 31170ms / cpuTime 40ms / outcome "ok" / log "waitUntil() tasks did not
// complete ... have been cancelled"). This suite proves the fix's contracts:
//
//   1. waitUntil/unknown retain the 19s profile while Queue/Cron use the bounded
//      120s durable-invocation safety profile
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
import { importMutant, registerMutants } from "./lib/mutant-import.mjs";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const scanEnginePath = path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js");
registerMutants([{
  id: "A3-E1-call-status-instead-of-effective-status",
  from: '        if (effStatus === "completed") {',
  to: '        if (status === "completed") {',
}]);
const {
  createScanDeadline,
  markDeadlineDeferred,
  PhysicalSubrequestCounter,
  raceModuleDeadline,
  SCAN_DEADLINE_DEFAULTS,
  SCAN_DURABLE_INVOCATION_DEADLINE_DEFAULTS,
  SCAN_DURABLE_PHASE5_MODULE_BUDGETS,
  SCAN_MODULE_BUDGETS,
} = await eng("scan-budget.js");
const {
  buildScanQuality,
  createFinalizeLatch,
  createInvocationProviderGuard,
  finalizeScanResult,
  runScanEngine,
} = await eng("scan-engine.js");
const { sendLifecycleEmail } = await import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "lib", "lifecycle-email.js",
)).href);
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

function makePostTerminalEngineFixture({
  failFirstTerminalReport = false,
  onPostTerminalHold = null,
} = {}) {
  let terminalStatus = null;
  let terminalReportAttempts = 0;
  let heldPostTerminalLaunches = 0;
  let releaseHeld;
  const calls = [];
  const statement = (sql) => {
    let args = [];
    return {
      sql,
      bind(...values) { args = values; return this; },
      async first() { calls.push({ kind: "first", sql, args }); return null; },
      async all() { calls.push({ kind: "all", sql, args }); return { results: [] }; },
      run() {
        calls.push({ kind: "run", sql, args });
        if (/UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(sql)) {
          terminalStatus = args[0];
          return Promise.resolve({ meta: { changes: 1 } });
        }
        if (/INSERT INTO audit_events/.test(sql)) {
          return Promise.resolve({ meta: { changes: 1 } });
        }
        if (terminalStatus != null && releaseHeld == null) {
          heldPostTerminalLaunches += 1;
          const held = new Promise((resolve) => { releaseHeld = () => resolve({ meta: { changes: 1 } }); });
          onPostTerminalHold?.();
          return held;
        }
        return Promise.resolve({ meta: { changes: 1 } });
      },
    };
  };
  const env = {
    SCAN_CAPACITY_MODE: "legacy",
    RESEND_API_KEY: "fixture-resend-key",
    cybermeters_db: {
      prepare: statement,
      async batch(statements) {
        calls.push({ kind: "batch" });
        return Promise.all(statements.map((entry) => entry.run()));
      },
    },
    cybermeters_reports: {
      async put(key) {
        calls.push({ kind: "r2_put", key });
        terminalReportAttempts += 1;
        if (failFirstTerminalReport && terminalReportAttempts === 1) {
          throw new Error("fixture terminal report refusal");
        }
        return {};
      },
      async get() { calls.push({ kind: "r2_get" }); return null; },
      async delete() { calls.push({ kind: "r2_delete" }); return {}; },
    },
  };
  return {
    env,
    calls,
    get terminalStatus() { return terminalStatus; },
    get terminalReportAttempts() { return terminalReportAttempts; },
    get heldPostTerminalLaunches() { return heldPostTerminalLaunches; },
    releaseHeld() { releaseHeld?.(); },
  };
}

const exhaustedPhysicalCounter = () => {
  const counter = new PhysicalSubrequestCounter({ limit: 1, safetyMargin: 0 });
  counter.contextFor("deadline_fixture_precharge").recordAttempt();
  return counter;
};

const withEngineFetchFixture = async (run) => {
  const previousFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async (input) => {
    fetches += 1;
    const url = String(input);
    if (/dns\.google\/resolve|cloudflare-dns\.com\/dns-query/.test(url)) {
      return Response.json({ Status: 0, Answer: [] });
    }
    if (/crt\.sh|certspotter/.test(url)) return Response.json([]);
    if (/services\.nvd\.nist\.gov/.test(url)) return Response.json({ vulnerabilities: [] });
    return new Response("<html><title>Fixture</title></html>", {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  };
  try {
    return await run(() => fetches);
  } finally {
    globalThis.fetch = previousFetch;
  }
};

// A real lifecycle claim held across freeze must never resume into Resend. The
// underlying INSERT can be uncancellable, so its honest ledger state is pending
// and reconciliation/retry owned; no accepted delivery is claimed.
{
  const c = fakeClock();
  const deadline = createScanDeadline({}, c.now, { executionContext: "queue" });
  let releaseInsert;
  let signalInsertStarted;
  const insertStarted = new Promise((resolve) => { signalInsertStarted = resolve; });
  let inserts = 0;
  let updates = 0;
  let ledgerStatus = null;
  const sourceEnv = {
    RESEND_API_KEY: "fixture-resend-key",
    HELLO_EMAIL_FROM: "hello@fixture.example",
    FRONTEND_URL: "https://app.fixture.example",
    cybermeters_db: {
      prepare(sql) {
        let args = [];
        return {
          bind(...values) { args = values; return this; },
          async first() { return null; },
          run() {
            if (/INSERT INTO lifecycle_email_events/.test(sql)) {
              inserts += 1;
              ledgerStatus = "pending";
              signalInsertStarted();
              return new Promise((resolve) => { releaseInsert = () => resolve({ meta: { changes: 1 } }); });
            }
            if (/UPDATE lifecycle_email_events/.test(sql)) {
              updates += 1;
              ledgerStatus = args[0];
            }
            return Promise.resolve({ meta: { changes: 1 } });
          },
        };
      },
    },
    cybermeters_reports: {},
  };
  const guard = createInvocationProviderGuard(sourceEnv, deadline);
  const previousFetch = globalThis.fetch;
  let externalFetches = 0;
  globalThis.fetch = async () => {
    externalFetches += 1;
    return Response.json({ id: "provider-accepted" });
  };
  let result;
  try {
    const sending = sendLifecycleEmail(guard.env, {
      type: "lifecycle_first_scan_completed",
      workspace_id: "workspace-fixture",
      domain: "fixture.example",
      to: "owner@fixture.example",
      scan_quality: "complete",
    });
    await insertStarted;
    c.tick(deadline.totalCeilingMs);
    deadline.markTotalExceeded();
    const frozen = guard.freeze();
    releaseInsert();
    result = await sending;
    const after = guard.snapshot();
    eq("held lifecycle claim is recorded as an unknown mutation",
      frozen.in_flight_mutation_outcome_unknown_count, 1);
    eq("late D1 completion is refused before customer email",
      after.late_completions_refused, 1);
    ok("external side-effect admission closes with the invocation",
      guard.env.RESEND_API_KEY === undefined && guard.snapshot().external_side_effects_refused >= 1);
  } finally {
    globalThis.fetch = previousFetch;
  }
  eq("held lifecycle claim launches no Resend request after freeze", externalFetches, 0);
  ok("held lifecycle send is never reported accepted", result?.sent !== true);
  eq("uncancellable lifecycle claim remains honestly retryable", ledgerStatus, "pending");
  eq("no false sent/failed ledger update launches after freeze", updates, 0);
  eq("exactly one underlying idempotency claim was issued", inserts, 1);
}

// Resend's own fetch timeout is 10s. Queue/Cron must stop admitting a new send
// once fewer than 12s remain, leaving two seconds for response handling and the
// delivery-ledger write rather than accepting work the invocation cannot close.
{
  const c = fakeClock();
  const deadline = createScanDeadline({}, c.now, { executionContext: "queue" });
  const guard = createInvocationProviderGuard({ RESEND_API_KEY: "fixture-resend-key" }, deadline);
  c.tick(deadline.totalCeilingMs - 12_000);
  eq("external effect remains admissible at the exact 12s boundary",
    guard.env.RESEND_API_KEY, "fixture-resend-key");
  c.tick(1);
  eq("external effect is refused below the 12s response-and-ledger floor",
    guard.env.RESEND_API_KEY, undefined);
  eq("side-effect floor is explicit in provider telemetry",
    guard.snapshot().external_side_effect_min_total_remaining_ms, 12_000);
  ok("side-effect floor refusal is counted",
    guard.snapshot().external_side_effects_refused >= 1);
}

// An env stub recording every R2 put and D1 status write, with injectable failure
// flags (mutable mid-test to simulate transient outages).
function stubEnv(flags = {}) {
  const f = { r2Fail: false, d1Fail: false, auditFail: false, ...flags };
  const r2 = [];
  const d1 = [];
  const audits = [];
  const batches = [];
  const db = {
    prepare: (sql) => {
      let args = [];
      return {
        sql,
        bind(...values) { args = values; return this; },
        async run() {
          if (f.d1Fail) throw new Error("D1 down");
          if (/UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(sql)) {
            d1.push({ sql, args });
            return { meta: { changes: 1 } };
          }
          if (/INSERT INTO audit_events/.test(sql)) {
            if (f.auditFail) throw new Error("audit insert down");
            if (!audits.some((row) => row.id === args[0])) {
              audits.push({ id: args[0], workspace_id: args[1], scan_id: args[2], args, sql });
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }
          return { meta: { changes: 0 } };
        },
      };
    },
    async batch(statements) {
      batches.push(statements.length);
      const d1Length = d1.length;
      const auditLength = audits.length;
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        return results;
      } catch (error) {
        d1.length = d1Length;
        audits.length = auditLength;
        throw error;
      }
    },
  };
  return {
    _r2: r2, _d1: d1, _audits: audits, _batches: batches, flags: f,
    cybermeters_reports: { put: async (key, body) => { if (f.r2Fail) throw new Error("R2 down"); r2.push({ key, body }); } },
    cybermeters_db: db,
  };
}
// Terminal D1 status of the last scans-UPDATE (the arg bound as `status`).
const lastD1Status = (env) => { const w = env._d1[env._d1.length - 1]; return w ? w.args[0] : null; };

// ── 1. Legacy deadline math is byte-compatible for unknown/waitUntil ──────
{
  const c = fakeClock();
  const dl = createScanDeadline({}, c.now);
  eq("default executable budget = 19s", dl.budgetMs, 19_000);
  eq("default total ceiling = 24s", dl.totalCeilingMs, 24_000);
  eq("default finalization reserve = 5s", dl.finalizationReserveMs, 5_000);
  ok("default ceiling is below the 30s waitUntil cliff", dl.totalCeilingMs < 30_000);
  ok("fresh deadline not exceeded", dl.exceeded() === false);
  ok("fresh deadline can run measured subdomain cap", dl.canRun(SCAN_MODULE_BUDGETS.subdomains) === true);
  c.tick(16_000); // 16s elapsed
  ok("at 16s, ssl cap can NOT fit 19s executable budget", dl.canRun(SCAN_MODULE_BUDGETS.ssl) === false);
  ok("at 16s, asset exposure cap still fits", dl.canRun(SCAN_MODULE_BUDGETS.asset_exposure) === true);
  c.tick(6_000); // 22s elapsed → past budget
  ok("at 22s, deadline exceeded", dl.exceeded() === true);
  ok("at 22s, remaining is 0", dl.remainingMs() === 0);

  const waituntil = createScanDeadline({}, c.now, { executionContext: "waituntil" });
  eq("explicit waitUntil executable budget remains 19s", waituntil.budgetMs, 19_000);
  eq("explicit waitUntil total ceiling remains 24s", waituntil.totalCeilingMs, 24_000);
  eq("explicit waitUntil finalization reserve remains 5s", waituntil.finalizationReserveMs, 5_000);

  const unrecognised = createScanDeadline({}, c.now, { executionContext: "future-context" });
  eq("unrecognised context fails closed to 19s", unrecognised.budgetMs, 19_000);
}

// ── 1b. Queue/Cron get the bounded durable-invocation profile ───────────
{
  for (const executionContext of ["queue", "cron"]) {
    const c = fakeClock();
    const dl = createScanDeadline({}, c.now, { executionContext });
    eq(`${executionContext}: executable budget = 115s`, dl.budgetMs, 115_000);
    eq(`${executionContext}: total ceiling = 120s`, dl.totalCeilingMs, 120_000);
    eq(`${executionContext}: finalization reserve = 5s`, dl.finalizationReserveMs, 5_000);
    for (const elapsed of [30_000, 60_000, 90_000]) {
      const clock = fakeClock();
      const measured = createScanDeadline({}, clock.now, { executionContext });
      clock.tick(elapsed);
      ok(`${executionContext}: ${elapsed / 1000}s still admits the largest module cap`,
        measured.canRun(SCAN_MODULE_BUDGETS.subdomains) === true);
    }
    c.tick(115_000);
    ok(`${executionContext}: 115s reaches the executable safety net`, dl.exceeded() === true);
    eq(`${executionContext}: 115s leaves zero executable budget`, dl.remainingMs(), 0);
    eq(`${executionContext}: reserve remains available at executable cutoff`, dl.totalRemainingMs(), 5_000);
  }
  eq("durable CVE cap covers three 10s leaves plus pacing", SCAN_DURABLE_PHASE5_MODULE_BUDGETS.cve_intelligence, 32_000);
  eq("durable KEV cap covers its 10s effective HTTP leaf", SCAN_DURABLE_PHASE5_MODULE_BUDGETS.known_exploited_vulnerabilities, 12_000);
  eq("durable Email Intelligence cap covers 10s/6s parallel leaves", SCAN_DURABLE_PHASE5_MODULE_BUDGETS.email_security_intelligence, 12_000);
  eq("durable Phase-5 launch estimate is max, not sum",
    Math.max(...Object.values(SCAN_DURABLE_PHASE5_MODULE_BUDGETS)), 32_000);
  ok("durable Phase-5 max leaves global finalization headroom",
    Math.max(...Object.values(SCAN_DURABLE_PHASE5_MODULE_BUDGETS))
      < SCAN_DURABLE_INVOCATION_DEADLINE_DEFAULTS.budgetMs);

  const reserveClock = fakeClock();
  const reserveDeadline = createScanDeadline({}, reserveClock.now, { executionContext: "queue" });
  reserveClock.tick(reserveDeadline.budgetMs);
  let reserveTimerMs = null;
  let terminalWriteStarted = 0;
  const reserveResult = await reserveDeadline.raceToTotal(
    async () => { terminalWriteStarted += 1; return "terminal-written"; },
    () => "ceiling-refused",
    {
      setTimer: (_fn, ms) => { reserveTimerMs = ms; return {}; },
      clearTimer: () => {},
    },
  );
  eq("durable executable cutoff exposes exactly the 5s terminal-write reserve",
    reserveTimerMs, 5_000);
  eq("terminal write can still start inside the dedicated reserve", terminalWriteStarted, 1);
  eq("terminal write settling inside reserve wins the total-ceiling race",
    reserveResult, "terminal-written");
  reserveClock.tick(5_000);
  let postCeilingLaunches = 0;
  const refused = await reserveDeadline.raceToTotal(
    async () => { postCeilingLaunches += 1; return "unsafe"; },
    () => "ceiling-refused",
  );
  eq("work is refused once the full 120s invocation ceiling is spent",
    refused, "ceiling-refused");
  eq("no write is launched after the total ceiling", postCeilingLaunches, 0);
}

// ── 1b-ii. Queue/Cron arm both the executable watchdog and total ceiling ───
{
  for (const executionContext of ["queue", "cron"]) {
    const c = fakeClock();
    const dl = createScanDeadline({}, c.now, { executionContext });
    let executableTimer = null, totalTimer = null;
    let executableDelay = null, totalDelay = null;
    const armed = dl.arm({
      setTimer(fn, ms) { executableTimer = fn; executableDelay = ms; return { unref() {} }; },
      clearTimer() {},
      setTotalTimer(fn, ms) { totalTimer = fn; totalDelay = ms; return { unref() {} }; },
      clearTotalTimer() {},
    });
    ok(`${executionContext}: watchdog pair arms`, armed === true);
    eq(`${executionContext}: executable watchdog is 115s`, executableDelay, 115_000);
    eq(`${executionContext}: invocation watchdog is 120s`, totalDelay, 120_000);
    executableTimer();
    ok(`${executionContext}: executable watchdog aborts provider signal`, dl.signal.aborted === true);
    eq(`${executionContext}: executable abort owner is global deadline`,
      dl.globalDeadlineProvenance().reason, "scan_deadline_exhausted");
    totalTimer();
    ok(`${executionContext}: total watchdog records an exceeded invocation ceiling`,
      dl.totalCeilingProvenance().exceeded === true);
    eq(`${executionContext}: total watchdog has a distinct owner reason`,
      dl.totalCeilingProvenance().reason, "scan_total_ceiling_exhausted");
  }
}

// ── 1c. Env override remains deterministic and clamps per profile ──────────
{
  const c = fakeClock();
  eq("over-cliff override clamps to max", createScanDeadline({ SCAN_DEADLINE_MS: 90_000 }, c.now).budgetMs, SCAN_DEADLINE_DEFAULTS.maxBudgetMs);
  eq("tiny override clamps to min", createScanDeadline({ SCAN_DEADLINE_MS: 100 }, c.now).budgetMs, SCAN_DEADLINE_DEFAULTS.minBudgetMs);
  eq("garbage override → default", createScanDeadline({ SCAN_DEADLINE_MS: "nonsense" }, c.now).budgetMs, SCAN_DEADLINE_DEFAULTS.budgetMs);
  eq("queue override inside durable band is preserved",
    createScanDeadline({ SCAN_DEADLINE_MS: 19_000 }, c.now, { executionContext: "queue" }).budgetMs,
    19_000);
  eq("queue override retains an exact 5s terminal reserve",
    createScanDeadline({ SCAN_DEADLINE_MS: 19_000 }, c.now, { executionContext: "queue" }).totalCeilingMs,
    24_000);
  eq("queue over-limit override clamps to durable max",
    createScanDeadline({ SCAN_DEADLINE_MS: 300_000 }, c.now, { executionContext: "queue" }).budgetMs,
    SCAN_DURABLE_INVOCATION_DEADLINE_DEFAULTS.maxBudgetMs);
  eq("queue tiny override clamps to durable min",
    createScanDeadline({ SCAN_DEADLINE_MS: 100 }, c.now, { executionContext: "queue" }).budgetMs,
    SCAN_DURABLE_INVOCATION_DEADLINE_DEFAULTS.minBudgetMs);
}

// ── 2. Deferred module is honest, never a clean result ──
{
  const kev = markDeadlineDeferred({ matches: [], checked: 0, matched: 0, source: "cisa_kev" });
  eq("deferred: executed false", kev.executed, false);
  eq("deferred: incomplete true", kev.incomplete, true);
  eq("deferred: outcome deadline_exceeded", kev.outcome, "deadline_exceeded");
  eq("deferred: reason scan_deadline_exhausted", kev.reason, "scan_deadline_exhausted");
  ok("legacy/default deferred value has no additive timeout_source",
    !Object.prototype.hasOwnProperty.call(kev, "timeout_source"));
  ok("deferred: base empty shape preserved (no fake findings)", Array.isArray(kev.matches) && kev.matches.length === 0);
  ok("deferred: has NO clean/ok signal", kev.outcome !== "ok" && kev.error === undefined);

  const moduleCap = markDeadlineDeferred(
    { source: "cisa_kev" },
    { reason: "module_budget_exhausted", timeoutSource: "module_race" },
  );
  eq("module cap reason is not misattributed to the global scan", moduleCap.reason, "module_budget_exhausted");
  eq("module cap source agrees with telemetry vocabulary", moduleCap.timeout_source, "module_race");
  ok("module cap never says scan_deadline_exhausted", moduleCap.reason !== "scan_deadline_exhausted");
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

// ── 10b. Durable terminal writes are bounded by the total ceiling without an
// unsafe competing R2 overwrite. A timed-out R2 outcome is explicitly unknown;
// recovery may write D1 failed but may not start a second R2 body while the first
// write could still land and be reconciled.
{
  const env = stubEnv();
  let r2Launches = 0;
  env.cybermeters_reports.put = async () => {
    r2Launches += 1;
    return new Promise(() => {});
  };
  const deadline = {
    raceToTotal: async (thunk, onCeiling) => {
      void thunk();
      return onCeiling();
    },
  };
  const latch = createFinalizeLatch();
  const first = await finalizeScanResult(latch, {
    scanId: "scan_total_r2", report: { status: "completed" },
    score: 70, rating: "medium", status: "completed", env, deadline,
  });
  ok("terminal R2 ceiling returns without claiming durability", first.finalized === false);
  ok("terminal R2 timeout records an uncertain in-flight outcome", latch.r2WriteUncertain === true);
  eq("terminal R2 timeout has canonical total-ceiling error",
    first.errors.r2, "scan_total_ceiling_exhausted_write_outcome_unknown");
  await finalizeScanResult(latch, {
    scanId: "scan_total_r2", report: { status: "failed" },
    score: 0, rating: "unknown", status: "failed", env,
  });
  eq("recovery never starts a competing failed R2 overwrite", r2Launches, 1);
  eq("recovery can still move D1 out of running", lastD1Status(env), "failed");
}

// Positive control: when both writes settle inside the reserve, the bounded
// finalizer remains R2-first, reaches completed and consumes two bounded slots.
{
  const env = stubEnv();
  let boundedWrites = 0;
  const deadline = {
    raceToTotal: async (thunk) => {
      boundedWrites += 1;
      return thunk();
    },
  };
  const latch = createFinalizeLatch();
  const fin = await finalizeScanResult(latch, {
    scanId: "scan_total_ok", report: { status: "completed", scan_quality: { status: "complete" } },
    score: 90, rating: "low", status: "completed", env, deadline,
  });
  ok("bounded terminal writes finalize successfully inside reserve", fin.finalized === true);
  eq("R2 and D1 each use the total-ceiling boundary", boundedWrites, 2);
  eq("bounded terminal order keeps R2 first", env._r2.length, 1);
  eq("bounded terminal result reaches D1 completed", lastD1Status(env), "completed");
}

// ── 4. Happy path: finalize exactly once; a late promise cannot re-write it ──
{
  const env = stubEnv();
  const latch = createFinalizeLatch();
  const report = {
    scan_id: "scan_x", domain: "owner.example", domain_id: "domain_owner",
    status: "completed", cyber_metrics_score: 72, risk_level: "high",
    scan_quality: { status: "partial" }, monitoring_states: null,
  };

  const first = await finalizeScanResult(latch, {
    scanId: "scan_x", workspaceId: "ws_OWNER", report,
    score: 72, rating: "high", status: "completed", env,
  });
  ok("first finalize is durable", first.finalized === true && first.wrote === true);
  eq("latch state finalized", latch.state, "finalized");
  eq("R2 written once", env._r2.length, 1);
  eq("D1 written once", env._d1.length, 1);
  ok("R2 body carries partial quality", JSON.parse(env._r2[0].body).scan_quality.status === "partial");
  eq("D1 status = completed", env._d1[0].args[0], "completed");
  ok("D1 score/rating bound", env._d1[0].args[1] === 72 && env._d1[0].args[2] === "high");
  eq("terminal unit writes exactly one completion audit", env._audits.length, 1);
  eq("completed terminal D1 unit contains exactly UPDATE + audit", env._batches[0], 2);
  eq("completion audit identity is owner-scoped and deterministic",
    env._audits[0]?.id, "audit_scan_completed:v1:ws_OWNER:scan_x");
  ok("completion statement carries legacy and completed-scan guards",
    /NOT EXISTS[\s\S]*event_type = 'scan_completed'/.test(env._audits[0]?.sql || "") &&
    /EXISTS[\s\S]*FROM scans[\s\S]*status = 'completed'/.test(env._audits[0]?.sql || "") &&
    /ON CONFLICT\(id\) DO NOTHING/.test(env._audits[0]?.sql || ""));

  // A LATE promise re-finalizes → no-op, nothing re-written, state unchanged.
  const late = await finalizeScanResult(latch, { scanId: "scan_x", report: { status: "completed", late: true }, status: "completed", env });
  ok("late finalize is a no-op", late.finalized === true && late.wrote === false && late.reason === "already_finalized");
  eq("R2 still exactly once", env._r2.length, 1);
  eq("D1 still exactly once", env._d1.length, 1);
  eq("completion audit still exactly once", env._audits.length, 1);

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
    eq("failed terminal uses no completion batch", env._batches.length, 0);
    eq("failed terminal writes no completion audit", env._audits.length, 0);
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
    eq("transient R2 failure path writes no completion audit", env._audits.length, 0);
  }
}

// ── 6e. A ceiling during the atomic D1 batch is outcome-unknown and not retried ──
{
  const env = stubEnv();
  let batchLaunches = 0;
  env.cybermeters_db.batch = async () => {
    batchLaunches += 1;
    return new Promise(() => {});
  };
  let races = 0;
  const deadline = {
    raceToTotal: async (thunk, onCeiling) => {
      races += 1;
      if (races === 1) return thunk(); // R2 settles.
      void thunk();                    // D1 batch issued, outcome unknown.
      return onCeiling();
    },
  };
  const latch = createFinalizeLatch();
  const first = await finalizeScanResult(latch, {
    scanId: "scan_d1_unknown", workspaceId: "ws_UNKNOWN",
    report: {
      scan_id: "scan_d1_unknown", domain: "unknown.example", status: "completed",
      cyber_metrics_score: 65, risk_level: "medium", scan_quality: { status: "complete" },
    },
    score: 65, rating: "medium", status: "completed", env, deadline,
  });
  ok("ceiling during D1 batch leaves finalization incomplete", first.finalized === false);
  ok("ceiling during D1 batch latches unknown outcome", latch.d1WriteUncertain === true);
  eq("ceiling during D1 batch reports the canonical unknown error",
    first.errors.d1, "scan_total_ceiling_exhausted_write_outcome_unknown");
  await finalizeScanResult(latch, {
    scanId: "scan_d1_unknown", report: { status: "failed" },
    score: 0, rating: "unknown", status: "failed", env,
  });
  eq("unknown D1 batch is never retried inside the invocation", batchLaunches, 1);
  eq("unknown D1 batch has no competing failed status body", env._d1.length, 0);
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
    await finalizeScanResult(latch, {
      scanId: "scan_d1b", workspaceId: "ws_GUARD",
      report: {
        scan_id: "scan_d1b", domain: "guard.example", domain_id: "dom_guard",
        status: "completed", cyber_metrics_score: 88, risk_level: "low",
        scan_quality: { status: "complete" },
      },
      score: 88, rating: "low", status: "completed", env,
    });
    env.flags.d1Fail = false; // D1 recovers
    const rec = await finalizeScanResult(latch, { scanId: "scan_d1b", report: { status: "failed" }, score: 0, rating: "unknown", status: "failed", env });
    ok("recovery converges to durable finalized", rec.finalized === true && latch.state === "finalized");
    eq("D1 terminal status is completed (never downgraded)", lastD1Status(env), "completed");
    eq("R2 has exactly one (completed) report", env._r2.length, 1);
    eq("R2 report is the completed one", JSON.parse(env._r2[0].body).status, "completed");
    eq("guardCompleted writes one audit from the captured completed payload", env._audits.length, 1);
    eq("guardCompleted preserves the authoritative owner in the audit id",
      env._audits[0]?.id, "audit_scan_completed:v1:ws_GUARD:scan_d1b");
    ok("guardCompleted does not rebuild audit metadata from failed arguments",
      env._audits[0]?.args[3]?.includes("guard.example") &&
      JSON.parse(env._audits[0]?.args[4] || "{}").score === 88);
  }
}

// ── 6d. The completed status and audit are one rollback-safe D1 unit ────────
{
  const env = stubEnv({ auditFail: true });
  const latch = createFinalizeLatch();
  const report = {
    scan_id: "scan_atomic", domain: "atomic.example", status: "completed",
    cyber_metrics_score: 80, risk_level: "low", scan_quality: { status: "complete" },
  };
  const first = await finalizeScanResult(latch, {
    scanId: "scan_atomic", workspaceId: "ws_ATOMIC", report,
    score: 80, rating: "low", status: "completed", env,
  });
  ok("audit failure leaves D1 terminal unit uncommitted", first.finalized === false && latch.d1Written === false);
  eq("audit failure rolls back completed status", env._d1.length, 0);
  eq("audit failure leaves no completion row", env._audits.length, 0);
  env.flags.auditFail = false;
  const recovered = await finalizeScanResult(latch, {
    scanId: "scan_atomic", report: { status: "failed" },
    score: 0, rating: "unknown", status: "failed", env,
  });
  ok("guardCompleted retry commits status and audit together", recovered.finalized === true);
  eq("atomic retry writes one status", env._d1.length, 1);
  eq("atomic retry writes one completion", env._audits.length, 1);
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
  ok("fast path: takeover measured cap still fits", dl.canRun(SCAN_MODULE_BUDGETS.subdomain_takeover) === true);
  ok("fast path: exposure measured cap still fits", dl.canRun(SCAN_MODULE_BUDGETS.asset_exposure) === true);
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
    c.tick(25_000); // past the executable budget
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
  const dl = createScanDeadline({}, c.now);          // 19s executable budget, measured from entry (t=0)
  c.tick(14_000);                                    // Phase 1 + discovery consumed 14s

  // Asset exposure launches (14s + measured 2.5s cap < 19s) but its probes can need
  // ~8s. The race bounds it inside the executable budget and protects finalisation.
  ok("exposure is allowed to START at 14s", dl.canRun(SCAN_MODULE_BUDGETS.asset_exposure) === true);
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
  eq("explicit finalization reserve is surfaced", dl.finalizationReserveMs, SCAN_DEADLINE_DEFAULTS.finalizationReserveMs);
  ok("total ceiling stays below the waitUntil cliff", dl.totalCeilingMs < 30_000);
}

// ── 11. Source wiring: the deadline is created at engine entry and BOUNDS each network
//     phase (not merely gates its start); finalization is latched + durable. ──

// ── 11. Real-engine total-ceiling negatives before source wiring ─────────
// A provider write may be uncancellable. The contract is caller-bounded + outcome
// unknown + no competing terminal launch; it is never a false cancellation claim.
{
  const never = new Promise(() => {});
  const calls = [];
  const env = {
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_DEADLINE_MS: "5000",
    cybermeters_db: {
      prepare(sql) {
        calls.push({ kind: "prepare", sql });
        return {
          bind() { return this; },
          run() { calls.push({ kind: "run", sql }); return never; },
          all() { calls.push({ kind: "all", sql }); return Promise.resolve({ results: [] }); },
        };
      },
      batch() { calls.push({ kind: "batch" }); return Promise.resolve([]); },
    },
    cybermeters_reports: {
      put() { calls.push({ kind: "r2_put" }); return Promise.resolve({}); },
      get() { calls.push({ kind: "r2_get" }); return Promise.resolve(null); },
    },
  };
  const result = await runScanEngine("stall-running", "dom", "ws", "example.com", env, {
    executionContext: "queue",
    preTerminalCeilingTimers: {
      setTimer(fn) { queueMicrotask(fn); return { unref() {} }; },
      clearTimer() {},
    },
  });
  eq("never-resolving initial D1 returns at the total ceiling",
    result?.outcome, "scan_total_ceiling_exhausted");
  eq("initial D1 stall is attributed to its exact stage", result?.stage, "initial_d1_running");
  eq("uncancellable initial write is explicitly outcome-unknown",
    result?.provider_outcome, "in_flight_unknown");
  eq("unknown initial D1 mutation is handed to reconciliation",
    result?.provider_guard?.in_flight_mutation_outcome_unknown_count, 1);
  eq("initial D1 stall does not launch identity read or terminal R2",
    calls.filter((call) => call.kind === "all" || call.kind === "r2_put").length, 0);
  eq("initial D1 stall launches exactly one provider mutation",
    calls.filter((call) => call.kind === "run").length, 1);
}

{
  const never = new Promise(() => {});
  const calls = [];
  let timerCall = 0;
  const env = {
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_DEADLINE_MS: "5000",
    cybermeters_db: {
      prepare(sql) {
        calls.push({ kind: "prepare", sql });
        return {
          bind() { return this; },
          run() { calls.push({ kind: "run", sql }); return Promise.resolve({}); },
          all() { calls.push({ kind: "all", sql }); return never; },
        };
      },
      batch() { calls.push({ kind: "batch" }); return Promise.resolve([]); },
    },
    cybermeters_reports: {
      put() { calls.push({ kind: "r2_put" }); return Promise.resolve({}); },
      get() { calls.push({ kind: "r2_get" }); return Promise.resolve(null); },
    },
  };
  const result = await runScanEngine("stall-identity", "dom", "ws", "example.com", env, {
    executionContext: "cron",
    preTerminalCeilingTimers: {
      setTimer(fn) {
        timerCall += 1;
        if (timerCall === 2) queueMicrotask(fn);
        return { unref() {} };
      },
      clearTimer() {},
    },
  });
  eq("never-resolving initial identity read returns at the total ceiling",
    result?.outcome, "scan_total_ceiling_exhausted");
  eq("identity stall is attributed to its exact stage", result?.stage, "initial_identity_read");
  eq("identity stall preserves the single running write",
    calls.filter((call) => call.kind === "run").length, 1);
  eq("identity stall never launches a competing terminal body",
    calls.filter((call) => call.kind === "r2_put").length, 0);
}

// A real successful engine invocation must surface the inner post-terminal race
// through the same structured ceiling/freeze result as the outer watchdog. Hold
// the first scan-owned D1 operation after terminal completion, fire that exact
// stage, then release the uncancellable write and prove its continuation cannot
// reach later audit/email/provider work.
await withEngineFetchFixture(async (fetchCount) => {
  let fireCeiling = null;
  const fixture = makePostTerminalEngineFixture({
    onPostTerminalHold: () => queueMicrotask(() => fireCeiling?.()),
  });
  const result = await runScanEngine(
    "stall-success-post-terminal", "dom", "ws", "example.com", fixture.env,
    {
      executionContext: "queue",
      testOnlyPhysicalSubrequestCounter: exhaustedPhysicalCounter(),
      testOnlyInvocationCeilingTimers: {
        success_post_terminal: {
          setTimer(fn) { fireCeiling = fn; return { unref() {} }; },
          clearTimer() {},
        },
      },
    },
  );
  const callsAtReturn = fixture.calls.length;
  const fetchesAtReturn = fetchCount();
  fixture.releaseHeld();
  await Promise.resolve();
  await Promise.resolve();
  eq("success post-terminal ceiling returns the canonical outcome",
    result?.outcome, "scan_total_ceiling_exhausted");
  eq("success post-terminal ceiling reports its exact stage",
    result?.stage, "success_post_terminal");
  eq("success post-terminal unknown mutation is reconciliation-owned",
    result?.provider_guard?.in_flight_mutation_outcome_unknown_count, 1);
  eq("success post-terminal ceiling keeps the durable completed terminal",
    fixture.terminalStatus, "completed");
  eq("success post-terminal release launches no later D1/R2/audit provider",
    fixture.calls.length, callsAtReturn);
  eq("success post-terminal release launches no later email/provider fetch",
    fetchCount(), fetchesAtReturn);
  eq("success post-terminal fixture held exactly one provider operation",
    fixture.heldPostTerminalLaunches, 1);
});

// The recovery/failure branch has the identical requirement. Make the first
// completed-report write fail, allow the failed terminal pair to settle, then
// hold its first post-terminal D1 operation across the exact inner ceiling.
await withEngineFetchFixture(async (fetchCount) => {
  let fireCeiling = null;
  const fixture = makePostTerminalEngineFixture({
    failFirstTerminalReport: true,
    onPostTerminalHold: () => queueMicrotask(() => fireCeiling?.()),
  });
  const result = await runScanEngine(
    "stall-failure-post-terminal", "dom", "ws", "example.com", fixture.env,
    {
      executionContext: "cron",
      testOnlyPhysicalSubrequestCounter: exhaustedPhysicalCounter(),
      testOnlyInvocationCeilingTimers: {
        failure_post_terminal: {
          setTimer(fn) { fireCeiling = fn; return { unref() {} }; },
          clearTimer() {},
        },
      },
    },
  );
  const callsAtReturn = fixture.calls.length;
  const fetchesAtReturn = fetchCount();
  fixture.releaseHeld();
  await Promise.resolve();
  await Promise.resolve();
  eq("failure post-terminal ceiling returns the canonical outcome",
    result?.outcome, "scan_total_ceiling_exhausted");
  eq("failure post-terminal ceiling reports its exact stage",
    result?.stage, "failure_post_terminal");
  eq("failure post-terminal unknown mutation is reconciliation-owned",
    result?.provider_guard?.in_flight_mutation_outcome_unknown_count, 1);
  eq("failure post-terminal ceiling preserves the failed terminal",
    fixture.terminalStatus, "failed");
  eq("failure recovery wrote one refused completed body and one failed body",
    fixture.terminalReportAttempts, 2);
  eq("failure post-terminal release launches no later D1/R2/audit provider",
    fixture.calls.length, callsAtReturn);
  eq("failure post-terminal release launches no later email/provider fetch",
    fetchCount(), fetchesAtReturn);
  eq("failure post-terminal fixture held exactly one provider operation",
    fixture.heldPostTerminalLaunches, 1);
});

// Once frozen, a stalled provider write remains explicitly unknown and every
// post-terminal/failure persistence or audit launch is refused before provider I/O.
{
  const c = fakeClock();
  const deadline = createScanDeadline({}, c.now, { executionContext: "queue" });
  const never = new Promise(() => {});
  let underlyingLaunches = 0;
  const sourceEnv = {
    cybermeters_db: {
      prepare() {
        return {
          bind() { return this; },
          run() { underlyingLaunches += 1; return never; },
        };
      },
      batch() { underlyingLaunches += 1; return Promise.resolve([]); },
    },
    cybermeters_reports: {
      put() { underlyingLaunches += 1; return Promise.resolve({}); },
    },
  };
  const guard = createInvocationProviderGuard(sourceEnv, deadline);
  guard.env.cybermeters_db.prepare("UPDATE scans SET status='completed'").bind().run();
  c.tick(deadline.totalCeilingMs);
  deadline.markTotalExceeded();
  const frozen = guard.freeze();
  let auditRefused = false, r2Refused = false;
  try { guard.env.cybermeters_db.prepare("INSERT INTO audit_events VALUES (?)").bind("x").run(); }
  catch (error) { auditRefused = error?.code === "scan_total_ceiling_provider_refused"; }
  try { guard.env.cybermeters_reports.put("reports/late.json", "{}"); }
  catch (error) { r2Refused = error?.code === "scan_total_ceiling_provider_refused"; }
  eq("freeze records the already-started terminal write as outcome-unknown",
    frozen.in_flight_mutation_outcome_unknown_count, 1);
  ok("post-ceiling audit launch is refused before D1", auditRefused);
  ok("post-ceiling R2 launch is refused before R2", r2Refused);
  eq("refused post/failure writes do not reach providers", underlyingLaunches, 1);
}

// ── 12. Source wiring: the deadline is created at engine entry and BOUNDS each network
//     phase (not merely gates its start); finalization is latched + durable. ──
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
  const contextIndex = src.indexOf("const executionContext = opts.executionContext");
  const deadlineIndex = src.indexOf("const deadline = createScanDeadline(env, now, { executionContext })");
  const durableArmIndex = src.indexOf("if (durableInvocation) deadline.arm();");
  const initialD1Index = src.indexOf("// Mark scan as running in D1");
  ok("execution context is resolved before deadline creation",
    contextIndex >= 0 && deadlineIndex > contextIndex);
  ok("deadline receives the resolved execution context", deadlineIndex >= 0);
  ok("now() seam defaults to Date.now (true engine entry)", /opts\.now === "function" \? opts\.now : Date\.now/.test(src));
  ok("measured module caps are imported by the engine", /SCAN_MODULE_BUDGETS/.test(src));
  ok("engine uses a capped-module runner for network phases", /runCappedModule/.test(src));
  ok("legacy phase5 remains bounded by the 1s shared cap",
    /hardMs: SCAN_MODULE_BUDGETS\.phase5_intelligence/.test(src));
  ok("queue/cron Phase-5 launch admission uses max durable cap, not sum",
    /Math\.max\(\.\.\.Object\.values\(SCAN_DURABLE_PHASE5_MODULE_BUDGETS\)\)/.test(src));
  ok("queue/cron Phase-5 runs three independently capped modules",
    (src.match(/runCappedModule\("(?:cve_intelligence|known_exploited_vulnerabilities|email_security_intelligence)"/g) || []).length === 3);
  ok("each durable Phase-5 result is recorded independently",
    /recordDurablePhase5\("cve_intelligence", cveRun\)/.test(src)
      && /recordDurablePhase5\("known_exploited_vulnerabilities", kevRun\)/.test(src)
      && /recordDurablePhase5\("email_security_intelligence", emailIntelRun\)/.test(src));
  ok("default Queue/Cron arms the whole-invocation watchdog at engine entry",
    durableArmIndex > deadlineIndex && durableArmIndex < initialD1Index);
  ok("legacy reserved mode still owns its explicit watchdog without double-arming durable runs",
    /if \(!durableInvocation && reservedMode\) deadline\.arm\(\);/.test(src));
  ok("durable success and failure finalization receive the total deadline",
    (src.match(/deadline: durableInvocation \? deadline : null/g) || []).length === 2);
  ok("every inner total-ceiling path uses the structured invocation result",
    ["success_post_terminal", "finalized_diagnostics", "failure_post_terminal", "whole_invocation"]
      .every((stage) => new RegExp(`raceInvocationCeiling\\(\\s*[\"']${stage}[\"']`).test(src))
      && /invocationCeilingResult\("terminal_finalization"\)/.test(src)
      && /invocationCeilingResult\("failure_terminal_finalization"\)/.test(src));
  ok("inner total-ceiling paths do not return local null/undefined/shapes",
    !/raceToTotal\(persistFinalizedDiagnostics, \(\) => null\)/.test(src)
      && !/runPostTerminalWork,\s*\(\) => \(\{ completed: false, ceiling_exceeded: true \}\)/.test(src)
      && !/runFailurePostTerminalWork,\s*\(\) => \(\{ completed: false, ceiling_exceeded: true \}\)/.test(src));
  ok("late provider values cannot resume abandoned external side effects",
    /if \(frozen && unknown\.has\(id\)\)/.test(src)
      && /property === "RESEND_API_KEY" && externalSideEffectAdmissionClosed\(\)/.test(src));
  ok("finalize checks durable state, not a pre-write flag", /latch\.state === "finalized"/.test(src) && !/latch\.closed/.test(src));
  ok("success path throws to recovery when not durably finalized", /if \(!finalized\.finalized\)/.test(src));
  ok("completed D1 finalization batches status with the canonical audit statement",
    /if \(effStatus === "completed"\)[\s\S]*cybermeters_db\.batch\(\[[\s\S]*statusStatement[\s\S]*scanCompletionAuditStatement\(env, latch\.completion\)/.test(src));
  ok("failed terminal finalization never builds a scan completion audit",
    /if \(effStatus === "completed"\)/.test(src) &&
    !/effStatus === "failed"[\s\S]{0,300}scanCompletionAuditStatement/.test(src));
  ok("Phase 11 retains lifecycle delivery but owns no scan_completed audit",
    /type:\s*"lifecycle_first_scan_completed"/.test(src) &&
    !/event_type:\s*["']scan_completed["']/.test(src));
}

// ── A3 mutation: guardCompleted must use the effective completed intent ─────
{
  const mutant = await importMutant(scanEnginePath, "A3-E1-call-status-instead-of-effective-status");
  const env = stubEnv({ d1Fail: true });
  const latch = mutant.createFinalizeLatch();
  await mutant.finalizeScanResult(latch, {
    scanId: "scan_mutant_guard", workspaceId: "ws_MUTANT",
    report: {
      scan_id: "scan_mutant_guard", domain: "mutant.example", status: "completed",
      cyber_metrics_score: 84, risk_level: "low", scan_quality: { status: "complete" },
    },
    score: 84, rating: "low", status: "completed", env,
  });
  env.flags.d1Fail = false;
  await mutant.finalizeScanResult(latch, {
    scanId: "scan_mutant_guard", report: { status: "failed" },
    score: 0, rating: "unknown", status: "failed", env,
  });
  ok("A3-E1 mutant killed: call status cannot suppress guardCompleted audit",
    env._audits.length !== 1);
}

console.log(`\nscan-deadline: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
