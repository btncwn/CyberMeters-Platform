// ── Scan subrequest-capacity primitives (Tier 1) ──────────────────────────────
// Config resolution, runtime subrequest ledger, dynamic exposure cap, critical-prefix
// list, per-scan DNS answer cache, and the customer-safe deferred_capacity state.
//
// This commit adds primitives only — no module reordering. The two-stage discovery
// order and the reserved-exposure wiring land in a later commit and consume these.
// Design: docs/SCAN-SUBREQUEST-CAPACITY-FIX-BRIEF.md (f226790). The deterministic
// harness scripts/validate-scan-subrequest-budget.js is the contract these satisfy.

export const CAPACITY_DEFAULTS = Object.freeze({
  limit:                50,   // SCAN_SUBREQUEST_LIMIT — design for a 50-class ceiling
  mode:                 "legacy", // SCAN_CAPACITY_MODE — legacy until BBB live acceptance passes
  safetyMargin:         5,    // reserved, never allocated (finalization + redirect tail)
  perHostCost:          2,    // C_h: 1 GET + 1 budgeted redirect hop
  maxProbeRedirectHops: 3,    // a single exposure host consumes <= 4 external subrequests
});

function clampInt(value, dflt, min, max) {
  const n = typeof value === "number" ? value : parseInt(value, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

// Resolve the effective capacity config from env. Default mode is "legacy" so the
// first production deploy does NOT switch scans globally to reserved — that only
// happens once the env flag is flipped after live acceptance.
export function resolveScanCapacity(env = {}) {
  return {
    limit:                clampInt(env.SCAN_SUBREQUEST_LIMIT, CAPACITY_DEFAULTS.limit, 1, 10_000),
    mode:                 env.SCAN_CAPACITY_MODE === "reserved" ? "reserved" : "legacy",
    safetyMargin:         CAPACITY_DEFAULTS.safetyMargin,
    perHostCost:          CAPACITY_DEFAULTS.perHostCost,
    maxProbeRedirectHops: CAPACITY_DEFAULTS.maxProbeRedirectHops,
  };
}

// Core-ASM critical prefixes discovered by a single-resolver A lookup — deterministic
// and CT-independent. Mandatory always run; optional only when justified + budget.
export const CRITICAL_PREFIXES_MANDATORY = Object.freeze([
  "admin", "login", "portal", "dashboard", "manage", "vpn", "remote", "api",
]);
export const CRITICAL_PREFIXES_OPTIONAL = Object.freeze(["management", "staging", "dev"]);

// Dynamic exposure host cap:
//   usable = limit - safety_margin
//   exposure_budget = max(0, usable - projected_consumed)
//   host_cap = floor(exposure_budget / per_host_cost)
export function computeExposureCap({ limit, safetyMargin, consumed, perHostCost }) {
  const usable = limit - safetyMargin;
  const exposureBudget = Math.max(0, usable - consumed);
  return Math.max(0, Math.floor(exposureBudget / perHostCost));
}

// Conservative per-module external-subrequest cost, used to gate post-exposure modules:
// a module only runs if its cost fits the remaining budget, else it is skipped BEFORE
// issuing any fetch. These are upper-bounds for the typical fan-out (a bot-challenge /
// heavy-redirect path can exceed them — the safety margin + honest degradation absorb
// that). The live meter measures discovery + exposure exactly; these estimate the rest.
export const MODULE_SUBREQUEST_COST = Object.freeze({
  dns:                  18,   // full DNS posture (A/AAAA/MX/NS/TXT/DMARC/CAA + cross-checks)
  ssl:                  6,
  headers:              6,
  email_security:       24,   // SPF/DMARC/BIMI + DKIM selector sweep
  subdomains:           6,    // CT: crt.sh + CertSpotter + wildcard
  technology_detection: 4,
  whois_intelligence:   4,
  subdomain_takeover:   12,
  dns_bruteforce:       24,
  cve:                  4,
  kev:                  4,
  cloud_storage:        12,
});

// Honest "not run because exposure consumed its reserved budget" module result — never
// a fake clean/zero-findings result. Represented in scan_quality/modules_skipped/warnings.
export function skippedModuleResult(source, extra = {}) {
  return { skipped: true, skip_reason: "subrequest_budget", source, ...extra };
}

// Runtime subrequest ledger. spend() accrues consumption per category; wouldExceed()
// lets a stage refuse to start an over-budget batch (honest skip) before issuing I/O.
export class SubrequestBudget {
  constructor({ limit = CAPACITY_DEFAULTS.limit, safetyMargin = CAPACITY_DEFAULTS.safetyMargin } = {}) {
    this.limit = limit;
    this.safetyMargin = safetyMargin;
    this.consumed = 0;
    this.byCategory = {};
  }
  usable()          { return this.limit - this.safetyMargin; }
  remaining()       { return Math.max(0, this.usable() - this.consumed); }
  wouldExceed(cost) { return this.consumed + cost > this.usable(); }
  spend(category, cost = 1) {
    this.consumed += cost;
    this.byCategory[category] = (this.byCategory[category] || 0) + cost;
    return this.consumed;
  }
}

// ── Global scan wall-clock deadline (Tier 1: waitUntil-cancellation guard) ────
// The scan engine runs inside ctx.waitUntil(); Cloudflare cancels that background
// promise ~30s after the response is sent, silently (no exception → no catch → no
// failed report → orphaned "running" row). The deadline gives the engine an
// explicit wall-clock budget BELOW that cliff: expensive network phases refuse to
// launch once the budget is spent, leaving headroom to finalize honestly. Proven
// root cause: an invocation with wallTime 31170ms / cpuTime 40ms / outcome "ok"
// logged "waitUntil() tasks did not complete ... have been cancelled".
export const SCAN_DEADLINE_DEFAULTS = Object.freeze({
  budgetMs:    21_000, // network phases stop here — ~9s reserved under the ~30s cliff
  minBudgetMs:  5_000,
  // Hard ceiling on the config override: even at max, ≥6s stays reserved for
  // finalization (the terminal R2+D1 write runs first in finalization and is fast,
  // so this comfortably protects the anti-orphan guarantee).
  maxBudgetMs: 24_000,
});

// A monotonic wall-clock deadline. `now` is injectable so tests can drive the clock
// deterministically (production passes Date.now). exceeded() gates launched phases;
// canRun(estimateMs) refuses a phase that could not plausibly finish in budget.
export function createScanDeadline(env = {}, now = Date.now) {
  const budgetMs = clampInt(env.SCAN_DEADLINE_MS, SCAN_DEADLINE_DEFAULTS.budgetMs,
    SCAN_DEADLINE_DEFAULTS.minBudgetMs, SCAN_DEADLINE_DEFAULTS.maxBudgetMs);
  const startedAtMs = now();
  return {
    budgetMs,
    startedAtMs,
    elapsedMs()   { return now() - startedAtMs; },
    remainingMs() { return Math.max(0, budgetMs - (now() - startedAtMs)); },
    exceeded()    { return now() - startedAtMs >= budgetMs; },
    // A phase launches only if elapsed + its estimate still fits the budget.
    canRun(estimateMs = 0) { return (now() - startedAtMs) + estimateMs < budgetMs; },
  };
}

// Bound a LAUNCHED network phase to the remaining wall-clock budget. canRun() only
// decides whether a phase may START; this bounds how long it may RUN, so a phase that
// overruns its estimate (e.g. asset exposure launched with a 6s estimate but whose
// probes time out at 8-10s each) cannot drag the invocation across the ~30s waitUntil
// cliff. If the phase does not settle within the cap, resolve to onDeadline() — an
// honest deferred result — and ABANDON the underlying promise: its late value is
// discarded and modules perform no persistence, so it cannot mutate finalized state.
// `setTimer`/`clearTimer` are injectable so tests drive the timeout deterministically.
export async function raceModuleDeadline(deadline, thunk, onDeadline, { hardMs = null, setTimer = setTimeout, clearTimer = clearTimeout, onStart = null } = {}) {
  const remaining = deadline.remainingMs();
  const capMs = hardMs != null ? Math.min(hardMs, remaining) : remaining;
  // PR-A1 telemetry-only hook: report the cap actually applied to this run so the
  // caller can record allocated_ms without duplicating (and drifting from) the cap
  // computation above. Guarded and observational — a throwing hook never affects
  // the race, and omitting it changes nothing.
  if (typeof onStart === "function") { try { onStart(capMs); } catch { /* telemetry only */ } }
  if (capMs <= 0) return onDeadline();

  const DEADLINE = Symbol("deadline");
  let timer = null;
  const timeout = new Promise((resolve) => { timer = setTimer(() => resolve(DEADLINE), capMs); });
  // Wrap so the work branch never rejects the race (avoids an unhandled rejection);
  // the real rejection is re-thrown to the caller below.
  const work = Promise.resolve().then(thunk).then((v) => ({ v }), (e) => ({ e }));
  const winner = await Promise.race([work, timeout]);
  if (timer != null) clearTimer(timer);
  if (winner === DEADLINE) return onDeadline();
  if ("e" in winner) throw winner.e;
  return winner.v;
}

// Stamp a module's valid-but-empty result as honestly deferred by the deadline —
// never a fake clean/zero-findings result. `incomplete: true` makes buildScanQuality
// classify the scan "partial"; executed:false + reason keep the record diagnosable.
// The caller supplies the module's normal empty shape so downstream scoring/
// remediation see the same fields they would on a genuine empty run.
export function markDeadlineDeferred(base = {}) {
  return {
    ...base,
    executed:   false,
    incomplete: true,
    outcome:    "deadline_exceeded",
    reason:     "scan_deadline_exhausted",
  };
}

// ── Outbound accounting (PR-C1A: telemetry only) ──────────────────────────────
// Counts observed external HTTP/DoH attempts at instrumented leaf helpers. D1 may
// receive a module's attempts only when the scan engine can prove the module
// launched, settled normally, and every outbound leaf it used was instrumented.
// Partial/abandoned observations stay in R2 diagnostics only.
function isTimeoutError(err) {
  const name = err?.name || "";
  return name === "TimeoutError" || /timed out|timeout/i.test(String(err?.message || ""));
}

function isAbortError(err) {
  const name = err?.name || "";
  return name === "AbortError" || /abort/i.test(String(err?.message || ""));
}

export const OUTBOUND_FULLY_INSTRUMENTED_MODULES = Object.freeze(new Set([
  "dns",
  "ssl",
  "headers",
  "email_security",
  "subdomains",
  "technology_detection",
  "whois_intelligence",
  "dns_bruteforce",
  "subdomain_takeover",
  "asset_exposure",
  "cloud_storage_discovery",
  "cve_intelligence",
  "known_exploited_vulnerabilities",
  "email_security_intelligence",
]));

export function createOutboundAccounting() {
  const modules = new Map();

  function ensure(module) {
    const key = String(module || "");
    if (!modules.has(key)) {
      modules.set(key, {
        module: key,
        launched: false,
        fully_instrumented: OUTBOUND_FULLY_INSTRUMENTED_MODULES.has(key),
        settled: false,
        abandoned: false,
        attempts: 0,
        completed: 0,
        aborted: 0,
        timed_out: 0,
        cutoff: null,
      });
    }
    return modules.get(key);
  }

  function contextFor(module, { fullyInstrumented = OUTBOUND_FULLY_INSTRUMENTED_MODULES.has(module) } = {}) {
    const row = ensure(module);
    row.launched = true;
    row.fully_instrumented = !!fullyInstrumented;
    return {
      module,
      recordAttempt() { row.attempts += 1; },
      recordCompleted() { row.completed += 1; },
      recordError(err) {
        if (isTimeoutError(err)) row.timed_out += 1;
        else if (isAbortError(err)) row.aborted += 1;
      },
      markSettled() { row.settled = true; },
      markAbandoned(cutoff = "module_race") { row.abandoned = true; row.cutoff = cutoff; },
      markIncomplete(cutoff = "uninstrumented_leaf") { row.fully_instrumented = false; row.cutoff = row.cutoff || cutoff; },
      snapshot() { return snapshot(module); },
    };
  }

  function snapshot(module) {
    const row = ensure(module);
    const complete = row.launched && row.fully_instrumented && row.settled && !row.abandoned;
    return {
      outbound_attempts_observed: row.attempts,
      outbound_completed_observed: row.completed,
      outbound_aborted_observed: row.aborted,
      outbound_timed_out_observed: row.timed_out,
      outbound_measurement_complete: complete,
      outbound_measurement_cutoff: complete ? null : (row.cutoff || (
        !row.launched ? "module_not_launched" :
        !row.fully_instrumented ? "uninstrumented_leaf" :
        row.abandoned ? "module_abandoned" :
        !row.settled ? "module_not_settled" :
        "unavailable"
      )),
    };
  }

  return {
    contextFor,
    snapshot,
    attemptsForD1(module) {
      const snap = snapshot(module);
      return snap.outbound_measurement_complete ? snap.outbound_attempts_observed : null;
    },
  };
}

// ── Per-module telemetry collector (Tier 1: diagnosability) ───────────────────
// Times each instrumented module and classifies its outcome so a future orphaned
// scan is diagnosable from D1 alone (which module, how long, what happened). Purely
// observational — recording never alters a module's value or throws into the scan
// flow. `now` is injectable for deterministic tests.
export function createModuleTelemetry(now = Date.now) {
  const rows = [];
  const iso = (ms) => new Date(ms).toISOString();

  // Classify a module's returned result into an outcome label.
  const outcomeOf = (v) => {
    if (!v) return "missing";
    if (v.error) return "error";
    if (v.incomplete) return v.outcome || "incomplete";
    if (v.skipped) return "skipped";
    return "ok";
  };

  return {
    rows,
    outcomeOf,
    // Wrap a module thunk: time it, classify, record a row — then return the value
    // (or re-throw the rejection) unchanged, so Promise.allSettled semantics hold.
    async run(module, thunk) {
      const startedMs = now();
      let outcome = "ok", timeout = false, errorClass = null;
      try {
        const v = await thunk();
        outcome = outcomeOf(v);
        return v;
      } catch (e) {
        outcome = "error";
        errorClass = e?.name || "Error";
        if (/timed out|timeout|abort/i.test(String(e?.message || ""))) timeout = true;
        throw e;
      } finally {
        const doneMs = now();
        rows.push({ module, started_at: iso(startedMs), completed_at: iso(doneMs), duration_ms: doneMs - startedMs, outbound_calls: null, outcome, timeout, error_class: errorClass });
      }
    },
    // Record a module that ran outside the wrapper (deferred, reserved-mode, or a
    // pure-computation phase) — coarse outcome, no duration. allocated_ms /
    // timeout_source (PR-A1) are diagnostics-only: surfaced in the R2 execution
    // diagnostics, never bound into the D1 INSERT (no schema change).
    record(module, { outcome = "ok", timeout = false, error_class = null, duration_ms = null, outbound_calls = null, allocated_ms = null, timeout_source = null, outbound = null } = {}) {
      rows.push({ module, started_at: null, completed_at: null, duration_ms, outbound_calls, outcome, timeout, error_class, allocated_ms, timeout_source, outbound });
    },
    // True if a module already has a telemetry row (avoids double-recording).
    has(module) { return rows.some((r) => r.module === module); },
    setOutbound(module, outbound) {
      const row = [...rows].reverse().find((r) => r.module === module);
      if (row) {
        row.outbound = outbound ?? null;
        row.outbound_calls = outbound?.outbound_measurement_complete ? outbound.outbound_attempts_observed : null;
      }
    },
  };
}

// ── Execution diagnostics (PR-A1: additive, R2-only) ──────────────────────────
// A structured, versioned snapshot of the scan's execution timing embedded in the
// R2 report next to timeline_trust. Purely observational: no runtime consumer
// reads it; scan_quality, events, alerts and every customer surface are untouched.
//   execution_context — how the engine was invoked (queue | cron | waituntil);
//                       unknown/absent fails safe to null, never guessed.
//   trigger           — advisory scan origin (manual | scheduled); additive in
//                       PR-B1A because the scheduled Queue cutover makes both
//                       origins execute as "queue". Correlation-only (sourced
//                       from the advisory message field, validated at the
//                       engine); unknown/absent fails safe to null.
//   wall_ms           — the engine-OBSERVED wall time per module. For a module
//                       abandoned by raceModuleDeadline the underlying provider
//                       fetch continues unobserved, so used≡wall from the
//                       engine's view; the distinction is deliberately not faked.
//   allocated_ms      — the cap actually applied where an existing allocation or
//                       launch gate is already known (race cap, or 0 for a
//                       launch-gate refusal); null where no allocation exists
//                       (the parallel Phase-1 modules share the whole budget).
//   timeout_source    — module_race (race cap fired) | launch_gate (canRun
//                       refused the launch) | per_fetch (the module's own fetch
//                       timeout, derived from the existing timeout flag) | null.
export const SCAN_EXECUTION_DIAGNOSTICS_VERSION = "scan-exec-diag-v1";

export function buildExecutionDiagnostics({ executionContext = null, trigger = null, deadline = null, telemetry = null } = {}) {
  return {
    version:            SCAN_EXECUTION_DIAGNOSTICS_VERSION,
    execution_context:  executionContext ?? null,
    trigger:            trigger ?? null,
    deadline_budget_ms: deadline?.budgetMs ?? null,
    engine_wall_ms:     typeof deadline?.elapsedMs === "function" ? deadline.elapsedMs() : null,
    modules: (telemetry?.rows ?? []).map((r) => ({
      module:         r.module,
      wall_ms:        r.duration_ms ?? null,
      outcome:        r.outcome ?? null,
      timeout:        !!r.timeout,
      error_class:    r.error_class ?? null,
      allocated_ms:   r.allocated_ms ?? null,
      timeout_source: r.timeout_source ?? (r.timeout ? "per_fetch" : null),
      outbound_calls: r.outbound_calls ?? null,
      outbound_attempts_observed: r.outbound?.outbound_attempts_observed ?? null,
      outbound_completed_observed: r.outbound?.outbound_completed_observed ?? null,
      outbound_aborted_observed: r.outbound?.outbound_aborted_observed ?? null,
      outbound_timed_out_observed: r.outbound?.outbound_timed_out_observed ?? null,
      outbound_measurement_complete: r.outbound?.outbound_measurement_complete ?? false,
      outbound_measurement_cutoff: r.outbound?.outbound_measurement_cutoff ?? "unavailable",
    })),
  };
}

// Per-scan DNS answer cache — resolve each (name,type) exactly once across core DNS,
// the critical-prefix pass, brute-force and takeover.
export function makeDnsCache() { return new Map(); }
export function dnsCacheKey(name, type) {
  return `${String(name).toLowerCase()}|${String(type).toUpperCase()}`;
}

// Customer-safe "not checked because of the budget cap" record — distinct from
// not_executed (runtime exhaustion) and reachable:false (genuine failure). Never a
// clean result: reachable stays null and the module flags incomplete. `reason` is
// "projected_subrequest_budget" when the dynamic cap deferred the host before probing.
export function deferredCapacityAsset(host, reason = "projected_subrequest_budget") {
  return {
    host,
    url:          `https://${host}`,
    status:       null,
    reachable:    null,
    probe_status: "deferred_capacity",
    reason,
    title:        null,
    server:       null,
    content_type: null,
    tech:         [],
  };
}
