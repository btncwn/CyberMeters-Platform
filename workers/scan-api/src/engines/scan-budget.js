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
