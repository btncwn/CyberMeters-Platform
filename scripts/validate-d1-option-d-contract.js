#!/usr/bin/env node
// D1 Option D — behavioural fixture per inventoried decision gate.
//
// Authority: FOUNDER-DECISION-006-D1-OPTION-D (seq 50) via work order seq 51 and
// amendment seq 126. Bar 3 of the five-point gate.
//
// THE SEMANTIC BOUNDARY UNDER TEST:
//     degraded != complete · degraded != healthy
//     degraded != score/band/BRS/timeline/verification/resolution permission
//
// Exactly ONE case may be degraded: single-CT-provider loss WITH valid surviving
// positive evidence AND a valid structured deficiency. Everything else — malformed
// or unknown contract data, no publishable fallback, both-provider loss, or ANY
// independent incomplete cause — stays partial.
//
// Every fixture drives the REAL producer/consumer functions. Hand-built status
// objects would keep passing after the guard was deleted, which is the regression
// this exists to catch.
import { pathToFileURL } from "node:url";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;

const { buildScanQuality } = await import(eng("scan-engine.js"));
const { moduleCompletionGate } = await import(eng("asm-cases.js"));
const {
  buildDegradation, isValidDegradation, mayGradeDegraded, collectDegradations,
  isNonAuthoritativeQuality, SCAN_DEGRADATION_CONTRACT_VERSION, SCAN_DEGRADATION_FIELDS,
} = await import(eng("scan-degradation-contract.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const OBSERVED = "2026-08-18T01:00:00Z";
// A fully built, validated record (what the contract validates).
const validDeg = () => buildDegradation({
  module: "subdomains", dependency: "ct_provider:crt_sh", reason: "fetch failed",
  fallbackSource: "ct_provider:certspotter", fallbackCount: 2, observedAt: OBSERVED,
});
// The deterministic FACTS a module actually emits — no wall-clock stamp, so module
// output stays byte-identical across runs. The engine stamps it centrally.
const validFacts = () => ({
  module: "subdomains", dependency: "ct_provider:crt_sh", reason: "fetch failed",
  fallback_source: "ct_provider:certspotter", fallback_count: 2,
});

// ── GATE 1 — the structured contract itself ─────────────────────────────────
{
  const d = validDeg();
  ok("G1_CONTRACT_BUILDS_A_VALID_RECORD", isValidDegradation(d));
  eq("G1_CONTRACT_FIELD_SET_IS_EXACT", Object.keys(d).sort(), [...SCAN_DEGRADATION_FIELDS].sort());
  eq("G1_CONTRACT_VERSION_IS_STAMPED", d.contract_version, SCAN_DEGRADATION_CONTRACT_VERSION);
  // Every required field is load-bearing: dropping any one must invalidate.
  for (const field of SCAN_DEGRADATION_FIELDS) {
    const broken = { ...d }; delete broken[field];
    ok(`G1_MISSING_${field.toUpperCase()}_IS_INVALID`, isValidDegradation(broken) === false);
  }
  // An undeclared extra field means producer and contract disagree -> invalid.
  ok("G1_UNDECLARED_EXTRA_FIELD_IS_INVALID", isValidDegradation({ ...d, extra: 1 }) === false);
  // Unrecognised status / claim effect / version fail closed.
  ok("G1_UNKNOWN_STATUS_IS_INVALID", isValidDegradation({ ...d, status: "weird" }) === false);
  ok("G1_UNKNOWN_CLAIM_EFFECT_IS_INVALID", isValidDegradation({ ...d, claim_effect: "all_clear" }) === false);
  ok("G1_UNKNOWN_CONTRACT_VERSION_IS_INVALID", isValidDegradation({ ...d, contract_version: "x/9" }) === false);
  // A non-publishable or empty fallback cannot support degraded.
  ok("G1_NON_PUBLISHABLE_FALLBACK_IS_INVALID", isValidDegradation({ ...d, fallback_publishable: false }) === false);
  ok("G1_ZERO_FALLBACK_COUNT_IS_INVALID",
    buildDegradation({ module: "subdomains", dependency: "ct_provider:crt_sh", reason: "x",
      fallbackSource: "ct_provider:certspotter", fallbackCount: 0, observedAt: OBSERVED }) === null);
  ok("G1_NON_ISO_OBSERVED_AT_IS_INVALID", isValidDegradation({ ...d, observed_at: "yesterday" }) === false);
}

// ── GATE 2 — the producer re-grade (the ONLY degraded case) ─────────────────
{
  const q = (modules) => buildScanQuality({ dns: {}, ...modules });
  const single = q({ subdomains: { degradations: [validFacts()] } });
  eq("G2_SINGLE_PROVIDER_LOSS_IS_DEGRADED", single.status, "degraded");
  eq("G2_DEGRADED_CARRIES_THE_STRUCTURED_RECORD", single.degradations.length, 1);
  ok("G2_DEGRADED_IS_NOT_COMPLETE", single.status !== "complete");

  eq("G2_BOTH_PROVIDER_LOSS_STAYS_PARTIAL",
    q({ subdomains: { incomplete: true, incomplete_reason: "ct_sources_unavailable" } }).status, "partial");
  eq("G2_NO_PUBLISHABLE_FALLBACK_STAYS_PARTIAL",
    q({ subdomains: { incomplete: true, incomplete_reason: "ct_source_degraded" } }).status, "partial");
  // THE ESCAPE THIS PINS: a malformed record must not reach degraded through the
  // legacy warning branch. It is a partial DRIVER, not a warning.
  eq("G2_MALFORMED_CONTRACT_STAYS_PARTIAL",
    q({ subdomains: { degradations: [{ ...validFacts(), fallback_count: 0 }] } }).status, "partial");
  eq("G2_NON_ARRAY_DEGRADATIONS_STAYS_PARTIAL",
    q({ subdomains: { degradations: "nope" } }).status, "partial");
  // Any independent incomplete cause dominates.
  eq("G2_INDEPENDENT_INCOMPLETE_CAUSE_DOMINATES",
    q({ subdomains: { degradations: [validFacts()] }, headers: { incomplete: true } }).status, "partial");
  eq("G2_CORE_MODULE_ERROR_DOMINATES",
    buildScanQuality({ dns: { error: "boom" }, subdomains: { degradations: [validFacts()] } }).status, "partial");
  // Honest preservation: a dominated scan still REPORTS the degradation.
  eq("G2_DOMINATED_SCAN_STILL_REPORTS_THE_DEGRADATION",
    q({ subdomains: { degradations: [validFacts()] }, headers: { incomplete: true } }).degradations.length, 1);
  eq("G2_CLEAN_SCAN_IS_STILL_COMPLETE", q({ subdomains: {} }).status, "complete");
  eq("G2_COMPLETE_SCAN_CARRIES_NO_DEGRADATIONS", q({ subdomains: {} }).degradations.length, 0);
}

// ── GATE 3 — the re-grade predicate in isolation ────────────────────────────
{
  ok("G3_PREDICATE_REQUIRES_A_DEGRADATION", mayGradeDegraded({ partialDrivers: 0, degradations: [], rejected: 0 }) === false);
  ok("G3_PREDICATE_REFUSES_WITH_PARTIAL_DRIVER", mayGradeDegraded({ partialDrivers: 1, degradations: [validDeg()], rejected: 0 }) === false);
  ok("G3_PREDICATE_REFUSES_WITH_REJECTED_RECORD", mayGradeDegraded({ partialDrivers: 0, degradations: [validDeg()], rejected: 1 }) === false);
  ok("G3_PREDICATE_ALLOWS_THE_GOVERNED_CASE", mayGradeDegraded({ partialDrivers: 0, degradations: [validDeg()], rejected: 0 }) === true);
  const collected = collectDegradations({ subdomains: { degradations: [validFacts(), { bad: 1 }] } }, OBSERVED);
  eq("G3_COLLECTOR_KEEPS_VALID_AND_COUNTS_REJECTED", [collected.degradations.length, collected.rejected], [1, 1]);
}

// ── GATE 4 — fail-closed equivalence predicate ──────────────────────────────
{
  ok("G4_PARTIAL_IS_NON_AUTHORITATIVE", isNonAuthoritativeQuality("partial") === true);
  ok("G4_DEGRADED_IS_NON_AUTHORITATIVE", isNonAuthoritativeQuality("degraded") === true);
  ok("G4_COMPLETE_IS_AUTHORITATIVE", isNonAuthoritativeQuality("complete") === false);
  ok("G4_UNKNOWN_IS_NOT_TREATED_AS_AUTHORITATIVE_BY_ACCIDENT", isNonAuthoritativeQuality("unknown") === false);
}

// ── GATE 5 — verification / resolution (the I11A-C3 successor surface) ──────
{
  const gate = (status) => moduleCompletionGate({ headers: {} }, { status, modules_skipped: [] });
  ok("G5_PARTIAL_CANNOT_VERIFY", gate("partial").canVerify("headers") === false);
  ok("G5_DEGRADED_CANNOT_VERIFY", gate("degraded").canVerify("headers") === false);
  ok("G5_COMPLETE_STILL_VERIFIES", gate("complete").canVerify("headers") === true);
  ok("G5_DEGRADED_SETS_THE_NON_AUTHORITATIVE_FLAG", gate("degraded").scanPartial === true);
}

console.log(`\nD1 Option D contract fixtures: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("D1 Option D contract validation FAILED"); process.exit(1); }
console.log("D1 Option D contract validation passed");
