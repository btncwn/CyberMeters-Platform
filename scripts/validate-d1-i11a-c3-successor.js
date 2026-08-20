#!/usr/bin/env node
// D1 Option D — I11A-C3 SUCCESSOR.
//
// Authority: FOUNDER-DECISION-006-D1-OPTION-D (seq 50), which declares the pinned
// I11A-C3 behaviour DEFECTIVE and requires it reversed.
//
// THE SUPERSEDED PIN. I11A-C3 froze the fact that a `degraded` scan could still
// verify: `asm-cases.js` compared `scanQuality?.status === "partial"` only, so
// `degraded` slipped past the completeness guard and could verify and resolve
// managed cases. `scripts/validate-scan-quality-vocabulary-inventory.js` asserted
// that defect "remains explicit and unfixed" — a deliberate pin held open for
// exactly this work order.
//
// THIS FILE IS THAT ASSERTION'S NAMED SUCCESSOR. It asserts the opposite, and it
// is the active contract from FD-006 onward:
//
//     a `degraded` scan can NEVER verify and can NEVER resolve.
//
// It also proves the reversal reaches the read-only consumer
// `website-security-lifecycle.js` WITHOUT editing it — that file consumes
// `gate.scanPartial`, so fixing the shared gate fixes it by construction. That is
// why it stays read-only in the seq-126 envelope.
import path from "node:path";
import fs from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;

const { moduleCompletionGate } = await import(eng("asm-cases.js"));
const { isAuthoritativeQuality } = await import(eng("scan-degradation-contract.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };

const gateFor = (status) => moduleCompletionGate({ headers: {}, subdomains: {} }, { status, modules_skipped: [] });

// ── The reversal itself ─────────────────────────────────────────────────────
ok("C3S_DEGRADED_CANNOT_VERIFY", gateFor("degraded").canVerify("headers") === false);
ok("C3S_DEGRADED_CANNOT_RESOLVE", gateFor("degraded").canVerify("headers") === false); // one gate drives both
ok("C3S_DEGRADED_IS_FLAGGED_NON_AUTHORITATIVE", gateFor("degraded").scanPartial === true);

// ── The reversal did not over-reach ─────────────────────────────────────────
ok("C3S_PARTIAL_STILL_CANNOT_VERIFY", gateFor("partial").canVerify("headers") === false);
ok("C3S_COMPLETE_STILL_VERIFIES", gateFor("complete").canVerify("headers") === true);
ok("C3S_COMPLETE_IS_NOT_FLAGGED_NON_AUTHORITATIVE", gateFor("complete").scanPartial === false);

// ── End-to-end: a REAL governed degraded scan cannot verify ─────────────────
{
  // Deterministic module FACTS; the engine stamps observed_at centrally.
  const facts = {
    module: "subdomains", dependency: "ct_provider:crt_sh", reason: "fetch failed",
    fallback_source: "ct_provider:certspotter", fallback_count: 2,
  };
  const quality = buildScanQuality({ dns: {}, headers: {}, subdomains: { degradations: [facts] } });
  ok("C3S_E2E_GOVERNED_SCAN_IS_DEGRADED", quality.status === "degraded", `got ${quality.status}`);
  const gate = moduleCompletionGate({ headers: {}, subdomains: {} }, quality);
  ok("C3S_E2E_GOVERNED_DEGRADED_SCAN_CANNOT_VERIFY", gate.canVerify("headers") === false);
  // Honest preservation: the surviving evidence is still carried, not erased.
  ok("C3S_E2E_SURVIVING_EVIDENCE_IS_STILL_REPORTED", quality.degradations.length === 1);
}

// ── The read-only consumer inherits the fix without being edited ────────────
{
  // website-security-lifecycle.js reads `gate.scanPartial`. Proving the flag is
  // true for degraded proves that consumer is fail-closed too, which is why the
  // seq-126 envelope keeps that file read-only.
  ok("C3S_SHARED_FLAG_COVERS_READ_ONLY_CONSUMERS", gateFor("degraded").scanPartial === true);
}

// ── ADVERSARIAL BOUNDARY — isolated, load-bearing, no disjunct ──────────────
//
// SUPERSEDES the seq-138 predicate `canVerify(...) === false || scanPartial === false`.
// That second disjunct was TRUE for every unrecognised status (they are not
// non-authoritative), so the assertion passed regardless of what `canVerify`
// returned. It was load-bearing in appearance and green in fact — a false
// positive, per Governance seq 151.
//
// Every assertion below states EXACTLY ONE thing: for a structurally valid input
// carrying PRESENT module evidence and a non-authoritative quality, the named
// canVerify result must be false. No scanPartial, status, warning or presentation
// disjunct participates. Each fails on exact seq-138 bytes for the named reason
// `canVerify(...) !== false`.
const adversarial = (quality) => moduleCompletionGate({ headers: {} }, quality).canVerify("headers");

ok("C3S_UNKNOWN_QUALITY_CANNOT_VERIFY",
  adversarial({ status: "unknown", modules_skipped: [] }) === false,
  "unknown quality with present module evidence must not permit verification");
ok("C3S_UNRECOGNISED_QUALITY_CANNOT_VERIFY",
  adversarial({ status: "not_a_real_status", modules_skipped: [] }) === false,
  "an unrecognised status must not permit verification");
ok("C3S_EMPTY_QUALITY_CANNOT_VERIFY",
  adversarial({ status: "", modules_skipped: [] }) === false,
  "an empty status must not permit verification");
ok("C3S_MISSING_STATUS_CANNOT_VERIFY",
  adversarial({ modules_skipped: [] }) === false,
  "a quality object with no status must not permit verification");
ok("C3S_NULL_STATUS_CANNOT_VERIFY",
  adversarial({ status: null, modules_skipped: [] }) === false,
  "a null status must not permit verification");
// THE SUPPORTED INGRESS: `scanQuality = null` is a declared DEFAULT PARAMETER of
// verifyManagedAsmCasesForScan, so this shape is reachable by any caller that
// omits the option — not hypothetical.
ok("C3S_NULL_SCAN_QUALITY_CANNOT_VERIFY",
  adversarial(null) === false,
  "a null scanQuality with present module evidence must not permit verification");
ok("C3S_UNDEFINED_SCAN_QUALITY_CANNOT_VERIFY",
  adversarial(undefined) === false,
  "an omitted scanQuality with present module evidence must not permit verification");
// Retained from seq 138: with NO evidence at all the gate already failed closed.
// Kept so the correction cannot regress the both-absent case.
ok("C3S_NO_QUALITY_EVIDENCE_CANNOT_VERIFY", moduleCompletionGate(null, null).canVerify("headers") === false);


// ── GOVERNANCE seq 167 — THE TYPE/VALUE CONTRACT MATRIX (18 rows, verbatim) ──
//
// D1LSV-01 (CONFIRMED P2): seq 158 stringified BEFORE admission, so `["complete"]`,
// `{toString:()=>"complete"}` and `new String("complete")` all coerced through
// `String(status ?? "").trim().toLowerCase()` into the authoritative token and
// VERIFIED.
//
// The ruled law: an authoritative allow-list is a TYPE-AND-VALUE contract.
// Stringification, trimming, case folding, unboxing or ANY coercion performed
// BEFORE type admission is an ingress in its own right and must fail closed.
//
// Trim and case-fold remain legal AFTER admission — the raw type of `" COMPLETE "`
// is still primitive string, which is why that row is expected `true`.
//
// Each row asserts BOTH the authoritative predicate AND the customer-governing
// canVerify result, each in isolation. No disjunct participates in any of them.
const TYPE_VALUE_MATRIX = [
  ["complete",                   "complete",                       true],
  ["complete-trimmed-case",      " COMPLETE ",                     true],
  ["partial",                    "partial",                        false],
  ["degraded",                   "degraded",                       false],
  ["unknown",                    "unknown",                        false],
  ["unrecognised",               "future-quality",                 false],
  ["empty",                      "",                               false],
  ["null",                       null,                             false],
  ["undefined",                  undefined,                        false],
  ["number",                     1,                                false],
  ["boolean",                    true,                             false],
  ["plain-object",               {},                               false],
  ["empty-array",                [],                               false],
  ["multi-array",                ["complete", "partial"],          false],
  ["complete-array",             ["complete"],                     false],
  ["complete-object-coercion",   { toString: () => "complete" },   false],
  ["complete-string-object",     new String("complete"),           false],
  ["complete-symbol",            Symbol("complete"),               false],
];

for (const [name, raw, expected] of TYPE_VALUE_MATRIX) {
  ok(`C3S_TYPEVALUE_${name.toUpperCase().replace(/-/g, "_")}_AUTHORITATIVE`,
    isAuthoritativeQuality(raw) === expected,
    `isAuthoritativeQuality(raw) must be ${expected} for ${name}`);
  ok(`C3S_TYPEVALUE_${name.toUpperCase().replace(/-/g, "_")}_CANVERIFY`,
    moduleCompletionGate({ headers: {} }, { status: raw }).canVerify("headers") === expected,
    `canVerify must be ${expected} for ${name}`);
}

// ── SUCCESSOR-3 (Governance seq 181) — READ STABILITY / SNAPSHOT-ONCE ──────
//
// Successor-2 read `scanQuality?.status` TWICE. A getter- or Proxy-backed carrier
// returning a non-authoritative value first and primitive "complete" second made
// the non-authoritative predicate false AND the authoritative predicate true, so
// canVerify returned true with present evidence — a TOCTOU fail-open. Each
// predicate was individually type-strict; the SECOND live read was the ingress.
//
// These assert the structural rule, not another comparison: ONE governed decision
// observes each field ONCE. Every case counts the property reads, because a
// blocked verdict reached with two reads is still the defect.
const unstableCarrier = (first) => {
  let reads = 0;
  return {
    carrier: { get status() { reads += 1; return reads === 1 ? first : "complete"; }, modules_skipped: [] },
    reads: () => reads,
  };
};
for (const [label, first] of [
  ["UNKNOWN", "unknown"], ["UNDEFINED", undefined], ["OBJECT", {}], ["FALSE", false],
]) {
  const u = unstableCarrier(first);
  const cv = moduleCompletionGate({ headers: {} }, u.carrier).canVerify("headers");
  ok(`C3S_READ_STABILITY_${label}_FIRST_CANNOT_VERIFY`, cv === false,
    `a non-authoritative first observation must block regardless of a later value`);
  ok(`C3S_READ_STABILITY_${label}_EXACTLY_ONE_READ`, u.reads() === 1,
    `status property reads must be exactly 1, got ${u.reads()}`);
}
// Cross-field control: the snapshot must be taken BEFORE any other scanQuality
// property access, so reading modules_skipped cannot change the observed status.
{
  let statusReads = 0, order = [];
  const carrier = {
    get status() { statusReads += 1; order.push("status"); return statusReads === 1 ? "complete" : "partial"; },
    get modules_skipped() { order.push("modules_skipped"); return []; },
  };
  const cv = moduleCompletionGate({ headers: {} }, carrier).canVerify("headers");
  ok("C3S_READ_STABILITY_SNAPSHOT_PRECEDES_OTHER_CARRIER_READS",
    order[0] === "status" && statusReads === 1,
    `first access must be status and exactly once, got ${JSON.stringify(order)} reads=${statusReads}`);
  // POSITIVE CONTROL — a legitimate primitive "complete" first observation still
  // verifies, so the rule blocks instability without blocking the honest path.
  ok("C3S_READ_STABILITY_LEGITIMATE_COMPLETE_STILL_VERIFIES", cv === true,
    "first-observation complete must remain authoritative");
}

// ── AST READ-COUNT INVENTORY (seq 181 condition 6) ────────────────────────
//
// Binds the exact-one-live-read denominator to a resolvable static inventory, so
// the runtime proof above cannot silently drift from the source. Counts MemberExpression
// reads of `.status` on the `scanQuality` parameter inside moduleCompletionGate,
// excluding comments — a regex over raw text would count this very comment.
{
  const require2 = createRequire(path.join(root, "frontend", "package.json"));
  const ts = require2("typescript");
  const file = path.join(root, "workers/scan-api/src/engines/asm-cases.js");
  const sf = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  let gate = null;
  const walk = (n) => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === "moduleCompletionGate") gate = n;
    ts.forEachChild(n, walk);
  };
  walk(sf);
  let statusReads = 0, otherCarrierReads = 0;
  const scan = (n) => {
    if (ts.isPropertyAccessExpression(n)) {
      const base = n.expression;
      const baseText = base.getText(sf).replace(/[?]$/, "");
      if (baseText === "scanQuality") {
        if (n.name.text === "status") statusReads += 1; else otherCarrierReads += 1;
      }
    }
    ts.forEachChild(n, scan);
  };
  if (gate) scan(gate);
  ok("C3S_AST_GATE_FOUND", gate !== null, "moduleCompletionGate must be resolvable in the AST");
  ok("C3S_AST_EXACTLY_ONE_LIVE_STATUS_READ", statusReads === 1,
    `AST counted ${statusReads} scanQuality.status reads inside the gate; snapshot-once requires exactly 1`);
  ok("C3S_AST_CARRIER_READS_ACCOUNTED", otherCarrierReads >= 1,
    `expected the modules_skipped carrier read to remain, got ${otherCarrierReads}`);
}

console.log(`\nD1 I11A-C3 successor: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("D1 I11A-C3 successor validation FAILED"); process.exit(1); }
console.log("D1 I11A-C3 successor validation passed");
