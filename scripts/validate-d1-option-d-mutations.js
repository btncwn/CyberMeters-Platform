#!/usr/bin/env node
// D1 Option D — mutation proof (Bar 4 of the five-point gate).
//
// For every inventoried decision gate, a mutant that lets `degraded` ESCAPE a
// protection applied to `partial` must be killed by the relevant fixture, for the
// NAMED reason. A surviving mutant is terminal failure, not a limitation.
//
// Discipline carried from the F-42/F-48 and F-47 successors:
//   * each mutant edits the REAL production source, exactly once (anchor count
//     asserted), and every byte is restored and hash-verified afterwards;
//   * a kill counts only when the named assertion is among the failures — a
//     transform/parse error is never a kill, because a file that no longer parses
//     proves nothing;
//   * negative controls exist for the opposite failure: a suite that fails on any
//     edit would score 100% here while discriminating nothing.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACT = "workers/scan-api/src/engines/scan-degradation-contract.js";
const ENGINE = "workers/scan-api/src/engines/scan-engine.js";
const ASM = "workers/scan-api/src/engines/asm-cases.js";
const FIXTURES = ["scripts/validate-d1-option-d-contract.js", "scripts/validate-d1-i11a-c3-successor.js"];

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const abs = (rel) => path.join(root, rel);
const read = (rel) => fs.readFileSync(abs(rel), "utf8");
const write = (rel, v) => fs.writeFileSync(abs(rel), v);

function runFixtures() {
  const failed = [];
  let reached = true;
  for (const f of FIXTURES) {
    const r = spawnSync(process.execPath, [abs(f)], { cwd: root, encoding: "utf8", timeout: 300000 });
    const out = `${r.stdout || ""}${r.stderr || ""}`;
    // A fixture that never printed its own summary did not run its assertions.
    if (!/assertions passed/.test(out)) reached = false;
    for (const line of out.split("\n")) if (line.startsWith("FAIL ")) failed.push(line.split(/\s+/)[1]);
  }
  return { failed, reached };
}

// [label, file, exact anchor, replacement, named assertion that must die]
const GUARD_ANCHOR = '  if (typeof status !== "string") return false;\n  return AUTHORITATIVE_SCAN_QUALITIES.includes(status.trim().toLowerCase());';
const MUTANTS = [
  // GATE: the I11A-C3 defect reintroduced at the FLAG level.
  //
  // MEASURED, not assumed. Before the seq-151 correction this mutant reopened
  // verification for `degraded` and died on C3S_DEGRADED_CANNOT_VERIFY. It no
  // longer can: `degraded` is not in the authoritative allow-list either, so
  // canVerify stays false through a SECOND independent guard. Verification is now
  // protected twice over; what this mutant still uniquely breaks is the
  // non-authoritative FLAG that drives defer reasons in asm-cases.js and
  // website-security-lifecycle.js. The expectation names the level where the
  // necessity is real rather than claiming a verification kill it no longer
  // produces. D1-M9/D1-M10 cover the verification level directly.
  // SUCCESSOR-3: retargeted to the snapshot-once call site. The mutant reverts the
  // SAME defect (the partial-only literal) at the same decision; only the operand
  // moved, because the predicate now consumes the single captured observation
  // instead of re-reading the carrier.
  // ── FOURTH NARROWING CLASS (seq 181): READ INSTABILITY ──────────────────
  // Each reintroduces one shape of the double-read and must die on a NAMED
  // read-stability assertion. Together with D1-M11..M15 (coercion), D1-M9/M10
  // (allow-by-default) and the seq-151 disjunct work, all four narrowings at this
  // one gate are now mutation-proven.
  ["D1-M16-second-live-read-restored", ASM,
    "  const qualityAuthoritative = isAuthoritativeQuality(observedQualityStatus);",
    "  const qualityAuthoritative = isAuthoritativeQuality(scanQuality?.status);",
    "C3S_READ_STABILITY_UNKNOWN_EXACTLY_ONE_READ"],
  // Snapshotting only the CARRIER is not snapshot-once: each predicate then reads
  // .status off it, so a getter still fires twice. seq 181 condition 1 says
  // "snapshot the field, not the carrier" for exactly this reason. The anchor
  // spans the whole decision region because the harness applies ONE exact
  // find/replace and this defect necessarily touches three lines.
  ["D1-M17-snapshots-the-carrier-not-the-field", ASM,
    "  const observedQualityStatus = scanQuality?.status;\n  const haveEvidence = Boolean(modules || scanQuality);\n  const incomplete = new Set(scanQuality?.modules_skipped || []);\n  for (const [name, value] of Object.entries(modules || {})) {\n    // A module that errored OR self-reported incomplete evidence (e.g. exposure\n    // probes starved by the subrequest budget) did not truly re-check the exposure.\n    if (value?.error || value?.incomplete === true) incomplete.add(name);\n  }\n  // \u2500\u2500 D1 Option D (FD-006 seq 50) \u2014 I11A-C3 DEFECT REVERSED \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n  // This gate previously compared to the literal \"partial\" only, so a `degraded`\n  // scan could still verify and resolve managed cases. FD-006 declares that\n  // behaviour defective: `degraded` is never verification or resolution\n  // permission. The shared predicate covers every non-authoritative quality, so a\n  // future status cannot escape merely by not being spelled \"partial\".\n  const scanPartial = isNonAuthoritativeQuality(observedQualityStatus);\n  // D1 bounded successor (Governance seq 151). The gate used to fail closed ONLY\n  // for the two statuses it recognised as weak, so every other value \u2014 `unknown`,\n  // an unrecognised or empty status, a missing status, or an absent scanQuality\n  // altogether \u2014 was treated as authoritative and could VERIFY. `scanQuality` is a\n  // declared default parameter (`= null`) of verifyManagedAsmCasesForScan, so that\n  // shape is supported, not hypothetical. Verification now requires quality to be\n  // EXPLICITLY authoritative; absence and unrecognised values fail closed.\n  const qualityAuthoritative = isAuthoritativeQuality(observedQualityStatus);",
    "  const observedCarrier = scanQuality;\n  const haveEvidence = Boolean(modules || scanQuality);\n  const incomplete = new Set(scanQuality?.modules_skipped || []);\n  for (const [name, value] of Object.entries(modules || {})) {\n    // A module that errored OR self-reported incomplete evidence (e.g. exposure\n    // probes starved by the subrequest budget) did not truly re-check the exposure.\n    if (value?.error || value?.incomplete === true) incomplete.add(name);\n  }\n  // \u2500\u2500 D1 Option D (FD-006 seq 50) \u2014 I11A-C3 DEFECT REVERSED \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n  // This gate previously compared to the literal \"partial\" only, so a `degraded`\n  // scan could still verify and resolve managed cases. FD-006 declares that\n  // behaviour defective: `degraded` is never verification or resolution\n  // permission. The shared predicate covers every non-authoritative quality, so a\n  // future status cannot escape merely by not being spelled \"partial\".\n  const scanPartial = isNonAuthoritativeQuality(observedCarrier?.status);\n  // D1 bounded successor (Governance seq 151). The gate used to fail closed ONLY\n  // for the two statuses it recognised as weak, so every other value \u2014 `unknown`,\n  // an unrecognised or empty status, a missing status, or an absent scanQuality\n  // altogether \u2014 was treated as authoritative and could VERIFY. `scanQuality` is a\n  // declared default parameter (`= null`) of verifyManagedAsmCasesForScan, so that\n  // shape is supported, not hypothetical. Verification now requires quality to be\n  // EXPLICITLY authoritative; absence and unrecognised values fail closed.\n  const qualityAuthoritative = isAuthoritativeQuality(observedCarrier?.status);",
    "C3S_READ_STABILITY_UNKNOWN_EXACTLY_ONE_READ"],
  ["D1-M18-snapshot-moved-after-another-carrier-read", ASM,
    "  const observedQualityStatus = scanQuality?.status;\n  const haveEvidence = Boolean(modules || scanQuality);\n  const incomplete = new Set(scanQuality?.modules_skipped || []);",
    "  const haveEvidence = Boolean(modules || scanQuality);\n  const incomplete = new Set(scanQuality?.modules_skipped || []);\n  const observedQualityStatus = scanQuality?.status;",
    "C3S_READ_STABILITY_SNAPSHOT_PRECEDES_OTHER_CARRIER_READS"],
  ["D1-M1-verification-gate-reverts-to-partial-literal", ASM,
    "  const scanPartial = isNonAuthoritativeQuality(observedQualityStatus);",
    '  const scanPartial = observedQualityStatus === "partial";',
    "C3S_DEGRADED_IS_FLAGGED_NON_AUTHORITATIVE"],
  // GATE: malformed contract must stay partial (the escape my own probe caught).
  ["D1-M2-malformed-record-is-only-a-warning", ENGINE,
    "  const partialDrivers = coreIncomplete.length + incompleteModules.length\n    + coreBudgetSkipped.length + rejectedDegradations;",
    "  const partialDrivers = coreIncomplete.length + incompleteModules.length\n    + coreBudgetSkipped.length;",
    "G2_MALFORMED_CONTRACT_STAYS_PARTIAL"],
  // GATE: any independent incomplete cause dominates — PREDICATE level.
  //
  // MEASURED, not assumed: this mutant dies at the predicate assertion, NOT at the
  // engine assertion, because `scan-engine` independently re-checks
  // `partialDrivers > 0` on its status line. Two guards prevent the same escape,
  // so removing only this one changes nothing the engine can observe. That is
  // defence in depth, and the expectation names the level where the necessity is
  // real rather than claiming an engine-level kill this mutant does not produce.
  // D1-M8 below covers the engine level, so the gate is proven at BOTH layers.
  ["D1-M3-predicate-ignores-partial-drivers", CONTRACT,
    "  if (partialDrivers > 0) return false;", "  if (false) return false;",
    "G3_PREDICATE_REFUSES_WITH_PARTIAL_DRIVER"],
  // GATE: the same dominance rule at the ENGINE level — the customer-visible one.
  ["D1-M8-engine-ignores-partial-drivers", ENGINE,
    "  const status = partialDrivers > 0\n    ? \"partial\"",
    "  const status = false\n    ? \"partial\"",
    "G2_INDEPENDENT_INCOMPLETE_CAUSE_DOMINATES"],
  // GATE: a rejected record anywhere makes the contract untrustworthy.
  ["D1-M4-predicate-ignores-rejected-records", CONTRACT,
    "  if (rejected > 0) return false;", "  if (false) return false;",
    "G3_PREDICATE_REFUSES_WITH_REJECTED_RECORD"],
  // GATE: no publishable fallback cannot earn degraded.
  ["D1-M5-accepts-non-publishable-fallback", CONTRACT,
    "  if (record.fallback_publishable !== true) return false;", "  if (false) return false;",
    "G1_NON_PUBLISHABLE_FALLBACK_IS_INVALID"],
  // GATE: unknown contract version fails closed.
  ["D1-M6-accepts-unknown-contract-version", CONTRACT,
    "  if (record.contract_version !== SCAN_DEGRADATION_CONTRACT_VERSION) return false;",
    "  if (false) return false;",
    "G1_UNKNOWN_CONTRACT_VERSION_IS_INVALID"],
  // ── GOVERNANCE seq 151 — THE ADVERSARIAL UNKNOWN-QUALITY GATE ─────────────
  // Reopening verification for a non-authoritative quality is the exact defect the
  // ruling found. Both directions are mutated: removing the requirement, and
  // widening the allow-list to admit `unknown`. Each must die on the ISOLATED
  // named assertion — no disjunct can absorb it.
  ["D1-M9-verification-drops-authoritative-quality-requirement", ASM,
    "      if (!qualityAuthoritative) return false;      // unknown/absent/unrecognised → never verify\n", "",
    "C3S_UNKNOWN_QUALITY_CANNOT_VERIFY"],
  ["D1-M10-authoritative-allowlist-admits-unknown", CONTRACT,
    'export const AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["complete"]);',
    'export const AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["complete", "unknown"]);',
    "C3S_UNKNOWN_QUALITY_CANNOT_VERIFY"],
  // ── GOVERNANCE seq 167 — THE TYPE/COERCION GUARD, attacked five ways ───────
  // D1LSV-01: seq 158 stringified before admission, so anything whose coerced
  // form was "complete" verified. Each mutant below attacks the type guard from a
  // different direction and must die on a NAMED matrix assertion.
  ["D1-M11-type-guard-removed-restores-coercion", CONTRACT,
    GUARD_ANCHOR,
    '  return AUTHORITATIVE_SCAN_QUALITIES.includes(String(status ?? "").trim().toLowerCase());',
    "C3S_TYPEVALUE_COMPLETE_ARRAY_AUTHORITATIVE"],
  ["D1-M12-type-guard-moved-after-coercion", CONTRACT,
    GUARD_ANCHOR,
    '  const coerced = String(status ?? "").trim().toLowerCase();\n  if (typeof coerced !== "string") return false;\n  return AUTHORITATIVE_SCAN_QUALITIES.includes(coerced);',
    "C3S_TYPEVALUE_COMPLETE_OBJECT_COERCION_AUTHORITATIVE"],
  ["D1-M13-type-guard-inverted", CONTRACT,
    '  if (typeof status !== "string") return false;\n  return AUTHORITATIVE_SCAN_QUALITIES.includes(status.trim().toLowerCase());',
    '  if (typeof status === "string") return false;\n  return AUTHORITATIVE_SCAN_QUALITIES.includes(String(status).trim().toLowerCase());',
    "C3S_TYPEVALUE_COMPLETE_AUTHORITATIVE"],
  ["D1-M14-type-guard-widened-to-boxed-strings", CONTRACT,
    '  if (typeof status !== "string") return false;\n  return AUTHORITATIVE_SCAN_QUALITIES.includes(status.trim().toLowerCase());',
    '  if (typeof status !== "string" && !(status instanceof String)) return false;\n  return AUTHORITATIVE_SCAN_QUALITIES.includes(status.trim().toLowerCase());',
    "C3S_TYPEVALUE_COMPLETE_STRING_OBJECT_AUTHORITATIVE"],
  ["D1-M15-authoritative-list-emptied-blocks-legitimate-complete", CONTRACT,
    'export const AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["complete"]);',
    'export const AUTHORITATIVE_SCAN_QUALITIES = Object.freeze([]);',
    "C3S_TYPEVALUE_COMPLETE_CANVERIFY"],
  // GATE: fail-closed equivalence predicate must include degraded.
  ["D1-M7-equivalence-drops-degraded", CONTRACT,
    'export const NON_AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["partial", "degraded"]);',
    'export const NON_AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["partial"]);',
    "G4_DEGRADED_IS_NON_AUTHORITATIVE"],
];

// Cosmetic edits that MUST NOT fail the suite.
const CONTROLS = [
  ["C1-comment-wording", CONTRACT,
    "// THE RE-GRADE PREDICATE.", "// THE RE-GRADE PREDICATE (governed)."],
  ["C2-contract-field-order-comment", CONTRACT,
    "// Exactly the seq-51 minimum field set.", "// Exactly the seq-51 required field set."],
];

function applyExact(rel, find, replace, label) {
  const src = read(rel);
  const n = src.split(find).length - 1;
  if (n !== 1) throw new Error(`${label}: anchor must appear exactly once in ${rel}, found ${n}`);
  write(rel, src.replace(find, replace));
}

function main() {
  const files = [...new Set([CONTRACT, ENGINE, ASM])];
  const originals = new Map(files.map((f) => [f, read(f)]));
  const originalHashes = new Map([...originals].map(([f, v]) => [f, sha256(v)]));
  const restore = () => { for (const [f, v] of originals) write(f, v); };

  const base = runFixtures();
  if (!base.reached || base.failed.length) {
    console.error(`FAIL baseline is not green (${base.failed.length} failing) — mutation proof is meaningless from a red baseline`);
    base.failed.slice(0, 6).forEach((f) => console.error(`   ${f}`));
    return 1;
  }
  console.log("PASS baseline green — every D1 fixture passes before mutation\n");

  let killed = 0;
  for (const [label, file, find, replace, needle] of MUTANTS) {
    try {
      applyExact(file, find, replace, label);
      const r = runFixtures();
      if (!r.reached) console.log(`SKIP ${label} — a fixture did not reach its summary; not counted as a kill`);
      else if (!r.failed.length) console.log(`SURVIVED ${label} — degraded escaped and nothing noticed`);
      else if (r.failed.includes(needle)) { console.log(`KILLED ${label} — right reason ("${needle}")`); killed += 1; }
      else console.log(`WRONG-REASON ${label} — failed, but not on "${needle}" (got ${r.failed.slice(0, 3).join(", ")})`);
    } catch (err) { console.log(`ERROR ${label} — ${err.message}`); }
    finally { restore(); }
  }

  console.log("");
  let survived = 0;
  for (const [label, file, find, replace] of CONTROLS) {
    try {
      applyExact(file, find, replace, label);
      const r = runFixtures();
      if (r.reached && !r.failed.length) { console.log(`CONTROL-OK ${label} — cosmetic change survives, as required`); survived += 1; }
      else console.log(`CONTROL-FAILED ${label} — the suite is hypersensitive`);
    } catch (err) { console.log(`ERROR ${label} — ${err.message}`); }
    finally { restore(); }
  }

  for (const [f, want] of originalHashes) {
    if (sha256(read(f)) !== want) { console.error(`FAIL source not restored: ${f}`); return 1; }
  }
  console.log("\nSource bytes restored and hash-verified.");
  console.log(`D1 Option D mutations: ${killed}/${MUTANTS.length} killed (right reason); controls ${survived}/${CONTROLS.length} survived`);
  const ok = killed === MUTANTS.length && survived === CONTROLS.length;
  console.log(ok ? "D1 Option D mutation proof PASSED" : "D1 Option D mutation proof FAILED");
  return ok ? 0 : 1;
}

process.exit(main());
