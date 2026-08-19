#!/usr/bin/env node
//
// F-48 — mutation proof (work order bar 4). Node 24+.
//
// Each mutant reintroduces exactly one defect this correction exists to prevent,
// runs the F-48 semantic validator in a FRESH process, and must produce the
// frozen outcome. Bytes are restored and re-verified after every mutant.
//
// EXPECTATION FORM, declared before execution: a REQUIRED-KILL set plus a
// FORBIDDEN-KILL set, not one exact ordered list. Reason, from this package's own
// history (F-42): an exact list invites a mismatch on incidental assertions and
// then tempts the author to edit the list until it matches — fitting the
// expectation to the result. The two-sided contract is stricter where it matters:
// the defect assertions MUST die and every control MUST survive.
//
// THE F-42 LESSON CARRIED FORWARD: there, reverting one guard was not enough,
// because a sibling module's `incomplete` still forced `partial` — only a JOINT
// mutant reproduced the customer-visible failure. So F48-M3 below deletes the
// F-48 guard *and* neutralises the F-42 guard together, to prove no accidental
// backstop is doing F-48's work for it.
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const HEADERS = path.join(root, "workers", "scan-api", "src", "engines", "headers-scan.js");
const VALIDATOR = path.join(root, "scripts", "validate-f48-origin-503-false-healthy.js");

const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const once = (source, from, to, label) => {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
};

const MUTANTS = Object.freeze([
  {
    id: "F48-M1",
    defect: "the origin-5xx guard is removed — 301 -> 503 grades complete + assessed_healthy again",
    mutate: (s) => once(s, "    if (Number(getRes.status) >= 500) {", "    if (false) {", "F48-M1"),
    requireKilled: [
      "F48_BAR1_NEVER_COMPLETE_AND_HEALTHY",
      "F48_BAR1_NOT_ASSESSED_HEALTHY",
      "F48_BAR1_COVERAGE_NOT_COMPLETE",
      "F48_BAR1_SCAN_NOT_COMPLETE",
      "F48_BAR1_STATE_IS_EVIDENCE_INSUFFICIENT",
      "F48_BAR1_SCAN_QUALITY_IS_PARTIAL",
      "F48_BAR1_HEADERS_INCOMPLETE",
      "F48_BAR1_REASON_NAMES_ORIGIN_ERROR",
    ],
    forbidKilled: [
      "F48_BAR2_ALL_503_STILL_ISSUE_DETECTED",
      "F48_BAR3_HEALTHY_STATE_UNCHANGED",
      "F48_BAR3_CF_HEALTHY_STATE_UNCHANGED",
      "F48_BAR3_CONTROL_404_NOT_TREATED_AS_ORIGIN_ERROR",
    ],
  },
  {
    id: "F48-M2",
    defect: "the incompleteness is observed but never declared — reason dropped from the module result",
    mutate: (s) => once(s,
      "  const originErrored = !probeExecuted && originErrorObservation !== null;",
      "  const originErrored = false;", "F48-M2"),
    requireKilled: [
      "F48_BAR1_REASON_NAMES_ORIGIN_ERROR",
      "F48_BAR1_OBSERVED_ORIGIN_STATUS_RECORDED",
    ],
    forbidKilled: [
      "F48_BAR2_ALL_503_STILL_ISSUE_DETECTED",
      "F48_BAR3_HEALTHY_STATE_UNCHANGED",
      "F48_BAR3_F42_EDGE_REASON_PRESERVED",
    ],
  },
  {
    id: "F48-M3",
    defect: "JOINT: F-48 guard removed AND the F-42 edge guard neutralised — no sibling backstop can mask it",
    mutate: (s) => once(
      once(s, "    if (Number(getRes.status) >= 500) {", "    if (false) {", "F48-M3a"),
      "    if (getObservation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
      "    if (false) {", "F48-M3b"),
    requireKilled: [
      "F48_BAR1_NEVER_COMPLETE_AND_HEALTHY",
      "F48_BAR1_NOT_ASSESSED_HEALTHY",
      "F48_BAR1_STATE_IS_EVIDENCE_INSUFFICIENT",
      // F-42's own control must also die here, proving the joint mutant really
      // removed both protections rather than only one.
      "F48_BAR3_F42_EDGE_REASON_PRESERVED",
    ],
    forbidKilled: [
      "F48_BAR3_HEALTHY_STATE_UNCHANGED",
      "F48_BAR3_CONTROL_404_NOT_TREATED_AS_ORIGIN_ERROR",
    ],
  },
  {
    id: "F48-M4",
    defect: "the 5xx boundary is widened to any non-200 — silently changes healthy-origin behaviour",
    mutate: (s) => once(s, "    if (Number(getRes.status) >= 500) {",
                        "    if (Number(getRes.status) !== 200) {", "F48-M4"),
    requireKilled: ["F48_BAR3_CONTROL_404_NOT_TREATED_AS_ORIGIN_ERROR"],
    forbidKilled: [
      "F48_BAR1_NOT_ASSESSED_HEALTHY",
      "F48_BAR2_ALL_503_STILL_ISSUE_DETECTED",
      "F48_BAR3_HEALTHY_STATE_UNCHANGED",
    ],
  },
]);

function runValidator() {
  try {
    return { code: 0, out: execFileSync(process.execPath, [VALIDATOR], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (err) {
    return { code: err.status ?? -1, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}
const failSet = (out) => new Set(out.split("\n").filter((l) => l.startsWith("FAIL ")).map((l) => l.split(/\s+/)[1]));
const reachedSummary = (out) => /F-48 origin-503 false-healthy: \d+\/\d+ assertions passed/.test(out);

{
  const base = runValidator();
  if (base.code !== 0 || !reachedSummary(base.out)) {
    console.error("BASELINE NOT GREEN — refusing to run mutations");
    process.exit(1);
  }
  console.log("PASS F48_BASELINE_GREEN");
}

let killed = 0, rejected = 0;
for (const m of MUTANTS) {
  const original = fs.readFileSync(HEADERS, "utf8");
  const beforeSha = sha(HEADERS);
  let verdict = "REJECTED", detail = "";
  try {
    const mutated = m.mutate(original);
    if (mutated === original) throw new Error("identical bytes");
    fs.writeFileSync(HEADERS, mutated);
    const res = runValidator();
    const got = failSet(res.out);
    const survived = m.requireKilled.filter((id) => !got.has(id));
    const deadControls = m.forbidKilled.filter((id) => got.has(id));
    if (!reachedSummary(res.out)) detail = "validator did not reach its summary (syntax/import failure)";
    else if (res.code === 0) detail = "mutant SURVIVED — the guard is not load-bearing";
    else if (survived.length) detail = `required kills survived: ${JSON.stringify(survived)}`;
    else if (deadControls.length) detail = `controls wrongly died: ${JSON.stringify(deadControls)}`;
    else verdict = "KILLED";
  } catch (err) { detail = err.message; }
  finally {
    fs.writeFileSync(HEADERS, original);
    if (sha(HEADERS) !== beforeSha) { console.error("RESTORE FAILED"); process.exit(1); }
  }
  if (verdict === "KILLED") { killed++; console.log(`PASS ${m.id} killed — required kills died, every control survived (${m.defect})`); }
  else { rejected++; console.log(`FAIL ${m.id} ${verdict} — ${detail}`); }
}

// Invalid-kill control: a broken harness must never count as a caught defect.
{
  const original = fs.readFileSync(HEADERS, "utf8");
  const beforeSha = sha(HEADERS);
  fs.writeFileSync(HEADERS, original + "\nthis is not javascript(((\n");
  const res = runValidator();
  const bad = res.code !== 0 && !reachedSummary(res.out);
  fs.writeFileSync(HEADERS, original);
  if (sha(HEADERS) !== beforeSha) { console.error("RESTORE FAILED (control)"); process.exit(1); }
  console.log(`${bad ? "PASS" : "FAIL"} F48_CONTROL_SYNTAX_FAILURE_REJECTED`);
  if (!bad) rejected++;
}

console.log(`\nF-48 mutations: ${killed}/${MUTANTS.length} killed`);
if (killed !== MUTANTS.length || rejected > 0) { console.error("F-48 mutation validation FAILED"); process.exit(1); }
console.log("F-48 mutation validation passed");
