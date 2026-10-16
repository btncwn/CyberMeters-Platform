#!/usr/bin/env node
//
// External exposure incomplete-reason — mutation proof. Node 24+.
//
// Each mutant reintroduces exactly one defect that validate-exposure-incomplete-
// reason.js exists to prevent, runs that validator in a FRESH process, and must
// produce the exact ordered FAIL set frozen below. Anchors are replaced exactly
// once; every mutated file is restored and its bytes re-verified.
//
// A kill counts ONLY when: the anchor was present exactly once, the bytes
// changed, the validator reached its own summary, it exited non-zero, and the
// FAIL set matched. A syntax error, an import failure or a wrong-reason failure
// is REJECTED as a kill — those prove the harness broke, not that it caught
// something.
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const VALIDATOR = path.join(root, "scripts", "validate-exposure-incomplete-reason.js");

const FILES = Object.freeze({
  jobs:     src("engines", "exposure-jobs.js"),
  findings: src("engines", "exposure-findings.js"),
});

const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const once = (source, from, to, label) => {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
};

// The production defect, restored on each side of the boundary it crossed.
const FALSE_SENTENCE_RESTORED = Object.freeze([
  "X1_MODULE_CARRIES_REASON",
  "X1_CARD_NO_FALSE_BUDGET_SENTENCE",
  "X1_CARD_STATES_THE_REASON",
]);

// Frozen BEFORE running anything. Runtime results may not edit this table.
const MUTANTS = Object.freeze([
  {
    id: "XM1",
    defect: "reader returns no incomplete_reason, so a finished job reads as cut off by the budget (the original defect)",
    file: "jobs",
    mutate: (s) => once(s,
      "    job_state:row.state,incomplete_reason:exposureIncompleteReason(row.state,coverage,checks.length),",
      "    job_state:row.state,incomplete_reason:null,", "XM1"),
    expect: [
      "X1_READ_REASON_INCONCLUSIVE",
      ...FALSE_SENTENCE_RESTORED,
      "X2_READ_CANCELLED_REASON",
      "X2_READ_BUDGET_EXHAUSTED_REASON",
    ],
  },
  {
    id: "XM2",
    defect: "projection drops the reason the reader supplied, so the stored report loses it",
    file: "findings",
    mutate: (s) => once(s,
      "    incomplete_reason: carriedIncompleteReason(receipt.incomplete_reason),",
      "    incomplete_reason: null,", "XM2"),
    expect: [
      ...FALSE_SENTENCE_RESTORED,
      "X2_MODULE_UNKNOWN_REASON_FAILS_CLOSED",
    ],
  },
  {
    id: "XM3",
    defect: "planner plans HTTP checks for a name whose current authoritative evidence says it has no address",
    file: "jobs",
    mutate: (s) => once(s,
      "  if(!authoritative)return {applicable:true,reason:'address_evidence_not_authoritative'};",
      "  if(true)return {applicable:true,reason:'address_evidence_not_authoritative'};", "XM3"),
    expect: [
      "X3_MAIL_ONLY_NOT_PLANNED", "X3_NXDOMAIN_NOT_PLANNED", "X3_MAIL_ONLY_NOT_IN_HOST_LIST",
      "X3_RECORDED_NOT_APPLICABLE", "X3_EVIDENCE_IS_CITED", "X3_PENDING_ASSETS_EXCLUDES_NOT_APPLICABLE",
      "X3_READ_COVERAGE_COUNTS_HOSTS", "X3_MODULE_CARRIES_HOSTS", "X3_MODULE_COVERAGE_CARRIES_COUNT",
      "X3_NO_DNS_NO_ADDRESS_CHECK_PLANNED",
      "X3_GATE_MAIL_ONLY_NOT_APPLICABLE", "X3_GATE_NXDOMAIN_NOT_APPLICABLE", "X3_GATE_HTTP_PREFLIGHT_PROOF_ALONE_SUFFICES",
    ],
  },
  {
    id: "XM4",
    defect: "planner trusts no-address evidence of any age, so a stale answer silently removes a name from HTTP checks",
    file: "jobs",
    mutate: (s) => once(s,
      "||now-observedMs>EXPOSURE_JOB_LIMITS.noAddressEvidenceMs||",
      "||", "XM4"),
    expect: [
      "X4_NOTHING_RECORDED_NOT_APPLICABLE",
      "X4_REMAINDER_AWAITS_ROTATION",
      "X4_GATE_STALE_OBSERVATION_STAYS_PLANNED",
    ],
  },
  // "Latest observation only" is enforced TWICE: the planner's SQL join selects
  // only the row whose scan_id is the asset's last_observation_scan_id, and the
  // pure gate re-checks the same identity. Measured before freezing: removing
  // the gate's check alone leaves the planner outcome intact because the join
  // still holds, so XM5 is two-sided — the gate assertion MUST die and the
  // planner assertions MUST survive. XM6 removes both and is the decisive one.
  {
    id: "XM5",
    defect: "pure gate trusts an observation that is not the asset's latest one",
    file: "jobs",
    mutate: (s) => once(s,
      "  if(!asset?.observation_scan_id||asset.observation_scan_id!==asset.last_observation_scan_id)return {applicable:true,reason:'no_current_observation'};",
      "  if(!asset?.observation_scan_id)return {applicable:true,reason:'no_current_observation'};", "XM5"),
    expect: ["X4_GATE_SUPERSEDED_OBSERVATION_STAYS_PLANNED"],
    requireSurvived: ["X4_NOTHING_RECORDED_NOT_APPLICABLE", "X4_REMAINDER_AWAITS_ROTATION"],
  },
  {
    id: "XM6",
    defect: "both the SQL join and the gate accept a superseded observation, so an old no-address answer removes a name that now has an address",
    file: "jobs",
    mutate: (s) => once(once(s,
      "  if(!asset?.observation_scan_id||asset.observation_scan_id!==asset.last_observation_scan_id)return {applicable:true,reason:'no_current_observation'};",
      "  if(!asset?.observation_scan_id)return {applicable:true,reason:'no_current_observation'};", "XM6a"),
      "      ON alo.workspace_id=a.workspace_id AND alo.asset_id=a.id AND alo.scan_id=a.last_observation_scan_id",
      "      ON alo.workspace_id=a.workspace_id AND alo.asset_id=a.id", "XM6b"),
    expect: [
      "X4_NOTHING_RECORDED_NOT_APPLICABLE",
      "X4_REMAINDER_AWAITS_ROTATION",
      "X4_GATE_SUPERSEDED_OBSERVATION_STAYS_PLANNED",
    ],
  },
]);

function runValidator(target = VALIDATOR) {
  try {
    const out = execFileSync(process.execPath, [target], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status ?? -1, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

const failSet = (out) => out.split("\n").filter((l) => l.startsWith("FAIL ")).map((l) => l.split(/\s+/)[1]);
const passSet = (out) => out.split("\n").filter((l) => l.startsWith("PASS ")).map((l) => l.split(/\s+/)[1]);
const reachedSummary = (out) => /Exposure incomplete-reason: \d+\/\d+ assertions passed/.test(out);

let killed = 0, rejected = 0;

// Baseline: the unmutated tree must be green, or every kill below is meaningless.
{
  const base = runValidator();
  if (base.code !== 0 || !reachedSummary(base.out)) {
    console.error("BASELINE NOT GREEN — refusing to run mutations");
    console.error(base.out.split("\n").filter((l) => l.startsWith("FAIL ")).join("\n"));
    process.exit(1);
  }
  console.log("PASS BASELINE_GREEN");
}

for (const m of MUTANTS) {
  const file = FILES[m.file];
  const original = fs.readFileSync(file, "utf8");
  const beforeSha = sha(file);
  let verdict = "REJECTED";
  let detail = "";
  try {
    const mutated = m.mutate(original);
    if (mutated === original) throw new Error("mutation produced identical bytes");
    fs.writeFileSync(file, mutated);
    const res = runValidator();
    const got = failSet(res.out);
    const passed = new Set(passSet(res.out));
    // The must-survive claim is evaluated BEFORE the exact FAIL-set comparison
    // so it names the real cause instead of a diff of identifiers.
    const backstopLost = (m.requireSurvived || []).filter((id) => !passed.has(id));
    if (!reachedSummary(res.out)) {
      detail = "validator did not reach its summary (syntax/import failure)";
    } else if (res.code === 0) {
      detail = "validator still passed — the mutant SURVIVED";
    } else if (backstopLost.length) {
      detail = `independent SQL-join backstop did not hold: ${JSON.stringify(backstopLost)}`;
    } else if (JSON.stringify(got) !== JSON.stringify(m.expect)) {
      detail = `wrong reason: got ${JSON.stringify(got)}`;
    } else {
      verdict = "KILLED";
    }
  } catch (err) {
    detail = err.message;
  } finally {
    fs.writeFileSync(file, original);
    if (sha(file) !== beforeSha) {
      console.error(`RESTORE FAILED for ${file}`);
      process.exit(1);
    }
  }
  if (verdict === "KILLED") { killed++; console.log(`PASS ${m.id} killed by exact FAIL set (${m.defect})`); }
  else { rejected++; console.log(`FAIL ${m.id} ${verdict} — ${detail}`); }
}

// ── Invalid-kill control: a broken harness must NOT count as a kill ─────────
{
  const file = FILES.jobs;
  const original = fs.readFileSync(file, "utf8");
  const beforeSha = sha(file);
  fs.writeFileSync(file, original + "\nthis is not javascript(((\n");
  const res = runValidator();
  const bad = res.code !== 0 && !reachedSummary(res.out);
  fs.writeFileSync(file, original);
  if (sha(file) !== beforeSha) { console.error("RESTORE FAILED (syntax control)"); process.exit(1); }
  console.log(`${bad ? "PASS" : "FAIL"} CONTROL_SYNTAX_FAILURE_REJECTED`);
  if (!bad) rejected++;
}

console.log(`\nExposure incomplete-reason mutations: ${killed}/${MUTANTS.length} killed, ${rejected} rejected`);
if (rejected > 0) { console.error("Exposure incomplete-reason mutation proof FAILED"); process.exit(1); }
console.log("Exposure incomplete-reason mutation proof passed");
