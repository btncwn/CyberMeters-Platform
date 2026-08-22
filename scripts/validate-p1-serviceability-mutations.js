#!/usr/bin/env node
//
// P1.1 — MUTATION PROOF for the canonical serviceability authority. Node 24+.
//
// The class is BIDIRECTIONAL, so the kill set is too. Restoring the false ISSUE and
// overshooting into false HEALTHY must EACH turn the suite red, on DISTINCT named
// assertions — a single "is it usable" guard would let a repair in one direction
// silently re-open the other.
//
// CANONICAL AUTHORITY, cited at its true type: Governance RULINGS seq 42
// (F48-F51-CLASSIFICATION), seq 63 (F48-REMEDIATION-ACCEPTANCE) and seq 262
// (I11A-ACC-P2-01-BAR-CONFLICT — FINAL, authorizes this succession). seq 260 is an
// Executive SUBMISSION and seq 263 an Executive MEASUREMENT: context, not rulings.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const abs = (r) => path.join(root, r);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

const SERVICEABILITY = "workers/scan-api/src/lib/serviceability.js";
const SSL_SCAN       = "workers/scan-api/src/engines/ssl-scan.js";
const VALIDATOR      = "scripts/validate-p1-serviceability-contract.js";

// [id, file, find, replace, mustFailAssertion]
const MUTANTS = [
  // ── DIRECTION 1 — restore the false ISSUE ────────────────────────────────
  // The exact pre-P1.1 line: transport treated as serviceability.
  ["P11-M1-redirect-evidence-reverts-to-transport", SSL_SCAN,
    "  let redirectEvidenceObserved = mayGroundAbsence(httpServiceability);",
    "  let redirectEvidenceObserved = httpObservation.transport_observed === true;",
    "P11_G2_ALL503_NO_REDIRECT_FINDING"],
  // Same direction through the contract instead of the call site.
  ["P11-M2-5xx-declared-serviceable", SERVICEABILITY,
    "  if (status >= 500) {\n    return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,\n      SERVICEABILITY_REASONS.ORIGIN_ERROR, status);\n  }",
    "  if (status >= 500) {\n    return decided(true, CONCLUSION_CLASSES.CONCLUSIVE,\n      SERVICEABILITY_REASONS.ORIGIN_ERROR, status);\n  }",
    "P11_G2_ALL503_STATE_IS_EVIDENCE_INSUFFICIENT"],
  // ── DIRECTION 2 — overshoot into false HEALTHY / lost detection ───────────
  // Suppressing everything is NOT a fix: the genuine issue must still fire.
  ["P11-M3-absence-never-groundable", SERVICEABILITY,
    "export function mayGroundAbsence(record) { return eligible(record); }",
    "export function mayGroundAbsence(record) { return false; }",
    "P11_G5_POSITIVE_GENUINE_NO_REDIRECT_STILL_RAISES_THE_ISSUE"],
  // The false-FIXED direction: anything grounds health again.
  ["P11-M4-health-conclusion-always-eligible", SERVICEABILITY,
    "export function maySupportHealthyConclusion(record) { return eligible(record); }",
    "export function maySupportHealthyConclusion(record) { return true; }",
    "P11_G6_PROVIDER_503_IS_UNCONFIRMED_NOT_CLAIMED"],
  // ── FAIL-CLOSED must not become fail-open ────────────────────────────────
  ["P11-M5-unknown-collapses-to-serviceable", SERVICEABILITY,
    "  serviceable:      null,\n    conclusion_class: CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,",
    "  serviceable:      true,\n    conclusion_class: CONCLUSION_CLASSES.CONCLUSIVE,",
    "P11_G1_FAILCLOSED_NULL_IS_NULL"],
  // ── The 4xx decision is load-bearing in BOTH directions ──────────────────
  ["P11-M6-403-treated-as-serviceable", SERVICEABILITY,
    "  if (ACCESS_RESTRICTED_STATUSES.includes(status)) {",
    "  if (false && ACCESS_RESTRICTED_STATUSES.includes(status)) {",
    "P11_G1_403_IS_NOT_SERVICEABLE"],
  ["P11-M7-404-swept-into-the-5xx-rule", SERVICEABILITY,
    "  if (status >= 400) {\n    return decided(true, CONCLUSION_CLASSES.CONCLUSIVE,\n      SERVICEABILITY_REASONS.ORIGIN_NEGATIVE_ANSWER, status);\n  }",
    "  if (status >= 400) {\n    return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,\n      SERVICEABILITY_REASONS.ORIGIN_ERROR, status);\n  }",
    "P11_G1_404_IS_SERVICEABLE_NEGATIVE_ANSWER"],
  // ── P11-LV-01 — admission is a TYPE **AND VALUE** contract ────────────────
  // Reverting to the typeof-only guard lets every finite number reach the range
  // ladder: `200.5` grounds a conclusion and `600` is decided a real 5xx.
  ["P11-M8-admission-reverts-to-typeof-only", SERVICEABILITY,
    "  if (typeof status !== \"number\" || !Number.isInteger(status)\n      || status < MIN_HTTP_STATUS || status > MAX_HTTP_STATUS) {",
    "  if (typeof status !== \"number\" || !Number.isFinite(status)) {",
    "P11_G1_MALFORMED_FRACTIONAL_200_5_IS_UNKNOWN_SHAPE"],
  // Keeping the integer check but dropping the RANGE lets 600 masquerade as a 5xx.
  ["P11-M9-range-bounds-dropped", SERVICEABILITY,
    "      || status < MIN_HTTP_STATUS || status > MAX_HTTP_STATUS) {",
    "      || false) {",
    "P11_G1_MALFORMED_ABOVE_RANGE_600_IS_UNKNOWN_SHAPE"],
];

// Cosmetic edits that MUST survive — a suite that dies on a comment proves nothing.
const CONTROLS = [
  ["C1-comment-wording", SERVICEABILITY,
    "// ── The three decision helpers ─", "// ── The three decision helpers (canonical) ─"],
  ["C2-reason-comment", SERVICEABILITY,
    "// 4xx BOUNDARY — DECIDED EXPLICITLY", "// 4xx BOUNDARY — decided explicitly"],
];

const originals = new Map([SERVICEABILITY, SSL_SCAN].map((r) => [r, fs.readFileSync(abs(r), "utf8")]));
const hashes = new Map([...originals].map(([r, v]) => [r, sha(v)]));
const restore = () => { for (const [r, v] of originals) fs.writeFileSync(abs(r), v); };

function runValidator() {
  const r = spawnSync(process.execPath, [abs(VALIDATOR)], { cwd: root, encoding: "utf8", timeout: 600000 });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  return { failed: new Set([...out.matchAll(/^FAIL ([A-Z0-9_]+)/gm)].map((m) => m[1])), code: r.status };
}

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };

// Baseline: the suite must be GREEN before any mutant, or every kill is meaningless.
{
  const base = runValidator();
  ok("P11_MUT_BASELINE_IS_GREEN", base.code === 0 && base.failed.size === 0,
     `code=${base.code} failed=${[...base.failed].join(",")}`);
}

for (const [id, file, find, replace, mustFail] of MUTANTS) {
  const src = originals.get(file);
  if (src.split(find).length - 1 !== 1) { ok(`${id}: anchor is unique`, false, "anchor missing or ambiguous"); continue; }
  fs.writeFileSync(abs(file), src.replace(find, replace));
  try {
    const r = runValidator();
    ok(`${id}: killed by ${mustFail}`, r.failed.has(mustFail),
       `exit=${r.code} failed=[${[...r.failed].join(",")}]`);
  } finally {
    restore();
    ok(`${id}: bytes restored`, sha(fs.readFileSync(abs(file), "utf8")) === hashes.get(file));
  }
}

for (const [id, file, find, replace] of CONTROLS) {
  const src = originals.get(file);
  if (src.split(find).length - 1 !== 1) { ok(`${id}: anchor is unique`, false, "anchor missing"); continue; }
  fs.writeFileSync(abs(file), src.replace(find, replace));
  try {
    const r = runValidator();
    ok(`${id}: cosmetic change SURVIVES`, r.code === 0 && r.failed.size === 0,
       `exit=${r.code} failed=[${[...r.failed].join(",")}]`);
  } finally { restore(); }
}

for (const [r, want] of hashes) ok(`final bytes restored: ${r}`, sha(fs.readFileSync(abs(r), "utf8")) === want);

console.log(`\nP1.1 serviceability mutations: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("P1.1 serviceability mutation proof FAILED"); process.exit(1); }
console.log("P1.1 serviceability mutation proof passed");
