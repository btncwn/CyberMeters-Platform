#!/usr/bin/env node
//
// Item 11A completeness — mutation proof. Node 24+.
//
// A green harness proves nothing until it is shown to go red for the right
// reason. Each mutant reintroduces exactly one defect this criterion exists to
// prevent, runs the semantic validator in a FRESH process, and must produce the
// exact ordered FAIL set frozen below. Anchors are replaced exactly once; every
// mutated file is restored and its bytes re-verified.
//
// A kill counts ONLY when: the anchor was present exactly once, the bytes
// changed, the validator reached its own summary, it exited non-zero, and the
// FAIL set matched. A syntax error, an import failure or a wrong-reason failure
// is REJECTED as a kill — those prove the harness broke, not that it caught
// something.
//
// ── SUCCESSOR DISPOSITION (F-42/F-48) ───────────────────────────────────────
// Authority: GOVERNANCE-RULING-F48-REMEDIATION-ACCEPTANCE-001 (seq 63, FINAL
// Class-S, bundle c33c07913029da5885737d61a1b3d183b30c7cd80f1b1b0eb2672948cb23e3ac)
// via WORKORDER-F42-F48-SUCCESSOR-HARNESS-DISPOSITION-001 (seq 64, bundle
// a496decf1355a7626e43f8f7fe28ddd3a28f09251cb1d368a3d754e1efc7c0cb).
//
// WHAT CHANGED AND WHY. F-48 added a `status_code >= 500` backstop in
// headers-scan.js. Because a signed Cloudflare edge error is itself 520-530,
// that backstop ALSO catches every case the F-42 edge guard catches. So when an
// F-42 guard is reverted, the customer-visible OUTCOME stays fail-closed
// (`incomplete` / `partial` / `evidence_insufficient`) and only the ATTRIBUTION
// goes wrong: the customer is told the origin errored when in fact the origin
// was never observed at all.
//
// The four contracts M1, M2, F42-M1 and F42-M3 were frozen BEFORE F-48 existed
// and demanded outcome kills. Measured on the accepted seq-57 combined baseline
// they therefore degraded to 3/7 (exit 1) — the exact result independently
// captured and preserved by F48-V-INDEPENDENT-VERIFICATION-001 (seq 59, bundle
// cfd506664a51cfb6434a50c7beb9ce3aaaadbf91a81941c4478f00914fd8719e). That
// capture is historical evidence and is NEVER edited, replaced or relabelled.
//
// NOTHING BELOW IS DELETED OR WEAKENED TO GO GREEN. Every previously required
// outcome identifier is retained verbatim in the frozen tables below and now
// carries a BINDING MUST-SURVIVE claim: it asserts that F-48's independent
// backstop still holds the customer outcome fail-closed while the F-42 guard is
// absent. The four contracts thus become TWO-SIDED where they were one-sided —
// wrong attribution MUST be detected, and the outcome MUST NOT regress — which
// is strictly more proof than before, not less. If a future change lets those
// outcome assertions die under these mutants, the backstop has broken and the
// harness fails.
//
// M3, M4 and F42-M2 are deliberately untouched: their kills are outcome- and
// technology-level, F-48 does not backstop tech inference, and the ruling
// requires their existing strength preserved.
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const VALIDATOR = path.join(root, "scripts", "validate-i11a-website-completeness.js");

const FILES = Object.freeze({
  headers: src("engines", "headers-scan.js"),
  tech:    src("engines", "tech-scan.js"),
  engine:  src("engines", "scan-engine.js"),
  domains: src("engines", "cyber-mot-domains.js"),
});

// F-42 (GOVERNANCE-RULING-GX530-I-F42-001, bundle 5dbbfd74…fa2f) is proven by a
// second validator, because its bar is asserted on the GRADER and the CANONICAL
// RESOLVER rather than on module-local fields. Mutants may therefore target
// either harness.
const F42_VALIDATOR = path.join(root, "scripts", "validate-f42-false-healthy-split-fixtures.js");

const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const once = (source, from, to, label) => {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
};

// ── PRESERVED PRE-F-48 OUTCOME EXPECTATIONS ─────────────────────────────────
// These are the EXACT identifiers M1 and M2 required as kills before F-48
// existed. They are retained verbatim — not deleted — and are now asserted from
// the other side: under an F-42 mutant they MUST STILL PASS, because F-48's
// `status_code >= 500` backstop keeps the customer outcome fail-closed. This is
// the defence-in-depth property Governance accepted, made into a binding test.
const PRE_F48_HEADERS_OUTCOME_MUST_SURVIVE = Object.freeze([
  "C1_HEADERS_EDGE_520_IS_INCOMPLETE", "C1_HEADERS_EDGE_520_NOT_ACCESSIBLE", "C1_HEADERS_EDGE_520_NOT_ASSESSED",
  "C1_HEADERS_EDGE_523_IS_INCOMPLETE", "C1_HEADERS_EDGE_523_NOT_ACCESSIBLE", "C1_HEADERS_EDGE_523_NOT_ASSESSED",
  "C1_HEADERS_EDGE_527_IS_INCOMPLETE", "C1_HEADERS_EDGE_527_NOT_ACCESSIBLE", "C1_HEADERS_EDGE_527_NOT_ASSESSED",
  "C1_HEADERS_EDGE_530_IS_INCOMPLETE", "C1_HEADERS_EDGE_530_NOT_ACCESSIBLE", "C1_HEADERS_EDGE_530_NOT_ASSESSED",
  "C1_HEADERS_EDGE_FORCES_PARTIAL", "C1_HEADERS_EDGE_CANNOT_VERIFY",
]);

// The attribution/reason kills the mutants actually produce, measured by
// execution on the reconstructed seq-57 baseline before this table was frozen.
// Removing the edge guard makes a signed edge error fall through to F-48's
// origin-error path, so the customer is told the ORIGIN errored when the origin
// was never observed — wrong reason, wrong state, and the two reasons collapse
// into one another.
const F42_ATTRIBUTION_KILLS = Object.freeze([
  "C1_HEADERS_EDGE_520_REASON", "C1_HEADERS_EDGE_520_OBSERVATION_STATE",
  "C1_HEADERS_EDGE_523_REASON", "C1_HEADERS_EDGE_523_OBSERVATION_STATE",
  "C1_HEADERS_EDGE_527_REASON", "C1_HEADERS_EDGE_527_OBSERVATION_STATE",
  "C1_HEADERS_EDGE_530_REASON", "C1_HEADERS_EDGE_530_OBSERVATION_STATE",
  // The decisive discriminators: the signed-edge reason must stay DISTINCT from
  // the origin-5xx reason. Under the mutant they become the same string.
  "C1_CONTROL_ORIGIN_5XX_REASON_DISTINCT_FROM_EDGE",
  "C1_REASONS_ARE_DISTINCT",
]);

// Frozen BEFORE running anything. Runtime results may not edit this table.
const MUTANTS = Object.freeze([
  {
    id: "M1",
    defect: "headers: any Response counts as the origin answering (the original defect)",
    file: "headers",
    mutate: (s) => once(s,
      "    if (getObservation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
      "    if (false) {", "M1"),
    // SUCCESSOR (seq 63/64): attribution kills required, prior outcome
    // expectations retained as a must-survive backstop claim.
    expect: F42_ATTRIBUTION_KILLS,
    requireSurvived: PRE_F48_HEADERS_OUTCOME_MUST_SURVIVE,
  },
  {
    id: "M2",
    defect: "headers: only a transport failure counts, so edge errors slip through",
    file: "headers",
    mutate: (s) => once(s,
      "getObservation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE",
      "getObservation.state === FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE", "M2"),
    // SUCCESSOR (seq 63/64): same disposition as M1 — this mutant reaches the
    // identical wrong-attribution state by a different edit.
    expect: F42_ATTRIBUTION_KILLS,
    requireSurvived: PRE_F48_HEADERS_OUTCOME_MUST_SURVIVE,
  },
  {
    id: "M3",
    defect: "tech: an edge error page is read as the customer's stack again",
    file: "tech",
    mutate: (s) => once(s,
      "  if (observation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
      "  if (false) {", "M3"),
    expect: [
      "C1_TECH_EDGE_IS_INCOMPLETE", "C1_TECH_EDGE_REASON",
      "C1_TECH_EDGE_NO_TECHNOLOGY_INFERRED", "C1_TECH_EDGE_DOES_NOT_CLAIM_CLOUDFLARE",
      "C1_TECH_EDGE_FORCES_PARTIAL",
    ],
  },
  {
    id: "M4",
    defect: "tech: flags incomplete honestly but still publishes an inferred stack",
    file: "tech",
    mutate: (s) => once(s,
      "      technologies:  [],\n      info_findings: [],",
      "      technologies:  [\"Cloudflare\"],\n      info_findings: [],", "M4"),
    expect: ["C1_TECH_EDGE_NO_TECHNOLOGY_INFERRED", "C1_TECH_EDGE_DOES_NOT_CLAIM_CLOUDFLARE"],
  },
  // ── SURFACE-PARITY MUTANTS ────────────────────────────────────────────────
  // The marker existed in the engine all along; what failed was it REACHING the
  // customer. Each mutant restores one step of that regression and must die only on
  // the named surface assertion.
  {
    id: "MS1",
    defect: "engine stops emitting the incomplete list, so the surface loses the reason entirely",
    file: "engine",
    mutate: (s) => once(s,
      "  const modulesIncomplete = incompleteModules.map((name) => ({",
      "  const modulesIncomplete = [].map((name) => ({", "MS1"),
    expect: ["C1_SURFACE_INCOMPLETE_CARRIES_MODULE_AND_REASON", "C1_SURFACE_REASON_IS_NOT_NULL"],
  },
  {
    id: "MS2",
    defect: "engine emits the module name but drops the reason, reducing it to a bare skip again",
    file: "engine",
    mutate: (s) => once(s,
      "    incomplete_reason: modules[name]?.incomplete_reason ?? null,",
      "    incomplete_reason: null,", "MS2"),
    expect: ["C1_SURFACE_INCOMPLETE_CARRIES_MODULE_AND_REASON", "C1_SURFACE_REASON_IS_NOT_NULL"],
  },
  {
    id: "MS3",
    defect: "domain card reverts to 'could not be collected' and states no reason",
    file: "domains",
    mutate: (s) => once(s,
      "      base.summary = `Required evidence (${insufficientDetail.join(\", \")}) was not usable this scan \u2014 not enough to assess.`;",
      "      base.summary = `Required evidence (${requiredInsufficient.join(\", \")}) could not be collected this scan \u2014 not enough to assess.`;", "MS3"),
    expect: ["C1_SURFACE_CARD_STATES_THE_REASON", "C1_SURFACE_CARD_DOES_NOT_CLAIM_NEVER_COLLECTED"],
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
const reachedSummary = (out) => /I11A website completeness: \d+\/\d+ assertions passed/.test(out);

let killed = 0, rejected = 0;

// Baseline: the unmutated tree must be green, or every kill below is meaningless.
{
  const base = runValidator();
  if (base.code !== 0 || !reachedSummary(base.out)) {
    console.error("BASELINE NOT GREEN — refusing to run mutations");
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
    // Two-sided contract (seq 63/64): the attribution assertions must die AND
    // the preserved outcome assertions must still pass. A mutant that silently
    // took the customer outcome down with it is NOT the accepted behaviour.
    const passed = new Set(passSet(res.out));
    const backstopLost = (m.requireSurvived || []).filter((id) => !passed.has(id));
    // ORDER MATTERS. The backstop claim is evaluated BEFORE the exact-ordered
    // FAIL-set comparison. If it ran second it could never fire — any extra
    // death already mismatches the ordered list — and an assertion that cannot
    // fail is decorative. Evaluated first, it names the real cause ("the F-48
    // backstop stopped holding") instead of dumping a diff of identifiers.
    if (!reachedSummary(res.out)) {
      detail = "validator did not reach its summary (syntax/import failure)";
    } else if (res.code === 0) {
      detail = "validator still passed — the mutant SURVIVED";
    } else if (backstopLost.length) {
      detail = `F-48 outcome backstop did not hold: ${JSON.stringify(backstopLost)}`;
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

// ── Invalid-kill controls: a broken harness must NOT count as a kill ─────────
{
  const file = FILES.headers;
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

// ── F-42 mutants — necessity proven at the CUSTOMER-VISIBLE level ───────────
//
// Reverting ONE guard is not enough to restore the false-healthy transition:
// the other module's `incomplete` still forces `partial`, so the split fixtures
// stay honest. That mutual backstop is real protection, and it also means a
// single-file mutant CANNOT prove the customer-visible necessity of either
// guard. F42-M3 therefore reverts BOTH guards together and is the decisive one:
// it is the only mutant that reproduces Governance's measured
// `complete → assessed_healthy`.
//
// EXPECTATION FORM, chosen deliberately and declared before execution: these
// mutants freeze a REQUIRED-KILL set and a FORBIDDEN-KILL set rather than one
// exact ordered list. Reason, from this package's own history: an exact list
// invites a mismatch on incidental assertions, and the temptation is then to
// edit the list until it matches — fitting the expectation to the result. A
// two-sided contract is stricter where it matters (the defect assertions MUST
// die; every BAR5 control MUST survive) and claims no precision it does not
// have. Any surviving required-kill, or any dead control, is a FAIL.
const F42_MUTANTS = Object.freeze([
  {
    id: "F42-M1",
    defect: "headers guard reverted — a signed edge error is observed-origin evidence again",
    files: ["headers"],
    mutate: {
      headers: (s) => once(s,
        "    if (getObservation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
        "    if (false) {", "F42-M1"),
    },
    // SUCCESSOR (seq 63/64): the guard's necessity here is ATTRIBUTION. Removing
    // it makes headers-scan report F-48's origin-error reason/state for a
    // response the origin never sent.
    requireKilled: [
      "F42_BAR1_HEADERS_REASON", "F42_BAR1_OBSERVATION_STATE",
    ],
    forbidKilled: [
      // Retained verbatim from the pre-F-48 requireKilled set — not deleted.
      // F-48's 5xx backstop must keep these true while the F-42 guard is absent;
      // if any of them dies, defence in depth has failed and this is a FAIL.
      "F42_BAR1_HEADERS_NOT_ACCESSIBLE", "F42_BAR1_HEADERS_NOT_ASSESSED",
      "F42_BAR1_HEADERS_INCOMPLETE", "F42_BAR1_ABSENCE_IS_NOT_ASSESSED_ABSENCE",
      // Original controls, unchanged.
      "F42_BAR5_UNSIGNED_530_IS_AN_ORIGIN_RESPONSE", "F42_BAR5_GENUINE_503_IS_OBSERVED",
      "F42_BAR5_HEALTHY_ORIGIN_STILL_COMPLETE", "F42_BAR5_HEALTHY_ORIGIN_STILL_ASSESSED_HEALTHY",
      "F42_BAR5_REAL_CLOUDFLARE_ORIGIN_STILL_DETECTED",
    ],
  },
  {
    id: "F42-M2",
    defect: "tech guard reverted — the edge error page is customer stack evidence again",
    files: ["tech"],
    mutate: {
      tech: (s) => once(s,
        "  if (observation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
        "  if (false) {", "F42-M2"),
    },
    requireKilled: [
      "F42_BAR1_NO_TECHNOLOGY_FROM_EDGE_PAGE", "F42_BAR1_TECH_INCOMPLETE",
      "F42_BAR1_EDGE_PAGE_IS_NOT_CLOUDFLARE_STACK_EVIDENCE",
    ],
    forbidKilled: [
      "F42_BAR5_REAL_CLOUDFLARE_ORIGIN_STILL_DETECTED",
      "F42_BAR5_REAL_STACK_BEHIND_CLOUDFLARE_STILL_DETECTED",
      "F42_BAR5_HEALTHY_ORIGIN_STILL_ASSESSED_HEALTHY",
    ],
  },
  {
    id: "F42-M3",
    defect: "BOTH guards reverted — Governance's measured complete → ASSESSED_HEALTHY returns",
    files: ["headers", "tech"],
    mutate: {
      headers: (s) => once(s,
        "    if (getObservation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
        "    if (false) {", "F42-M3h"),
      tech: (s) => once(s,
        "  if (observation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {",
        "  if (false) {", "F42-M3t"),
    },
    // SUCCESSOR (seq 63/64): with BOTH guards reverted the customer outcome is
    // still held by F-48's independent 5xx backstop, so the necessity proven
    // here is attribution across headers AND technology, plus the grader's
    // module naming. The tech kills are unaffected by F-48 — it does not
    // backstop technology inference — so they remain outcome-level.
    requireKilled: [
      // Headers attribution: wrong reason and wrong observation state.
      "F42_BAR1_HEADERS_REASON", "F42_BAR1_OBSERVATION_STATE",
      // Technology: an edge error page is published as the customer's stack.
      "F42_BAR1_NO_TECHNOLOGY_FROM_EDGE_PAGE", "F42_BAR1_TECH_INCOMPLETE",
      "F42_BAR1_EDGE_PAGE_IS_NOT_CLOUDFLARE_STACK_EVIDENCE",
      // The grader must stop naming the unobserved modules.
      "F42_BAR6_GRADER_NAMES_THE_UNOBSERVED_MODULES",
    ],
    forbidKilled: [
      // Retained verbatim from the pre-F-48 requireKilled set — not deleted.
      // These are the exact GX530-I split-fixture outcomes. F-48's backstop must
      // keep them true with both F-42 guards absent; a death here means the
      // false-healthy path has reopened and is a FAIL.
      "F42_BAR2_SPLIT_A__SCAN_QUALITY_IS_NOT_COMPLETE",
      "F42_BAR2_SPLIT_A__WEBSITE_IS_NOT_ASSESSED_HEALTHY",
      "F42_BAR2_SPLIT_A__WEBSITE_COVERAGE_IS_NOT_COMPLETE",
      "F42_BAR3_SPLIT_B__SCAN_QUALITY_IS_NOT_COMPLETE",
      "F42_BAR3_SPLIT_B__WEBSITE_IS_NOT_ASSESSED_HEALTHY",
      "F42_BAR3_SPLIT_B__WEBSITE_COVERAGE_IS_NOT_COMPLETE",
      // Bar 4: uniform signed 530 is held fail-closed by SSL independently of
      // these guards. If a mutant here breaks it, the regression guard was
      // never load-bearing where Governance said it was.
      "F42_BAR4_UNIFORM_530__WEBSITE_IS_NOT_ASSESSED_HEALTHY",
      "F42_BAR4_UNIFORM_530__SCAN_QUALITY_IS_NOT_COMPLETE",
      // Controls stay correct under the mutant.
      "F42_BAR5_UNSIGNED_530_IS_AN_ORIGIN_RESPONSE", "F42_BAR5_GENUINE_503_IS_OBSERVED",
      "F42_BAR5_HEALTHY_ORIGIN_STILL_COMPLETE", "F42_BAR5_HEALTHY_ORIGIN_STILL_ASSESSED_HEALTHY",
    ],
  },
]);

const f42ReachedSummary = (out) => /F-42 split-fixture proof: \d+\/\d+ assertions passed/.test(out);

{
  const base = runValidator(F42_VALIDATOR);
  if (base.code !== 0 || !f42ReachedSummary(base.out)) {
    console.error("F-42 BASELINE NOT GREEN — refusing to run F-42 mutations");
    process.exit(1);
  }
  console.log("PASS F42_BASELINE_GREEN");
}

for (const m of F42_MUTANTS) {
  const originals = Object.fromEntries(m.files.map((k) => [k, fs.readFileSync(FILES[k], "utf8")]));
  const beforeShas = Object.fromEntries(m.files.map((k) => [k, sha(FILES[k])]));
  let verdict = "REJECTED", detail = "";
  try {
    for (const k of m.files) {
      const mutated = m.mutate[k](originals[k]);
      if (mutated === originals[k]) throw new Error(`${k}: identical bytes`);
      fs.writeFileSync(FILES[k], mutated);
    }
    const res = runValidator(F42_VALIDATOR);
    const got = new Set(failSet(res.out));
    const survivedRequired = m.requireKilled.filter((id) => !got.has(id));
    const deadControls = m.forbidKilled.filter((id) => got.has(id));
    if (!f42ReachedSummary(res.out)) detail = "validator did not reach its summary (syntax/import failure)";
    else if (res.code === 0) detail = "mutant SURVIVED — the guard is not load-bearing";
    else if (survivedRequired.length) detail = `required kills survived: ${JSON.stringify(survivedRequired)}`;
    else if (deadControls.length) detail = `controls wrongly died: ${JSON.stringify(deadControls)}`;
    else verdict = "KILLED";
  } catch (err) { detail = err.message; }
  finally {
    for (const k of m.files) fs.writeFileSync(FILES[k], originals[k]);
    for (const k of m.files) {
      if (sha(FILES[k]) !== beforeShas[k]) { console.error(`RESTORE FAILED for ${FILES[k]}`); process.exit(1); }
    }
  }
  if (verdict === "KILLED") { killed++; console.log(`PASS ${m.id} killed — required kills died, every control survived (${m.defect})`); }
  else { rejected++; console.log(`FAIL ${m.id} ${verdict} — ${detail}`); }
}

const TOTAL = MUTANTS.length + F42_MUTANTS.length;
console.log(`\nI11A completeness + F-42 mutations: ${killed}/${TOTAL} killed`);
if (killed !== TOTAL || rejected > 0) {
  console.error("I11A completeness mutation validation FAILED");
  process.exit(1);
}
console.log("I11A completeness mutation validation passed");
