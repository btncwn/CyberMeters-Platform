#!/usr/bin/env node
//
// RCE.5 — Cyber Essentials declaration drift guard. CI-blocking.
//
// The repo's authoritative CE honesty metadata is `external_coverage` in
// shared/cyber-essentials-questions.js. Two of the five controls are externally
// assessable (and only PARTIALLY); three are `none` — questionnaire-only. Source
// comments and internal documents had drifted from that truth and asserted a
// withdrawn proxy in the PRESENT tense.
//
// This guard is narrow by construction. Every expectation is DERIVED FROM
// CE_QUESTIONS AT RUNTIME — never from a hard-coded control list. A guard that
// cannot observe the runtime is not a guard (see the mutation runner's compound
// M05 ∘ M04 contract).
//
//   RCE5_G1  the declared count word == the live `partial` count
//   RCE5_G2  the declaration table maps every live control exactly once, on
//            `control_key` (never `.key`), with a matching coverage token
//   RCE5_G4  the EXECUTABLE AST of the two RCE.5 source files is unchanged —
//            comments are invisible to it, executable edits are not
//   RCE5_G5  no PRESENT-TENSE proxy-evidence claim for any `none` control
//
// RCE5_G3 (the lib/cyber-essentials.js footprint sentence) is deliberately NOT
// here. It lands with RCE.5 Unit 2, in the same commit as that file's comment
// correction, so CI is green at every point in the sequence and no guard is ever
// disabled. Do not add G3 before Unit 2.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const rel = (...p) => path.join(root, ...p);

// Canonical acorn resolution — the same pattern scripts/validate-report-preparing.js
// uses, so the parser is the version pinned by workers/scan-api/package.json.
const workerRequire = createRequire(rel("workers", "scan-api", "package.json"));
const { parse } = workerRequire("acorn");

let pass = 0, fail = 0;
const results = [];
const ok = (guard, name, cond, detail = "") => {
  if (cond) { pass++; results.push(`ok   [${guard}] ${name}`); }
  else { fail++; results.push(`FAIL [${guard}] ${name}${detail ? ` -- ${detail}` : ""}`); }
};

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

// ── Files this guard inspects ────────────────────────────────────────────────
// G4's scope is EXACTLY these two product source files. It must not inspect the
// documents, the CI workflow, ci-workflow-policy.js, or this validator itself.
const CASES_FILE = "workers/scan-api/src/engines/cyber-essentials-cases.js";
const LIB_FILE = "workers/scan-api/src/lib/cyber-essentials.js";
const G4_FILES = [CASES_FILE, LIB_FILE];
// G5 inspects the engine comment and the readiness document. lib/cyber-essentials.js
// joins this list with Unit 2, not before.
const G5_FILES = [CASES_FILE, "docs/cyber-essentials-readiness.md"];

const readFile = (relPath) => fs.readFileSync(rel(relPath), "utf8");

// ── Live truth (the ONLY source of expectations) ─────────────────────────────
const { CE_QUESTIONS } = await import(
  new URL("../shared/cyber-essentials-questions.js", import.meta.url).href
);

const liveControls = CE_QUESTIONS.map((c) => ({
  key: c.control_key,                       // control_key — NEVER `.key`
  coverage: c.external_coverage || "none",
}));
const livePartial = liveControls.filter((c) => c.coverage === "partial").map((c) => c.key);
const liveNone = liveControls.filter((c) => c.coverage === "none").map((c) => c.key);
const liveKeySet = new Set(liveControls.map((c) => c.key));

// ═════════════════════════════════════════════════════════════════════════════
// RCE5_G1 — the declared count word tracks the live `partial` count
// ═════════════════════════════════════════════════════════════════════════════
const NUMBER_WORDS = new Map([
  ["zero", 0], ["one", 1], ["two", 2], ["three", 3], ["four", 4], ["five", 5],
]);
const wordToNumber = (token) => {
  const t = String(token).trim().toLowerCase();
  if (/^\d+$/.test(t)) return Number(t);
  return NUMBER_WORDS.has(t) ? NUMBER_WORDS.get(t) : null;
};

const casesSrc = readFile(CASES_FILE);
const countMatch = casesSrc.match(/declares only ([A-Za-z]+|\d+)\b/);

// Non-vacuity: "no count word found" is a FAILURE, never a silent pass.
ok("RCE5_G1", "the declaration's count word is present and parseable",
   countMatch !== null && wordToNumber(countMatch[1]) !== null,
   countMatch ? `unparseable token ${JSON.stringify(countMatch[1])}` : "no `declares only <N>` clause found");

if (countMatch && wordToNumber(countMatch[1]) !== null) {
  const declared = wordToNumber(countMatch[1]);
  ok("RCE5_G1", "declared externally-assessable count equals the live `partial` count",
     declared === livePartial.length,
     `declared ${declared} (${countMatch[1]}) vs live ${livePartial.length} [${livePartial.join(", ")}]`);
}

// ═════════════════════════════════════════════════════════════════════════════
// RCE5_G2 — the declaration table, mapped on control_key, with non-vacuity
// ═════════════════════════════════════════════════════════════════════════════
// Rows look like:
//   //   boundary_protection         external_coverage "partial"  → assessable
const ROW_RE = /^\s*\/\/\s+([a-z_]+)\s+external_coverage\s+"([a-z]+)"\s*(?:→|->)/gm;
const declaredRows = [...casesSrc.matchAll(ROW_RE)].map((m) => ({ key: m[1], coverage: m[2] }));
const declaredKeys = declaredRows.map((r) => r.key);

// (1) every mapped identifier is a non-empty string
ok("RCE5_G2", "every live control identifier is a non-empty string",
   liveControls.length > 0 && liveControls.every((c) => typeof c.key === "string" && c.key.length > 0),
   `identifiers: ${JSON.stringify(liveControls.map((c) => c.key))}`);

// (2) exactly five unique live controls
ok("RCE5_G2", "exactly five unique live control identifiers exist",
   liveKeySet.size === 5 && liveControls.length === 5,
   `unique ${liveKeySet.size} of ${liveControls.length}`);

// (3) the declared identifier set equals the live control set
const declaredSet = new Set(declaredKeys);
const setsEqual = declaredSet.size === liveKeySet.size &&
  [...liveKeySet].every((k) => declaredSet.has(k));
ok("RCE5_G2", "the declaration table's control set equals the live CE_QUESTIONS set",
   setsEqual,
   `declared [${[...declaredSet].sort().join(", ")}] vs live [${[...liveKeySet].sort().join(", ")}]`);

// (4) every control appears exactly once
const dupes = declaredKeys.filter((k, i) => declaredKeys.indexOf(k) !== i);
ok("RCE5_G2", "every control appears exactly once in the declaration table",
   declaredKeys.length === liveKeySet.size && dupes.length === 0,
   `rows ${declaredKeys.length}, duplicates [${[...new Set(dupes)].join(", ")}]`);

// (5) every declared coverage token equals the live value
const coverageMismatches = declaredRows
  .filter((r) => liveKeySet.has(r.key))
  .filter((r) => r.coverage !== liveControls.find((c) => c.key === r.key).coverage)
  .map((r) => `${r.key}: declared "${r.coverage}" vs live "${liveControls.find((c) => c.key === r.key).coverage}"`);
ok("RCE5_G2", "every declared external_coverage token equals the live value",
   coverageMismatches.length === 0, coverageMismatches.join(" | "));

// ── G2 NEGATIVE FIXTURE (B-4) ────────────────────────────────────────────────
// A `.key`-based implementation is the failure this guard exists to prevent, and
// it is subtle: with `.key` every identifier is `undefined` while the AGGREGATE
// partial/none split still reads 2/3, so a count-only guard would pass. Prove
// here, in-process, that the non-vacuity assertions reject it.
{
  const wrong = CE_QUESTIONS.map((c) => ({ key: c.key, coverage: c.external_coverage || "none" }));
  const wrongIdentifiersAllBad =
    wrong.every((c) => typeof c.key !== "string" || c.key.length === 0);
  const wrongAggregateStillLooksRight =
    wrong.filter((c) => c.coverage === "partial").length === livePartial.length &&
    wrong.filter((c) => c.coverage === "none").length === liveNone.length;
  const wrongSetWouldNotMatch = new Set(wrong.map((c) => c.key)).size !== liveKeySet.size ||
    ![...liveKeySet].every((k) => new Set(wrong.map((c) => c.key)).has(k));

  ok("RCE5_G2", "negative fixture: a `.key` mapping yields non-string identifiers",
     wrongIdentifiersAllBad, `got ${JSON.stringify(wrong.map((c) => c.key))}`);
  ok("RCE5_G2", "negative fixture: `.key` aggregate counts still LOOK correct (why count-only guards miss it)",
     wrongAggregateStillLooksRight);
  ok("RCE5_G2", "negative fixture: `.key` is rejected by the identifier-set assertion",
     wrongSetWouldNotMatch);
}

// ═════════════════════════════════════════════════════════════════════════════
// RCE5_G4 — executable-AST fingerprint over exactly the two source files
// ═════════════════════════════════════════════════════════════════════════════
// acorn discards comments unless `onComment` is supplied; stripping the positional
// fields removes the byte offsets that would otherwise move when a comment's length
// changes. The result is INVARIANT under comment-only edits and CHANGES on any
// executable edit. This is a durable content pin, not a diff, so it stays
// meaningful after merge.
//
// Unit 2's authorised comment correction to lib/cyber-essentials.js does not move
// these values and needs no repin. A repin request on either file is therefore
// itself evidence the edit was NOT comment-only — treat it as a review stop-signal.
//
// Coupled to acorn's AST shape: an acorn version bump requires a mechanical repin.
const AST_POSITION_FIELDS = new Set(["start", "end", "range", "loc"]);
const executableFingerprint = (source) => {
  const ast = parse(source, { ecmaVersion: "latest", sourceType: "module" });
  return sha256(JSON.stringify(ast, (k, v) => (AST_POSITION_FIELDS.has(k) ? undefined : v)));
};

const EXPECTED_EXECUTABLE_AST_SHA256 = Object.freeze({
  "workers/scan-api/src/engines/cyber-essentials-cases.js":
    "d3705ecd49b6b035100c1ad9e8652a949f28c315569567784b339a5fefd7bbeb",
  "workers/scan-api/src/lib/cyber-essentials.js":
    "819b0b5ca7df1558baa95b561bfb89a9aef7a4b5030d04085ddf05be45bc72e7",
});

for (const file of G4_FILES) {
  let actual = null, parseError = null;
  try { actual = executableFingerprint(readFile(file)); }
  catch (e) { parseError = e.message; }
  ok("RCE5_G4", `${file} parses as an ES module`, parseError === null, parseError || "");
  if (parseError === null) {
    ok("RCE5_G4", `${file} executable AST is unchanged (comments are invisible to this pin)`,
       actual === EXPECTED_EXECUTABLE_AST_SHA256[file],
       `expected ${EXPECTED_EXECUTABLE_AST_SHA256[file]}, measured ${actual}`);
  }
}

// ── G4 DISCRIMINATING CONTROL (must-flip) ────────────────────────────────────
// A fingerprint that cannot detect an executable change is worthless. Prove, in
// process, that a comment-only edit leaves the value fixed while an executable
// insertion moves it. Without this, G4 could be silently vacuous.
{
  const base = readFile(CASES_FILE);
  const baseFp = executableFingerprint(base);

  const commentMutated = `${base}\n// RCE5_G4 in-process control: a comment must not move the pin\n`;
  const commentFp = executableFingerprint(commentMutated);

  const idx = base.indexOf("\nexport ");
  const execMutated = idx === -1
    ? `const __rce5_g4_control = 1;\n${base}`
    : `${base.slice(0, idx)}\nconst __rce5_g4_control = 1;\n${base.slice(idx)}`;
  const execFp = executableFingerprint(execMutated);

  ok("RCE5_G4", "control: a comment-only edit does NOT move the executable fingerprint",
     commentFp === baseFp);
  ok("RCE5_G4", "control: an executable insertion DOES move the executable fingerprint (must flip)",
     execFp !== baseFp);
}

// ═════════════════════════════════════════════════════════════════════════════
// RCE5_G5 — no PRESENT-TENSE proxy-evidence claim for any `none` control
// ═════════════════════════════════════════════════════════════════════════════
// The three `none` controls have no external observation behind them. Their former
// proxies (email-auth for access_control / malware_protection; certificate expiry +
// the ASM backlog for patch_management_readiness) were WITHDRAWN with no replacement.
// A sentence may narrate that history; it may not assert it as current.
//
// The historical allowlist is an EXACT literal list, deliberately not a tense-detecting
// regex — a general "past tense" matcher is precisely the generic bypass this guard
// must not have. Adding a clause here is a deliberate, reviewable edit.
const HISTORICAL_ALLOWLIST = Object.freeze([
  "were once scored from",
  "was once scored from",
  "were withdrawn",
  "no replacement was introduced",
  "Indicator became",
  "denominator changed from",
  "no withdrawn proxy signal is used",
]);

const PROXY_VERBS = [
  "scored from", "driven by", "derived from", "based on", "informed by",
  "uses", "is used", "are used",
];
const PROXY_NOUNS = ["proxy", "proxies", "signal", "signals", "evidence"];

// Display names the documents use for the `none` controls, so the guard sees a claim
// phrased in prose as well as one phrased with the canonical key.
const CONTROL_ALIASES = {
  access_control: ["access_control", "User Access Control"],
  malware_protection: ["malware_protection", "Malware Protection"],
  patch_management_readiness: ["patch_management_readiness", "Security Update Management"],
};

// Non-vacuity: the guard must resolve a non-empty `none` set and actually read each file.
ok("RCE5_G5", "the live `none` control set is non-empty (guard is not vacuous)",
   liveNone.length > 0, `none set: [${liveNone.join(", ")}]`);

// Two granularities, deliberately different — each fixes a real failure mode found
// during fail-first:
//
//   BLOCK  associates the control NAME with the claim. A claim often refers back
//          anaphorically ("Their readiness categories are driven by proxy signals"),
//          so a strict per-sentence match misses it entirely.
//   CLAUSE decides whether a given claim is permitted. Matching the allowlist at
//          block level would let ONE historical clause whitelist an entire comment
//          block or paragraph, including a genuinely false claim beside it.
//
// A block is format-dependent, and getting this wrong makes the guard vacuous:
//   .md  → a paragraph (separated by a blank line). Splitting on every newline
//          would strand "Their readiness categories are driven by proxy signals"
//          in a block that names no control, and the claim would go unseen.
//   .js  → a contiguous run of `//` comment lines. Executable lines terminate a run,
//          so an unrelated code block can never be merged into a comment claim.
const blocksOf = (text, file) => {
  const lines = text.replace(/\r/g, "").split("\n");
  const raw = [];
  if (file.endsWith(".md")) {
    let cur = [];
    for (const line of lines) {
      if (line.trim() === "") { if (cur.length) { raw.push(cur.join("\n")); cur = []; } }
      else cur.push(line);
    }
    if (cur.length) raw.push(cur.join("\n"));
  } else {
    let cur = [];
    for (const line of lines) {
      if (/^\s*\/\//.test(line)) cur.push(line);
      else if (cur.length) { raw.push(cur.join("\n")); cur = []; }
    }
    if (cur.length) raw.push(cur.join("\n"));
  }
  return raw
    .map((b) => b.replace(/^[\s/*>#-]+/gm, " ").replace(/[ \t]+/g, " ").trim())
    .filter(Boolean);
};

// Clauses split on sentence punctuation AND newlines, so a comment block (whose
// lines carry no full stops) still yields fine-grained windows.
const clausesOf = (block) => block
  .split(/(?<=[.!?;:])\s+|\n+/)
  .map((c) => c.replace(/\s+/g, " ").trim())
  .filter(Boolean);

for (const file of G5_FILES) {
  let text = null;
  try { text = readFile(file); } catch (e) { text = null; }
  ok("RCE5_G5", `${file} is readable (guard is not vacuous)`, text !== null);
  if (text === null) continue;

  const offenders = [];
  for (const block of blocksOf(text, file)) {
    const blockLower = block.toLowerCase();
    // Does this block talk about a `none` control at all?
    // Defensive: a broken identifier mapping (e.g. `.key`, which yields undefined)
    // must make the GUARD FAIL CLEANLY via RCE5_G2 — never crash this loop, because a
    // crash produces no FAIL set and would be scored an unexpected-failure harness defect.
    const namesNone = liveNone.some((key) => {
      const aliases = (CONTROL_ALIASES[key] || [key]).filter((a) => typeof a === "string" && a);
      return aliases.some((alias) => blockLower.includes(alias.toLowerCase()));
    });
    if (!namesNone) continue;

    // Within such a block, judge each clause on its own merits.
    for (const clause of clausesOf(block)) {
      const lower = clause.toLowerCase();
      const hasVerb = PROXY_VERBS.some((v) => lower.includes(v));
      const hasNoun = PROXY_NOUNS.some((n) => new RegExp(`\\b${n}\\b`).test(lower));
      if (!hasVerb || !hasNoun) continue;
      // Permitted ONLY if this clause itself carries an exact enumerated
      // historical/retraction phrase. Proximity to one is not enough.
      const historical = HISTORICAL_ALLOWLIST.some((c) => lower.includes(c.toLowerCase()));
      if (!historical) offenders.push(clause.slice(0, 140));
    }
  }

  ok("RCE5_G5", `${file} asserts no present-tense proxy evidence for a \`none\` control`,
     offenders.length === 0, offenders.join(" || "));
}

// ── G3 must not be present in Unit 1 ─────────────────────────────────────────
// Self-check: this validator must not inspect the lib footprint sentence before
// Unit 2. Guards against a premature G3 being added and quietly turning CI red.
ok("RCE5_UNIT", "Unit 1 does not inspect the lib footprint sentence (G3 lands with Unit 2)",
   !G5_FILES.includes(LIB_FILE));

// ── Summary ──────────────────────────────────────────────────────────────────
for (const line of results) console.log(line);
console.log(`\nce-declaration-drift: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("ce-declaration-drift validation FAILED"); process.exit(1); }
console.log("ce-declaration-drift validation passed");
