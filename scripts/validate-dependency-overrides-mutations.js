#!/usr/bin/env node
//
// Dependency-override governance — semantic mutation proof. CI-blocking.
//
// Two independent obligations, because either alone is worthless:
//
//   PART A — negative fixtures. Each fixture corrupts the register or the
//   workspace inputs in exactly one way and predeclares the EXACT SET of
//   assertion names that must fail. Exact-set equality, not "at least one
//   failure": a fixture that fails for a different reason than the one it was
//   written for is a wrong-reason pass and is rejected here.
//
//   PART B — guard mutants. Each enforcement guard is neutered in the REAL
//   validator source (its condition forced to `true`), the paired fixture is
//   re-evaluated in a FRESH child process, and the guard is KILLED only if the
//   fixture stops failing. A guard that can be removed without any fixture
//   noticing is decoration; this is what proves each rule is load-bearing.
//
// Harness controls guard the harness itself:
//   • no-op control — a comment-only source edit must leave the fixture failing
//     exactly as before (proves a "kill" is not just noise from editing);
//   • wrong-target control — neutering a DIFFERENT guard must leave the fixture
//     failing exactly as before (proves a kill is attributable to that guard).
//
// Expected sets are declared BEFORE the run and are never edited to match an
// observed result. The clock is injected (frozen-clock convention) so expiry is
// exercised without depending on the wall clock.
//
// Node 24+.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadInputs } from "./validate-dependency-overrides.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(root, "scripts", "validate-dependency-overrides.js");

// Frozen clocks — never the wall clock.
const NOW = "2026-08-03";
const NOW_FAR_FUTURE = "2027-06-01";

const base = loadInputs(root);
const clone = (value) => structuredClone(value);
const entryOf = (register, id) => register.overrides.find((item) => item.id === id);

// ── PART A: fixtures and their predeclared exact failure sets ────────────────
// Keyed by fixture name. `now` is always injected.
export const FIXTURES = {
  baseline: () => ({ register: clone(base.register), workspaces: clone(base.workspaces), now: NOW }),

  "unregistered-override": () => {
    const workspaces = clone(base.workspaces);
    workspaces.frontend.manifest.overrides = { lodash: "4.17.21" };
    return { register: clone(base.register), workspaces, now: NOW };
  },

  "stale-record": () => {
    const workspaces = clone(base.workspaces);
    delete workspaces["workers/scan-api"].manifest.overrides.sharp;
    return { register: clone(base.register), workspaces, now: NOW };
  },

  "spec-drift": () => {
    const workspaces = clone(base.workspaces);
    workspaces["workers/scan-api"].manifest.overrides.sharp = "0.35.2";
    return { register: clone(base.register), workspaces, now: NOW };
  },

  "resolved-version-drift": () => {
    const workspaces = clone(base.workspaces);
    workspaces["workers/scan-api"].lock.packages["node_modules/sharp"].version = "0.35.2";
    return { register: clone(base.register), workspaces, now: NOW };
  },

  "package-name-drift": () => {
    const register = clone(base.register);
    const entry = entryOf(register, "OV-1");
    entry.package = "sharp-image";
    entry.dependency_path = ["wrangler", "miniflare", "sharp-image"];
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "dependency-root-drift": () => {
    const register = clone(base.register);
    const entry = entryOf(register, "OV-1");
    entry.dependency_root = "not-a-declared-dependency";
    entry.dependency_path = ["not-a-declared-dependency", "miniflare", "sharp"];
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "dependency-path-drift": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").dependency_path = ["wrangler", "miniflare", "some-other-package"];
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  // The dev-only claim, contradicted: sharp becomes reachable from a
  // production root while still declared dev_only.
  "dev-only-claim-contradicted": () => {
    const workspaces = clone(base.workspaces);
    const lock = workspaces["workers/scan-api"].lock;
    lock.packages[""].dependencies.sharp = "0.35.3";
    return { register: clone(base.register), workspaces, now: NOW };
  },

  // Runtime reachability claimed where the graph shows none.
  "runtime-claim-without-reachability": () => {
    const register = clone(base.register);
    const entry = entryOf(register, "OV-1");
    entry.reachability = "production_runtime";
    delete entry.production_closure_evidence;
    entry.production_reachability_reason = "asserted without evidence";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "expired-review-deadline": () => ({
    register: clone(base.register), workspaces: clone(base.workspaces), now: NOW_FAR_FUTURE,
  }),

  "missing-review-by": () => {
    const register = clone(base.register);
    delete entryOf(register, "OV-1").review_by;
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "malformed-review-by": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").review_by = "2026-13-45";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "review-by-not-after-reviewed-on": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").review_by = "2026-08-03";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "missing-owner": () => {
    const register = clone(base.register);
    delete entryOf(register, "OV-1").owner;
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "empty-owner": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").owner = "   ";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "off-vocabulary-owner": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").owner = "somebody else";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "duplicate-record": () => {
    const register = clone(base.register);
    register.overrides.push(clone(entryOf(register, "OV-1")));
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "unknown-field": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").permanent = true;
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "current-basis-without-advisory": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").advisories_cleared = [];
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "historical-basis-still-listing-advisories": () => {
    const register = clone(base.register);
    const entry = entryOf(register, "OV-1");
    entry.advisory_basis = "historical";
    entry.historical_note = "fixture: historical basis must not retain a cleared advisory";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "malformed-advisory-id": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").advisories_cleared = ["CVE-2026-1234"];
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "range-spec-without-justification": () => {
    const register = clone(base.register);
    const workspaces = clone(base.workspaces);
    entryOf(register, "OV-1").declared_spec = "^0.35.3";
    workspaces["workers/scan-api"].manifest.overrides.sharp = "^0.35.3";
    return { register, workspaces, now: NOW };
  },

  "runtime-record-claiming-closure-evidence": () => {
    const register = clone(base.register);
    const workspaces = clone(base.workspaces);
    const entry = entryOf(register, "OV-1");
    entry.reachability = "production_runtime";
    entry.production_reachability_reason = "fixture: injected production reachability";
    workspaces["workers/scan-api"].manifest.dependencies.sharp = "0.35.3";
    workspaces["workers/scan-api"].lock.packages[""].dependencies.sharp = "0.35.3";
    delete workspaces["workers/scan-api"].lock.packages["node_modules/sharp"].dev;
    return { register, workspaces, now: NOW };
  },

  "missing-reason-and-removal-criterion": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").removal_criterion = "";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "ungoverned-workspace": () => {
    const register = clone(base.register);
    entryOf(register, "OV-1").workspace = "workers/email-ingest";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "schema-drift": () => {
    const register = clone(base.register);
    register.schema = "cybermeters.dependency-override-register/v2";
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "overrides-not-a-list": () => {
    const register = clone(base.register);
    register.overrides = { "OV-1": {} };
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },

  "empty-owner-vocabulary": () => {
    const register = clone(base.register);
    register.owner_vocabulary = [];
    return { register, workspaces: clone(base.workspaces), now: NOW };
  },
};

// Predeclared EXACT failing-assertion sets. Written before the first run.
export const EXPECTED = {
  baseline: [],
  "unregistered-override": [
    "binding: every live override in every governed workspace is registered",
  ],
  "stale-record": [
    "binding: no register record survives its override",
  ],
  "spec-drift": [
    "binding: registered spec matches the workspace manifest exactly",
  ],
  "resolved-version-drift": [
    "binding: registered resolved version matches the committed lockfile",
  ],
  "package-name-drift": [
    "binding: every live override in every governed workspace is registered",
    "binding: no register record survives its override",
  ],
  "dependency-root-drift": [
    "binding: declared dependency root is declared by the workspace manifest",
  ],
  "dependency-path-drift": [
    "register: reachability declarations are complete and mutually exclusive",
  ],
  "dev-only-claim-contradicted": [
    "closure: reachability claim matches the locked production graph",
    "closure: npm dev classification agrees with the independent closure walk",
  ],
  // Only the reachability claim fires: npm marks sharp dev=true and the closure
  // walk finds it absent from production, so the two derivations AGREE. The
  // agreement guard is silent here by design — it catches disagreement, not a
  // false claim, which is the preceding guard's job.
  "runtime-claim-without-reachability": [
    "closure: reachability claim matches the locked production graph",
  ],
  "expired-review-deadline": [
    "register: no override review deadline has elapsed",
  ],
  "missing-review-by": [
    "register: every record carries exactly the known fields",
  ],
  "malformed-review-by": [
    "register: every record dates are exact ISO 8601 calendar dates in order",
  ],
  "review-by-not-after-reviewed-on": [
    "register: every record dates are exact ISO 8601 calendar dates in order",
  ],
  "missing-owner": [
    "register: every record carries exactly the known fields",
  ],
  "empty-owner": [
    "register: every record names an owner from the canonical vocabulary",
  ],
  "off-vocabulary-owner": [
    "register: every record names an owner from the canonical vocabulary",
  ],
  "duplicate-record": [
    "register: override ids are unique",
    "register: (workspace, package) pairs are unique",
  ],
  "unknown-field": [
    "register: every record carries exactly the known fields",
  ],
  "current-basis-without-advisory": [
    "register: advisory basis matches the advisories listed",
  ],
  "historical-basis-still-listing-advisories": [
    "register: advisory basis matches the advisories listed",
  ],
  "malformed-advisory-id": [
    "register: advisory basis matches the advisories listed",
  ],
  "range-spec-without-justification": [
    "register: reachability declarations are complete and mutually exclusive",
  ],
  "runtime-record-claiming-closure-evidence": [
    "register: reachability declarations are complete and mutually exclusive",
  ],
  "missing-reason-and-removal-criterion": [
    "register: every record states a reason and a removal criterion",
  ],
  // Moving the record out of the governed set genuinely orphans the live
  // `sharp` override too — it is no longer claimed by any governed record.
  // Both failures are correct and neither masks the other.
  "ungoverned-workspace": [
    "register: every record targets a governed workspace",
    "binding: every live override in every governed workspace is registered",
  ],
  "schema-drift": [
    "register: schema identifier is exact",
  ],
  "overrides-not-a-list": [
    "register: overrides is a list",
  ],
  "empty-owner-vocabulary": [
    "register: owner vocabulary is a non-empty list",
  ],
};

// ── PART B: guard mutants — guard assertion name → fixture that must catch it ─
export const GUARD_MUTANTS = Object.freeze([
  ["binding: every live override in every governed workspace is registered", "unregistered-override"],
  ["binding: no register record survives its override", "stale-record"],
  ["binding: registered spec matches the workspace manifest exactly", "spec-drift"],
  ["binding: registered resolved version matches the committed lockfile", "resolved-version-drift"],
  ["binding: declared dependency root is declared by the workspace manifest", "dependency-root-drift"],
  ["closure: reachability claim matches the locked production graph", "dev-only-claim-contradicted"],
  ["closure: npm dev classification agrees with the independent closure walk", "dev-only-claim-contradicted"],
  ["register: no override review deadline has elapsed", "expired-review-deadline"],
  ["register: every record dates are exact ISO 8601 calendar dates in order", "malformed-review-by"],
  ["register: every record names an owner from the canonical vocabulary", "off-vocabulary-owner"],
  ["register: override ids are unique", "duplicate-record"],
  ["register: (workspace, package) pairs are unique", "duplicate-record"],
  ["register: every record carries exactly the known fields", "unknown-field"],
  ["register: advisory basis matches the advisories listed", "malformed-advisory-id"],
  ["register: reachability declarations are complete and mutually exclusive", "dependency-path-drift"],
  ["register: every record states a reason and a removal criterion", "missing-reason-and-removal-criterion"],
  ["register: every record targets a governed workspace", "ungoverned-workspace"],
  ["register: schema identifier is exact", "schema-drift"],
  ["register: overrides is a list", "overrides-not-a-list"],
  ["register: owner vocabulary is a non-empty list", "empty-owner-vocabulary"],
]);

// Locate `push("<name>", …);` and force its condition to `true`, leaving the
// assertion present but toothless. Balanced-paren scan so nested calls survive.
export function neuterGuard(source, name) {
  const marker = `push(${JSON.stringify(name)},`;
  const start = source.indexOf(marker);
  if (start < 0) return null;
  let depth = 0;
  let index = source.indexOf("(", start);
  const open = index;
  for (; index < source.length; index += 1) {
    const ch = source[index];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  if (depth !== 0) return null;
  const end = index + 1;
  const replacement = `push(${JSON.stringify(name)}, true)`;
  if (source.slice(open, end) === replacement) return null;
  return source.slice(0, start) + replacement + source.slice(end);
}

const CHILD = `
import { evaluateOverrideRegister } from ${JSON.stringify(VALIDATOR)};
import { FIXTURES } from ${JSON.stringify(path.join(root, "scripts", "validate-dependency-overrides-mutations.js"))};
const fixture = FIXTURES[process.argv[1]]();
const failed = evaluateOverrideRegister({
  register: fixture.register,
  workspaces: fixture.workspaces,
  now: new Date(fixture.now + "T00:00:00Z"),
}).filter((check) => !check.passed).map((check) => check.name);
console.log("__RESULT__" + JSON.stringify(failed));
`;

function failingSet(fixtureName) {
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", CHILD, fixtureName],
    { cwd: root, encoding: "utf8" });
  const marker = out.lastIndexOf("__RESULT__");
  if (marker < 0) throw new Error(`child produced no result for ${fixtureName}: ${out}`);
  return JSON.parse(out.slice(marker + "__RESULT__".length)).sort();
}

const sameSet = (a, b) =>
  JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

// The harness body runs ONLY as a CLI. The mutant child process imports
// FIXTURES from this module, so importing it must never start a nested run.
function main() {
let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass += 1;
  else { fail += 1; console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); }
};

const original = fs.readFileSync(VALIDATOR, "utf8");
const restore = () => fs.writeFileSync(VALIDATOR, original);

try {
  // ── PART A ────────────────────────────────────────────────────────────────
  console.log("── Part A: negative fixtures (exact-set equality) ──");
  const declared = Object.keys(EXPECTED).sort();
  const built = Object.keys(FIXTURES).sort();
  ok("every fixture has a predeclared expected set", sameSet(declared, built),
    `fixtures ${built.length} vs expectations ${declared.length}`);

  for (const name of built) {
    const actual = failingSet(name);
    const expected = EXPECTED[name] || [];
    ok(`fixture ${name}`, sameSet(actual, expected),
      `expected [${expected.join(" | ")}] got [${actual.join(" | ")}]`);
  }

  // A registered override must be visibly EXERCISED on the happy path, not
  // silently absent: the baseline must actually evaluate real records.
  ok("baseline exercises every registered override",
    base.register.overrides.length === 1 &&
      sameSet(base.register.overrides.map((entry) => entry.id), ["OV-1"]),
    `ids ${base.register.overrides.map((entry) => entry.id).join(",")}`);

  // ── PART B ────────────────────────────────────────────────────────────────
  console.log("\n── Part B: guard mutants (each guard must be load-bearing) ──");
  for (const [guard, fixtureName] of GUARD_MUTANTS) {
    const mutated = neuterGuard(original, guard);
    if (!mutated) { ok(`mutant ${guard}`, false, "guard not found in source"); continue; }
    fs.writeFileSync(VALIDATOR, mutated);
    let after;
    try { after = failingSet(fixtureName); } finally { restore(); }
    const before = EXPECTED[fixtureName];
    const killed = before.includes(guard) && !after.includes(guard) &&
      sameSet(after, before.filter((name) => name !== guard));
    ok(`mutant killed: ${guard}`, killed,
      `via ${fixtureName}: before [${before.join(" | ")}] after [${after.join(" | ")}]`);
  }

  // ── Harness controls ──────────────────────────────────────────────────────
  console.log("\n── Harness controls ──");
  const controlGuard = "binding: every live override in every governed workspace is registered";
  const controlFixture = "unregistered-override";

  const noop = original.replace(
    "// Node 24+.",
    "// Node 24+.\n// mutation-harness no-op control line (semantically inert).");
  ok("no-op control changes the source", noop !== original);
  fs.writeFileSync(VALIDATOR, noop);
  let noopResult;
  try { noopResult = failingSet(controlFixture); } finally { restore(); }
  ok("no-op control leaves the fixture failing exactly as before",
    sameSet(noopResult, EXPECTED[controlFixture]),
    `got [${noopResult.join(" | ")}]`);

  const wrongTarget = neuterGuard(original, "register: every record targets a governed workspace");
  ok("wrong-target control mutates a different guard", Boolean(wrongTarget));
  fs.writeFileSync(VALIDATOR, wrongTarget);
  let wrongResult;
  try { wrongResult = failingSet(controlFixture); } finally { restore(); }
  ok("wrong-target control leaves the fixture failing exactly as before",
    sameSet(wrongResult, EXPECTED[controlFixture]),
    `got [${wrongResult.join(" | ")}]`);
} finally {
  restore();
}

if (fs.readFileSync(VALIDATOR, "utf8") !== original) {
  console.error("FAIL validator source was not restored");
  process.exit(1);
}

console.log(`\ndependency-override mutations: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("dependency-override mutation proof FAILED"); process.exit(1); }
console.log("dependency-override mutation proof passed");
}

if (import.meta.url === `file://${process.argv[1]}`) main();
