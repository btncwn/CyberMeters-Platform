#!/usr/bin/env node
//
// Dependency-override governance — CI-blocking.
//
// An `overrides` entry in a workspace package.json replaces a version that some
// dependency DECLARED for itself. It is the repository's canonical mechanism for
// taking a security fix that upstream has not yet adopted — used correctly it
// INSTALLS a patched package, which is the opposite of suppressing `npm audit`.
// Used carelessly it is a silent permanent fork of someone else's graph.
//
// The gap this closes: before this guard, `frontend/package.json` carried two
// overrides (`esbuild`, `test-exclude`) that appeared in NO record anywhere —
// no owner, no review date, no removal criterion, and (as it turns out) no
// remaining advisory basis. They had become permanent forks by default. Prose in
// docs/DEPENDENCY-OVERRIDES.md cannot prevent that, because nothing mechanically
// binds the prose to the manifest.
//
// This validator is that binding. scripts/security/dependency-override-register.json
// is the machine-readable register; every live override must have exactly one
// record and every record must describe a live override. It fails closed on:
//
//   • an unregistered override, or a register entry whose override is gone;
//   • spec / resolved-version drift between register, manifest and lockfile;
//   • a `dev_only` claim contradicted by the locked production graph;
//   • a missing, malformed, or elapsed review deadline;
//   • a missing or off-vocabulary owner;
//   • a declared dependency root that the workspace manifest does not declare;
//   • duplicate ids or duplicate (workspace, package) pairs;
//   • unknown or missing fields that make a record ambiguous.
//
// Production reachability is decided by WALKING the lockfile from the manifest's
// production `dependencies` only — npm's own `dev` flag is then required to
// agree. Two independent derivations must both say "absent" before a dev-only
// claim stands; disagreement fails closed rather than picking a winner.
//
// The evaluator is pure and takes an injected `now`, so the mutation runner can
// exercise expiry without touching the wall clock (frozen-clock convention).
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

export const REGISTER_PATH = "scripts/security/dependency-override-register.json";
export const EXPECTED_SCHEMA = "cybermeters.dependency-override-register/v1";
export const GOVERNED_WORKSPACES = Object.freeze(["frontend", "workers/scan-api"]);

const REQUIRED_FIELDS = Object.freeze([
  "id", "workspace", "package", "declared_spec", "resolved_version",
  "dependency_root", "dependency_path", "reachability", "advisory_basis",
  "advisories_cleared", "reason", "removal_criterion", "owner",
  "introduced_on", "reviewed_on", "review_by", "record",
]);

// Conditional fields are legal only in the state that requires them; the
// unknown-field guard below rejects anything outside this union.
const OPTIONAL_FIELDS = Object.freeze([
  "production_closure_evidence",   // required iff reachability === "dev_only"
  "production_reachability_reason", // required iff reachability === "production_runtime"
  "historical_note",                // required iff advisory_basis === "historical"
  "range_justification",            // required iff declared_spec is not an exact version
]);

const REACHABILITY = Object.freeze(["dev_only", "production_runtime"]);
const ADVISORY_BASIS = Object.freeze(["current", "historical"]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ADVISORY_ID = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/;

const assertion = (name, passed, detail = "") => ({ name, passed: Boolean(passed), detail });
const nonEmpty = (value) => typeof value === "string" && value.trim().length > 0;

// An exact calendar date, rejecting real-looking but invalid days (2026-02-30).
function parseIsoDate(value) {
  if (!ISO_DATE.test(value || "")) return null;
  const ms = Date.parse(`${value}T00:00:00Z`);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString().slice(0, 10) === value ? ms : null;
}

// npm nested resolution: prefer the deepest node_modules under the requiring
// package, then walk up towards the root, exactly as Node/npm resolve.
function resolveLockEntry(lock, fromPath, name) {
  const segments = fromPath === "" ? [] : fromPath.split("/node_modules/");
  for (let depth = segments.length; depth >= 0; depth -= 1) {
    const prefix = segments.slice(0, depth).join("/node_modules/");
    const candidate = prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`;
    if (lock.packages && Object.prototype.hasOwnProperty.call(lock.packages, candidate)) {
      return candidate;
    }
  }
  return null;
}

// Independent production closure: walk from the root manifest's `dependencies`
// only. Optional and non-optional peer deps are followed because npm installs
// them into the shipped tree; devDependencies are never followed.
export function productionClosure(lock) {
  const rootEntry = (lock.packages || {})[""] || {};
  const reachable = new Set();
  const queue = [];
  for (const name of Object.keys(rootEntry.dependencies || {})) queue.push(["", name]);
  while (queue.length) {
    const [fromPath, name] = queue.pop();
    const key = resolveLockEntry(lock, fromPath, name);
    if (!key || reachable.has(key)) continue;
    reachable.add(key);
    const entry = lock.packages[key] || {};
    const next = {
      ...(entry.dependencies || {}),
      ...(entry.optionalDependencies || {}),
      ...(entry.peerDependencies || {}),
    };
    for (const dependency of Object.keys(next)) queue.push([key, dependency]);
  }
  // "node_modules/a" -> "a"; "node_modules/a/node_modules/@scope/b" -> "@scope/b".
  return new Set([...reachable].map((key) => key.replace(/^(?:.*\/)?node_modules\//, "")));
}

export function evaluateOverrideRegister({ register, workspaces, now }) {
  const results = [];
  const push = (name, passed, detail) => results.push(assertion(name, passed, detail));

  push("register: schema identifier is exact", register?.schema === EXPECTED_SCHEMA,
    `got ${JSON.stringify(register?.schema)}`);
  const vocabulary = Array.isArray(register?.owner_vocabulary) ? register.owner_vocabulary : null;
  push("register: owner vocabulary is a non-empty list", Boolean(vocabulary?.length));
  const entries = Array.isArray(register?.overrides) ? register.overrides : null;
  push("register: overrides is a list", Array.isArray(entries));
  // An invalid authoritative identity (no vocabulary, no override list) is a
  // load-bearing failure on its own. Continuing would cascade it into a per-record
  // owner failure for every entry and bury the real cause, so stop here.
  if (!entries || !vocabulary?.length) return results;

  // ── Record shape ───────────────────────────────────────────────────────────
  const allowed = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);
  const shapeProblems = [];
  for (const entry of entries) {
    const label = entry?.id || "<no id>";
    for (const field of REQUIRED_FIELDS) {
      if (!Object.prototype.hasOwnProperty.call(entry || {}, field)) {
        shapeProblems.push(`${label}: missing ${field}`);
      }
    }
    for (const field of Object.keys(entry || {})) {
      if (!allowed.has(field)) shapeProblems.push(`${label}: unknown field ${field}`);
    }
  }
  push("register: every record carries exactly the known fields", shapeProblems.length === 0,
    shapeProblems.join(" | "));
  if (shapeProblems.length) return results;

  const ids = entries.map((entry) => entry.id);
  push("register: override ids are unique", new Set(ids).size === ids.length);
  const pairs = entries.map((entry) => `${entry.workspace}::${entry.package}`);
  push("register: (workspace, package) pairs are unique", new Set(pairs).size === pairs.length,
    pairs.filter((pair, index) => pairs.indexOf(pair) !== index).join(", "));

  const ownerProblems = entries
    .filter((entry) => !nonEmpty(entry.owner) || !vocabulary.includes(entry.owner))
    .map((entry) => `${entry.id}: ${JSON.stringify(entry.owner)}`);
  push("register: every record names an owner from the canonical vocabulary",
    ownerProblems.length === 0, ownerProblems.join(" | "));

  const reasonProblems = entries
    .filter((entry) => !nonEmpty(entry.reason) || !nonEmpty(entry.removal_criterion))
    .map((entry) => entry.id);
  push("register: every record states a reason and a removal criterion",
    reasonProblems.length === 0, reasonProblems.join(", "));

  const workspaceProblems = entries
    .filter((entry) => !GOVERNED_WORKSPACES.includes(entry.workspace))
    .map((entry) => `${entry.id}: ${entry.workspace}`);
  push("register: every record targets a governed workspace",
    workspaceProblems.length === 0, workspaceProblems.join(" | "));

  // ── Dates ──────────────────────────────────────────────────────────────────
  const dateProblems = [];
  const expired = [];
  for (const entry of entries) {
    const introduced = parseIsoDate(entry.introduced_on);
    const reviewed = parseIsoDate(entry.reviewed_on);
    const reviewBy = parseIsoDate(entry.review_by);
    if (introduced === null) dateProblems.push(`${entry.id}: introduced_on ${JSON.stringify(entry.introduced_on)}`);
    if (reviewed === null) dateProblems.push(`${entry.id}: reviewed_on ${JSON.stringify(entry.reviewed_on)}`);
    if (reviewBy === null) dateProblems.push(`${entry.id}: review_by ${JSON.stringify(entry.review_by)}`);
    if (reviewed !== null && reviewBy !== null && reviewBy <= reviewed) {
      dateProblems.push(`${entry.id}: review_by is not after reviewed_on`);
    }
    if (reviewBy !== null && reviewBy < now.getTime()) expired.push(`${entry.id}: ${entry.review_by}`);
  }
  push("register: every record dates are exact ISO 8601 calendar dates in order",
    dateProblems.length === 0, dateProblems.join(" | "));
  push("register: no override review deadline has elapsed", expired.length === 0,
    expired.join(" | "));

  // ── Advisory basis ─────────────────────────────────────────────────────────
  const basisProblems = [];
  for (const entry of entries) {
    if (!ADVISORY_BASIS.includes(entry.advisory_basis)) {
      basisProblems.push(`${entry.id}: advisory_basis ${JSON.stringify(entry.advisory_basis)}`);
      continue;
    }
    const cleared = Array.isArray(entry.advisories_cleared) ? entry.advisories_cleared : null;
    if (!cleared) { basisProblems.push(`${entry.id}: advisories_cleared is not a list`); continue; }
    const malformed = cleared.filter((id) => !ADVISORY_ID.test(id));
    if (malformed.length) basisProblems.push(`${entry.id}: malformed advisory id ${malformed.join(", ")}`);
    if (entry.advisory_basis === "current" && cleared.length === 0) {
      basisProblems.push(`${entry.id}: advisory_basis "current" with no advisory cleared`);
    }
    if (entry.advisory_basis === "historical") {
      if (cleared.length > 0) basisProblems.push(`${entry.id}: advisory_basis "historical" still lists advisories`);
      if (!nonEmpty(entry.historical_note)) basisProblems.push(`${entry.id}: historical without a historical_note`);
    }
    if (entry.advisory_basis === "current" && Object.prototype.hasOwnProperty.call(entry, "historical_note")) {
      basisProblems.push(`${entry.id}: advisory_basis "current" carries a historical_note`);
    }
  }
  push("register: advisory basis matches the advisories listed",
    basisProblems.length === 0, basisProblems.join(" | "));

  // ── Reachability declarations ──────────────────────────────────────────────
  const declarationProblems = [];
  for (const entry of entries) {
    if (!REACHABILITY.includes(entry.reachability)) {
      declarationProblems.push(`${entry.id}: reachability ${JSON.stringify(entry.reachability)}`);
      continue;
    }
    if (entry.reachability === "dev_only") {
      if (!nonEmpty(entry.production_closure_evidence)) {
        declarationProblems.push(`${entry.id}: dev_only without production_closure_evidence`);
      }
      if (Object.prototype.hasOwnProperty.call(entry, "production_reachability_reason")) {
        declarationProblems.push(`${entry.id}: dev_only carries a production_reachability_reason`);
      }
    } else {
      if (!nonEmpty(entry.production_reachability_reason)) {
        declarationProblems.push(`${entry.id}: production_runtime without production_reachability_reason`);
      }
      if (Object.prototype.hasOwnProperty.call(entry, "production_closure_evidence")) {
        declarationProblems.push(`${entry.id}: production_runtime claims closure evidence`);
      }
    }
    if (!EXACT_VERSION.test(entry.declared_spec) && !nonEmpty(entry.range_justification)) {
      declarationProblems.push(`${entry.id}: non-exact spec ${entry.declared_spec} without a range_justification`);
    }
    if (EXACT_VERSION.test(entry.declared_spec) && Object.prototype.hasOwnProperty.call(entry, "range_justification")) {
      declarationProblems.push(`${entry.id}: exact spec carries a range_justification`);
    }
    if (!Array.isArray(entry.dependency_path) || entry.dependency_path.length < 2) {
      declarationProblems.push(`${entry.id}: dependency_path must name a root and the package`);
    } else if (entry.dependency_path[0] !== entry.dependency_root) {
      declarationProblems.push(`${entry.id}: dependency_path does not start at dependency_root`);
    } else if (entry.dependency_path[entry.dependency_path.length - 1] !== entry.package) {
      declarationProblems.push(`${entry.id}: dependency_path does not end at the package`);
    }
  }
  push("register: reachability declarations are complete and mutually exclusive",
    declarationProblems.length === 0, declarationProblems.join(" | "));

  // ── Binding to the real manifests and lockfiles ────────────────────────────
  const unregistered = [];
  const stale = [];
  const specDrift = [];
  const resolvedDrift = [];
  const rootDrift = [];
  const devClaimContradicted = [];
  const devFlagDisagreement = [];

  for (const workspace of GOVERNED_WORKSPACES) {
    const source = workspaces[workspace];
    if (!source) { stale.push(`${workspace}: workspace not supplied`); continue; }
    const declared = source.manifest?.overrides || {};
    const records = entries.filter((entry) => entry.workspace === workspace);
    const byPackage = new Map(records.map((entry) => [entry.package, entry]));

    for (const name of Object.keys(declared)) {
      if (!byPackage.has(name)) unregistered.push(`${workspace}: ${name}`);
    }
    for (const entry of records) {
      if (!Object.prototype.hasOwnProperty.call(declared, entry.package)) {
        stale.push(`${entry.id}: ${workspace}/${entry.package} is not overridden`);
        continue;
      }
      if (declared[entry.package] !== entry.declared_spec) {
        specDrift.push(`${entry.id}: manifest ${declared[entry.package]} vs register ${entry.declared_spec}`);
      }
      const lock = source.lock || {};
      const locked = (lock.packages || {})[`node_modules/${entry.package}`];
      if (!locked) {
        resolvedDrift.push(`${entry.id}: no lockfile entry for ${entry.package}`);
      } else if (locked.version !== entry.resolved_version) {
        resolvedDrift.push(`${entry.id}: lock ${locked.version} vs register ${entry.resolved_version}`);
      }

      const manifestDeps = source.manifest?.dependencies || {};
      const manifestDevDeps = source.manifest?.devDependencies || {};
      if (!Object.prototype.hasOwnProperty.call(manifestDeps, entry.dependency_root) &&
          !Object.prototype.hasOwnProperty.call(manifestDevDeps, entry.dependency_root)) {
        rootDrift.push(`${entry.id}: root ${entry.dependency_root} is not declared by ${workspace}`);
      }

      const closure = productionClosure(lock);
      const inProductionClosure = closure.has(entry.package);
      if (entry.reachability === "dev_only" && inProductionClosure) {
        devClaimContradicted.push(`${entry.id}: ${entry.package} IS reachable from a production root`);
      }
      if (entry.reachability === "production_runtime" && !inProductionClosure) {
        devClaimContradicted.push(`${entry.id}: declared production_runtime but absent from the production closure`);
      }
      // npm's own dev flag must agree with the independent walk.
      if (locked) {
        const npmSaysDev = locked.dev === true;
        if (npmSaysDev === inProductionClosure) {
          devFlagDisagreement.push(`${entry.id}: npm dev=${npmSaysDev}, closure walk reachable=${inProductionClosure}`);
        }
      }
    }
  }

  push("binding: every live override in every governed workspace is registered",
    unregistered.length === 0, unregistered.join(" | "));
  push("binding: no register record survives its override", stale.length === 0, stale.join(" | "));
  push("binding: registered spec matches the workspace manifest exactly",
    specDrift.length === 0, specDrift.join(" | "));
  push("binding: registered resolved version matches the committed lockfile",
    resolvedDrift.length === 0, resolvedDrift.join(" | "));
  push("binding: declared dependency root is declared by the workspace manifest",
    rootDrift.length === 0, rootDrift.join(" | "));
  push("closure: reachability claim matches the locked production graph",
    devClaimContradicted.length === 0, devClaimContradicted.join(" | "));
  push("closure: npm dev classification agrees with the independent closure walk",
    devFlagDisagreement.length === 0, devFlagDisagreement.join(" | "));

  return results;
}

export function loadInputs(repoRoot = root) {
  const register = JSON.parse(fs.readFileSync(path.join(repoRoot, REGISTER_PATH), "utf8"));
  const workspaces = {};
  for (const workspace of GOVERNED_WORKSPACES) {
    workspaces[workspace] = {
      manifest: JSON.parse(fs.readFileSync(path.join(repoRoot, workspace, "package.json"), "utf8")),
      lock: JSON.parse(fs.readFileSync(path.join(repoRoot, workspace, "package-lock.json"), "utf8")),
    };
  }
  return { register, workspaces };
}

// CLI entry — the live clock is used here and ONLY here.
if (import.meta.url === `file://${process.argv[1]}`) {
  let pass = 0, fail = 0;
  let checks;
  try {
    const { register, workspaces } = loadInputs(root);
    checks = evaluateOverrideRegister({ register, workspaces, now: new Date() });
  } catch (error) {
    console.error(`FAIL dependency-override register could not be read or parsed — ${error.message}`);
    process.exit(1);
  }
  for (const check of checks) {
    if (check.passed) pass += 1;
    else { fail += 1; console.log(`FAIL ${check.name}${check.detail ? " — " + check.detail : ""}`); }
  }
  console.log(`\ndependency-overrides: ${pass} passed, ${fail} failed`);
  if (fail > 0) { console.error("dependency-override validation FAILED"); process.exit(1); }
  console.log("dependency-override validation passed");
}
