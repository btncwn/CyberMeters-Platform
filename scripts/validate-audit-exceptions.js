#!/usr/bin/env node
// Full-graph frontend audit with explicit, expiring risk acceptance. This does
// not install a fix or change the high/critical threshold. The evaluator is pure;
// CLI I/O is fixed to the frontend workspace and never accepts an audit file.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SEVERITIES = ["info", "low", "moderate", "high", "critical"];
const PACKAGE = /^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/;
const GHSA = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
const FIELDS = ["id", "workspace", "package", "advisories", "lock_paths",
  "reachability", "production_closure_evidence", "reason", "removal_criterion",
  "owner", "introduced_on", "reviewed_on", "review_by", "record"];
const object = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const text = (x) => typeof x === "string" && x.trim().length > 0;
const keysAre = (x, fields) => object(x) &&
  JSON.stringify(Object.keys(x).sort()) === JSON.stringify([...fields].sort());
const unique = (xs) => new Set(xs).size === xs.length;
const sameSet = (xs, ys) => JSON.stringify([...xs].sort()) === JSON.stringify([...ys].sort());
const packagePaths = (lock, name) => Object.keys(lock.packages)
  .filter((p) => p.startsWith("node_modules/") && p.endsWith(`/${name}`)).sort();

function date(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const ms = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === value ? ms : null;
}

function toolCompleted(result) {
  return object(result) && !result.error && result.signal == null &&
    [0, 1].includes(result.status) && typeof result.stdout === "string";
}

function parse(stdout) {
  try { return JSON.parse(stdout); } catch { return null; }
}

function advisoryId(via) {
  const match = typeof via?.url === "string"
    ? /^https:\/\/github\.com\/advisories\/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/.exec(via.url)
    : null;
  return match?.[1] || null;
}

function matches(entry, advisory, name, via) {
  return entry.package === name && via.name === name && via.dependency === name &&
    advisory.id === advisoryId(via) && advisory.range === via.range;
}

export function evaluateAuditExceptions({ workspace, auditResult, register, lock,
  productionResults, owners, now = new Date() }) {
  const results = [];
  const check = (name, passed, detail = "") => {
    results.push({ name, passed: Boolean(passed), detail });
    return Boolean(passed);
  };

  if (!check("audit-tool", toolCompleted(auditResult), "npm audit must complete with JSON, without spawn/signal/tool errors")) return results;
  const audit = parse(auditResult.stdout);
  if (!check("audit-schema", object(audit) && !Object.hasOwn(audit, "error") &&
    audit.auditReportVersion === 2 && object(audit.vulnerabilities) &&
    object(audit.metadata?.vulnerabilities), "expected npm audit report v2")) return results;
  const findings = Object.entries(audit.vulnerabilities);
  const counts = audit.metadata.vulnerabilities;
  if (!check("audit-counts", SEVERITIES.every((s) => Number.isInteger(counts[s]) &&
    counts[s] === findings.filter(([, v]) => v?.severity === s).length) &&
    Number.isInteger(counts.total) && counts.total === findings.length &&
    (auditResult.status === 0 || findings.length > 0), "counts and process result must agree with the findings")) return results;

  if (!check("lock-schema", object(lock) && lock.lockfileVersion === 3 &&
    object(lock.packages) && object(lock.packages[""]), "expected the committed npm v3 lock")) return results;
  const findingShape = findings.every(([name, v]) => PACKAGE.test(name) && object(v) &&
    v.name === name && SEVERITIES.includes(v.severity) &&
    Array.isArray(v.nodes) && v.nodes.length > 0 && unique(v.nodes) &&
    v.nodes.every((p) => typeof p === "string" && packagePaths(lock, name).includes(p)) &&
    Array.isArray(v.via) && v.via.length > 0 && v.via.every((via) =>
      typeof via === "string" ? Object.hasOwn(audit.vulnerabilities, via) :
        object(via) && via.name === name && via.dependency === name &&
        text(via.url) && text(via.range) && SEVERITIES.includes(via.severity) &&
        SEVERITIES.indexOf(v.severity) >= SEVERITIES.indexOf(via.severity)));
  if (!check("audit-findings", findingShape, "findings must bind to real lock paths and complete advisory/via identities")) return results;

  if (!check("register-schema", keysAre(register, ["schema", "reviewed_on", "exceptions"]) &&
    register.schema === "cybermeters.audit-exception-register/v1" &&
    Array.isArray(register.exceptions), "unknown or incomplete exception register")) return results;
  const entries = register.exceptions;
  if (!check("record-shape", entries.every((e) => keysAre(e, FIELDS) &&
    Array.isArray(e.advisories) && e.advisories.length > 0 &&
    e.advisories.every((a) => keysAre(a, ["id", "range"]) && GHSA.test(a.id) && text(a.range)) &&
    Array.isArray(e.lock_paths) && e.lock_paths.length > 0 && e.lock_paths.every(text)),
  "records must carry exactly the declared fields")) return results;
  if (!check("record-identity", entries.every((e) => /^E-[1-9][0-9]*$/.test(e.id) &&
    PACKAGE.test(e.package) && unique(e.lock_paths) &&
    unique(e.advisories.map((a) => a.id))) && unique(entries.map((e) => e.id)) &&
    unique(entries.map((e) => `${e.workspace}::${e.package}`)), "ambiguous or duplicate exception")) return results;
  if (!check("workspace", workspace === "frontend" && entries.every((e) => e.workspace === workspace),
    "this gate only accepts records for its full frontend graph")) return results;
  if (!check("owner", Array.isArray(owners) && owners.length > 0 &&
    entries.every((e) => text(e.owner) && owners.includes(e.owner)), "owner must come from the canonical override vocabulary")) return results;

  const instant = new Date(now);
  const today = Number.isFinite(instant.getTime()) ? date(instant.toISOString().slice(0, 10)) : null;
  if (!check("dates", today !== null && date(register.reviewed_on) !== null &&
    date(register.reviewed_on) <= today && entries.every((e) => {
      const introduced = date(e.introduced_on), reviewed = date(e.reviewed_on), by = date(e.review_by);
      return introduced !== null && reviewed !== null && by !== null &&
        introduced <= reviewed && reviewed <= today && by > reviewed &&
        by >= today && by - reviewed <= 90 * 86400_000;
    }), "UTC calendar dates must be valid, ordered, unexpired, and within 90 days of review")) return results;
  if (!check("record-purpose", entries.every((e) => text(e.reason) && text(e.removal_criterion) &&
    e.reachability === "dev_only" &&
    e.production_closure_evidence === `npm ls --omit=dev ${e.package}` &&
    e.record === `docs/AUDIT-EXCEPTIONS.md#${e.id.toLowerCase()}`),
  "a risk acceptance needs its dev-only evidence, owner-facing reason, removal criterion and docs anchor")) return results;
  if (!check("lock-binding", entries.every((e) =>
    sameSet(e.lock_paths, packagePaths(lock, e.package)) &&
    e.lock_paths.every((p) => lock.packages[p]?.dev === true)),
  "every locked path of an excepted package must be listed and dev=true")) return results;

  if (!check("production-closure", entries.every((e) => {
    const result = productionResults?.[e.package];
    if (!toolCompleted(result)) return false;
    const tree = parse(result.stdout);
    return object(tree) && !Object.hasOwn(tree, "error") &&
      (!Object.hasOwn(tree, "problems") || (Array.isArray(tree.problems) && tree.problems.length === 0)) &&
      tree.name === lock.packages[""].name && tree.version === lock.packages[""].version &&
      (!Object.hasOwn(tree, "dependencies") || (object(tree.dependencies) && Object.keys(tree.dependencies).length === 0));
  }), "npm ls --omit=dev must complete with the matching workspace and an empty tree")) return results;

  const isExcepted = (name, via) => entries.some((e) =>
    e.advisories.some((a) => matches(e, a, name, via)));
  if (!check("no-stale-record", entries.every((e) => e.advisories.every((a) =>
    findings.some(([name, v]) => v.via.some((via) => object(via) && matches(e, a, name, via))))),
  "every registered advisory must still match a current finding exactly")) return results;

  function covered(name, visiting = new Set()) {
    if (visiting.has(name)) return false;
    const v = audit.vulnerabilities[name];
    if (!v) return false;
    const next = new Set([...visiting, name]);
    return v.via.every((via) => typeof via === "string" ? covered(via, next) : isExcepted(name, via));
  }
  const unaccepted = findings.filter(([name, v]) =>
    ["high", "critical"].includes(v.severity) && !covered(name)).map(([name]) => name);
  check("high-critical-coverage", unaccepted.length === 0,
    `unaccepted high/critical packages: ${unaccepted.join(", ") || "none"}`);
  return results;
}

// Injectable only for the offline command-contract proof; the CLI calls this
// without overrides. Including every dependency class defeats inherited omit
// configuration. The sole --omit invocation is the separate reachability proof.
export function collectAuditInputs(repoRoot, runner = spawnSync) {
  const read = (p) => JSON.parse(fs.readFileSync(path.join(repoRoot, p), "utf8"));
  const register = read("scripts/security/audit-exception-register.json");
  const run = (args) => {
    const r = runner("npm", args, { cwd: path.join(repoRoot, "frontend"), encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024, timeout: 120_000,
      env: { ...process.env, npm_config_registry: "https://registry.npmjs.org", NO_UPDATE_NOTIFIER: "1" } });
    return { status: r.status, signal: r.signal, error: r.error ? String(r.error) : null, stdout: r.stdout };
  };
  const auditResult = run(["audit", "--json", "--include=dev", "--include=optional", "--include=peer"]);
  const productionResults = {};
  for (const e of Array.isArray(register.exceptions) ? register.exceptions : []) {
    if (typeof e?.package === "string" && PACKAGE.test(e.package)) {
      productionResults[e.package] = run(["ls", "--omit=dev", "--json", e.package]);
    }
  }
  return { workspace: "frontend", auditResult, register,
    lock: read("frontend/package-lock.json"), productionResults,
    owners: read("scripts/security/dependency-override-register.json").owner_vocabulary };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) throw new Error("no arguments: audit the complete frontend graph");
    const input = collectAuditInputs(root);
    const results = evaluateAuditExceptions(input);
    for (const r of results) console.log(`${r.passed ? "PASS" : "FAIL"} ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
    const failed = results.filter((r) => !r.passed).length;
    console.log(`audit-exceptions: ${results.length - failed} passed, ${failed} failed`);
    if (failed) process.exitCode = 1;
  } catch (error) {
    console.error(`FAIL audit tool/input — ${error.message}`);
    process.exitCode = 1;
  }
}
