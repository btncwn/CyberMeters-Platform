#!/usr/bin/env node
// Exact, expiring dependency-audit governance.
//
// The Worker gate consumes the complete npm audit v2 JSON. It preserves the
// repository's high/critical threshold while admitting exactly two temporary
// undici advisories only when the committed Wrangler -> Miniflare -> undici
// path remains dev-only and absent from the runtime dependency closure.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerDir = path.join(root, "workers", "scan-api");

const ELIGIBLE_ADVISORY_IDS = Object.freeze([
  "GHSA-8xcm-r25x-g524",
  "GHSA-4cwx-7wf7-3272",
]);
const EXPECTED_EXCEPTION = Object.freeze({
  id: "worker-undici-wrangler-miniflare-2026-08",
  package: "undici",
  installed_version: "7.28.0",
  package_audit_range: "7.0.0 - 7.28.0",
  advisory_range: ">=7.0.0 <7.29.0",
  dependency_path: Object.freeze([
    Object.freeze({ lock_key: "node_modules/wrangler", name: "wrangler", version: "4.110.0" }),
    Object.freeze({ lock_key: "node_modules/miniflare", name: "miniflare", version: "4.20260708.1" }),
    Object.freeze({ lock_key: "node_modules/undici", name: "undici", version: "7.28.0" }),
  ]),
  expires_at: "2026-08-17T00:00:00.000Z",
  recheck_owner: "Turhan Acar (Founder)",
  reason: "No compatible patched undici release is currently available through Miniflare; undici is absent from the deployed Worker runtime dependency closure.",
});
const FRONTEND_PACKAGE_SHA256 = "8ec49d51c5ec3afd76c2b0c4b3362f8848cc067f7990352d55c48f5e5dbc1673";
const WORKER_PACKAGE_SHA256 = "c53312238dcebafae3b7d3ade394913b92c0ad55ce04a1b39f8fb39f6ba34262";
const FRONTEND_LOCK_EXCEPT_BRACE_SHA256 = "5a04850b0b0c124ffd4f97e9827534b2b6be38034bb18ce1437c49213c0adabf";
const PATCHED_BRACE = Object.freeze({
  version: "5.0.9",
  resolved: "https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.9.tgz",
  integrity: "sha512-ScQ4IuvIEF1TMlP7Zt+vjJ//9zlPb2SDcxWxM3bk8s6t6GGdJ7KO1dCcTidOPJKePW30LE/2cT7wCyPho9/Wxg==",
});
const SEVERITIES = Object.freeze(["info", "low", "moderate", "high", "critical"]);
const BLOCKING_SEVERITIES = new Set(["high", "critical"]);

export class DependencyAuditGovernanceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DependencyAuditGovernanceError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new DependencyAuditGovernanceError(code, message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function exactSet(actual, expected) {
  return actual.length === expected.length &&
    [...actual].sort().every((value, index) => value === [...expected].sort()[index]);
}

function requireNonEmptyString(value, code, field) {
  if (typeof value !== "string" || value.trim() === "") fail(code, `${field} is required`);
}

function advisoryId(via) {
  const match = String(via?.url || "").match(/\/advisories\/(GHSA-[a-z0-9-]+)$/i);
  if (!match) fail("MALFORMED_AUDIT", `advisory URL is malformed: ${via?.url}`);
  return match[1];
}

export function parseCompleteAuditJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(String(text));
  } catch {
    fail("MALFORMED_AUDIT", "npm audit output is not complete JSON");
  }
  if (!isObject(parsed)) fail("MALFORMED_AUDIT", "npm audit output is not an object");
  return parsed;
}

function validateAuditShape(audit) {
  if (audit.auditReportVersion !== 2 || !isObject(audit.vulnerabilities) ||
      !isObject(audit.metadata) || !isObject(audit.metadata.vulnerabilities) ||
      !isObject(audit.metadata.dependencies)) {
    fail("MALFORMED_AUDIT", "npm audit v2 metadata or vulnerabilities are missing");
  }
  const vulnerabilityEntries = Object.entries(audit.vulnerabilities);
  const reported = audit.metadata.vulnerabilities;
  const reportedTotal = SEVERITIES.reduce((sum, severity) => {
    if (!Number.isInteger(reported[severity]) || reported[severity] < 0) {
      fail("MALFORMED_AUDIT", `metadata.vulnerabilities.${severity} is invalid`);
    }
    return sum + reported[severity];
  }, 0);
  if (reportedTotal !== reported.total || reported.total !== vulnerabilityEntries.length) {
    fail("INCOMPLETE_AUDIT", "npm audit vulnerability totals do not match the payload");
  }
  const actualCounts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  for (const [key, vulnerability] of vulnerabilityEntries) {
    if (!isObject(vulnerability) || vulnerability.name !== key ||
        !SEVERITIES.includes(vulnerability.severity) ||
        typeof vulnerability.isDirect !== "boolean" ||
        !Array.isArray(vulnerability.via) || !Array.isArray(vulnerability.effects) ||
        typeof vulnerability.range !== "string" ||
        !Array.isArray(vulnerability.nodes) || vulnerability.nodes.length === 0) {
      fail("MALFORMED_AUDIT", `vulnerability ${key} is incomplete`);
    }
    actualCounts[vulnerability.severity] += 1;
    for (const via of vulnerability.via) {
      if (typeof via === "string") {
        if (!Object.hasOwn(audit.vulnerabilities, via)) {
          fail("INCOMPLETE_AUDIT", `${key} references missing vulnerability ${via}`);
        }
        continue;
      }
      if (!isObject(via) || !Number.isInteger(via.source) ||
          typeof via.name !== "string" || typeof via.dependency !== "string" ||
          typeof via.title !== "string" || !SEVERITIES.includes(via.severity) ||
          typeof via.range !== "string") {
        fail("MALFORMED_AUDIT", `advisory detail for ${key} is incomplete`);
      }
      advisoryId(via);
    }
  }
  for (const severity of SEVERITIES) {
    if (reported[severity] !== actualCounts[severity]) {
      fail("INCOMPLETE_AUDIT", `npm audit ${severity} total does not match entries`);
    }
  }
  for (const field of ["prod", "dev", "optional", "peer", "peerOptional", "total"]) {
    if (!Number.isInteger(audit.metadata.dependencies[field]) ||
        audit.metadata.dependencies[field] < 0) {
      fail("MALFORMED_AUDIT", `metadata.dependencies.${field} is invalid`);
    }
  }
}

function validateExceptionConfig(config, now) {
  if (!isObject(config) || config.schema_version !== 1 ||
      !Array.isArray(config.exceptions) || config.exceptions.length !== 1) {
    fail("INVALID_EXCEPTION_CONFIG", "exactly one schema-v1 exception is required");
  }
  const exception = config.exceptions[0];
  if (!isObject(exception)) fail("INVALID_EXCEPTION_CONFIG", "exception record is malformed");
  for (const field of ["id", "package", "installed_version", "package_audit_range",
    "advisory_range", "expires_at", "recheck_owner", "reason"]) {
    requireNonEmptyString(exception[field], "INVALID_EXCEPTION_CONFIG", field);
  }
  if (!Array.isArray(exception.advisory_ids) ||
      !exactSet(exception.advisory_ids, ELIGIBLE_ADVISORY_IDS)) {
    fail("INVALID_EXCEPTION_CONFIG", "exception advisory IDs are not the exact eligible pair");
  }
  if (!Array.isArray(exception.dependency_path) ||
      JSON.stringify(exception.dependency_path) !== JSON.stringify(EXPECTED_EXCEPTION.dependency_path)) {
    fail("INVALID_EXCEPTION_CONFIG", "exception dependency path is not the pinned path");
  }
  for (const field of ["id", "package", "installed_version", "package_audit_range",
    "advisory_range", "expires_at", "recheck_owner", "reason"]) {
    if (exception[field] !== EXPECTED_EXCEPTION[field]) {
      fail("INVALID_EXCEPTION_CONFIG", `${field} does not match the pinned exception`);
    }
  }
  const currentTime = Date.parse(now);
  const expiryTime = Date.parse(exception.expires_at);
  if (!Number.isFinite(currentTime) || !Number.isFinite(expiryTime)) {
    fail("INVALID_EXCEPTION_CONFIG", "exception time values are invalid");
  }
  if (currentTime >= expiryTime) fail("EXPIRED_EXCEPTION", `exception expired at ${exception.expires_at}`);
  return exception;
}

function dependencyParents(lockfile, dependencyName) {
  const parents = [];
  for (const [lockKey, node] of Object.entries(lockfile.packages || {})) {
    if (lockKey === "" || !isObject(node)) continue;
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      if (isObject(node[field]) && Object.hasOwn(node[field], dependencyName)) {
        parents.push(lockKey);
      }
    }
  }
  return [...new Set(parents)].sort();
}

function runtimeLsContainsUndici(value) {
  if (!isObject(value)) return false;
  if (isObject(value.dependencies) && Object.hasOwn(value.dependencies, "undici")) return true;
  return Object.values(value).some((child) => runtimeLsContainsUndici(child));
}

function validateWorkerDevOnlyPath(packageJson, lockfile, runtimeLs, exception) {
  if (!isObject(packageJson) || !isObject(lockfile) || !isObject(lockfile.packages) ||
      !isObject(runtimeLs)) {
    fail("MALFORMED_CLOSURE", "package, lock or npm ls data is malformed");
  }
  if (runtimeLs.name !== packageJson.name || runtimeLs.version !== packageJson.version) {
    fail("MALFORMED_CLOSURE", "npm ls runtime-closure identity is missing or changed");
  }
  if (isObject(packageJson.dependencies) && Object.hasOwn(packageJson.dependencies, "undici")) {
    fail("RUNTIME_DEPENDENCY", "undici appears in root runtime dependencies");
  }
  if (packageJson.devDependencies?.wrangler !== "4.110.0") {
    fail("PATH_DRIFT", "root Wrangler devDependency changed");
  }
  const rootLock = lockfile.packages[""];
  if (!isObject(rootLock) || rootLock.dependencies?.undici !== undefined ||
      rootLock.devDependencies?.wrangler !== "4.110.0") {
    fail("RUNTIME_DEPENDENCY", "root lock runtime/dev classification changed");
  }
  for (const expected of exception.dependency_path) {
    const node = lockfile.packages[expected.lock_key];
    if (!isObject(node) || node.version !== expected.version || node.dev !== true) {
      fail("PATH_DRIFT", `${expected.lock_key} version or dev-only classification changed`);
    }
  }
  const wrangler = lockfile.packages["node_modules/wrangler"];
  const miniflare = lockfile.packages["node_modules/miniflare"];
  if (wrangler.dependencies?.miniflare !== "4.20260708.1" ||
      miniflare.dependencies?.undici !== "7.28.0") {
    fail("PATH_DRIFT", "Wrangler -> Miniflare -> undici dependency specs changed");
  }
  if (JSON.stringify(dependencyParents(lockfile, "undici")) !==
      JSON.stringify(["node_modules/miniflare"]) ||
      JSON.stringify(dependencyParents(lockfile, "miniflare")) !==
      JSON.stringify(["node_modules/wrangler"])) {
    fail("PATH_DRIFT", "an additional or changed path reaches undici/Miniflare");
  }
  const undiciNodes = Object.keys(lockfile.packages)
    .filter((key) => key === "node_modules/undici" || key.endsWith("/node_modules/undici"));
  if (JSON.stringify(undiciNodes) !== JSON.stringify(["node_modules/undici"])) {
    fail("PATH_DRIFT", "lockfile undici node shape changed");
  }
  if (runtimeLsContainsUndici(runtimeLs)) {
    fail("RUNTIME_DEPENDENCY", "npm ls --omit=dev contains undici");
  }
}

export function normaliseBraceLockForHash(lockText) {
  const pattern = /("node_modules\/brace-expansion":\s*\{\s*"version":\s*")[^"]+("\s*,\s*"resolved":\s*")[^"]+("\s*,\s*"integrity":\s*")[^"]+("\s*,)/m;
  const matches = String(lockText).match(new RegExp(pattern.source, "gm")) || [];
  if (matches.length !== 1) fail("BRACE_PATCH_DRIFT", `brace-expansion lock entry count ${matches.length}`);
  return String(lockText).replace(pattern, "$1<version>$2<resolved>$3<integrity>$4");
}

export function validateFrontendBracePatch({ packageText, lockText }) {
  if (sha256(packageText) !== FRONTEND_PACKAGE_SHA256) {
    fail("FRONTEND_PACKAGE_DRIFT", "frontend/package.json changed");
  }
  if (sha256(normaliseBraceLockForHash(lockText)) !== FRONTEND_LOCK_EXCEPT_BRACE_SHA256) {
    fail("BRACE_PATCH_DRIFT", "frontend lock changed outside the brace-expansion entry");
  }
  let lockfile;
  try { lockfile = JSON.parse(lockText); } catch { fail("BRACE_PATCH_DRIFT", "frontend lock is malformed"); }
  const packages = lockfile.packages || {};
  const brace = packages["node_modules/brace-expansion"];
  if (!isObject(brace) || brace.version !== PATCHED_BRACE.version ||
      brace.resolved !== PATCHED_BRACE.resolved || brace.integrity !== PATCHED_BRACE.integrity ||
      brace.dev !== true) {
    fail("BRACE_PATCH_REQUIRED", "brace-expansion is not the exact dev-only 5.0.9 patch");
  }
  const pathShape = [
    ["", "devDependencies", "@vitest/coverage-v8", "^3.2.7"],
    ["node_modules/@vitest/coverage-v8", "dependencies", "test-exclude", "^7.0.1"],
    ["node_modules/test-exclude", "dependencies", "minimatch", "^10.2.2"],
    ["node_modules/minimatch", "dependencies", "brace-expansion", "^5.0.5"],
  ];
  for (const [key, field, dependency, spec] of pathShape) {
    if (packages[key]?.[field]?.[dependency] !== spec) {
      fail("BRACE_PATH_DRIFT", `${key || "root"} -> ${dependency} changed`);
    }
  }
  for (const key of ["node_modules/@vitest/coverage-v8", "node_modules/test-exclude",
    "node_modules/minimatch", "node_modules/brace-expansion"]) {
    if (packages[key]?.dev !== true) fail("BRACE_PATH_DRIFT", `${key} is not dev-only`);
  }
  if (JSON.stringify(dependencyParents(lockfile, "brace-expansion")) !==
      JSON.stringify(["node_modules/minimatch"])) {
    fail("BRACE_PATH_DRIFT", "brace-expansion has an unexpected dependency parent");
  }
  return { package: "brace-expansion", version: PATCHED_BRACE.version, path: pathShape.map(([, , name]) => name) };
}

export function validateWorkerPackageManifest(packageText) {
  if (sha256(packageText) !== WORKER_PACKAGE_SHA256) {
    fail("WORKER_PACKAGE_DRIFT", "workers/scan-api/package.json changed");
  }
  return true;
}

export function evaluateDependencyAudit({ audit, packageJson, lockfile, runtimeLs, config, now }) {
  validateAuditShape(audit);
  const exception = validateExceptionConfig(config, now);
  validateWorkerDevOnlyPath(packageJson, lockfile, runtimeLs, exception);

  const vulnerability = audit.vulnerabilities.undici;
  if (!isObject(vulnerability) || vulnerability.isDirect !== false ||
      vulnerability.range !== exception.package_audit_range ||
      JSON.stringify(vulnerability.nodes) !== JSON.stringify(["node_modules/undici"])) {
    fail("UNDICI_AUDIT_SHAPE_DRIFT", "undici audit package/range/node shape changed");
  }

  const admitted = [];
  const belowThreshold = [];
  for (const [packageName, entry] of Object.entries(audit.vulnerabilities)) {
    if (packageName !== "undici" && BLOCKING_SEVERITIES.has(entry.severity)) {
      fail("UNEXCEPTED_BLOCKING_ADVISORY", `${packageName} has an unexcepted ${entry.severity} finding`);
    }
    const objectVia = entry.via.filter((via) => isObject(via));
    if (objectVia.length === 0 && BLOCKING_SEVERITIES.has(entry.severity)) {
      fail("UNEXCEPTED_BLOCKING_ADVISORY", `${packageName} has an unexpanded ${entry.severity} finding`);
    }
    for (const via of objectVia) {
      const id = advisoryId(via);
      if (ELIGIBLE_ADVISORY_IDS.includes(id)) {
        if (packageName !== "undici" || via.name !== "undici" ||
            via.dependency !== "undici" || via.range !== exception.advisory_range) {
          fail("UNDICI_ADVISORY_DRIFT", `${id} moved package, dependency or range`);
        }
        admitted.push({ id, severity: via.severity });
      } else if (BLOCKING_SEVERITIES.has(via.severity)) {
        fail("UNEXCEPTED_BLOCKING_ADVISORY", `${id} (${via.severity}) is not excepted`);
      } else {
        belowThreshold.push({ id, package: packageName, severity: via.severity });
      }
    }
  }
  const admittedIds = admitted.map(({ id }) => id);
  if (!exactSet(admittedIds, ELIGIBLE_ADVISORY_IDS) || new Set(admittedIds).size !== 2) {
    fail("UNDICI_ADVISORY_DRIFT", "the exact admitted advisory pair is not present once each");
  }
  return { exception, admitted, belowThreshold };
}

export function formatAuditResult(result) {
  const pathLabel = result.exception.dependency_path
    .map(({ name, version }) => `${name}@${version}`).join(" -> ");
  const lines = result.admitted.map(({ id }) =>
    `ACTIVE TEMPORARY EXCEPTION ${id}: undici@${result.exception.installed_version} via ${pathLabel}; expires ${result.exception.expires_at}; re-check owner ${result.exception.recheck_owner}`);
  if (result.belowThreshold.length > 0) {
    lines.push(`NON-BLOCKING BELOW-HIGH ADVISORIES OBSERVED: ${result.belowThreshold.map(({ id }) => id).join(", ")}`);
  }
  lines.push(`Worker dependency audit gate PASS with ${result.admitted.length} ACTIVE TEMPORARY EXCEPTIONS; full npm audit JSON evaluated.`);
  return lines;
}

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function runCommand(command, args, cwd, allowedStatuses) {
  const child = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (child.error || child.signal || !allowedStatuses.includes(child.status)) {
    fail("AUDIT_COMMAND_FAILED", `${command} ${args.join(" ")} failed: ${child.error?.message || child.stderr || child.signal || child.status}`);
  }
  return child;
}

export function runDependencyAuditGate({ now = new Date().toISOString() } = {}) {
  const frontendPatch = validateFrontendBracePatch({
    packageText: fs.readFileSync(path.join(root, "frontend/package.json")),
    lockText: fs.readFileSync(path.join(root, "frontend/package-lock.json"), "utf8"),
  });
  const auditChild = runCommand("npm", ["audit", "--json", "--audit-level=high"], workerDir, [0, 1]);
  const runtimeChild = runCommand("npm", ["ls", "--omit=dev", "undici", "--json"], workerDir, [0, 1]);
  const workerPackageText = fs.readFileSync(path.join(workerDir, "package.json"));
  validateWorkerPackageManifest(workerPackageText);
  const result = evaluateDependencyAudit({
    audit: parseCompleteAuditJson(auditChild.stdout),
    packageJson: JSON.parse(workerPackageText),
    lockfile: loadJson(path.join(workerDir, "package-lock.json")),
    runtimeLs: parseCompleteAuditJson(runtimeChild.stdout),
    config: loadJson(path.join(root, "scripts/dependency-audit-exceptions.json")),
    now,
  });
  console.log(`PATCHED DEV-TOOLCHAIN ADVISORY: ${frontendPatch.package}@${frontendPatch.version}; no exception.`);
  for (const line of formatAuditResult(result)) console.log(line);
  return result;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    runDependencyAuditGate();
  } catch (error) {
    console.error(`DEPENDENCY AUDIT GATE FAIL [${error.code || "UNEXPECTED"}]: ${error.message}`);
    process.exit(1);
  }
}
