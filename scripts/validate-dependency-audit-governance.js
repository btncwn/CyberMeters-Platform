#!/usr/bin/env node
// Dependency-audit exception governance — deterministic fixtures and negative
// controls. No network access and no installed dependency tree are required.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DependencyAuditGovernanceError,
  evaluateDependencyAudit,
  formatAuditResult,
  parseCompleteAuditJson,
  validateFrontendBracePatch,
  validateWorkerPackageManifest,
} from "./dependency-audit-governance.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const clone = (value) => structuredClone(value);
const packageJson = readJson(path.join(root, "workers/scan-api/package.json"));
const lockfile = readJson(path.join(root, "workers/scan-api/package-lock.json"));
const config = readJson(path.join(root, "scripts/dependency-audit-exceptions.json"));
const runtimeLs = { name: "cybermeters-scan-api", version: "0.1.0" };
const validNow = "2026-08-03T20:00:00.000Z";

let passed = 0;
let failed = 0;
const seen = new Set();
function check(id, condition, detail = "") {
  if (seen.has(id)) throw new Error(`duplicate control id: ${id}`);
  seen.add(id);
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function throwsCode(fn, ...codes) {
  try {
    fn();
    return false;
  } catch (error) {
    return error instanceof DependencyAuditGovernanceError && codes.includes(error.code);
  }
}

function advisory(id, severity, source) {
  return {
    source,
    name: "undici",
    dependency: "undici",
    title: `fixture ${id}`,
    url: `https://github.com/advisories/${id}`,
    severity,
    range: ">=7.0.0 <7.29.0",
  };
}

function auditFixture() {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      miniflare: {
        name: "miniflare", severity: "moderate", isDirect: false,
        via: ["undici"], effects: ["wrangler"], range: ">=4.20250906.1",
        nodes: ["node_modules/miniflare"],
      },
      undici: {
        name: "undici", severity: "high", isDirect: false,
        via: [
          advisory("GHSA-8xcm-r25x-g524", "moderate", 1130715),
          advisory("GHSA-4cwx-7wf7-3272", "high", 1130718),
        ],
        effects: ["miniflare"], range: "7.0.0 - 7.28.0",
        nodes: ["node_modules/undici"],
      },
      wrangler: {
        name: "wrangler", severity: "moderate", isDirect: true,
        via: ["miniflare"], effects: [], range: "<=0.0.0-31bfd374c || >=4.36.0",
        nodes: ["node_modules/wrangler"],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 2, high: 1, critical: 0, total: 3 },
      dependencies: { prod: 3, dev: 93, optional: 60, peer: 0, peerOptional: 0, total: 95 },
    },
  };
}

function evaluate(overrides = {}) {
  return evaluateDependencyAudit({
    audit: overrides.audit || auditFixture(),
    packageJson: overrides.packageJson || packageJson,
    lockfile: overrides.lockfile || lockfile,
    runtimeLs: overrides.runtimeLs || runtimeLs,
    config: overrides.config || config,
    now: overrides.now || validNow,
  });
}

const cleanResult = evaluate();
check("EXACT_TWO_DEV_TOOLCHAIN_ADVISORIES_ADMITTED",
  cleanResult.admitted.map(({ id }) => id).join(",") ===
  "GHSA-8xcm-r25x-g524,GHSA-4cwx-7wf7-3272");
{
  const changedSet = auditFixture();
  changedSet.vulnerabilities.undici.via.pop();
  check("ADMITTED_ADVISORY_SET_DRIFT_FAILS",
    throwsCode(() => evaluate({ audit: changedSet }), "UNDICI_ADVISORY_DRIFT"));
}
const output = formatAuditResult(cleanResult).join("\n");
check("ACTIVE_EXCEPTIONS_VISIBLE_NOT_ZERO_VULNERABILITIES",
  (output.match(/^ACTIVE TEMPORARY EXCEPTION /gm) || []).length === 2 &&
  !/0 vulnerabilities/i.test(output));

{
  const audit = auditFixture();
  audit.vulnerabilities.undici.via.push(advisory("GHSA-zzzz-yyyy-xxxx", "high", 9999999));
  check("UNRELATED_HIGH_CRITICAL_FAILS",
    throwsCode(() => evaluate({ audit }), "UNEXCEPTED_BLOCKING_ADVISORY"));
}

{
  const runtimePackage = clone(packageJson);
  runtimePackage.dependencies.undici = "7.28.0";
  const runtimeLock = clone(lockfile);
  runtimeLock.packages[""].dependencies.undici = "7.28.0";
  check("ADMITTED_UNDICI_IN_RUNTIME_DEPENDENCIES_FAILS",
    throwsCode(() => evaluate({
      packageJson: runtimePackage,
      lockfile: runtimeLock,
      runtimeLs: { ...runtimeLs, dependencies: { undici: { version: "7.28.0" } } },
    }), "RUNTIME_DEPENDENCY"));
}

{
  const changedPath = clone(lockfile);
  changedPath.packages["node_modules/other-tool"] = {
    version: "1.0.0", dev: true, dependencies: { undici: "7.28.0" },
  };
  check("CHANGED_DEPENDENCY_PATH_FAILS",
    throwsCode(() => evaluate({ lockfile: changedPath }), "PATH_DRIFT"));
}

{
  const changedVersion = clone(lockfile);
  changedVersion.packages["node_modules/undici"].version = "7.28.1";
  const changedRange = auditFixture();
  changedRange.vulnerabilities.undici.range = "7.0.0 - 7.28.1";
  check("CHANGED_UNDICI_VERSION_OR_RANGE_FAILS",
    throwsCode(() => evaluate({ lockfile: changedVersion }), "PATH_DRIFT") &&
    throwsCode(() => evaluate({ audit: changedRange }), "UNDICI_AUDIT_SHAPE_DRIFT"));
}

check("EXPIRED_EXCEPTION_FAILS",
  throwsCode(() => evaluate({ now: "2026-08-17T00:00:00.000Z" }), "EXPIRED_EXCEPTION"));

{
  const missingOwner = clone(config); delete missingOwner.exceptions[0].recheck_owner;
  const missingReason = clone(config); delete missingReason.exceptions[0].reason;
  const missingExpiry = clone(config); delete missingExpiry.exceptions[0].expires_at;
  check("MISSING_OWNER_REASON_EXPIRY_FAILS",
    [missingOwner, missingReason, missingExpiry].every((candidate) =>
      throwsCode(() => evaluate({ config: candidate }), "INVALID_EXCEPTION_CONFIG")));
}

{
  const truncated = auditFixture(); truncated.metadata.vulnerabilities.total = 2;
  const incomplete = auditFixture(); delete incomplete.vulnerabilities.undici;
  const missingDependencyMetadata = auditFixture(); delete missingDependencyMetadata.metadata.dependencies;
  check("MALFORMED_TRUNCATED_INCOMPLETE_AUDIT_FAILS",
    throwsCode(() => parseCompleteAuditJson('{"auditReportVersion":2'), "MALFORMED_AUDIT") &&
    throwsCode(() => evaluate({ audit: truncated }), "INCOMPLETE_AUDIT") &&
    throwsCode(() => evaluate({ audit: incomplete }), "INCOMPLETE_AUDIT") &&
    throwsCode(() => evaluate({ audit: missingDependencyMetadata }), "MALFORMED_AUDIT"));
}

{
  const braceAudit = auditFixture();
  braceAudit.vulnerabilities.brace_expansion = {
    name: "brace_expansion", severity: "high", isDirect: false,
    via: [{
      source: 1130705, name: "brace-expansion", dependency: "brace-expansion",
      title: "brace-expansion fixture", url: "https://github.com/advisories/GHSA-rgw5-rvv9-x895",
      severity: "high", range: ">=4.0.0 <5.0.9",
    }],
    effects: [], range: "4.0.0 - 5.0.8", nodes: ["node_modules/brace-expansion"],
  };
  braceAudit.metadata.vulnerabilities.high += 1;
  braceAudit.metadata.vulnerabilities.total += 1;
  check("BRACE_5_0_8_ADVISORY_NEVER_EXCEPTED",
    throwsCode(() => evaluate({ audit: braceAudit }), "UNEXCEPTED_BLOCKING_ADVISORY"));
}

const frontendPackageText = fs.readFileSync(path.join(root, "frontend/package.json"));
const frontendLockText = fs.readFileSync(path.join(root, "frontend/package-lock.json"), "utf8");
check("CLEAN_POST_PATCH_FRONTEND_LOCK_PASSES",
  validateFrontendBracePatch({ packageText: frontendPackageText, lockText: frontendLockText }).version === "5.0.9");
{
  const vulnerableLock = frontendLockText
    .replace('"version": "5.0.9"', '"version": "5.0.8"')
    .replace("brace-expansion-5.0.9.tgz", "brace-expansion-5.0.8.tgz");
  check("BRACE_5_0_8_LOCK_FAILS",
    throwsCode(() => validateFrontendBracePatch({
      packageText: frontendPackageText,
      lockText: vulnerableLock,
    }), "BRACE_PATCH_REQUIRED"));
}

check("WORKER_PACKAGE_MANIFEST_BYTE_PIN_PASSES",
  validateWorkerPackageManifest(fs.readFileSync(path.join(root, "workers/scan-api/package.json"))) === true);

{
  const audit = auditFixture();
  audit.vulnerabilities.undici.via.push(advisory("GHSA-m8rv-5g2x-5cg5", "moderate", 1130726));
  const result = evaluate({ audit });
  check("COMPLETE_AUDIT_RETAINS_BELOW_THRESHOLD_FINDINGS",
    result.belowThreshold.some(({ id }) => id === "GHSA-m8rv-5g2x-5cg5"));
}

const workflow = fs.readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
check("CI_CONSUMES_COMPLETE_AUDIT_GATE_WITHOUT_OMIT_DEV",
  /run: node scripts\/dependency-audit-governance\.js/.test(workflow) &&
  !/npm audit[^\n]*--omit=dev/.test(workflow) &&
  /working-directory: frontend\s+run: npm audit --audit-level=high/.test(workflow));

console.log(`\nDependency audit governance: ${passed}/${passed + failed} controls passed`);
if (failed) process.exit(1);
console.log("Dependency audit governance validation passed");
