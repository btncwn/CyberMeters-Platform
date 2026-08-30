#!/usr/bin/env node
// Exact-anchor semantic mutation registry for the SSL runtime tri-state.
// Each child loads a fresh copied engine tree, must complete the normal harness,
// and must fail only the frozen right-reason assertion set.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  analyseOrderedRegistry,
  createMutationSandbox,
  installMutationSignalCleanup,
  preflightMutationTargets,
  replaceExactly,
} from "./item10-p5-mutation-harness.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(ROOT, "scripts", "validate-ssl-runtime-tristate-contract.js");
const MODULE_RELATIVE = path.join("workers", "scan-api", "src", "engines", "tls-evidence.js");
const SOURCE_PATH = path.join(ROOT, MODULE_RELATIVE);
const EXPECTED_ASSERTIONS = 182;

installMutationSignalCleanup();

const MUTANTS = Object.freeze([
  {
    id: "approve-invalid-positive-provenance",
    from: `      && !contradictedCarrier(ssl)
      && isApprovedPositiveTlsAbsenceEvidence(absence)
      && timelyPositiveAbsence(ssl, absence)`,
    to: `      && !contradictedCarrier(ssl)
      && timelyPositiveAbsence(ssl, absence)`,
    expectedFailures: [
      "resolver.unavailable.invalid_positive_source",
      "resolver.unavailable.incomplete_positive",
      "resolver.unavailable.ts_offset",
      "resolver.unavailable.ts_missing_millis",
      "resolver.unavailable.ts_lowercase",
      "resolver.unavailable.envelope_domain_mismatch",
      "resolver.unavailable.missing_assessed_domain",
      "score.unavailable.invalid_positive_source.no_finding",
      "score.unavailable.invalid_positive_source.no_action",
      "score.unavailable.incomplete_positive.no_finding",
      "score.unavailable.incomplete_positive.no_action",
      "score.unavailable.ts_offset.no_finding",
      "score.unavailable.ts_offset.no_action",
      "score.unavailable.ts_missing_millis.no_finding",
      "score.unavailable.ts_missing_millis.no_action",
      "score.unavailable.ts_lowercase.no_finding",
      "score.unavailable.ts_lowercase.no_action",
      "score.unavailable.envelope_domain_mismatch.no_finding",
      "score.unavailable.envelope_domain_mismatch.no_action",
      "score.unavailable.invalid_positive_source.no_penalty",
      "score.unavailable.incomplete_positive.no_penalty",
      "score.unavailable.ts_offset.no_penalty",
      "score.unavailable.ts_missing_millis.no_penalty",
      "score.unavailable.ts_lowercase.no_penalty",
      "score.unavailable.envelope_domain_mismatch.no_penalty",
    ],
  },
  {
    id: "demote-approved-positive-absence",
    from: `      && isApprovedPositiveTlsAbsenceEvidence(absence)
      && timelyPositiveAbsence(ssl, absence)`,
    to: `      && false
      && timelyPositiveAbsence(ssl, absence)`,
    expectedFailures: [
      "resolver.positive_absence",
      "resolver.positive_absence.source_bound",
      "resolver.positive_absence.context_match",
      "score.positive_absence.finding",
      "score.positive_absence.action",
      "score.positive_absence.impact",
      "score.positive_absence.provenance",
      "posture.positive_absence.score_delta",
      "posture.positive_absence.action",
      "cert.positive_absence.status",
      "cert.positive_absence.risk",
      "cert.positive_absence.signal",
      "cert.positive_absence.active_service",
      "cert.positive_absence.active_service_value",
      "confidence.positive_absence_supported",
      "alert.positive_absence.state",
      "alert.positive_absence.remediation",
      "domain.positive_absence.state",
      "domain.positive_absence.severity",
      "report.positive_absence.finding_retained",
      "report.positive_absence.action_retained",
      "snapshot.positive_absence.finding_retained",
    ],
  },
  {
    id: "trust-unproven-false-as-present",
    from: `  if (ssl?.https_available !== true || ssl?.executed === false || ssl?.error) return false;`,
    to: `  if (ssl?.https_available == null || ssl?.executed === false || ssl?.error) return false;`,
    expectedFailures: [
      "resolver.unavailable.bare_false",
      "resolver.unavailable.legacy_false",
      "resolver.unavailable.synthetic_false",
      "cert.unavailable.status",
      "cert.unavailable.ownership",
      "cert.unavailable.ownership_confidence",
      "cert.unavailable.active_service",
      "cert.unavailable.active_service_value",
      "alert.unavailable.state",
      "domain.unavailable.state",
      "report.unavailable.explicit_state",
      "report.unavailable.null_key_retained",
      "report.unavailable.cert_status",
      "report.unavailable.cert_ownership",
      "report.unavailable.cert_signal",
    ],
  },
  {
    id: "retain-unproven-customer-finding",
    from: `export function projectTlsFindingsForCustomer(findings, modules = {}) {
  const values = Array.isArray(findings) ? findings : [];
  if (isTlsPositivelyAbsent(modules?.ssl)) return [...values];
  return values.filter((finding) =>`,
    to: `export function projectTlsFindingsForCustomer(findings, modules = {}) {
  const values = Array.isArray(findings) ? findings : [];
  return [...values];
  return values.filter((finding) =>`,
    expectedFailures: [
      "report.unavailable.findings",
    ],
  },
  {
    id: "retain-unproven-customer-action",
    from: `export function projectTlsRecommendationsForCustomer(recommendations, modules = {}) {
  const values = Array.isArray(recommendations) ? recommendations : [];
  if (isTlsPositivelyAbsent(modules?.ssl)) return [...values];
  return values.filter((recommendation) =>`,
    to: `export function projectTlsRecommendationsForCustomer(recommendations, modules = {}) {
  const values = Array.isArray(recommendations) ? recommendations : [];
  return [...values];
  return values.filter((recommendation) =>`,
    expectedFailures: ["report.unavailable.actions"],
  },
  {
    id: "retain-unproven-certificate-claim",
    from: `  if (resolved.state === TLS_RUNTIME_STATES.UNAVAILABLE && ci && typeof ci === "object") {`,
    to: `  if (false && ci && typeof ci === "object") {`,
    expectedFailures: [
      "report.unavailable.cert_status",
      "report.unavailable.cert_ownership",
      "report.unavailable.cert_signal",
    ],
  },
  {
    id: "retain-unproven-snapshot-claim",
    from: `export function projectTlsSnapshotForCustomer(snapshot, modules = {}) {
  if (!snapshot || typeof snapshot !== "object" || isTlsPositivelyAbsent(modules?.ssl)) return snapshot;`,
    to: `export function projectTlsSnapshotForCustomer(snapshot, modules = {}) {
  return snapshot;`,
    expectedFailures: [
      "snapshot.unavailable.findings",
      "snapshot.unavailable.actions",
      "snapshot.unavailable.domain",
      "executive.unavailable.findings",
      "executive.unavailable.actions",
      "pdf.unavailable.no_tls_install",
    ],
  },
  {
    id: "trust-legacy-finding-confidence",
    from: `export function findingHasApprovedTlsAbsence(finding) {
  return isApprovedPositiveTlsAbsenceEvidence(
    finding?.evidence?.tls_positive_absence_evidence,
  );
}`,
    to: `export function findingHasApprovedTlsAbsence() {
  return true;
}`,
    expectedFailures: ["confidence.legacy_false_demoted"],
  },
  // ── IC-17 corrective mutants: each reopens one reproduced defect class ──
  {
    id: "accept-contradicted-carrier",
    from: `      && ssl?.https_available === false
      && !contradictedCarrier(ssl)`,
    to: `      && ssl?.https_available === false`,
    expectedFailures: [
      "resolver.unavailable.contradicted_error",
      "resolver.unavailable.contradicted_not_executed",
      "resolver.unavailable.contradicted_deadline",
      "resolver.unavailable.contradicted_incomplete",
      "resolver.unavailable.contradicted_incomplete_reason",
      "score.unavailable.contradicted_error.no_finding",
      "score.unavailable.contradicted_error.no_action",
      "score.unavailable.contradicted_not_executed.no_finding",
      "score.unavailable.contradicted_not_executed.no_action",
      "score.unavailable.contradicted_deadline.no_finding",
      "score.unavailable.contradicted_deadline.no_action",
      "score.unavailable.contradicted_incomplete.no_finding",
      "score.unavailable.contradicted_incomplete.no_action",
      "score.unavailable.contradicted_incomplete_reason.no_finding",
      "score.unavailable.contradicted_incomplete_reason.no_action",
      "score.unavailable.contradicted_error.no_penalty",
      "score.unavailable.contradicted_not_executed.no_penalty",
      "score.unavailable.contradicted_deadline.no_penalty",
      "score.unavailable.contradicted_incomplete.no_penalty",
      "score.unavailable.contradicted_incomplete_reason.no_penalty",
    ],
  },
  {
    id: "drop-error-disqualifier",
    from: `  if (ssl.error) return true;
  if (ssl.incomplete === true) return true;`,
    to: `  if (ssl.incomplete === true) return true;`,
    expectedFailures: [
      "resolver.unavailable.contradicted_error",
      "score.unavailable.contradicted_error.no_finding",
      "score.unavailable.contradicted_error.no_action",
      "score.unavailable.contradicted_error.no_penalty",
    ],
  },
  {
    id: "accept-parseable-timestamp",
    from: `  try {
    return new Date(parsed).toISOString() === value;
  } catch {
    return false;
  }`,
    to: `  try {
    return true;
  } catch {
    return false;
  }`,
    expectedFailures: [
      "resolver.unavailable.ts_offset",
      "resolver.unavailable.ts_missing_millis",
      "resolver.unavailable.ts_lowercase",
      "score.unavailable.ts_offset.no_finding",
      "score.unavailable.ts_offset.no_action",
      "score.unavailable.ts_missing_millis.no_finding",
      "score.unavailable.ts_missing_millis.no_action",
      "score.unavailable.ts_lowercase.no_finding",
      "score.unavailable.ts_lowercase.no_action",
      "score.unavailable.ts_offset.no_penalty",
      "score.unavailable.ts_missing_millis.no_penalty",
      "score.unavailable.ts_lowercase.no_penalty",
    ],
  },
  {
    id: "drop-domain-binding",
    from: `    if (endpoint.protocol !== "https:") return false;
    if (endpoint.hostname !== value.assessed_domain) return false;`,
    to: `    if (endpoint.protocol !== "https:") return false;`,
    expectedFailures: [
      "resolver.unavailable.envelope_domain_mismatch",
      "score.unavailable.envelope_domain_mismatch.no_finding",
      "score.unavailable.envelope_domain_mismatch.no_action",
      "score.unavailable.envelope_domain_mismatch.no_penalty",
    ],
  },
  {
    id: "drop-assessed-domain-requirement",
    from: `  if (!nonEmpty(value.assessed_domain)) return false;
  try {
    const endpoint = new URL(value.endpoint);
    if (endpoint.protocol !== "https:") return false;
    if (endpoint.hostname !== value.assessed_domain) return false;
  } catch {`,
    to: `  try {
    const endpoint = new URL(value.endpoint);
    if (endpoint.protocol !== "https:") return false;
    if (value.assessed_domain != null && endpoint.hostname !== value.assessed_domain) return false;
  } catch {`,
    expectedFailures: [
      "resolver.unavailable.missing_assessed_domain",
    ],
  },
  {
    id: "drop-reference-requirement",
    from: `  const reference = ssl?.certificate_evidence?.observed_at;
  if (!validObservedAt(reference)) return false;`,
    to: `  const reference = ssl?.certificate_evidence?.observed_at ?? "2026-08-09T12:00:05.000Z";
  if (!validObservedAt(reference)) return false;`,
    expectedFailures: [
      "resolver.unavailable.ts_no_reference",
      "score.unavailable.ts_no_reference.no_finding",
      "score.unavailable.ts_no_reference.no_action",
      "score.unavailable.ts_no_reference.no_penalty",
    ],
  },
  {
    id: "drop-future-bound",
    from: `  if (observed > anchor) return false;
  if (anchor - observed > TLS_POSITIVE_ABSENCE_MAX_AGE_MS) return false;`,
    to: `  if (anchor - observed > TLS_POSITIVE_ABSENCE_MAX_AGE_MS) return false;`,
    expectedFailures: [
      "resolver.unavailable.ts_future",
      "score.unavailable.ts_future.no_finding",
      "score.unavailable.ts_future.no_action",
      "score.unavailable.ts_future.no_penalty",
    ],
  },
  {
    id: "drop-staleness-bound",
    from: `  if (observed > anchor) return false;
  if (anchor - observed > TLS_POSITIVE_ABSENCE_MAX_AGE_MS) return false;
  return true;`,
    to: `  if (observed > anchor) return false;
  return true;`,
    expectedFailures: [
      "resolver.unavailable.ts_stale",
      "score.unavailable.ts_stale.no_finding",
      "score.unavailable.ts_stale.no_action",
      "score.unavailable.ts_stale.no_penalty",
    ],
  },
  {
    id: "drop-carrier-binding",
    from: `  const carrierDomain = ssl?.assessed_domain ?? ssl?.domain ?? null;
  if (carrierDomain != null && carrierDomain !== absence.assessed_domain) return false;`,
    to: `  const carrierDomain = null;
  if (carrierDomain != null && carrierDomain !== absence.assessed_domain) return false;`,
    expectedFailures: [
      "resolver.unavailable.carrier_domain_mismatch",
      "score.unavailable.carrier_domain_mismatch.no_finding",
      "score.unavailable.carrier_domain_mismatch.no_action",
      "score.unavailable.carrier_domain_mismatch.no_penalty",
    ],
  },
  {
    id: "drop-context-binding",
    from: `  const contextDomain = context?.assessedDomain ?? null;
  if (contextDomain != null && contextDomain !== absence.assessed_domain) return false;`,
    to: `  const contextDomain = null;
  if (contextDomain != null && contextDomain !== absence.assessed_domain) return false;`,
    expectedFailures: [
      "resolver.unavailable.context_mismatch",
    ],
  },
]);

let pass = 0;
let fail = 0;
function ok(name, condition, detail = "") {
  if (condition) {
    pass += 1;
    console.log(`PASS ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

const ids = MUTANTS.map((mutant) => mutant.id);
const registry = analyseOrderedRegistry({
  registeredIds: ids,
  expectedIds: [
    "approve-invalid-positive-provenance",
    "demote-approved-positive-absence",
    "trust-unproven-false-as-present",
    "retain-unproven-customer-finding",
    "retain-unproven-customer-action",
    "retain-unproven-certificate-claim",
    "retain-unproven-snapshot-claim",
    "trust-legacy-finding-confidence",
    "accept-contradicted-carrier",
    "drop-error-disqualifier",
    "accept-parseable-timestamp",
    "drop-domain-binding",
    "drop-assessed-domain-requirement",
    "drop-reference-requirement",
    "drop-future-bound",
    "drop-staleness-bound",
    "drop-carrier-binding",
    "drop-context-binding",
  ],
  expectedCount: 18,
  expectedFailureIds: ids,
});
ok("registry is exact, ordered, unique and complete", registry.valid, JSON.stringify(registry));

// Harness-integrity negative controls: a semantic kill cannot be credited to an
// unchanged module, a syntax failure, or an import/load failure.
{
  const child = spawnSync(process.execPath, [VALIDATOR], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, SSL_TRISTATE_ENGINE_SRC: path.dirname(path.dirname(SOURCE_PATH)) },
  });
  const output = `${child.stdout || ""}${child.stderr || ""}`;
  const summaries = [...output.matchAll(/^SSL_TRISTATE_RESULT=(.+)$/gm)]
    .map((match) => { try { return JSON.parse(match[1]); } catch { return null; } })
    .filter(Boolean);
  ok("negative control: no-op candidate is not a mutation kill",
    child.error == null && child.status === 0 && child.signal == null
      && summaries.length === 1 && summaries[0]?.total === EXPECTED_ASSERTIONS
      && summaries[0]?.failed?.length === 0,
    `status=${child.status} signal=${child.signal} error=${child.error?.message || "none"}`);
}

{
  const controlRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-tristate-negative-control-"));
  const syntaxPath = path.join(controlRoot, "syntax.mjs");
  const missingPath = path.join(controlRoot, "missing.mjs");
  try {
    fs.writeFileSync(syntaxPath, "export const = ;\n");
    const syntax = preflightMutationTargets({
      moduleUrls: [pathToFileURL(syntaxPath).href],
      sourceFiles: [syntaxPath],
    });
    ok("negative control: syntax failure cannot count as a semantic kill",
      !syntax.ok && syntax.failures.some((failure) => failure.kind === "syntax"));
    const missing = preflightMutationTargets({
      moduleUrls: [pathToFileURL(missingPath).href],
      sourceFiles: [],
    });
    ok("negative control: module-load failure cannot count as a semantic kill",
      !missing.ok && missing.failures.some((failure) => failure.kind === "module"));
  } finally {
    fs.rmSync(controlRoot, { recursive: true, force: false });
  }
}

const pristine = fs.readFileSync(SOURCE_PATH, "utf8");
const pristineDigest = crypto.createHash("sha256").update(pristine).digest("hex");

for (const mutant of MUTANTS) {
  let sandbox;
  try {
    const mutated = replaceExactly(pristine, mutant.from, mutant.to, mutant.id);
    sandbox = createMutationSandbox(ROOT, `ssl-tristate-${mutant.id}-`);
    const mutantPath = path.join(sandbox.tempRoot, MODULE_RELATIVE);
    fs.writeFileSync(mutantPath, mutated);
    const mutantUrl = pathToFileURL(mutantPath).href;
    const mutantDigest = crypto.createHash("sha256").update(mutated).digest("hex");
    const preflight = preflightMutationTargets({ moduleUrls: [mutantUrl], sourceFiles: [mutantPath] });
    ok(`${mutant.id}: mutated module preflight`, preflight.ok, JSON.stringify(preflight.failures));
    if (!preflight.ok) continue;

    const child = spawnSync(process.execPath, [VALIDATOR], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, SSL_TRISTATE_ENGINE_SRC: sandbox.workerSource },
    });
    const output = `${child.stdout || ""}${child.stderr || ""}`;
    const summaries = [...output.matchAll(/^SSL_TRISTATE_RESULT=(.+)$/gm)]
      .map((match) => { try { return JSON.parse(match[1]); } catch { return null; } })
      .filter(Boolean);
    const loadedUrls = [...output.matchAll(/^LOADED_TLS_MODULE_URL=(.+)$/gm)].map((match) => match[1]);
    const summary = summaries.length === 1 ? summaries[0] : null;
    const fatal = /SyntaxError|ReferenceError|TypeError|ERR_[A-Z0-9_]+|UnhandledPromiseRejection/.test(output);
    const semantic = child.error == null
      && child.status === 1
      && child.signal == null
      && !fatal
      && summaries.length === 1
      && summary?.total === EXPECTED_ASSERTIONS
      && Array.isArray(summary?.passed)
      && Array.isArray(summary?.failed)
      && summary.passed.length + summary.failed.length === EXPECTED_ASSERTIONS;
    ok(`${mutant.id}: semantic child completed`, semantic,
      `status=${child.status} signal=${child.signal} error=${child.error?.message || "none"}\n${output.slice(0, 1800)}`);
    ok(`${mutant.id}: exact loaded-module proof`,
      loadedUrls.length === 1 && loadedUrls[0] === pathToFileURL(path.join(sandbox.workerSource, "engines", "tls-evidence.js")).href
        && crypto.createHash("sha256").update(fs.readFileSync(mutantPath)).digest("hex") === mutantDigest,
      `urls=${JSON.stringify(loadedUrls)} expected_sha=${mutantDigest}`);
    ok(`${mutant.id}: exact expected failure set`,
      JSON.stringify(summary?.failed) === JSON.stringify(mutant.expectedFailures),
      `got=${JSON.stringify(summary?.failed)} want=${JSON.stringify(mutant.expectedFailures)}`);
  } catch (error) {
    ok(`${mutant.id}: harness execution`, false, error.stack || error.message);
  } finally {
    sandbox?.cleanup();
  }
}

const afterDigest = crypto.createHash("sha256").update(fs.readFileSync(SOURCE_PATH)).digest("hex");
ok("mutation sandboxes leave candidate source untouched", afterDigest === pristineDigest,
  `before=${pristineDigest} after=${afterDigest}`);

console.log(`\nSSL runtime tri-state mutations: ${pass}/${pass + fail} passed; ${MUTANTS.length} semantic mutants killed`);
if (fail) process.exit(1);
