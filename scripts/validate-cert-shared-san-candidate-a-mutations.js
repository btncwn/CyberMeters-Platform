#!/usr/bin/env node
// Candidate A v2 semantic mutation contract. Every byte mutant runs the real
// 30-fixture validator in a fresh process and is accepted only for its exact,
// ordered FAIL set. Target bytes and the complete dirty-worktree fingerprint
// must be restored after every run.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-cert-shared-san-candidate-a.js");
const target = (relative) => path.join(root, ...relative.split("/"));
const targets = {
  projector: target("workers/scan-api/src/routes/certificate-shared-san-projection.js"),
  ssl: target("workers/scan-api/src/engines/ssl-scan.js"),
  p2: target("scripts/validate-item9-certificate-p2-engine-trace.js"),
  certIntel: target("workers/scan-api/src/engines/cert-intel.js"),
  phase5: target("workers/scan-api/src/engines/phase5-evidence.js"),
  route: target("workers/scan-api/src/routes/scans.js"),
  snapshot: target("workers/scan-api/src/engines/report-snapshot.js"),
  p4Fixture: target("scripts/fixtures/item9-p4-certificate-trust-depth.json"),
};
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");

function git(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" });
}
function worktreeFingerprint() {
  const status = git(["status", "--porcelain=v1", "-z"]);
  const paths = status.split("\0").filter(Boolean).map((entry) => entry.slice(3));
  const hash = crypto.createHash("sha256").update(status);
  for (const relative of paths.sort()) {
    const absolute = path.join(root, relative);
    hash.update(relative);
    hash.update("\0");
    if (fs.existsSync(absolute) && fs.statSync(absolute).isFile()) {
      hash.update(fs.readFileSync(absolute));
    }
    hash.update("\0");
  }
  return hash.digest("hex");
}
function replaceExactly(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}
function failureIds(output) {
  return String(output).split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL SAN_A_F"))
    .map((line) => line.slice("FAIL SAN_A_".length).split(" — ")[0]);
}
function runValidator(timeout = 180_000) {
  const child = spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: "utf8",
    timeout,
    env: {
      ...process.env,
      CERT_SHARED_SAN_CANDIDATE_PARENT:
        process.env.CERT_SHARED_SAN_CANDIDATE_PARENT || "6076d0836b8239129e780f3692790a2925b77e01",
    },
  });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  const failures = failureIds(output);
  const summary = String(child.stdout || "").match(/Candidate A shared-SAN: (\d+)\/(\d+) fixtures passed/);
  const normal = child.error == null && child.signal == null && child.status === 1 &&
    summary != null && Number(summary[2]) === 30 && Number(summary[1]) + failures.length === 30;
  return { child, output, failures, normal };
}

const mutants = [
  {
    id: "SAN_A_M01", target: "projector", expected: ["F01", "F02"],
    mutate: (s) => replaceExactly(s,
      "sharedSanAssessment = notAssessed(LEGACY_AMBIGUOUS_ZERO);",
      "sharedSanAssessment = assessed(MEASURED_ZERO, buildCertificateOwnershipAssessment(ssl, domain));",
      "M01"),
  },
  {
    id: "SAN_A_M02", target: "projector", expected: ["F01", "F02", "F08"],
    mutate: (s) => replaceExactly(s,
      "const schemaVersion = ssl?.certificate_evidence?.schema_version;",
      'const schemaVersion = "external-certificate-observation-v3";', "M02"),
  },
  {
    id: "SAN_A_M03", target: "projector", expected: ["F06"],
    mutate: (s) => replaceExactly(s,
      "postCutover && fivePredicatesHold && evidenceComplete && rawSharedSanCount === 0",
      "postCutover && evidenceComplete && rawSharedSanCount === 0", "M03"),
  },
  {
    id: "SAN_A_M04", target: "projector", expected: ["F05"],
    mutate: (s) => replaceExactly(s,
      "      MEASURED_POSITIVE,\n", "      LEGACY_MEASURED_POSITIVE,\n", "M04"),
  },
  {
    id: "SAN_A_M05", target: "projector", expected: ["F03", "F17"],
    mutate: (s) => replaceExactly(s,
      "  return {\n    ...rawCertificateIntelligence,\n    shared_san_assessment: sharedSanAssessment,\n  };",
      "  return {\n    ...rawCertificateIntelligence,\n    shared_san_count: sharedSanAssessment.shared_san_count,\n    ownership: {\n      ...(rawCertificateIntelligence.ownership || {}),\n      status: sharedSanAssessment.ownership_status,\n      customer_owned: sharedSanAssessment.customer_owned,\n      confidence: sharedSanAssessment.confidence,\n    },\n    shared_san_assessment: sharedSanAssessment,\n  };", "M05"),
  },
  {
    id: "SAN_A_M06", target: "ssl", expected: ["F04", "F05", "F10", "F19"],
    mutate: (s) => replaceExactly(s,
      '      schema_version: "external-certificate-observation-v3",',
      '      schema_version: "external-certificate-observation-v2",', "M06"),
  },
  {
    id: "SAN_A_M07", target: "p2", expected: ["F19"],
    mutate: (s) => replaceExactly(s,
      `  eq("SSL declares the additive P4 evidence schema",\n    report.modules?.ssl?.certificate_evidence?.schema_version,\n    "external-certificate-observation-v3");`,
      `  ok("SSL declares the additive P4 evidence schema",\n    report.modules?.ssl?.certificate_evidence?.schema_version\n      ?.startsWith("external-certificate-observation-v"));`, "M07"),
  },
  {
    id: "SAN_A_M08", target: "certIntel", expected: ["F18"],
    mutate: (s) => replaceExactly(s,
      `\t      san_count:             ssl.cert_san_count ?? 0,\n\t      raw_san_count:         ssl.cert_raw_san_count ?? ssl.cert_san_count ?? 0,\n\t      wildcard_san_count:    ssl.cert_wildcard_san_count ?? 0,`,
      `\t      san_count:             ssl.cert_san_count ?? null,\n\t      raw_san_count:         ssl.cert_raw_san_count ?? ssl.cert_san_count ?? null,\n\t      wildcard_san_count:    ssl.cert_wildcard_san_count ?? null,`, "M08"),
  },
  {
    id: "SAN_A_M09", target: "phase5", expected: ["F12"],
    mutate: (s) => {
      let out = replaceExactly(s,
        'import { isPublishableModuleEvidence } from "./scan-budget.js";',
        'import { isPublishableModuleEvidence } from "./scan-budget.js";\nimport { projectCertificateSharedSanForCustomer } from "../routes/certificate-shared-san-projection.js";', "M09 import");
      out = replaceExactly(out,
        "export function projectPhase5EvidenceForCustomer(modules = {}) {\n  const evidence = resolvePhase5EvidenceContract(modules);",
        "export function projectPhase5EvidenceForCustomer(modules = {}) {\n  projectCertificateSharedSanForCustomer({ ssl: modules.ssl, certificateIntelligence: modules.certificate_intelligence });\n  const evidence = resolvePhase5EvidenceContract(modules);", "M09 invocation");
      return out;
    },
  },
  {
    id: "SAN_A_M10", target: "ssl", expected: ["F10"],
    mutate: (s) => replaceExactly(s,
      '      schema_version: "external-certificate-observation-v3",',
      '      schema_version: "external-certificate-observation-v3",\n      schema_note: "mutation",', "M10"),
  },
  {
    id: "SAN_A_M11", target: "projector", expected: ["F07", "F09"],
    mutate: (s) => replaceExactly(s,
      "const rawSharedSanCount = ssl?.cert_shared_san_count;",
      "const rawSharedSanCount = ssl?.cert_shared_san_count ?? 0;", "M11"),
  },
  {
    id: "SAN_A_M12", target: "route", expected: ["F21"],
    mutate: (s) => replaceExactly(s,
      `          modules: {\n            ...normalisedModules,\n            historical_changes: projectHistoricalChangesForCustomer(\n              normalisedModules.historical_changes,\n              { comparable: false, currentModules: normalisedModules },\n            ),\n            certificate_intelligence: projectedCertificateIntelligence,\n          },\n          business_risk: null,`,
      `          modules: {\n            ...normalisedModules,\n            historical_changes: projectHistoricalChangesForCustomer(\n              normalisedModules.historical_changes,\n              { comparable: false, currentModules: normalisedModules },\n            ),\n            certificate_intelligence: normalisedModules.certificate_intelligence,\n          },\n          business_risk: null,`, "M12"),
  },
  {
    id: "SAN_A_M14", target: "snapshot", expected: ["F12", "F13"],
    mutate: (s) => replaceExactly(s,
      "  const lifecycleRelationship = Array.isArray(certificateLifecycleRecords)",
      "  certificateAssurance.shared_san_candidate_a_mutation =\n    report?.modules?.certificate_intelligence?.shared_san_assessment?.measurement_state ?? null;\n  const lifecycleRelationship = Array.isArray(certificateLifecycleRecords)", "M14"),
  },
  {
    id: "SAN_A_M15", target: "p4Fixture", expected: ["F20"],
    mutate: (s) => replaceExactly(s,
      '"schema_version": "external-certificate-observation-v2"',
      '"schema_version": "external-certificate-observation-v3"', "M15"),
  },
];

let failures = 0;
let killed = 0;
const initialFingerprint = worktreeFingerprint();
for (const mutant of mutants) {
  const file = targets[mutant.target];
  const original = fs.readFileSync(file);
  try {
    const mutated = mutant.mutate(original.toString("utf8"));
    if (mutated === original.toString("utf8")) throw new Error("mutation changed no bytes");
    fs.writeFileSync(file, mutated);
    const result = runValidator();
    const exact = JSON.stringify(result.failures) === JSON.stringify(mutant.expected);
    if (result.normal && exact) {
      killed += 1;
      console.log(`PASS ${mutant.id} exact FAIL set ${JSON.stringify(result.failures)}`);
    } else {
      failures += 1;
      console.error(`FAIL ${mutant.id} expected=${JSON.stringify(mutant.expected)} actual=${JSON.stringify(result.failures)} status=${result.child.status} signal=${result.child.signal} error=${result.child.error?.message || "none"}\n${result.output}`);
    }
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${mutant.id} — ${error?.message || error}`);
  } finally {
    fs.writeFileSync(file, original);
    if (digest(fs.readFileSync(file)) !== digest(original)) {
      failures += 1;
      console.error(`FAIL ${mutant.id} target bytes not restored`);
    }
    if (worktreeFingerprint() !== initialFingerprint) {
      failures += 1;
      console.error(`FAIL ${mutant.id} worktree fingerprint not restored`);
    }
  }
}

let controls = 0;
function control(name, condition) {
  if (condition) { controls += 1; console.log(`PASS ${name}`); }
  else { failures += 1; console.error(`FAIL ${name}`); }
}

// Syntax failure: no normal fixture summary, therefore never a semantic kill.
{
  const file = targets.route;
  const original = fs.readFileSync(file);
  try {
    fs.writeFileSync(file, `${original.toString("utf8")}\nthis is invalid syntax !\n`);
    const result = runValidator();
    control("SYNTAX_FAILURE_REJECTED", !result.normal && result.failures.length === 0);
  } finally { fs.writeFileSync(file, original); }
}

// Import/load failure: no normal fixture summary.
{
  const file = targets.projector;
  const original = fs.readFileSync(file);
  try {
    fs.writeFileSync(file, replaceExactly(original.toString("utf8"),
      'from "../engines/cert-intel.js";', 'from "../engines/missing-cert-intel.js";', "load control"));
    const result = runValidator();
    control("LOAD_FAILURE_REJECTED", !result.normal && result.failures.length === 0);
  } finally { fs.writeFileSync(file, original); }
}

// Timeout/signal: a process killed before its normal summary is not a kill.
{
  const result = runValidator(1);
  control("TIMEOUT_REJECTED", !result.normal && result.child.error?.code === "ETIMEDOUT");
}

// A real but different semantic failure cannot satisfy M01.
{
  const file = targets.projector;
  const original = fs.readFileSync(file);
  try {
    fs.writeFileSync(file, replaceExactly(original.toString("utf8"),
      "confidence: ownership.confidence,", "confidence: null,", "wrong reason"));
    const result = runValidator();
    control("WRONG_REASON_REJECTED", result.normal && result.failures.length > 0 &&
      JSON.stringify(result.failures) !== JSON.stringify(mutants[0].expected));
  } finally { fs.writeFileSync(file, original); }
}

// Right IDs in the wrong order are explicitly rejected by exact-array equality.
control("WRONG_ORDER_REJECTED",
  JSON.stringify(["F02", "F01"]) !== JSON.stringify(mutants[0].expected));

if (worktreeFingerprint() !== initialFingerprint) {
  failures += 1;
  console.error("FAIL final worktree fingerprint drift");
}
console.log(`Candidate A mutations: ${killed}/${mutants.length} semantic mutants killed; ${controls}/5 invalid-kill controls rejected`);
if (failures || killed !== mutants.length || controls !== 5) process.exit(1);
