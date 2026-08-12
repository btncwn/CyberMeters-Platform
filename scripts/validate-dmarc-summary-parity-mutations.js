#!/usr/bin/env node
// Exact semantic mutation contract for the pre-Item11 DMARC parity corrective.
// Every mutant runs the focused suite in a fresh isolated source tree. A kill
// counts only for its frozen FAIL-id set; syntax/load/no-op kills are rejected.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = "scripts/validate-dmarc-summary-parity.js";
const stateFile = "workers/scan-api/src/engines/dmarc-state.js";
const emailFile = "workers/scan-api/src/engines/email-scan.js";
const presentationFile =
  "workers/scan-api/src/engines/dmarcbis-presentation.js";
const snapshotFile = "workers/scan-api/src/engines/report-snapshot.js";
const EXPECTED_MUTANTS = 10;

const sha256 = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

function replaceOnce(source, from, to) {
  const first = source.indexOf(from);
  if (first < 0 || source.indexOf(from, first + from.length) >= 0) {
    throw new Error(`mutation anchor missing or non-unique: ${JSON.stringify(from)}`);
  }
  return source.slice(0, first) + to + source.slice(first + from.length);
}

function replaceInSection(source, startMarker, endMarker, replacements) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) {
    throw new Error(`section markers missing: ${startMarker} / ${endMarker}`);
  }
  let section = source.slice(start, end);
  for (const [from, to] of replacements) section = replaceOnce(section, from, to);
  return source.slice(0, start) + section + source.slice(end);
}

const M = (name, file, expectedFailures, mutate) => ({
  name, file, expectedFailures: [...expectedFailures].sort(), mutate,
});

const MUTANTS = Object.freeze([
  M("stale lookup failure wins over valid exact policy", stateFile, [
    "DMARC-PARITY-COMPOSED-SUMMARY",
    "DMARC-PARITY-OVERALL-SUMMARY-PARITY",
    "DMARC-PARITY-PNONE-NOT-HEALTHY",
    "DMARC-PARITY-SNAPSHOT-SUMMARY-TECHNICAL-PARITY",
    "DMARC-PARITY-SUMMARY-CANONICAL",
    "DMARC-PARITY-UNRELATED-EMAIL-SUMMARY-UNCHANGED",
    "DMARC-PARITY-VALID-NONE-STALE",
  ], (source) => replaceOnce(
    source,
    `    evidence.policy_completeness === "complete" &&
    VALID_POLICIES.has(policy) &&`,
    `    evidence.policy_completeness === "complete" &&
    evidence.core_completeness === "complete" &&
    VALID_POLICIES.has(policy) &&`,
  )),
  M("p=none is promoted to rejection/healthy", stateFile, [
    "DMARC-PARITY-COMPOSED-SUMMARY",
    "DMARC-PARITY-HISTORICAL-READ-RAW",
    "DMARC-PARITY-OVERALL-SUMMARY-PARITY",
    "DMARC-PARITY-PNONE-NOT-HEALTHY",
    "DMARC-PARITY-SNAPSHOT-SUMMARY-TECHNICAL-PARITY",
    "DMARC-PARITY-SUMMARY-CANONICAL",
    "DMARC-PARITY-VALID-NONE-STALE",
  ], (source) => replaceOnce(
    source,
    `          policy,
          percentage: 100,`,
    `          policy: policy === "none" ? "reject" : policy,
          percentage: 100,`,
  )),
  M("unavailable evidence becomes absent", stateFile, [
    "DMARC-PARITY-UNAVAILABLE-DISTINCT",
  ], (source) => replaceOnce(
    source,
    `    incomplete ? "incomplete" : "unavailable",
    evidence,`,
    `    incomplete ? "incomplete" : "absent",
    evidence,`,
  )),
  M("proven absence becomes unavailable", stateFile, [
    "DMARC-PARITY-ABSENT-DISTINCT",
  ], (source) => replaceOnce(
    source,
    `      evidence.policy_source_kind === "none" &&
      evidence.policy_completeness === "complete") {`,
    `      evidence.policy_source_kind === "never" &&
      evidence.policy_completeness === "complete") {`,
  )),
  M("malformed evidence becomes a valid monitoring policy", stateFile, [
    "DMARC-PARITY-MALFORMED-DISTINCT",
  ], (source) => {
    let mutated = replaceOnce(
      source,
      "  const policy = normalizePolicy(evidence.effective_requested_policy);",
      `  const policy = normalizePolicy(
    evidence.effective_requested_policy ??
      (evidence.observation_state === "present_invalid" ? "none" : null)
  );`,
    );
    mutated = replaceOnce(
      mutated,
      "    VALID_POLICY_OBSERVATIONS.has(evidence.observation_state) &&",
      `    (VALID_POLICY_OBSERVATIONS.has(evidence.observation_state) ||
      evidence.observation_state === "present_invalid") &&`,
    );
    mutated = replaceOnce(
      mutated,
      "    VALID_POLICY_RECORDS.has(evidence.record_validity) &&",
      `    (VALID_POLICY_RECORDS.has(evidence.record_validity) ||
      evidence.record_validity === "invalid") &&`,
    );
    return replaceOnce(
      mutated,
      "    POLICY_SOURCE_KINDS.has(evidence.policy_source_kind) &&",
      `    (POLICY_SOURCE_KINDS.has(evidence.policy_source_kind) ||
      evidence.policy_source_kind === "none") &&`,
    );
  }),
  M("report summary bypasses canonical DMARC projection", snapshotFile, [
    "DMARC-PARITY-COMPOSED-SUMMARY",
  ], (source) => replaceOnce(
    source,
    `  const reportForCustomer = projectDmarcReportForCustomer(
    projectTlsReportForCustomer(report ?? {}),
    dmarcPolicyEvidence,
  );`,
    "  const reportForCustomer = projectTlsReportForCustomer(report ?? {});",
  )),
  M("technical view bypasses canonical DMARC assessment", presentationFile, [
    "DMARC-PARITY-SNAPSHOT-SUMMARY-TECHNICAL-PARITY",
    "DMARC-PARITY-TECHNICAL-CANONICAL",
  ], (source) => replaceOnce(
    source,
    "    canonical_assessment: canonicalAssessment,",
    "    canonical_assessment: null,",
  )),
  M("DMARC projection changes unrelated DKIM/SPF", emailFile, [
    "DMARC-PARITY-SPF-DKIM-UNCHANGED",
  ], (source) => replaceOnce(
    source,
    `  result.dmarc = {
    present: candidates.length > 0,`,
    `  result.spf = { present: false, record: null };
  result.dkim = { present: false, selector: null };
  result.dmarc = {
    present: candidates.length > 0,`,
  )),
  M("read path rewrites immutable snapshot bytes", snapshotFile, [
    "DMARC-PARITY-HISTORICAL-READ-RAW",
  ], (source) => replaceOnce(
    source,
    `    snapshot,
    customerSnapshot,`,
    `    snapshot: customerSnapshot,
    customerSnapshot,`,
  )),
  M("latest DMARC evidence accepts a foreign workspace", snapshotFile, [
    "DMARC-PARITY-SOFT-DELETE-ISOLATION",
    "DMARC-PARITY-TENANT-ISOLATION",
  ], (source) => replaceInSection(
    source,
    "export async function readLatestDomainDmarcPolicyEvidence(",
    "  return read.dmarcPolicy;",
    [
      [
        "WHERE s.workspace_id = ? AND s.domain_id = ? AND s.status = 'completed'",
        "WHERE s.domain_id = ? AND s.status = 'completed'",
      ],
      ["    .bind(workspaceId, domainId)", "    .bind(domainId)"],
      [
        `    read.row.workspace_id !== workspaceId ||
    read.row.domain_id !== domainId`,
        "    read.row.domain_id !== domainId",
      ],
    ],
  )),
]);

let passed = 0;
let failed = 0;
function check(name, condition, detail = "") {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function runValidator(repo) {
  return spawnSync(process.execPath, [path.join(repo, validator)], {
    cwd: repo,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
  });
}

function failureIds(output) {
  return [...String(output).matchAll(
    /^FAIL (DMARC-PARITY-[A-Z0-9-]+)/gm,
  )].map((match) => match[1]).sort();
}

function isolatedRepo() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cm-dmarc-parity-mutant-"));
  const workerRoot = path.join(temp, "workers", "scan-api");
  fs.mkdirSync(path.join(temp, "scripts"), { recursive: true });
  fs.mkdirSync(workerRoot, { recursive: true });
  fs.cpSync(
    path.join(root, "workers", "scan-api", "src"),
    path.join(workerRoot, "src"),
    { recursive: true },
  );
  fs.cpSync(path.join(root, "shared"), path.join(temp, "shared"), {
    recursive: true,
  });
  fs.copyFileSync(path.join(root, validator), path.join(temp, validator));
  fs.symlinkSync(
    path.join(root, "workers", "scan-api", "node_modules"),
    path.join(workerRoot, "node_modules"),
    "dir",
  );
  return temp;
}

function semanticKill(result, expectedFailures) {
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const got = failureIds(output);
  const problems = [];
  if (result.error) problems.push(`spawn ${result.error.message}`);
  if (result.signal !== null) problems.push(`signal ${result.signal}`);
  if (result.status !== 1) problems.push(`exit ${result.status}, want 1`);
  if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|TypeError:/.test(output)) {
    problems.push("syntax/load/runtime failure");
  }
  if (JSON.stringify(got) !== JSON.stringify(expectedFailures)) {
    problems.push(
      `FAIL set ${JSON.stringify(got)}, want ${JSON.stringify(expectedFailures)}`,
    );
  }
  return { accepted: problems.length === 0, problems, output };
}

const targetPaths = [...new Set(MUTANTS.map((mutant) => mutant.file))];
const before = new Map(targetPaths.map((relative) => [
  relative,
  sha256(fs.readFileSync(path.join(root, relative))),
]));

check("mutant inventory is exact", MUTANTS.length === EXPECTED_MUTANTS);
const baseline = runValidator(root);
check("unmutated baseline is green",
  baseline.status === 0 && baseline.signal === null &&
  !/^(FAIL|SyntaxError|Error)/m.test(
    `${baseline.stdout || ""}\n${baseline.stderr || ""}`,
  ),
  `${baseline.stdout || ""}\n${baseline.stderr || ""}`.trim());

for (const mutant of MUTANTS) {
  const temp = isolatedRepo();
  let detail = "";
  let accepted = false;
  try {
    const target = path.join(temp, mutant.file);
    const original = fs.readFileSync(target, "utf8");
    const mutated = mutant.mutate(original);
    if (mutated === original) throw new Error("mutation did not change target bytes");
    fs.writeFileSync(target, mutated);
    const outcome = semanticKill(runValidator(temp), mutant.expectedFailures);
    accepted = outcome.accepted;
    detail = outcome.problems.length
      ? `${outcome.problems.join("; ")}\n${outcome.output.trim()}`
      : mutant.expectedFailures.join(", ");
  } catch (error) {
    detail = error?.stack || error?.message || String(error);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  check(`mutant ${mutant.name} killed for exact reason`, accepted, detail);
  check(`mutant ${mutant.name} preserved target bytes`,
    sha256(fs.readFileSync(path.join(root, mutant.file))) ===
      before.get(mutant.file));
}

let noOpRejected = false;
try {
  const source = fs.readFileSync(path.join(root, stateFile), "utf8");
  const mutated = source.replace("canonical_evidence_state", "canonical_evidence_state");
  if (mutated === source) throw new Error("mutation did not change target bytes");
} catch (error) {
  noOpRejected = /did not change target bytes/.test(String(error?.message));
}
check("no-op mutant is rejected", noOpRejected);

const syntaxTemp = isolatedRepo();
let syntaxRejected = false;
try {
  const target = path.join(syntaxTemp, stateFile);
  const source = fs.readFileSync(target, "utf8");
  const mutated = replaceOnce(
    source,
    "export function deriveDmarcState(input = {}) {",
    "export function deriveDmarcState(input = {} {",
  );
  fs.writeFileSync(target, mutated);
  syntaxRejected = !semanticKill(
    runValidator(syntaxTemp),
    ["DMARC-PARITY-VALID-NONE-STALE"],
  ).accepted;
} finally {
  fs.rmSync(syntaxTemp, { recursive: true, force: true });
}
check("syntax/load kill is rejected", syntaxRejected);

check("all target bytes remain restored", targetPaths.every((relative) =>
  sha256(fs.readFileSync(path.join(root, relative))) === before.get(relative)));

console.log(
  `\nDMARC summary parity mutations: ${EXPECTED_MUTANTS}/${EXPECTED_MUTANTS} ` +
  `mutants evaluated; ${passed}/${passed + failed} harness assertions passed`,
);
if (failed) process.exit(1);
console.log("DMARC summary parity mutation validation passed");
