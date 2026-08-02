#!/usr/bin/env node
// Strict source-mutation proof for CE Stage-1 containment.
// Every mutant runs the focused validator in a fresh process against exactly one named
// assertion. Syntax/load/runtime/wrong-reason kills are rejected, and every target byte plus
// the complete intended-worktree fingerprint must be restored after each run.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-ce-multidomain-containment.js");
const readiness = path.join(root, "workers", "scan-api", "src", "engines", "ce-readiness.js");
const lifecycle = path.join(root, "workers", "scan-api", "src", "engines", "ce-lifecycle.js");
const frontend = path.join(root, "frontend", "src", "pages", "ws", "WorkspaceCyberEssentialsPage.jsx");
const targets = [readiness, lifecycle, frontend];
const EXPECTED_MUTANTS = 12;
const EXPECTED_ASSERTIONS = 22;

const original = new Map(targets.map((file) => [file, fs.readFileSync(file)]));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sourceShas = () => Object.fromEntries(targets.map((file) => [path.relative(root, file), sha256(fs.readFileSync(file))]));

function workingTreeFingerprint() {
  const status = spawnSync("git", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], {
    cwd: root, encoding: "buffer",
  });
  if (status.error || status.signal || status.status !== 0) throw new Error("cannot fingerprint worktree status");
  const raw = status.stdout.toString("utf8");
  const hash = crypto.createHash("sha256").update(raw);
  for (const record of raw.split("\0").filter(Boolean)) {
    const relative = record.slice(3);
    const file = path.join(root, relative);
    hash.update(relative).update("\0");
    if (fs.existsSync(file) && fs.statSync(file).isFile()) hash.update(fs.readFileSync(file));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function restoreAll() {
  for (const [file, bytes] of original) fs.writeFileSync(file, bytes);
}

let interrupted = false;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    interrupted = true;
    restoreAll();
    console.error(`INTERRUPTED ${signal}: production target bytes restored; rerun fingerprint proof before trusting the worktree`);
    process.exit(130);
  });
}

function replaceExactlyOnce(text, anchor, replacement, label) {
  const first = text.indexOf(anchor);
  if (first < 0 || text.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor count is not exactly one`);
  }
  return text.slice(0, first) + replacement + text.slice(first + anchor.length);
}

function runValidator(only = null) {
  return spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: "utf8",
    timeout: 180000,
    env: { ...process.env, ...(only ? { CE_CONTAINMENT_ONLY: only } : {}) },
  });
}

function totals(output) {
  const match = output.match(/ce-multidomain-containment: (\d+) passed, (\d+) failed/);
  return match ? { pass: Number(match[1]), fail: Number(match[2]) } : null;
}
function failNames(output) {
  return [...output.matchAll(/^FAIL (.+?)(?: —|$)/gm)].map((match) => match[1]).sort();
}

const readinessGate = "  if (containmentReason) return cyberEssentialsContainedResponse(wsId, containmentReason);";
const lifecycleGate = "    if (readiness.assessable === false) {";
const listProjection = `  return (rows.results || []).map((row) => ceControlRecordToApi(row, {
    containment_reason: containmentReason,
  }));`;
const getPreamble = `export async function getCeControlRecord(env, workspaceId, recordId) {
  const domainCount = await resolveCeWorkspaceDomainCount(env, workspaceId);
  const containmentReason = ceWorkspaceContainmentReason(domainCount);`;
const getQuery = `    .prepare(\`SELECT * FROM cyber_essentials_control_records WHERE workspace_id = ? AND id = ?\`)
    .bind(workspaceId, recordId).first().catch(() => null);`;
const recordedFields = `    recorded_readiness_state: row.readiness_state ?? null,
    recorded_readiness_reason: row.readiness_reason ?? null,
    recorded_evidence: recordedEvidence,`;

const mutants = [
  {
    id: "M1", name: "remove multi-domain readiness gate", file: readiness,
    target: "multi-domain readiness is not assessed before scan or R2 work",
    edits: [[readinessGate, "  if (false) return cyberEssentialsContainedResponse(wsId, containmentReason);"]],
  },
  {
    id: "M2", name: "allow count zero", file: readiness,
    target: "zero linked domains are not assessed",
    edits: [["  if (domainCount.count === 1) return null;", "  if (domainCount.count <= 1) return null;"]],
  },
  {
    id: "M3", name: "convert count-query failure to one", file: readiness,
    target: "domain-count query failure fails closed instead of becoming count zero or one",
    edits: [["  } catch {\n    return { known: false, count: null };\n  }", "  } catch {\n    return { known: true, count: 1 };\n  }"]],
  },
  {
    id: "M4", name: "filter unverified linked domains out of the count", file: readiness,
    target: "multi-domain readiness is not assessed before scan or R2 work",
    edits: [["                WHERE workspace_id = ?`)", "                WHERE workspace_id = ? AND verification_status = 'verified'`)"]],
  },
  {
    id: "M5", name: "let lifecycle proceed despite assessable false", file: lifecycle,
    target: "multi-domain lifecycle performs zero durable case and alert writes",
    edits: [[lifecycleGate, "    if (false) {"]],
  },
  {
    id: "M6", name: "bypass durable-record list read-side gate", file: lifecycle,
    target: "contained list projection cannot bypass the durable read-side gate",
    edits: [[listProjection, "  return (rows.results || []).map((row) => ceControlRecordToApi(row));"]],
  },
  {
    id: "M7", name: "fall back to stored ready when count lookup fails", file: lifecycle,
    target: "count failure never falls back to stored ready on durable get",
    edits: [[getPreamble, `${getPreamble.split("\n").slice(0, 2).join("\n")}
  const containmentReason = domainCount.known ? ceWorkspaceContainmentReason(domainCount) : null;`]],
  },
  {
    id: "M8", name: "verify awaiting case from unrelated-domain scan", file: readiness,
    target: "awaiting-verification case is not verified by an unrelated clean scan",
    edits: [[readinessGate, "  if (false) return cyberEssentialsContainedResponse(wsId, containmentReason);"]],
  },
  {
    id: "M9", name: "emit alert under containment", file: readiness,
    target: "alert resolver finds no actionable transition under containment",
    edits: [[readinessGate, "  if (false) return cyberEssentialsContainedResponse(wsId, containmentReason);"]],
  },
  {
    id: "M10", name: "restore green PriorityGaps branch", file: frontend,
    target: "frontend neutral not-assessed fixture rejects green zero gaps",
    edits: [[`function PriorityGaps({ readiness }) {
  if (readinessIsNotAssessed(readiness)) {`, `function PriorityGaps({ readiness }) {
  if (false) {`]],
  },
  {
    id: "M11", name: "omit recorded historical fields", file: lifecycle,
    target: "stored ready projects unknown with explicit recorded historical fields",
    edits: [[recordedFields, ""]],
  },
  {
    id: "M12", name: "weaken foreign-record non-enumeration gate", file: lifecycle,
    target: "foreign durable record remains non-enumerating",
    edits: [[getQuery, `    .prepare(\`SELECT * FROM cyber_essentials_control_records WHERE id = ?\`)
    .bind(recordId).first().catch(() => null);`]],
  },
];

const intendedTree = workingTreeFingerprint();
const intendedSourceShas = sourceShas();
let killed = 0;
let failed = 0;

try {
  if (mutants.length !== EXPECTED_MUTANTS) throw new Error(`pinned mutant count drift: got ${mutants.length}`);
  const baseline = runValidator();
  const baselineOutput = `${baseline.stdout || ""}\n${baseline.stderr || ""}`;
  const baselineTotals = totals(baselineOutput);
  if (baseline.error || baseline.signal != null || baseline.status !== 0 ||
      baselineTotals?.pass !== EXPECTED_ASSERTIONS || baselineTotals?.fail !== 0) {
    throw new Error(`baseline is not ${EXPECTED_ASSERTIONS}/${EXPECTED_ASSERTIONS} green\n${baselineOutput}`);
  }
  console.log(`PASS baseline validator green (${EXPECTED_ASSERTIONS}/${EXPECTED_ASSERTIONS})`);

  for (const mutant of mutants) {
    restoreAll();
    let mutated = original.get(mutant.file).toString("utf8");
    mutant.edits.forEach(([anchor, replacement], index) => {
      mutated = replaceExactlyOnce(mutated, anchor, replacement, `${mutant.id} edit ${index + 1}`);
    });
    fs.writeFileSync(mutant.file, mutated);

    const child = runValidator(mutant.target);
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const gotTotals = totals(output);
    const gotFailures = failNames(output);
    const problems = [];
    if (child.error) problems.push(`spawn error: ${child.error.message}`);
    if (child.signal != null) problems.push(`signal: ${child.signal}`);
    if (child.status !== 1) problems.push(`exit status ${child.status}, want 1`);
    if (gotTotals?.pass !== 0 || gotTotals?.fail !== 1) problems.push(`summary ${JSON.stringify(gotTotals)}, want 0/1`);
    if (JSON.stringify(gotFailures) !== JSON.stringify([mutant.target])) problems.push(`FAIL names ${JSON.stringify(gotFailures)}`);
    if (/runtime:|ERR_MODULE|SyntaxError|unknown targeted assertion|assertion count drift/i.test(output)) problems.push("wrong-reason load/syntax/runtime kill");

    restoreAll();
    const restoredShas = sourceShas();
    const restoredTree = workingTreeFingerprint();
    if (JSON.stringify(restoredShas) !== JSON.stringify(intendedSourceShas)) problems.push("production source SHA not restored");
    if (restoredTree !== intendedTree) problems.push("intended-worktree fingerprint not restored");

    if (problems.length === 0) {
      killed++;
      console.log(`PASS ${mutant.id} ${mutant.name} died only at: ${mutant.target}`);
    } else {
      failed++;
      console.error(`FAIL ${mutant.id} ${mutant.name}: ${problems.join("; ")}\n${output.slice(-3000)}`);
    }
  }
} finally {
  restoreAll();
}

const finalShas = sourceShas();
const finalTree = workingTreeFingerprint();
if (JSON.stringify(finalShas) !== JSON.stringify(intendedSourceShas) || finalTree !== intendedTree) {
  console.error("FAIL final restore/fingerprint proof");
  process.exit(1);
}
if (interrupted) process.exit(130);
console.log(`\nce-multidomain-containment mutations: ${killed}/${EXPECTED_MUTANTS} killed; ${failed} harness failures`);
console.log(`production source SHA restored: ${JSON.stringify(finalShas)}`);
console.log(`intended-worktree fingerprint restored: ${finalTree}`);
if (failed || killed !== EXPECTED_MUTANTS) process.exit(1);
