#!/usr/bin/env node
// Candidate A F11/M13 — oracle/projector atomicity governance.
//
// The production check accepts either an uncommitted frozen candidate whose
// single diff contains both changes, or committed history in which both stable
// markers were introduced by exactly the same commit. The operational self-test
// constructs isolated temporary repositories and proves oracle-only and
// projection-only intermediate commits fail while an atomic commit passes.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const sslPath = "workers/scan-api/src/engines/ssl-scan.js";
const projectorPath = "workers/scan-api/src/routes/certificate-shared-san-projection.js";
const oracleMarker = "external-certificate-observation-v3";
const projectionMarker = "legacy_ambiguous_zero";

function git(repo, args, options = {}) {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  }).trim();
}

function read(repo, relative) {
  const absolute = path.join(repo, ...relative.split("/"));
  return fs.existsSync(absolute) ? fs.readFileSync(absolute, "utf8") : "";
}

function revisionFile(repo, revision, relative) {
  try {
    return git(repo, ["show", `${revision}:${relative}`]);
  } catch {
    return "";
  }
}

function projectorIntroductions(repo) {
  const commit = git(repo, [
    "log", "-1", "--format=%H", "--diff-filter=A", "--", projectorPath,
  ]);
  return commit ? [commit] : [];
}

function checkRepository(repo, { allowUncommitted = true } = {}) {
  const workingOracle = read(repo, sslPath).includes(oracleMarker);
  const workingProjection = read(repo, projectorPath).includes(projectionMarker);
  let headOracle = false;
  let headProjection = false;
  try {
    headOracle = git(repo, ["show", `HEAD:${sslPath}`]).includes(oracleMarker);
  } catch { /* absent */ }
  try {
    headProjection = git(repo, ["show", `HEAD:${projectorPath}`]).includes(projectionMarker);
  } catch { /* absent */ }

  if (allowUncommitted && workingOracle && workingProjection &&
      (!headOracle || !headProjection)) {
    return {
      ok: !headOracle && !headProjection,
      mode: "uncommitted_frozen_diff",
      detail: "both markers are introduced together relative to HEAD",
    };
  }

  // The projector is a new Candidate-A-only file. Its single addition commit
  // is therefore the bounded cutover point: prove both stable markers are
  // absent in its parent and present in that same commit. Avoid an unbounded
  // pickaxe scan over ssl-scan.js history in every CI run.
  const projectionCommits = projectorIntroductions(repo);
  const introductionCommit = projectionCommits.length === 1
    ? projectionCommits[0]
    : null;
  const parent = introductionCommit ? `${introductionCommit}^` : null;
  const oracleIntroduced = introductionCommit != null &&
    revisionFile(repo, introductionCommit, sslPath).includes(oracleMarker) &&
    !revisionFile(repo, parent, sslPath).includes(oracleMarker);
  const projectionIntroduced = introductionCommit != null &&
    revisionFile(repo, introductionCommit, projectorPath).includes(projectionMarker) &&
    !revisionFile(repo, parent, projectorPath).includes(projectionMarker);
  const oracleCommits = oracleIntroduced ? [introductionCommit] : [];
  return {
    ok: workingOracle && workingProjection &&
      oracleIntroduced && projectionIntroduced,
    mode: "committed_history",
    oracleCommits,
    projectionCommits,
  };
}

function writeFixture(repo, { oracle, projection }) {
  const sslAbsolute = path.join(repo, ...sslPath.split("/"));
  const projectorAbsolute = path.join(repo, ...projectorPath.split("/"));
  fs.mkdirSync(path.dirname(sslAbsolute), { recursive: true });
  fs.mkdirSync(path.dirname(projectorAbsolute), { recursive: true });
  fs.writeFileSync(sslAbsolute,
    `export const schema = "external-certificate-observation-v${oracle ? 3 : 2}";\n`);
  if (projection) {
    fs.writeFileSync(projectorAbsolute,
      `export const state = "${projectionMarker}";\n`);
  } else if (fs.existsSync(projectorAbsolute)) {
    fs.rmSync(projectorAbsolute);
  }
}

function commitAll(repo, message) {
  git(repo, ["add", "."]);
  git(repo, ["commit", "-q", "-m", message], {
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Candidate A governance fixture",
      GIT_AUTHOR_EMAIL: "candidate-a@example.invalid",
      GIT_COMMITTER_NAME: "Candidate A governance fixture",
      GIT_COMMITTER_EMAIL: "candidate-a@example.invalid",
    },
  });
}

function operationalSelfTest() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cert-san-a-atomicity-"));
  try {
    git(temp, ["init", "-q"]);
    writeFixture(temp, { oracle: false, projection: false });
    commitAll(temp, "base");
    const base = git(temp, ["rev-parse", "HEAD"]);

    git(temp, ["switch", "-q", "-c", "oracle-only", base]);
    writeFixture(temp, { oracle: true, projection: false });
    commitAll(temp, "oracle only");
    const oracleOnly = checkRepository(temp, { allowUncommitted: false });

    git(temp, ["switch", "-q", "-c", "projection-only", base]);
    writeFixture(temp, { oracle: false, projection: true });
    commitAll(temp, "projection only");
    const projectionOnly = checkRepository(temp, { allowUncommitted: false });

    git(temp, ["switch", "-q", "-c", "atomic", base]);
    writeFixture(temp, { oracle: true, projection: true });
    commitAll(temp, "atomic candidate");
    const atomic = checkRepository(temp, { allowUncommitted: false });

    return {
      ok: !oracleOnly.ok && !projectionOnly.ok && atomic.ok,
      oracle_only: oracleOnly,
      projection_only: projectionOnly,
      atomic,
    };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

let failures = 0;
const current = checkRepository(root);
if (current.ok) {
  console.log(`PASS SAN_A_F11 — ${current.mode}: ${current.detail || current.oracleCommits?.[0]}`);
} else {
  failures += 1;
  console.error(`FAIL SAN_A_F11 — oracle and projection are not one atomic candidate: ${JSON.stringify(current)}`);
}

const selfTest = operationalSelfTest();
if (selfTest.ok) {
  console.log("PASS SAN_A_M13 — oracle-only FAIL, projection-only FAIL, atomic PASS");
} else {
  failures += 1;
  console.error(`FAIL SAN_A_M13 — three-state governance proof failed: ${JSON.stringify(selfTest)}`);
}

console.log(`Candidate A atomicity governance: ${2 - failures}/2 passed`);
if (failures) process.exit(1);
