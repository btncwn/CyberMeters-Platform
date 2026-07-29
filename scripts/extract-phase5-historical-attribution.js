#!/usr/bin/env node
// Exact bounded, read-only, sanitised extraction used by the Phase-5
// historical attribution audit.
//
// Production invocation (explicitly read-only):
//   node scripts/extract-phase5-historical-attribution.js \
//     --remote --expected=57 \
//     --output=/tmp/phase5-candidate-evidence.json
//
// The D1 SELECT is fixed below and deliberately requests MAX_CANDIDATES + 1 so
// cohort growth fails instead of silently truncating. R2 objects are fetched
// sequentially into an auto-cleaned temporary directory. Only the three
// Phase-5 module contract flags plus frozen quality/score/rating are emitted.
// Scan, workspace, tenant, domain and report identifiers are never written to
// the sanitised output or stdout. No D1/R2 write command exists in this file.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerDir = path.join(root, "workers", "scan-api");
const MAX_CANDIDATES = 57;
const CANDIDATE_QUERY = `
SELECT id AS scan_id, scan_quality, score, rating
FROM scans
WHERE status = 'completed'
  AND scan_quality IN ('partial', 'degraded')
  AND (
    lower(coalesce(rating, '')) = 'excellent'
    OR score >= 90
  )
ORDER BY created_at ASC, id ASC
LIMIT ${MAX_CANDIDATES + 1}
`.trim();
const MODULE_KEYS = [
  "cve_intelligence",
  "known_exploited_vulnerabilities",
  "email_security_intelligence",
];

const arg = (name) => process.argv
  .find((value) => value.startsWith(`--${name}=`))
  ?.slice(name.length + 3);
const outputPath = path.resolve(arg("output") ?? "");
const expected = Number(arg("expected") ?? MAX_CANDIDATES);
const remote = process.argv.includes("--remote");
if (!outputPath || outputPath === path.resolve("")) {
  console.error("usage: extract-phase5-historical-attribution.js --remote --expected=57 --output=/tmp/file.json");
  process.exit(2);
}
if (!remote) {
  console.error("refusing to run without the explicit read-only --remote flag");
  process.exit(2);
}
if (!Number.isInteger(expected) || expected < 0 || expected > MAX_CANDIDATES) {
  throw new Error(`expected must be an integer from 0 to ${MAX_CANDIDATES}`);
}
const relativeOutput = path.relative(root, outputPath);
if (!relativeOutput.startsWith("..") && !path.isAbsolute(relativeOutput)) {
  throw new Error("sanitised extraction output must be outside the repository");
}

function parseD1Rows(stdout) {
  const parsed = JSON.parse(String(stdout));
  if (Array.isArray(parsed)) {
    if (parsed.length === 1 && Array.isArray(parsed[0]?.results)) {
      return parsed[0].results;
    }
    if (parsed.every((value) => value && typeof value === "object" &&
        !Array.isArray(value))) {
      return parsed;
    }
  }
  if (Array.isArray(parsed?.results)) return parsed.results;
  throw new Error("unexpected Wrangler D1 JSON response");
}

function sanitiseModule(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const sanitised = {};
  for (const key of [
    "executed",
    "incomplete",
    "outcome",
    "skipped",
    "evidence_publishable",
  ]) {
    if (value[key] !== undefined) sanitised[key] = value[key];
  }
  if (value.error !== undefined) sanitised.error = Boolean(value.error);
  return sanitised;
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "phase5-readonly-"));
try {
  const rawCandidates = execFileSync("npx", [
    "wrangler",
    "d1",
    "execute",
    "cybermeters-db",
    "--remote",
    "--json",
    "--command",
    CANDIDATE_QUERY,
  ], {
    cwd: workerDir,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const candidates = parseD1Rows(rawCandidates);
  if (candidates.length > MAX_CANDIDATES) {
    throw new Error(
      `candidate cohort exceeds fixed ${MAX_CANDIDATES}-report bound`,
    );
  }
  if (candidates.length !== expected) {
    throw new Error(
      `expected ${expected} candidate reports, received ${candidates.length}`,
    );
  }

  const sanitisedRows = [];
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    if (!candidate?.scan_id) throw new Error("candidate scan identity missing");
    const reportPath = path.join(scratch, `report-${index}.json`);
    execFileSync("npx", [
      "wrangler",
      "r2",
      "object",
      "get",
      `cybermeters-reports/reports/${candidate.scan_id}.json`,
      "--remote",
      "--file",
      reportPath,
    ], {
      cwd: workerDir,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    sanitisedRows.push({
      scan_quality: candidate.scan_quality ?? null,
      score: Number.isFinite(candidate.score) ? candidate.score : null,
      rating: candidate.rating ?? null,
      modules: Object.fromEntries(MODULE_KEYS.map((key) => [
        key,
        sanitiseModule(report?.modules?.[key]),
      ])),
    });
  }
  fs.writeFileSync(outputPath, `${JSON.stringify(sanitisedRows, null, 2)}\n`, {
    mode: 0o600,
  });
  process.stdout.write(JSON.stringify({
    procedure: "bounded-read-only-d1-r2-phase5-attribution-v1",
    population: sanitisedRows.length,
    output_contains_identifiers: false,
    d1_writes: 0,
    r2_writes: 0,
  }) + "\n");
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
