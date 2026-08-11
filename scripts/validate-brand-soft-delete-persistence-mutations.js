#!/usr/bin/env node
//
// H-01 strict semantic mutants. Each mutant runs the DB-backed Brand soft-delete
// validator in a fresh isolated source tree and must fail with the exact pinned
// H01 assertion identities: no syntax/load/wrong-reason kill is accepted.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = "scripts/validate-brand-soft-delete-persistence.js";
const EXPECTED_MUTANTS = 27;
const EXPECTED_ASSERTIONS = 31;

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const replaceOnce = (source, from, to) => {
  const first = source.indexOf(from);
  if (first < 0 || source.indexOf(from, first + from.length) >= 0) {
    throw new Error(`mutation anchor missing or non-unique: ${JSON.stringify(from)}`);
  }
  return source.slice(0, first) + to + source.slice(first + from.length);
};
const replaceInSection = (source, startMarker, endMarker, from, to) => {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error(`section markers missing: ${startMarker} / ${endMarker}`);
  const section = source.slice(start, end);
  const mutated = replaceOnce(section, from, to);
  return source.slice(0, start) + mutated + source.slice(end);
};

const M = (name, file, expectedFailures, mutate) => ({ name, file, expectedFailures, mutate });
const asset = "workers/scan-api/src/engines/asset-persistence.js";
const passive = "workers/scan-api/src/engines/brand-passive-discovery.js";
const dns = "workers/scan-api/src/engines/brand-dns-enrichment.js";
const http = "workers/scan-api/src/engines/brand-http-enrichment.js";
const protection = "workers/scan-api/src/engines/brand-protection.js";
const cases = "workers/scan-api/src/engines/brand-cases.js";
const routes = "workers/scan-api/src/routes/brand.js";
const workspaces = "workers/scan-api/src/routes/workspaces-core.js";
const events = "workers/scan-api/src/lib/events.js";

const MUTANTS = Object.freeze([
  M("canonical existing-row read accepts deleted workspace", asset,
    ["H01-DELETED-DIRECT-EXISTING-READ", "H01-SOURCE-CANONICAL-INITIAL-READ"],
    (s) => replaceInSection(s, "let existing;", "const state =", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("canonical collision-winner read accepts deleted workspace", asset,
    ["H01-SOURCE-CANONICAL-WINNER-READ"],
    (s) => replaceInSection(s, "const winner =", "if (winner?.id", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("canonical CAS-verification read accepts deleted workspace", asset,
    ["H01-SOURCE-CANONICAL-VERIFY-READ"],
    (s) => replaceInSection(s, "const verified =", "if (verified &&", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("canonical insert accepts deleted workspace", asset,
    ["H01-DELETED-DIRECT", "H01-RACE-PASSIVE-CT", "H01-SOURCE-CANONICAL-PERSIST-INSERT"],
    (s) => replaceInSection(s, "`WITH candidate", "const winner =", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("canonical update accepts delete-between-read-and-write", asset,
    ["H01-RACE-DIRECT-UPDATE", "H01-SOURCE-CANONICAL-PERSIST-UPDATE"],
    (s) => replaceInSection(s, "`UPDATE workspace_brand_assets", "const verified =", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("scan workspace_domains authorizer includes deleted workspace", asset,
    ["H01-DELETED-SCAN-PRODUCER", "H01-SOURCE-SCAN-AUTHORIZER"],
    (s) => replaceInSection(s, "export async function upsertBrandAssets", "// The active workspace/domain membership read", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("scan profile link drops active-workspace authority", asset,
    ["H01-RACE-SCAN-PRODUCER", "H01-SOURCE-SCAN-PROFILE-LINK"],
    (s) => {
      let out = replaceOnce(s,
        "ON w.id = p.workspace_id AND w.deleted_at IS NULL",
        "ON w.id = p.workspace_id");
      return replaceOnce(out,
        "WHERE w.id = workspace_brand_assets.workspace_id\n                             AND w.deleted_at IS NULL",
        "WHERE w.id = workspace_brand_assets.workspace_id");
    }),
  M("passive direct discovery reads deleted workspace_domains", passive,
    ["H01-DELETED-PASSIVE-DIRECT", "H01-SOURCE-PASSIVE-PRODUCER"],
    (s) => replaceInSection(s, "export async function discoverBrandCandidatesForWorkspace", "// Bounded CT queries", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("passive scheduler selects deleted workspace", passive,
    ["H01-DELETED-PASSIVE-SCHEDULE"],
    (s) => replaceInSection(s, "export async function runBrandPassiveDiscoverySweep", "const all =", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("DNS candidate selection probes deleted workspace", dns,
    ["H01-DELETED-DNS-MANUAL", "H01-SOURCE-DNS-SELECT"],
    (s) => replaceInSection(s, "export function selectBrandCandidatesSql", "async function fireResolvingAssetEvent", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("DNS candidate update writes after deletion", dns,
    ["H01-RACE-DNS-WRITE-EVENT", "H01-SOURCE-DNS-UPDATE"],
    (s) => replaceOnce(s,
      "WHERE w.id = workspace_brand_assets.workspace_id\n                     AND w.deleted_at IS NULL\n                     AND lower(d.domain) = lower(workspace_brand_assets.domain)",
      "WHERE w.id = workspace_brand_assets.workspace_id\n                     AND lower(d.domain) = lower(workspace_brand_assets.domain)")),
  M("DNS scheduled selector admits deleted workspace", dns,
    ["H01-DELETED-DNS-SCHEDULE", "H01-SOURCE-DNS-SWEEP"],
    (s) => replaceInSection(s, "export async function runBrandDnsEnrichmentSweep", "return { workspaces:", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("DNS event domain read admits deleted workspace", dns,
    ["H01-RACE-DNS-EVENT-DOMAIN-READ", "H01-SOURCE-DNS-EVENT-READ"],
    (s) => replaceInSection(s, "async function fireResolvingAssetEvent", "const evType", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("DNS event insert writes after deletion", dns,
    ["H01-RACE-DNS-EVENT-INSERT", "H01-SOURCE-DNS-EVENT-INSERT"],
    (s) => replaceInSection(s, "INSERT OR IGNORE INTO asset_events", ").bind(", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("HTTP candidate selection probes deleted workspace", http,
    ["H01-DELETED-HTTP-MANUAL", "H01-SOURCE-HTTP-SELECT"],
    (s) => replaceInSection(s, "export function selectBrandHttpCandidatesSql", "function parseJsonArray", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("HTTP candidate update writes after deletion", http,
    ["H01-RACE-HTTP-WRITE", "H01-SOURCE-HTTP-UPDATE"],
    (s) => replaceInSection(s, "export async function enrichBrandCandidatesHttp", "export async function runBrandHttpEnrichmentSweep", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("HTTP scheduled selector admits deleted workspace", http,
    ["H01-DELETED-HTTP-SCHEDULE", "H01-SOURCE-HTTP-SWEEP"],
    (s) => replaceInSection(s, "export async function runBrandHttpEnrichmentSweep", "const all =", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("profile loader returns deleted workspace profile", protection,
    ["H01-DELETED-PROFILE-READ", "H01-SOURCE-PROFILE-READ"],
    (s) => replaceInSection(s, "export async function loadWorkspaceBrandProfile", "if (persisted)", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("Brand case candidate reads lose active authority", cases,
    ["H01-SOURCE-CASE-READS"],
    (s) => replaceInSection(s, "async function candidateForCase", "function bundleRowToApi", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("Brand case candidate updates lose active authority", cases,
    ["H01-SOURCE-CASE-UPDATES"],
    (s) => {
      const start = s.indexOf("async function updateCandidateClassification");
      const end = s.indexOf("export async function reviewBrandCase", start);
      const section = s.slice(start, end);
      if ((section.match(/AND w\.deleted_at IS NULL/g) || []).length !== 2) {
        throw new Error("expected two case-update active guards");
      }
      return s.slice(0, start) + section.replaceAll("AND w.deleted_at IS NULL", "AND 1 = 1") + s.slice(end);
    }),
  M("Brand case insert writes after deletion", cases,
    ["H01-RACE-CASE-INSERT", "H01-SOURCE-CASE-INSERT"],
    (s) => replaceInSection(s, "INSERT INTO managed_cases", "const row = await getBrandCase",
      "ON w.id = a.workspace_id AND w.deleted_at IS NULL",
      "ON w.id = a.workspace_id")),
  M("profile route upsert writes after deletion", routes,
    ["H01-RACE-PROFILE-WRITE", "H01-SOURCE-ROUTE-PROFILE-WRITE"],
    (s) => replaceOnce(s,
      "WHERE w.id = ? AND w.deleted_at IS NULL\n                                AND lower(d.domain) = lower(?)",
      "WHERE w.id = ?\n                                AND lower(d.domain) = lower(?)")),
  M("classification route update writes after deletion", routes,
    ["H01-SOURCE-ROUTE-CLASSIFICATION-WRITE"],
    (s) => replaceInSection(s, "// POST /brand/candidates/:id/classify", "return json({ error: \"Method not allowed\"", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("legacy refresh insert writes after deletion", routes,
    ["H01-SOURCE-ROUTE-LEGACY-INSERT"],
    (s) => replaceInSection(s, "`WITH candidate", "} catch { /* non-fatal */ }", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("route profile links lose active authority", routes,
    ["H01-SOURCE-ROUTE-PROFILE-LINKS"],
    (s) => replaceInSection(s, "SET brand_profile_id = ?", "const row = await env.cybermeters_db", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("domain-removal candidate update writes after deletion", workspaces,
    ["H01-SOURCE-DOMAIN-REMOVAL-WRITE"],
    (s) => replaceInSection(s, "UPDATE workspace_brand_assets", ".bind(workspaceId, domainRow.domain)", "AND w.deleted_at IS NULL", "AND 1 = 1")),
  M("canonical audit writer inserts for deleted workspace", events,
    ["H01-DELETED-AUDIT-EVENT", "H01-SOURCE-AUDIT-GUARD"],
    (s) => replaceInSection(s, "const sql = active_workspace_required", ": `INSERT INTO audit_events", "WHERE w.id = ? AND w.deleted_at IS NULL", "WHERE w.id = ?")),
]);

let passed = 0;
let failed = 0;
function check(name, condition, detail = "") {
  if (condition) passed++;
  else { failed++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}

function runValidator(repo) {
  return spawnSync(process.execPath, [path.join(repo, validator)], {
    cwd: repo,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
  });
}

function failIds(output) {
  return [...String(output).matchAll(/^FAIL (H01-[A-Z0-9-]+)/gm)]
    .map((match) => match[1]).sort();
}

const targetPaths = [...new Set(MUTANTS.map((mutant) => mutant.file))];
const before = new Map(targetPaths.map((relative) => {
  const bytes = fs.readFileSync(path.join(root, relative));
  return [relative, sha256(bytes)];
}));

check("mutant table count is exact", MUTANTS.length === EXPECTED_MUTANTS,
  `got ${MUTANTS.length} want ${EXPECTED_MUTANTS}`);
const baseline = runValidator(root);
check("unmutated baseline is green", baseline.status === 0 && baseline.signal === null &&
  !/^(FAIL|SyntaxError|Error)/m.test(`${baseline.stdout}\n${baseline.stderr}`),
  `${baseline.stdout}\n${baseline.stderr}`.trim());

for (const mutant of MUTANTS) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cm-brand-h01-mutant-"));
  let exact = false;
  let detail = "";
  try {
    const workerRoot = path.join(temp, "workers", "scan-api");
    fs.mkdirSync(path.join(temp, "scripts"), { recursive: true });
    fs.mkdirSync(workerRoot, { recursive: true });
    fs.cpSync(path.join(root, "workers", "scan-api", "src"), path.join(workerRoot, "src"), { recursive: true });
    fs.cpSync(path.join(root, "shared"), path.join(temp, "shared"), { recursive: true });
    fs.copyFileSync(path.join(root, validator), path.join(temp, validator));
    fs.symlinkSync(path.join(root, "workers", "scan-api", "node_modules"),
      path.join(workerRoot, "node_modules"), "dir");

    const target = path.join(temp, mutant.file);
    const original = fs.readFileSync(target, "utf8");
    const mutated = mutant.mutate(original);
    if (mutated === original) throw new Error("mutation did not change target bytes");
    fs.writeFileSync(target, mutated);

    const result = runValidator(temp);
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    const got = failIds(output);
    const want = [...mutant.expectedFailures].sort();
    const problems = [];
    if (result.error) problems.push(`spawn ${result.error.message}`);
    if (result.signal !== null) problems.push(`signal ${result.signal}`);
    if (result.status !== 1) problems.push(`exit ${result.status}, want 1`);
    if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module/.test(output)) problems.push("syntax/load failure");
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      problems.push(`FAIL set ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
    exact = problems.length === 0;
    detail = problems.length ? `${problems.join("; ")}\n${output.trim()}` : want.join(", ");
  } catch (error) {
    detail = error?.stack || error?.message || String(error);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  check(`mutant ${mutant.name} killed for exact reason`, exact, detail);
}

check("source target bytes remain restored", targetPaths.every((relative) =>
  sha256(fs.readFileSync(path.join(root, relative))) === before.get(relative)));
check("mutation assertion count is exact", passed + failed + 1 === EXPECTED_ASSERTIONS,
  `got ${passed + failed + 1} want ${EXPECTED_ASSERTIONS}`);

console.log(`\nBrand H-01 mutations: ${passed}/${passed + failed} assertions; ${MUTANTS.length} exact mutants`);
if (failed || passed + failed !== EXPECTED_ASSERTIONS) process.exit(1);
console.log("Brand H-01 mutation validation passed");
