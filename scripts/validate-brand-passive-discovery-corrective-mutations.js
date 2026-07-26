#!/usr/bin/env node
//
// Item 8 PR-D load-bearing mutation harness. Each mutant runs the full DB-backed
// corrective validator in an isolated temporary source tree and must go RED.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validatorName = "validate-brand-passive-discovery-corrective.js";
const mutations = [
  {
    name: "B1 evidence merge removed",
    file: "workers/scan-api/src/engines/asset-persistence.js",
    from: "const evidence = mergeBrandCandidateEvidence(existing?.evidence_json, observation.evidence);",
    to: "const evidence = safeJsonArray(observation.evidence);",
  },
  {
    name: "B1 customer classification overwritten",
    file: "workers/scan-api/src/engines/asset-persistence.js",
    from: "SET variant_type = ?, similarity_score = ?, risk_level = ?,",
    to: "SET classification = 'unreviewed', variant_type = ?, similarity_score = ?, risk_level = ?,",
  },
  {
    name: "B1 Unicode/A-label filter dedupe removed",
    file: "workers/scan-api/src/engines/brand-passive-discovery.js",
    from: "if (seen.has(fqdn)) continue;",
    to: "if (false) continue;",
  },
  {
    name: "B1 monotonic last_seen refresh removed",
    file: "workers/scan-api/src/engines/asset-persistence.js",
    from: "last_seen: latestIso(existing?.last_seen, now),",
    to: "last_seen: existing?.last_seen || now,",
  },
  {
    name: "B2b deleted_at scheduler gate removed",
    file: "workers/scan-api/src/engines/brand-passive-discovery.js",
    from: "JOIN workspaces w ON w.id = a.workspace_id AND w.deleted_at IS NULL",
    to: "JOIN workspaces w ON w.id = a.workspace_id",
  },
  {
    name: "B2a authentication gate removed",
    file: "workers/scan-api/src/routes/brand.js",
    from: 'if (!user) return json({ error: "Unauthorized" }, 401);',
    to: 'if (false) return json({ error: "Unauthorized" }, 401);',
  },
  {
    name: "B2a tenant membership gate removed",
    file: "workers/scan-api/src/routes/brand.js",
    from: 'if (!access) return json({ error: "Forbidden" }, 403);',
    to: 'if (false) return json({ error: "Forbidden" }, 403);',
  },
  {
    name: "B2a active-workspace route gate removed",
    file: "workers/scan-api/src/routes/brand.js",
    from: "SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL LIMIT 1",
    to: "SELECT id FROM workspaces WHERE id = ? LIMIT 1",
  },
  {
    name: "B2a CT query fan-out cap widened",
    file: "workers/scan-api/src/engines/brand-passive-discovery.js",
    from: "export const BRAND_CT_QUERY_CAP          = 4;",
    to: "export const BRAND_CT_QUERY_CAP          = 40;",
  },
  {
    name: "B2a CT response-byte cap widened",
    file: "workers/scan-api/src/engines/brand-passive-discovery.js",
    from: "export const BRAND_CT_RESPONSE_MAX_BYTES = 1_000_000;",
    to: "export const BRAND_CT_RESPONSE_MAX_BYTES = 10_000_000;",
  },
  {
    name: "B2a atomic concurrency claim removed",
    file: "workers/scan-api/src/routes/brand.js",
    from: "{ failClosed: true, atomic: true },",
    to: "{ failClosed: true, atomic: false },",
  },
  {
    name: "B2a total upstream failure rendered as success",
    file: "workers/scan-api/src/routes/brand.js",
    from: "if (stats.queries_succeeded === 0 && stats.query_failures > 0) {",
    to: "if (false) {",
  },
];

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

for (const mutation of mutations) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cm-item8-prd-mutant-"));
  try {
    const workerRoot = path.join(temp, "workers", "scan-api");
    fs.mkdirSync(path.join(temp, "scripts"), { recursive: true });
    fs.mkdirSync(workerRoot, { recursive: true });
    fs.cpSync(path.join(root, "workers", "scan-api", "src"), path.join(workerRoot, "src"), { recursive: true });
    fs.copyFileSync(path.join(root, "scripts", validatorName), path.join(temp, "scripts", validatorName));
    fs.symlinkSync(path.join(root, "workers", "scan-api", "node_modules"),
      path.join(workerRoot, "node_modules"), "dir");

    const target = path.join(temp, mutation.file);
    const source = fs.readFileSync(target, "utf8");
    ok(`${mutation.name}: mutation anchor exists`, source.includes(mutation.from));
    if (!source.includes(mutation.from)) continue;
    fs.writeFileSync(target, source.replace(mutation.from, mutation.to));

    const result = spawnSync(process.execPath, [path.join(temp, "scripts", validatorName)], {
      cwd: temp,
      encoding: "utf8",
      timeout: 30_000,
    });
    ok(`${mutation.name}: mutant is killed`, result.status !== 0,
      `status=${result.status}; stdout=${result.stdout}; stderr=${result.stderr}`);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

console.log(`\nBrand passive discovery PR-D mutations: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand passive discovery PR-D mutation validation passed");
