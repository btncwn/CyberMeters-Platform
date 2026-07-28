#!/usr/bin/env node
// Load-bearing mutation proof for the workspace-domain tenant-scope contract.
//
// The single mutant preserves JOIN workspace_domains and removes only:
//   1. wd.workspace_id = ? from resolveWorkspaceDomain's WHERE clause; and
//   2. the corresponding workspaceId bind.
//
// Both existing assurance layers must reject it:
//   • validate-tenant-query-audit.js (static predicate proof); and
//   • validate-tenant-isolation.js (real worker/router/auth/D1 oracle proof).
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const TARGET = path.join(ROOT, "workers", "scan-api", "src", "engines", "rua-routing.js");
const EXPECTED_MUTANTS = 1;
const EXPECTED_ASSERTIONS = 8;

const ORIGINAL_ANCHOR = `      .prepare(\`SELECT d.id FROM domains d
                JOIN workspace_domains wd ON wd.domain_id = d.id
                WHERE wd.workspace_id = ? AND d.domain = ? LIMIT 1\`)
      .bind(workspaceId, domain).first();`;
const MUTATED_ANCHOR = `      .prepare(\`SELECT d.id FROM domains d
                JOIN workspace_domains wd ON wd.domain_id = d.id
                WHERE d.domain = ? LIMIT 1\`)
      .bind(domain).first();`;

let assertions = 0;
let mutants = 0;
let staticExit = null;
let routerExit = null;
const check = (condition, message) => {
  assertions++;
  if (!condition) throw new Error(message);
};
const occurrences = (source, needle) => source.split(needle).length - 1;
const run = (script) => spawnSync(process.execPath, [path.join(ROOT, "scripts", script)], {
  cwd: ROOT,
  encoding: "utf8",
  timeout: 120_000,
  env: { ...process.env },
});
const combinedOutput = (result) => `${result.stdout || ""}\n${result.stderr || ""}`;

const original = fs.readFileSync(TARGET, "utf8");
check(
  occurrences(original, ORIGINAL_ANCHOR) === 1,
  "mutation anchor must exist exactly once in resolveWorkspaceDomain",
);
const mutated = original.replace(ORIGINAL_ANCHOR, MUTATED_ANCHOR);
check(mutated !== original, "mutated source must differ from original source");

try {
  fs.writeFileSync(TARGET, mutated);
  check(fs.readFileSync(TARGET, "utf8") === mutated, "mutated source must be written exactly");
  mutants++;

  const staticResult = run("validate-tenant-query-audit.js");
  staticExit = staticResult.status;
  const staticOutput = combinedOutput(staticResult);
  check(staticResult.status !== 0, "static tenant-query audit must reject the workspace-predicate mutant");
  check(
    staticOutput.includes("workspace_domain_scope_missing") &&
      staticOutput.includes("workers/scan-api/src/engines/rua-routing.js"),
    "static failure must identify the unscoped workspace_domains query",
  );

  const routerResult = run("validate-tenant-isolation.js");
  routerExit = routerResult.status;
  const routerOutput = combinedOutput(routerResult);
  check(routerResult.status !== 0, "real router tenant-isolation harness must reject the workspace-predicate mutant");
  check(
    routerOutput.includes("FAIL [Invariant 8 — workspace-domain route has no existence oracle]") &&
      routerOutput.includes("foreign-existing and nonexistent domains have identical sanitised status/body semantics"),
    "router failure must be the foreign-existing versus nonexistent domain oracle",
  );
} finally {
  fs.writeFileSync(TARGET, original);
}

check(fs.readFileSync(TARGET, "utf8") === original, "mutated source must be restored exactly");

if (mutants !== EXPECTED_MUTANTS || assertions !== EXPECTED_ASSERTIONS) {
  throw new Error(
    `mutation pin mismatch: mutants ${mutants}/${EXPECTED_MUTANTS}, assertions ${assertions}/${EXPECTED_ASSERTIONS}`,
  );
}

console.log("Tenant-scope assurance mutations:");
console.log(`  mutants: ${mutants}/${EXPECTED_MUTANTS}`);
console.log(`  assertions: ${assertions}/${EXPECTED_ASSERTIONS}`);
console.log(`  static mutant rejection exit: ${staticExit}`);
console.log(`  router mutant rejection exit: ${routerExit}`);
console.log("tenant-scope assurance mutation validation passed");
