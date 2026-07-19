#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-production-integrity-sql.js  (CI-blocking)
//
// The production integrity runbook (scripts/security/production-integrity-assertions.sql)
// is executed by the founder against production D1 at the release gate. This gate
// makes sure every query in it is syntactically valid and references only real
// columns, by executing each against a fresh in-memory schema (empty DB → every
// check must return 0 anomalies, and none may error). It never touches production.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { buildDb } from "./security/lib/worker-harness.js";
import { REPO_ROOT } from "./security/lib/tenant-resources.js";

const sqlPath = path.join(REPO_ROOT, "scripts", "security", "production-integrity-assertions.sql");
const raw = fs.readFileSync(sqlPath, "utf8");
// Split on statement terminators, dropping comments/blank lines.
const statements = raw
  .split(/;\s*$/m)
  .map((s) => s.split("\n").filter((l) => !l.trim().startsWith("--")).join("\n").trim())
  .filter((s) => /^select/i.test(s));

const db = buildDb();
let failed = 0, ran = 0;
for (const stmt of statements) {
  try {
    const row = db.prepare(stmt).get();
    if (!row || !("anomalies" in row) || !("check_name" in row)) {
      failed++; console.error(`  ✗ query did not return {check_name, anomalies}: ${stmt.slice(0, 60)}...`);
    } else if (row.anomalies !== 0) {
      // Empty schema → every check must be 0; non-zero means the query logic is wrong.
      failed++; console.error(`  ✗ ${row.check_name} returned ${row.anomalies} on an EMPTY database (query logic error)`);
    } else ran++;
  } catch (e) {
    failed++; console.error(`  ✗ SQL error in check "${(stmt.match(/'([^']+)' AS check_name/) || [])[1] || "?"}": ${e.message}`);
  }
}

console.log("Production integrity runbook (read-only):");
console.log(`  checks validated against in-memory schema: ${ran}/${statements.length}`);
if (failed) { console.error(`\nproduction-integrity SQL validation FAILED (${failed}).`); process.exit(1); }
console.log("production-integrity SQL validation passed (runbook is executable; run against prod at the release gate)");
