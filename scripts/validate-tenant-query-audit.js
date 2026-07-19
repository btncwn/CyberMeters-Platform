#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-tenant-query-audit.js  (CI-blocking)
//
// Runs the static tenant-query audit and enforces:
//   • every HIGH-SIGNAL finding (hostname_only_ownership, global_latest_fallback,
//     r2_key_not_workspace_bound, body_workspace_trust) is either fixed or carries
//     a documented suppression (reason + security contract);
//   • no STALE suppression — a suppression whose fingerprint matches no current
//     finding fails, forcing re-review when a guarded statement changes;
//   • the informational unscoped_tenant_query set is reported (never blocks — those
//     queries are guarded out-of-band, proven by the entry-point inventory + the
//     dynamic two-tenant harness).
//
// Mutation proof: removing `workspace_id = ? AND` from any `WHERE workspace_id = ?
// AND domain = ?` query turns it into a bare `WHERE domain = ?` on a tenant table,
// which the hostname_only_ownership detector flags with no suppression → CI fails.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { auditSql, REPO_ROOT } from "./security/lib/tenant-query-audit.js";

const BLOCKING = new Set(["hostname_only_ownership", "global_latest_fallback", "r2_key_not_workspace_bound", "body_workspace_trust"]);

let failed = 0;
const fail = (m) => { failed++; console.error("  ✗ " + m); };

const supPath = path.join(REPO_ROOT, "scripts", "security", "tenant-query-audit-suppressions.json");
const sup = JSON.parse(fs.readFileSync(supPath, "utf8"));
const supByFp = new Map(sup.suppressions.map((s) => [s.fingerprint, s]));
const usedFp = new Set();

const findings = auditSql();
const blocking = findings.filter((f) => BLOCKING.has(f.detector));
const info = findings.filter((f) => !BLOCKING.has(f.detector));

for (const f of blocking) {
  const s = supByFp.get(f.fingerprint);
  if (!s) fail(`UNSUPPRESSED ${f.detector} [${f.fingerprint}] ${f.file}:${f.line}\n      ${f.sql}\n      → fix it or add a documented suppression to tenant-query-audit-suppressions.json`);
  else usedFp.add(f.fingerprint);
}
// Stale suppressions (fingerprint no longer produced by the audit).
for (const [fp, s] of supByFp) {
  if (!usedFp.has(fp)) fail(`STALE suppression [${fp}] for ${s.file} (${s.detector}) — the guarded statement changed or moved; re-verify and update the fingerprint`);
}

// ── Report ───────────────────────────────────────────────────────────────────
const infoByTable = {};
for (const f of info) for (const t of (f.tables || [])) (infoByTable[t] ??= 0), infoByTable[t]++;
const unsuppressed = blocking.filter((f) => !supByFp.has(f.fingerprint)).length;
console.log("Static tenant-query audit:");
console.log(`  SQL/R2/body findings scanned: ${findings.length}`);
console.log(`  high-signal (blocking) findings: ${blocking.length} across ${usedFp.size} suppressions  unsuppressed: ${unsuppressed}`);
console.log(`  informational unscoped_tenant_query: ${info.filter((f) => f.detector === "unscoped_tenant_query").length} (guarded out-of-band — see FULL-REPO-ASSURANCE.md)`);
if (failed) { console.error(`\nstatic tenant-query audit FAILED (${failed}).`); process.exit(1); }
console.log("static tenant-query audit passed");
