#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-tenant-query-audit.js  (CI-blocking)
//
// Runs the static tenant-query audit and enforces:
//   • every HIGH-SIGNAL finding (hostname_only_ownership,
//     workspace_domain_scope_missing, global_latest_fallback,
//     r2_key_not_workspace_bound, body_workspace_trust) is either fixed or
//     carries a documented suppression (reason + security contract);
//   • no STALE suppression — a suppression whose fingerprint matches no current
//     finding fails, forcing re-review when a guarded statement changes;
//   • the informational unscoped_tenant_query set is reported (never blocks — those
//     queries are guarded out-of-band, proven by the entry-point inventory + the
//     dynamic two-tenant harness).
//
// The load-bearing workspace_domains fixture below proves that the JOIN name
// alone is not scope. The source-level mutation harness then removes only the
// workspace predicate + bind from resolveWorkspaceDomain and proves this
// validator exits non-zero.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { auditSql, hasTenantPredicate, REPO_ROOT } from "./security/lib/tenant-query-audit.js";

const BLOCKING = new Set(["hostname_only_ownership", "workspace_domain_scope_missing", "global_latest_fallback", "r2_key_not_workspace_bound", "body_workspace_trust"]);

let failed = 0;
const fail = (m) => { failed++; console.error("  ✗ " + m); };

const WORKSPACE_DOMAIN_SCOPED_FIXTURE = `SELECT d.id FROM domains d
  JOIN workspace_domains wd ON wd.domain_id = d.id
  WHERE wd.workspace_id = ? AND d.domain = ? LIMIT 1`;
const WORKSPACE_DOMAIN_JOIN_ONLY_FIXTURE = `SELECT d.id FROM domains d
  JOIN workspace_domains wd ON wd.domain_id = d.id
  WHERE d.domain = ? LIMIT 1`;
if (!hasTenantPredicate(WORKSPACE_DOMAIN_SCOPED_FIXTURE)) {
  fail("positive fixture: wd.workspace_id = ? must be recognised as tenant-scoped");
}
if (hasTenantPredicate(WORKSPACE_DOMAIN_JOIN_ONLY_FIXTURE)) {
  fail("negative fixture: JOIN workspace_domains without a workspace predicate must not be recognised as tenant-scoped");
}

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
console.log("  workspace-domain fixtures: scoped predicate accepted; JOIN-only rejected");
console.log(`  SQL/R2/body findings scanned: ${findings.length}`);
console.log(`  high-signal (blocking) findings: ${blocking.length} across ${usedFp.size} suppressions  unsuppressed: ${unsuppressed}`);
console.log(`  informational unscoped_tenant_query: ${info.filter((f) => f.detector === "unscoped_tenant_query").length} (guarded out-of-band — see FULL-REPO-ASSURANCE.md)`);
if (failed) { console.error(`\nstatic tenant-query audit FAILED (${failed}).`); process.exit(1); }
console.log("static tenant-query audit passed");
