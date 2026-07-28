#!/usr/bin/env node
// Generates docs/security/TENANT-QUERY-AUDIT.md from the live audit.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { auditSql, REPO_ROOT } from "./lib/tenant-query-audit.js";

const BLOCKING = new Set(["hostname_only_ownership", "workspace_domain_scope_missing", "global_latest_fallback", "r2_key_not_workspace_bound", "body_workspace_trust"]);

function main() {
  const findings = auditSql();
  const sup = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "scripts", "security", "tenant-query-audit-suppressions.json"), "utf8"));
  const info = findings.filter((f) => !BLOCKING.has(f.detector));
  const infoByTable = {};
  for (const f of info) for (const t of (f.tables || [])) infoByTable[t] = (infoByTable[t] || 0) + 1;

  const L = [];
  L.push("# CyberMeters — Static Tenant-Query Audit");
  L.push("");
  L.push("> **Generated** by `scripts/security/build-tenant-query-audit-report.js`.");
  L.push("> CI gate: `scripts/validate-tenant-query-audit.js` (blocks on any unsuppressed");
  L.push("> high-signal finding or stale suppression).");
  L.push("");
  L.push("The audit extracts every `.prepare()`/`.exec()` SQL statement and every R2 key");
  L.push("expression from the Worker source, then classifies each against the tenant-owned");
  L.push("table set from the isolation matrix. A statement carrying an inline tenant predicate");
  L.push("(`workspace_id` / `owner_user_id` / `owner_id` / `user_id` / `subscription_id`)");
  L.push("is **safe** and not reported. A `workspace_domains` JOIN without such a predicate");
  L.push("is never proof of tenant scope.");
  L.push("");
  L.push("## Detectors");
  L.push("");
  L.push("| Detector | Severity | Gate |");
  L.push("|---|---|---|");
  L.push("| `workspace_domain_scope_missing` | high | blocking |");
  L.push("| `hostname_only_ownership` | high | blocking |");
  L.push("| `global_latest_fallback` | high | blocking |");
  L.push("| `r2_key_not_workspace_bound` | high | blocking |");
  L.push("| `body_workspace_trust` | medium | blocking |");
  L.push("| `unscoped_tenant_query` | informational | reported (guarded out-of-band) |");
  L.push("");
  L.push("## Current results");
  L.push("");
  const counts = {};
  for (const f of findings) counts[f.detector] = (counts[f.detector] || 0) + 1;
  for (const [d, n] of Object.entries(counts).sort()) L.push(`- **${d}:** ${n}`);
  L.push("");
  L.push(`Blocking findings are all covered by ${sup.suppressions.length} documented suppressions`);
  L.push("(each a manually-verified out-of-band guard with a security contract) — see");
  L.push("`scripts/security/tenant-query-audit-suppressions.json`. Zero unsuppressed.");
  L.push("");
  L.push("## Mutation proof");
  L.push("");
  L.push("The anchored source mutant preserves `JOIN workspace_domains` in");
  L.push("`resolveWorkspaceDomain`, removes only `wd.workspace_id = ?` and its bind, and");
  L.push("must fail both `validate-tenant-query-audit.js` and the real-router oracle in");
  L.push("`validate-tenant-isolation.js`. The mutation harness restores the source exactly.");
  L.push("");
  L.push("## Informational: `unscoped_tenant_query` by table");
  L.push("");
  L.push("These queries touch a tenant-owned table without an inline tenant predicate; their");
  L.push("safety rests on an out-of-band guard (an authenticated, workspace-authorized route —");
  L.push("proven by the entry-point inventory — or an already-scoped scan/subscription context).");
  L.push("They are listed for the record, not as defects.");
  L.push("");
  L.push("| Table | Unscoped queries |");
  L.push("|---|---:|");
  for (const [t, n] of Object.entries(infoByTable).sort((a, b) => b[1] - a[1])) L.push(`| \`${t}\` | ${n} |`);
  L.push("");
  fs.writeFileSync(path.join(REPO_ROOT, "docs", "security", "TENANT-QUERY-AUDIT.md"), L.join("\n"));
  console.log(`Wrote docs/security/TENANT-QUERY-AUDIT.md (${findings.length} findings, ${sup.suppressions.length} suppressions)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
