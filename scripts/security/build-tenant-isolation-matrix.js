#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// build-tenant-isolation-matrix.js
//
// Emits the canonical tenant-isolation invariant matrix:
//   • scripts/security/tenant-isolation-matrix.json  (machine-readable)
//   • docs/security/TENANT-ISOLATION-MATRIX.md        (readable)
//
// Ownership is derived from the live schema, so the matrix cannot claim a
// column a table does not have. `validate-tenant-isolation-matrix.js` re-checks
// completeness and consistency in CI.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { extractTables, deriveOwnership, RESOURCE_CLASSES, INVARIANTS, tableClassIndex, REPO_ROOT } from "./lib/tenant-resources.js";

export function buildMatrix() {
  const tables = extractTables();
  const idx = tableClassIndex();
  const classes = RESOURCE_CLASSES.map((rc) => {
    const ownership = {};
    for (const t of rc.tables) ownership[t] = tables[t] ? deriveOwnership(t, tables[t]) : { model: "MISSING_TABLE", column: null };
    return {
      class: rc.class, domain: rc.domain, tables: rc.tables, ownership,
      non_tenant: !!rc.non_tenant,
      coverage: { dynamic_harness: !!rc.harness, property_based: !!rc.property, note: rc.coverage_note ?? null },
    };
  });
  const schemaTables = Object.keys(tables).sort();
  const classified = schemaTables.filter((t) => idx.has(t));
  const tenantOwned = classified.filter((t) => {
    const c = RESOURCE_CLASSES.find((rc) => rc.class === idx.get(t));
    return !c.non_tenant;
  });
  return {
    schema: "cybermeters.tenant-isolation-matrix/v1",
    generated_by: "scripts/security/build-tenant-isolation-matrix.js",
    invariants: INVARIANTS,
    resource_classes: classes,
    table_index: Object.fromEntries(schemaTables.map((t) => [t, idx.get(t) ?? null])),
    counts: {
      schema_tables: schemaTables.length,
      classified: classified.length,
      tenant_owned_tables: tenantOwned.length,
      infra_or_identity_tables: classified.length - tenantOwned.length,
      unclassified: schemaTables.length - classified.length,
      resource_classes: classes.length,
      classes_with_dynamic_coverage: classes.filter((c) => c.coverage.dynamic_harness).length,
    },
  };
}

function renderMd(m) {
  const L = [];
  L.push("# CyberMeters — Tenant-Isolation Invariant Matrix");
  L.push("");
  L.push("> **Generated** by `scripts/security/build-tenant-isolation-matrix.js` from the live");
  L.push("> schema. CI gate: `scripts/validate-tenant-isolation-matrix.js` fails if any D1 table");
  L.push("> is unclassified, if a declared ownership column is absent from the schema, or if a");
  L.push("> class claims dynamic-harness coverage it does not have.");
  L.push("");
  L.push("Every tenant-owned resource class is bound to a tenant by one of the ownership models");
  L.push("below. A new table that is not assigned to a class fails the gate — so tenancy for new");
  L.push("data cannot be silently omitted.");
  L.push("");
  L.push("## Counts");
  L.push("");
  for (const [k, v] of Object.entries(m.counts)) L.push(`- **${k.replace(/_/g, " ")}:** ${v}`);
  L.push("");
  L.push("## The 12 invariants");
  L.push("");
  for (const inv of m.invariants) L.push(`${inv.id}. ${inv.text}`);
  L.push("");
  L.push("## Resource classes");
  L.push("");
  L.push("| Class | Domain | Ownership | Tables | Dynamic harness | Property |");
  L.push("|---|---|---|---|:---:|:---:|");
  for (const c of m.resource_classes) {
    const models = [...new Set(Object.values(c.ownership).map((o) => `${o.model}${o.column ? `(${o.column})` : ""}`))].join(", ");
    const mark = (b) => (b ? "✓" : "—");
    L.push(`| ${c.class}${c.non_tenant ? " ⁿᵗ" : ""} | ${c.domain} | ${models} | ${c.tables.length} | ${mark(c.coverage.dynamic_harness)} | ${mark(c.coverage.property_based)} |`);
  }
  L.push("");
  L.push("_ⁿᵗ = non-tenant (global infrastructure / identity root)._");
  L.push("");
  L.push("### Coverage notes");
  L.push("");
  for (const c of m.resource_classes.filter((c) => c.coverage.note)) L.push(`- **${c.class}:** ${c.coverage.note}`);
  L.push("");
  L.push("## Table → class index");
  L.push("");
  L.push("| Table | Ownership model | Class |");
  L.push("|---|---|---|");
  const tables = extractTables();
  for (const [t, cls] of Object.entries(m.table_index)) {
    const o = deriveOwnership(t, tables[t]);
    L.push(`| \`${t}\` | ${o.model}${o.column ? `(${o.column})` : ""} | ${cls ?? "**UNCLASSIFIED**"} |`);
  }
  L.push("");
  return L.join("\n");
}

function main() {
  const m = buildMatrix();
  fs.writeFileSync(path.join(REPO_ROOT, "scripts", "security", "tenant-isolation-matrix.json"), JSON.stringify(m, null, 2) + "\n");
  fs.writeFileSync(path.join(REPO_ROOT, "docs", "security", "TENANT-ISOLATION-MATRIX.md"), renderMd(m));
  console.log(`Wrote tenant-isolation matrix: ${m.counts.schema_tables} tables, ${m.counts.resource_classes} classes, ${m.counts.unclassified} unclassified`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
