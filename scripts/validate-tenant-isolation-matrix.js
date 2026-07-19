#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-tenant-isolation-matrix.js  (CI-blocking)
//
// Asserts the tenant-isolation invariant matrix is complete and honest:
//   1. every D1 table in the schema is assigned to exactly one resource class
//      (a new table cannot be silently un-triaged for tenancy);
//   2. every non-infra table resolves to a concrete ownership model + column
//      that actually exists in the schema (no fictional ownership);
//   3. the committed matrix JSON matches a fresh rebuild (drift gate);
//   4. every class that CLAIMS dynamic-harness coverage is genuinely exercised
//      by the two-tenant harness source (anti-tautology — a class cannot assert
//      coverage it does not have).
//
// Exits non-zero on any failure.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { extractTables, deriveOwnership, tableClassIndex, RESOURCE_CLASSES, INVARIANTS, REPO_ROOT } from "./security/lib/tenant-resources.js";
import { buildMatrix } from "./security/build-tenant-isolation-matrix.js";

let failed = 0;
const fail = (m) => { failed++; console.error("  ✗ " + m); };

// Markers a class's dynamic-harness coverage must be backed by. Any one present
// in the harness source proves the class's read/write path is exercised.
const HARNESS_MARKERS = {
  workspaces: ["/api/workspaces/ws1"], workspace_memberships: ["/members"],
  invitations: ["/invitations"], domains: ["/domains"], scans: ["scan_ws1"],
  assets: ["/assets"], findings: ["/report"], reports_snapshots: ["report-snapshots", "/snapshot"],
  managed_cases: ["/managed-cases", "/cases"], notifications: ["/notifications"],
  certificates: ["/certificates"], brand: ["/brand/"], shadow_it: ["/shadow-it"],
  posture_state: ["/scorecard", "/business-risk", "/maturity"], subscriptions: ["/subscription"],
  audit_log: ["/audit-events"], identity_exposure: ["/identity"],
  reports_snapshots_alt: ["/report-snapshots"],
};

const HARNESS_FILES = ["scripts/validate-tenant-isolation.js", "scripts/validate-tenant-isolation-extended.js"]
  .map((p) => path.join(REPO_ROOT, p)).filter((p) => fs.existsSync(p));
const harnessSrc = HARNESS_FILES.map((f) => fs.readFileSync(f, "utf8")).join("\n");

// ── 1 + 2: completeness & ownership ──────────────────────────────────────────
let idx;
try { idx = tableClassIndex(); } catch (e) { fail(e.message); idx = new Map(); }
const tables = extractTables();
for (const t of Object.keys(tables).sort()) {
  if (!idx.has(t)) fail(`table ${t} is NOT assigned to any resource class — triage its tenancy and add it to RESOURCE_CLASSES`);
}
for (const rc of RESOURCE_CLASSES) {
  for (const t of rc.tables) {
    if (!tables[t]) { fail(`class ${rc.class} references table ${t} which is not in the schema`); continue; }
    const o = deriveOwnership(t, tables[t]);
    if (!rc.non_tenant && (o.model === "UNCLASSIFIED")) fail(`table ${t} (class ${rc.class}) has no resolvable ownership column`);
    if (o.column && !tables[t].has(o.column) && o.model !== "identity_root") fail(`table ${t} ownership column ${o.column} absent from schema`);
  }
}
if (INVARIANTS.length !== 12) fail(`expected 12 invariants, found ${INVARIANTS.length}`);

// ── 3: drift gate ────────────────────────────────────────────────────────────
const jsonPath = path.join(REPO_ROOT, "scripts", "security", "tenant-isolation-matrix.json");
if (!fs.existsSync(jsonPath)) fail(`${jsonPath} missing — run node scripts/security/build-tenant-isolation-matrix.js`);
else {
  const committed = fs.readFileSync(jsonPath, "utf8");
  const fresh = JSON.stringify(buildMatrix(), null, 2) + "\n";
  if (committed !== fresh) fail("committed tenant-isolation-matrix.json is stale — re-run the builder and commit");
}

// ── 4: harness cross-reference (anti-tautology) ──────────────────────────────
for (const rc of RESOURCE_CLASSES) {
  if (!rc.harness) continue;
  const markers = HARNESS_MARKERS[rc.class];
  if (!markers) { fail(`class ${rc.class} claims harness coverage but has no marker mapping in the validator`); continue; }
  if (!markers.some((mk) => harnessSrc.includes(mk))) {
    fail(`class ${rc.class} claims dynamic-harness coverage, but none of its markers [${markers.join(", ")}] appear in the harness source`);
  }
}

// ── Report ───────────────────────────────────────────────────────────────────
const m = buildMatrix();
console.log("Tenant-isolation matrix:");
console.log(`  tables: ${m.counts.schema_tables}  classified: ${m.counts.classified}  unclassified: ${m.counts.unclassified}`);
console.log(`  tenant-owned: ${m.counts.tenant_owned_tables}  infra/identity: ${m.counts.infra_or_identity_tables}  classes: ${m.counts.resource_classes}`);
console.log(`  classes with dynamic-harness coverage: ${m.counts.classes_with_dynamic_coverage}`);
if (failed) { console.error(`\ntenant-isolation matrix validation FAILED (${failed}).`); process.exit(1); }
console.log("tenant-isolation matrix validation passed");
