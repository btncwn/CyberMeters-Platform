#!/usr/bin/env node
//
// Migration validation: (1) every migration applies cleanly to a fresh database
// (schema + all migrations converge), and (2) no migration contains an
// EXECUTABLE destructive statement (DROP TABLE / DROP COLUMN / DELETE FROM /
// TRUNCATE) outside a SQL comment. Additive-only migrations are the rule — a
// destructive one needs explicit human approval, not a silent merge.
// CI-blocking. Requires Node 24+ (node:sqlite).
//
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const migDir = path.join(root, "database", "migrations");
const files = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql")).sort();

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── 1. Destructive-statement scan (ignoring comments) ──
// Strip line comments (-- …) and block comments (/* … */), then look for
// executable destructive DDL/DML. DROP INDEX and DROP … IF EXISTS on a temp are
// not data-destroying and are allowed.
const DESTRUCTIVE = /\b(DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM|TRUNCATE)\b/i;
const APPROVED_DESTRUCTIVE_MIGRATIONS = new Map([
  ["105-ct-platform-deadline-provenance.sql", {
    sha256: "f3a95b2ec0af4246b09a88c7d4e4e1326cbd0892d01614a45c2df26569632d0d",
    reason: "founder-gated, copy-guarded SQLite table rebuild; remote carrier rollback proven at six injected boundaries",
  }],
]);
const approvedDestructiveMigration = (filename, raw) => {
  const approval = APPROVED_DESTRUCTIVE_MIGRATIONS.get(filename);
  if (!approval) return false;
  return crypto.createHash("sha256").update(raw).digest("hex") === approval.sha256;
};
for (const f of files) {
  const raw = fs.readFileSync(path.join(migDir, f), "utf8");
  const noComments = raw
    .replace(/--[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  const hit = noComments.match(DESTRUCTIVE);
  const approved = Boolean(hit) && approvedDestructiveMigration(f, raw);
  ok(`${f}: no unapproved executable destructive statement`, !hit || approved);
  if (hit && !approved) console.log(`  → found: ${hit[0]}`);
}

// Mutation-style fail-closed controls for the one governed rebuild. Approval is
// bound to both identity and exact bytes: appending another DROP, altering any
// rebuild statement, or copying the same SQL under another migration number
// must not inherit the exception.
const governedFilename = "105-ct-platform-deadline-provenance.sql";
const governedRaw = fs.readFileSync(path.join(migDir, governedFilename), "utf8");
ok("governed rebuild approval matches the frozen migration bytes",
  approvedDestructiveMigration(governedFilename, governedRaw));
ok("governed rebuild approval rejects an appended destructive statement",
  !approvedDestructiveMigration(governedFilename, `${governedRaw}\nDROP TABLE unrelated_customer_history;\n`));
ok("governed rebuild approval does not transfer to another migration identity",
  !approvedDestructiveMigration("106-unrelated.sql", governedRaw));

// ── 2. Fresh-apply convergence ──
// schema.sql + every migration in order must apply so the resulting database has
// the core tables. Individual `IF NOT EXISTS`/ordering no-ops are tolerated (as
// in the app's own startup), but the end state must be a usable schema.
const db = new DatabaseSync(":memory:");
let applyErrors = 0;
const apply = (p, label) => {
  try { db.exec(fs.readFileSync(p, "utf8")); }
  catch (e) {
    // Tolerate idempotency/ordering no-ops — the same classes the app's own
    // startup tolerates when schema.sql (the consolidated current schema) and the
    // historical migrations are both applied: duplicate column/table/index, and
    // "no such table/column" from a migration whose target schema.sql already
    // moved past. The real convergence gate is the core-tables check below.
    if (!/duplicate|already exists|no such (table|column)/i.test(e.message)) { applyErrors++; if (process.env.MIG_DEBUG) console.error(`  apply ${label}: ${e.message.slice(0, 100)}`); }
  }
};
apply(path.join(root, "database", "schema.sql"), "schema.sql");
for (const f of files) apply(path.join(migDir, f), f);
ok("schema + all migrations apply without a hard error", applyErrors === 0);

// Core tables must exist after applying everything.
const CORE = ["users", "user_sessions", "workspaces", "workspace_members", "workspace_domains", "scans", "subscriptions", "audit_events", "notification_events", "stripe_processed_events"];
const present = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name));
for (const t of CORE) ok(`core table exists after migrations: ${t}`, present.has(t));

const scheduledColumns = db.prepare("PRAGMA table_info(scheduled_scans)").all();
const scheduledProjectionColumn = scheduledColumns.find(
  (column) => column.name === "asset_change_projection_json",
);
ok(
  "schema plus migrations converges on the nullable scheduled projection column",
  scheduledProjectionColumn?.type === "TEXT" &&
    scheduledProjectionColumn?.notnull === 0,
);

const findingColumns = db.prepare("PRAGMA table_info(findings)").all();
const findingSlugColumn = findingColumns.find((column) => column.name === "finding_slug");
ok(
  "schema plus migrations converges on the nullable canonical finding identity column",
  findingSlugColumn?.type === "TEXT" && findingSlugColumn?.notnull === 0,
);

// Migration 106 must upgrade an existing scheduled_scans table without rewriting
// legacy counts. This is a real SQLite execution proof, not a source-text check.
const pre106 = new DatabaseSync(":memory:");
pre106.exec(`
  CREATE TABLE scheduled_scans (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    asset_change_count INTEGER DEFAULT 0
  );
  INSERT INTO scheduled_scans (id, domain, asset_change_count)
  VALUES ('sched-sentinel', 'example.com', 7);
`);
pre106.exec(fs.readFileSync(
  path.join(migDir, "106-scheduled-asset-change-projection.sql"),
  "utf8",
));
const upgradedColumns = pre106.prepare("PRAGMA table_info(scheduled_scans)").all();
const upgradedSentinel = pre106.prepare(
  "SELECT asset_change_count, asset_change_projection_json FROM scheduled_scans WHERE id = 'sched-sentinel'",
).get();
ok(
  "migration 106 adds one nullable TEXT column without backfilling legacy rows",
  upgradedColumns.filter(
    (column) => column.name === "asset_change_projection_json",
  ).length === 1 &&
    upgradedColumns.find(
      (column) => column.name === "asset_change_projection_json",
    )?.type === "TEXT" &&
    upgradedSentinel?.asset_change_count === 7 &&
    upgradedSentinel?.asset_change_projection_json === null,
);
pre106.close();

// Migration 107 is forward-only identity storage. Applying it to an existing
// findings table must add one nullable TEXT column while preserving every legacy
// value byte-for-byte and leaving the new identity NULL (no backfill).
const pre107 = new DatabaseSync(":memory:");
const legacyEvidenceBytes = '{"source":"cloudflare_workers_fetch","opaque":"\\u0061","count":1}';
pre107.exec(`
  CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    recommendation TEXT,
    evidence_json TEXT,
    confidence REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);
pre107.prepare(`INSERT INTO findings
  (id, scan_id, severity, title, recommendation, evidence_json, confidence, created_at)
  VALUES ('legacy-sentinel', 'scan-old', 'critical', 'Original title', 'Original recommendation', ?, 0.42, '2026-08-01T01:02:03.000Z')`)
  .run(legacyEvidenceBytes);
const legacyBefore107 = pre107.prepare("SELECT * FROM findings WHERE id='legacy-sentinel'").get();
pre107.exec(fs.readFileSync(
  path.join(migDir, "107-finding-canonical-identity.sql"),
  "utf8",
));
const columns107 = pre107.prepare("PRAGMA table_info(findings)").all();
const legacyAfter107 = pre107.prepare("SELECT * FROM findings WHERE id='legacy-sentinel'").get();
const { finding_slug: legacySlug107, ...legacyComparable107 } = legacyAfter107;
ok(
  "migration 107 adds one nullable TEXT identity without rewriting historical bytes",
  columns107.filter((column) => column.name === "finding_slug").length === 1
    && columns107.find((column) => column.name === "finding_slug")?.type === "TEXT"
    && columns107.find((column) => column.name === "finding_slug")?.notnull === 0
    && legacySlug107 === null
    && JSON.stringify(legacyComparable107) === JSON.stringify(legacyBefore107)
    && legacyAfter107.evidence_json === legacyEvidenceBytes,
);
pre107.close();

// The route-local empty-environment bootstrap is a separate physical schema
// site. Execute the SQL extracted from the source so it cannot silently omit the
// projection column while schema.sql and migration 106 remain green.
const scansRouteSource = fs.readFileSync(
  path.join(root, "workers", "scan-api", "src", "routes", "scans.js"),
  "utf8",
);
const bootstrapMatch = scansRouteSource.match(
  /`(CREATE TABLE IF NOT EXISTS scheduled_scans \([\s\S]*?\n\s*\))`/,
);
const bootstrapDb = new DatabaseSync(":memory:");
if (bootstrapMatch) bootstrapDb.exec(bootstrapMatch[1]);
const bootstrapColumns = bootstrapMatch
  ? bootstrapDb.prepare("PRAGMA table_info(scheduled_scans)").all()
  : [];
ok(
  "scheduled route bootstrap executes with legacy and projection columns",
  bootstrapColumns.some((column) => column.name === "workspace_id") &&
    bootstrapColumns.some((column) => column.name === "asset_change_count") &&
    bootstrapColumns.some(
      (column) => column.name === "asset_change_projection_json" &&
        column.type === "TEXT" && column.notnull === 0,
    ),
);
bootstrapDb.close();

console.log(`\nMigrations (${files.length} files): ${pass}/${pass + fail} passed`);
if (fail) { console.error("migration validation FAILED"); process.exit(1); }
console.log("migration validation passed");
