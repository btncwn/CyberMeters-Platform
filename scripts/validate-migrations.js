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
import { splitStatements, isToleratedStatement } from "./lib/migration-apply-tolerated.js";

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
  ["112-remove-external-breach-provider.sql", {
    sha256: "f52da71bd7e34586bbcc3eea29dae961ee96a78771b6c71e61ae225df59c42f3",
    reason: "Founder explicitly requested complete LeakCheck removal, including test records, before onboarding customers (2026-10-10)",
  }],
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

const removalName = "112-remove-external-breach-provider.sql";
const removalRaw = fs.readFileSync(path.join(migDir, removalName), "utf8");
ok("provider removal approval is restricted to exact migration bytes", approvedDestructiveMigration(removalName, removalRaw));
ok("provider removal approval rejects unrelated deletion", !approvedDestructiveMigration(removalName, removalRaw + "\nDROP TABLE users;"));

// ── 1b. Cloudflare D1 compatibility ──
// Local SQLite accepts statements that remote D1 rejects. Migration 132 applied
// locally and in CI, then failed on D1 with "too many terms in compound SELECT"
// (an eight-term UNION ALL); D1 does not document its compound limit, so
// migrations use one INSERT per row-set instead of any compound SELECT. D1 also
// runs each file in its own transaction and rejects explicit transaction
// control, and caps a single SQL statement at 100,000 bytes (UTF-8):
// https://developers.cloudflare.com/d1/platform/limits/
// The one-term policy below is conservative repository policy, not a published
// numeric D1 compound-SELECT limit.
const D1_MAX_STATEMENT_BYTES = 100_000;
const stripQuoted = (stmt) => stmt
  .replace(/'(?:[^']|'')*'/g, "''")
  .replace(/"(?:[^"]|"")*"/g, '""')
  .replace(/`[^`]*`/g, "``")
  .replace(/\[[^\]]*\]/g, "[]");
// Count each chain independently: nested SELECTs and separate CTEs must not
// inflate a compound chain's term count. Quoted text is already removed.
const maxCompoundSelectTerms = (bare) => {
  const chains = [1];
  let max = 1;
  for (const token of bare.match(/[();]|\b(?:UNION|INTERSECT|EXCEPT)\b/gi) || []) {
    if (token === "(") chains.push(1);
    else if (token === ")") { if (chains.length > 1) chains.pop(); }
    else if (token === ";") chains[chains.length - 1] = 1;
    else max = Math.max(max, ++chains[chains.length - 1]);
  }
  return max;
};
const TRANSACTION_CONTROL = /^\s*(BEGIN(\s+(DEFERRED|IMMEDIATE|EXCLUSIVE))?(\s+TRANSACTION)?|COMMIT(\s+TRANSACTION)?|END(\s+TRANSACTION)?|ROLLBACK\b[\s\S]*|SAVEPOINT\b[\s\S]*|RELEASE\b[\s\S]*)\s*;?\s*$/i;
const d1Problems = (stmt) => {
  const problems = [];
  const bare = stripQuoted(stmt);
  const terms = maxCompoundSelectTerms(bare);
  if (terms > 1) problems.push(`compound SELECT (${terms} terms; repository maximum 1); use one INSERT per row-set`);
  if (TRANSACTION_CONTROL.test(bare)) problems.push("explicit transaction control; D1 wraps each file itself");
  if (Buffer.byteLength(stmt, "utf8") > D1_MAX_STATEMENT_BYTES) problems.push(`statement over ${D1_MAX_STATEMENT_BYTES} bytes`);
  return problems;
};
const d1MigrationProblems = (raw) => splitStatements(raw).flatMap((stmt) =>
  d1Problems(stmt).map((problem) => `${problem} :: ${stmt.replace(/\s+/g, " ").slice(0, 80)}`));
for (const f of files) {
  const raw = fs.readFileSync(path.join(migDir, f), "utf8");
  const found = d1MigrationProblems(raw);
  ok(`${f}: D1-compatible`, found.length === 0);
  for (const line of found) console.log(`  → ${line}`);
}
// Controls: the rules catch what D1 rejected, and do not misfire on valid SQL.
const failing132 = `INSERT OR IGNORE INTO alert_activation
(id, workspace_id, domain_key, activated_at, baseline_count, created_at)
SELECT 'aa_bf132_' || lower(hex(randomblob(16))), w.id, d.domain_key, datetime('now'), 0, datetime('now')
  FROM workspaces w
  CROSS JOIN (
    SELECT 'certificates_trust' AS domain_key
    UNION ALL SELECT 'identity_exposure'
    UNION ALL SELECT 'shadow_it_unmanaged_technology'
    UNION ALL SELECT 'brand_protection'
    UNION ALL SELECT 'attack_surface'
    UNION ALL SELECT 'email_protection'
    UNION ALL SELECT 'website_security'
    UNION ALL SELECT 'cyber_essentials_readiness'
  ) d
 WHERE w.deleted_at IS NULL;`;
const incidentDb = new DatabaseSync(":memory:");
incidentDb.exec(`CREATE TABLE workspaces (id TEXT, deleted_at TEXT);
  CREATE TABLE alert_activation (id TEXT, workspace_id TEXT, domain_key TEXT,
    activated_at TEXT, baseline_count INTEGER, created_at TEXT);
  INSERT INTO workspaces VALUES ('incident-fixture', NULL);`);
incidentDb.exec(failing132);
ok("D1 control: local SQLite accepts the original eight-term migration 132 shape",
  incidentDb.prepare("SELECT COUNT(*) AS n FROM alert_activation").get().n === 8);
incidentDb.close();
ok("D1 control: production validation rejects migration 132 and reports eight terms",
  d1MigrationProblems(failing132).some((problem) => problem.includes("compound SELECT (8 terms;")));
ok("D1 control: separate nested chains count independently",
  maxCompoundSelectTerms("WITH a AS (SELECT 1 UNION SELECT 2), b AS (SELECT 3 EXCEPT SELECT 4) SELECT * FROM a") === 2);
ok("D1 control: a three-term mixed chain is counted",
  maxCompoundSelectTerms("SELECT 1 UNION ALL SELECT 2 INTERSECT SELECT 3") === 3);
ok("D1 control: independent statements reset term counts",
  d1MigrationProblems("SELECT 1 UNION SELECT 2; SELECT 3 UNION SELECT 4;").every((problem) => problem.includes("(2 terms;")));
ok("D1 control: comments and quoted operators are ignored",
  d1MigrationProblems(`-- UNION SELECT 2
    SELECT 'UNION '' INTERSECT', "EXCEPT", [UNION], \`INTERSECT\` /* EXCEPT */;`).length === 0);
ok("D1 control: nested single SELECTs are allowed",
  d1MigrationProblems("SELECT * FROM (SELECT 1) a JOIN (SELECT 2) b;").length === 0);
const statementAtLimit = "SELECT '" + "x".repeat(D1_MAX_STATEMENT_BYTES - 9) + "'";
ok("D1 control: exactly 100,000 UTF-8 bytes is allowed",
  Buffer.byteLength(statementAtLimit, "utf8") === D1_MAX_STATEMENT_BYTES && d1MigrationProblems(statementAtLimit).length === 0);
ok("D1 control: 100,001 UTF-8 bytes is rejected",
  d1MigrationProblems(statementAtLimit.slice(0, -1) + "x'").some((problem) => problem.includes("100000 bytes")));
const multibyteStatement = `SELECT '${"é".repeat(50_000)}'`;
ok("D1 control: statement size counts UTF-8 bytes, not characters",
  multibyteStatement.length < D1_MAX_STATEMENT_BYTES && d1MigrationProblems(multibyteStatement).some((problem) => problem.includes("100000 bytes")));
ok("D1 control: INTERSECT and EXCEPT are rejected", d1Problems("SELECT 1 INTERSECT SELECT 1").length > 0 && d1Problems("SELECT 1 EXCEPT SELECT 2").length > 0);
ok("D1 control: explicit BEGIN TRANSACTION / COMMIT are rejected", d1Problems("BEGIN TRANSACTION").length > 0 && d1Problems("COMMIT").length > 0);
ok("D1 control: an oversized statement is rejected", d1Problems(`INSERT INTO t VALUES ('${"x".repeat(D1_MAX_STATEMENT_BYTES)}')`).length > 0);
ok("D1 control: the word union inside a string literal is allowed", d1Problems("INSERT INTO t (note) VALUES ('trade union member')").length === 0);
ok("D1 control: a trigger body's BEGIN ... END is allowed",
  splitStatements("CREATE TRIGGER trg AFTER INSERT ON t BEGIN UPDATE t SET n = n + 1; END;").every((stmt) => d1Problems(stmt).length === 0));
ok("D1 control: one INSERT per row-set (the 132 fix) is allowed",
  d1Problems("INSERT OR IGNORE INTO alert_activation (id, k) SELECT 'x', 'email_protection' FROM workspaces w WHERE w.deleted_at IS NULL").length === 0);

// ── 2. Fresh-apply convergence ──
// schema.sql + every migration in order must apply so the resulting database has
// the core tables. Individual `IF NOT EXISTS`/ordering no-ops are tolerated (as
// in the app's own startup), but the end state must be a usable schema.
const db = new DatabaseSync(":memory:");
let applyErrors = 0;
const shaHex = (s) => crypto.createHash("sha256").update(s).digest("hex");
// schema.sql is the consolidated current form; it applies as one exec with no self-conflict.
try { db.exec(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8")); }
catch (e) { applyErrors++; if (process.env.MIG_DEBUG) console.error(`  apply schema.sql: ${e.message.slice(0, 100)}`); }
// F-025/F-035 (corrective) — apply each migration STATEMENT-BY-STATEMENT so a tolerated error
// on one statement never skips the rest of the file (the R1 false-green). Tolerance is bound
// to the exact file bytes + the exact failing statement; anything else is a TERMINAL drift.
for (const f of files) {
  const raw = fs.readFileSync(path.join(migDir, f), "utf8");
  const fileSha = shaHex(raw);
  for (const stmt of splitStatements(raw)) {
    try { db.exec(stmt); }
    catch (e) {
      if (!isToleratedStatement(f, fileSha, stmt, e.message)) {
        applyErrors++; if (process.env.MIG_DEBUG) console.error(`  apply ${f}: ${e.message.slice(0, 100)} :: ${stmt.slice(0, 60)}`);
      }
    }
  }
}
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
