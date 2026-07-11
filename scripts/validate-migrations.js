#!/usr/bin/env node
//
// Migration validation: (1) every migration applies cleanly to a fresh database
// (schema + all migrations converge), and (2) no migration contains an
// EXECUTABLE destructive statement (DROP TABLE / DROP COLUMN / DELETE FROM /
// TRUNCATE) outside a SQL comment. Additive-only migrations are the rule — a
// destructive one needs explicit human approval, not a silent merge.
// CI-blocking. Requires Node 24+ (node:sqlite).
//
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
for (const f of files) {
  const raw = fs.readFileSync(path.join(migDir, f), "utf8");
  const noComments = raw
    .replace(/--[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  const hit = noComments.match(DESTRUCTIVE);
  ok(`${f}: no executable destructive statement`, !hit);
  if (hit) console.log(`  → found: ${hit[0]}`);
}

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

console.log(`\nMigrations (${files.length} files): ${pass}/${pass + fail} passed`);
if (fail) { console.error("migration validation FAILED"); process.exit(1); }
console.log("migration validation passed");
