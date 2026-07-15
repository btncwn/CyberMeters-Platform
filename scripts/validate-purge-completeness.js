#!/usr/bin/env node
//
// Purge-completeness regression: hard-deleting a workspace must remove ALL of its
// rows across every purge table AND its R2 objects, and must NOT touch another
// workspace's data. Guards the orphaned-row class (a table added to the schema
// but forgotten in WORKSPACE_PURGE_TABLES would leave a tenant's data behind).
// CI-blocking. Requires Node 24+ (node:sqlite).
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const mod = await import(pathToFileURL(workerPath).href);
const { purgeWorkspaceData, WORKSPACE_PURGE_TABLES, SCAN_CHILD_TABLES } = mod;

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
  apply(path.join(root, "database", "migrations", f));
}
// Seeding tests the purge's DELETE completeness, not FK integrity — disable FK
// enforcement so a row can be seeded in any table without materialising its
// whole parent chain. (The purge itself deletes scan children before scans.)
db.exec("PRAGMA foreign_keys = OFF");

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async () => db.prepare(sql).get(...args) ?? null,
    all:   async () => ({ results: db.prepare(sql).all(...args) }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

// R2 stub that records which keys were deleted.
const deletedKeys = [];
const r2 = { get: async () => null, put: async () => ({}), head: async () => null,
  delete: async (k) => { deletedKeys.push(k); }, list: async () => ({ objects: [] }) };
const env = { cybermeters_db: makeD1(db), cybermeters_reports: r2 };

// Generic row seeder: reads the table's columns and fills workspace_id + a
// UNIQUE dummy for every NOT NULL / PK column so any purge table can be seeded
// blindly. Dummies are unique per (table, column, workspace) so UNIQUE
// constraints (e.g. lifecycle_email_events.dedupe_key) don't collide when the
// same table is seeded for two workspaces.
let _seq = 0;
function seedRow(table, workspaceId, extra = {}) {
  let cols;
  try { cols = db.prepare(`PRAGMA table_info(${table})`).all(); } catch { return false; }
  if (!cols.length) return false;
  const uniq = `${table.slice(0, 6)}_${workspaceId}_${++_seq}`;
  const vals = {};
  for (const c of cols) {
    if (c.name in extra) { vals[c.name] = extra[c.name]; continue; }
    if (c.name === "workspace_id") { vals[c.name] = workspaceId; continue; }
    if (c.pk) { if (/INT/i.test(c.type)) continue; vals[c.name] = uniq; continue; }
    if (c.dflt_value != null) continue;
    if (c.notnull) vals[c.name] = /INT|REAL|NUM/i.test(c.type) ? (++_seq) : `${c.name.slice(0, 6)}_${uniq}`;
  }
  const keys = Object.keys(vals);
  try { db.prepare(`INSERT INTO ${table} (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => vals[k])); return true; }
  catch (e) { if (process.env.PURGE_DEBUG) console.error(`  seed ${table}: ${e.message.slice(0, 80)}`); return false; }
}

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
const countWs = (table, ws) => { try { return db.prepare(`SELECT COUNT(*) c FROM ${table} WHERE workspace_id = ?`).get(ws).c; } catch { return -1; } };

// ── The list must be derived from the SCHEMA, not from itself ───────────────
// Everything below this block seeds rows by iterating WORKSPACE_PURGE_TABLES —
// so it can only ever prove that the list purges the tables on the list. A table
// forgotten from the list was never seeded and never counted, and the suite
// stayed green. That is not a hypothetical: `cyber_essentials_answers` survived
// every workspace purge for the whole life of the table while this file reported
// 10/10, and index.js carried a comment claiming a test named
// `purge_covers_all_workspace_fk_tables` kept the list in sync. That test never
// existed — the name appeared nowhere in the repository.
//
// So: ask the real schema which tables hold a workspace_id, and require each one
// to be either purged or EXPLICITLY excepted with a reason. A new tenant-scoped
// table now fails CI until someone decides which it is.
const EXPECTED_NOT_PURGED = {
  // Purged by purgeWorkspaceData itself, ahead of the table loop, because their
  // R2 objects must be deleted first.
  scans: "purged directly by purgeWorkspaceData (with its R2 report objects)",
  workspace_reports: "purged directly by purgeWorkspaceData (with its R2 objects)",
  // Deliberately retained — see DELETION_PURGE_WINDOW_DAYS in index.js.
  audit_events: "retained: audit history",
  subscriptions: "retained: accounting",
  deletion_requests: "retained: the record of the deletion request itself",
};
{
  const allTables = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
  ).all().map((r) => r.name);
  const tenantScoped = allTables.filter((t) => {
    try { return db.prepare(`PRAGMA table_info(${t})`).all().some((c) => c.name === "workspace_id"); }
    catch { return false; }
  });
  ok("the schema really does expose tenant-scoped tables (the discovery is not vacuous)",
     tenantScoped.length >= 40);

  const listed = new Set(WORKSPACE_PURGE_TABLES);
  const unaccounted = tenantScoped.filter((t) => !listed.has(t) && !(t in EXPECTED_NOT_PURGED));
  ok("every workspace_id-bearing table is either purged or explicitly excepted",
     unaccounted.length === 0);
  if (unaccounted.length) {
    console.log("  NOT PURGED and NOT excepted (tenant data would outlive the workspace):");
    for (const t of unaccounted) console.log(`    ✗ ${t}`);
  }

  // The exception list must not rot into a dumping ground: every entry has to name
  // a table that still exists and still carries workspace_id.
  for (const [t, why] of Object.entries(EXPECTED_NOT_PURGED)) {
    ok(`exception '${t}' still refers to a real tenant-scoped table (${why})`, tenantScoped.includes(t));
  }

  // The specific regression. Named, so a future rewrite of the loop above cannot
  // quietly drop it.
  ok("cyber_essentials_answers is purged (customer notes + answered_by are customer data)",
     listed.has("cyber_essentials_answers"));
}

// Seed two workspaces with a row in every purge table + reports + a scan (+child).
const seeded = [];
// A few tables have CHECK constraints on a column — give them a valid value.
const EXTRA = { workspace_alert_channels: { channel_type: "webhook" } };
for (const t of WORKSPACE_PURGE_TABLES) { const e = EXTRA[t] || {}; if (seedRow(t, "wsPurge", e)) seeded.push(t); seedRow(t, "wsKeep", e); }
seedRow("workspace_reports", "wsPurge", { report_key: "reports/exec-wsPurge.pdf" });
seedRow("workspace_reports", "wsKeep",  { report_key: "reports/exec-wsKeep.pdf" });
seedRow("scans", "wsPurge", { id: "scan_wsPurge" });
seedRow("scans", "wsKeep",  { id: "scan_wsKeep" });
for (const c of SCAN_CHILD_TABLES) { seedRow(c, "wsPurge", { scan_id: "scan_wsPurge" }); }

ok("seeded a meaningful number of purge tables (>= 20)", seeded.length >= 20);

// Run the purge to completion (it is batched: returns {done:false} until reports
// and scans are drained, then {done:true} after clearing the purge tables).
let guard = 0, res;
do { res = await purgeWorkspaceData(env, "wsPurge"); } while (res && res.done === false && ++guard < 50);
ok("purge reached completion (done:true) within the batch cap", res?.done === true);

// Every purge table must now have ZERO rows for wsPurge.
let orphanTables = [];
for (const t of seeded) { if (countWs(t, "wsPurge") !== 0) orphanTables.push(t); }
ok("no orphaned rows remain in any purge table for the purged workspace",
   orphanTables.length === 0);
if (orphanTables.length) console.log("  orphaned:", orphanTables.join(", "));

ok("workspace_reports fully purged", countWs("workspace_reports", "wsPurge") === 0);
ok("scans fully purged", (db.prepare("SELECT COUNT(*) c FROM scans WHERE workspace_id=?").get("wsPurge").c) === 0);

// R2 objects deleted for both the exec report and the scan json.
ok("R2 exec report object deleted", deletedKeys.includes("reports/exec-wsPurge.pdf"));
ok("R2 scan json object deleted", deletedKeys.includes("reports/scan_wsPurge.json"));

// The OTHER workspace is untouched — purge must never over-delete.
let bled = [];
for (const t of seeded) { if (countWs(t, "wsKeep") === 0) bled.push(t); }
ok("the other workspace's rows all survive (no over-deletion)", bled.length === 0);
if (bled.length) console.log("  over-deleted:", bled.join(", "));
ok("other workspace's report + scan survive",
   countWs("workspace_reports", "wsKeep") === 1 &&
   db.prepare("SELECT COUNT(*) c FROM scans WHERE workspace_id=?").get("wsKeep").c === 1);
ok("R2 did not delete the other workspace's objects",
   !deletedKeys.includes("reports/exec-wsKeep.pdf") && !deletedKeys.includes("reports/scan_wsKeep.json"));

console.log(`\nPurge completeness: ${pass}/${pass + fail} passed`);
if (fail) { console.error("purge-completeness validation FAILED"); process.exit(1); }
console.log("purge-completeness validation passed");
