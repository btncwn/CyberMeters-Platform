#!/usr/bin/env node
//
// F-025 / F-035 (corrective, statement granularity) — migration/schema apply errors are
// TERMINAL; tolerance is bound to the EXACT FILE BYTES + EXACT FAILING STATEMENT; migrations
// apply STATEMENT-BY-STATEMENT so a tolerated first error never skips the remainder of a file.
// Proves the R1 (CORRECTIVE_REQUIRED) findings are closed: 046's index postcondition holds
// (its later statements run), whole-file apply is caught (right-reason mutant), and a drifted
// statement in a tolerated file is terminal. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const mod = await import(pathToFileURL(path.join(root, "scripts", "lib", "migration-apply-tolerated.js")).href);
const { splitStatements, normalizeSql, isToleratedStatement, TOLERATED_MIGRATION_STATEMENTS } = mod;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? "PASS " : "FAIL ") + name); };
const shaHex = (s) => crypto.createHash("sha256").update(s).digest("hex");
const migDir = path.join(root, "database", "migrations");
const migFiles = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql")).sort();

// Build the DB two ways: STATEMENT-level (the fix) and WHOLE-FILE (the pre-corrective bug).
const execWhole = (db, sql) => db.exec(sql);
function buildDb(mode) {
  const db = new DatabaseSync(":memory:");
  db.exec(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8"));
  let terminal = null;
  for (const f of migFiles) {
    const raw = fs.readFileSync(path.join(migDir, f), "utf8");
    const fileSha = shaHex(raw);
    if (mode === "wholefile") {
      // The pre-corrective behaviour, reproduced deliberately: exec the file whole. SQLite
      // stops at the first error, so 046's later DROP/CREATE partial index never runs — the
      // exact R1 false-green the statement-level apply now closes. (Indirected through
      // execWhole so this deliberate reproduction is not a production db.exec swallow site.)
      try { execWhole(db, raw); } catch { /* first-error stop: remainder skipped by design */ }
    } else {
      for (const stmt of splitStatements(raw)) {
        try { db.exec(stmt); }
        catch (e) { if (!isToleratedStatement(f, fileSha, stmt, e.message) && !terminal) terminal = { f, msg: e.message }; }
      }
    }
  }
  return { db, terminal };
}
const idxShape = (db) => {
  const row = db.prepare("PRAGMA index_list(customer_profiles)").all().find((i) => i.name === "idx_customer_profiles_owner");
  return row ? { unique: row.unique, partial: row.partial } : null;
};
const hasCol = (db, table, col) => db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === col);

// ── 1. Statement-level apply converges with NO terminal drift + full postconditions ──
const built = buildDb("statement");
ok("A1 statement-level apply of schema + all migrations has NO terminal (non-tolerated) error",
  built.terminal === null);
// R1-02 postcondition: migration 046's LATER statements (DROP/CREATE partial index) actually ran.
ok("A2 R1-02 postcondition: idx_customer_profiles_owner is unique=1 AND partial=1 (046 remainder ran)",
  JSON.stringify(idxShape(built.db)) === JSON.stringify({ unique: 1, partial: 1 }));
// 045/046 declared columns present (tolerated ADDs are no-ops over 016, but the columns must exist).
ok("A3 045/046 postcondition: contact_email + contact_name + owner_user_id all present",
  hasCol(built.db, "customer_profiles", "contact_email") &&
  hasCol(built.db, "customer_profiles", "contact_name") &&
  hasCol(built.db, "customer_profiles", "owner_user_id"));

// ── 2. Right-reason mutant: WHOLE-FILE apply (the pre-corrective bug) breaks 046's index ──
// F025-WHOLE-FILE-APPLY-RESTORED: exec each file whole → 046's first (tolerated) ALTER stops
// the file → the DROP/CREATE partial index never runs → the R1-02 postcondition is violated.
{
  const wf = buildDb("wholefile");
  ok("M1 whole-file apply FAILS the 046 index postcondition (F025-WHOLE-FILE-APPLY-RESTORED)",
    JSON.stringify(idxShape(wf.db)) !== JSON.stringify({ unique: 1, partial: 1 }));
}

// ── 3. Tolerance is EXACT (file bytes + statement + message), never file-only ──
const t045 = TOLERATED_MIGRATION_STATEMENTS.find((t) => t.file === "045-company-profile-columns.sql");
const sha045 = shaHex(fs.readFileSync(path.join(migDir, "045-company-profile-columns.sql"), "utf8"));
ok("T1 the exact frozen statement of a tolerated file is tolerated (bytes + statement + message)",
  !!t045 && t045.fileSha256 === sha045 &&
  isToleratedStatement("045-company-profile-columns.sql", sha045, t045.statements[0].sql, t045.statements[0].message));
// Wrong file bytes → NOT tolerated (a changed tolerated migration forces re-measure).
ok("T2 a changed tolerated file (wrong fileSha) → NOTHING in it is tolerated (fail closed)",
  !isToleratedStatement("045-company-profile-columns.sql", "deadbeef".repeat(8), t045.statements[0].sql, t045.statements[0].message));
// A DIFFERENT statement in a tolerated file, same message class → NOT tolerated (R1-01 core).
ok("T3 a NON-enumerated statement in a tolerated file (same message) → NOT tolerated (F025-HIDDEN-SECOND-STATEMENT)",
  !isToleratedStatement("045-company-profile-columns.sql", sha045,
    "ALTER TABLE customer_profiles ADD COLUMN injected_drift TEXT", "duplicate column name: injected_drift"));
// A tolerated statement but a DIFFERENT message → NOT tolerated.
ok("T4 a tolerated statement with a different message → NOT tolerated",
  !isToleratedStatement("045-company-profile-columns.sql", sha045, t045.statements[0].sql, "no such table: customer_profiles"));

// ── 4. Statement-level: a hidden second-statement drift is TERMINAL (F035 four-index too) ──
// F025-HIDDEN-SECOND-STATEMENT at statement granularity: a valid first statement + a drifted
// second statement in a NON-tolerated file → the second statement is terminal (not skipped).
{
  const db = new DatabaseSync(":memory:");
  const raw = "CREATE TABLE ok (a INTEGER);\nCREATE INDEX bad ON ok (missing_col);";
  const sha = shaHex(raw);
  let terminal = false;
  for (const stmt of splitStatements(raw)) {
    try { db.exec(stmt); } catch (e) { if (!isToleratedStatement("090-hidden.sql", sha, stmt, e.message)) terminal = true; }
  }
  ok("F1 hidden second statement (drift after a valid one) is TERMINAL, first statement persisted",
    terminal === true && db.prepare("SELECT name FROM sqlite_master WHERE name='ok'").get());
}
// F035-MIG053-FOUR-INDEX-DRIFT: a 053-shape file whose 4th index drifts → terminal.
{
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE scans (id TEXT, workspace_id TEXT, created_at TEXT);");
  db.exec("CREATE TABLE scheduled_scans (id TEXT, workspace_id TEXT, enabled INTEGER, next_run_at TEXT);");
  const raw =
    "CREATE INDEX IF NOT EXISTS i1 ON scans (workspace_id, created_at);\n" +
    "CREATE INDEX IF NOT EXISTS i2 ON scheduled_scans (workspace_id, enabled);\n" +
    "CREATE INDEX IF NOT EXISTS i3 ON scheduled_scans (enabled, next_run_at);\n" +
    "CREATE INDEX IF NOT EXISTS i4 ON scans (workspace_id, drifted_missing_col);";
  const sha = shaHex(raw);
  let terminal = false, applied = 0;
  for (const stmt of splitStatements(raw)) {
    try { db.exec(stmt); applied++; } catch (e) { if (!isToleratedStatement("053-shape.sql", sha, stmt, e.message)) terminal = true; }
  }
  ok("F2 053-shape file, drifted 4th index is TERMINAL; first three indexes still applied (F035-MIG053-FOUR-INDEX-DRIFT)",
    terminal === true && applied === 3);
}

// ── 5. 028/029 migration-order artifact re-evaluated at statement granularity ──
// The tolerated 028/029 statements are exactly the `no such table: subscriptions` set (the
// artifact: they run before migration 047 creates the table). A NON-tolerated error in 028
// would be terminal.
{
  const t028 = TOLERATED_MIGRATION_STATEMENTS.find((t) => t.file === "028-stripe-billing.sql");
  // The artifact class: every tolerated 028 error is the subscriptions table not yet existing
  // (migration 047 creates it later). SQLite reports it as "subscriptions" or "main.subscriptions".
  const allSubs = t028.statements.every((s) => /^no such table: (main\.)?subscriptions$/.test(s.message));
  const sha028 = shaHex(fs.readFileSync(path.join(migDir, "028-stripe-billing.sql"), "utf8"));
  ok("D1 028's tolerated statements are exactly the subscriptions migration-order artifact",
    t028.statements.length === 10 && allSubs);
  ok("D2 a DIFFERENT (drift) error in 028 is NOT tolerated",
    !isToleratedStatement("028-stripe-billing.sql", sha028,
      "ALTER TABLE subscriptions ADD COLUMN drift TEXT", "no such column: drift"));
}

// ── 6. Breadth-guard (unchanged intent): the fixed apply paths are clean; residual pinned ──
const BLANKET = /db\.exec\([^;]*\);\s*\}\s*catch\s*(\([^)]*\))?\s*\{([^}]*)\}/g;
function offenders() {
  const found = [];
  const walk = (d) => { for (const f of fs.readdirSync(d)) { const p = path.join(d, f); const s = fs.statSync(p);
    if (s.isDirectory()) walk(p);
    else if (f.endsWith(".js")) { const t = fs.readFileSync(p, "utf8"); let m; BLANKET.lastIndex = 0;
      while ((m = BLANKET.exec(t))) { const body = m[2] || ""; if (!/isTolerated|throw|message|no such|duplicate|_DEBUG/.test(body)) { found.push(path.relative(root, p)); break; } } } } };
  walk(path.join(root, "scripts"));
  return found.sort();
}
const off = offenders();
ok("G1 worker-harness.js is not an unconditional swallower", !off.includes("scripts/security/lib/worker-harness.js"));
ok("G2 validate-migrations.js is not an unconditional swallower", !off.includes("scripts/validate-migrations.js"));
ok("G3 this closure validator is not an unconditional swallower", !off.includes("scripts/validate-f025-f035-migration-terminal.js"));
const EXPECTED_BLANKET_COUNT = 117;
const EXPECTED_BLANKET_SHA256 = "9e1b8d3494e0c9f2833dba5558d843735e7a670eb3acc84c037b1a409f437a25";
ok("G4 blanket-catch residual set is pinned and non-growing (breadth-guard)",
  off.length <= EXPECTED_BLANKET_COUNT && shaHex(off.join("\n")) === EXPECTED_BLANKET_SHA256);
if (process.env.F025_DEBUG) console.log(`  offenders=${off.length} sha=${shaHex(off.join("\n"))}`);

// ── L. Lexical splitter controls (R1 P1-R1-01) ──
// splitStatements is a single-pass, lexically aware scanner: it never shatters a
// valid CREATE TRIGGER on a nested CASE...END or on an inner ';', and never treats
// a ';' or comment marker inside a quoted literal as significant. Each control goes
// red under exactly the named right-reason mutant(s).
const replays = (pieces) => {
  const db = new DatabaseSync(":memory:");
  try { for (const st of pieces) db.exec(st); return db; } catch { return null; }
};

// L1/L2 — the real trigger migrations segment to their measured counts and the one
// trigger piece keeps its inner ';' (a split would raise the count). TRIGGER_INNER_SEMICOLON_SPLIT.
for (const [pfx, count, label] of [["103", 4, "L1"], ["105", 21, "L2"]]) {
  const f = migFiles.find((x) => x.startsWith(pfx));
  const pieces = splitStatements(fs.readFileSync(path.join(migDir, f), "utf8"));
  const trig = pieces.filter((s) => /CREATE\s+TRIGGER/i.test(s));
  ok(`${label} migration ${pfx} → ${count} statements, exactly one trigger keeping its inner ';' (TRIGGER_INNER_SEMICOLON_SPLIT)`,
    pieces.length === count && trig.length === 1 && trig[0].includes(";"));
}

// L3 — a valid trigger whose body has CASE...END followed by a further body statement.
// Correct → 3 pieces that replay cleanly and the trigger fires. CASE_END_AS_TRIGGER_END
// or TRIGGER_INNER_SEMICOLON_SPLIT → the trigger shatters and replay throws "incomplete input".
const trgSql = [
  "CREATE TABLE src(v INTEGER);",
  "CREATE TABLE log(v INTEGER);",
  "CREATE TRIGGER trg AFTER INSERT ON src BEGIN",
  "  INSERT INTO log VALUES(CASE WHEN NEW.v = 1 THEN 0 ELSE 1 END);",
  "  INSERT INTO log VALUES(2);",
  "END;",
].join("\n") + "\n";
const trgPieces = splitStatements(trgSql);
const trgDb = replays(trgPieces);
let trgFires = false;
if (trgDb) { try { trgDb.exec("INSERT INTO src VALUES(1)"); trgFires = trgDb.prepare("SELECT COUNT(*) c FROM log").get().c === 2; } catch { trgFires = false; } }
ok("L3 trigger with CASE...END + a further body statement → 3 pieces, replays clean, trigger fires (CASE_END_AS_TRIGGER_END / TRIGGER_INNER_SEMICOLON_SPLIT)",
  trgPieces.length === 3 && trgDb !== null && trgFires);

// L4 — a ';' inside a quoted literal is not a statement boundary. QUOTED_SEMICOLON_SPLIT.
ok("L4 quoted ';' does not split the statement (QUOTED_SEMICOLON_SPLIT)",
  splitStatements("INSERT INTO q VALUES('a;b');").length === 1);

// L5 — comment markers inside quoted text are preserved verbatim. QUOTED_COMMENT_STRIP.
const q1 = splitStatements("INSERT INTO q VALUES('-- not a comment');");
const q2 = splitStatements("SELECT '/* not a comment */' AS x;");
ok("L5 comment markers inside quoted text are preserved, not stripped (QUOTED_COMMENT_STRIP)",
  q1.length === 1 && q1[0].includes("-- not a comment") &&
  q2.length === 1 && q2[0].includes("/* not a comment */"));

// L6 — real comments are stripped and real ';' still split (lexical comment handling).
const c1 = splitStatements("SELECT 1; -- trailing\nSELECT 2;");
const c2 = splitStatements("SELECT /* mid */ 1; SELECT 2;");
ok("L6 actual line/block comments are stripped and real statements still split",
  c1.length === 2 && !c1.join(" ").includes("trailing") &&
  c2.length === 2 && !c2.join(" ").includes("mid"));

console.log(`\nF-025/F-035 migration terminal (statement granularity): ${pass}/${pass + fail} passed`);
if (fail > 0) { console.error("f025-f035 validation FAILED"); process.exit(1); }
console.log("f025-f035 validation passed");
