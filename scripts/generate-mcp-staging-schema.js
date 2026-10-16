#!/usr/bin/env node
// Build an empty staging D1 from the final locally validated platform schema.
// Historical migrations cannot be sent wholesale to a fresh D1: several
// statements have exact, already documented schema/ordering overlaps.
// This script never contacts Cloudflare and writes only to ignored local/.
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { isToleratedStatement, splitStatements } from "./lib/migration-apply-tolerated.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationDir = path.join(root, "database", "migrations");
const outputDir = path.join(root, "local");
const output = path.join(outputDir, "mcp-staging-schema.sql");
const migrations = fs.readdirSync(migrationDir).filter((name) => name.endsWith(".sql")).sort();

// The existing gate pins the two destructive historical migrations to their
// approved exact bytes and checks the source chain's fresh convergence.
execFileSync(process.execPath, [path.join(root, "scripts", "validate-migrations.js")], {
  cwd: root,
  stdio: "pipe",
});

const db = new DatabaseSync(":memory:");
db.exec(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8"));
let tolerated = 0;
for (const file of migrations) {
  const raw = fs.readFileSync(path.join(migrationDir, file), "utf8");
  const fileHash = crypto.createHash("sha256").update(raw).digest("hex");
  for (const statement of splitStatements(raw)) {
    try {
      db.exec(statement);
    } catch (error) {
      if (!isToleratedStatement(file, fileHash, statement, error.message)) {
        throw new Error(`Migration ${file} has an unapproved error: ${error.message}`);
      }
      tolerated++;
    }
  }
}

const objects = db.prepare(`
  SELECT type, name, tbl_name, sql FROM sqlite_schema
  WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
  ORDER BY rowid
`).all();
const tables = objects.filter((object) => object.type === "table");
if (tables.length === 0 || !tables.some((table) => table.name === "mcp_oauth_connections")) {
  throw new Error("The converged schema is missing required MCP tables");
}
for (const table of tables) {
  const count = db.prepare(`SELECT COUNT(*) AS n FROM "${table.name.replaceAll('"', '""')}"`).get().n;
  if (count !== 0) throw new Error(`Fresh schema unexpectedly contains data in ${table.name}`);
}
if (db.prepare("PRAGMA foreign_key_check").all().length !== 0 ||
    db.prepare("PRAGMA quick_check").get().quick_check !== "ok") {
  throw new Error("Locally converged schema failed integrity checks");
}

const ddl = `-- Empty staging D1 bootstrap. Generated from database/schema.sql + ${migrations.length} migrations.\n` +
  `-- Apply only to a verified empty cybermeters-db-staging D1. Never use on production.\n` +
  objects.map((object) => `${object.sql};\n`).join("\n");

// Re-import the artifact into a second empty database and prove the final
// schema's table/index/view/trigger definitions match byte for byte.
const replay = new DatabaseSync(":memory:");
replay.exec(ddl);
const replayObjects = replay.prepare(`
  SELECT type, name, tbl_name, sql FROM sqlite_schema
  WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
  ORDER BY rowid
`).all();
if (JSON.stringify(replayObjects) !== JSON.stringify(objects) ||
    replay.prepare("PRAGMA foreign_key_check").all().length !== 0 ||
    replay.prepare("PRAGMA quick_check").get().quick_check !== "ok") {
  throw new Error("Generated staging schema did not reproduce the validated source schema");
}

fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
const temporary = `${output}.${process.pid}.tmp`;
fs.writeFileSync(temporary, ddl, { mode: 0o600, flag: "wx" });
fs.renameSync(temporary, output);
replay.close();
db.close();
console.log(`Generated ${output}`);
console.log(`${tables.length} empty tables, ${objects.length} schema objects, ${tolerated} exact historical no-ops; local replay and integrity passed.`);
