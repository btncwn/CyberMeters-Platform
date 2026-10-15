#!/usr/bin/env node
// Import a synthetic fixture only after checking the exact staging D1 identity,
// complete empty schema, generated artifact, and disabled staging Worker config.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { buildMcpStagingFixtureSql, MCP_STAGING_IDENTITIES } from "./generate-mcp-staging-fixture.js";
import { verifyPassword } from "../workers/scan-api/src/lib/password.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databaseName = "cybermeters-db-staging";
const defaults = Object.freeze({
  manifest: path.join(root, "local/mcp-staging-resources.json"),
  config: path.join(root, "workers/scan-api/.wrangler/mcp-staging/wrangler.jsonc"),
  sql: path.join(root, "local/mcp-staging-fixture.sql"),
  credentials: path.join(root, "local/mcp-staging-fixture-credentials.json"),
  schema: path.join(root, "local/mcp-staging-schema.sql"),
});
const passwordHash = /pbkdf2:sha256:100000:[a-f0-9]{32}:[a-f0-9]{64}/g;
const expectedRows = Object.freeze({
  users: 2, workspaces: 2, workspace_members: 2, mcp_beta_workspace_access: 2,
  subscriptions: 2,
});

function readPrivateFile(file) {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `Refusing non-regular file: ${file}`);
  assert.equal(stat.mode & 0o077, 0, `File must be owner-only (0600): ${file}`);
  assert.equal(fs.realpathSync(file), path.resolve(file), `Refusing symlink path: ${file}`);
  return fs.readFileSync(file, "utf8");
}

function checkFixedPaths(paths) {
  // Only tests may inject paths. The CLI always uses the fixed ignored files.
  assert.equal(fs.realpathSync(path.dirname(paths.manifest)), path.dirname(paths.manifest));
  assert.equal(fs.realpathSync(path.dirname(paths.config)), path.dirname(paths.config));
  assert.equal(fs.realpathSync(path.dirname(paths.sql)), path.dirname(paths.sql));
  assert.equal(fs.realpathSync(path.dirname(paths.credentials)), path.dirname(paths.credentials));
}

function expectedTables(schemaSql) {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(schemaSql);
    return db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all().map((row) => row.name);
  } finally { db.close(); }
}

function parseJson(output, label) {
  try { return JSON.parse(output); }
  catch { throw new Error(`${label} did not return JSON; import refused`); }
}

function parseQuery(output, label) {
  const value = parseJson(output, label);
  if (!Array.isArray(value) || value.length !== 1 || value[0]?.success !== true ||
      !Array.isArray(value[0].results)) {
    throw new Error(`${label} failed or had unexpected D1 result shape`);
  }
  return value[0].results;
}

function assertNames(actual, expected) {
  if (!Array.isArray(actual) || actual.some((name) => typeof name !== "string") ||
      JSON.stringify([...actual].sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error("Remote D1 schema differs from the generated staging schema");
  }
}

function assertCounts(rows, tables, afterImport = false) {
  const expected = Object.fromEntries(tables.map((name) => [name,
    afterImport ? (expectedRows[name] ?? 0) : 0]));
  if (rows.length !== tables.length ||
      rows.some((row) => typeof row?.table_name !== "string" ||
        !Number.isSafeInteger(row.row_count) || row.row_count < 0 ||
        expected[row.table_name] !== row.row_count) ||
      new Set(rows.map((row) => row.table_name)).size !== tables.length) {
    throw new Error(afterImport ? "Staging fixture readback failed" :
      "Staging D1 is not completely empty; import refused");
  }
}

function tableCountSql(tables) {
  // Names came from exact comparison with the generated local schema.
  return `${tables.map((name) =>
    `SELECT '${name}' AS table_name, COUNT(*) AS row_count FROM "${name}"`).join(" UNION ALL ")};`;
}

export async function guardedMcpStagingFixtureImport({ runWrangler, paths = defaults } = {}) {
  if (typeof runWrangler !== "function") throw new Error("Wrangler runner is required");
  checkFixedPaths(paths);
  const resources = parseJson(readPrivateFile(paths.manifest), "staging resource manifest");
  const expectedConfig = buildMcpStagingConfigs(resources).api;
  const config = parseJson(readPrivateFile(paths.config), "staging API config");
  assert.deepEqual(config, expectedConfig,
    "Staging API config must match the generated disabled configuration exactly");
  const binding = config.d1_databases[0];
  assert.equal(binding.database_name, databaseName);
  assert.equal(binding.database_id, resources.staging_d1_database_id);
  assert.equal(config.vars.MAINTENANCE_MODE, "on");

  const sql = readPrivateFile(paths.sql);
  const credentials = parseJson(readPrivateFile(paths.credentials), "fixture credentials");
  if (credentials?.kind !== "synthetic-mcp-staging-only" ||
      !Array.isArray(credentials.accounts) || credentials.accounts.length !== 2 ||
      credentials.accounts.some((account, index) =>
        account.email !== MCP_STAGING_IDENTITIES[index].email ||
        typeof account.password !== "string" || account.password.length < 40 ||
        !/^[A-Za-z0-9_-]+$/.test(account.password)) ||
      credentials.accounts[0].password === credentials.accounts[1].password) {
    throw new Error("Invalid synthetic fixture credentials");
  }
  const hashes = [...sql.matchAll(passwordHash)].map((match) => match[0]);
  if (hashes.length !== 2 || buildMcpStagingFixtureSql(hashes) !== sql ||
      sql.includes(credentials.accounts[0].password) ||
      sql.includes(credentials.accounts[1].password)) {
    throw new Error("Fixture SQL does not exactly match its safe generator");
  }
  for (const [index, account] of credentials.accounts.entries()) {
    if (!await verifyPassword(account.password, hashes[index])) {
      throw new Error(`Fixture hash does not match synthetic account ${index + 1}`);
    }
  }
  const tables = expectedTables(readPrivateFile(paths.schema));
  for (const required of [...Object.keys(expectedRows), "domains", "scans", "findings",
    "user_sessions", "mcp_oauth_connections"]) {
    if (!tables.includes(required)) throw new Error(`Staging schema is missing ${required}`);
  }

  const call = (args) => runWrangler(args);
  const info = parseJson(await call(["d1", "info", databaseName, "--config", paths.config, "--json"]),
    "remote D1 info");
  if (info?.uuid !== binding.database_id || info?.name !== databaseName) {
    throw new Error("Remote D1 identity differs from the dedicated staging binding");
  }
  const databases = parseJson(await call(["d1", "list", "--config", paths.config, "--json"]),
    "remote D1 list");
  if (!Array.isArray(databases) ||
      databases.filter((db) => db.name === databaseName).length !== 1 ||
      databases.filter((db) => db.uuid === binding.database_id).length !== 1 ||
      databases.find((db) => db.name === databaseName)?.uuid !== binding.database_id) {
    throw new Error("Remote D1 inventory does not uniquely identify staging");
  }
  const query = async (statement, label) => parseQuery(await call(["d1", "execute", databaseName,
    "--remote", "--config", paths.config, "--command", statement, "--json"]), label);
  const remoteTables = (await query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name <> '_cf_KV' ORDER BY name;", "remote schema"))
    .map((row) => row.name);
  assertNames(remoteTables, tables);
  const countSql = tableCountSql(tables);
  assertCounts(await query(countSql, "remote preflight counts"), tables);
  if ((await query("PRAGMA quick_check;", "remote integrity"))[0]?.quick_check !== "ok" ||
      (await query("PRAGMA foreign_key_check;", "remote foreign keys")).length !== 0) {
    throw new Error("Staging D1 integrity check failed");
  }
  // Repeat just before write. The staging Worker must remain in maintenance mode.
  assertCounts(await query(countSql, "remote final preflight counts"), tables);
  const importResult = parseJson(await call(["d1", "execute", databaseName, "--remote",
    "--config", paths.config, "--file", paths.sql, "--yes", "--json"]), "fixture import");
  if (!Array.isArray(importResult) || importResult.length !== 1 ||
      importResult[0]?.success !== true) {
    throw new Error("D1 did not confirm fixture import; inspect staging before retrying");
  }
  assertCounts(await query(countSql, "remote fixture readback"), tables, true);
  const states = await query("SELECT status, COUNT(*) AS n FROM mcp_beta_workspace_access GROUP BY status;",
    "remote beta gate readback");
  if (states.length !== 1 || states[0]?.status !== "paused" || states[0]?.n !== 2 ||
      (await query("PRAGMA foreign_key_check;", "remote post-import foreign keys")).length !== 0) {
    throw new Error("Fixture imported but staging beta or integrity readback failed; inspect staging");
  }
  return { database: databaseName, users: 2, workspaces: 2, betaStatus: "paused" };
}

function cliWrangler(args) {
  const binary = path.join(root, "workers/scan-api/node_modules/.bin/wrangler");
  return execFileSync(binary, args, { cwd: root, encoding: "utf8", timeout: 120000,
    maxBuffer: 8 * 1024 * 1024, env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" } });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) {
    console.error("Usage: node scripts/import-mcp-staging-fixture.js");
    process.exitCode = 2;
  } else {
    guardedMcpStagingFixtureImport({ runWrangler: cliWrangler })
      .then((result) => console.log(`Imported synthetic fixture into ${result.database}: two paused workspaces.`))
      .catch((error) => { console.error(`Staging fixture import refused: ${error.message}`); process.exitCode = 1; });
  }
}
