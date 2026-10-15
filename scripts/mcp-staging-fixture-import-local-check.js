#!/usr/bin/env node
// Hermetic importer tests: every Wrangler response is fake; no network or D1 write.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { hashPassword } from "../workers/scan-api/src/lib/password.js";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { buildMcpStagingFixtureSql, generateMcpStagingCredentials } from "./generate-mcp-staging-fixture.js";
import { guardedMcpStagingFixtureImport } from "./import-mcp-staging-fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scratch = fs.mkdtempSync(path.join(root, "local", ".mcp-import-test-"));
fs.chmodSync(scratch, 0o700);
const resources = {
  staging_d1_database_id: "22222222-2222-4222-8222-222222222222",
  staging_oauth_kv_namespace_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  staging_edge_client_rate_namespace_id: "880031",
  staging_edge_global_rate_namespace_id: "880032",
};
const files = {
  manifest: path.join(scratch, "resources.json"),
  config: path.join(scratch, "wrangler.jsonc"),
  sql: path.join(scratch, "fixture.sql"),
  credentials: path.join(scratch, "credentials.json"),
  schema: path.join(scratch, "schema.sql"),
};
const put = (file, value) => fs.writeFileSync(file, value, { mode: 0o600 });
const rows = (results) => JSON.stringify([{ success: true, results }]);
const productionD1Id = fs.readFileSync(path.join(root, "workers/scan-api/wrangler.toml"), "utf8")
  .match(/database_id\s*=\s*"([^"]+)"/)?.[1];
assert.ok(productionD1Id);
const testCredentials = generateMcpStagingCredentials();
const hashes = await Promise.all(testCredentials.accounts.map((account) => hashPassword(account.password)));
const schemaSql = fs.readFileSync(path.join(root, "local/mcp-staging-schema.sql"), "utf8");
const schemaDb = new DatabaseSync(":memory:");
schemaDb.exec(schemaSql);
const tables = schemaDb.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
  .all().map((row) => row.name);
schemaDb.close();
const fixtureSql = buildMcpStagingFixtureSql(hashes);

function fakeCloudflare({ remoteUuid = resources.staging_d1_database_id,
  remoteName = "cybermeters-db-staging", nonempty = false, badSchema = false } = {}) {
  const calls = [];
  let imported = false;
  const runWrangler = async (args) => {
    calls.push(args);
    if (args[0] !== "d1") throw new Error("Unexpected CLI command");
    if (args[1] === "info") return JSON.stringify({ uuid: remoteUuid, name: remoteName });
    if (args[1] === "list") return JSON.stringify([{ uuid: remoteUuid, name: remoteName }]);
    if (args[1] !== "execute") throw new Error("Unexpected D1 operation");
    if (args.includes("--file")) {
      assert.deepEqual(args.slice(0, 3), ["d1", "execute", "cybermeters-db-staging"]);
      assert.ok(args.includes("--remote"));
      assert.equal(args[args.indexOf("--file") + 1], files.sql);
      imported = true;
      return rows([{ "Total queries executed": 10 }]);
    }
    const statement = args[args.indexOf("--command") + 1];
    if (statement.includes("sqlite_master")) return rows(
      (badSchema ? tables.slice(1) : tables).map((name) => ({ name })));
    if (statement.startsWith("SELECT '") && statement.includes("row_count")) return rows(
      tables.map((name) => ({ table_name: name,
        row_count: imported ? ({ users: 2, workspaces: 2, workspace_members: 2,
          mcp_beta_workspace_access: 2, subscriptions: 2 }[name] ?? 0) :
          (nonempty && name === "users" ? 1 : 0) })));
    if (statement === "PRAGMA quick_check;") return rows([{ quick_check: "ok" }]);
    if (statement === "PRAGMA foreign_key_check;") return rows([]);
    if (statement.startsWith("SELECT status, COUNT(*)")) return rows([{ status: "paused", n: 2 }]);
    throw new Error(`Unexpected D1 query: ${statement.slice(0, 60)}`);
  };
  return { runWrangler, calls, get imported() { return imported; } };
}

let passed = 0;
async function check(label, fn) {
  await fn();
  passed++;
  console.log(`PASS ${label}`);
}

try {
  put(files.manifest, `${JSON.stringify(resources)}\n`);
  put(files.config, `${JSON.stringify(buildMcpStagingConfigs(resources).api)}\n`);
  put(files.sql, fixtureSql);
  put(files.credentials, `${JSON.stringify(testCredentials)}\n`);
  put(files.schema, schemaSql);

  await check("dedicated empty staging imports once and verifies paused readback", async () => {
    const fake = fakeCloudflare();
    assert.deepEqual(await guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), { database: "cybermeters-db-staging", users: 2, workspaces: 2,
      betaStatus: "paused" });
    assert.equal(fake.calls.filter((args) => args.includes("--file")).length, 1);
  });
  await check("production D1 in generated config is refused before remote access", async () => {
    const config = buildMcpStagingConfigs(resources).api;
    config.d1_databases[0].database_id = productionD1Id;
    put(files.config, `${JSON.stringify(config)}\n`);
    const fake = fakeCloudflare();
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /Staging API config/);
    assert.equal(fake.calls.length, 0);
    put(files.config, `${JSON.stringify(buildMcpStagingConfigs(resources).api)}\n`);
  });
  await check("remote UUID mismatch is refused before SQL", async () => {
    const fake = fakeCloudflare({ remoteUuid: productionD1Id });
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /Remote D1 identity/);
    assert.equal(fake.imported, false);
  });
  await check("remote name mismatch is refused before SQL", async () => {
    const fake = fakeCloudflare({ remoteName: "cybermeters-db" });
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /Remote D1 identity/);
    assert.equal(fake.imported, false);
  });
  await check("nonempty staging D1 refuses import", async () => {
    const fake = fakeCloudflare({ nonempty: true });
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /not completely empty/);
    assert.equal(fake.imported, false);
  });
  await check("incomplete remote schema refuses import", async () => {
    const fake = fakeCloudflare({ badSchema: true });
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /schema differs/);
    assert.equal(fake.imported, false);
  });
  await check("tampered fixture SQL refuses remote access", async () => {
    put(files.sql, `${fixtureSql}DELETE FROM users;\n`);
    const fake = fakeCloudflare();
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /Fixture SQL/);
    assert.equal(fake.calls.length, 0);
    put(files.sql, fixtureSql);
  });
  await check("mismatched credentials refuse remote access", async () => {
    const bad = structuredClone(testCredentials);
    bad.accounts[0].password = generateMcpStagingCredentials().accounts[0].password;
    put(files.credentials, `${JSON.stringify(bad)}\n`);
    const fake = fakeCloudflare();
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /hash does not match/);
    assert.equal(fake.calls.length, 0);
    put(files.credentials, `${JSON.stringify(testCredentials)}\n`);
  });
  await check("world-readable fixture refuses remote access", async () => {
    fs.chmodSync(files.sql, 0o644);
    const fake = fakeCloudflare();
    await assert.rejects(guardedMcpStagingFixtureImport({ runWrangler: fake.runWrangler,
      paths: files }), /owner-only/);
    assert.equal(fake.calls.length, 0);
  });
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
console.log(`Guarded MCP staging fixture importer: ${passed} passed, 0 failed; fake Wrangler only.`);
