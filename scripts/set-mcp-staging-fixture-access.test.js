#!/usr/bin/env node
// Hermetic tests: the Wrangler runner and D1 are simulated in memory.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { MCP_STAGING_IDENTITIES } from "./generate-mcp-staging-fixture.js";
import { setMcpStagingFixtureAccess } from "./set-mcp-staging-fixture-access.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scratch = fs.mkdtempSync(path.join(root, "local", ".mcp-access-test-"));
fs.chmodSync(scratch, 0o700);
const resources = {
  staging_d1_database_id: "22222222-2222-4222-8222-222222222222",
  staging_oauth_kv_namespace_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  staging_edge_client_rate_namespace_id: "880031",
  staging_edge_global_rate_namespace_id: "880032",
};
const paths = {
  manifest: path.join(scratch, "resources.json"),
  config: path.join(scratch, "wrangler.jsonc"),
};
const productionD1Id = fs.readFileSync(path.join(root, "workers/scan-api/wrangler.toml"), "utf8")
  .match(/database_id\s*=\s*"([^"]+)"/)?.[1];
assert.ok(productionD1Id);
const put = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
const d1 = (results) => JSON.stringify([{ success: true, results }]);

function fakeCloudflare({ remoteUuid = resources.staging_d1_database_id,
  remoteName = "cybermeters-db-staging", inventory = null, skipWrite = false } = {}) {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    PRAGMA foreign_keys=ON;
    CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, status TEXT, email_verified INTEGER);
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT, owner_user_id TEXT,
      deleted_at TEXT, FOREIGN KEY (owner_user_id) REFERENCES users(id));
    CREATE TABLE workspace_members (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
      role TEXT, FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
      FOREIGN KEY (user_id) REFERENCES users(id));
    CREATE TABLE mcp_beta_workspace_access (workspace_id TEXT PRIMARY KEY, status TEXT,
      enrolled_by TEXT, updated_at TEXT, FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
      FOREIGN KEY (enrolled_by) REFERENCES users(id));
  `);
  for (const identity of MCP_STAGING_IDENTITIES) {
    db.prepare("INSERT INTO users VALUES (?,?,'active',1)")
      .run(identity.userId, identity.email);
    db.prepare("INSERT INTO workspaces VALUES (?,?,?,NULL)")
      .run(identity.workspaceId, identity.workspaceName, identity.userId);
    db.prepare("INSERT INTO workspace_members VALUES (?,?,?,'owner')")
      .run(identity.memberId, identity.workspaceId, identity.userId);
    db.prepare("INSERT INTO mcp_beta_workspace_access VALUES (?,'paused',?,NULL)")
      .run(identity.workspaceId, identity.userId);
  }
  const calls = [];
  const runWrangler = async (args) => {
    calls.push(args);
    assert.equal(args[0], "d1");
    assert.equal(args[args.indexOf("--config") + 1], paths.config);
    if (args[1] === "info") return JSON.stringify({ name: remoteName, uuid: remoteUuid });
    if (args[1] === "list") return JSON.stringify(inventory ??
      [{ name: remoteName, uuid: remoteUuid }]);
    assert.equal(args[1], "execute");
    assert.equal(args[2], "cybermeters-db-staging");
    assert.ok(args.includes("--remote"));
    assert.ok(args.includes("--json"));
    const sql = args[args.indexOf("--command") + 1];
    assert.equal(typeof sql, "string");
    if (sql.startsWith("UPDATE")) {
      if (!skipWrite) db.prepare(sql).run();
      return d1([]);
    }
    return d1(db.prepare(sql).all());
  };
  const statuses = () => db.prepare(
    "SELECT workspace_id,status FROM mcp_beta_workspace_access ORDER BY workspace_id",
  ).all();
  const writes = () => calls.filter((args) =>
    args[1] === "execute" && args[args.indexOf("--command") + 1]?.startsWith("UPDATE"));
  return { db, calls, runWrangler, statuses, writes, close: () => db.close() };
}

let passed = 0;
async function check(label, fn) {
  await fn();
  passed++;
  console.log(`PASS ${label}`);
}

try {
  put(paths.manifest, resources);
  put(paths.config, buildMcpStagingConfigs(resources).api);

  await check("enable and pause change only the two synthetic rows", async () => {
    const fake = fakeCloudflare();
    try {
      assert.deepEqual(await setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), { database: "cybermeters-db-staging", workspaces: 2,
        status: "enabled", changed: true });
      assert.deepEqual(fake.statuses().map((row) => row.status), ["enabled", "enabled"]);
      assert.equal(fake.writes().length, 1);
      assert.deepEqual(await setMcpStagingFixtureAccess("pause", {
        runWrangler: fake.runWrangler, paths,
      }), { database: "cybermeters-db-staging", workspaces: 2,
        status: "paused", changed: true });
      assert.deepEqual(fake.statuses().map((row) => row.status), ["paused", "paused"]);
      assert.equal(fake.writes().length, 2);
    } finally { fake.close(); }
  });
  await check("already paused is verified without a write", async () => {
    const fake = fakeCloudflare();
    try {
      const result = await setMcpStagingFixtureAccess("pause", {
        runWrangler: fake.runWrangler, paths,
      });
      assert.equal(result.changed, false);
      assert.equal(fake.writes().length, 0);
    } finally { fake.close(); }
  });
  await check("partial enabled state can be fully paused", async () => {
    const fake = fakeCloudflare();
    try {
      fake.db.prepare("UPDATE mcp_beta_workspace_access SET status='enabled' WHERE workspace_id=?")
        .run(MCP_STAGING_IDENTITIES[0].workspaceId);
      const result = await setMcpStagingFixtureAccess("pause", {
        runWrangler: fake.runWrangler, paths,
      });
      assert.equal(result.status, "paused");
      assert.deepEqual(fake.statuses().map((row) => row.status), ["paused", "paused"]);
      assert.equal(fake.writes().length, 1);
    } finally { fake.close(); }
  });
  await check("partial enabled state cannot enable", async () => {
    const fake = fakeCloudflare();
    try {
      fake.db.prepare("UPDATE mcp_beta_workspace_access SET status='enabled' WHERE workspace_id=?")
        .run(MCP_STAGING_IDENTITIES[0].workspaceId);
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /must be paused/);
      assert.equal(fake.writes().length, 0);
    } finally { fake.close(); }
  });
  await check("production D1 binding is refused before remote access", async () => {
    const config = buildMcpStagingConfigs(resources).api;
    config.d1_databases[0].database_id = productionD1Id;
    put(paths.config, config);
    const fake = fakeCloudflare();
    try {
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /generated disabled configuration/);
      assert.equal(fake.calls.length, 0);
    } finally {
      fake.close();
      put(paths.config, buildMcpStagingConfigs(resources).api);
    }
  });
  await check("remote production UUID is refused before any SQL", async () => {
    const fake = fakeCloudflare({ remoteUuid: productionD1Id });
    try {
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /Remote D1 identity/);
      assert.equal(fake.calls.filter((args) => args[1] === "execute").length, 0);
    } finally { fake.close(); }
  });
  await check("wrong remote database name is refused before any SQL", async () => {
    const fake = fakeCloudflare({ remoteName: "cybermeters-db" });
    try {
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /Remote D1 identity/);
      assert.equal(fake.calls.filter((args) => args[1] === "execute").length, 0);
    } finally { fake.close(); }
  });
  await check("ambiguous staging inventory is refused before any SQL", async () => {
    const fake = fakeCloudflare({ inventory: [
      { name: "cybermeters-db-staging", uuid: resources.staging_d1_database_id },
      { name: "cybermeters-db-staging", uuid: "33333333-3333-4333-8333-333333333333" },
    ] });
    try {
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /inventory/);
      assert.equal(fake.calls.filter((args) => args[1] === "execute").length, 0);
    } finally { fake.close(); }
  });
  await check("extra customer-like user refuses access before write", async () => {
    const fake = fakeCloudflare();
    try {
      fake.db.prepare("INSERT INTO users VALUES ('customer','real@example.com','active',1)").run();
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /non-synthetic users/);
      assert.equal(fake.writes().length, 0);
    } finally { fake.close(); }
  });
  await check("changed synthetic owner refuses access before write", async () => {
    const fake = fakeCloudflare();
    try {
      fake.db.prepare("UPDATE workspace_members SET role='viewer' WHERE id=?")
        .run(MCP_STAGING_IDENTITIES[0].memberId);
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /non-synthetic members/);
      assert.equal(fake.writes().length, 0);
    } finally { fake.close(); }
  });
  await check("extra beta row refuses access before write", async () => {
    const fake = fakeCloudflare();
    try {
      fake.db.exec("INSERT INTO users VALUES ('x','x@example.invalid','active',1)");
      fake.db.exec("INSERT INTO workspaces VALUES ('w_x','X','x',NULL)");
      fake.db.exec("INSERT INTO mcp_beta_workspace_access VALUES ('w_x','paused','x',NULL)");
      await assert.rejects(setMcpStagingFixtureAccess("pause", {
        runWrangler: fake.runWrangler, paths,
      }), /non-synthetic users/);
      assert.equal(fake.writes().length, 0);
    } finally { fake.close(); }
  });
  await check("unconfirmed update fails post-write readback", async () => {
    const fake = fakeCloudflare({ skipWrite: true });
    try {
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /readback failed/);
      assert.equal(fake.writes().length, 1);
    } finally { fake.close(); }
  });
  await check("world-readable config is refused before remote access", async () => {
    fs.chmodSync(paths.config, 0o644);
    const fake = fakeCloudflare();
    try {
      await assert.rejects(setMcpStagingFixtureAccess("enable", {
        runWrangler: fake.runWrangler, paths,
      }), /owner-only/);
      assert.equal(fake.calls.length, 0);
    } finally { fake.close(); }
  });
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
console.log(`MCP staging beta access guard: ${passed} passed, 0 failed; fake Wrangler only.`);
