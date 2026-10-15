#!/usr/bin/env node
// Change only the two synthetic MCP beta rows in the dedicated staging D1.
// The CLI has no override for the database, config, resource manifest, or SQL.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { MCP_STAGING_IDENTITIES } from "./generate-mcp-staging-fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databaseName = "cybermeters-db-staging";
const defaults = Object.freeze({
  manifest: path.join(root, "local/mcp-staging-resources.json"),
  config: path.join(root, "workers/scan-api/.wrangler/mcp-staging/wrangler.jsonc"),
});
const identities = [...MCP_STAGING_IDENTITIES].sort((a, b) => a.workspaceId.localeCompare(b.workspaceId));
const quote = (value) => `'${value.replaceAll("'", "''")}'`;
const ids = identities.map((identity) => quote(identity.workspaceId)).join(", ");

function privateJson(file, label) {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular file`);
  assert.equal(stat.mode & 0o077, 0, `${label} must be owner-only (0600)`);
  assert.equal(fs.realpathSync(file), path.resolve(file), `${label} has a symlink path`);
  assert.equal(fs.realpathSync(path.dirname(file)), path.dirname(file),
    `${label} has a symlink directory`);
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`${label} is not valid JSON`); }
}

function parseJson(output, label) {
  try { return JSON.parse(output); }
  catch { throw new Error(`${label} did not return JSON; staging access unchanged`); }
}

function parseQuery(output, label) {
  const value = parseJson(output, label);
  if (!Array.isArray(value) || value.length !== 1 || value[0]?.success !== true ||
      !Array.isArray(value[0].results)) {
    throw new Error(`${label} failed or returned an unexpected D1 result`);
  }
  return value[0].results;
}

function expectedRows() {
  return {
    users: identities.map((identity) => ({
      id: identity.userId, email: identity.email, status: "active", email_verified: 1,
    })).sort((a, b) => a.id.localeCompare(b.id)),
    workspaces: identities.map((identity) => ({
      id: identity.workspaceId, name: identity.workspaceName,
      owner_user_id: identity.userId, deleted_at: null,
    })),
    members: identities.map((identity) => ({
      id: identity.memberId, workspace_id: identity.workspaceId,
      user_id: identity.userId, role: "owner",
    })).sort((a, b) => a.id.localeCompare(b.id)),
  };
}

async function assertSyntheticFixture(query) {
  const expected = expectedRows();
  for (const [label, sql, rows] of [
    ["users", "SELECT id,email,status,email_verified FROM users ORDER BY id;", expected.users],
    ["workspaces", "SELECT id,name,owner_user_id,deleted_at FROM workspaces ORDER BY id;",
      expected.workspaces],
    ["members", "SELECT id,workspace_id,user_id,role FROM workspace_members ORDER BY id;",
      expected.members],
  ]) {
    const actual = await query(sql, `remote ${label} fixture`);
    if (!isDeepStrictEqual(actual, rows)) {
      throw new Error(`Remote D1 has non-synthetic ${label}; access unchanged`);
    }
  }
  const access = await query(
    "SELECT workspace_id,status,enrolled_by FROM mcp_beta_workspace_access ORDER BY workspace_id;",
    "remote beta fixture",
  );
  if (access.length !== 2 || access.some((row, index) =>
    row.workspace_id !== identities[index].workspaceId ||
    row.enrolled_by !== identities[index].userId ||
    !["paused", "enabled"].includes(row.status))) {
    throw new Error("Remote D1 has non-synthetic beta access; access unchanged");
  }
  return access;
}

function updateSql(action) {
  const previous = action === "enable" ? "paused" : "enabled";
  const desired = action === "enable" ? "enabled" : "paused";
  const exactUsers = identities.map((i) =>
    `(id=${quote(i.userId)} AND email=${quote(i.email)} AND status='active' AND email_verified=1)`);
  const exactWorkspaces = identities.map((i) =>
    `(id=${quote(i.workspaceId)} AND name=${quote(i.workspaceName)} AND owner_user_id=${quote(i.userId)} AND deleted_at IS NULL)`);
  const exactMembers = identities.map((i) =>
    `(id=${quote(i.memberId)} AND workspace_id=${quote(i.workspaceId)} AND user_id=${quote(i.userId)} AND role='owner')`);
  const guards = [
    `(SELECT COUNT(*) FROM users)=2`,
    `(SELECT COUNT(*) FROM users WHERE ${exactUsers.join(" OR ")})=2`,
    `(SELECT COUNT(*) FROM workspaces)=2`,
    `(SELECT COUNT(*) FROM workspaces WHERE ${exactWorkspaces.join(" OR ")})=2`,
    `(SELECT COUNT(*) FROM workspace_members)=2`,
    `(SELECT COUNT(*) FROM workspace_members WHERE ${exactMembers.join(" OR ")})=2`,
    `(SELECT COUNT(*) FROM mcp_beta_workspace_access)=2`,
    `(SELECT COUNT(*) FROM mcp_beta_workspace_access WHERE workspace_id IN (${ids}))=2`,
  ];
  return `UPDATE mcp_beta_workspace_access SET status=${quote(desired)}, updated_at=CURRENT_TIMESTAMP ` +
    `WHERE workspace_id IN (${ids}) AND status=${quote(previous)} AND ${guards.join(" AND ")};`;
}

/** Injected runner and paths are for hermetic tests; the CLI uses fixed ignored files. */
export async function setMcpStagingFixtureAccess(action, { runWrangler, paths = defaults } = {}) {
  if (action !== "enable" && action !== "pause") {
    throw new Error("Action must be enable or pause");
  }
  if (typeof runWrangler !== "function") throw new Error("Wrangler runner is required");
  const resources = privateJson(paths.manifest, "staging resource manifest");
  const config = privateJson(paths.config, "disabled staging API config");
  if (!isDeepStrictEqual(config, buildMcpStagingConfigs(resources).api)) {
    throw new Error("Staging API config must match the generated disabled configuration exactly");
  }
  const binding = config.d1_databases[0];
  assert.equal(binding.database_name, databaseName);
  assert.equal(binding.database_id, resources.staging_d1_database_id);
  assert.equal(config.vars.MAINTENANCE_MODE, "on");

  const call = (args) => runWrangler(args);
  const info = parseJson(await call(["d1", "info", databaseName, "--config", paths.config, "--json"]),
    "remote D1 info");
  if (info?.name !== databaseName || info?.uuid !== binding.database_id) {
    throw new Error("Remote D1 identity differs from the dedicated staging binding");
  }
  const inventory = parseJson(await call(["d1", "list", "--config", paths.config, "--json"]),
    "remote D1 list");
  if (!Array.isArray(inventory) ||
      inventory.filter((db) => db.name === databaseName).length !== 1 ||
      inventory.filter((db) => db.uuid === binding.database_id).length !== 1 ||
      inventory.find((db) => db.name === databaseName)?.uuid !== binding.database_id) {
    throw new Error("Remote D1 inventory does not uniquely identify staging");
  }
  const query = async (sql, label) => parseQuery(await call(["d1", "execute", databaseName,
    "--remote", "--config", paths.config, "--command", sql, "--json"]), label);
  const before = await assertSyntheticFixture(query);
  if ((await query("PRAGMA quick_check;", "remote integrity"))[0]?.quick_check !== "ok" ||
      (await query("PRAGMA foreign_key_check;", "remote foreign keys")).length !== 0) {
    throw new Error("Staging D1 integrity check failed; access unchanged");
  }
  const desired = action === "enable" ? "enabled" : "paused";
  if (action === "enable" && before.some((row) => row.status !== "paused")) {
    throw new Error("Both synthetic workspaces must be paused before enable");
  }
  const alreadyDesired = before.every((row) => row.status === desired);
  if (!alreadyDesired) {
    // One guarded SQL statement makes the two-row transition atomic.
    await query(updateSql(action), "remote guarded beta update");
  }
  const after = await assertSyntheticFixture(query);
  if (after.some((row) => row.status !== desired) ||
      (await query("PRAGMA foreign_key_check;", "remote post-update foreign keys")).length !== 0) {
    throw new Error("Staging beta access readback failed; disable the staging gateway");
  }
  return { database: databaseName, workspaces: 2, status: desired, changed: !alreadyDesired };
}

function cliWrangler(args) {
  const binary = path.join(root, "workers/scan-api/node_modules/.bin/wrangler");
  return execFileSync(binary, args, { cwd: root, encoding: "utf8", timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" } });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const action = process.argv[2];
  if (process.argv.length !== 3 || !["enable", "pause"].includes(action)) {
    console.error("Usage: node scripts/set-mcp-staging-fixture-access.js enable|pause");
    process.exitCode = 2;
  } else {
    setMcpStagingFixtureAccess(action, { runWrangler: cliWrangler })
      .then((result) => console.log(
        `${result.changed ? "Set" : "Verified"} two synthetic staging beta workspaces ${result.status}.`,
      ))
      .catch((error) => {
        console.error(`Staging beta access ${action} refused: ${error.message}`);
        process.exitCode = 1;
      });
  }
}
