import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { buildMcpStagingFixtureSql } from "./generate-mcp-staging-fixture.js";
import { buildMcpContentStagingSql } from "./mcp-content-staging-fixture.js";
import { guardedMcpContentStagingImport } from "./import-mcp-content-staging-fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schema = fs.readFileSync(path.join(root, "local/mcp-staging-schema.sql"), "utf8");
const now = new Date("2026-10-15T12:00:00.000Z");
const resource = {
  staging_d1_database_id: "22222222-2222-4222-8222-222222222222",
  staging_oauth_kv_namespace_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  staging_edge_client_rate_namespace_id: "880031",
  staging_edge_global_rate_namespace_id: "880032",
};
const hashes = ["a", "b"].map((ch) => `pbkdf2:sha256:100000:${ch.repeat(32)}:${ch.repeat(64)}`);
const content = buildMcpContentStagingSql(now);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const encoded = (results) => JSON.stringify([{ success: true, results }]);

function harness(options = {}) {
  const directory = fs.mkdtempSync(path.join(root, "local", ".mcp-content-import-test-"));
  fs.chmodSync(directory, 0o700);
  const paths = { manifest: path.join(directory, "resources.json"),
    config: path.join(directory, "wrangler.jsonc"),
    baseSql: path.join(directory, "base.sql"), sql: path.join(directory, "content.sql") };
  const put = (file, value) => fs.writeFileSync(file, value, { mode: 0o600 });
  put(paths.manifest, `${JSON.stringify(resource)}\n`);
  put(paths.config, `${JSON.stringify(buildMcpStagingConfigs(resource).api)}\n`);
  put(paths.baseSql, buildMcpStagingFixtureSql(hashes));
  put(paths.sql, content);
  const db = new DatabaseSync(":memory:");
  db.exec(schema);
  db.exec("PRAGMA foreign_keys=ON");
  db.exec(buildMcpStagingFixtureSql(hashes));
  const calls = [];
  let imports = 0;
  const runWrangler = async (args) => {
    calls.push(args);
    assert.equal(args[0], "d1");
    if (args[1] === "info") return JSON.stringify({
      uuid: options.remoteUuid ?? resource.staging_d1_database_id,
      name: options.remoteName ?? "cybermeters-db-staging",
    });
    if (args[1] === "list") return JSON.stringify([{ uuid: options.remoteUuid ?? resource.staging_d1_database_id,
      name: options.remoteName ?? "cybermeters-db-staging" }]);
    assert.equal(args[1], "execute");
    assert.deepEqual(args.slice(0, 3), ["d1", "execute", "cybermeters-db-staging"]);
    assert.ok(args.includes("--remote"));
    if (args.includes("--file")) {
      imports += 1;
      assert.equal(args[args.indexOf("--file") + 1], paths.sql);
      const statements = fs.readFileSync(paths.sql, "utf8").split("\n")
        .filter((line) => line.startsWith("INSERT INTO "));
      assert.equal(statements.length, 12);
      db.exec("BEGIN");
      try {
        for (const [index, statement] of statements.entries()) {
          if (index === options.failImportAt) throw new Error("simulated atomic import failure");
          db.prepare(statement).run();
        }
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      return encoded([{ "Total queries executed": 12, "Rows written": 12 }]);
    }
    const statement = args[args.indexOf("--command") + 1];
    assert.equal(typeof statement, "string");
    if (options.activeOAuth && statement.includes("mcp_oauth_connections WHERE status='active'")) {
      return encoded([{ n: 1 }]);
    }
    if (options.userSession && statement === "SELECT COUNT(*) AS n FROM user_sessions;") {
      return encoded([{ n: 1 }]);
    }
    return encoded(db.prepare(statement).all());
  };
  return { paths, db, calls, runWrangler, put, get imports() { return imports; },
    close() { db.close(); fs.rmSync(directory, { recursive: true, force: true }); } };
}

const run = (f, extra = {}) => guardedMcpContentStagingImport({
  runWrangler: f.runWrangler, paths: f.paths, now, expectedSha256: sha256(content), ...extra,
});
const count = (f, table) => f.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;

test("bare importer CLI requires an explicit reviewed hash and makes no remote call", () => {
  const result = spawnSync(process.execPath,
    [path.join(root, "scripts/import-mcp-content-staging-fixture.js")],
    { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--apply-reviewed-sha256/);
});

test("exact disabled staging imports one atomic file and verifies every content row", async () => {
  const f = harness();
  try {
    const result = await run(f);
    assert.deepEqual(result, { database: "cybermeters-db-staging", contentRows: 12,
      betaStatus: "paused", sha256: sha256(content) });
    assert.equal(f.imports, 1);
    assert.equal(count(f, "domains"), 2);
    assert.equal(count(f, "findings"), 2);
    assert.deepEqual(f.db.prepare("SELECT DISTINCT status FROM mcp_beta_workspace_access").all()
      .map((row) => row.status), ["paused"]);
    await assert.rejects(run(f), /not empty/);
    assert.equal(f.imports, 1);
  } finally { f.close(); }
});

test("reviewed SHA-256 is mandatory before any remote call", async () => {
  const f = harness();
  try {
    await assert.rejects(run(f, { expectedSha256: undefined }), /reviewed SHA-256/);
    await assert.rejects(run(f, { expectedSha256: "0".repeat(64) }), /SHA-256 differs/);
    assert.equal(f.calls.length, 0);
  } finally { f.close(); }
});

test("production or modified API config is refused before any remote call", async () => {
  const f = harness();
  try {
    const config = buildMcpStagingConfigs(resource).api;
    config.d1_databases[0].database_id = "11111111-1111-4111-8111-111111111111";
    f.put(f.paths.config, `${JSON.stringify(config)}\n`);
    await assert.rejects(run(f), /disabled generated config/);
    assert.equal(f.calls.length, 0);
  } finally { f.close(); }
});

test("remote D1 UUID mismatch is refused before mutation", async () => {
  const f = harness({ remoteUuid: "11111111-1111-4111-8111-111111111111" });
  try {
    await assert.rejects(run(f), /dedicated staging database/);
    assert.equal(f.imports, 0);
  } finally { f.close(); }
});

test("non-synthetic user, enabled beta and nonempty content each refuse import", async () => {
  for (const mutation of [
    (f) => f.db.exec("UPDATE users SET email='someone@example.org' WHERE id='usr_mcp_stage_a'"),
    (f) => f.db.exec("UPDATE users SET password_hash='tampered' WHERE id='usr_mcp_stage_a'"),
    (f) => f.db.exec("UPDATE users SET auth_provider='google' WHERE id='usr_mcp_stage_a'"),
    (f) => f.db.exec("UPDATE mcp_beta_workspace_access SET status='enabled' WHERE workspace_id='ws_mcp_stage_a'"),
    (f) => f.db.exec("INSERT INTO domains (id,user_id,domain) VALUES ('extra','usr_mcp_stage_a','extra.example.invalid')"),
  ]) {
    const f = harness();
    try {
      mutation(f);
      await assert.rejects(run(f), /differs from two paused synthetic tenants|not empty/);
      assert.equal(f.imports, 0);
    } finally { f.close(); }
  }
});

test("tampered base fixture hash file refuses remote contact", async () => {
  const f = harness();
  try {
    f.put(f.paths.baseSql, `${buildMcpStagingFixtureSql(hashes)}DELETE FROM users;\n`);
    await assert.rejects(run(f), /Base synthetic fixture SQL differs/);
    assert.equal(f.calls.length, 0);
  } finally { f.close(); }
});

test("active OAuth grant or user session refuses import", async () => {
  for (const options of [{ activeOAuth: true }, { userSession: true }]) {
    const f = harness(options);
    try {
      await assert.rejects(run(f), /must be zero/);
      assert.equal(f.imports, 0);
    } finally { f.close(); }
  }
});

test("tampered, stale, or world-readable SQL refuses import before remote contact", async () => {
  const f = harness();
  try {
    f.put(f.paths.sql, `${content}DELETE FROM users;\n`);
    await assert.rejects(run(f, { expectedSha256: sha256(`${content}DELETE FROM users;\n`) }),
      /differs from the reviewed generator/);
    f.put(f.paths.sql, content);
    await assert.rejects(run(f, { now: new Date("2026-10-17T12:00:00.000Z") }),
      /older than 24 hours/);
    fs.chmodSync(f.paths.sql, 0o644);
    await assert.rejects(run(f), /owner-only/);
    assert.equal(f.calls.length, 0);
  } finally { f.close(); }
});

test("mid-file D1 failure rolls back all content in the atomic import seam", async () => {
  const f = harness({ failImportAt: 7 });
  try {
    await assert.rejects(run(f), /simulated atomic import failure/);
    assert.equal(f.imports, 1);
    for (const table of ["domains", "workspace_domains", "scans", "findings",
      "managed_cases", "certificate_lifecycle"]) assert.equal(count(f, table), 0);
    assert.deepEqual(f.db.prepare("PRAGMA foreign_key_check").all(), []);
  } finally { f.close(); }
});
