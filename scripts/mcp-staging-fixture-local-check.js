#!/usr/bin/env node
// Verify the synthetic fixture against the complete, empty staging schema.
// Uses test-only passwords in memory; no D1/Cloudflare access or credential output.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { hashPassword, verifyPassword } from "../workers/scan-api/src/lib/password.js";
import { listMcpOAuthConsentWorkspaces } from "../workers/scan-api/src/routes/mcp-oauth-admission.js";
import { buildMcpStagingFixtureSql, generateMcpStagingCredentials,
  MCP_STAGING_IDENTITIES, writeMcpStagingFixtureArtifacts } from "./generate-mcp-staging-fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = path.join(root, "local", "mcp-staging-schema.sql");
if (!fs.existsSync(schemaPath)) {
  throw new Error("First run node scripts/generate-mcp-staging-schema.js");
}
assert.match(fs.readFileSync(path.join(root, ".gitignore"), "utf8"), /^local\/$/m);

const generated = generateMcpStagingCredentials();
assert.notEqual(generated.accounts[0].password, generated.accounts[1].password);
const generatedHashes = await Promise.all(generated.accounts.map((account) =>
  hashPassword(account.password)));
const generatedSql = buildMcpStagingFixtureSql(generatedHashes);
const temporary = fs.mkdtempSync(path.join(root, "local", ".mcp-fixture-validation-"));
try {
  const artifacts = writeMcpStagingFixtureArtifacts(temporary, generatedSql, generated);
  for (const file of [artifacts.sqlPath, artifacts.credentialsPath]) {
    assert.equal(fs.statSync(file).mode & 0o077, 0,
      "Fixture artifacts must be readable only by the local owner");
  }
  assert.equal(fs.statSync(temporary).mode & 0o077, 0);
  assert.equal(fs.readFileSync(artifacts.sqlPath, "utf8"), generatedSql);
  const saved = JSON.parse(fs.readFileSync(artifacts.credentialsPath, "utf8"));
  assert.deepEqual(saved, generated);
  for (const account of generated.accounts) assert.equal(generatedSql.includes(account.password), false);
  assert.throws(() => writeMcpStagingFixtureArtifacts(temporary, generatedSql, generated));
  fs.rmSync(artifacts.sqlPath);
  assert.throws(() => writeMcpStagingFixtureArtifacts(temporary, generatedSql, generated),
    "Existing credentials alone must prevent replacement");
  assert.throws(() => writeMcpStagingFixtureArtifacts(path.join(root, "docs"), generatedSql, generated),
    "Artifacts must not be written outside ignored local/");
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}

const testPasswords = [randomBytes(24).toString("base64url"),
  randomBytes(24).toString("base64url")];
const hashes = await Promise.all(testPasswords.map(hashPassword));
const sql = buildMcpStagingFixtureSql(hashes);
for (const password of testPasswords) assert.equal(sql.includes(password), false);
assert.throws(() => buildMcpStagingFixtureSql([hashes[0], hashes[0]]));
const db = new DatabaseSync(":memory:");
try {
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(fs.readFileSync(schemaPath, "utf8"));
  db.exec(sql);
  assert.equal(db.prepare("PRAGMA quick_check").get().quick_check, "ok");
  assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM users").get().n, 2);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM workspaces").get().n, 2);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM workspace_members").get().n, 2);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE subscription_status = 'trialing' AND plan = 'starter' AND julianday(trial_end) > julianday('now')").get().n, 2);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM domains").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM scans").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM findings").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM user_sessions").get().n, 0);

  const d1 = {
    prepare(statement) {
      return {
        bind(...values) {
          const prepared = db.prepare(statement);
          return {
            async first() { return prepared.get(...values) ?? null; },
            async all() { return { results: prepared.all(...values) }; },
          };
        },
      };
    },
  };
  const env = { cybermeters_db: d1 };
  for (const [index, identity] of MCP_STAGING_IDENTITIES.entries()) {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(identity.userId);
    assert.equal(user.email, identity.email);
    assert.equal(user.email_verified, 1);
    assert.equal(user.status, "active");
    assert.equal(await verifyPassword(testPasswords[index], user.password_hash), true);
    assert.equal(await listMcpOAuthConsentWorkspaces(env, identity.userId), null,
      "Paused beta workspace must not appear in consent");
  }

  db.prepare("UPDATE mcp_beta_workspace_access SET status = 'enabled'").run();
  for (const identity of MCP_STAGING_IDENTITIES) {
    const workspaces = await listMcpOAuthConsentWorkspaces(env, identity.userId);
    assert.equal(workspaces.length, 1);
    assert.equal(workspaces[0].id, identity.workspaceId);
    assert.equal(workspaces[0].role, "owner");
  }
  const first = MCP_STAGING_IDENTITIES[0];
  db.prepare("DELETE FROM workspace_members WHERE user_id = ?").run(first.userId);
  assert.equal(await listMcpOAuthConsentWorkspaces(env, first.userId), null,
    "Membership removal must immediately remove consent access");
  assert.equal((await listMcpOAuthConsentWorkspaces(env, MCP_STAGING_IDENTITIES[1].userId)).length, 1);
} finally {
  db.close();
}

// When the noninteractive CLI has generated actual local artifacts, validate
// the pair without ever printing or copying its random passwords.
const artifactSql = path.join(root, "local", "mcp-staging-fixture.sql");
const artifactCredentials = path.join(root, "local", "mcp-staging-fixture-credentials.json");
if (fs.existsSync(artifactSql) || fs.existsSync(artifactCredentials)) {
  assert.equal(fs.existsSync(artifactSql) && fs.existsSync(artifactCredentials), true,
    "The generated fixture SQL and credential file must form a complete pair");
  for (const file of [artifactSql, artifactCredentials]) {
    assert.equal(fs.statSync(file).mode & 0o077, 0);
  }
  const privateSql = fs.readFileSync(artifactSql, "utf8");
  const privateCredentials = JSON.parse(fs.readFileSync(artifactCredentials, "utf8"));
  assert.equal(privateCredentials.kind, "synthetic-mcp-staging-only");
  assert.equal(privateCredentials.accounts.length, 2);
  const verificationDb = new DatabaseSync(":memory:");
  try {
    verificationDb.exec("PRAGMA foreign_keys = ON");
    verificationDb.exec(fs.readFileSync(schemaPath, "utf8"));
    verificationDb.exec(privateSql);
    for (const [index, account] of privateCredentials.accounts.entries()) {
      assert.equal(account.email, MCP_STAGING_IDENTITIES[index].email);
      assert.equal(privateSql.includes(account.password), false);
      const row = verificationDb.prepare("SELECT password_hash FROM users WHERE email = ?")
        .get(account.email);
      assert.equal(await verifyPassword(account.password, row.password_hash), true);
    }
    assert.deepEqual(verificationDb.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    verificationDb.close();
  }
}
console.log("Synthetic MCP staging fixture PASS: schema, hash, paused gate, two-tenant isolation, live membership fence, local artifact permissions.");
