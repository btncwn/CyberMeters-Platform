#!/usr/bin/env node
// Generate synthetic, isolated MCP staging identities. The output is an ignored
// local SQL artifact; this script never contacts Cloudflare or prints passwords.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hashPassword } from "../workers/scan-api/src/lib/password.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = path.join(root, "local");
const SQL_NAME = "mcp-staging-fixture.sql";
const CREDENTIALS_NAME = "mcp-staging-fixture-credentials.json";
const HASH = /^pbkdf2:sha256:100000:[a-f0-9]{32}:[a-f0-9]{64}$/;

export const MCP_STAGING_IDENTITIES = Object.freeze([
  Object.freeze({ userId: "usr_mcp_stage_a", email: "mcp-stage-a@example.invalid",
    workspaceId: "ws_mcp_stage_a", memberId: "wm_mcp_stage_a",
    workspaceName: "MCP staging A" }),
  Object.freeze({ userId: "usr_mcp_stage_b", email: "mcp-stage-b@example.invalid",
    workspaceId: "ws_mcp_stage_b", memberId: "wm_mcp_stage_b",
    workspaceName: "MCP staging B" }),
]);

function literal(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

/** Hashes come only from the platform's PBKDF2-SHA256 hasher. No raw secret is
 * accepted by this renderer or written to the SQL artifact. */
export function buildMcpStagingFixtureSql(passwordHashes) {
  if (!Array.isArray(passwordHashes) || passwordHashes.length !== 2 ||
      passwordHashes.some((hash) => typeof hash !== "string" || !HASH.test(hash)) ||
      passwordHashes[0] === passwordHashes[1]) {
    throw new Error("Expected two distinct CyberMeters password hashes");
  }
  const statements = [
    "-- Synthetic MCP staging fixture only. Never apply to production.",
    "-- Import only into a verified empty cybermeters-db-staging D1.",
    "-- Beta access starts paused; enable each row only for a controlled test.",
  ];
  for (const [index, identity] of MCP_STAGING_IDENTITIES.entries()) {
    statements.push(
      `INSERT INTO users (id, email, name, plan, password_hash, status, email_verified, email_verified_at, auth_provider) VALUES (${literal(identity.userId)}, ${literal(identity.email)}, ${literal(`Staging test ${index + 1}`)}, 'free', ${literal(passwordHashes[index])}, 'active', 1, datetime('now'), 'local');`,
      `INSERT INTO workspaces (id, name, owner_user_id) VALUES (${literal(identity.workspaceId)}, ${literal(identity.workspaceName)}, ${literal(identity.userId)});`,
      `INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (${literal(identity.memberId)}, ${literal(identity.workspaceId)}, ${literal(identity.userId)}, 'owner');`,
      `INSERT INTO mcp_beta_workspace_access (workspace_id, status, enrolled_by) VALUES (${literal(identity.workspaceId)}, 'paused', ${literal(identity.userId)});`,
      // A current, bounded Trial is required by the same live entitlement
      // decision used for customer consent; users.plan alone grants nothing.
      `INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, trial_start, trial_end) VALUES (${literal(`sub_${identity.userId}`)}, ${literal(identity.userId)}, ${literal(identity.workspaceId)}, 'starter', 'trialing', 'trialing', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+14 days'));`,
    );
  }
  return `${statements.join("\n")}\n`;
}

/** Used only for synthetic staging accounts; raw values are never logged. */
export function generateMcpStagingCredentials() {
  return {
    kind: "synthetic-mcp-staging-only",
    accounts: MCP_STAGING_IDENTITIES.map((identity) => ({
      email: identity.email,
      password: randomBytes(32).toString("base64url"),
    })),
  };
}

/** Restrict writes to the repository's ignored local/ directory (or a child
 * directory created there by the local validator). Refuse existing artifacts. */
export function writeMcpStagingFixtureArtifacts(directory, sql, credentials = null) {
  const target = path.resolve(directory);
  if (target !== outputDir && !target.startsWith(`${outputDir}${path.sep}`)) {
    throw new Error("MCP fixture artifacts must remain under ignored local/");
  }
  fs.mkdirSync(target, { recursive: true, mode: 0o700 });
  if (fs.lstatSync(outputDir).isSymbolicLink() ||
      fs.lstatSync(target).isSymbolicLink() ||
      fs.realpathSync(target) !== target) {
    throw new Error("MCP fixture artifact directory must not be a symlink");
  }
  fs.chmodSync(target, 0o700);
  const sqlPath = path.join(target, SQL_NAME);
  const credentialsPath = path.join(target, CREDENTIALS_NAME);
  if (fs.existsSync(sqlPath) || fs.existsSync(credentialsPath)) {
    throw new Error("Refusing to replace an existing MCP staging fixture artifact");
  }
  if (typeof sql !== "string" || !sql.startsWith("-- Synthetic MCP staging fixture only.")) {
    throw new Error("Invalid MCP staging fixture SQL");
  }
  if (credentials !== null &&
      (credentials.kind !== "synthetic-mcp-staging-only" ||
       !Array.isArray(credentials.accounts) || credentials.accounts.length !== 2 ||
       credentials.accounts.some((account, index) =>
         account.email !== MCP_STAGING_IDENTITIES[index].email ||
         typeof account.password !== "string" || account.password.length < 40 ||
         !/^[A-Za-z0-9_-]+$/.test(account.password)) ||
       credentials.accounts[0].password === credentials.accounts[1].password)) {
    throw new Error("Invalid synthetic MCP staging credentials");
  }
  let wroteCredentials = false;
  try {
    if (credentials !== null) {
      fs.writeFileSync(credentialsPath, `${JSON.stringify(credentials, null, 2)}\n`,
        { flag: "wx", mode: 0o600 });
      wroteCredentials = true;
    }
    fs.writeFileSync(sqlPath, sql, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (wroteCredentials) fs.rmSync(credentialsPath, { force: true });
    throw error;
  }
  return { sqlPath, credentialsPath: credentials === null ? null : credentialsPath };
}

function readHiddenPassword(prompt) {
  let fd;
  try { fd = fs.openSync("/dev/tty", "r+"); }
  catch { throw new Error("A local interactive terminal is required; no password was read"); }
  let echoOff = false;
  const restore = () => {
    if (echoOff) {
      try { execFileSync("stty", ["echo"], { stdio: [fd, "ignore", "ignore"] }); }
      catch { /* Keep the original failure; the terminal can be reset with stty echo. */ }
      echoOff = false;
    }
  };
  const interrupt = () => { restore(); process.exit(130); };
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    execFileSync("stty", ["-echo"], { stdio: [fd, "ignore", "ignore"] });
    echoOff = true;
    fs.writeSync(fd, prompt);
    const bytes = [];
    const byte = Buffer.alloc(1);
    while (bytes.length < 512) {
      if (fs.readSync(fd, byte, 0, 1, null) !== 1) break;
      if (byte[0] === 10 || byte[0] === 13) break;
      bytes.push(byte[0]);
    }
    fs.writeSync(fd, "\n");
    const password = Buffer.from(bytes).toString("utf8");
    if (password.length < 20 || password.length > 128 ||
        password !== password.trim() || /[\x00-\x1f\x7f]/.test(password)) {
      throw new Error("Use a 20–128 character password without surrounding spaces");
    }
    return password;
  } finally {
    restore();
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", interrupt);
    fs.closeSync(fd);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== "--generate-local-test-credentials")) {
    throw new Error("Usage: node scripts/generate-mcp-staging-fixture.js [--generate-local-test-credentials]");
  }
  const automatic = args[0] === "--generate-local-test-credentials";
  const existingSql = path.join(outputDir, SQL_NAME);
  const existingCredentials = path.join(outputDir, CREDENTIALS_NAME);
  if (fs.existsSync(existingSql) || fs.existsSync(existingCredentials)) {
    throw new Error("Refusing to replace an existing MCP staging fixture artifact");
  }
  const credentials = automatic ? generateMcpStagingCredentials() : null;
  const passwords = automatic ? credentials.accounts.map((account) => account.password) :
    MCP_STAGING_IDENTITIES.map((identity) =>
      readHiddenPassword(`Password for ${identity.email} (hidden): `));
  if (passwords[0] === passwords[1]) throw new Error("Use distinct passwords for the two accounts");
  const hashes = await Promise.all(passwords.map(hashPassword));
  const sql = buildMcpStagingFixtureSql(hashes);
  const artifacts = writeMcpStagingFixtureArtifacts(outputDir, sql, credentials);
  console.log(`Generated ${artifacts.sqlPath} with two synthetic, paused MCP beta workspaces.`);
  if (automatic) console.log(`Test credentials saved only in ignored ${artifacts.credentialsPath} (0600).`);
  else console.log("Passwords were neither printed nor saved; the operator must retain their entered values securely.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
