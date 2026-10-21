import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { hashToken } from "../src/lib/auth-crypto.js";
import { hashPassword } from "../src/lib/password.js";
import { authRoutes } from "../src/routes/auth.js";
import {
  admitMcpOAuthToken, canGrantMcpPortfolio, isMcpOAuthClientAllowed, mcpCimdEnabled,
  listMcpOAuthConnections,
  listMcpOAuthConsentWorkspaces, reconcileMcpOAuthPortfolioPlan,
  reconcileMcpOAuthPortfolioSubscription,
  MCP_OAUTH_RESOURCE, sameMcpOAuthAuthorizationRequest,
  validMcpOAuthAuthorizationRequest,
} from "../src/routes/mcp-oauth-admission.js";
import { applyMcpDcrDefaults, evaluateMcpDcrRegistration, isMcpDcrLoopbackRedirect } from "../src/routes/mcp-oauth-dcr.js";
import {
  drainRevokedMcpOAuthGrantBacklog, MCP_OAUTH_KV_IO_BUDGET,
  revokeMcpOAuthUserGrantsForPurge, revokeMcpOAuthUserWorkspaceConnections,
  revokeMcpOAuthWorkspaceConnections,
} from "../src/routes/mcp-oauth-purge.js";
import {
  bridgeMcpOAuthBrowserSession, claimMcpOAuthBrowserSession,
  claimMcpOAuthStartBudget, claimMcpOAuthTokenBudget, createMcpOAuthIntent,
  purgeExpiredMcpOAuthBrowserRows, readBoundedMcpOAuthBody,
  readMcpOAuthBrowserSession, readMcpOAuthIntent, requireMcpWebSession,
} from "../src/routes/mcp-oauth-browser.js";

function fixture() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec(`
    CREATE TABLE users(id TEXT PRIMARY KEY, status TEXT, email_verified INTEGER);
    CREATE TABLE workspaces(id TEXT PRIMARY KEY, name TEXT, deleted_at TEXT, owner_user_id TEXT);
    CREATE TABLE workspace_members(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, role TEXT);
    CREATE TABLE user_sessions(id TEXT PRIMARY KEY, user_id TEXT, token_hash TEXT, expires_at TEXT);
    CREATE TABLE deletion_requests(id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT,
      workspace_id TEXT, status TEXT);
    CREATE TABLE subscriptions(id TEXT PRIMARY KEY, workspace_id TEXT, owner_user_id TEXT,
      plan TEXT, status TEXT, subscription_status TEXT, trial_end TEXT, expires_at TEXT,
      current_period_end TEXT, payment_failed_at TEXT, stripe_subscription_id TEXT,
      created_at TEXT, updated_at TEXT);
  `);
  const migration = fileURLToPath(new URL("../../../database/migrations/121-mcp-oauth.sql", import.meta.url));
  sqlite.exec(readFileSync(migration, "utf8"));
  const selectedMigration = fileURLToPath(new URL("../../../database/migrations/124-mcp-oauth-selected-workspaces.sql", import.meta.url));
  sqlite.exec(readFileSync(selectedMigration, "utf8"));
  const rate = fileURLToPath(new URL("../../../database/migrations/026-api-rate-limits.sql", import.meta.url));
  sqlite.exec(readFileSync(rate, "utf8"));
  sqlite.exec(`
    INSERT INTO users VALUES ('u1','active',1),('u2','active',1);
    INSERT INTO workspaces VALUES ('w1','One',NULL,'u1'),('w2','Two',NULL,'u2');
    INSERT INTO workspace_members VALUES ('wm1','w1','u1','viewer'),('wm2','w2','u2','owner');
    INSERT INTO mcp_beta_workspace_access(workspace_id,status) VALUES ('w1','enabled'),('w2','enabled');
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('c1','u1','client','https://mcp.cybermeters.com/mcp','w1',0,'["mcp:read"]');
    INSERT INTO subscriptions(id,workspace_id,owner_user_id,plan,status,
      subscription_status,trial_end,created_at) VALUES
      ('trial_u1','w1','u1','professional','trialing','trialing','2099-01-01','2026-01-01');
  `);
  const db = {
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      return { bind(...args) { return {
        first: async () => statement.get(...args) ?? null,
        all: async () => ({ results: statement.all(...args) }),
        run: async () => ({ meta: { changes: Number(statement.run(...args).changes) } }),
      }; } };
    },
  };
  return { sqlite, env: { cybermeters_db: db, MCP_DEPLOYMENT_TIER: "staging" } };
}

function token(overrides = {}) {
  return {
    props: { userId: "u1", connectionId: "c1", workspaceId: "w1", portfolioRead: false },
    audience: MCP_OAUTH_RESOURCE, scope: ["mcp:read"], userId: "u1", clientId: "client",
    ...overrides,
  };
}

test("OAuth token is bound to active connection, user, membership, beta and audience", async () => {
  const { sqlite, env } = fixture();
  assert.ok(await admitMcpOAuthToken(env, token()));
  assert.equal(await admitMcpOAuthToken(env, token({ audience: "https://other.example/mcp" })), null);
  assert.equal(await admitMcpOAuthToken(env, token({ props: { ...token().props, workspaceId: "w2" } })), null);
  assert.equal(await admitMcpOAuthToken(env, token({ clientId: "other" })), null);
  assert.equal(await admitMcpOAuthToken(env, token({ scope: ["mcp:write"] })), null);
  sqlite.exec("DELETE FROM workspace_members WHERE id = 'wm1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  sqlite.exec("INSERT INTO workspace_members VALUES ('wm1','w1','u1','viewer')");
  sqlite.exec("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'w1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  sqlite.exec("UPDATE workspaces SET deleted_at = NULL WHERE id = 'w1'");
  sqlite.exec("UPDATE mcp_beta_workspace_access SET status = 'paused' WHERE workspace_id = 'w1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  sqlite.exec("UPDATE mcp_beta_workspace_access SET status = 'enabled' WHERE workspace_id = 'w1'");
  sqlite.exec("UPDATE mcp_oauth_connections SET status = 'revoked' WHERE id = 'c1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
});

test("production founder canary requires its owner secret and current workspace ownership", async () => {
  const { sqlite, env } = fixture();
  delete env.MCP_DEPLOYMENT_TIER;
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null,
    "missing deployment tier must retain the founder fence");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  env.MCP_DEPLOYMENT_TIER = "production";
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null);
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  env.MCP_FOUNDER_CANARY_USER_ID = "u1";
  assert.deepEqual((await listMcpOAuthConsentWorkspaces(env, "u1")).map((row) => row.id), ["w1"]);
  assert.ok(await admitMcpOAuthToken(env, token()));
  sqlite.exec(`INSERT INTO subscriptions(id,workspace_id,owner_user_id,plan,status,
    subscription_status,trial_end,created_at) VALUES
    ('trial_u2','w2','u2','professional','trialing','trialing','2099-01-01','2026-01-01');
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('c_u2','u2','client','https://mcp.cybermeters.com/mcp','w2',0,
        '["mcp:read"]');`);
  const otherToken = token({ userId: "u2", props: {
    userId: "u2", connectionId: "c_u2", workspaceId: "w2", portfolioRead: false,
  } });
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u2"), null);
  assert.equal(await admitMcpOAuthToken(env, otherToken), null);
  sqlite.exec("INSERT INTO workspace_members VALUES ('wm_extra','w1','u2','viewer')");
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u2"), null);
  sqlite.exec(`INSERT INTO mcp_oauth_connections
    (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
    VALUES ('c_member','u2','client','https://mcp.cybermeters.com/mcp','w1',0,
      '["mcp:read"]')`);
  assert.equal(await admitMcpOAuthToken(env, token({ userId: "u2", props: {
    userId: "u2", connectionId: "c_member", workspaceId: "w1", portfolioRead: false,
  } })), null);
  sqlite.exec("UPDATE workspaces SET owner_user_id='u2' WHERE id='w1'");
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null);
  assert.equal(await admitMcpOAuthToken(env, token()), null);
});

test("MCP_CUSTOMER_ACCESS=customers opens MCP to entitled members; every other check stays", async () => {
  const { sqlite, env } = fixture();
  env.MCP_DEPLOYMENT_TIER = "production";
  // u2 is not the founder, owns w2 on a live trial and has no enrolment row.
  sqlite.exec(`INSERT INTO subscriptions(id,workspace_id,owner_user_id,plan,status,
    subscription_status,trial_end,created_at) VALUES
    ('trial_u2','w2','u2','professional','trialing','trialing','2099-01-01','2026-01-01');
    DELETE FROM mcp_beta_workspace_access WHERE workspace_id = 'w2';
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('c_u2','u2','client','https://mcp.cybermeters.com/mcp','w2',0,'["mcp:read"]');`);
  const customer = token({ userId: "u2", props: {
    userId: "u2", connectionId: "c_u2", workspaceId: "w2", portfolioRead: false,
  } });
  // Not set, or any other value: the founder fence holds.
  for (const value of [undefined, "", "founder", "CUSTOMERS", "true"]) {
    env.MCP_CUSTOMER_ACCESS = value;
    assert.equal(await listMcpOAuthConsentWorkspaces(env, "u2"), null, String(value));
    assert.equal(await admitMcpOAuthToken(env, customer), null, String(value));
  }
  env.MCP_CUSTOMER_ACCESS = "customers";
  assert.deepEqual((await listMcpOAuthConsentWorkspaces(env, "u2")).map((row) => row.id), ["w2"]);
  assert.ok(await admitMcpOAuthToken(env, customer));
  // A member who is not the owner (u1 is a viewer of w1) is admitted too.
  assert.ok(await admitMcpOAuthToken(env, token()));
  // A paused workspace is closed.
  sqlite.exec("INSERT INTO mcp_beta_workspace_access(workspace_id,status) VALUES ('w2','paused')");
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u2"), null);
  assert.equal(await admitMcpOAuthToken(env, customer), null);
  sqlite.exec("DELETE FROM mcp_beta_workspace_access WHERE workspace_id = 'w2'");
  // Membership, plan, deletion and the connection are still checked on every read.
  sqlite.exec("UPDATE subscriptions SET trial_end = '2001-01-01' WHERE id = 'trial_u2'");
  assert.equal(await admitMcpOAuthToken(env, customer), null, "expired trial");
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u2"), null);
  sqlite.exec("UPDATE subscriptions SET trial_end = '2099-01-01' WHERE id = 'trial_u2'");
  sqlite.exec("DELETE FROM workspace_members WHERE id = 'wm2'");
  assert.equal(await admitMcpOAuthToken(env, customer), null, "no membership");
  sqlite.exec("INSERT INTO workspace_members VALUES ('wm2','w2','u2','owner')");
  sqlite.exec("INSERT INTO deletion_requests VALUES ('d1','workspace','u2','w2','pending')");
  assert.equal(await admitMcpOAuthToken(env, customer), null, "workspace being deleted");
  sqlite.exec("DELETE FROM deletion_requests WHERE id = 'd1'");
  sqlite.exec("UPDATE users SET email_verified = 0 WHERE id = 'u2'");
  assert.equal(await admitMcpOAuthToken(env, customer), null, "unverified user");
  sqlite.exec("UPDATE users SET email_verified = 1 WHERE id = 'u2'");
  sqlite.exec("UPDATE mcp_oauth_connections SET status = 'revoked' WHERE id = 'c_u2'");
  assert.equal(await admitMcpOAuthToken(env, customer), null, "revoked connection");
  // A token for another tenant's workspace is never admitted.
  sqlite.exec("UPDATE mcp_oauth_connections SET status = 'active' WHERE id = 'c_u2'");
  assert.equal(await admitMcpOAuthToken(env, token({ userId: "u2", props: {
    userId: "u2", connectionId: "c_u2", workspaceId: "w1", portfolioRead: false,
  } })), null);
  assert.ok(await admitMcpOAuthToken(env, customer));
  // Staging keeps its own rule: synthetic users, enrolment rows required.
  env.MCP_DEPLOYMENT_TIER = "staging";
  assert.equal(await admitMcpOAuthToken(env, customer), null, "staging needs an 'enabled' row");
});

test("production founder portfolio grant fails after a selected workspace changes owner", async () => {
  const { sqlite, env } = fixture();
  env.MCP_DEPLOYMENT_TIER = "production";
  env.MCP_FOUNDER_CANARY_USER_ID = "u1";
  sqlite.exec(`INSERT INTO subscriptions(id,owner_user_id,plan,status,subscription_status,
    current_period_end,created_at) VALUES
    ('paid_u1','u1','business','active','active','2099-01-01','2026-01-01');
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('c2','u1','client','https://mcp.cybermeters.com/mcp',NULL,1,
        '["mcp:read","portfolio:read"]');
    INSERT INTO mcp_oauth_connection_workspaces VALUES ('c2','w1');`);
  const selected = token({
    props: { userId: "u1", connectionId: "c2", workspaceId: null, portfolioRead: true },
    scope: ["mcp:read", "portfolio:read"],
  });
  assert.ok(await admitMcpOAuthToken(env, selected));
  sqlite.exec("UPDATE workspaces SET owner_user_id='u2' WHERE id='w1'");
  assert.equal(await admitMcpOAuthToken(env, selected), null);
});

test("single-workspace OAuth read denies when current plan state cannot be resolved", async () => {
  const { sqlite, env } = fixture();
  assert.ok(await admitMcpOAuthToken(env, token()));
  sqlite.exec("DROP TABLE subscriptions");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
});

test("single-workspace beta admits a live trial but denies expired trial or free account", async () => {
  const { sqlite, env } = fixture();
  assert.ok(await admitMcpOAuthToken(env, token()));
  sqlite.exec("UPDATE subscriptions SET plan = 'free' WHERE id = 'trial_u1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  sqlite.exec("UPDATE subscriptions SET plan = 'professional' WHERE id = 'trial_u1'");
  sqlite.exec("UPDATE subscriptions SET trial_end = '2020-01-01' WHERE id = 'trial_u1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null);
  sqlite.exec("DELETE FROM subscriptions WHERE id = 'trial_u1'");
  assert.equal(await admitMcpOAuthToken(env, token()), null);
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null);
  sqlite.exec(`INSERT INTO subscriptions(id,workspace_id,owner_user_id,plan,status,
    subscription_status,current_period_end,created_at) VALUES
    ('paid_u1','w1','u1','starter','active','active','2099-01-01','2026-01-01')`);
  assert.ok(await admitMcpOAuthToken(env, token()));
});

test("CIMD requires an exact reviewed client ID and removal fences existing tokens", async () => {
  const { sqlite, env } = fixture();
  const approved = "https://client.example/oauth/metadata.json";
  assert.equal(isMcpOAuthClientAllowed(env, "opaque-dcr-client"), true);
  assert.equal(isMcpOAuthClientAllowed(env, approved), false);
  env.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS = JSON.stringify([approved]);
  for (const flag of [undefined, "false", "TRUE", true, "1"]) {
    env.MCP_OAUTH_CIMD_ENABLED = flag;
    assert.equal(mcpCimdEnabled(env), false);
    assert.equal(isMcpOAuthClientAllowed(env, approved), false);
  }
  env.MCP_OAUTH_CIMD_ENABLED = "true";
  assert.equal(mcpCimdEnabled(env), true);
  assert.equal(isMcpOAuthClientAllowed(env, approved), true);
  for (const other of [
    "https://client.example/oauth/other.json",
    "https://client.example/oauth/metadata.json?changed=1",
    "https://evil.example/oauth/metadata.json",
    "https://client.example/",
    "http://client.example/oauth/metadata.json",
    "ftp://client.example/oauth/metadata.json",
    "https:client.example/oauth/metadata.json",
    " https://client.example/oauth/metadata.json",
    "opaque/client",
    "opaque:client",
  ]) assert.equal(isMcpOAuthClientAllowed(env, other), false, other);
  sqlite.exec(`UPDATE mcp_oauth_connections SET client_id = '${approved}' WHERE id = 'c1'`);
  assert.ok(await admitMcpOAuthToken(env, token({ clientId: approved })));
  env.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS = "[]";
  assert.equal(await admitMcpOAuthToken(env, token({ clientId: approved })), null);
  env.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS = "not-json";
  assert.equal(isMcpOAuthClientAllowed(env, approved), false);
});

test("portfolio access requires separate scope, paid entitlement, current enrolled membership", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO mcp_oauth_connections
    (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
    VALUES ('c2','u1','client','https://mcp.cybermeters.com/mcp',NULL,1,'["mcp:read","portfolio:read"]')`);
  sqlite.exec("INSERT INTO mcp_oauth_connection_workspaces VALUES ('c2','w1')");
  const portfolio = token({
    props: { userId: "u1", connectionId: "c2", workspaceId: null, portfolioRead: true },
    scope: ["mcp:read", "portfolio:read"],
  });
  assert.equal(await canGrantMcpPortfolio(env, "u1"), false);
  assert.equal(await admitMcpOAuthToken(env, portfolio), null);
  assert.equal(sqlite.prepare("SELECT status FROM mcp_oauth_connections WHERE id='c2'").get().status,
    "revoked", "a lower-plan portfolio grant is fenced and requires fresh consent");
  sqlite.exec("UPDATE mcp_oauth_connections SET status='active', revoked_at=NULL WHERE id='c2'");
  sqlite.exec(`INSERT INTO subscriptions(id,owner_user_id,plan,status,subscription_status,
    current_period_end,created_at) VALUES
    ('sub1','u1','business','active','active','2099-01-01','2026-01-01')`);
  assert.equal(await canGrantMcpPortfolio(env, "u1"), true);
  assert.ok(await admitMcpOAuthToken(env, portfolio));
  sqlite.exec("INSERT INTO workspace_members VALUES ('wm3','w2','u1','viewer')");
  assert.ok(await admitMcpOAuthToken(env, portfolio), "new membership must not widen the selected set");
  assert.equal(await admitMcpOAuthToken(env, { ...portfolio, scope: ["mcp:read"] }), null);
  sqlite.exec("DELETE FROM workspace_members WHERE user_id = 'u1'");
  assert.equal(await admitMcpOAuthToken(env, portfolio), null);
});

test("plan downgrade revokes portfolio connections while preserving single-workspace consent", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO subscriptions(id,workspace_id,owner_user_id,plan,status,
    subscription_status,current_period_end,created_at) VALUES
    ('paid_u1','w2','u1','business','active','active','2099-01-01','2026-01-01');
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('c2','u1','client','https://mcp.cybermeters.com/mcp',NULL,1,
        '["mcp:read","portfolio:read"]');
    INSERT INTO mcp_oauth_connection_workspaces VALUES ('c2','w1');`);
  const portfolio = token({
    props: { userId: "u1", connectionId: "c2", workspaceId: null, portfolioRead: true },
    scope: ["mcp:read", "portfolio:read"],
  });
  assert.ok(await admitMcpOAuthToken(env, portfolio));
  sqlite.exec("UPDATE subscriptions SET plan = 'professional' WHERE id = 'paid_u1'");
  assert.deepEqual(await reconcileMcpOAuthPortfolioSubscription(env, "paid_u1"), { revoked: 1 });
  assert.deepEqual(await reconcileMcpOAuthPortfolioPlan(env, "u1"), { revoked: 0 });
  assert.deepEqual(sqlite.prepare(
    "SELECT id, status FROM mcp_oauth_connections ORDER BY id",
  ).all().map(({ id, status }) => ({ id, status })),
  [{ id: "c1", status: "active" }, { id: "c2", status: "revoked" }]);
  assert.equal(sqlite.prepare(
    "SELECT kv_cleanup_pending FROM mcp_oauth_connections WHERE id='c2'",
  ).get().kv_cleanup_pending, 1);
  assert.equal(await admitMcpOAuthToken(env, portfolio), null);
  assert.ok(await admitMcpOAuthToken(env, token()));
  sqlite.exec("UPDATE subscriptions SET plan = 'business' WHERE id = 'paid_u1'");
  assert.equal(await admitMcpOAuthToken(env, portfolio), null,
    "upgrading must not silently restore the revoked portfolio grant");
});

test("membership and workspace lifecycle revoke direct and selected grants without cross-tenant effect", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec("DELETE FROM mcp_oauth_connections");
  const ids = [1, 2, 3, 4].map((n) => `mcpconn_00000000-0000-4000-8000-${String(n).padStart(12, "0")}`);
  const insert = sqlite.prepare(`INSERT INTO mcp_oauth_connections
    (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
    VALUES (?,?,?,?,?,?,?)`);
  insert.run(ids[0], "u1", "client", MCP_OAUTH_RESOURCE, "w1", 0, '["mcp:read"]');
  insert.run(ids[1], "u1", "client", MCP_OAUTH_RESOURCE, null, 1, '["mcp:read","portfolio:read"]');
  insert.run(ids[2], "u1", "client", MCP_OAUTH_RESOURCE, "w2", 0, '["mcp:read"]');
  insert.run(ids[3], "u2", "client", MCP_OAUTH_RESOURCE, "w2", 0, '["mcp:read"]');
  sqlite.prepare("INSERT INTO mcp_oauth_connection_workspaces VALUES (?, 'w1'), (?, 'w2')")
    .run(ids[1], ids[1]);
  const grants = ids.map((id, index) => ({ id: `grant_${index}`, userId: index === 3 ? "u2" : "u1",
    metadata: { connectionId: id } }));
  env.OAUTH_KV = {};
  env.MCP_OAUTH_PURGE_API = {
    async listUserGrants(userId) { return { items: grants.filter((grant) => grant.userId === userId) }; },
    async revokeGrant(id, userId) {
      const index = grants.findIndex((grant) => grant.id === id && grant.userId === userId);
      if (index < 0) throw new Error("unknown_grant");
      grants.splice(index, 1);
    },
  };
  await revokeMcpOAuthUserWorkspaceConnections(env, "u1", "w1");
  assert.deepEqual(sqlite.prepare("SELECT id FROM mcp_oauth_connections WHERE status='revoked' ORDER BY id").all()
    .map((row) => row.id), ids.slice(0, 2));
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_connections WHERE kv_cleanup_pending=1").get().n, 1);
  await revokeMcpOAuthWorkspaceConnections(env, "w2");
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_connections WHERE status='active'").get().n, 0);
  for (let attempt = 0; attempt < ids.length; attempt++) {
    await drainRevokedMcpOAuthGrantBacklog(env);
  }
  assert.equal(grants.length, 0);
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_connections WHERE kv_cleanup_pending=1").get().n, 0);
});

test("workspace lifecycle fences more than 20 grants, then drains direct grant IDs without repeated scans", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec("DELETE FROM mcp_oauth_connections");
  const insert = sqlite.prepare(`INSERT INTO mcp_oauth_connections
    (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes,oauth_grant_id)
    VALUES (?,?,?,?,?,0,'["mcp:read"]',?)`);
  const grants = new Set();
  for (let n = 1; n <= 21; n++) {
    const grantId = String(n).padStart(16, "0");
    grants.add(grantId);
    insert.run(
    `mcpconn_00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    "u1", "client", MCP_OAUTH_RESOURCE, "w1", grantId);
  }
  env.OAUTH_KV = {};
  env.MCP_OAUTH_PURGE_API = {
    async listUserGrants() { throw new Error("full_user_sweep_not_allowed"); },
    async revokeGrant(grantId) { assert.equal(grants.delete(grantId), true); },
  };
  assert.deepEqual(await revokeMcpOAuthWorkspaceConnections(env, "w1"), { revoked: 21 });
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_connections WHERE status='active'").get().n, 0);
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_connections WHERE kv_cleanup_pending=1").get().n, 20);
  for (let attempt = 0; attempt < 20; attempt++) {
    assert.deepEqual(await drainRevokedMcpOAuthGrantBacklog(env), { processed: 1, pending: true });
  }
  assert.equal(grants.size, 0);
  assert.deepEqual(await drainRevokedMcpOAuthGrantBacklog(env), { processed: 0, pending: false });
});

test("KV grant cleanup caps a single invocation and reports incomplete purge", async () => {
  const { env } = fixture();
  env.OAUTH_KV = {};
  let revoked = 0;
  env.MCP_OAUTH_PURGE_API = {
    async listUserGrants(_userId, { cursor }) {
      const offset = Number(cursor ?? 0);
      const end = Math.min(offset + 25, 101);
      return { items: Array.from({ length: end - offset }, (_, index) => ({
        id: `grant_${offset + index}`,
      })), cursor: end < 101 ? String(end) : undefined };
    },
    async revokeGrant() { revoked++; },
  };
  await assert.rejects(revokeMcpOAuthUserGrantsForPurge(env, "u1"),
    /mcp_oauth_purge_incomplete/);
  assert.ok(revoked > 0 && revoked < 25, "a bounded invocation must make partial progress only");
  assert.ok(26 + revoked * 2 <= MCP_OAUTH_KV_IO_BUDGET);
});

async function authLifecycleFixture() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(`
    CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT, password_hash TEXT,
      mfa_enabled INTEGER, mfa_enabled_at TEXT, totp_secret TEXT,
      mfa_recovery_codes_hash_json TEXT, mfa_last_verified_at TEXT);
    CREATE TABLE password_reset_tokens(id TEXT PRIMARY KEY, user_id TEXT,
      token_hash TEXT, expires_at TEXT, used_at TEXT);
    CREATE TABLE user_sessions(id TEXT PRIMARY KEY, user_id TEXT);
    CREATE TABLE api_tokens(id TEXT PRIMARY KEY, user_id TEXT, status TEXT);
    CREATE TABLE mcp_oauth_connections(id TEXT PRIMARY KEY, user_id TEXT,
      status TEXT, revoked_at TEXT);
    CREATE TABLE audit_events(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
      actor_type TEXT, event_type TEXT, entity_type TEXT, entity_id TEXT,
      description TEXT, metadata_json TEXT, created_at TEXT);
  `);
  const originalHash = await hashPassword("OriginalSecurePassword2026!");
  sqlite.prepare("INSERT INTO users VALUES ('u1','owner@example.com',?,1,NULL,NULL,NULL,NULL)")
    .run(originalHash);
  sqlite.prepare("INSERT INTO password_reset_tokens VALUES ('reset1','u1',?,'2099-01-01',NULL)")
    .run(await hashToken("reset-secret-1"));
  sqlite.exec(`INSERT INTO user_sessions VALUES ('session1','u1');
    INSERT INTO api_tokens VALUES ('api1','u1','active');
    INSERT INTO mcp_oauth_connections VALUES ('conn1','u1','active',NULL);`);
  const db = {
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      const bound = (...values) => ({
        first: async () => statement.get(...values) ?? null,
        all: async () => ({ results: statement.all(...values) }),
        run: async () => ({ meta: { changes: Number(statement.run(...values).changes) } }),
      });
      return { ...bound(), bind: bound };
    },
    async batch(statements) {
      sqlite.exec("BEGIN");
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        sqlite.exec("COMMIT");
        return results;
      } catch (error) { sqlite.exec("ROLLBACK"); throw error; }
    },
  };
  const env = { cybermeters_db: db };
  const route = async (path, body) => {
    const url = new URL(`https://api.cybermeters.com${path}`);
    const request = new Request(url, { method: "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return authRoutes({ request, url, env,
      json: (value, status = 200) => Response.json(value, { status }),
      serverError: (_area, error) => Response.json({ error: String(error?.message ?? error) }, { status: 503 }),
      requireAuth: async () => ({ id: "u1", email: "owner@example.com", api_token_id: null }),
      consumeApiRateLimit: async () => null,
      rateLimitScopeId: async () => "test",
    });
  };
  return { sqlite, env, route, originalHash };
}

test("password reset atomically revokes MCP, session, and API credentials", async () => {
  const f = await authLifecycleFixture();
  try {
    const response = await f.route("/api/auth/reset-password",
      { token: "reset-secret-1", password: "DistinctLongPassword2026!" });
    assert.equal(response.status, 200, await response.clone().text());
    assert.notEqual(f.sqlite.prepare("SELECT password_hash FROM users WHERE id='u1'").get().password_hash,
      f.originalHash);
    assert.equal(f.sqlite.prepare("SELECT COUNT(*) AS n FROM user_sessions").get().n, 0);
    assert.equal(f.sqlite.prepare("SELECT status FROM api_tokens WHERE id='api1'").get().status, "revoked");
    assert.equal(f.sqlite.prepare("SELECT status FROM mcp_oauth_connections WHERE id='conn1'").get().status, "revoked");
    assert.ok(f.sqlite.prepare("SELECT used_at FROM password_reset_tokens WHERE id='reset1'").get().used_at);
  } finally { f.sqlite.close(); }
});

test("MCP revoke write failure rolls back the whole password reset", async () => {
  const f = await authLifecycleFixture();
  try {
    f.sqlite.exec(`CREATE TRIGGER block_mcp_reset BEFORE UPDATE ON mcp_oauth_connections
      BEGIN SELECT RAISE(ABORT, 'mcp write unavailable'); END`);
    const response = await f.route("/api/auth/reset-password",
      { token: "reset-secret-1", password: "DistinctLongPassword2026!" });
    assert.equal(response.status, 503);
    assert.equal(f.sqlite.prepare("SELECT password_hash FROM users WHERE id='u1'").get().password_hash,
      f.originalHash);
    assert.equal(f.sqlite.prepare("SELECT COUNT(*) AS n FROM user_sessions").get().n, 1);
    assert.equal(f.sqlite.prepare("SELECT status FROM api_tokens WHERE id='api1'").get().status, "active");
    assert.equal(f.sqlite.prepare("SELECT status FROM mcp_oauth_connections WHERE id='conn1'").get().status, "active");
    assert.equal(f.sqlite.prepare("SELECT used_at FROM password_reset_tokens WHERE id='reset1'").get().used_at, null);
  } finally { f.sqlite.close(); }
});

test("MFA disable revokes MCP connection in the same D1 batch", async () => {
  const f = await authLifecycleFixture();
  try {
    const response = await f.route("/api/auth/mfa/disable",
      { password: "OriginalSecurePassword2026!" });
    assert.equal(response.status, 200, await response.clone().text());
    assert.equal(f.sqlite.prepare("SELECT mfa_enabled FROM users WHERE id='u1'").get().mfa_enabled, 0);
    assert.equal(f.sqlite.prepare("SELECT status FROM mcp_oauth_connections WHERE id='conn1'").get().status, "revoked");
  } finally { f.sqlite.close(); }
});

test("consent lists only live enrolled tenant memberships", async () => {
  const { sqlite, env } = fixture();
  assert.deepEqual((await listMcpOAuthConsentWorkspaces(env, "u1")).map((w) => w.id), ["w1"]);
  sqlite.exec("UPDATE users SET status = 'suspended' WHERE id = 'u1'");
  assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null);
});

test("pending account and workspace deletion immediately fence OAuth reads and consent", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO deletion_requests VALUES ('d1','workspace','u1','w1','pending')`);
  for (const status of ["pending", "purging", "blocked_active_subscription", "blocked_residual_data"]) {
    sqlite.prepare("UPDATE deletion_requests SET status = ? WHERE id = 'd1'").run(status);
    assert.equal(await admitMcpOAuthToken(env, token()), null, status);
    assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null, status);
  }
  sqlite.exec(`UPDATE deletion_requests SET status = 'cancelled' WHERE id = 'd1'`);
  assert.ok(await admitMcpOAuthToken(env, token()));
  sqlite.exec(`INSERT INTO deletion_requests VALUES ('d2','account','u1',NULL,'pending')`);
  for (const status of ["pending", "purging", "blocked_active_subscription", "blocked_residual_data"]) {
    sqlite.prepare("UPDATE deletion_requests SET status = ? WHERE id = 'd2'").run(status);
    assert.equal(await admitMcpOAuthToken(env, token()), null, status);
    assert.equal(await listMcpOAuthConsentWorkspaces(env, "u1"), null, status);
  }
});

test("authorization requires explicit read scope and S256 for every client", () => {
  const request = { responseType: "code", resource: MCP_OAUTH_RESOURCE,
    codeChallengeMethod: "S256", codeChallenge: "a".repeat(43), scope: ["mcp:read"] };
  assert.equal(validMcpOAuthAuthorizationRequest(request), true);
  assert.equal(validMcpOAuthAuthorizationRequest({ ...request, scope: [] }), false);
  assert.equal(validMcpOAuthAuthorizationRequest({ ...request, scope: ["portfolio:read"] }), false);
  assert.equal(validMcpOAuthAuthorizationRequest({ ...request, codeChallengeMethod: "plain" }), false);
  assert.equal(validMcpOAuthAuthorizationRequest({ ...request, resource: "https://other.example/mcp" }), false);
});

test("deployment tier selects only canonical production or staging OAuth origins", async () => {
  const { resolveMcpOAuthConfig } = await import("../src/routes/mcp-oauth-admission.js");
  assert.deepEqual(resolveMcpOAuthConfig({ MCP_DEPLOYMENT_TIER: "staging" }), {
    issuer: "https://api-staging.cybermeters.com",
    resource: "https://mcp-staging.cybermeters.com/mcp",
    appOrigin: "https://app-staging.cybermeters.com",
  });
  assert.deepEqual(resolveMcpOAuthConfig({ MCP_DEPLOYMENT_TIER: "production" }), {
    issuer: "https://api.cybermeters.com", resource: MCP_OAUTH_RESOURCE,
    appOrigin: "https://app.cybermeters.com",
  });
  assert.throws(() => resolveMcpOAuthConfig({ MCP_DEPLOYMENT_TIER: "prod" }));
  assert.throws(() => resolveMcpOAuthConfig({ MCP_STAGING_ISSUER: "https://evil.example" }));
  assert.throws(() => resolveMcpOAuthConfig({ MCP_DEPLOYMENT_TIER: "staging",
    MCP_STAGING_ISSUER: "https://evil.example" }));
});

test("consent handle cannot switch state, PKCE, scope or another authorization request", () => {
  const expected = {
    responseType: "code", clientId: "client", redirectUri: "http://localhost:7777/callback",
    state: "state-1", codeChallenge: "a".repeat(43), codeChallengeMethod: "S256",
    resource: MCP_OAUTH_RESOURCE, issuer: "https://api.cybermeters.com",
    scope: ["mcp:read", "offline_access"],
  };
  assert.equal(sameMcpOAuthAuthorizationRequest(expected, { ...expected }), true);
  for (const changed of [
    { state: "state-2" }, { codeChallenge: "b".repeat(43) },
    { codeChallengeMethod: "plain" }, { scope: ["mcp:read"] },
    { clientId: "other" }, { redirectUri: "http://localhost:7778/callback" },
    { resource: "https://other.example/mcp" },
  ]) {
    assert.equal(sameMcpOAuthAuthorizationRequest(expected, { ...expected, ...changed }), false);
  }
});

test("DCR accepts bounded loopback, rejects hosted callbacks unless explicitly allowed", async () => {
  const { sqlite, env } = fixture();
  const disabledRequest = new Request("https://api.cybermeters.com/oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.6" }, body: "{}",
  });
  for (const flag of [undefined, "false", "TRUE", true, "1"]) {
    env.MCP_OAUTH_DCR_ENABLED = flag;
    assert.equal((await evaluateMcpDcrRegistration({ request: disabledRequest,
      clientMetadata: {} }, env)).status, 403);
  }
  env.MCP_OAUTH_DCR_ENABLED = "true";
  env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = "true";
  assert.equal(isMcpDcrLoopbackRedirect("http://localhost:7777/oauth/callback"), true);
  assert.equal(isMcpDcrLoopbackRedirect("http://127.0.0.1:49152/callback"), true);
  assert.equal(isMcpDcrLoopbackRedirect("http://[::1]:49152/oauth/callback"), true);
  assert.equal(isMcpDcrLoopbackRedirect("http://localhost:80/callback"), false);
  assert.equal(isMcpDcrLoopbackRedirect("http://localhost:7777/callback?token=1"), false);
  assert.equal(isMcpDcrLoopbackRedirect("http://evil.example:7777/callback"), false);
  const request = new Request("https://api.cybermeters.com/oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.6" }, body: "{}",
  });
  const metadata = { client_name: "Local Client", redirect_uris: ["http://localhost:7777/oauth/callback"],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"], response_types: ["code"] };
  assert.equal(await evaluateMcpDcrRegistration({ request, clientMetadata: metadata }, env), undefined);
  for (const flag of [undefined, "false", "TRUE", true, "1"]) {
    env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = flag;
    sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
    assert.equal((await evaluateMcpDcrRegistration({ request, clientMetadata: metadata }, env)).status, 400);
  }
  env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = "true";
  for (const changed of [
    { token_endpoint_auth_method: "client_secret_basic" },
    { token_endpoint_auth_method: undefined },
    { token_endpoint_auth_methods_supported: ["none", "client_secret_post"] },
    { grant_types: ["refresh_token"] },
    { grant_types: ["authorization_code", "authorization_code"] },
    { response_types: [] },
  ]) {
    sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
    assert.equal((await evaluateMcpDcrRegistration({ request,
      clientMetadata: { ...metadata, ...changed } }, env)).status, 400);
  }
  sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
  assert.equal((await evaluateMcpDcrRegistration({ request, clientMetadata: {
    ...metadata, redirect_uris: ["https://example.com/callback"] } }, env)).status, 400);
  env.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS = '["https://example.com/callback"]';
  sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
  assert.equal(await evaluateMcpDcrRegistration({ request, clientMetadata: {
    ...metadata, redirect_uris: ["https://example.com/callback"] } }, env), undefined);
  env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = "false";
  assert.equal((await evaluateMcpDcrRegistration({ request, clientMetadata: metadata }, env)).status, 400);
  sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
  assert.equal(await evaluateMcpDcrRegistration({ request, clientMetadata: {
    ...metadata, redirect_uris: ["https://example.com/callback"] } }, env), undefined);
  env.MCP_OAUTH_CIMD_ENABLED = "false";
  env.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS = '["https://client.example/oauth/metadata.json"]';
  assert.equal(isMcpOAuthClientAllowed(env, "https://client.example/oauth/metadata.json"), false);
});

test("production DCR allowlist admits only the exact Claude and ChatGPT hosted callbacks", async () => {
  const { sqlite, env } = fixture();
  const toml = readFileSync(fileURLToPath(new URL("../wrangler.toml", import.meta.url)), "utf8");
  const vars = toml.slice(toml.indexOf("\n[vars]"));
  const configured = vars.match(/^MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS = '([^']*)'$/m)?.[1];
  const callbacks = ["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect"];
  assert.deepEqual(JSON.parse(configured), callbacks);
  env.MCP_OAUTH_DCR_ENABLED = "true";
  env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = "false";
  env.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS = configured;
  const request = new Request("https://api.cybermeters.com/oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.7" }, body: "{}",
  });
  const register = (redirect, method = "none") => {
    sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
    return evaluateMcpDcrRegistration({ request, clientMetadata: {
      client_name: "Hosted client", redirect_uris: [redirect], token_endpoint_auth_method: method,
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] } }, env);
  };
  for (const callback of callbacks) {
    assert.equal(await register(callback), undefined);
    assert.equal(await register(callback, "client_secret_post"), undefined);
  }
  for (const other of [
    "https://claude.ai/api/mcp/other_callback",
    "https://claude.ai/api/mcp/auth_callback/",
    "https://claude.ai/api/mcp/auth_callback?next=1",
    "https://claude.ai/api/mcp/auth_callback#x",
    "https://evil.example/api/mcp/auth_callback",
    "http://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect/",
    "https://chatgpt.com/connector_platform_oauth_redirect?next=https://evil.example",
    "https://chatgpt.com/connector_platform_oauth_redirect#x",
    "https://chatgpt.com/connector/oauth/unlisted-callback-id",
    "https://chatgpt.com.evil.example/connector_platform_oauth_redirect",
    "https://chatgpt.com@evil.example/connector_platform_oauth_redirect",
    "http://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com:8443/connector_platform_oauth_redirect",
  ]) assert.equal((await register(other)).status, 400, other);
});

test("RFC 7591 defaults admit a Claude registration that omits them; sent values stay strict", async () => {
  const { sqlite, env } = fixture();
  env.MCP_OAUTH_DCR_ENABLED = "true";
  env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = "false";
  env.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS = '["https://claude.ai/api/mcp/auth_callback"]';
  const request = new Request("https://api.cybermeters.com/oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.8" }, body: "{}",
  });
  const claude = { client_name: "Claude", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] };
  assert.deepEqual(applyMcpDcrDefaults(claude), { ...claude, grant_types: ["authorization_code"],
    response_types: ["code"], token_endpoint_auth_method: "none" });
  // A field that was sent is never replaced by a default.
  assert.equal(applyMcpDcrDefaults({ ...claude, token_endpoint_auth_method: "client_secret_post" })
    .token_endpoint_auth_method, "client_secret_post");
  assert.deepEqual(applyMcpDcrDefaults({ ...claude, grant_types: ["authorization_code", "refresh_token"] })
    .grant_types, ["authorization_code", "refresh_token"]);
  assert.equal(applyMcpDcrDefaults(null), null);
  assert.deepEqual(applyMcpDcrDefaults([1]), [1]);

  const register = (metadata) => {
    sqlite.exec("DELETE FROM api_rate_limits WHERE action = 'mcp_dcr_register'");
    return evaluateMcpDcrRegistration({ request, clientMetadata: applyMcpDcrDefaults(metadata) }, env);
  };
  assert.equal(await register(claude), undefined);
  assert.equal(await register({ ...claude, grant_types: ["authorization_code", "refresh_token"] }), undefined);
  // What the hosted connector actually sends (production log, 20 Oct 2026):
  // a secret sent in the token request body, for the allow-listed callback.
  assert.equal(await register({ ...claude, token_endpoint_auth_method: "client_secret_post" }), undefined);
  assert.equal(await register({ ...claude, token_endpoint_auth_method: "client_secret_post",
    token_endpoint_auth_methods_supported: ["client_secret_post"] }), undefined);

  const logged = [];
  const warn = console.warn;
  console.warn = (line) => logged.push(JSON.parse(line));
  try {
    for (const [changed, rule, value] of [
      // A secret is only for allow-listed hosted callbacks, never loopback or others.
      [{ token_endpoint_auth_method: "client_secret_post", redirect_uris: ["http://localhost:7777/callback"] }, "auth_method_not_none", "client_secret_post"],
      [{ token_endpoint_auth_method: "client_secret_post", redirect_uris: ["https://claude.ai/api/mcp/auth_callback", "https://evil.example/cb"] }, "auth_method_not_none", "client_secret_post"],
      [{ token_endpoint_auth_method: "client_secret_post", token_endpoint_auth_methods_supported: ["none"] }, "auth_methods_supported_not_none", ["none"]],
      [{ token_endpoint_auth_method: "client_secret_basic" }, "auth_method_not_none", "client_secret_basic"],
      [{ grant_types: ["implicit"] }, "grant_types_invalid", ["implicit"]],
      [{ grant_types: [] }, "grant_types_invalid", []],
      [{ response_types: ["token"] }, "response_types_invalid", ["token"]],
      [{ token_endpoint_auth_methods_supported: ["client_secret_post"] }, "auth_methods_supported_not_none", ["client_secret_post"]],
      [{ redirect_uris: ["https://claude.com/api/mcp/auth_callback"] }, "redirect_not_allowed", undefined],
    ]) {
      assert.equal((await register({ ...claude, ...changed })).status, 400, rule);
      const entry = logged.at(-1);
      assert.equal(entry.event, "mcp_dcr_rejected");
      assert.equal(entry.rule, rule);
      if (value !== undefined) assert.deepEqual(entry.value, value);
    }
    assert.equal(logged.at(-1).redirect_host, "claude.com");
    assert.equal(logged[0].redirect_host, "localhost:7777");
    assert.equal(logged[1].redirect_host, "claude.ai");
    // The log never carries the IP, the client name or a free-form value.
    const text = JSON.stringify(logged);
    assert.equal(text.includes("203.0.113.8"), false);
    assert.equal(text.includes("Claude"), false);
    await register({ ...claude, token_endpoint_auth_method: "my-secret-scheme" });
    assert.equal(logged.at(-1).value, "other");
    await register({ ...claude, client_name: "x".repeat(81) });
    assert.deepEqual([logged.at(-1).rule, logged.at(-1).detail], ["client_name_invalid", "length_81"]);
  } finally {
    console.warn = warn;
  }
});

test("validated OAuth budgets limit each IP before shared emergency capacity", async () => {
  const { sqlite, env } = fixture();
  env.MCP_OAUTH_DCR_LOOPBACK_ENABLED = "true";
  const request = (ip) => new Request("https://api.cybermeters.com/authorize", {
    headers: { "CF-Connecting-IP": ip },
  });
  assert.equal(await claimMcpOAuthStartBudget(request("203.0.113.1"), env), true);
  let counters = sqlite.prepare(`SELECT scope, request_count FROM api_rate_limits
    WHERE action = 'mcp_authorize_start' ORDER BY rowid`).all();
  assert.deepEqual(counters.map((row) => row.scope), ["mcp_oauth_ip", "mcp_oauth_global"]);
  sqlite.prepare(`UPDATE api_rate_limits SET request_count = 8
    WHERE action = 'mcp_authorize_start' AND scope = 'mcp_oauth_global'`).run();
  const beforeCappedAuthorize = sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_authorize_start'`).get().n;
  for (let attempt = 0; attempt < 3; attempt++) {
    assert.equal(await claimMcpOAuthStartBudget(request(`203.0.113.${attempt + 2}`), env), false);
  }
  assert.equal(sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_authorize_start'`).get().n, beforeCappedAuthorize,
    "a full shared cap must not create counters for new IPs");
  assert.equal(sqlite.prepare(`SELECT request_count FROM api_rate_limits
    WHERE action = 'mcp_authorize_start' AND scope = 'mcp_oauth_global'`).get().request_count, 8);

  assert.equal(await claimMcpOAuthTokenBudget(request("203.0.113.3"), env), null);
  counters = sqlite.prepare(`SELECT scope FROM api_rate_limits
    WHERE action = 'mcp_token_exchange' ORDER BY rowid`).all();
  assert.deepEqual(counters.map((row) => row.scope), ["mcp_oauth_ip", "mcp_oauth_global"]);
  sqlite.prepare(`UPDATE api_rate_limits SET request_count = 8
    WHERE action = 'mcp_token_exchange' AND scope = 'mcp_oauth_global'`).run();
  const beforeCappedToken = sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_token_exchange'`).get().n;
  for (let attempt = 0; attempt < 3; attempt++) {
    assert.equal((await claimMcpOAuthTokenBudget(request(`203.0.113.${attempt + 4}`), env)).status, 429);
  }
  assert.equal(sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_token_exchange'`).get().n, beforeCappedToken);
  assert.equal(sqlite.prepare(`SELECT request_count FROM api_rate_limits
    WHERE action = 'mcp_token_exchange' AND scope = 'mcp_oauth_global'`).get().request_count, 8);

  env.MCP_OAUTH_DCR_ENABLED = "true";
  const registration = new Request("https://api.cybermeters.com/oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.5" }, body: "{}",
  });
  const metadata = { client_name: "Test", redirect_uris: ["http://localhost:7777/callback"],
    token_endpoint_auth_method: "none", grant_types: ["authorization_code"],
    response_types: ["code"] };
  assert.equal(await evaluateMcpDcrRegistration({ request: registration,
    clientMetadata: metadata }, env), undefined);
  counters = sqlite.prepare(`SELECT scope FROM api_rate_limits
    WHERE action = 'mcp_dcr_register' ORDER BY rowid`).all();
  assert.deepEqual(counters.map((row) => row.scope), ["mcp_dcr_ip", "mcp_oauth_global"]);
  sqlite.prepare(`UPDATE api_rate_limits SET request_count = 12
    WHERE action = 'mcp_dcr_register' AND scope = 'mcp_oauth_global'`).run();
  const beforeCappedDcr = sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_dcr_register'`).get().n;
  const anotherIp = new Request(registration.url, { method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.6" }, body: "{}" });
  assert.equal((await evaluateMcpDcrRegistration({ request: anotherIp,
    clientMetadata: metadata }, env)).status, 429);
  assert.equal(sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_dcr_register'`).get().n, beforeCappedDcr);
  assert.equal(sqlite.prepare(`SELECT request_count FROM api_rate_limits
    WHERE action = 'mcp_dcr_register' AND scope = 'mcp_oauth_global'`).get().request_count, 12);
  const prior = sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_dcr_register'`).get().n;
  assert.equal((await evaluateMcpDcrRegistration({ request: anotherIp,
    clientMetadata: { ...metadata, token_endpoint_auth_method: "client_secret_basic" } }, env)).status, 400);
  assert.equal(sqlite.prepare(`SELECT COUNT(*) AS n FROM api_rate_limits
    WHERE action = 'mcp_dcr_register'`).get().n, prior,
    "invalid metadata must not spend the shared registration budget");
});

test("browser bridge binds an opaque cookie to a verified web session and one intent", async () => {
  const { sqlite, env } = fixture();
  const rawSession = "a".repeat(64);
  sqlite.prepare(`INSERT INTO user_sessions VALUES ('s1','u1',?, '2099-01-01')`)
    .run(await hashToken(rawSession));
  const issuer = "https://api.cybermeters.com";
  const authorize = new Request(`${issuer}/authorize?client_id=client&state=safe`, {
    headers: { "CF-Connecting-IP": "203.0.113.5" },
  });
  const intent = await createMcpOAuthIntent(authorize, env);
  assert.ok(intent);
  assert.ok(await readMcpOAuthIntent(env, intent));
  const bridgeRequest = (origin, bearer, cookie) => new Request(`${issuer}/api/mcp/oauth/browser-session`, {
    method: "POST", headers: { Origin: origin, "Content-Type": "application/json",
      Authorization: `Bearer ${bearer}`, ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify({ intent }),
  });
  assert.equal((await bridgeMcpOAuthBrowserSession(bridgeRequest("https://evil.example", rawSession), env)).status, 400);
  assert.equal((await bridgeMcpOAuthBrowserSession(bridgeRequest("https://app.cybermeters.com", `cm_${"a".repeat(64)}`), env)).status, 401);
  const response = await bridgeMcpOAuthBrowserSession(
    bridgeRequest("https://app.cybermeters.com", rawSession), env);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("Set-Cookie"), /HttpOnly; Secure; SameSite=Lax/);
  const cookie = response.headers.get("Set-Cookie").split(";")[0];
  const intentRow = await readMcpOAuthIntent(env, intent);
  const resumed = await bridgeMcpOAuthBrowserSession(
    bridgeRequest("https://app.cybermeters.com", rawSession, cookie), env);
  assert.equal(resumed.status, 200, "browser Back can resume the same handoff");
  assert.equal(resumed.headers.get("Set-Cookie"), null, "resume must not mint a new cookie");
  assert.deepEqual(await resumed.json(), await response.json());
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_browser_sessions").get().n, 1);
  assert.equal((await bridgeMcpOAuthBrowserSession(
    bridgeRequest("https://app.cybermeters.com", rawSession), env)).status, 409,
  "the intent URL without its cookie cannot take over the existing handoff");
  const secondSession = "b".repeat(64);
  sqlite.prepare(`INSERT INTO user_sessions VALUES ('s2','u1',?, '2099-01-01')`)
    .run(await hashToken(secondSession));
  assert.equal((await bridgeMcpOAuthBrowserSession(
    bridgeRequest("https://app.cybermeters.com", secondSession, cookie), env)).status, 409,
  "a different web session cannot resume the handoff, even with its cookie");
  assert.equal((await readMcpOAuthBrowserSession(new Request(`${issuer}/authorize`,
    { headers: { Cookie: cookie } }), env, intentRow.id_hash)).user_id, "u1");
  assert.equal(await readMcpOAuthBrowserSession(new Request(`${issuer}/authorize`,
    { headers: { Cookie: cookie } }), env, "wrong-intent-hash"), null);
  assert.equal(await claimMcpOAuthBrowserSession(new Request(`${issuer}/authorize`,
    { headers: { Cookie: cookie } }), env, intentRow.id_hash, "u1"), true);
  assert.equal(await claimMcpOAuthBrowserSession(new Request(`${issuer}/authorize`,
    { headers: { Cookie: cookie } }), env, intentRow.id_hash, "u1"), false);
  assert.equal(await readMcpOAuthBrowserSession(new Request(`${issuer}/authorize`,
    { headers: { Cookie: cookie } }), env, intentRow.id_hash), null);
  sqlite.exec("UPDATE mcp_oauth_browser_sessions SET consumed_at = NULL");
  sqlite.exec("UPDATE user_sessions SET expires_at = '2020-01-01' WHERE id = 's1'");
  assert.equal(await readMcpOAuthBrowserSession(new Request(`${issuer}/authorize`,
    { headers: { Cookie: cookie } }), env, intentRow.id_hash), null);
});

test("pending account deletion blocks the session used by connection management", async () => {
  const { sqlite, env } = fixture();
  const bearer = "a".repeat(64);
  sqlite.prepare(`INSERT INTO user_sessions VALUES ('s1','u1',?, '2099-01-01')`)
    .run(await hashToken(bearer));
  const request = new Request("https://api.cybermeters.com/api/mcp/oauth/connections", {
    headers: { Authorization: `Bearer ${bearer}` },
  });
  assert.equal((await requireMcpWebSession(request, env)).user_id, "u1");
  sqlite.exec(`INSERT INTO deletion_requests VALUES ('d1','account','u1',NULL,'pending')`);
  for (const status of ["pending", "purging", "blocked_active_subscription", "blocked_residual_data"]) {
    sqlite.prepare("UPDATE deletion_requests SET status = ? WHERE id = 'd1'").run(status);
    assert.equal(await requireMcpWebSession(request, env), null, status);
  }
});

test("expired browser sessions and authorization URLs are cleaned in bounded batches", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO user_sessions VALUES ('s1','u1','hash','2099-01-01');
    INSERT INTO mcp_oauth_login_intents(id_hash,authorization_url,expires_at)
      VALUES ('old1','https://api.cybermeters.com/authorize?state=private','2020-01-01'),
             ('old2','https://api.cybermeters.com/authorize?state=private2','2020-01-01');
    INSERT INTO mcp_oauth_browser_sessions(cookie_hash,intent_hash,user_id,web_session_id,expires_at)
      VALUES ('cookie1','old1','u1','s1','2020-01-01');`);
  assert.deepEqual(await purgeExpiredMcpOAuthBrowserRows(env, 1), { sessions: 1, intents: 1 });
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_login_intents").get().n, 1);
  assert.deepEqual(await purgeExpiredMcpOAuthBrowserRows(env, 1), { sessions: 0, intents: 1 });
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM mcp_oauth_login_intents").get().n, 0);
});

test("connection history pages past 100 and keeps active own grants first", async () => {
  const { sqlite, env } = fixture();
  const insert = sqlite.prepare(`INSERT INTO mcp_oauth_connections
    (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes,status,created_at)
    VALUES (?, ?, 'client', ?, ?, 0, '["mcp:read"]', ?, ?)`);
  for (let i = 0; i < 105; i++) {
    insert.run(`hist${String(i).padStart(3, "0")}`, "u1", MCP_OAUTH_RESOURCE, "w1",
      i === 104 ? "revoked" : "active", `2026-01-01 00:${String(i % 60).padStart(2, "0")}:00`);
  }
  insert.run("foreign", "u2", MCP_OAUTH_RESOURCE, "w2", "active", "2026-01-01 00:59:00");
  const first = await listMcpOAuthConnections(env, "u1", 0);
  const second = await listMcpOAuthConnections(env, "u1", first.next_offset);
  const third = await listMcpOAuthConnections(env, "u1", second.next_offset);
  assert.deepEqual([first.connections.length, second.connections.length, third.connections.length],
    [50, 50, 6]);
  assert.equal(third.next_offset, null);
  assert.equal(first.connections[0].status, "active");
  assert.equal(third.connections.at(-1).status, "revoked");
  assert.equal(JSON.stringify([first, second, third]).includes("foreign"), false);
  assert.equal(await listMcpOAuthConnections(env, "u1", -1), null);
});

test("OAuth browser request bodies are capped without Content-Length", async () => {
  const small = new Request("https://api.cybermeters.com/", { method: "POST", body: "ok" });
  assert.equal(await readBoundedMcpOAuthBody(small, 2), "ok");
  const large = new Request("https://api.cybermeters.com/", { method: "POST", body: "x".repeat(100) });
  assert.equal(await readBoundedMcpOAuthBody(large, 32), null);
  const stalled = new Request("https://api.cybermeters.com/", {
    method: "POST", duplex: "half", body: new ReadableStream({ start() {} }),
  });
  assert.equal(await readBoundedMcpOAuthBody(stalled, 32, 20), null);
});
