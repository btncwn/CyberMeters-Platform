import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { hashToken } from "../src/lib/auth-crypto.js";
import {
  admitMcpOAuthToken, canGrantMcpPortfolio, listMcpOAuthConnections,
  listMcpOAuthConsentWorkspaces,
  MCP_OAUTH_RESOURCE, sameMcpOAuthAuthorizationRequest,
  validMcpOAuthAuthorizationRequest,
} from "../src/routes/mcp-oauth-admission.js";
import { evaluateMcpDcrRegistration, isMcpDcrLoopbackRedirect } from "../src/routes/mcp-oauth-dcr.js";
import {
  bridgeMcpOAuthBrowserSession, claimMcpOAuthBrowserSession, createMcpOAuthIntent,
  purgeExpiredMcpOAuthBrowserRows, readBoundedMcpOAuthBody,
  readMcpOAuthBrowserSession, readMcpOAuthIntent, requireMcpWebSession,
} from "../src/routes/mcp-oauth-browser.js";

function fixture() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec(`
    CREATE TABLE users(id TEXT PRIMARY KEY, status TEXT, email_verified INTEGER);
    CREATE TABLE workspaces(id TEXT PRIMARY KEY, name TEXT, deleted_at TEXT);
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
  const rate = fileURLToPath(new URL("../../../database/migrations/026-api-rate-limits.sql", import.meta.url));
  sqlite.exec(readFileSync(rate, "utf8"));
  sqlite.exec(`
    INSERT INTO users VALUES ('u1','active',1),('u2','active',1);
    INSERT INTO workspaces VALUES ('w1','One',NULL),('w2','Two',NULL);
    INSERT INTO workspace_members VALUES ('wm1','w1','u1','viewer'),('wm2','w2','u2','owner');
    INSERT INTO mcp_beta_workspace_access(workspace_id,status) VALUES ('w1','enabled'),('w2','enabled');
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('c1','u1','client','https://mcp.cybermeters.com/mcp','w1',0,'["mcp:read"]');
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
  return { sqlite, env: { cybermeters_db: db } };
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

test("portfolio access requires separate scope, paid entitlement, current enrolled membership", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO mcp_oauth_connections
    (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
    VALUES ('c2','u1','client','https://mcp.cybermeters.com/mcp',NULL,1,'["mcp:read","portfolio:read"]')`);
  const portfolio = token({
    props: { userId: "u1", connectionId: "c2", workspaceId: null, portfolioRead: true },
    scope: ["mcp:read", "portfolio:read"],
  });
  assert.equal(await canGrantMcpPortfolio(env, "u1"), false);
  assert.equal(await admitMcpOAuthToken(env, portfolio), null);
  sqlite.exec(`INSERT INTO subscriptions(id,owner_user_id,plan,status,subscription_status,
    current_period_end,created_at) VALUES
    ('sub1','u1','business','active','active','2099-01-01','2026-01-01')`);
  assert.equal(await canGrantMcpPortfolio(env, "u1"), true);
  assert.ok(await admitMcpOAuthToken(env, portfolio));
  assert.equal(await admitMcpOAuthToken(env, { ...portfolio, scope: ["mcp:read"] }), null);
  sqlite.exec("DELETE FROM workspace_members WHERE user_id = 'u1'");
  assert.equal(await admitMcpOAuthToken(env, portfolio), null);
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
  const { env } = fixture();
  env.MCP_OAUTH_DCR_ENABLED = "true";
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
  const metadata = { client_name: "Gemini CLI", redirect_uris: ["http://localhost:7777/oauth/callback"],
    grant_types: ["authorization_code"], response_types: ["code"] };
  assert.equal(await evaluateMcpDcrRegistration({ request, clientMetadata: metadata }, env), undefined);
  assert.equal((await evaluateMcpDcrRegistration({ request, clientMetadata: {
    ...metadata, redirect_uris: ["https://example.com/callback"] } }, env)).status, 400);
  env.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS = '["https://example.com/callback"]';
  assert.equal(await evaluateMcpDcrRegistration({ request, clientMetadata: {
    ...metadata, redirect_uris: ["https://example.com/callback"] } }, env), undefined);
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
  const bridgeRequest = (origin, bearer) => new Request(`${issuer}/api/mcp/oauth/browser-session`, {
    method: "POST", headers: { Origin: origin, "Content-Type": "application/json",
      Authorization: `Bearer ${bearer}` }, body: JSON.stringify({ intent }),
  });
  assert.equal((await bridgeMcpOAuthBrowserSession(bridgeRequest("https://evil.example", rawSession), env)).status, 400);
  assert.equal((await bridgeMcpOAuthBrowserSession(bridgeRequest("https://app.cybermeters.com", `cm_${"a".repeat(64)}`), env)).status, 401);
  const response = await bridgeMcpOAuthBrowserSession(
    bridgeRequest("https://app.cybermeters.com", rawSession), env);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("Set-Cookie"), /HttpOnly; Secure; SameSite=Lax/);
  const cookie = response.headers.get("Set-Cookie").split(";")[0];
  const intentRow = await readMcpOAuthIntent(env, intent);
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
