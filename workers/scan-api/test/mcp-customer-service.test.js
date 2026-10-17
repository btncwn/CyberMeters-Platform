import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { callMcpCustomerRead, MCP_CUSTOMER_RESOURCE,
  recordMcpGatewayDenial } from "../src/routes/mcp-customer-service.js";

const TEST_RESOURCE = "https://mcp-staging.cybermeters.com/mcp";
const BEARER = `user_a:${"b".repeat(16)}:${"a".repeat(32)}`;
const denied = (promise) => assert.rejects(promise, (error) =>
  error.message === "mcp_customer_unavailable" && !JSON.stringify(error).includes(BEARER));

function fixture() {
  const sql = new DatabaseSync(":memory:");
  sql.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT, email_verified INTEGER);
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT, owner_user_id TEXT, deleted_at TEXT);
    CREATE TABLE workspace_members (workspace_id TEXT, user_id TEXT, role TEXT);
    CREATE TABLE mcp_beta_workspace_access (workspace_id TEXT PRIMARY KEY, status TEXT);
    CREATE TABLE mcp_oauth_connections (id TEXT PRIMARY KEY, user_id TEXT, client_id TEXT,
      resource TEXT, workspace_id TEXT, portfolio_read INTEGER, granted_scopes TEXT,
      status TEXT, last_used_at TEXT);
    CREATE TABLE mcp_oauth_connection_workspaces (connection_id TEXT, workspace_id TEXT,
      PRIMARY KEY(connection_id, workspace_id));
    CREATE TABLE workspace_domains (workspace_id TEXT);
    CREATE TABLE managed_cases (id TEXT, workspace_id TEXT, case_type TEXT,
      domain_key TEXT, status TEXT, severity TEXT, remediation_id TEXT,
      created_at TEXT, updated_at TEXT, verified_at TEXT);
    CREATE TABLE scans (id TEXT, workspace_id TEXT, domain TEXT, status TEXT,
      scan_quality TEXT, score REAL, rating TEXT, created_at TEXT);
    CREATE TABLE deletion_requests (id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT,
      workspace_id TEXT, status TEXT);
    CREATE TABLE subscriptions (id TEXT PRIMARY KEY, workspace_id TEXT, owner_user_id TEXT,
      plan TEXT, status TEXT, subscription_status TEXT, trial_end TEXT, expires_at TEXT,
      current_period_end TEXT, payment_failed_at TEXT, stripe_subscription_id TEXT,
      created_at TEXT, updated_at TEXT);
    CREATE TABLE api_rate_limits (id TEXT PRIMARY KEY, scope TEXT, scope_id TEXT,
      action TEXT, window_start TEXT, window_seconds INTEGER, request_count INTEGER,
      created_at TEXT, updated_at TEXT);
  `);
  sql.prepare("INSERT INTO users VALUES ('user_a','active',1)").run();
  sql.prepare("INSERT INTO users VALUES ('user_b','active',1)").run();
  sql.prepare(`INSERT INTO subscriptions
    (id, workspace_id, owner_user_id, plan, status, subscription_status,
      current_period_end, created_at, updated_at)
    VALUES ('sub_a','ws_a','user_a','business','active','active',
      '2099-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`).run();
  for (const [ws, user] of [["ws_a", "user_a"], ["ws_b", "user_b"]]) {
    sql.prepare("INSERT INTO workspaces VALUES (?,?,?,NULL)").run(ws, `Name ${ws}`, user);
    sql.prepare("INSERT INTO workspace_members VALUES (?,?,'viewer')").run(ws, user);
    sql.prepare("INSERT INTO mcp_beta_workspace_access VALUES (?,'enabled')").run(ws);
  }
  sql.prepare("INSERT INTO mcp_oauth_connections VALUES ('conn_a','user_a','client_a',?,'ws_a',0,'[\"mcp:read\"]','active',NULL)")
    .run(TEST_RESOURCE);
  const env = {
    MCP_CUSTOMER_READ_ENABLED: "true", MCP_CUSTOMER_OAUTH_ENABLED: "true",
    MCP_DEPLOYMENT_TIER: "staging",
    cybermeters_db: { prepare(statement) { return { bind(...values) {
      const prepared = sql.prepare(statement);
      return {
        async first() { return prepared.get(...values) ?? null; },
        async all() { return { results: prepared.all(...values) }; },
        async run() { return { meta: { changes: prepared.run(...values).changes } }; },
      };
    } }; } },
  };
  const audit = [];
  const token = (props = {}) => ({ audience: TEST_RESOURCE,
    scope: ["mcp:read"], expiresAt: Math.floor(Date.now() / 1000) + 600,
    props: { userId: "user_a", connectionId: "conn_a", workspaceId: "ws_a",
      portfolioRead: false, ...props } });
  const opts = (overrides = {}) => ({
    validateToken: async () => token(),
    consumeBudget: async () => null,
    appendAudit: async (_env, event) => { audit.push(event); return true; },
    projectRead: async (_env, grant, facts, input) => ({
      workspace_id: grant.workspaceId, role: facts.workspace.role,
      requested_workspace_id: input.workspaceId,
    }), ...overrides,
  });
  return { sql, env, token, opts, audit, close: () => sql.close() };
}

test("anonymous gateway denials have per-client and shared audit caps; authenticated denials remain durable", async () => {
  const f = fixture();
  const hashes = Array.from({ length: 110 }, (_, n) => n.toString(16).padStart(64, "0"));
  const input = (client_ip_hash, authenticated = false) => ({
    reason: "invalid_bearer", authenticated, client_ip_hash,
  });
  const appendAudit = async (_env, event) => { f.audit.push(event); return true; };
  try {
    for (let n = 0; n < 8; n++) {
      assert.equal(await recordMcpGatewayDenial(f.env, input(hashes[0]), { appendAudit }), true);
    }
    assert.equal(f.audit.length, 4, "one client can write only four anonymous audit rows per minute");
    for (let n = 1; n < hashes.length; n++) {
      assert.equal(await recordMcpGatewayDenial(f.env, input(hashes[n]), { appendAudit }), true);
    }
    assert.equal(f.audit.length, 96, "the shared budget bounds distributed anonymous audit rows");
    assert.equal(f.sql.prepare(`SELECT COUNT(*) AS total FROM api_rate_limits
      WHERE action = 'mcp_gateway_denial_audit'`).get().total, 94);
    assert.equal(await recordMcpGatewayDenial(f.env, input(hashes[0], true), { appendAudit }), true);
    assert.equal(f.audit.length, 97, "authenticated denial bypasses anonymous caps");
    assert.ok(f.audit.every((event) => event.event_type === "mcp_customer_gateway_denied"));
    assert.equal(JSON.stringify(f.audit).includes(hashes[0]), false);
    f.sql.exec("DROP TABLE api_rate_limits");
    assert.equal(await recordMcpGatewayDenial(f.env, input(hashes[0], true), { appendAudit }), true);
    await denied(recordMcpGatewayDenial(f.env, input(hashes[0]), { appendAudit }));
  } finally { f.close(); }
});

test("workspace-bound customer token selects only its bound workspace and records last use", async () => {
  const f = fixture();
  try {
    const own = await callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER }, f.opts());
    assert.deepEqual(own, {
      workspace_id: "ws_a", role: "viewer", requested_workspace_id: "ws_a",
    });
    assert.ok(f.sql.prepare("SELECT last_used_at FROM mcp_oauth_connections WHERE id='conn_a'").get().last_used_at);
    assert.equal(f.audit[0].workspace_id, "ws_a");
    assert.equal(f.audit[0].user_id, "user_a");
    assert.equal(f.audit[0].metadata.tool, "getWorkspaceSummary");
    assert.equal(typeof f.audit[0].metadata.client_id_hash, "string");
    assert.equal(f.audit[0].metadata.connection_id, "conn_a");
    await callMcpCustomerRead(f.env, "listWorkspaces", { bearer: BEARER }, f.opts());
    assert.equal(f.audit[1].workspace_id, "ws_a",
      "single-workspace listing must retain workspace audit attribution");
    assert.equal(JSON.stringify(f.audit).includes(BEARER), false);
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER, workspaceId: "ws_b" }, f.opts()));
    const rejected = f.audit.at(-1);
    assert.equal(rejected.workspace_id, "ws_a", "attribute denial to grant, not foreign input");
    assert.equal(rejected.user_id, "user_a");
    assert.equal(rejected.metadata.tool, "getWorkspaceSummary");
    assert.equal(rejected.metadata.connection_id, "conn_a");
    assert.equal(typeof rejected.metadata.client_id_hash, "string");
    assert.equal(JSON.stringify(rejected).includes("ws_b"), false);
  } finally { f.close(); }
});

test("production founder canary rejects another member and an ownership transfer at the data service", async () => {
  const f = fixture();
  try {
    delete f.env.MCP_DEPLOYMENT_TIER;
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER }, f.opts()));
    f.env.MCP_DEPLOYMENT_TIER = "production";
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER }, f.opts()));
    f.env.MCP_FOUNDER_CANARY_USER_ID = "user_a";
    f.sql.prepare("UPDATE mcp_oauth_connections SET resource = ? WHERE id = 'conn_a'")
      .run(MCP_CUSTOMER_RESOURCE);
    const productionToken = (props = {}) => ({ ...f.token(props), audience: MCP_CUSTOMER_RESOURCE });
    const productionOpts = (overrides = {}) => f.opts({
      validateToken: async () => productionToken(), ...overrides,
    });
    const own = await callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER },
      productionOpts());
    assert.equal(own.workspace_id, "ws_a");
    f.sql.prepare(`INSERT INTO subscriptions
      (id, workspace_id, owner_user_id, plan, status, subscription_status,
       current_period_end, created_at, updated_at)
      VALUES ('sub_b','ws_b','user_b','business','active','active',
       '2099-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`).run();
    f.sql.prepare(`INSERT INTO mcp_oauth_connections
      VALUES ('conn_b','user_b','client_a',?,'ws_b',0,'["mcp:read"]','active',NULL)`)
      .run(MCP_CUSTOMER_RESOURCE);
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER },
      productionOpts({ validateToken: async () => productionToken({
        userId: "user_b", connectionId: "conn_b", workspaceId: "ws_b",
      }) })));
    f.sql.prepare("INSERT INTO workspace_members VALUES ('ws_a','user_b','viewer')").run();
    f.sql.prepare(`INSERT INTO mcp_oauth_connections
      VALUES ('conn_member','user_b','client_a',?,'ws_a',0,'["mcp:read"]','active',NULL)`)
      .run(MCP_CUSTOMER_RESOURCE);
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER },
      productionOpts({ validateToken: async () => productionToken({
        userId: "user_b", connectionId: "conn_member", workspaceId: "ws_a",
      }) })));
    f.sql.prepare("UPDATE workspaces SET owner_user_id='user_b' WHERE id='ws_a'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER },
      productionOpts()));
  } finally { f.close(); }
});

test("revocation, membership removal, beta pause, bad scope, and audit outage deny", async () => {
  const f = fixture();
  try {
    const input = { bearer: BEARER, workspaceId: "ws_a" };
    f.sql.prepare("UPDATE mcp_oauth_connections SET status='revoked' WHERE id='conn_a'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("UPDATE mcp_oauth_connections SET status='active' WHERE id='conn_a'").run();
    f.sql.prepare("DELETE FROM workspace_members WHERE workspace_id='ws_a'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("INSERT INTO workspace_members VALUES ('ws_a','user_a','viewer')").run();
    f.sql.prepare("UPDATE mcp_beta_workspace_access SET status='paused' WHERE workspace_id='ws_a'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("UPDATE mcp_beta_workspace_access SET status='enabled' WHERE workspace_id='ws_a'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input,
      f.opts({ validateToken: async () => ({ ...f.token(), scope: ["portfolio:read"] }) })));
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input,
      f.opts({ appendAudit: async () => false })));
    assert.equal(f.sql.prepare("SELECT last_used_at FROM mcp_oauth_connections WHERE id='conn_a'").get().last_used_at, null);
  } finally { f.close(); }
});

test("portfolio access is server-derived, enrolled, paginated, and scope-bound", async () => {
  const f = fixture();
  try {
    f.sql.prepare("INSERT INTO workspace_members VALUES ('ws_b','user_a','analyst')").run();
    f.sql.prepare("INSERT INTO mcp_oauth_connections VALUES ('conn_portfolio','user_a','client_a',?,NULL,1,'[\"mcp:read\",\"portfolio:read\"]','active',NULL)")
      .run(TEST_RESOURCE);
    f.sql.prepare("INSERT INTO mcp_oauth_connection_workspaces VALUES ('conn_portfolio','ws_a'),('conn_portfolio','ws_b')").run();
    const ptoken = f.token({ connectionId: "conn_portfolio", workspaceId: null, portfolioRead: true });
    ptoken.scope = ["mcp:read", "portfolio:read"];
    const opts = f.opts({ validateToken: async () => ptoken,
      projectRead: async (_env, grant) => ({ workspace_ids: grant.portfolioWorkspaceIds }) });
    const result = await callMcpCustomerRead(f.env, "listFindings",
      { bearer: BEARER, portfolio: true }, opts);
    assert.deepEqual(result.workspace_ids, ["ws_a", "ws_b"]);
    assert.equal(f.audit[0].metadata.selected_workspace_count, 2);
    assert.deepEqual(f.audit[0].metadata.selected_workspace_ids, ["ws_a", "ws_b"]);
    f.sql.prepare("UPDATE mcp_beta_workspace_access SET status='paused' WHERE workspace_id='ws_b'").run();
    await denied(callMcpCustomerRead(f.env, "listFindings",
      { bearer: BEARER, portfolio: true }, opts));
    await denied(callMcpCustomerRead(f.env, "listFindings",
      { bearer: BEARER, portfolio: true, workspaceId: "ws_b" }, opts));
    await denied(callMcpCustomerRead(f.env, "listFindings",
      { bearer: BEARER, portfolio: true }, f.opts({
        validateToken: async () => ({ ...ptoken, scope: ["mcp:read"] }),
      })));
  } finally { f.close(); }
});

test("portfolio reads share one atomic connection budget across workspaces", async () => {
  const f = fixture();
  try {
    f.sql.prepare("INSERT INTO workspace_members VALUES ('ws_b','user_a','analyst')").run();
    f.sql.prepare("INSERT INTO mcp_oauth_connections VALUES ('conn_portfolio','user_a','client_a',?,NULL,1,'[\"mcp:read\",\"portfolio:read\"]','active',NULL)")
      .run(TEST_RESOURCE);
    f.sql.prepare("INSERT INTO mcp_oauth_connection_workspaces VALUES ('conn_portfolio','ws_a'),('conn_portfolio','ws_b')").run();
    const token = f.token({ connectionId: "conn_portfolio", workspaceId: null, portfolioRead: true });
    token.scope = ["mcp:read", "portfolio:read"];
    const options = f.opts({ validateToken: async () => token, consumeBudget: undefined });
    for (let index = 0; index < 30; index++) {
      const workspaceId = index % 2 === 0 ? "ws_a" : "ws_b";
      const output = await callMcpCustomerRead(f.env, "getWorkspaceSummary",
        { bearer: BEARER, workspaceId }, options);
      assert.equal(output.workspace_id, workspaceId);
    }
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER, workspaceId: "ws_a" }, options));
    const count = f.sql.prepare("SELECT MAX(request_count) AS n FROM api_rate_limits WHERE scope='mcp_customer_connection' AND scope_id='conn_portfolio'").get();
    assert.equal(count.n, 31);
    const accessTokenBudget = f.sql.prepare("SELECT MAX(request_count) AS n, scope_id FROM api_rate_limits WHERE scope='mcp_customer_access_token'").get();
    assert.equal(accessTokenBudget.n, 30);
    assert.notEqual(accessTokenBudget.scope_id, BEARER);
  } finally { f.close(); }
});

test("an invited live Trial has a lower shared MCP token and connection budget", async () => {
  const f = fixture();
  try {
    f.sql.prepare(`UPDATE subscriptions SET plan='professional', status='trialing',
      subscription_status='trialing', trial_end='2099-01-01T00:00:00Z'
      WHERE id='sub_a'`).run();
    const options = f.opts({ consumeBudget: undefined });
    for (let index = 0; index < 10; index++) {
      const result = await callMcpCustomerRead(f.env, "getWorkspaceSummary",
        { bearer: BEARER }, options);
      assert.equal(result.workspace_id, "ws_a");
    }
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, options));
    const connectionBudget = f.sql.prepare(`SELECT MAX(request_count) AS n FROM api_rate_limits
      WHERE scope='mcp_customer_connection' AND scope_id='conn_a'`).get();
    assert.equal(connectionBudget.n, 11);
    const tokenBudget = f.sql.prepare(`SELECT MAX(request_count) AS n, scope_id
      FROM api_rate_limits WHERE scope='mcp_customer_access_token'`).get();
    assert.equal(tokenBudget.n, 10);
    assert.notEqual(tokenBudget.scope_id, BEARER);
    assert.equal(f.audit.filter((event) => event.event_type === "mcp_customer_summary_read").length, 10);
  } finally { f.close(); }
});

test("expired Trial and unreadable plan deny instead of using the paid MCP budget", async () => {
  const f = fixture();
  try {
    f.sql.prepare(`UPDATE subscriptions SET plan='professional', status='trialing',
      subscription_status='trialing', trial_end='2020-01-01T00:00:00Z'
      WHERE id='sub_a'`).run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts({ consumeBudget: undefined })));
    f.sql.prepare("DROP TABLE subscriptions").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts({ consumeBudget: undefined })));
    const count = f.sql.prepare("SELECT COUNT(*) AS n FROM api_rate_limits").get();
    assert.equal(count.n, 0, "invalid plans must be rejected before token budget claims");
  } finally { f.close(); }
});

test("a paid-to-Trial change applies the lower cap to the same token immediately", async () => {
  const f = fixture();
  try {
    const options = f.opts({ consumeBudget: undefined });
    for (let index = 0; index < 11; index++) {
      await callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER }, options);
    }
    f.sql.prepare(`UPDATE subscriptions SET plan='professional', status='trialing',
      subscription_status='trialing', trial_end='2099-01-01T00:00:00Z'
      WHERE id='sub_a'`).run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, options));
    assert.equal(f.audit.filter((event) => event.event_type === "mcp_customer_summary_read").length, 11);
  } finally { f.close(); }
});

test("portfolio summary dispatches canonical summaries for only selected workspaces", async () => {
  const f = fixture();
  try {
    f.sql.prepare("INSERT INTO workspace_members VALUES ('ws_b','user_a','analyst')").run();
    f.sql.prepare("INSERT INTO workspaces VALUES ('ws_c','Name ws_c','user_a',NULL)").run();
    f.sql.prepare("INSERT INTO workspace_members VALUES ('ws_c','user_a','viewer')").run();
    f.sql.prepare("INSERT INTO mcp_beta_workspace_access VALUES ('ws_c','enabled')").run();
    f.sql.prepare("INSERT INTO mcp_oauth_connections VALUES ('conn_portfolio','user_a','client_a',?,NULL,1,'[\"mcp:read\",\"portfolio:read\"]','active',NULL)")
      .run(TEST_RESOURCE);
    f.sql.prepare("INSERT INTO mcp_oauth_connection_workspaces VALUES ('conn_portfolio','ws_a'),('conn_portfolio','ws_b')").run();
    const ptoken = f.token({ connectionId: "conn_portfolio", workspaceId: null, portfolioRead: true });
    ptoken.scope = ["mcp:read", "portfolio:read"];
    const result = await callMcpCustomerRead(f.env, "getPortfolioSummary", { bearer: BEARER },
      f.opts({ validateToken: async () => ptoken, projectRead: undefined }));
    assert.equal(result.scope, "portfolio");
    assert.equal(result.selected_workspace_count, 2);
    assert.deepEqual(result.workspaces.map((row) => row.workspace_id), ["ws_a", "ws_b"]);
    assert.equal(result.workspaces.some((row) => row.workspace_id === "ws_c"), false);
    assert.equal(result.workspaces.every((row) => row.score_state !== "assessed"), true);
    const deniedIds = ["ws_c", "ws_other"];
    const errors = [];
    for (const workspaceId of deniedIds) {
      try {
        await callMcpCustomerRead(f.env, "getWorkspaceSummary",
          { bearer: BEARER, workspaceId }, f.opts({ validateToken: async () => ptoken }));
      } catch (error) { errors.push(error.message); }
    }
    assert.deepEqual(errors, ["mcp_customer_unavailable", "mcp_customer_unavailable"]);
  } finally { f.close(); }
});

test("foreign and nonexistent scan and case IDs return the same service denial", async () => {
  const f = fixture();
  try {
    f.sql.prepare("INSERT INTO scans VALUES ('scan_b','ws_b','b.example','queued',NULL,0,'unknown','2026-10-15T00:00:00Z')").run();
    f.sql.prepare("INSERT INTO managed_cases VALUES ('case_b','ws_b','email_case','email_protection','open','critical',NULL,'2026-10-15T00:00:00Z','2026-10-15T00:00:00Z',NULL)").run();
    for (const [method, key, ids] of [
      ["getScanStatus", "scanId", ["scan_b", "scan_absent"]],
      ["getManagedCase", "caseId", ["case_b", "case_absent"]],
    ]) {
      const errors = [];
      for (const id of ids) {
        try {
          await callMcpCustomerRead(f.env, method,
            { bearer: BEARER, workspaceId: "ws_a", [key]: id },
            f.opts({ projectRead: undefined }));
        } catch (error) { errors.push(error.message); }
      }
      assert.deepEqual(errors, ["mcp_customer_unavailable", "mcp_customer_unavailable"]);
    }
  } finally { f.close(); }
});

test("customer path rejects general API token, disabled mode, and unknown method", async () => {
  const f = fixture();
  try {
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: `cm_${"a".repeat(64)}` }, f.opts()));
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: `oauth_${"a".repeat(40)}` }, f.opts()));
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: `${"b".repeat(16)}:${"a".repeat(32)}` }, f.opts()));
    await denied(callMcpCustomerRead(f.env, "listWorkspaces",
      { bearer: BEARER, workspaceId: "ws_a" }, f.opts()));
    await denied(callMcpCustomerRead(f.env, "deleteDomain",
      { bearer: BEARER, workspaceId: "ws_a" }, f.opts()));
    for (const flagName of ["MCP_CUSTOMER_READ_ENABLED", "MCP_CUSTOMER_OAUTH_ENABLED"]) {
      for (const flag of [undefined, "false", "TRUE", true, "1"]) {
        f.env[flagName] = flag;
        await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
          { bearer: BEARER }, f.opts()));
      }
      f.env[flagName] = "true";
      assert.equal((await callMcpCustomerRead(f.env, "getWorkspaceSummary",
        { bearer: BEARER }, f.opts())).workspace_id, "ws_a");
    }
  } finally { f.close(); }
});

test("pending account or workspace deletion blocks every new customer read", async () => {
  const f = fixture();
  try {
    const input = { bearer: BEARER, workspaceId: "ws_a" };
    f.sql.prepare("INSERT INTO deletion_requests VALUES ('delete_account','account','user_a',NULL,'pending')").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("UPDATE deletion_requests SET status='blocked_active_subscription' WHERE id='delete_account'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("UPDATE deletion_requests SET status='blocked_residual_data' WHERE id='delete_account'").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("DELETE FROM deletion_requests WHERE id='delete_account'").run();
    f.sql.prepare("INSERT INTO deletion_requests VALUES ('delete_ws','workspace','user_a','ws_a','purging')").run();
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts()));
    f.sql.prepare("UPDATE deletion_requests SET status='cancelled' WHERE id='delete_ws'").run();
    const result = await callMcpCustomerRead(f.env, "getWorkspaceSummary", input, f.opts());
    assert.equal(result.workspace_id, "ws_a");
  } finally { f.close(); }
});

test("production tier requires the distinct production audience and founder identity", async () => {
  const f = fixture();
  try {
    f.env.MCP_DEPLOYMENT_TIER = "production";
    f.env.MCP_FOUNDER_CANARY_USER_ID = "user_a";
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts()));
    f.sql.prepare("UPDATE mcp_oauth_connections SET resource = ? WHERE id = 'conn_a'")
      .run(MCP_CUSTOMER_RESOURCE);
    const result = await callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts({ validateToken: async (_env, resource) => {
        assert.equal(resource, MCP_CUSTOMER_RESOURCE);
        return { ...f.token(), audience: MCP_CUSTOMER_RESOURCE };
      } }));
    assert.equal(result.workspace_id, "ws_a");
  } finally { f.close(); }
});
