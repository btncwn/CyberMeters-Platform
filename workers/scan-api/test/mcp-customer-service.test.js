import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { callMcpCustomerRead, MCP_CUSTOMER_RESOURCE } from "../src/routes/mcp-customer-service.js";

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
    CREATE TABLE deletion_requests (id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT,
      workspace_id TEXT, status TEXT);
    CREATE TABLE api_rate_limits (id TEXT PRIMARY KEY, scope TEXT, scope_id TEXT,
      action TEXT, window_start TEXT, window_seconds INTEGER, request_count INTEGER,
      created_at TEXT, updated_at TEXT);
  `);
  sql.prepare("INSERT INTO users VALUES ('user_a','active',1)").run();
  sql.prepare("INSERT INTO users VALUES ('user_b','active',1)").run();
  for (const [ws, user] of [["ws_a", "user_a"], ["ws_b", "user_b"]]) {
    sql.prepare("INSERT INTO workspaces VALUES (?,?,?,NULL)").run(ws, `Name ${ws}`, user);
    sql.prepare("INSERT INTO workspace_members VALUES (?,?,'viewer')").run(ws, user);
    sql.prepare("INSERT INTO mcp_beta_workspace_access VALUES (?,'enabled')").run(ws);
  }
  sql.prepare("INSERT INTO mcp_oauth_connections VALUES ('conn_a','user_a','client_a',?,'ws_a',0,'[\"mcp:read\"]','active',NULL)")
    .run(MCP_CUSTOMER_RESOURCE);
  const env = {
    MCP_CUSTOMER_READ_ENABLED: "true", MCP_CUSTOMER_OAUTH_ENABLED: "true",
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
  const token = (props = {}) => ({ audience: MCP_CUSTOMER_RESOURCE,
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

test("workspace-bound customer token selects only its bound workspace and records last use", async () => {
  const f = fixture();
  try {
    const own = await callMcpCustomerRead(f.env, "getWorkspaceSummary", { bearer: BEARER }, f.opts());
    assert.deepEqual(own, {
      workspace_id: "ws_a", role: "viewer", requested_workspace_id: "ws_a",
    });
    assert.ok(f.sql.prepare("SELECT last_used_at FROM mcp_oauth_connections WHERE id='conn_a'").get().last_used_at);
    assert.equal(f.audit[0].workspace_id, "ws_a");
    assert.equal(JSON.stringify(f.audit).includes(BEARER), false);
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER, workspaceId: "ws_b" }, f.opts()));
    assert.equal(f.audit.at(-1).workspace_id, undefined);
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
      .run(MCP_CUSTOMER_RESOURCE);
    const ptoken = f.token({ connectionId: "conn_portfolio", workspaceId: null, portfolioRead: true });
    ptoken.scope = ["mcp:read", "portfolio:read"];
    const opts = f.opts({ validateToken: async () => ptoken,
      projectRead: async (_env, grant) => ({ workspace_ids: grant.portfolioWorkspaceIds }) });
    const result = await callMcpCustomerRead(f.env, "listFindings",
      { bearer: BEARER, portfolio: true }, opts);
    assert.deepEqual(result.workspace_ids, ["ws_a", "ws_b"]);
    f.sql.prepare("UPDATE mcp_beta_workspace_access SET status='paused' WHERE workspace_id='ws_b'").run();
    const fewer = await callMcpCustomerRead(f.env, "listFindings",
      { bearer: BEARER, portfolio: true }, opts);
    assert.deepEqual(fewer.workspace_ids, ["ws_a"]);
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
      .run(MCP_CUSTOMER_RESOURCE);
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
    f.env.MCP_CUSTOMER_READ_ENABLED = "false";
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts()));
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

test("staging tier requires the distinct staging audience", async () => {
  const f = fixture();
  try {
    f.env.MCP_DEPLOYMENT_TIER = "staging";
    await denied(callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts()));
    const staging = "https://mcp-staging.cybermeters.com/mcp";
    f.sql.prepare("UPDATE mcp_oauth_connections SET resource = ? WHERE id = 'conn_a'").run(staging);
    const result = await callMcpCustomerRead(f.env, "getWorkspaceSummary",
      { bearer: BEARER }, f.opts({ validateToken: async (_env, resource) => {
        assert.equal(resource, staging);
        return { ...f.token(), audience: staging };
      } }));
    assert.equal(result.workspace_id, "ws_a");
  } finally { f.close(); }
});
