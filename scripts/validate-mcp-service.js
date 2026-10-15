#!/usr/bin/env node
import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { hashToken } from "../workers/scan-api/src/lib/auth-crypto.js";
import {
  getWorkspaceSummaryForMcp,
  loadMcpAdmissionFacts,
} from "../workers/scan-api/src/routes/mcp-service.js";

const NOW = Date.parse("2026-10-15T12:00:00.000Z");
const TOKEN = `cm_${"a".repeat(64)}`;
const env = () => ({
  MCP_INTERNAL_ENABLED: "true",
  MCP_TRIAL_WORKSPACE_ID: "ws_1",
  MCP_TRIAL_TOKEN_ID: "tok_1",
  cybermeters_db: {},
});

function facts() {
  return {
    token: { token_id: "tok_1" },
    workspace: { id: "ws_1", name: "Test workspace" },
    admission: {
      requestedWorkspaceId: "ws_1",
      identity: {
        kind: "api_token", tokenId: "tok_1", userId: "usr_1",
        status: "active", scope: "read", workspaceId: "ws_1",
        expiresAt: "2026-10-16T12:00:00.000Z",
      },
      user: { id: "usr_1", status: "active" },
      workspace: {
        id: "ws_1", deletedAt: null, ownerUserId: "usr_other", memberCount: 1,
      },
      membership: { role: "viewer" },
      entitlement: { mcp: true },
    },
  };
}

function harness({ mutate, rateResult = null, rateError = false,
  auditError = false, auditReturn = true } = {}) {
  const calls = [];
  const audits = [];
  const record = facts();
  mutate?.(record);
  const overrides = {
    now: NOW,
    // This validator isolates admission/audit behavior. Canonical read
    // projections are exercised by the dedicated MCP-04 projection tests.
    projectRead: async () => ({
      workspace_id: "ws_1",
      display_name: "Test workspace",
      domain_count: 0,
      open_case_count: 0,
      score_state: "not_assessed",
      score_value: null,
      latest_measurement_at: null,
      evidence_state: "insufficient",
      coverage_state: "not_assessed",
      limitations: ["No verified complete assessment currently establishes this workspace's score."],
    }),
    hashToken: async (raw) => {
      calls.push("hash");
      assert.equal(raw, TOKEN);
      return "token-hash";
    },
    loadFacts: async (_env, hash, workspaceId) => {
      calls.push("load");
      assert.equal(hash, "token-hash");
      assert.equal(workspaceId, "ws_1");
      return record;
    },
    consumeBudget: async (_env, scopes, action, limit, window, options) => {
      calls.push("rate");
      assert.deepEqual(scopes, [{ scope: "mcp_token_workspace", scope_id: "tok_1:ws_1" }]);
      assert.deepEqual([action, limit, window], ["mcp_read", 30, 60]);
      assert.deepEqual(options, { atomic: true, failClosed: true });
      if (rateError) throw new Error("rate-store-secret");
      return rateResult;
    },
    appendAudit: async (_env, event) => {
      calls.push("audit");
      audits.push(event);
      assert.equal(event.required, true);
      assert.match(event.metadata.request_id, /^[0-9a-f-]{36}$/);
      if (event.event_type === "mcp_workspace_summary_read") {
        assert.equal(event.active_workspace_required, true);
        assert.equal(event.workspace_id, "ws_1");
        assert.equal(event.user_id, "usr_1");
        assert.equal(event.metadata.tool, "cybermeters_get_workspace_summary");
      } else {
        assert.equal(event.event_type, "mcp_read_denied");
        assert.equal(event.workspace_id, undefined);
        assert.equal(event.user_id, undefined);
        assert.match(event.metadata.reason, /^(invalid_request|identity_denied|budget_denied|projection_denied|audit_unavailable)$/);
      }
      assert.equal(JSON.stringify(event).includes(TOKEN), false);
      if (auditError) throw new Error("audit-store-secret");
      return auditReturn;
    },
  };
  return { calls, audits, overrides };
}

async function denied(testEnv, overrides, workspaceId = "ws_1") {
  await assert.rejects(
    getWorkspaceSummaryForMcp(testEnv, { bearer: TOKEN, workspaceId }, overrides),
    (error) => error.message === "mcp_summary_unavailable" &&
      !JSON.stringify(error).includes(TOKEN),
  );
}

test("one bound, expiring, read-only token returns a minimal honest summary", async () => {
  const { calls, overrides } = harness();
  const result = await getWorkspaceSummaryForMcp(env(), { bearer: TOKEN, workspaceId: "ws_1" }, overrides);
  assert.deepEqual(calls, ["hash", "load", "rate", "audit"]);
  assert.deepEqual(result, {
    workspace_id: "ws_1",
    display_name: "Test workspace",
    domain_count: 0,
    open_case_count: 0,
    score_state: "not_assessed",
    score_value: null,
    latest_measurement_at: null,
    evidence_state: "insufficient",
    coverage_state: "not_assessed",
    limitations: ["No verified complete assessment currently establishes this workspace's score."],
  });
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

test("gateway input and trial config gates reject before token or data access", async () => {
  for (const [change, workspaceId] of [
    [(e) => { e.MCP_INTERNAL_ENABLED = "false"; }, "ws_1"],
    [(e) => { delete e.MCP_INTERNAL_ENABLED; }, "ws_1"],
    [(e) => { e.MCP_TRIAL_WORKSPACE_ID = "ws_2"; }, "ws_1"],
    [(e) => { e.MCP_TRIAL_TOKEN_ID = ""; }, "ws_1"],
    [(e) => { delete e.cybermeters_db; }, "ws_1"],
    [() => {}, "ws_2"],
  ]) {
    const e = env(); change(e);
    const { calls, overrides } = harness();
    await denied(e, overrides, workspaceId);
    assert.deepEqual(calls, e.cybermeters_db ? ["audit"] : []);
  }
  for (const bearer of ["session-token", `cm_${"z".repeat(64)}`, "cm_short", "",
    { toString() { throw new Error("untrusted coercion"); } }]) {
    const { calls, overrides } = harness();
    await assert.rejects(getWorkspaceSummaryForMcp(env(), { bearer, workspaceId: "ws_1" }, overrides),
      /mcp_summary_unavailable/);
    assert.deepEqual(calls, ["audit"]);
  }
});

test("two-tenant and stale-authorization matrix denies with one indistinguishable error", async () => {
  const cases = [
    (r) => { r.token.token_id = "tok_foreign"; },
    (r) => { r.admission.identity.workspaceId = "ws_2"; },
    (r) => { r.admission.identity.workspaceId = null; },
    (r) => { r.admission.identity.status = "revoked"; },
    (r) => { r.admission.identity.scope = "write"; },
    (r) => { r.admission.identity.scope = "admin"; },
    (r) => { r.admission.identity.expiresAt = null; },
    (r) => { r.admission.identity.expiresAt = "2026-10-14T12:00:00.000Z"; },
    (r) => { r.admission.user.status = "suspended"; },
    (r) => { r.admission.workspace.deletedAt = "2026-10-14T00:00:00.000Z"; },
    (r) => { r.admission.membership = null; },
    (r) => { r.admission.membership.role = "unknown"; },
    (r) => { r.admission.entitlement.mcp = false; },
    (r) => { r.workspace = null; r.admission.workspace = null; },
  ];
  for (const mutate of cases) {
    const { calls, overrides } = harness({ mutate });
    await denied(env(), overrides);
    assert.equal(calls.filter((call) => call === "audit").length, 1);
  }
});

test("rate or audit storage failure cannot return customer data", async () => {
  for (const settings of [
    { rateResult: { status: 429 } },
    { rateResult: { status: 503 } },
    { rateError: true },
    { auditError: true },
    { auditReturn: false },
  ]) {
    const { calls, overrides } = harness(settings);
    await denied(env(), overrides);
    if (settings.auditError || settings.auditReturn === false) {
      assert.deepEqual(calls, ["hash", "load", "rate", "audit", "audit"]);
    }
    else assert.deepEqual(calls, ["hash", "load", "rate", "audit"]);
  }
});

test("D1 fact loader binds token hash, workspace and user and never trusts caller fields", async () => {
  const bound = [];
  const fakeDb = {
    prepare(sql) {
      return { bind(...values) {
        bound.push({ sql, values });
        return { async first() {
          if (sql.includes("FROM api_tokens")) return {
            token_id: "tok_1", user_id: "usr_1", workspace_id: "ws_1",
            scope: "read", expires_at: "2026-10-16T12:00:00.000Z",
            token_status: "active", user_status: "active",
          };
          if (sql.includes("FROM workspaces")) return {
            id: "ws_1", name: "Test workspace", owner_user_id: "usr_other", deleted_at: null,
          };
          if (sql.includes("COUNT(*)")) return { member_count: 1 };
          if (sql.includes("FROM workspace_members")) return { role: "viewer" };
          throw new Error("unexpected query");
        } };
      } };
    },
  };
  const e = { ...env(), cybermeters_db: fakeDb };
  const result = await loadMcpAdmissionFacts(e, "hash-only", "ws_1");
  assert.deepEqual(bound.map(({ values }) => values), [
    ["hash-only"], ["ws_1"], ["ws_1", "usr_1"], ["ws_1"],
  ]);
  assert.equal(result.admission.user.status, "active");
  assert.equal(result.admission.workspace.memberCount, 1);
  assert.equal(result.admission.membership.role, "viewer");
  assert.equal(result.admission.entitlement.mcp, true);
});

test("two real tenant rows enforce binding, membership, revocation, budget, and durable audits", async () => {
  const sql = new DatabaseSync(":memory:");
  try {
    sql.exec(`
      CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT NOT NULL);
      CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL,
        owner_user_id TEXT NOT NULL, deleted_at TEXT);
      CREATE TABLE workspace_members (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL,
        role TEXT NOT NULL);
      CREATE TABLE api_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL, workspace_id TEXT, scope TEXT NOT NULL,
        expires_at TEXT, status TEXT NOT NULL);
      CREATE TABLE api_rate_limits (id TEXT PRIMARY KEY, scope TEXT NOT NULL,
        scope_id TEXT NOT NULL, action TEXT NOT NULL, window_start TEXT NOT NULL,
        window_seconds INTEGER NOT NULL, request_count INTEGER NOT NULL,
        created_at TEXT, updated_at TEXT);
      CREATE TABLE audit_events (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
        actor_type TEXT, event_type TEXT NOT NULL, entity_type TEXT, entity_id TEXT,
        description TEXT, metadata_json TEXT, created_at TEXT);
      CREATE TABLE workspace_domains (workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL);
      CREATE TABLE managed_cases (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
        status TEXT NOT NULL);
      CREATE TABLE scans (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
        domain TEXT, domain_id TEXT, status TEXT NOT NULL, score INTEGER,
        rating TEXT, scan_quality TEXT, created_at TEXT);
    `);
    const tokenA = `cm_${"a".repeat(64)}`;
    const tokenB = `cm_${"b".repeat(64)}`;
    const expires = new Date(Date.now() + 60_000).toISOString();
    for (const [user, workspace, token, raw] of [
      ["usr_a", "ws_a", "tok_a", tokenA],
      ["usr_b", "ws_b", "tok_b", tokenB],
    ]) {
      sql.prepare("INSERT INTO users VALUES (?, 'active')").run(user);
      sql.prepare("INSERT INTO workspaces VALUES (?, ?, ?, NULL)")
        .run(workspace, `Name ${workspace}`, "owner_other");
      sql.prepare("INSERT INTO workspace_members VALUES (?, ?, 'viewer')")
        .run(workspace, user);
      sql.prepare("INSERT INTO api_tokens VALUES (?, ?, ?, ?, 'read', ?, 'active')")
        .run(token, user, await hashToken(raw), workspace, expires);
    }
    const d1 = { prepare(statement) {
      return { bind(...values) {
        const prepared = sql.prepare(statement);
        return {
          async first() { return prepared.get(...values) ?? null; },
          async run() { return { meta: { changes: prepared.run(...values).changes } }; },
        };
      } };
    } };
    const trial = (workspace, token) => ({
      MCP_INTERNAL_ENABLED: "true", MCP_TRIAL_WORKSPACE_ID: workspace,
      MCP_TRIAL_TOKEN_ID: token, cybermeters_db: d1,
    });
    const read = (envValue, bearer, workspaceId) =>
      getWorkspaceSummaryForMcp(envValue, { bearer, workspaceId });
    const auditCount = () => sql.prepare("SELECT COUNT(*) AS n FROM audit_events").get().n;
    const a = trial("ws_a", "tok_a");
    const b = trial("ws_b", "tok_b");
    assert.equal((await read(a, tokenA, "ws_a")).display_name, "Name ws_a");
    assert.equal((await read(b, tokenB, "ws_b")).display_name, "Name ws_b");
    const afterSuccess = auditCount();
    assert.equal(afterSuccess, 2);

    for (const [trialEnv, bearer, workspaceId] of [
      [a, tokenB, "ws_a"], [b, tokenA, "ws_b"],
      [a, tokenA, "ws_b"], [a, tokenA, "ws_missing"],
    ]) await assert.rejects(read(trialEnv, bearer, workspaceId), /mcp_summary_unavailable/);
    assert.equal(auditCount(), afterSuccess + 4);
    const deniedRows = sql.prepare(
      "SELECT workspace_id, user_id, metadata_json FROM audit_events WHERE event_type = 'mcp_read_denied'",
    ).all();
    assert.equal(deniedRows.length, 4);
    for (const row of deniedRows) {
      assert.equal(row.workspace_id, null);
      assert.equal(row.user_id, null);
      assert.deepEqual(Object.keys(JSON.parse(row.metadata_json)).sort(), ["reason", "request_id"]);
      assert.equal(row.metadata_json.includes(tokenA) || row.metadata_json.includes(tokenB), false);
    }

    sql.prepare("DELETE FROM workspace_members WHERE workspace_id = 'ws_a'").run();
    await assert.rejects(read(a, tokenA, "ws_a"), /mcp_summary_unavailable/);
    sql.prepare("INSERT INTO workspace_members VALUES ('ws_a', 'usr_a', 'viewer')").run();
    sql.prepare("UPDATE api_tokens SET status = 'revoked' WHERE id = 'tok_a'").run();
    await assert.rejects(read(a, tokenA, "ws_a"), /mcp_summary_unavailable/);
    sql.prepare("UPDATE api_tokens SET status = 'active' WHERE id = 'tok_a'").run();
    sql.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'ws_a'").run();
    await assert.rejects(read(a, tokenA, "ws_a"), /mcp_summary_unavailable/);
    sql.prepare("UPDATE workspaces SET deleted_at = NULL WHERE id = 'ws_a'").run();

    for (let i = 0; i < 29; i++) await read(a, tokenA, "ws_a");
    await assert.rejects(read(a, tokenA, "ws_a"), /mcp_summary_unavailable/);
    assert.equal(sql.prepare("SELECT request_count AS n FROM api_rate_limits WHERE scope_id = 'tok_a:ws_a'").get().n, 31);
    assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'mcp_workspace_summary_read' AND workspace_id = 'ws_a'").get().n, 30);
  } finally {
    sql.close();
  }
});
