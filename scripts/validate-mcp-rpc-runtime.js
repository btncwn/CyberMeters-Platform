#!/usr/bin/env node
// Disposable local workerd proof for the named MCP service binding and D1 gates.
// Requires npm ci in both Worker directories; never uses --remote.
import assert from "node:assert/strict";
import { createHash, randomInt } from "node:crypto";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const gatewayDir = join(repo, "workers/mcp-server");
const wrangler = join(gatewayDir, "node_modules/.bin/wrangler");
const tokenA = `cm_${"a".repeat(64)}`;
const tokenB = `cm_${"b".repeat(64)}`;
const hash = (value) => createHash("sha256").update(value).digest("hex");
const tool = "cybermeters_get_workspace_summary";

async function main() {
  const temp = await mkdtemp(join(tmpdir(), "cybermeters-mcp-rpc-"));
  const port = randomInt(20_000, 45_000);
  const gatewayConfig = join(temp, "gateway.json");
  const backendConfig = join(temp, "backend.json");
  const seed = join(temp, "seed.sql");
  const state = join(temp, "state");
  const commandEnv = {
    ...process.env,
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_LOG_PATH: join(temp, "wrangler.log"),
  };
  let server;
  try {
    await writeFile(gatewayConfig, JSON.stringify({
      name: "cybermeters-mcp-server",
      main: join(gatewayDir, "src/index.js"),
      compatibility_date: "2026-06-18",
      compatibility_flags: ["nodejs_compat"],
      workers_dev: false,
      services: [{ binding: "MCP_BACKEND", service: "cybermeters-platform",
        entrypoint: "McpReadService", remote: false }],
      vars: { MCP_INTERNAL_ENABLED: "true" },
    }));
    await writeFile(backendConfig, JSON.stringify({
      name: "cybermeters-platform",
      main: join(repo, "workers/scan-api/src/worker.js"),
      compatibility_date: "2026-06-18",
      compatibility_flags: ["global_fetch_strictly_public"],
      workers_dev: false,
      d1_databases: [{ binding: "cybermeters_db", database_name: "mcp-disposable-local",
        database_id: "00000000-0000-4000-8000-000000000001" }],
      vars: { MCP_INTERNAL_ENABLED: "true", MCP_TRIAL_WORKSPACE_ID: "ws_a",
        MCP_TRIAL_TOKEN_ID: "tok_a" },
    }));
    await writeFile(seed, `
      CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT NOT NULL);
      CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL,
        owner_user_id TEXT NOT NULL, deleted_at TEXT);
      CREATE TABLE workspace_members (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL);
      CREATE TABLE api_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL,
        workspace_id TEXT, scope TEXT NOT NULL, expires_at TEXT, status TEXT NOT NULL);
      CREATE TABLE api_rate_limits (id TEXT PRIMARY KEY, scope TEXT NOT NULL, scope_id TEXT NOT NULL,
        action TEXT NOT NULL, window_start TEXT NOT NULL, window_seconds INTEGER NOT NULL,
        request_count INTEGER NOT NULL, created_at TEXT, updated_at TEXT);
      CREATE TABLE audit_events (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, actor_type TEXT,
        event_type TEXT NOT NULL, entity_type TEXT, entity_id TEXT, description TEXT,
        metadata_json TEXT, created_at TEXT);
      INSERT INTO users VALUES ('usr_a', 'active'), ('usr_b', 'active');
      INSERT INTO workspaces VALUES ('ws_a', 'Workspace A', 'other_owner', NULL),
        ('ws_b', 'Workspace B', 'other_owner', NULL);
      INSERT INTO workspace_members VALUES ('ws_a', 'usr_a', 'viewer'), ('ws_b', 'usr_b', 'viewer');
      INSERT INTO api_tokens VALUES ('tok_a', 'usr_a', '${hash(tokenA)}', 'ws_a', 'read',
        '2099-01-01T00:00:00.000Z', 'active'),
        ('tok_b', 'usr_b', '${hash(tokenB)}', 'ws_b', 'read',
        '2099-01-01T00:00:00.000Z', 'active');
    `);

    async function d1(sqlOrFile, isFile = false) {
      const args = ["d1", "execute", "mcp-disposable-local", "--config", backendConfig,
        "--local", "--persist-to", state, isFile ? "--file" : "--command", sqlOrFile,
        "--yes", "--json"];
      const { stdout } = await exec(wrangler, args, { cwd: gatewayDir, env: commandEnv,
        timeout: 30_000, maxBuffer: 1024 * 1024 });
      const result = JSON.parse(stdout);
      assert.equal(result[0]?.success, true);
      return result[0].results;
    }
    await d1(seed, true);

    server = spawn(wrangler, ["dev", "-c", gatewayConfig, "-c", backendConfig,
      "--local", "--port", String(port), "--inspector-port", "0", "--persist-to", state],
    { cwd: gatewayDir, env: commandEnv, stdio: ["ignore", "pipe", "pipe"] });
    await new Promise((resolveReady, rejectReady) => {
      let output = "";
      const timeout = setTimeout(() => rejectReady(new Error("Local Workers did not start")), 45_000);
      const onData = (chunk) => {
        output = (output + chunk.toString()).slice(-8_192);
        if (output.includes("Ready on http://")) {
          clearTimeout(timeout);
          resolveReady();
        }
      };
      server.stdout.on("data", onData);
      server.stderr.on("data", onData);
      server.once("exit", (code) => {
        clearTimeout(timeout);
        rejectReady(new Error(`Local Workers exited ${code}: ${output.slice(-1_000)}`));
      });
    });

    async function call(bearer, workspaceId) {
      const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "mcp-protocol-version": "2026-07-28",
          "mcp-method": "tools/call",
          "mcp-name": tool,
          ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
          name: tool, arguments: { workspace_id: workspaceId },
          _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {} },
        } }),
      });
      return { status: response.status, body: await response.json() };
    }
    function denied(response) {
      assert.equal(response.status, 200);
      assert.equal(response.body.result.isError, true);
      assert.equal(response.body.result.content[0].text, "workspace_summary_unavailable");
      assert.equal(JSON.stringify(response.body).includes(tokenA), false);
      assert.equal(JSON.stringify(response.body).includes(tokenB), false);
      assert.equal(JSON.stringify(response.body).includes("Workspace B"), false);
    }
    const own = await call(tokenA, "ws_a");
    assert.equal(own.status, 200);
    assert.equal(own.body.result.isError, undefined);
    assert.equal(JSON.parse(own.body.result.content[0].text).workspace_id, "ws_a");
    for (const [bearer, workspace] of [
      [tokenA, "ws_b"], [tokenA, "ws_missing"], [tokenB, "ws_a"],
    ]) denied(await call(bearer, workspace));
    const missing = await call(null, "ws_a");
    assert.equal(missing.status, 401);
    assert.deepEqual(missing.body, { error: "invalid_bearer" });

    for (let i = 0; i < 29; i++) {
      const response = await call(tokenA, "ws_a");
      assert.equal(response.body.result.isError, undefined);
    }
    denied(await call(tokenA, "ws_a"));
    const events = await d1("SELECT event_type, workspace_id, user_id, metadata_json FROM audit_events");
    assert.equal(events.filter((row) => row.event_type === "mcp_workspace_summary_read").length, 30);
    const denials = events.filter((row) => row.event_type === "mcp_read_denied");
    assert.equal(denials.length, 4);
    for (const row of denials) {
      assert.equal(row.workspace_id, null);
      assert.equal(row.user_id, null);
      assert.deepEqual(Object.keys(JSON.parse(row.metadata_json)).sort(), ["reason", "request_id"]);
    }
    assert.equal(JSON.stringify(events).includes(tokenA), false);
    assert.equal(JSON.stringify(events).includes(tokenB), false);
    const limit = await d1("SELECT request_count FROM api_rate_limits WHERE scope_id = 'tok_a:ws_a'");
    assert.equal(limit[0].request_count, 31);
    console.log("PASS local two-Worker RPC, two-tenant denial, atomic D1 budget, durable audit");
  } finally {
    if (server && server.exitCode === null && server.signalCode === null) {
      server.kill("SIGINT");
      await new Promise((resolveExit) => {
        const timeout = setTimeout(() => {
          server.kill("SIGKILL");
          resolveExit();
        }, 3_000);
        server.once("exit", () => {
          clearTimeout(timeout);
          resolveExit();
        });
      });
    }
    await rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
