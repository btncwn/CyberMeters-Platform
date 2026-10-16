import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  describeMcpDiscoveryFailure, EXPECTED_TOOL_NAMES, isAllowedHostedStagingUrl,
  isReusableSyntheticClientRecord, parseHostedStagingFlags, proveSequentialMcpReads,
} from "./mcp-hosted-staging-probe.js";

const script = fileURLToPath(new URL("./mcp-hosted-staging-probe.js", import.meta.url));

test("hosted proof refuses invocation without the exact explicit switch", () => {
  for (const args of [[], ["--help"], ["--run-hosted-staging", "https://api.cybermeters.com"]]) {
    const result = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /requires the exact --run-hosted-staging argument/);
    assert.equal(result.stdout, "");
  }
});

test("hosted proof can fetch only the exact staging origins and approved paths", () => {
  for (const url of [
    "https://api-staging.cybermeters.com/health",
    "https://api-staging.cybermeters.com/ready",
    "https://api-staging.cybermeters.com/api/auth/signup",
    "https://api-staging.cybermeters.com/api/free-scan",
    "https://api-staging.cybermeters.com/api/workspaces",
    "https://api-staging.cybermeters.com/api/billing/plans",
    "https://api-staging.cybermeters.com/.well-known/oauth-authorization-server",
    "https://api-staging.cybermeters.com/api/auth/login",
    "https://api-staging.cybermeters.com/api/auth/me",
    "https://api-staging.cybermeters.com/oauth/register",
    "https://api-staging.cybermeters.com/authorize?response_type=code",
    "https://api-staging.cybermeters.com/api/mcp/oauth/browser-session",
    "https://api-staging.cybermeters.com/authorize?intent=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "https://api-staging.cybermeters.com/oauth/token",
    "https://api-staging.cybermeters.com/api/mcp/oauth/connections?offset=0",
    "https://api-staging.cybermeters.com/api/mcp/oauth/connections/mcpconn_11111111-1111-4111-8111-111111111111",
    "https://api-staging.cybermeters.com/api/auth/logout",
    "https://app-staging.cybermeters.com/mcp/connect",
    "https://mcp-staging.cybermeters.com/mcp",
    "https://mcp-staging.cybermeters.com/.well-known/oauth-protected-resource/mcp",
  ]) assert.equal(isAllowedHostedStagingUrl(url), true, url);
  for (const url of [
    "https://api.cybermeters.com/health",
    "https://mcp.cybermeters.com/mcp",
    "https://app.cybermeters.com/mcp/connect",
    "http://api-staging.cybermeters.com/health",
    "https://api-staging.cybermeters.com.evil.invalid/health",
    "https://api-staging.cybermeters.com/api/workspaces/anything",
    "https://api-staging.cybermeters.com/api/mcp/oauth/connections?offset=-1",
    "https://api-staging.cybermeters.com/api/mcp/oauth/connections?offset=0&other=1",
    "https://mcp-staging.cybermeters.com/mcp?next=1",
    "http://127.0.0.1:55321/callback",
  ]) assert.equal(isAllowedHostedStagingUrl(url), false, url);
});

test("tool discovery diagnostic reveals only fixed protocol categories", () => {
  assert.equal(describeMcpDiscoveryFailure({ status: 503,
    value: { error: "mcp_not_configured" } }),
  "HTTP 503; code=mcp_not_configured");
  assert.equal(describeMcpDiscoveryFailure({ status: 429,
    value: { error: "mcp_rate_limited" } }),
  "HTTP 429; code=mcp_rate_limited");
  assert.equal(describeMcpDiscoveryFailure({ status: 500,
    value: { error: { code: -32603, message: "private result and bearer" } } }),
  "HTTP 500; code=jsonrpc_-32603");
  assert.equal(describeMcpDiscoveryFailure({ status: 401,
    value: { error: "Bearer secret customer.example" } }),
  "HTTP 401; code=unknown");
  assert.equal(describeMcpDiscoveryFailure({ status: 200,
    value: { result: { tools: [{ name: "private result" }] } } }),
  "HTTP 200; code=unknown");
});

test("reusable client is an opaque DCR ID bound to the exact synthetic callback", () => {
  const valid = { clientId: "AbC_123456789-xy",
    callback: "http://127.0.0.1:53119/callback" };
  assert.equal(isReusableSyntheticClientRecord(valid), true);
  for (const invalid of [
    { ...valid, clientId: "https://client.example/metadata" },
    { ...valid, clientId: "short" },
    { ...valid, callback: "http://localhost:53119/callback" },
    { ...valid, callback: "http://127.0.0.1:1024/callback" },
    { ...valid, callback: "http://127.0.0.1:53119/callback?next=1" },
    { ...valid, callback: "http://127.0.0.1:53119/callback#fragment" },
    { ...valid, callback: "http://127.0.0.1:53119/callback/../callback" },
    { ...valid, secret: "unexpected" },
  ]) assert.equal(isReusableSyntheticClientRecord(invalid), false);
});

test("hosted command accepts reuse only as an explicit opt-in", () => {
  assert.deepEqual(parseHostedStagingFlags(["--run-hosted-staging"]),
    { geminiApiProbe: false, reuseSyntheticClient: false, reliabilityProbe: false });
  assert.deepEqual(parseHostedStagingFlags(["--run-hosted-staging", "--reuse-synthetic-client",
    "--gemini-api-probe", "--reliability-probe"]),
  { geminiApiProbe: true, reuseSyntheticClient: true, reliabilityProbe: true });
  for (const args of [
    ["--reliability-probe"],
    ["--reuse-synthetic-client"],
    ["--run-hosted-staging", "--reliability-probe", "--reliability-probe"],
    ["--run-hosted-staging", "--reuse-synthetic-client", "--reuse-synthetic-client"],
    ["--run-hosted-staging", "--reuse-synthetic-client", "--unknown"],
  ]) assert.equal(parseHostedStagingFlags(args), null);
});

const identity = { workspaceId: "synthetic-a", workspaceName: "Synthetic A" };
function successfulReadCall(calls) {
  return async (_token, method, params) => {
    calls.push({ method, params });
    if (method === "tools/list") return { status: 200,
      value: { result: { tools: EXPECTED_TOOL_NAMES.map((name) => ({ name })) } } };
    return { status: 200, value: { result: { content: [{ type: "text",
      text: JSON.stringify({ workspaces: [{ workspace_id: identity.workspaceId,
        display_name: identity.workspaceName }] }) }] } } };
  };
}

test("default proof keeps one discovery and own-workspace read", async () => {
  const calls = [];
  await proveSequentialMcpReads({ token: "synthetic", identity,
    call: successfulReadCall(calls) });
  assert.deepEqual(calls.map(({ method }) => method), ["tools/list", "tools/call"]);
  assert.deepEqual(calls[1].params,
    { name: "cybermeters_list_workspaces", arguments: {} });
});

test("reliability probe checks five sequential discovery and own-workspace pairs", async () => {
  const calls = [];
  await proveSequentialMcpReads({ token: "synthetic", identity, rounds: 5,
    call: successfulReadCall(calls) });
  assert.equal(calls.length, 10);
  assert.deepEqual(calls.map(({ method }) => method),
    Array.from({ length: 5 }, () => ["tools/list", "tools/call"]).flat());
  assert.ok(calls.filter(({ method }) => method === "tools/call")
    .every(({ params }) => params.name === "cybermeters_list_workspaces" &&
      Object.keys(params.arguments).length === 0));
});

test("reliability probe stops on the first discovery failure without retrying", async () => {
  const calls = [];
  const success = successfulReadCall(calls);
  const call = async (...args) => {
    if (calls.length === 4) {
      calls.push({ method: args[1] });
      return { status: 503, value: { error: "mcp_not_configured",
        secret: "must never appear in diagnostics" } };
    }
    return success(...args);
  };
  await assert.rejects(proveSequentialMcpReads({ token: "synthetic", identity,
    rounds: 5, call }), (error) => {
    assert.match(error.message, /round 3\/5; HTTP 503; code=mcp_not_configured/);
    assert.doesNotMatch(error.message, /secret|must never appear/);
    return true;
  });
  assert.deepEqual(calls.map(({ method }) => method),
    ["tools/list", "tools/call", "tools/list", "tools/call", "tools/list"]);
});

test("reliability probe stops on a workspace error without a later discovery", async () => {
  const calls = [];
  const success = successfulReadCall(calls);
  const call = async (...args) => {
    if (calls.length === 3) {
      calls.push({ method: args[1] });
      return { status: 500, value: { result: { isError: true,
        content: [{ type: "text", text: "private customer data" }] } } };
    }
    return success(...args);
  };
  await assert.rejects(proveSequentialMcpReads({ token: "synthetic", identity,
    rounds: 5, call }), (error) => {
    assert.match(error.message, /Workspace list \(round 2\/5\): MCP read failed \(HTTP 500; tool_error=true; code=unknown\)/);
    assert.doesNotMatch(error.message, /private customer data/);
    return true;
  });
  assert.deepEqual(calls.map(({ method }) => method),
    ["tools/list", "tools/call", "tools/list", "tools/call"]);
});
