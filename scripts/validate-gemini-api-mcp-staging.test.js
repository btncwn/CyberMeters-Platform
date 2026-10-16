import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  buildGeminiSyntheticMcpRequest, runGeminiSyntheticMcpProbe,
  validateGeminiSyntheticMcpResponse,
} from "./mcp-gemini-api-staging-probe.js";

const apiKey = "test_google_key_12345678901234567890";
const token = `usr_mcp_stage_a:${"a".repeat(16)}:${"b".repeat(32)}`;

function response(workspaceId = "ws_mcp_stage_a") {
  return {
    status: "completed",
    steps: [
      { type: "mcp_server_tool_call", id: "call_1", server_name: "cybermeters_staging",
        name: "cybermeters_list_workspaces", arguments: {} },
      { type: "mcp_server_tool_result", call_id: "call_1", name: "cybermeters_list_workspaces",
        result: [{ type: "text", text: JSON.stringify({ workspaces: [{ workspace_id: workspaceId }] }) }] },
    ],
  };
}

test("direct execution is inert even when credential-like environment variables exist", () => {
  const script = fileURLToPath(new URL("./mcp-gemini-api-staging-probe.js", import.meta.url));
  const result = spawnSync(process.execPath, [script, "--execute"], {
    encoding: "utf8",
    env: { ...process.env, GEMINI_API_KEY: apiKey, MCP_STAGING_OAUTH_ACCESS_TOKEN: token },
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Offline only/);
  assert.equal(result.stderr, "");
  assert.equal(result.stdout.includes(apiKey), false);
  assert.equal(result.stdout.includes(token), false);
});

test("request is restricted to one synthetic user, one server and one read tool", () => {
  const request = buildGeminiSyntheticMcpRequest(apiKey, token);
  assert.equal(request.url, "https://generativelanguage.googleapis.com/v1beta/interactions");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.redirect, "error");
  assert.equal(request.init.headers["x-goog-api-key"], apiKey);
  const body = JSON.parse(request.init.body);
  assert.equal(body.model, "gemini-3.8-flash");
  assert.equal(body.store, false);
  assert.equal(body.background, false);
  assert.equal(body.stream, false);
  assert.equal(body.generation_config.max_output_tokens, 256);
  assert.deepEqual(body.tools, [{ type: "mcp_server", name: "cybermeters_staging",
    url: "https://mcp-staging.cybermeters.com/mcp",
    headers: { Authorization: `Bearer ${token}` },
    allowed_tools: { mode: "any", tools: ["cybermeters_list_workspaces"] } }]);
  assert.equal(body.input.includes(token), false);
  for (const invalid of [
    `usr_mcp_stage_b:${"a".repeat(16)}:${"b".repeat(32)}`,
    `usr_mcp_stage_a:${"a".repeat(16)}:${"b".repeat(31)}`,
    "not-an-oauth-token",
  ]) assert.throws(() => buildGeminiSyntheticMcpRequest(apiKey, invalid), /non-fixture-A/);
});

test("response evaluator requires actual matching MCP result with fixture A only", () => {
  assert.deepEqual(validateGeminiSyntheticMcpResponse(response()), {
    model: "gemini-3.8-flash", tool: "cybermeters_list_workspaces",
    workspaceId: "ws_mcp_stage_a", toolCalls: 1,
  });
  assert.throws(() => validateGeminiSyntheticMcpResponse(response("ws_mcp_stage_b")),
    /fixture-A-only/);
  const extra = response();
  extra.steps[1].result[0].text = JSON.stringify({
    workspaces: [{ workspace_id: "ws_mcp_stage_a" }, { workspace_id: "ws_mcp_stage_b" }],
  });
  assert.throws(() => validateGeminiSyntheticMcpResponse(extra), /fixture-A-only/);
  const duplicate = response();
  duplicate.steps.push(duplicate.steps[0]);
  assert.throws(() => validateGeminiSyntheticMcpResponse(duplicate), /exactly one/);
  const wrongTool = response();
  wrongTool.steps[0].name = "cybermeters_list_domains";
  assert.throws(() => validateGeminiSyntheticMcpResponse(wrongTool), /exactly one/);
});

test("probe makes one request, returns only synthetic IDs, and hides remote error bodies", async () => {
  let calls = 0;
  const result = await runGeminiSyntheticMcpProbe({ apiKey, accessToken: token,
    fetchImpl: async (url, init) => {
      calls++;
      assert.equal(url, "https://generativelanguage.googleapis.com/v1beta/interactions");
      assert.equal(init.redirect, "error");
      return new Response(JSON.stringify(response()), { status: 200 });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.workspaceId, "ws_mcp_stage_a");

  await assert.rejects(runGeminiSyntheticMcpProbe({ apiKey, accessToken: token,
    fetchImpl: async () => new Response(`server error ${apiKey} ${token}`, { status: 500 }),
  }), (error) => error.message === "Gemini synthetic MCP probe: Google returned HTTP 500");
});
