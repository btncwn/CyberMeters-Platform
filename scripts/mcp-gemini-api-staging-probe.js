#!/usr/bin/env node
// Optional Gemini Interactions probe for the synthetic MCP staging fixture.
// Import runGeminiSyntheticMcpProbe only while the guarded hosted staging proof
// holds a live OAuth grant. Running this file directly never makes a request.

import path from "node:path";
import { fileURLToPath } from "node:url";

export const GEMINI_INTERACTIONS_URL =
  "https://generativelanguage.googleapis.com/v1beta/interactions";
export const GEMINI_MCP_STAGING_URL = "https://mcp-staging.cybermeters.com/mcp";
const MODEL = "gemini-3.8-flash";
const SERVER_NAME = "cybermeters_staging";
const READ_TOOL = "cybermeters_list_workspaces";
const ACCOUNT_A = "usr_mcp_stage_a";
const WORKSPACE_A = "ws_mcp_stage_a";
const WORKSPACE_B = "ws_mcp_stage_b";
const SYNTHETIC_ACCESS_TOKEN =
  /^usr_mcp_stage_a:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{32}$/;
const MAX_RESPONSE_BYTES = 64 * 1024;

function fail(message) { throw new Error(`Gemini synthetic MCP probe: ${message}`); }

export function buildGeminiSyntheticMcpRequest(apiKey, accessToken) {
  if (typeof apiKey !== "string" || apiKey.length < 20 ||
      /[\r\n\x00-\x1f\x7f]/.test(apiKey)) fail("invalid API key");
  if (typeof accessToken !== "string" ||
      !SYNTHETIC_ACCESS_TOKEN.test(accessToken)) {
    fail("refused a non-fixture-A OAuth access token");
  }
  return {
    url: GEMINI_INTERACTIONS_URL,
    init: {
      method: "POST",
      redirect: "error",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify({
        model: MODEL,
        input: `Call ${READ_TOOL} once. Report the returned synthetic workspace ID only.`,
        tools: [{
          type: "mcp_server",
          name: SERVER_NAME,
          url: GEMINI_MCP_STAGING_URL,
          headers: { Authorization: `Bearer ${accessToken}` },
          allowed_tools: { mode: "any", tools: [READ_TOOL] },
        }],
        store: false,
        background: false,
        stream: false,
        generation_config: { max_output_tokens: 256 },
      }),
    },
  };
}

function projectedWorkspaceList(result) {
  try {
    let value = result;
    if (value && !Array.isArray(value) && Array.isArray(value.content)) {
      value = value.content;
    }
    if (Array.isArray(value)) {
      if (value.length !== 1 || value[0]?.type !== "text" ||
          typeof value[0].text !== "string") fail("unexpected MCP result shape");
      value = value[0].text;
    }
    if (typeof value === "string") value = JSON.parse(value);
    return value;
  } catch { fail("unexpected MCP result shape"); }
}

export function validateGeminiSyntheticMcpResponse(interaction) {
  if (interaction?.status !== "completed" || !Array.isArray(interaction.steps)) {
    fail("interaction did not complete with steps");
  }
  const calls = interaction.steps.filter((step) => step?.type === "mcp_server_tool_call");
  const results = interaction.steps.filter((step) => step?.type === "mcp_server_tool_result");
  if (calls.length !== 1 || results.length !== 1 ||
      calls[0].server_name !== SERVER_NAME || calls[0].name !== READ_TOOL ||
      results[0].call_id !== calls[0].id ||
      (results[0].server_name && results[0].server_name !== SERVER_NAME) ||
      (results[0].name && results[0].name !== READ_TOOL) ||
      results[0].is_error === true) {
    fail("expected exactly one successful workspace-list MCP call");
  }
  // Inspect the actual MCP result, not a model-written answer that may guess.
  const projected = projectedWorkspaceList(results[0].result);
  const rawResult = JSON.stringify(projected);
  if (!Array.isArray(projected?.workspaces) || projected.workspaces.length !== 1 ||
      projected.workspaces[0]?.workspace_id !== WORKSPACE_A ||
      projected.isError === true || rawResult.includes(WORKSPACE_B) ||
      rawResult.includes(ACCOUNT_A)) {
    fail("MCP result did not prove fixture-A-only access");
  }
  return { model: MODEL, tool: READ_TOOL, workspaceId: WORKSPACE_A, toolCalls: 1 };
}

async function boundedJson(response) {
  if (!response.body) fail("empty Google response");
  const reader = response.body.getReader();
  const parts = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        fail("Google response exceeded size limit");
      }
      parts.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail("Google response was not valid JSON"); }
}

/** Exactly one outbound Google request, with no retries or response-body logging. */
export async function runGeminiSyntheticMcpProbe({ apiKey, accessToken, fetchImpl = fetch }) {
  const { url, init } = buildGeminiSyntheticMcpRequest(apiKey, accessToken);
  let response;
  try {
    response = await fetchImpl(url, {
      ...init,
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    fail("Google request failed or timed out");
  }
  if (response.status !== 200) fail(`Google returned HTTP ${response.status}`);
  return validateGeminiSyntheticMcpResponse(await boundedJson(response));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log("Offline only: import this probe from the guarded synthetic staging OAuth flow.");
}
