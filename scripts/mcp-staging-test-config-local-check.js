#!/usr/bin/env node
import assert from "node:assert/strict";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { buildMcpStagingTestConfigs } from "./generate-mcp-staging-test-config.js";

const resources = {
  staging_d1_database_id: "22222222-2222-4222-8222-222222222222",
  staging_oauth_kv_namespace_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  staging_edge_client_rate_namespace_id: "990041",
  staging_edge_global_rate_namespace_id: "990042",
};
const base = buildMcpStagingConfigs(resources);
const test = buildMcpStagingTestConfigs(resources);
const expected = structuredClone(base);
Object.assign(expected.api.vars, {
  APP_VERSION: "mcp-staging-synthetic-test",
  MCP_STAGING_AUTH_TEST_ENABLED: "true",
  MCP_CUSTOMER_OAUTH_ENABLED: "true",
  MCP_CUSTOMER_READ_ENABLED: "true",
  MCP_OAUTH_DCR_ENABLED: "true",
});
expected.mcp.vars.MCP_CUSTOMER_ENABLED = "true";
assert.deepEqual(test, expected,
  "Synthetic-test configs may change only the five explicit flags and staging version");
assert.equal(test.api.vars.MAINTENANCE_MODE, "on");
assert.equal(test.api.vars.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS, "[]");
assert.equal(test.api.vars.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS, "[]");
assert.equal(test.api.routes[0].pattern, "api-staging.cybermeters.com");
assert.equal(test.mcp.routes[0].pattern, "mcp-staging.cybermeters.com");
assert.equal(test.api.d1_databases[0].database_name, "cybermeters-db-staging");
assert.equal(test.mcp.d1_databases, undefined);
assert.equal(test.mcp.services.every((binding) =>
  binding.service === "cybermeters-platform-staging"), true);
assert.throws(() => buildMcpStagingTestConfigs({ ...resources,
  staging_d1_database_id: "11111111-1111-4111-8111-111111111111" }),
/distinct staging D1|fixture|Fixture/);
console.log("MCP staging synthetic-test config PASS: exact flag delta; all routes and bindings remain isolated.");
