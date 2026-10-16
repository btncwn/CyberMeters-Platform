#!/usr/bin/env node
// Generate an ignored, synthetic-test-only variant of the isolated staging
// configs. This command never deploys or changes the production configs.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = path.join(root, "local/mcp-staging-resources.json");
const outputs = [
  path.join(root, "workers/scan-api/.wrangler/mcp-staging-test/wrangler.jsonc"),
  path.join(root, "workers/mcp-server/.wrangler/mcp-staging-test/wrangler.jsonc"),
];

export function buildMcpStagingTestConfigs(resources) {
  const { api, mcp } = buildMcpStagingConfigs(resources);
  if (api.vars.MAINTENANCE_MODE !== "on" ||
      api.vars.MCP_STAGING_AUTH_TEST_ENABLED !== "false" ||
      api.vars.MCP_CUSTOMER_OAUTH_ENABLED !== "false" ||
      api.vars.MCP_CUSTOMER_READ_ENABLED !== "false" ||
      api.vars.MCP_OAUTH_DCR_ENABLED !== "false" ||
      mcp.vars.MCP_CUSTOMER_ENABLED !== "false" ||
      api.vars.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS !== "[]" ||
      api.vars.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS !== "[]") {
    throw new Error("Base staging configuration is no longer disabled");
  }
  api.vars = {
    ...api.vars,
    APP_VERSION: "mcp-staging-synthetic-test",
    MCP_STAGING_AUTH_TEST_ENABLED: "true",
    MCP_CUSTOMER_OAUTH_ENABLED: "true",
    MCP_CUSTOMER_READ_ENABLED: "true",
    MCP_OAUTH_DCR_ENABLED: "true",
  };
  mcp.vars = { ...mcp.vars, MCP_CUSTOMER_ENABLED: "true" };
  return { api, mcp };
}

function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--prepare-synthetic-test") {
    throw new Error("Usage: node scripts/generate-mcp-staging-test-config.js --prepare-synthetic-test");
  }
  const stat = fs.lstatSync(manifest);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Staging resource manifest must be a regular file");
  const resources = JSON.parse(fs.readFileSync(manifest, "utf8"));
  const { api, mcp } = buildMcpStagingTestConfigs(resources);
  for (const [target, config] of [[outputs[0], api], [outputs[1], mcp]]) {
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const temp = `${target}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(temp, `${JSON.stringify(config, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      fs.renameSync(temp, target);
    } finally {
      try { fs.unlinkSync(temp); } catch { /* no temporary file remains */ }
    }
  }
  console.log("Prepared ignored synthetic-test staging Worker configs; no deployment was performed.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); }
  catch (error) { console.error(`Staging synthetic-test config refused: ${error.message}`); process.exitCode = 1; }
}
