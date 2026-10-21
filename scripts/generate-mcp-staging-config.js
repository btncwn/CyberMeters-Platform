#!/usr/bin/env node
// Generate isolated staging Worker configs. This command never deploys.
// Keep the resource manifest in ignored local/ or outside the repository.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const staging = Object.freeze({
  apiWorker: "cybermeters-platform-staging",
  mcpWorker: "cybermeters-mcp-server-staging",
  apiHost: "api-staging.cybermeters.com",
  mcpHost: "mcp-staging.cybermeters.com",
  appOrigin: "https://app-staging.cybermeters.com",
  d1Name: "cybermeters-db-staging",
  r2Name: "cybermeters-reports-staging",
});
const productionApiConfig = fs.readFileSync(path.join(root, "workers/scan-api/wrangler.toml"), "utf8");
const productionMcpConfig = fs.readFileSync(path.join(root, "workers/mcp-server/wrangler.toml"), "utf8");
const productionD1Ids = new Set([...productionApiConfig.matchAll(
  /^database_id\s*=\s*"([0-9a-f-]+)"\s*$/gm,
)].map((match) => match[1]));
const productionKvIds = new Set([...productionApiConfig.matchAll(
  /^id\s*=\s*"([a-f0-9]{32})"\s*$/gm,
)].map((match) => match[1]));
const productionRateIds = new Set([...productionMcpConfig.matchAll(
  /^namespace_id\s*=\s*"([0-9]+)"\s*$/gm,
)].map((match) => match[1]));
if (productionD1Ids.size === 0 || productionRateIds.size < 2) {
  throw new Error("Cannot read production resource IDs; staging configuration generation is disabled");
}
const fixture = Object.freeze({
  staging_d1_database_id: "11111111-1111-4111-8111-111111111111",
  staging_oauth_kv_namespace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  staging_edge_client_rate_namespace_id: "990031",
  staging_edge_global_rate_namespace_id: "990032",
});
const manifestKeys = Object.keys(fixture).sort();

function requireStageResources(input, allowFixture = false) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      JSON.stringify(Object.keys(input).sort()) !== JSON.stringify(manifestKeys)) {
    throw new Error(`Manifest must contain exactly: ${manifestKeys.join(", ")}`);
  }
  const values = Object.values(input);
  if (!values.every((value) => typeof value === "string" && value === value.trim())) {
    throw new Error("Staging resource IDs must be nonempty strings without surrounding whitespace");
  }
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(input.staging_d1_database_id) ||
      productionD1Ids.has(input.staging_d1_database_id)) {
    throw new Error("A distinct staging D1 database UUID is required");
  }
  if (!/^[a-f0-9]{32}$/.test(input.staging_oauth_kv_namespace_id) ||
      productionKvIds.has(input.staging_oauth_kv_namespace_id)) {
    throw new Error("A staging OAuth KV namespace ID (32 lowercase hex characters) is required");
  }
  const rateIds = [input.staging_edge_client_rate_namespace_id,
    input.staging_edge_global_rate_namespace_id];
  if (rateIds.some((id) => !/^[1-9][0-9]{0,9}$/.test(id) || productionRateIds.has(id)) ||
      rateIds[0] === rateIds[1]) {
    throw new Error("Two distinct staging rate-limit namespace IDs are required");
  }
  if (!allowFixture && manifestKeys.some((key) => input[key] === fixture[key])) {
    throw new Error("Local fixture IDs cannot be used for a staging configuration");
  }
  return input;
}

export function buildMcpStagingConfigs(input, { allowFixture = false } = {}) {
  const resources = requireStageResources(input, allowFixture);
  const api = {
    name: staging.apiWorker,
    main: "../../src/worker.js",
    compatibility_date: "2026-06-18",
    compatibility_flags: ["global_fetch_strictly_public"],
    workers_dev: false,
    preview_urls: false,
    routes: [{ pattern: staging.apiHost, custom_domain: true }],
    limits: { subrequests: 10000 },
    observability: { enabled: true, traces: { enabled: true } },
    d1_databases: [{
      binding: "cybermeters_db", database_name: staging.d1Name,
      database_id: resources.staging_d1_database_id,
    }],
    kv_namespaces: [{ binding: "OAUTH_KV", id: resources.staging_oauth_kv_namespace_id }],
    r2_buckets: [{ binding: "cybermeters_reports", bucket_name: staging.r2Name }],
    version_metadata: { binding: "CF_VERSION_METADATA" },
    vars: {
      APP_VERSION: "mcp-staging-disabled",
      MAINTENANCE_MODE: "on",
      MCP_STAGING_AUTH_TEST_ENABLED: "false",
      MCP_DEPLOYMENT_TIER: "staging",
      MCP_STAGING_ISSUER: `https://${staging.apiHost}`,
      MCP_STAGING_RESOURCE: `https://${staging.mcpHost}/mcp`,
      MCP_STAGING_APP_ORIGIN: staging.appOrigin,
      MCP_CUSTOMER_OAUTH_ENABLED: "false",
      MCP_CUSTOMER_READ_ENABLED: "false",
      MCP_OAUTH_DCR_ENABLED: "false",
      MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS: "[]",
      MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS: "[]",
      ALLOWED_ORIGIN: staging.appOrigin,
      FRONTEND_URL: staging.appOrigin,
      MICROSOFT_REDIRECT_URI: `https://${staging.apiHost}/api/auth/microsoft/callback`,
      RUA_INBOUND_DOMAIN: "reports-staging.cybermeters.com",
      SCAN_DISPATCH_MODE: "queue",
      SCHEDULED_DISPATCH_MODE: "queue",
      EXPOSURE_SCAN_MODE: "disabled",
      TLS_ASSESSMENT_MODE: "disabled",
      INDEPENDENT_BACKUP_MONITORING: "off",
    },
  };
  const mcp = {
    name: staging.mcpWorker,
    main: "../../src/index.js",
    compatibility_date: "2026-06-18",
    compatibility_flags: ["nodejs_compat", "global_fetch_strictly_public"],
    workers_dev: false,
    preview_urls: false,
    assets: { directory: "../../public" },
    routes: [{ pattern: staging.mcpHost, custom_domain: true }],
    observability: { enabled: true, traces: { enabled: true } },
    vars: {
      MCP_DEPLOYMENT_TIER: "staging",
      MCP_STAGING_ISSUER: `https://${staging.apiHost}`,
      MCP_STAGING_RESOURCE: `https://${staging.mcpHost}/mcp`,
      MCP_STAGING_APP_ORIGIN: staging.appOrigin,
      MCP_CUSTOMER_ENABLED: "false",
    },
    ratelimits: [
      { name: "MCP_EDGE_CLIENT_RATE", namespace_id: resources.staging_edge_client_rate_namespace_id,
        simple: { limit: 120, period: 60 } },
      { name: "MCP_EDGE_GLOBAL_RATE", namespace_id: resources.staging_edge_global_rate_namespace_id,
        simple: { limit: 1000, period: 60 } },
    ],
    services: [
      { binding: "MCP_BACKEND", service: staging.apiWorker, entrypoint: "McpReadService", remote: false },
      { binding: "MCP_AUTH", service: staging.apiWorker,
        entrypoint: "McpOAuthAuthorizationService", remote: false },
      { binding: "MCP_CUSTOMER_BACKEND", service: staging.apiWorker,
        entrypoint: "McpCustomerReadService", remote: false },
    ],
  };
  return { api, mcp };
}

export function writeMcpStagingConfigs(resources) {
  const configs = buildMcpStagingConfigs(resources);
  const outputs = [
    ["scan-api", configs.api],
    ["mcp-server", configs.mcp],
  ];
  const paths = [];
  for (const [worker, config] of outputs) {
    const directory = path.join(root, "workers", worker, ".wrangler", "mcp-staging");
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const target = path.join(directory, "wrangler.jsonc");
    const temporary = `${target}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, target);
    paths.push(target);
  }
  return paths;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const suppliedPath = process.argv[2];
  if (process.argv.length !== 3 || !suppliedPath) {
    console.error("Usage: node scripts/generate-mcp-staging-config.js local/mcp-staging-resources.json");
    process.exit(2);
  }
  try {
    const manifestPath = path.resolve(suppliedPath);
    const relative = path.relative(root, manifestPath);
    if (!relative.startsWith("..") && !path.isAbsolute(relative) &&
        !relative.startsWith(`local${path.sep}`) && !relative.startsWith(`tmp${path.sep}`)) {
      throw new Error("Keep the resource manifest in ignored local/ or tmp/, or outside the repository");
    }
    const resources = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    for (const output of writeMcpStagingConfigs(resources)) console.log(`Generated ${output}`);
    console.log("Customer flags remain false. Review both configs and resources before any deploy.");
  } catch (error) {
    console.error(`Staging config generation refused: ${error.message}`);
    process.exit(1);
  }
}
