#!/usr/bin/env node
// Offline staging isolation check. Only fake resources are used for dry-runs;
// no Cloudflare API request or deployment is made.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = Object.freeze({
  staging_d1_database_id: "11111111-1111-4111-8111-111111111111",
  staging_oauth_kv_namespace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  staging_edge_client_rate_namespace_id: "990031",
  staging_edge_global_rate_namespace_id: "990032",
});
let checks = 0;
function check(label, fn) {
  fn();
  checks += 1;
  console.log(`PASS ${label}`);
}

const { api, mcp } = buildMcpStagingConfigs(fixture, { allowFixture: true });
const production = fs.readFileSync(path.join(root, "workers/scan-api/wrangler.toml"), "utf8");
const productionD1Id = production.match(/database_id\s*=\s*"([^"]+)"/)?.[1];
assert.ok(productionD1Id, "Production D1 ID must be readable for isolation checks");

check("fixed staging hosts and distinct Worker names", () => {
  assert.equal(api.name, "cybermeters-platform-staging");
  assert.equal(mcp.name, "cybermeters-mcp-server-staging");
  assert.deepEqual(api.routes, [{ pattern: "api-staging.cybermeters.com", custom_domain: true }]);
  assert.deepEqual(mcp.routes, [{ pattern: "mcp-staging.cybermeters.com", custom_domain: true }]);
  assert.equal(api.workers_dev, false);
  assert.equal(mcp.workers_dev, false);
  assert.equal(api.preview_urls, false);
  assert.equal(mcp.preview_urls, false);
});
check("dedicated staging data and no production database", () => {
  assert.deepEqual(api.d1_databases, [{ binding: "cybermeters_db",
    database_name: "cybermeters-db-staging", database_id: fixture.staging_d1_database_id }]);
  assert.deepEqual(api.kv_namespaces, [{ binding: "OAUTH_KV",
    id: fixture.staging_oauth_kv_namespace_id }]);
  assert.deepEqual(api.r2_buckets, [{ binding: "cybermeters_reports",
    bucket_name: "cybermeters-reports-staging" }]);
  assert.notEqual(api.d1_databases[0].database_id, productionD1Id);
  assert.ok(!JSON.stringify({ api, mcp }).includes(productionD1Id));
});
check("private gateway bindings all target staging API", () => {
  assert.deepEqual(mcp.services.map(({ binding, service, entrypoint, remote }) =>
    [binding, service, entrypoint, remote]), [
    ["MCP_BACKEND", api.name, "McpReadService", false],
    ["MCP_AUTH", api.name, "McpOAuthAuthorizationService", false],
    ["MCP_CUSTOMER_BACKEND", api.name, "McpCustomerReadService", false],
  ]);
  assert.equal(mcp.d1_databases, undefined);
  assert.equal(mcp.kv_namespaces, undefined);
  assert.equal(mcp.r2_buckets, undefined);
});
check("staging origins explicit and customer access disabled", () => {
  assert.deepEqual(api.compatibility_flags, ["global_fetch_strictly_public"]);
  assert.deepEqual(mcp.compatibility_flags, ["nodejs_compat", "global_fetch_strictly_public"]);
  for (const config of [api, mcp]) {
    assert.equal(config.vars.MCP_DEPLOYMENT_TIER, "staging");
    assert.equal(config.vars.MCP_STAGING_ISSUER, "https://api-staging.cybermeters.com");
    assert.equal(config.vars.MCP_STAGING_RESOURCE, "https://mcp-staging.cybermeters.com/mcp");
    assert.equal(config.vars.MCP_STAGING_APP_ORIGIN, "https://app-staging.cybermeters.com");
  }
  assert.equal(api.vars.MCP_CUSTOMER_OAUTH_ENABLED, "false");
  assert.equal(api.vars.MCP_CUSTOMER_READ_ENABLED, "false");
  assert.equal(api.vars.MCP_OAUTH_DCR_ENABLED, "false");
  assert.equal(api.vars.MAINTENANCE_MODE, "on");
  assert.equal(api.vars.MCP_STAGING_AUTH_TEST_ENABLED, "false");
  assert.equal(api.vars.MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS, "[]");
  assert.equal(api.vars.MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS, "[]");
  assert.equal(mcp.vars.MCP_CUSTOMER_ENABLED, "false");
  assert.equal(api.vars.ALLOWED_ORIGIN, "https://app-staging.cybermeters.com");
  assert.equal(api.vars.FRONTEND_URL, "https://app-staging.cybermeters.com");
});
check("no production cron, queue, network, email, or metrics side effects", () => {
  for (const config of [api, mcp]) {
    for (const forbidden of ["triggers", "queues", "send_email", "email", "analytics_engine_datasets",
      "unsafe", "dispatch_namespaces", "browser", "vectorize", "ai"]) {
      assert.equal(config[forbidden], undefined, `${config.name}: ${forbidden}`);
    }
    assert.ok(!JSON.stringify(config).includes("cybermeters-scan-dispatch"));
    assert.ok(!JSON.stringify(config).includes("cybermeters-network-probe"));
    assert.ok(!JSON.stringify(config).includes("api.cybermeters.com\""));
  }
  assert.equal(api.services, undefined);
  assert.equal(api.vars.SCAN_DISPATCH_MODE, "queue");
  assert.equal(api.vars.SCHEDULED_DISPATCH_MODE, "queue");
  assert.equal(api.vars.EXPOSURE_SCAN_MODE, "disabled");
  assert.equal(api.vars.TLS_ASSESSMENT_MODE, "disabled");
  assert.equal(api.vars.RESEND_API_KEY, undefined);
});
const { isQueueDispatchMode, dispatchAdmittedScan } = await import(
  "../workers/scan-api/src/engines/scan-dispatch.js");
check("manual scans select Queue dispatch and have no Queue binding", () => {
  assert.equal(isQueueDispatchMode(api.vars), true);
  assert.equal(api.queues, undefined);
  assert.equal(api.services, undefined);
});
{
  const reports = [];
  const statements = [];
  const env = {
    ...api.vars,
    cybermeters_reports: { put: async (_key, body) => { reports.push(JSON.parse(body).status); } },
    cybermeters_db: { prepare: (sql) => ({ bind: (...args) => ({
      run: async () => { statements.push([sql, args]); return { success: true }; },
    }) }) },
  };
  const dispatchLogs = [];
  const originalLog = console.log;
  let result;
  try {
    console.log = (...args) => { dispatchLogs.push(args); };
    result = await dispatchAdmittedScan(env, {
      scanId: "synthetic_scan", domainId: "synthetic_domain",
      workspaceId: "synthetic_workspace", userId: "synthetic_user",
      domain: "fixture.invalid", reportKey: "synthetic/report.json",
    });
  } finally {
    console.log = originalLog;
  }
  check("missing Queue binding prevents scan execution and compensates synthetic row", () => {
    assert.equal(result.ok, false);
    assert.deepEqual(reports, ["queued", "failed"]);
    assert.ok(dispatchLogs.some(([label, body]) =>
      label === "[scan-dispatch]" && JSON.parse(body).outcome === "dispatch_failed"));
    assert.ok(statements.some(([sql]) =>
      /UPDATE scans SET status = 'failed'.*status = 'queued'/.test(sql)));
  });
}
check("separate staging edge budgets", () => {
  assert.deepEqual(mcp.ratelimits, [
    { name: "MCP_EDGE_CLIENT_RATE", namespace_id: fixture.staging_edge_client_rate_namespace_id,
      simple: { limit: 120, period: 60 } },
    { name: "MCP_EDGE_GLOBAL_RATE", namespace_id: fixture.staging_edge_global_rate_namespace_id,
      simple: { limit: 1000, period: 60 } },
  ]);
});
check("production D1 resource is refused", () => {
  assert.throws(() => buildMcpStagingConfigs({ ...fixture,
    staging_d1_database_id: productionD1Id }), /distinct staging D1/);
});
check("production edge namespace is refused", () => {
  assert.throws(() => buildMcpStagingConfigs({ ...fixture,
    staging_edge_client_rate_namespace_id: "320031" }), /distinct staging rate-limit/);
});
check("duplicate edge namespaces are refused", () => {
  assert.throws(() => buildMcpStagingConfigs({ ...fixture,
    staging_edge_global_rate_namespace_id: fixture.staging_edge_client_rate_namespace_id },
  { allowFixture: true }), /distinct staging rate-limit/);
});
check("missing, extra, malformed, or fixture resources are refused", () => {
  const { staging_oauth_kv_namespace_id: unused, ...missing } = fixture;
  assert.throws(() => buildMcpStagingConfigs(missing), /exactly/);
  assert.throws(() => buildMcpStagingConfigs({ ...fixture, secret: "x" }), /exactly/);
  assert.throws(() => buildMcpStagingConfigs({ ...fixture,
    staging_oauth_kv_namespace_id: "invalid" }), /KV namespace ID/);
  assert.throws(() => buildMcpStagingConfigs(fixture), /Fixture|fixture/);
});

for (const [worker, config] of [["scan-api", api], ["mcp-server", mcp]]) {
  const workerRoot = path.join(root, "workers", worker);
  const scratch = path.join(workerRoot, ".wrangler");
  fs.mkdirSync(scratch, { recursive: true });
  const directory = fs.mkdtempSync(path.join(scratch, "stage-check-"));
  try {
    const configPath = path.join(directory, "wrangler.jsonc");
    fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    const wrangler = path.join(workerRoot, "node_modules/wrangler/bin/wrangler.js");
    const run = spawnSync(process.execPath, [wrangler, "deploy", "--dry-run",
      "--config", configPath, "--outdir", path.join(directory, "bundle")], {
      cwd: workerRoot, encoding: "utf8", timeout: 120000,
      env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false",
        WRANGLER_LOG_PATH: path.join(directory, "wrangler.log") },
    });
    if (run.status !== 0) {
      throw new Error(`${worker} Wrangler dry-run failed:\n${(run.stderr || run.stdout ||
        run.error?.message || "unknown error").slice(-6000)}`);
    }
    check(`${worker} Wrangler dry-run with fake resources`, () => {
      assert.match(run.stdout + run.stderr, /Total Upload|--dry-run|dry.run/i);
    });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

console.log(`MCP staging config isolation: ${checks} passed, 0 failed`);
