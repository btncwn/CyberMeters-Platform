#!/usr/bin/env node
// Emergency founder-canary stop. Show --plan to the founder and run its exact
// --apply command only after explicit approval. No production state is read in
// plan mode. The release manifest pins both live and flag-off versions.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [mode, manifestArgument, approvedFlag, approvedDigest] = process.argv.slice(2);
if (!["--plan", "--apply"].includes(mode) || !manifestArgument ||
    (mode === "--apply" && (approvedFlag !== "--approved-plan-sha256" || !approvedDigest))) {
  process.stderr.write("Usage: node scripts/rollback-mcp-founder-canary.mjs --plan <manifest.json> | --apply <manifest.json> --approved-plan-sha256 <digest>\n");
  process.exit(2);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACCOUNT = /^[0-9a-f]{32}$/i;
const manifestPath = resolve(manifestArgument);
const manifestBytes = readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
assert.equal(manifest.kind, "mcp_founder_canary_release_v2");
for (const key of ["release_id", "production_d1_id", "scan_api_on_version",
  "scan_api_off_version", "gateway_on_version", "gateway_off_version",
  "pages_on_deployment_id", "pages_off_deployment_id"]) {
  assert.match(manifest[key], UUID, `invalid ${key}`);
}
assert.match(manifest.account_id, ACCOUNT);
assert.equal(manifest.pages_project, "cybermeters-dashboard");
assert.equal(manifest.pages_off_beta_flag, "false");
assert.match(manifest.pages_off_build_commit, /^[0-9a-f]{40}$/i);
assert.match(manifest.pages_off_build_time, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/);
for (const [on, off] of [["scan_api_on_version", "scan_api_off_version"],
  ["gateway_on_version", "gateway_off_version"],
  ["pages_on_deployment_id", "pages_off_deployment_id"]]) {
  assert.notEqual(manifest[on], manifest[off], `${on} must differ from ${off}`);
}
const apiConfig = join(root, "workers/scan-api/wrangler.toml");
const gatewayConfig = join(root, "workers/mcp-server/wrangler.toml");
const production = readFileSync(apiConfig, "utf8");
const digest = createHash("sha256")
  .update(manifestBytes)
  .update(readFileSync(fileURLToPath(import.meta.url)))
  .update(production)
  .update(readFileSync(gatewayConfig))
  .digest("hex");
if (mode === "--apply") assert.equal(approvedDigest, digest, "approved plan inputs changed");
assert.match(production, /database_name\s*=\s*"cybermeters-db"/);
assert.ok(production.includes(`database_id = "${manifest.production_d1_id}"`),
  "manifest D1 does not match the production Worker binding");
const wrangler = join(root, "workers/scan-api/node_modules/.bin/wrangler");

const pauseSql = "UPDATE mcp_beta_workspace_access SET status='paused', updated_at=CURRENT_TIMESTAMP WHERE status='enabled'";
const revokeSql = "UPDATE mcp_oauth_connections SET status='revoked', revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE status='active'";
const enabledSql = "SELECT COUNT(*) AS remaining FROM mcp_beta_workspace_access WHERE status='enabled'";
const activeSql = "SELECT COUNT(*) AS remaining FROM mcp_oauth_connections WHERE status='active'";
const auditId = `audit_mcp_founder_canary_rollback_v1:${manifest.release_id}`;
const auditSql = `INSERT INTO audit_events (id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at) VALUES ('${auditId}',NULL,NULL,'system','mcp_founder_canary_rollback','mcp_customer','${manifest.release_id}','Founder canary emergency rollback',NULL,CURRENT_TIMESTAMP) ON CONFLICT(id) DO NOTHING`;
const d1Args = (sql) => ["d1", "execute", "cybermeters-db", "--remote", "--yes",
  "--config", apiConfig, "--command", sql, "--json"];
const statusArgs = (name, config) => ["deployments", "status", "--name", name,
  "--config", config, "--json"];
const apiStatusArgs = statusArgs("cybermeters-platform", apiConfig);
const gatewayStatusArgs = statusArgs("cybermeters-mcp-server", gatewayConfig);
const apiArgs = ["versions", "deploy", `${manifest.scan_api_off_version}@100%`,
  "--name", "cybermeters-platform", "--config", apiConfig, "--yes"];
const gatewayArgs = ["versions", "deploy", `${manifest.gateway_off_version}@100%`,
  "--name", "cybermeters-mcp-server", "--config", gatewayConfig, "--yes"];
const pagesProjectUrl = `https://api.cloudflare.com/client/v4/accounts/${manifest.account_id}` +
  `/pages/projects/${manifest.pages_project}`;
const pagesRollbackUrl = `${pagesProjectUrl}/deployments/${manifest.pages_off_deployment_id}/rollback`;

const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
process.stdout.write(`Plan inputs SHA-256: ${digest}\n`);
for (const sql of [pauseSql, enabledSql, revokeSql, activeSql, auditSql]) {
  process.stdout.write(`${shellQuote(wrangler)} ${d1Args(sql).map(shellQuote).join(" ")}\n`);
}
for (const args of [apiStatusArgs, gatewayStatusArgs]) {
  process.stdout.write(`${shellQuote(wrangler)} ${args.map(shellQuote).join(" ")}\n`);
}
process.stdout.write(`${shellQuote(wrangler)} ${apiArgs.map(shellQuote).join(" ")}\n`);
process.stdout.write(`${shellQuote(wrangler)} ${gatewayArgs.map(shellQuote).join(" ")}\n`);
process.stdout.write(`GET ${pagesProjectUrl} (Bearer token from CLOUDFLARE_API_TOKEN)\n`);
process.stdout.write(`POST ${pagesRollbackUrl} (Bearer token from CLOUDFLARE_API_TOKEN)\n`);
process.stdout.write(`GET ${pagesProjectUrl} (verify canonical_deployment.id and production beta build flag)\n`);
for (const url of ["https://mcp.cybermeters.com/mcp",
  "https://api.cybermeters.com/.well-known/oauth-authorization-server",
  "https://api.cybermeters.com/health", "https://api.cybermeters.com/ready",
  "https://api.cybermeters.com/api/auth/me", "https://app.cybermeters.com/",
  "https://app.cybermeters.com/version.json"]) process.stdout.write(`GET ${url}\n`);
process.stdout.write(`Approved one-command rollback: node scripts/rollback-mcp-founder-canary.mjs --apply ${shellQuote(manifestPath)} --approved-plan-sha256 ${digest}\n`);
if (mode === "--plan") process.exit(0);

const failures = [];
function fail(label, error) {
  failures.push(label);
  process.stderr.write(`${label}: ${error?.message ?? String(error)}\n`);
}
function runWrangler(label, args) {
  const result = spawnSync(wrangler, args, { cwd: root, encoding: "utf8",
    timeout: 120000, maxBuffer: 2 * 1024 * 1024 });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.status !== 0) {
    fail(label, result.error ?? `exit ${result.status}`);
    return null;
  }
  return result.stdout;
}
function countRows(label, sql) {
  const output = runWrangler(label, d1Args(sql));
  if (output === null) return false;
  try {
    const payload = JSON.parse(output);
    const count = payload?.[0]?.results?.[0]?.remaining;
    if (payload.length !== 1 || payload[0].success !== true || Number(count) !== 0) {
      throw new Error(`remaining=${String(count)}`);
    }
    return true;
  } catch (error) {
    fail(label, error);
    return false;
  }
}
function d1Succeeded(label, sql) {
  const output = runWrangler(label, d1Args(sql));
  if (output === null) return false;
  try {
    const payload = JSON.parse(output);
    if (payload.length !== 1 || payload[0].success !== true) throw new Error("D1 did not confirm success");
    return true;
  } catch (error) { fail(label, error); return false; }
}
function currentVersion(label, args) {
  const output = runWrangler(label, args);
  if (output === null) return null;
  try {
    const versions = JSON.parse(output)?.versions;
    if (!Array.isArray(versions) || versions.length !== 1 || Number(versions[0].percentage) !== 100) {
      throw new Error("expected one production version at 100% traffic");
    }
    assert.match(versions[0].version_id, UUID);
    return versions[0].version_id;
  } catch (error) { fail(label, error); return null; }
}
function restoreWorker(label, statusArgs, expectedOn, expectedOff, deployArgs) {
  const current = currentVersion(`${label} current version`, statusArgs);
  if (current === expectedOff) return;
  if (current !== expectedOn) {
    fail(label, "current version differs from approved canary; stale rollback target refused");
    return;
  }
  if (runWrangler(`restore disabled ${label}`, deployArgs) !== null) {
    const restored = currentVersion(`${label} restored version`, statusArgs);
    if (restored !== expectedOff) fail(label, "disabled version is not receiving 100% traffic");
  }
}

// Fence data access first. If a later release changed, this containment still
// applies, while stale Worker/Page versions are never redeployed automatically.
const paused = d1Succeeded("pause beta access", pauseSql) &&
  countRows("verify paused beta access", enabledSql);
const revoked = d1Succeeded("revoke MCP grants", revokeSql) &&
  countRows("verify revoked grants", activeSql);
if (paused && revoked) d1Succeeded("record rollback audit receipt", auditSql);
restoreWorker("API", apiStatusArgs, manifest.scan_api_on_version,
  manifest.scan_api_off_version, apiArgs);
restoreWorker("gateway", gatewayStatusArgs, manifest.gateway_on_version,
  manifest.gateway_off_version, gatewayArgs);

const token = process.env.CLOUDFLARE_API_TOKEN;
async function pagesProject() {
  const response = await fetch(pagesProjectUrl, {
    headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(30000),
  });
  const body = await response.json();
  if (!response.ok || body?.success !== true || !body.result) {
    throw new Error(`Pages project read HTTP ${response.status}`);
  }
  return body.result;
}
function persistentBetaOff(project) {
  const vars = project?.deployment_configs?.production?.env_vars;
  if (!vars || typeof vars !== "object" || Array.isArray(vars)) return false;
  const flag = vars.VITE_MCP_BETA_ENABLED;
  return flag === undefined || (flag?.type === "plain_text" && flag.value === "false");
}
if (!token) fail("restore disabled frontend", "CLOUDFLARE_API_TOKEN is required");
else {
  try {
    let project = await pagesProject();
    const current = project?.canonical_deployment?.id;
    if (current !== manifest.pages_off_deployment_id &&
        current !== manifest.pages_on_deployment_id) {
      throw new Error("current Pages deployment differs from approved canary");
    }
    if (current === manifest.pages_on_deployment_id) {
      const response = await fetch(pagesRollbackUrl, {
        method: "POST", headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(30000),
      });
      const body = await response.json();
      if (!response.ok || body?.success !== true || body?.result?.id !== manifest.pages_off_deployment_id) {
        throw new Error(`Pages rollback HTTP ${response.status}`);
      }
    }
    let active = false;
    for (let attempt = 0; attempt < 5; attempt++) {
      project = await pagesProject();
      if (project?.canonical_deployment?.id === manifest.pages_off_deployment_id) {
        active = true;
        break;
      }
      await new Promise((done) => setTimeout(done, 1000));
    }
    if (!active) throw new Error("flag-off deployment is not canonical production");
    if (!persistentBetaOff(project)) throw new Error("persistent production beta build flag is not false");
    process.stdout.write("Disabled frontend deployment is canonical; persistent beta build flag is off.\n");
  } catch (error) { fail("restore disabled frontend", error); }
}

async function probe(label, url, expectedStatus, check) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (response.status !== expectedStatus) throw new Error(`HTTP ${response.status}`);
    const body = await response.text();
    if (!check(body, response)) throw new Error("unexpected response body");
    process.stdout.write(`${label}: HTTP ${expectedStatus}\n`);
  } catch (error) { fail(label, error); }
}
await probe("gateway closed", "https://mcp.cybermeters.com/mcp", 503,
  (body) => body.includes("mcp_not_configured"));
await probe("OAuth closed", "https://api.cybermeters.com/.well-known/oauth-authorization-server", 503,
  (body) => body.includes("MCP OAuth is not configured"));
await probe("API health", "https://api.cybermeters.com/health", 200,
  (body) => JSON.parse(body)?.status === "ok");
await probe("API readiness", "https://api.cybermeters.com/ready", 200,
  (body) => { const ready = JSON.parse(body); return ready?.status === "ready" &&
    ready?.checks?.d1 === true && ready?.checks?.r2 === true; });
await probe("anonymous API access", "https://api.cybermeters.com/api/auth/me", 401,
  (body) => JSON.parse(body)?.error === "Unauthorized");
await probe("frontend health", "https://app.cybermeters.com/", 200,
  (body, response) => response.headers.get("content-type")?.includes("text/html") && body.length > 0);
await probe("frontend disabled build", "https://app.cybermeters.com/version.json", 200,
  (body) => { const build = JSON.parse(body); return build?.commit === manifest.pages_off_build_commit &&
    build?.built_at === manifest.pages_off_build_time && build?.mcp_beta_enabled === false; });
if (failures.length) {
  process.stderr.write(`Incomplete rollback: ${[...new Set(failures)].join(", ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("Founder canary rollback completed.\n");
}
