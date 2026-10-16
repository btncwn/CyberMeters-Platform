// Guarded content import for the already seeded, dedicated MCP staging D1.
// The CLI requires an explicitly reviewed SHA-256 argument. Running this file
// without that opt-in never contacts Cloudflare.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { buildMcpStagingConfigs } from "./generate-mcp-staging-config.js";
import { buildMcpStagingFixtureSql, MCP_STAGING_IDENTITIES } from
  "./generate-mcp-staging-fixture.js";
import { buildMcpContentStagingSql, MCP_CONTENT_STAGING_ROWS } from
  "./mcp-content-staging-fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const database = "cybermeters-db-staging";
const defaults = Object.freeze({
  manifest: path.join(root, "local/mcp-staging-resources.json"),
  config: path.join(root, "workers/scan-api/.wrangler/mcp-staging/wrangler.jsonc"),
  baseSql: path.join(root, "local/mcp-staging-fixture.sql"),
  sql: path.join(root, "local/mcp-content-staging-fixture.sql"),
});
const contentTables = Object.freeze(["domains", "workspace_domains", "scans", "findings",
  "managed_cases", "managed_case_events", "certificate_lifecycle",
  "certificate_lifecycle_events", "certificate_observations", "scan_report_snapshots"]);

function privateFile(file, label) {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular file`);
  assert.equal(stat.mode & 0o077, 0, `${label} must be owner-only (0600)`);
  assert.equal(fs.realpathSync(file), path.resolve(file), `${label} has a symlink path`);
  assert.equal(fs.realpathSync(path.dirname(file)), path.dirname(file),
    `${label} has a symlink directory`);
  return fs.readFileSync(file, "utf8");
}

function json(text, label) {
  try { return JSON.parse(text); }
  catch { throw new Error(`${label} returned invalid JSON; import refused`); }
}

function rows(output, label) {
  const parsed = json(output, label);
  if (!Array.isArray(parsed) || parsed.length !== 1 || parsed[0]?.success !== true ||
      !Array.isArray(parsed[0].results)) throw new Error(`${label} failed; import refused`);
  return parsed[0].results;
}

function expectedIdentities(passwordHashes) {
  return {
    users: MCP_STAGING_IDENTITIES.map((row, index) => ({ id: row.userId,
      email: row.email, name: `Staging test ${index + 1}`, plan: "free",
      password_hash: passwordHashes[index], status: "active", email_verified: 1,
      auth_provider: "local" }))
      .sort((a, b) => a.id.localeCompare(b.id)),
    workspaces: MCP_STAGING_IDENTITIES.map((row) => ({ id: row.workspaceId,
      name: row.workspaceName, owner_user_id: row.userId, deleted_at: null }))
      .sort((a, b) => a.id.localeCompare(b.id)),
    members: MCP_STAGING_IDENTITIES.map((row) => ({ id: row.memberId,
      workspace_id: row.workspaceId, user_id: row.userId, role: "owner" }))
      .sort((a, b) => a.id.localeCompare(b.id)),
    beta: MCP_STAGING_IDENTITIES.map((row) => ({ workspace_id: row.workspaceId,
      status: "paused", enrolled_by: row.userId }))
      .sort((a, b) => a.workspace_id.localeCompare(b.workspace_id)),
  };
}

function exactContentSql(sql, now) {
  const match = sql.match(/INSERT INTO domains \(id,user_id,domain,verification_status,verified_at\) VALUES \('dom_mcp_stage_a','usr_mcp_stage_a','alpha\.mcp-stage\.example\.invalid','verified','([^']+)'\);/);
  if (!match) throw new Error("Content SQL is not the reviewed generator shape");
  const observedAt = Date.parse(match[1]);
  if (!Number.isFinite(observedAt) || new Date(observedAt).toISOString() !== match[1]) {
    throw new Error("Content SQL has an invalid observed timestamp");
  }
  const generatedAt = observedAt + 60 * 60_000;
  if (Math.abs(now.getTime() - generatedAt) > 24 * 60 * 60_000) {
    throw new Error("Content fixture is older than 24 hours; regenerate before import");
  }
  if (buildMcpContentStagingSql(new Date(generatedAt)) !== sql) {
    throw new Error("Content SQL differs from the reviewed generator");
  }
  return { observedAt: match[1], expiresAt: new Date(generatedAt + 21 * 86_400_000).toISOString() };
}

async function assertStagingState(query, { contentPresent, passwordHashes }) {
  const expected = expectedIdentities(passwordHashes);
  for (const [label, sql, wanted] of [
    ["users", "SELECT id,email,name,plan,password_hash,status,email_verified,auth_provider FROM users ORDER BY id;", expected.users],
    ["workspaces", "SELECT id,name,owner_user_id,deleted_at FROM workspaces ORDER BY id;", expected.workspaces],
    ["members", "SELECT id,workspace_id,user_id,role FROM workspace_members ORDER BY id;", expected.members],
    ["beta", "SELECT workspace_id,status,enrolled_by FROM mcp_beta_workspace_access ORDER BY workspace_id;", expected.beta],
  ]) {
    if (!isDeepStrictEqual(await query(sql, `remote ${label}`), wanted)) {
      throw new Error(`Remote ${label} differs from two paused synthetic tenants`);
    }
  }
  const counts = await query(contentTables.map((table) =>
    `SELECT '${table}' AS table_name, COUNT(*) AS row_count FROM ${table}`).join(" UNION ALL ") + ";",
  "remote content counts");
  const wanted = Object.fromEntries(contentTables.map((table) => [table,
    contentPresent && ["domains", "workspace_domains", "scans", "findings",
      "managed_cases", "certificate_lifecycle"].includes(table) ? 2 : 0]));
  if (counts.length !== contentTables.length ||
      counts.some((row) => !Object.hasOwn(wanted, row.table_name) ||
        row.row_count !== wanted[row.table_name])) {
    throw new Error(contentPresent ? "Content import readback differs from exact fixture" :
      "Staging content tables are not empty");
  }
  for (const [label, sql] of [
    ["active OAuth connections", "SELECT COUNT(*) AS n FROM mcp_oauth_connections WHERE status='active';"],
    ["user sessions", "SELECT COUNT(*) AS n FROM user_sessions;"],
  ]) {
    const result = await query(sql, `remote ${label}`);
    if (result.length !== 1 || result[0]?.n !== 0) {
      throw new Error(`Staging ${label} must be zero`);
    }
  }
  if ((await query("PRAGMA quick_check;", "remote integrity"))[0]?.quick_check !== "ok" ||
      (await query("PRAGMA foreign_key_check;", "remote foreign keys")).length !== 0) {
    throw new Error("Staging D1 integrity check failed");
  }
}

async function assertContentRows(query, observedAt, expiresAt) {
  const expected = [...MCP_CONTENT_STAGING_ROWS].sort((a, b) => a.domainId.localeCompare(b.domainId));
  const findingEvidence = JSON.stringify({ synthetic: true, source: "fixture_only",
    note: "No real DNS, certificate, or customer observation was performed." });
  for (const [label, sql, wanted] of [
    ["domains", "SELECT id,user_id,domain,verification_status,verified_at FROM domains ORDER BY id;",
      expected.map((r) => ({ id: r.domainId, user_id: r.userId, domain: r.domain,
        verification_status: "verified", verified_at: observedAt }))],
    ["workspace domains", "SELECT workspace_id,domain_id,verification_status,verified_at FROM workspace_domains ORDER BY domain_id;",
      expected.map((r) => ({ workspace_id: r.workspaceId, domain_id: r.domainId,
        verification_status: "verified", verified_at: observedAt }))],
    ["scans", "SELECT id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at FROM scans ORDER BY domain_id;",
      expected.map((r) => ({ id: r.scanId, workspace_id: r.workspaceId, domain_id: r.domainId,
        domain: r.domain, status: "completed", scan_quality: "complete", score: null,
        rating: null, created_at: observedAt }))],
    ["findings", "SELECT id,scan_id,finding_slug,severity,title,evidence_json,confidence,created_at FROM findings ORDER BY scan_id;",
      expected.map((r) => ({ id: r.findingId, scan_id: r.scanId,
        finding_slug: r.findingSlug, severity: "critical", title: r.findingTitle,
        evidence_json: findingEvidence, confidence: "synthetic", created_at: observedAt }))],
    ["cases", "SELECT id,workspace_id,domain,finding_id,case_type,domain_key,source_finding_type,source_scan_id,status,severity FROM managed_cases ORDER BY id;",
      expected.map((r) => ({ id: r.caseId, workspace_id: r.workspaceId, domain: r.domain,
        finding_id: r.findingId, case_type: "email_case", domain_key: "email_protection",
        source_finding_type: r.findingSlug, source_scan_id: r.scanId,
        status: "detected", severity: "critical" }))],
    ["certificates", "SELECT id,workspace_id,domain_id,primary_hostname,not_after,days_remaining,renewal_readiness,coverage_status,verification_status,current_certificate_observation_id,first_seen_at,last_seen_at FROM certificate_lifecycle ORDER BY domain_id;",
      expected.map((r) => ({ id: r.certificateId, workspace_id: r.workspaceId,
        domain_id: r.domainId, primary_hostname: r.domain, not_after: expiresAt,
        days_remaining: 21, renewal_readiness: "preparation", coverage_status: "unknown",
        verification_status: "not_verified", current_certificate_observation_id: null,
        first_seen_at: observedAt, last_seen_at: observedAt }))],
  ]) {
    if (!isDeepStrictEqual(await query(sql, `remote ${label} readback`), wanted)) {
      throw new Error(`${label} readback differs from synthetic fixture`);
    }
  }
}

/** Uses Wrangler --file, which the pinned Wrangler sends to D1's atomic import
 * endpoint. On any statement failure D1 restores its original bookmark. */
export async function guardedMcpContentStagingImport({ runWrangler, expectedSha256,
  paths = defaults, now = new Date() } = {}) {
  if (typeof runWrangler !== "function") throw new Error("Wrangler runner is required");
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("Invalid current time");
  if (typeof expectedSha256 !== "string" || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new Error("Explicit reviewed SHA-256 hash is required");
  }
  const resources = json(privateFile(paths.manifest, "staging manifest"), "staging manifest");
  const config = json(privateFile(paths.config, "disabled staging API config"), "staging API config");
  if (!isDeepStrictEqual(config, buildMcpStagingConfigs(resources).api) ||
      config.vars.MAINTENANCE_MODE !== "on" ||
      config.vars.MCP_CUSTOMER_READ_ENABLED !== "false" ||
      config.vars.MCP_CUSTOMER_OAUTH_ENABLED !== "false") {
    throw new Error("Staging config must be exactly the disabled generated config");
  }
  const binding = config.d1_databases[0];
  if (binding.database_name !== database || binding.database_id !== resources.staging_d1_database_id) {
    throw new Error("Staging D1 binding mismatch");
  }
  const baseSql = privateFile(paths.baseSql, "base synthetic fixture SQL");
  const passwordHashes = [...baseSql.matchAll(/pbkdf2:sha256:100000:[a-f0-9]{32}:[a-f0-9]{64}/g)]
    .map((match) => match[0]);
  if (passwordHashes.length !== 2 ||
      buildMcpStagingFixtureSql(passwordHashes) !== baseSql) {
    throw new Error("Base synthetic fixture SQL differs from its generator");
  }
  const fixture = privateFile(paths.sql, "synthetic content SQL");
  const actualHash = crypto.createHash("sha256").update(fixture).digest("hex");
  if (actualHash !== expectedSha256) throw new Error("Content SQL SHA-256 differs from reviewed hash");
  const { observedAt, expiresAt } = exactContentSql(fixture, now);

  const call = (args) => runWrangler(args);
  const info = json(await call(["d1", "info", database, "--config", paths.config, "--json"]), "remote D1 info");
  if (info?.name !== database || info?.uuid !== binding.database_id) {
    throw new Error("Remote D1 is not the dedicated staging database");
  }
  const inventory = json(await call(["d1", "list", "--config", paths.config, "--json"]), "remote D1 list");
  if (!Array.isArray(inventory) || inventory.filter((row) => row.name === database).length !== 1 ||
      inventory.filter((row) => row.uuid === binding.database_id).length !== 1 ||
      inventory.find((row) => row.name === database)?.uuid !== binding.database_id) {
    throw new Error("Remote D1 inventory does not uniquely identify staging");
  }
  const query = async (sql, label) => rows(await call(["d1", "execute", database,
    "--remote", "--config", paths.config, "--command", sql, "--json"]), label);
  await assertStagingState(query, { contentPresent: false, passwordHashes });
  // Repeat the complete guard just before the only mutation.
  await assertStagingState(query, { contentPresent: false, passwordHashes });
  const result = json(await call(["d1", "execute", database, "--remote", "--config",
    paths.config, "--file", paths.sql, "--yes", "--json"]), "atomic D1 import");
  if (!Array.isArray(result) || result.length !== 1 || result[0]?.success !== true ||
      result[0]?.results?.[0]?.["Total queries executed"] !== 12) {
    throw new Error("Atomic D1 import was not confirmed; inspect staging before retrying");
  }
  await assertStagingState(query, { contentPresent: true, passwordHashes });
  await assertContentRows(query, observedAt, expiresAt);
  return { database, contentRows: 12, betaStatus: "paused", sha256: actualHash };
}

function cliWrangler(args) {
  const binary = path.join(root, "workers/scan-api/node_modules/.bin/wrangler");
  return execFileSync(binary, args, { cwd: root, encoding: "utf8", timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" } });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== "--apply-reviewed-sha256") {
    console.error("Usage: node scripts/import-mcp-content-staging-fixture.js --apply-reviewed-sha256 <64-hex-sha256>");
    process.exitCode = 2;
  } else {
    guardedMcpContentStagingImport({ runWrangler: cliWrangler,
      expectedSha256: process.argv[3] })
      .then((result) => console.log(
        `Imported ${result.contentRows} synthetic content rows into ${result.database}; beta remains ${result.betaStatus}.`,
      ))
      .catch((error) => {
        console.error(`Synthetic staging content import refused: ${error.message}`);
        process.exitCode = 1;
      });
  }
}
