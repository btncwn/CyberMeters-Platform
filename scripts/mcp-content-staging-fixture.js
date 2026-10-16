#!/usr/bin/env node
// Deterministic, D1-only synthetic content for the two existing MCP staging
// tenants. This script never contacts Cloudflare or modifies the base fixture.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MCP_STAGING_IDENTITIES } from "./generate-mcp-staging-fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const localDir = path.join(root, "local");
const output = path.join(localDir, "mcp-content-staging-fixture.sql");
const DAY = 86_400_000;

export const MCP_CONTENT_STAGING_ROWS = Object.freeze(MCP_STAGING_IDENTITIES.map((identity, index) =>
  Object.freeze({
    ...identity,
    domainId: `dom_mcp_stage_${index === 0 ? "a" : "b"}`,
    domain: `${index === 0 ? "alpha" : "bravo"}.mcp-stage.example.invalid`,
    scanId: `scan_mcp_stage_${index === 0 ? "a" : "b"}`,
    findingId: `finding_mcp_stage_${index === 0 ? "a" : "b"}`,
    findingSlug: index === 0 ? "email_missing_dmarc" : "spf_missing",
    findingTitle: index === 0 ? "Synthetic DMARC policy gap" : "Synthetic SPF record gap",
    caseId: `case_mcp_stage_${index === 0 ? "a" : "b"}`,
    certificateId: `cl_mcp_stage_${index === 0 ? "a" : "b"}`,
  })));

const literal = (value) => `'${String(value).replaceAll("'", "''")}'`;

/** The complete-scan marker deliberately has no canonical R2 report/snapshot.
 * Readers must show unavailable/insufficient evidence, never a score or policy
 * conclusion. A later separately verified R2 fixture can test positive proof. */
export function buildMcpContentStagingSql(now = new Date()) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("Invalid fixture time");
  const observed = new Date(now.getTime() - 60 * 60_000).toISOString();
  const expires = new Date(now.getTime() + 21 * DAY).toISOString();
  const lines = [
    "-- Synthetic MCP content fixture for dedicated cybermeters-db-staging ONLY.",
    "-- D1-only negative-evidence test: no R2 report or verified snapshot is supplied.",
    "-- Do not apply without the guarded two-tenant, paused-beta staging preflight.",
  ];
  for (const row of MCP_CONTENT_STAGING_ROWS) {
    const evidence = JSON.stringify({ synthetic: true, source: "fixture_only",
      note: "No real DNS, certificate, or customer observation was performed." });
    lines.push(
      `INSERT INTO domains (id,user_id,domain,verification_status,verified_at) VALUES (${literal(row.domainId)},${literal(row.userId)},${literal(row.domain)},'verified',${literal(observed)});`,
      `INSERT INTO workspace_domains (workspace_id,domain_id,verification_status,verified_at) VALUES (${literal(row.workspaceId)},${literal(row.domainId)},'verified',${literal(observed)});`,
      `INSERT INTO scans (id,domain_id,domain,status,scan_quality,score,rating,workspace_id,created_at) VALUES (${literal(row.scanId)},${literal(row.domainId)},${literal(row.domain)},'completed','complete',NULL,NULL,${literal(row.workspaceId)},${literal(observed)});`,
      `INSERT INTO findings (id,scan_id,finding_slug,severity,title,evidence_json,confidence,created_at) VALUES (${literal(row.findingId)},${literal(row.scanId)},${literal(row.findingSlug)},'critical',${literal(row.findingTitle)},${literal(evidence)},'synthetic',${literal(observed)});`,
      `INSERT INTO managed_cases (id,workspace_id,case_type,domain_key,domain,finding_id,source_finding_type,source_scan_id,severity,status,created_at,updated_at) VALUES (${literal(row.caseId)},${literal(row.workspaceId)},'email_case','email_protection',${literal(row.domain)},${literal(row.findingId)},${literal(row.findingSlug)},${literal(row.scanId)},'critical','detected',${literal(observed)},${literal(observed)});`,
      `INSERT INTO certificate_lifecycle (id,workspace_id,domain_id,primary_hostname,not_after,days_remaining,renewal_readiness,coverage_status,verification_status,first_seen_at,last_seen_at) VALUES (${literal(row.certificateId)},${literal(row.workspaceId)},${literal(row.domainId)},${literal(row.domain)},${literal(expires)},21,'preparation','unknown','not_verified',${literal(observed)},${literal(observed)});`,
    );
  }
  return `${lines.join("\n")}\n`;
}

export function writeMcpContentStagingSql(now = new Date()) {
  if (fs.realpathSync(localDir) !== localDir || fs.lstatSync(localDir).isSymbolicLink()) {
    throw new Error("Ignored local/ directory must not be a symlink");
  }
  const sql = buildMcpContentStagingSql(now);
  fs.writeFileSync(output, sql, { flag: "wx", mode: 0o600 });
  return output;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) {
    console.error("Usage: node scripts/mcp-content-staging-fixture.js");
    process.exitCode = 2;
  } else {
    try { console.log(`Generated local-only synthetic SQL: ${writeMcpContentStagingSql()}`); }
    catch (error) { console.error(`Fixture generation refused: ${error.message}`); process.exitCode = 1; }
  }
}
