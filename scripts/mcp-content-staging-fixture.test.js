import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { buildMcpStagingFixtureSql } from "./generate-mcp-staging-fixture.js";
import { buildMcpContentStagingSql, MCP_CONTENT_STAGING_ROWS } from "./mcp-content-staging-fixture.js";
import { projectMcpDomains, projectMcpFindings, projectMcpPortfolioFindings } from
  "../workers/scan-api/src/routes/mcp-customer-discovery.js";
import { projectMcpFindingExplanation, projectMcpTlsPosture,
  projectMcpEmailPosture, projectMcpReportSummary } from
  "../workers/scan-api/src/routes/mcp-customer-status.js";
import { projectMcpManagedCases, projectMcpSummary } from
  "../workers/scan-api/src/routes/mcp-projections.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schema = fs.readFileSync(path.join(root, "local/mcp-staging-schema.sql"), "utf8");
const timestamp = new Date("2026-10-15T12:00:00.000Z");
const hashes = ["a", "b"].map((ch) => `pbkdf2:sha256:100000:${ch.repeat(32)}:${ch.repeat(64)}`);
const contentSql = buildMcpContentStagingSql(timestamp);

function fixture() {
  const sql = new DatabaseSync(":memory:");
  sql.exec(schema);
  sql.exec("PRAGMA foreign_keys=ON");
  sql.exec(buildMcpStagingFixtureSql(hashes));
  sql.exec(contentSql);
  let writes = 0;
  let reportReads = 0;
  const env = {
    cybermeters_db: { prepare(query) {
      const prepared = sql.prepare(query);
      return { bind(...params) { return {
        async first() { return prepared.get(...params) ?? null; },
        async all() { return { results: prepared.all(...params) }; },
        async run() { writes += 1; throw new Error("MCP projection unexpectedly wrote D1"); },
      }; } };
    } },
    cybermeters_reports: { async get() { reportReads += 1; return null; } },
  };
  return { sql, env, close: () => sql.close(),
    get writes() { return writes; }, get reportReads() { return reportReads; } };
}

test("content SQL is deterministic, synthetic and valid against converged staging schema", () => {
  assert.equal(contentSql, buildMcpContentStagingSql(timestamp));
  assert.equal((contentSql.match(/INSERT INTO /g) ?? []).length, 12);
  assert.match(contentSql, /cybermeters-db-staging ONLY/);
  assert.doesNotMatch(contentSql, /@gmail|@hotmail|@outlook|cm_[a-f0-9]{64}/i);
  assert.ok(MCP_CONTENT_STAGING_ROWS.every((row) => row.domain.endsWith(".example.invalid")));
  const f = fixture();
  try {
    assert.deepEqual(f.sql.prepare("PRAGMA foreign_key_check").all(), []);
    assert.equal(f.sql.prepare("PRAGMA quick_check").get().quick_check, "ok");
    for (const name of ["domains", "workspace_domains", "scans", "findings",
      "managed_cases", "certificate_lifecycle"]) {
      assert.equal(f.sql.prepare(`SELECT COUNT(*) AS n FROM ${name}`).get().n, 2);
    }
    assert.equal(f.sql.prepare("SELECT COUNT(*) AS n FROM scan_report_snapshots").get().n, 0);
    assert.equal(f.sql.prepare("SELECT COUNT(*) AS n FROM certificate_observations").get().n, 0);
    assert.deepEqual(f.sql.prepare("SELECT DISTINCT status FROM mcp_beta_workspace_access").all()
      .map((row) => row.status), ["paused"]);
    assert.throws(() => f.sql.exec(contentSql), /constraint failed/i);
  } finally { f.close(); }
});

test("paused beta blocks customer projections even when synthetic content exists", async () => {
  const f = fixture();
  try {
    const row = MCP_CONTENT_STAGING_ROWS[0];
    await assert.rejects(projectMcpDomains(f.env,
      { workspaceId: row.workspaceId, userId: row.userId }, null,
      { workspaceId: row.workspaceId }), /mcp_projection_unavailable/);
    assert.equal(f.writes, 0);
  } finally { f.close(); }
});

test("two tenant reads expose bounded content while suppressing unproven conclusions", async () => {
  const f = fixture();
  try {
    f.sql.exec("UPDATE mcp_beta_workspace_access SET status='enabled'");
    for (const [index, row] of MCP_CONTENT_STAGING_ROWS.entries()) {
      const foreign = MCP_CONTENT_STAGING_ROWS[1 - index];
      const grant = { workspaceId: row.workspaceId, userId: row.userId, role: "owner" };
      const input = { workspaceId: row.workspaceId };
      const domains = await projectMcpDomains(f.env, grant, null, input);
      const findings = await projectMcpFindings(f.env, grant, null, input);
      const certificate = await projectMcpTlsPosture(f.env, grant, null, input);
      const email = await projectMcpEmailPosture(f.env, grant, null, input);
      const report = await projectMcpReportSummary(f.env, grant, null, input);
      const cases = await projectMcpManagedCases(f.env, grant);
      const summary = await projectMcpSummary(f.env, grant,
        { workspace: { name: row.workspaceName } });
      const explanation = await projectMcpFindingExplanation(f.env, grant, null,
        { ...input, findingId: row.findingId });
      assert.equal(domains.domains[0].domain, row.domain);
      assert.equal(domains.domains[0].source_report_state, "unavailable");
      assert.equal(findings.findings[0].finding_id, row.findingId);
      assert.equal(findings.findings[0].severity, "critical");
      assert.equal(findings.findings[0].evidence_state, "insufficient");
      assert.equal(findings.findings[0].assessment, null);
      assert.equal(certificate.certificates[0].certificate_lifecycle_id, row.certificateId);
      assert.equal(certificate.certificates[0].assurance_status, "not_recorded");
      assert.ok(Object.values(certificate.certificates[0].signals)
        .every((signal) => signal.check_outcome === "not_checked"));
      assert.equal(email.status, "snapshot_unavailable");
      assert.equal(email.domains[0].dmarc, null);
      assert.equal(email.domains[0].spf, null);
      assert.equal(email.domains[0].dkim, null);
      assert.equal(report.status, "snapshot_unavailable");
      assert.equal(report.score, null);
      assert.equal(cases.cases[0].canonical_phase, "detected");
      assert.equal(summary.score_value, null);
      assert.equal(explanation.status, "snapshot_unavailable");
      assert.equal(explanation.remediation, null);
      const serialized = JSON.stringify({ domains, findings, certificate, email,
        report, cases, summary, explanation });
      for (const foreignValue of [foreign.workspaceId, foreign.domain,
        foreign.findingId, foreign.caseId, foreign.certificateId]) {
        assert.equal(serialized.includes(foreignValue), false);
      }
      assert.equal(serialized.includes("fixture_only"), false);
      assert.equal(serialized.includes("evidence_json"), false);
      await assert.rejects(projectMcpFindings(f.env, grant, null,
        { workspaceId: foreign.workspaceId }), /mcp_projection_unavailable/);
      await assert.rejects(projectMcpFindingExplanation(f.env, grant, null,
        { ...input, findingId: foreign.findingId }), /mcp_projection_unavailable/);
      await assert.rejects(projectMcpPortfolioFindings(f.env,
        { userId: row.userId, portfolioRead: true,
          portfolioWorkspaceIds: [row.workspaceId, foreign.workspaceId] }, null, {}),
      /mcp_projection_unavailable/);
    }
    assert.equal(f.writes, 0);
    assert.ok(f.reportReads > 0);
    assert.deepEqual(f.sql.prepare("PRAGMA foreign_key_check").all(), []);
  } finally { f.close(); }
});
