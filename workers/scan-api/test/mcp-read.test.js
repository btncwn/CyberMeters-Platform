import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { hashToken } from "../src/lib/auth-crypto.js";
import {
  getScanStatusForMcp, getWorkspacePostureForMcp,
  getWorkspaceSummaryForMcp, listManagedCasesForMcp,
  listRecentScansForMcp, listWorkspacesForMcp,
} from "../src/routes/mcp-service.js";
import {
  projectMcpLimitations, projectMcpRecentScans, projectMcpManagedCases,
  projectMcpScanStatus, projectMcpManagedCase, projectMcpPortfolioSummary,
  projectMcpPosture,
} from "../src/routes/mcp-projections.js";
import { projectUnvalidatedBrandSnapshotForCustomer } from "../src/engines/brand-candidate-presentation.js";
import { resolveCyberMotDomainStates } from "../src/engines/cyber-mot-domains.js";
import { CE_QUESTIONS } from "../src/lib/cyber-essentials.js";

const TOKEN_A = `cm_${"a".repeat(64)}`;
const TOKEN_B = `cm_${"b".repeat(64)}`;
const EXPIRES = "2099-01-01T00:00:00.000Z";

function fixture() {
  const sql = new DatabaseSync(":memory:");
  sql.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT NOT NULL);
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL,
      owner_user_id TEXT NOT NULL, deleted_at TEXT);
    CREATE TABLE workspace_members (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL);
    CREATE TABLE api_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL, workspace_id TEXT, scope TEXT NOT NULL,
      expires_at TEXT, status TEXT NOT NULL);
    CREATE TABLE api_rate_limits (id TEXT PRIMARY KEY, scope TEXT NOT NULL,
      scope_id TEXT NOT NULL, action TEXT NOT NULL, window_start TEXT NOT NULL,
      window_seconds INTEGER NOT NULL, request_count INTEGER NOT NULL,
      created_at TEXT, updated_at TEXT);
    CREATE TABLE audit_events (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
      actor_type TEXT, event_type TEXT NOT NULL, entity_type TEXT, entity_id TEXT,
      description TEXT, metadata_json TEXT, created_at TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL);
    CREATE TABLE scans (id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT,
      status TEXT, score INTEGER, rating TEXT, scan_quality TEXT, created_at TEXT);
    CREATE TABLE managed_cases (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
      case_type TEXT, domain_key TEXT, status TEXT, severity TEXT,
      remediation_id TEXT, created_at TEXT, updated_at TEXT, verified_at TEXT);
    CREATE TABLE scan_report_snapshots (id TEXT PRIMARY KEY, workspace_id TEXT,
      domain_id TEXT, scan_id TEXT, status TEXT, r2_key TEXT,
      checksum_sha256 TEXT, snapshot_schema_version TEXT, assessed_at TEXT,
      created_at TEXT, branding_json TEXT, related_changes_json TEXT);
    CREATE TABLE cyber_essentials_answers (workspace_id TEXT, control_key TEXT,
      question_key TEXT, answer TEXT);
  `);
  const d1 = { prepare(statement) {
    return { bind(...values) {
      const query = sql.prepare(statement);
      return {
        async first() { return query.get(...values) ?? null; },
        async all() { return { results: query.all(...values) }; },
        async run() { return { meta: { changes: query.run(...values).changes } }; },
      };
    } };
  } };
  const env = {
    MCP_INTERNAL_ENABLED: "true", MCP_TRIAL_WORKSPACE_ID: "ws_a",
    MCP_TRIAL_TOKEN_ID: "tok_a", cybermeters_db: d1,
    cybermeters_reports: { async get() { return null; } },
  };
  const seed = async () => {
    for (const [workspace, user, token, bearer] of [
      ["ws_a", "usr_a", "tok_a", TOKEN_A],
      ["ws_b", "usr_b", "tok_b", TOKEN_B],
    ]) {
      sql.prepare("INSERT INTO users VALUES (?, 'active')").run(user);
      sql.prepare("INSERT INTO workspaces VALUES (?, ?, ?, NULL)").run(workspace, `Name ${workspace}`, "other");
      sql.prepare("INSERT INTO workspace_members VALUES (?, ?, 'viewer')").run(workspace, user);
      sql.prepare("INSERT INTO api_tokens VALUES (?, ?, ?, ?, 'read', ?, 'active')")
        .run(token, user, await hashToken(bearer), workspace, EXPIRES);
    }
    sql.prepare("INSERT INTO workspace_domains VALUES ('ws_a','domain_a')").run();
    sql.prepare("INSERT INTO scans VALUES ('scan_a','ws_a','a.example','queued',98,'low',NULL,'2026-10-15T12:00:00.000Z')").run();
    sql.prepare("INSERT INTO scans VALUES ('scan_b','ws_b','b.example','queued',99,'low',NULL,'2026-10-15T12:00:00.000Z')").run();
    sql.prepare("INSERT INTO managed_cases VALUES ('case_a','ws_a','email_case','email_protection','open','critical',NULL,'2026-10-15T12:00:00.000Z','2026-10-15T12:00:00.000Z',NULL)").run();
    sql.prepare("INSERT INTO managed_cases VALUES ('case_b','ws_b','email_case','email_protection','open','critical',NULL,'2026-10-15T12:00:00.000Z','2026-10-15T12:00:00.000Z',NULL)").run();
  };
  return { sql, env, seed, close: () => sql.close() };
}

const input = (bearer = TOKEN_A, workspaceId = "ws_a") => ({ bearer, workspaceId });
const denied = (promise) => assert.rejects(promise, (error) =>
  error.message === "mcp_summary_unavailable" && !JSON.stringify(error).includes(TOKEN_A));

test("six internal reads expose only bounded, tenant-owned projections", async () => {
  const f = fixture();
  try {
    await f.seed();
    const { env, sql } = f;
    const workspaces = await listWorkspacesForMcp(env, { bearer: TOKEN_A });
    assert.deepEqual(workspaces, {
      workspaces: [{ workspace_id: "ws_a", display_name: "Name ws_a", role: "viewer" }], count: 1,
    });
    const summary = await getWorkspaceSummaryForMcp(env, input());
    assert.equal(summary.domain_count, 1);
    assert.equal(summary.open_case_count, 1);
    assert.equal(summary.score_value, null);
    assert.equal(summary.score_state, "not_assessed");
    const posture = await getWorkspacePostureForMcp(env, input());
    assert.equal(posture.domains.length, 8);
    assert.equal(posture.source_scan_id, null);
    const scans = await listRecentScansForMcp(env, input());
    assert.equal(scans.scans.length, 1);
    assert.equal(scans.scans[0].scan_id, "scan_a");
    assert.equal(scans.scans[0].score_available, false);
    assert.equal(scans.scans[0].scan_quality, null);
    assert.equal(scans.scans[0].assessment.quality, "unknown");
    assert.equal(scans.has_more, false);
    const status = await getScanStatusForMcp(env, { ...input(), scanId: "scan_a" });
    assert.equal(status.scan_id, "scan_a");
    assert.equal(status.score_available, false);
    const cases = await listManagedCasesForMcp(env, input());
    assert.equal(cases.cases.length, 1);
    assert.equal(cases.cases[0].case_id, "case_a");
    assert.equal(cases.cases[0].domain_key, "email_protection");
    assert.equal(cases.has_more, false);
    const json = JSON.stringify({ workspaces, summary, posture, scans, status, cases });
    assert.equal(json.includes(TOKEN_A) || json.includes("ws_b") || json.includes("case_b"), false);
    assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE workspace_id='ws_a'").get().n, 6);
    assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM scans").get().n, 2);
    assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM managed_cases").get().n, 2);
  } finally { f.close(); }
});

test("bounded lists disclose additional results, and canonical caveats are never truncated", async () => {
  const f = fixture();
  try {
    await f.seed();
    for (let i = 0; i < 11; i += 1) {
      f.sql.prepare("INSERT INTO scans VALUES (?, 'ws_a', 'a.example', 'queued', NULL, NULL, NULL, ?)")
        .run(`scan_extra_${i}`, `2026-10-15T13:${String(i).padStart(2, "0")}:00.000Z`);
      f.sql.prepare("INSERT INTO managed_cases VALUES (?, 'ws_a', 'email_case', 'email_protection', 'open', 'critical', NULL, ?, ?, NULL)")
        .run(`case_extra_${i}`, `2026-10-15T13:${String(i).padStart(2, "0")}:00.000Z`,
          `2026-10-15T13:${String(i).padStart(2, "0")}:00.000Z`);
    }
    const scans = await listRecentScansForMcp(f.env, input());
    const cases = await listManagedCasesForMcp(f.env, input());
    assert.equal(scans.scans.length, 10);
    assert.equal(cases.cases.length, 10);
    assert.equal(scans.has_more, true);
    assert.equal(cases.has_more, true);
    const scanPage = await projectMcpRecentScans(f.env, { workspaceId: "ws_a" }, null, {});
    const casePage = await projectMcpManagedCases(f.env, { workspaceId: "ws_a" }, null, {});
    assert.equal(scanPage.next_cursor.startsWith("s1~ws_a~"), true);
    assert.equal(casePage.next_cursor.startsWith("c1~ws_a~"), true);
    const scanNext = await projectMcpRecentScans(f.env, { workspaceId: "ws_a" }, null,
      { cursor: scanPage.next_cursor });
    const caseNext = await projectMcpManagedCases(f.env, { workspaceId: "ws_a" }, null,
      { cursor: casePage.next_cursor });
    assert.equal(scanNext.scans.length, 2);
    assert.equal(caseNext.cases.length, 2);
    assert.equal(scanNext.has_more, false);
    assert.equal(caseNext.has_more, false);
    assert.equal(scanNext.next_cursor, null);
    assert.equal(caseNext.next_cursor, null);
    await assert.rejects(projectMcpRecentScans(f.env, { workspaceId: "ws_b" }, null,
      { cursor: scanPage.next_cursor }), /invalid_projection/);
    await assert.rejects(projectMcpManagedCases(f.env, { workspaceId: "ws_b" }, null,
      { cursor: casePage.next_cursor }), /invalid_projection/);
    const caveats = ["First complete caveat.", "Second complete caveat."];
    assert.deepEqual(projectMcpLimitations(caveats), caveats);
    assert.throws(() => projectMcpLimitations(Array(5).fill("Caveat")), /invalid_projection/);
    assert.throws(() => projectMcpLimitations(["x".repeat(501)]), /invalid_projection/);
  } finally { f.close(); }
});

test("portfolio summary stays within selected workspaces and exposes bounded pages", async () => {
  const f = fixture();
  try {
    await f.seed();
    const selected = ["ws_a"];
    const portfolio = [{ id: "ws_a", name: "Name ws_a", role: "viewer" }];
    for (let index = 0; index < 5; index += 1) {
      const id = `ws_extra_${index}`;
      selected.push(id);
      portfolio.push({ id, name: `Name ${id}`, role: "viewer" });
      f.sql.prepare("INSERT INTO workspaces VALUES (?, ?, 'other', NULL)")
        .run(id, `Name ${id}`);
    }
    const grant = { portfolioRead: true, portfolioWorkspaceIds: selected };
    const first = await projectMcpPortfolioSummary(f.env, grant, { portfolio });
    assert.equal(first.workspaces.length, 5);
    assert.equal(first.selected_workspace_count, 6);
    assert.equal(first.has_more, true);
    assert.equal(first.coverage_state, "not_proven_complete");
    assert.ok(first.workspaces.every((row) => row.score_state === "not_assessed" &&
      row.score_value === null && row.evidence_state === "insufficient"));
    const second = await projectMcpPortfolioSummary(f.env, grant, { portfolio },
      { cursor: first.next_cursor });
    assert.equal(second.workspaces.length, 1);
    assert.equal(second.next_cursor, null);
    assert.equal(new Set([...first.workspaces, ...second.workspaces].map((row) => row.workspace_id)).size, 6);
    assert.equal(JSON.stringify([first, second]).includes("ws_b"), false);
    await assert.rejects(projectMcpPortfolioSummary(f.env, grant, { portfolio },
      { cursor: "ws_b" }), /invalid_projection/);
    await assert.rejects(projectMcpPortfolioSummary(f.env, grant,
      { portfolio: [...portfolio.slice(1), { id: "ws_b", name: "Name ws_b", role: "viewer" }] }),
      /invalid_projection/);
  } finally { f.close(); }
});

test("oversized or too many canonical R2 reports fail closed even when the helper catches read errors", async () => {
  const f = fixture();
  try {
    await f.seed();
    f.sql.prepare("INSERT INTO scans VALUES ('scan_complete','ws_a','a.example','completed',98,'low','complete','2026-10-15T14:00:00.000Z')").run();
    let parsed = false;
    f.env.cybermeters_reports = { async get() {
      return { size: 2_000_001, async json() { parsed = true; return {}; } };
    } };
    await denied(getWorkspaceSummaryForMcp(f.env, input()));
    assert.equal(parsed, false);

    f.sql.prepare("DELETE FROM scans WHERE id='scan_complete'").run();
    for (let i = 0; i < 17; i += 1) {
      f.sql.prepare("INSERT INTO scans VALUES (?, 'ws_a', 'a.example', 'completed', 98, 'low', 'complete', ?)")
        .run(`scan_complete_${i}`, `2026-10-15T14:${String(i).padStart(2, "0")}:00.000Z`);
    }
    let reads = 0;
    f.env.cybermeters_reports = { async get() { reads += 1; return null; } };
    await denied(getWorkspaceSummaryForMcp(f.env, input()));
    assert.equal(reads, 16);

    let objects = 0;
    let parsedObjects = 0;
    f.env.cybermeters_reports = { async get() {
      objects += 1;
      return { size: 2_000_000, async json() { parsedObjects += 1; return {}; } };
    } };
    await denied(getWorkspaceSummaryForMcp(f.env, input()));
    assert.equal(objects, 5);
    assert.equal(parsedObjects, 4);
  } finally { f.close(); }
});

// Live P2 (20 Oct 2026): ten 0.7-1.6 MB reports (11.95 MB) breached the 8 MB
// list budget and every cybermeters_list_recent_scans call failed closed.
test("a page of ten large reports still lists every scan; rows past the budget say evidence not read", async () => {
  const f = fixture();
  try {
    await f.seed();
    f.sql.prepare("DELETE FROM scans WHERE workspace_id='ws_a'").run();
    for (let i = 0; i < 10; i += 1) {
      f.sql.prepare("INSERT INTO scans VALUES (?, 'ws_a', 'a.example', 'completed', 90, 'low', 'partial', ?)")
        .run(`scan_big_${i}`, `2026-10-15T14:${String(i).padStart(2, "0")}:00.000Z`);
    }
    const parsed = [];
    const report = { modules: { dns: { records: [] } }, monitoring_states: null, findings: [] };
    f.env.cybermeters_reports = {
      async head() { return { size: 1_500_000 }; },
      async get(key) { return { size: 1_500_000, async json() { parsed.push(key); return report; } }; },
    };
    const page = await listRecentScansForMcp(f.env, input());
    assert.equal(page.scans.length, 10);
    // Newest first: 1.5 MB x 5 = 7.5 MB fits the 8 MB budget; the sixth would not.
    assert.deepEqual(page.scans.map((scan) => scan.evidence_read),
      ["read", "read", "read", "read", "read", "not_read", "not_read", "not_read", "not_read", "not_read"]);
    assert.deepEqual(page.scans.slice(0, 5).map((scan) => scan.scan_id),
      ["scan_big_9", "scan_big_8", "scan_big_7", "scan_big_6", "scan_big_5"]);
    assert.equal(parsed.length, 5, "an unread row's report body is never fetched or parsed");
    assert.ok(page.scans.slice(5).every((scan) => scan.score_available === false && scan.assessment.authoritative === false));

    // One report over the per-object cap leaves only that row unread.
    parsed.length = 0;
    f.env.cybermeters_reports = {
      async head(key) { return { size: key.includes("scan_big_8") ? 2_000_001 : 100_000 }; },
      async get(key) { return { size: key.includes("scan_big_8") ? 2_000_001 : 100_000, async json() { parsed.push(key); return report; } }; },
    };
    const oneLarge = await listRecentScansForMcp(f.env, input());
    assert.deepEqual(oneLarge.scans.map((scan) => scan.evidence_read),
      ["read", "not_read", "read", "read", "read", "read", "read", "read", "read", "read"]);
    assert.equal(parsed.length, 9);

    // A store without metadata reads keeps the previous rule: over budget fails closed.
    f.env.cybermeters_reports = { async get() { return { size: 1_500_000, async json() { return report; } }; } };
    await denied(listRecentScansForMcp(f.env, input()));
  } finally { f.close(); }
});

test("completed Cyber Essentials questionnaire cannot establish posture without a verified snapshot", async () => {
  const f = fixture();
  try {
    await f.seed();
    for (const control of CE_QUESTIONS) {
      for (const question of control.questions) {
        f.sql.prepare("INSERT INTO cyber_essentials_answers VALUES ('ws_a', ?, ?, 'yes')")
          .run(control.control_key, question.key);
      }
    }
    f.sql.prepare("INSERT INTO scans VALUES ('scan_complete','ws_a','a.example','completed',98,'low','partial','2026-10-15T14:00:00.000Z')").run();
    const withoutSnapshot = await getWorkspacePostureForMcp(f.env, input());
    assert.equal(withoutSnapshot.source_scan_id, null);
    assert.equal(withoutSnapshot.score_state, "not_assessed");
    assert.ok(withoutSnapshot.domains.every((row) => row.state !== "assessed_healthy"));

    f.sql.prepare(`INSERT INTO scan_report_snapshots VALUES
      ('snapshot_corrupt','ws_a','domain_a','scan_complete','completed',
       'snapshots/corrupt.json', ?, '1', '2026-10-15T14:00:00.000Z',
       '2026-10-15T14:00:00.000Z', NULL, NULL)`).run("0".repeat(64));
    let corruptReads = 0;
    f.env.cybermeters_reports = { async get(key) {
      if (key !== "snapshots/corrupt.json") return null;
      corruptReads += 1;
      return { size: 30, async text() {
        return '{"snapshot":{"scan_id":"scan_complete"}}';
      } };
    } };
    const corrupt = await projectMcpPosture(f.env, { workspaceId: "ws_a" });
    assert.equal(corruptReads, 1);
    assert.equal(corrupt.source_scan_id, null);
    assert.equal(corrupt.score_state, "not_assessed");
    assert.ok(corrupt.domains.every((row) => row.state !== "assessed_healthy"));
  } finally { f.close(); }
});

test("MCP posture withholds assessed state when a historical brand candidate suppresses the customer score", async () => {
  const workspaceId = "ws_a";
  const scanId = "scan_complete";
  const domainId = "domain_a";
  const canonical = {
    snapshot: { workspace_id: workspaceId, scan_id: scanId, domain_id: domainId },
    domains: resolveCyberMotDomainStates(null, { scanId }).map((domain) =>
      domain.domain_key === "brand_protection"
        ? { ...domain, state: "assessed_healthy", evidence_grade: { grade: "L1" } }
        : domain),
    overall: {
      assessment: { quality: "complete", authoritative: true,
        provisional: false, comparable: true },
      cyber_metrics_score: 82,
      score_band: "low",
      summary: "Healthy",
    },
  };
  const customerSnapshot = projectUnvalidatedBrandSnapshotForCustomer(canonical, {
    modules: { brand_monitoring: { candidates_validated: false } },
    findings: [{ id: "brand_lookalike", module: "brand_monitoring",
      finding_type: "vulnerability", severity: "critical" }],
  });
  assert.equal(customerSnapshot.overall.cyber_metrics_score, null);
  assert.equal(customerSnapshot.overall.assessment.authoritative, false);

  const posture = { state: "established", authoritative_scan_id: scanId,
    authoritative: { display_score: 82 }, latest_provisional: null };
  const env = { cybermeters_reports: { async get() { throw new Error("unexpected R2 read"); } } };
  const grant = { workspaceId };
  const readSnapshot = async (_env, id, options) => {
    assert.equal(id, scanId);
    assert.deepEqual(options,
      { repair: false, allowReconstruction: false, includeSuccessor: false });
    return { status: "ok", integrity: { verified: true },
      row: { workspace_id: workspaceId, scan_id: scanId, domain_id: domainId },
      customerSnapshot: canonical };
  };
  const getPosture = async (_env, scope) => {
    assert.deepEqual(scope, { workspaceId });
    return posture;
  };
  const established = await projectMcpPosture(env, grant, { getPosture, readSnapshot });
  assert.equal(established.score_state, "assessed");
  assert.equal(established.domains.find((domain) => domain.domain_key === "brand_protection").state,
    "assessed_healthy");

  const withheld = await projectMcpPosture(env, grant, { getPosture,
    readSnapshot: async (...args) => {
      const read = await readSnapshot(...args);
      return { ...read, customerSnapshot };
    } });
  assert.equal(withheld.source_scan_id, scanId);
  assert.equal(withheld.score_state, "current_not_assessed");
  assert.notEqual(withheld.domains.find((domain) => domain.domain_key === "brand_protection").state,
    "assessed_healthy");
  assert.equal(withheld.domains.find((domain) => domain.domain_key === "brand_protection").finding_count, 0);
});

test("one managed case read is scoped to tenant and hides foreign versus missing IDs", async () => {
  const f = fixture();
  try {
    await f.seed();
    const grant = { workspaceId: "ws_a" };
    const own = await projectMcpManagedCase(f.env, grant, null, { caseId: "case_a" });
    assert.equal(own.case_id, "case_a");
    assert.equal(own.domain_key, "email_protection");
    assert.equal(JSON.stringify(own).includes("case_b"), false);
    const reason = async (caseId) => {
      try { await projectMcpManagedCase(f.env, grant, null, { caseId }); }
      catch (error) { return error.message; }
      assert.fail(`Unexpected case result for ${caseId}`);
    };
    assert.equal(await reason("case_b"), await reason("case_absent"));
  } finally { f.close(); }
});

test("foreign or missing scan, mismatched bearer and unexpected arguments fail alike", async () => {
  const f = fixture();
  try {
    await f.seed();
    await denied(getScanStatusForMcp(f.env, { ...input(), scanId: "scan_b" }));
    await denied(getScanStatusForMcp(f.env, { ...input(), scanId: "missing" }));
    await denied(listWorkspacesForMcp(f.env, { bearer: TOKEN_B }));
    await denied(listWorkspacesForMcp(f.env, { bearer: TOKEN_A, workspaceId: "ws_b" }));
    await denied(getWorkspaceSummaryForMcp(f.env, input(TOKEN_A, "ws_b")));
    const grant = { workspaceId: "ws_a" };
    const foreign = await projectMcpScanStatus(f.env, grant, null, { scanId: "scan_b" })
      .then(() => null, (error) => error.message);
    const missing = await projectMcpScanStatus(f.env, grant, null, { scanId: "missing" })
      .then(() => null, (error) => error.message);
    assert.equal(foreign, missing);
    const deniedRows = f.sql.prepare("SELECT workspace_id,user_id,metadata_json FROM audit_events").all();
    assert.equal(deniedRows.length, 5);
    for (const row of deniedRows) {
      assert.equal(row.workspace_id, null);
      assert.equal(row.user_id, null);
      assert.equal(row.metadata_json.includes(TOKEN_A) || row.metadata_json.includes(TOKEN_B), false);
    }
  } finally { f.close(); }
});

test("revocation, budget storage failure and audit storage failure never return data", async () => {
  const f = fixture();
  try {
    await f.seed();
    f.sql.prepare("UPDATE api_tokens SET status='revoked' WHERE id='tok_a'").run();
    await denied(getWorkspaceSummaryForMcp(f.env, input()));
    f.sql.prepare("UPDATE api_tokens SET status='active' WHERE id='tok_a'").run();
    f.sql.exec("DROP TABLE api_rate_limits");
    await denied(getWorkspaceSummaryForMcp(f.env, input()));
    f.sql.exec("CREATE TABLE api_rate_limits (id TEXT PRIMARY KEY, scope TEXT, scope_id TEXT, action TEXT, window_start TEXT, window_seconds INTEGER, request_count INTEGER, created_at TEXT, updated_at TEXT)");
    f.sql.exec("DROP TABLE audit_events");
    await denied(getWorkspaceSummaryForMcp(f.env, input()));
  } finally { f.close(); }
});
