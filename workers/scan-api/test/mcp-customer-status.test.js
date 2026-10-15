import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import {
  projectMcpFindingExplanation, projectMcpTlsPosture,
  projectMcpEmailPosture, projectMcpReportSummary,
} from "../src/routes/mcp-customer-status.js";
import {
  projectCustomerFindingExplanation, projectCustomerTlsPosture,
  projectCustomerEmailPosture, projectCustomerReportSummary,
} from "../../mcp-server/src/customer-mcp.js";

function fixture() {
  const sql = new DatabaseSync(":memory:");
  sql.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, owner_user_id TEXT, deleted_at TEXT);
    CREATE TABLE workspace_members (workspace_id TEXT, user_id TEXT, role TEXT);
    CREATE TABLE mcp_beta_workspace_access (workspace_id TEXT PRIMARY KEY, status TEXT);
    CREATE TABLE deletion_requests (request_type TEXT, workspace_id TEXT, status TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT,
      verification_status TEXT, PRIMARY KEY (workspace_id, domain_id));
    CREATE TABLE scans (id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT,
      domain TEXT, status TEXT, scan_quality TEXT, created_at TEXT);
    CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT, finding_slug TEXT,
      severity TEXT, title TEXT, evidence_json TEXT);
    CREATE TABLE certificate_lifecycle (id TEXT PRIMARY KEY, workspace_id TEXT,
      domain_id TEXT, primary_hostname TEXT, not_after TEXT, days_remaining INTEGER,
      renewal_readiness TEXT, coverage_status TEXT, verification_status TEXT,
      last_seen_at TEXT, current_certificate_observation_id TEXT);
    CREATE TABLE certificate_observations (id TEXT PRIMARY KEY, workspace_id TEXT,
      domain_id TEXT, evidence_json TEXT);
    CREATE TABLE scan_report_snapshots (id TEXT PRIMARY KEY, workspace_id TEXT,
      domain_id TEXT, scan_id TEXT, status TEXT, r2_key TEXT,
      checksum_sha256 TEXT, snapshot_schema_version TEXT,
      assessed_at TEXT, created_at TEXT, branding_json TEXT,
      related_changes_json TEXT);
    INSERT INTO workspaces VALUES ('ws_a','owner_a',NULL),('ws_b','owner_b',NULL);
    INSERT INTO workspace_members VALUES ('ws_a','user_a','viewer'),('ws_b','user_b','viewer');
    INSERT INTO mcp_beta_workspace_access VALUES ('ws_a','enabled'),('ws_b','enabled');
    INSERT INTO domains VALUES ('d_shared','shared.example'),('d_a','a.example'),('d_b','b.example');
    INSERT INTO workspace_domains VALUES
      ('ws_a','d_shared','verified'),('ws_b','d_shared','unverified'),
      ('ws_a','d_a','verified'),('ws_b','d_b','verified');
    INSERT INTO scans VALUES
      ('scan_a','ws_a','d_a','a.example','completed','complete','2026-10-14T10:00:00.000Z'),
      ('scan_b','ws_b','d_b','b.example','completed','complete','2026-10-14T11:00:00.000Z'),
      ('scan_b_shared','ws_b','d_shared','shared.example','completed','complete','2026-10-14T12:00:00.000Z');
    INSERT INTO findings VALUES
      ('finding_a','scan_a','email_missing_dmarc','critical','DMARC missing','{}'),
      ('finding_b','scan_b','email_missing_dmarc','critical','Other tenant DMARC','{}'),
      ('finding_b_shared','scan_b_shared','email_missing_dmarc','high','Other tenant shared','{}');
    INSERT INTO certificate_lifecycle VALUES
      ('cl_a','ws_a','d_a','a.example','2026-12-01T00:00:00.000Z',47,
       'planning','complete','not_verified','2026-10-14T10:00:00.000Z',NULL),
      ('cl_b','ws_b','d_b','b.example','2026-12-01T00:00:00.000Z',47,
       'planning','complete','not_verified','2026-10-14T10:00:00.000Z',NULL);
  `);
  let writes = 0;
  let reads = 0;
  const env = {
    cybermeters_db: {
      prepare(statement) {
        const query = sql.prepare(statement);
        return { bind(...params) { return {
          async first() { return query.get(...params) ?? null; },
          async all() { return { results: query.all(...params) }; },
          async run() { writes += 1; throw new Error("unexpected D1 mutation"); },
        }; } };
      },
    },
    cybermeters_reports: {
      async get() { reads += 1; return null; },
      async put() { writes += 1; throw new Error("unexpected R2 mutation"); },
      async delete() { writes += 1; throw new Error("unexpected R2 mutation"); },
    },
  };
  return { sql, env, close: () => sql.close(),
    get writes() { return writes; }, get reads() { return reads; } };
}

const grantA = { userId: "user_a", workspaceId: "ws_a" };
const grantB = { userId: "user_b", workspaceId: "ws_b" };
const options = { repair: false, allowReconstruction: false, includeSuccessor: false };

test("status projection refuses a workspace paused or pending deletion after admission", async () => {
  const f = fixture();
  try {
    f.sql.prepare("UPDATE mcp_beta_workspace_access SET status='paused' WHERE workspace_id='ws_a'").run();
    await assert.rejects(projectMcpTlsPosture(f.env, grantA, null,
      { workspaceId: "ws_a" }), /mcp_projection_unavailable/);
    f.sql.prepare("UPDATE mcp_beta_workspace_access SET status='enabled' WHERE workspace_id='ws_a'").run();
    f.sql.prepare("INSERT INTO deletion_requests VALUES ('workspace','ws_a','pending')").run();
    await assert.rejects(projectMcpReportSummary(f.env, grantA, null,
      { workspaceId: "ws_a" }), /mcp_projection_unavailable/);
    f.sql.prepare("UPDATE deletion_requests SET status='blocked_residual_data' WHERE workspace_id='ws_a'").run();
    await assert.rejects(projectMcpReportSummary(f.env, grantA, null,
      { workspaceId: "ws_a" }), /mcp_projection_unavailable/);
  } finally { f.close(); }
});

function verifiedRead({ scanId = "scan_a", workspaceId = "ws_a", domainId = "d_a",
  domain = "a.example", findingTitle = "DMARC missing" } = {}) {
  return {
    status: "ok", integrity: { verified: true },
    row: { scan_id: scanId, workspace_id: workspaceId, domain_id: domainId },
    customerSnapshot: {
      snapshot: { scan_id: scanId, workspace_id: workspaceId, domain_id: domain,
        as_of: "2026-10-14T10:00:00.000Z", domain_id: domainId },
      overall: {
        assessment: { quality: "complete", authoritative: true,
          provisional: false, comparable: true },
        cyber_metrics_score: 82, score_band: "low", summary: "One domain assessment.",
      },
      observed_findings: [{ finding_id: "email_missing_dmarc", title: findingTitle,
        severity: "critical", evidence_grade: { grade: "L1" },
        evidence_ref: { source: "scan_report", count: 1 },
        remediation_id: "email.dmarc.publish" }],
      domains: [{ domain_key: "email_protection", state: "issue_detected",
        evidence_grade: { grade: "L1" } }],
      remediation_actions: [{ remediation_id: "email.dmarc.publish", priority: "critical",
        title: "Publish a DMARC policy", action: "Publish one valid policy." }],
    },
    customerModules: { email_security: { executed: true, incomplete: false,
      spf: { present: true, resolution_status: "complete" }, dkim: { present: false } } },
    dmarcPolicy: { status: "current", evidence: { observation_state: "present_valid",
      record_validity: "valid", effective_requested_policy: "none",
      policy_completeness: "complete" } },
  };
}

const rejectProjection = (promise) => assert.rejects(promise, (error) =>
  error.message === "mcp_projection_unavailable" || error.message === "mcp_report_read_budget" ||
  /D1 offline/.test(error.message));

test("finding explanation uses opaque D1 ID, verified link, snapshot slug and canonical guidance", async () => {
  const f = fixture();
  try {
    let called = 0;
    const readSnapshot = async (_env, scanId, opts) => {
      called += 1;
      assert.equal(scanId, "scan_a");
      assert.deepEqual(opts, options);
      return verifiedRead();
    };
    const result = await projectMcpFindingExplanation(f.env, grantA, null,
      { workspaceId: "ws_a", findingId: "finding_a" }, { readSnapshot });
    assert.equal(called, 1);
    assert.equal(result.status, "available");
    assert.equal(result.finding.type, "email_missing_dmarc");
    assert.equal(result.finding.evidence_state, "authoritative");
    assert.equal(result.remediation.remediation_id, "email.dmarc.publish");
    assert.equal(result.remediation.version, "1");
    assert.deepEqual(result.field_guide,
      { version: "area-link-v1", path: "/guide/email-protection",
        url: "https://app.cybermeters.com/guide/email-protection" });
    assert.equal(JSON.stringify(result).includes("evidence_json"), false);
    assert.equal(f.writes, 0);
  } finally { f.close(); }
});

test("foreign tenant and unverified shared link cannot resolve finding", async () => {
  const f = fixture();
  try {
    let calls = 0;
    const readSnapshot = async () => { calls += 1; return verifiedRead(); };
    await rejectProjection(projectMcpFindingExplanation(f.env, grantA, null,
      { workspaceId: "ws_a", findingId: "finding_b" }, { readSnapshot }));
    await rejectProjection(projectMcpFindingExplanation(f.env, grantB, null,
      { workspaceId: "ws_b", findingId: "finding_b_shared" }, { readSnapshot }));
    await rejectProjection(projectMcpFindingExplanation(f.env, grantA, null,
      { workspaceId: "ws_b", findingId: "finding_a" }, { readSnapshot }));
    assert.equal(calls, 0);
  } finally { f.close(); }
});

test("snapshot failure and unmatched frozen finding remain explicit", async () => {
  const f = fixture();
  try {
    const unavailable = await projectMcpFindingExplanation(f.env, grantA, null,
      { workspaceId: "ws_a", findingId: "finding_a" },
      { readSnapshot: async (_env, _scan, opts) => {
        assert.deepEqual(opts, options);
        return { status: "integrity_error" };
      } });
    assert.equal(unavailable.status, "snapshot_unavailable");
    assert.equal(unavailable.remediation, null);
    const mismatch = await projectMcpFindingExplanation(f.env, grantA, null,
      { workspaceId: "ws_a", findingId: "finding_a" },
      { readSnapshot: async () => verifiedRead({ findingTitle: "Different observation" }) });
    assert.equal(mismatch.status, "finding_not_in_snapshot");
  } finally { f.close(); }
});

test("TLS page uses canonical assurance states, keyset cursor and excludes foreign records", async () => {
  const f = fixture();
  try {
    for (let i = 0; i < 10; i += 1) {
      f.sql.prepare(`INSERT INTO certificate_lifecycle VALUES (?, 'ws_a','d_a', ?, NULL,NULL,
        'unknown','unknown','not_verified','2026-10-14T10:00:00.000Z',NULL)`)
        .run(`cl_z${i}`, `sub${i}.a.example`);
    }
    const first = await projectMcpTlsPosture(f.env, grantA, null, { workspaceId: "ws_a" });
    assert.equal(first.certificates.length, 10);
    assert.equal(first.has_more, true);
    assert.equal(first.certificates[0].assurance_status, "not_recorded");
    assert.equal(first.certificates[0].signals.trust_store_validation.state, "not_observed");
    assert.equal(JSON.stringify(first).includes("cl_b"), false);
    const second = await projectMcpTlsPosture(f.env, grantA, null,
      { workspaceId: "ws_a", cursor: first.next_cursor });
    assert.equal(second.certificates.length, 1);
    assert.equal(second.has_more, false);
    await rejectProjection(projectMcpTlsPosture(f.env, grantB, null,
      { workspaceId: "ws_b", cursor: first.next_cursor }));
    assert.equal(f.writes, 0);
  } finally { f.close(); }
});

test("TLS D1 failure propagates rather than becoming an empty/healthy status", async () => {
  const f = fixture();
  try {
    const original = f.env.cybermeters_db.prepare;
    f.env.cybermeters_db.prepare = (query) => {
      if (query.includes("FROM certificate_lifecycle")) throw new Error("D1 offline");
      return original(query);
    };
    await rejectProjection(projectMcpTlsPosture(f.env, grantA, null, { workspaceId: "ws_a" }));
  } finally { f.close(); }
});

test("email reads one verified snapshot per domain and never treats missing evidence as safe", async () => {
  const f = fixture();
  try {
    let count = 0;
    const readSnapshot = async (_env, scanId, opts) => {
      count += 1;
      assert.equal(scanId, "scan_a");
      assert.deepEqual(opts, options);
      return verifiedRead();
    };
    const page = await projectMcpEmailPosture(f.env, grantA, null,
      { workspaceId: "ws_a" }, { readSnapshot });
    assert.equal(page.domains.length, 2);
    assert.equal(count, 1);
    assert.equal(page.domains[0].status, "available");
    assert.equal(page.domains[0].dmarc.effective_requested_policy, "none");
    assert.equal(page.domains[0].spf.present, true);
    assert.equal(page.domains[0].dkim.observation_state, "unknown");
    assert.equal(page.domains[1].status, "not_assessed");
    assert.equal(JSON.stringify(page).includes("scan_b_shared"), false);
    assert.equal(f.writes, 0);
  } finally { f.close(); }
});

test("email snapshot integrity failure stays unavailable and pagination is tenant-bound", async () => {
  const f = fixture();
  try {
    for (let i = 0; i < 10; i += 1) {
      const id = `extra_${i}`;
      const domain = `z${i}.example`;
      f.sql.prepare("INSERT INTO domains VALUES (?, ?)").run(id, domain);
      f.sql.prepare("INSERT INTO workspace_domains VALUES ('ws_a', ?, 'verified')").run(id);
    }
    const first = await projectMcpEmailPosture(f.env, grantA, null,
      { workspaceId: "ws_a" }, { readSnapshot: async () => ({ status: "integrity_error" }) });
    assert.equal(first.has_more, true);
    assert.equal(first.domains.find((row) => row.domain === "a.example").status,
      "snapshot_unavailable");
    const second = await projectMcpEmailPosture(f.env, grantA, null,
      { workspaceId: "ws_a", cursor: first.next_cursor });
    assert.equal(second.domains.length, 2);
    await rejectProjection(projectMcpEmailPosture(f.env, grantB, null,
      { workspaceId: "ws_b", cursor: first.next_cursor }));
  } finally { f.close(); }
});

test("report says single scan and withholds summary when canonical snapshot is unavailable", async () => {
  const f = fixture();
  try {
    const report = await projectMcpReportSummary(f.env, grantA, null,
      { workspaceId: "ws_a" }, { readSnapshot: async (_env, scanId, opts) => {
        assert.equal(scanId, "scan_a");
        assert.deepEqual(opts, options);
        return verifiedRead();
      } });
    assert.equal(report.status, "available");
    assert.equal(report.report_scope, "single_scan");
    assert.equal(report.source_scan_id, "scan_a");
    assert.equal(report.score.value, 82);
    assert.equal(report.observed_findings_count, 1);
    assert.equal(report.priority_actions.length, 1);
    const unavailable = await projectMcpReportSummary(f.env, grantA, null,
      { workspaceId: "ws_a" }, { readSnapshot: async () => ({ status: "not_found" }) });
    assert.equal(unavailable.status, "snapshot_unavailable");
    assert.equal(unavailable.score, null);
    assert.equal(unavailable.assessed_at, null);
    assert.equal(f.writes, 0);
  } finally { f.close(); }
});

test("real snapshot reader rejects oversize R2 object before parsing or repair", async () => {
  const f = fixture();
  try {
    f.sql.exec(`INSERT INTO scan_report_snapshots VALUES
      ('snap_a','ws_a','d_a','scan_a','completed','reports/snapshots/a.json',
       'abc','1','2026-10-14T10:00:00.000Z','2026-10-14T10:00:00.000Z',NULL,NULL)`);
    f.env.cybermeters_reports.get = async () => ({ size: 2_000_001,
      async text() { throw new Error("oversize object parsed"); } });
    await rejectProjection(projectMcpReportSummary(f.env, grantA, null,
      { workspaceId: "ws_a" }));
    assert.equal(f.writes, 0);
  } finally { f.close(); }
});

test("gateway field allowlists accept each backend status projection", async () => {
  const f = fixture();
  try {
    const readSnapshot = async () => verifiedRead();
    const explain = await projectMcpFindingExplanation(f.env, grantA, null,
      { workspaceId: "ws_a", findingId: "finding_a" }, { readSnapshot });
    const tls = await projectMcpTlsPosture(f.env, grantA, null, { workspaceId: "ws_a" });
    const email = await projectMcpEmailPosture(f.env, grantA, null,
      { workspaceId: "ws_a" }, { readSnapshot });
    const report = await projectMcpReportSummary(f.env, grantA, null,
      { workspaceId: "ws_a" }, { readSnapshot });
    assert.equal(JSON.parse(projectCustomerFindingExplanation(explain, "ws_a", "finding_a")).status,
      "available");
    assert.equal(JSON.parse(projectCustomerTlsPosture(tls, "ws_a")).certificates.length, 1);
    assert.equal(JSON.parse(projectCustomerEmailPosture(email, "ws_a")).domains.length, 2);
    assert.equal(JSON.parse(projectCustomerReportSummary(report, "ws_a")).report_scope, "single_scan");
  } finally { f.close(); }
});
