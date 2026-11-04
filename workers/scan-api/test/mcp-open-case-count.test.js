// Focused regression: the MCP workspace-summary open_case_count must equal the
// canonical "open work" count (the same contract report-snapshot.js / Operations
// use), not a raw non-terminal status count. Before the fix, projectMcpSummary
// counted `status NOT IN ('closed','false_positive','risk_accepted')`, so
// verified / monitoring / superseded (and other canonical terminal/verified
// phases) leaked in as "open".
//
// Real projector + real service over a synthetic two-tenant in-memory SQLite.
// No unit mock fabricates the count; every assertion is the product path's own
// answer. Identifiers are fully synthetic (no company/workspace/scan ids).
import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { hashToken } from "../src/lib/auth-crypto.js";
import {
  getWorkspaceSummaryForMcp, listManagedCasesForMcp,
} from "../src/routes/mcp-service.js";

const TOKEN_A = `cm_${"a".repeat(64)}`;
const TOKEN_B = `cm_${"b".repeat(64)}`;
const EXPIRES = "2099-01-01T00:00:00.000Z";
const WS_A = "ws_syn_aaaa1111";
const WS_B = "ws_syn_bbbb2222";

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
    MCP_INTERNAL_ENABLED: "true", MCP_TRIAL_WORKSPACE_ID: WS_A,
    MCP_TRIAL_TOKEN_ID: "tok_syn_a", cybermeters_db: d1,
    cybermeters_reports: { async get() { return null; } },
  };
  const seed = async () => {
    for (const [workspace, user, token, bearer] of [
      [WS_A, "usr_syn_a", "tok_syn_a", TOKEN_A],
      [WS_B, "usr_syn_b", "tok_syn_b", TOKEN_B],
    ]) {
      sql.prepare("INSERT INTO users VALUES (?, 'active')").run(user);
      sql.prepare("INSERT INTO workspaces VALUES (?, ?, ?, NULL)").run(workspace, `Name ${workspace}`, "other");
      sql.prepare("INSERT INTO workspace_members VALUES (?, ?, 'viewer')").run(workspace, user);
      sql.prepare("INSERT INTO api_tokens VALUES (?, ?, ?, ?, 'read', ?, 'active')")
        .run(token, user, await hashToken(bearer), workspace, EXPIRES);
    }
    sql.prepare("INSERT INTO workspace_domains VALUES (?, 'domain_syn_a')").run(WS_A);
  };
  let n = 0;
  const addCase = (workspace, caseType, domainKey, status) => {
    const id = `case_syn_${String(n++).padStart(4, "0")}`;
    sql.prepare(
      `INSERT INTO managed_cases VALUES (?, ?, ?, ?, ?, 'medium', NULL,
        '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', NULL)`,
    ).run(id, workspace, caseType, domainKey, status);
    return id;
  };
  return { sql, env, seed, addCase, close: () => sql.close() };
}

const input = (bearer = TOKEN_A, workspaceId = WS_A) => ({ bearer, workspaceId });
const denied = (promise) => assert.rejects(promise, (error) =>
  error.message === "mcp_summary_unavailable" && !JSON.stringify(error).includes(TOKEN_A));

// The Root-verified counter-example shape (3 Nov 2026): 6 managed cases —
// detected x3 (open), verified x2 and superseded x1 (retained, NOT open).
// Raw non-terminal status counts 6; canonical phases count 3.
test("summary open_case_count counts canonical open phases, not raw non-terminal status", async () => {
  const f = fixture();
  try {
    await f.seed();
    f.addCase(WS_A, "certificate_case", "certificates_trust", "detected");
    f.addCase(WS_A, "identity_case", "identity_exposure", "detected");
    f.addCase(WS_A, "shadow_it_case", "shadow_it_unmanaged_technology", "detected");
    f.addCase(WS_A, "certificate_case", "certificates_trust", "verified");
    f.addCase(WS_A, "identity_case", "identity_exposure", "verified");
    f.addCase(WS_A, "certificate_case", "certificates_trust", "superseded");
    // Tenant isolation: a second tenant carries detected (open) work in the SAME
    // table. If the count were not workspace-scoped these would inflate WS_A to 5;
    // the query's `WHERE workspace_id = ?` must keep WS_A at exactly 3.
    f.addCase(WS_B, "certificate_case", "certificates_trust", "detected");
    f.addCase(WS_B, "certificate_case", "certificates_trust", "detected");

    const summary = await getWorkspaceSummaryForMcp(f.env, input());
    assert.equal(summary.open_case_count, 3); // was 6 under the raw-status query

    // The shown list is intentionally unchanged: it still surfaces every active
    // (not closed/false_positive/risk_accepted) record, verified/superseded included.
    const list = await listManagedCasesForMcp(f.env, input());
    assert.equal(list.cases.length, 6);
    assert.equal(list.has_more, false);
  } finally { f.close(); }
});

// Full canonical-phase matrix: base identity mapping, ASM/Brand legacy status
// mappings, canonical terminal states, legacy raw aliases, and unknown
// case_type / unknown status (which must stay OPEN, never silently concluded).
test("summary open_case_count honours per-case_type canonical phase mapping and aliases", async () => {
  const f = fixture();
  try {
    await f.seed();
    const rows = [
      // case_type,            status,              expectedOpen
      ["certificate_case",     "detected",          true],
      ["identity_case",        "triaged",           true],
      ["website_case",         "reopened",          true],
      ["certificate_case",     "verified",          false],
      ["identity_case",        "monitoring",        false],
      ["certificate_case",     "rejected",          false],
      ["certificate_case",     "accepted_risk",     false],
      ["certificate_case",     "false_positive",    false],
      ["certificate_case",     "closed_no_action",  false],
      ["certificate_case",     "superseded",        false],
      // Legacy raw aliases on a base case_type.
      ["identity_case",        "closed",            false],
      ["identity_case",        "risk_accepted",     false],
      // ASM (asm_exposure) legacy raw statuses fold through ASM_PHASE.
      ["asm_exposure",         "open",              true],   // -> detected
      ["asm_exposure",         "resolved",          false],  // -> verified
      ["asm_exposure",         "risk_accepted",     false],  // -> accepted_risk
      ["asm_exposure",         "closed",            false],  // -> closed_no_action
      ["asm_exposure",         "reopened",          true],   // -> reopened
      // Brand (brand_abuse).
      ["brand_abuse",          "detected",          true],
      ["brand_abuse",          "resolved",          false],  // -> verified
      ["brand_abuse",          "duplicate",         false],  // -> superseded
      // Unknown case_type / unknown status: unknown phase stays OPEN.
      ["mystery_case",         "detected",          true],   // null phase ?? 'detected'
      ["mystery_case",         "verified",          false],  // null phase ?? 'verified' (alias)
      ["certificate_case",     "brand_new_state",   true],   // unknown base status stays open
    ];
    for (const [caseType, status] of rows) {
      f.addCase(WS_A, caseType, "attack_surface", status);
    }
    const expectedOpen = rows.filter(([, , open]) => open).length;
    const summary = await getWorkspaceSummaryForMcp(f.env, input());
    assert.equal(summary.open_case_count, expectedOpen);
  } finally { f.close(); }
});

// The count is a true total (DB aggregate), never a first-N partial like the
// bounded case LIST (CASE_LIMIT = 10).
test("summary open_case_count totals all rows, not a first-10 page", async () => {
  const f = fixture();
  try {
    await f.seed();
    for (let i = 0; i < 13; i += 1) {
      f.addCase(WS_A, "certificate_case", "certificates_trust", "detected");
    }
    for (let i = 0; i < 4; i += 1) {
      f.addCase(WS_A, "certificate_case", "certificates_trust", "verified");
    }
    const summary = await getWorkspaceSummaryForMcp(f.env, input());
    assert.equal(summary.open_case_count, 13);
  } finally { f.close(); }
});

// Fail closed: if the managed-case aggregate returns an invalid shape, the
// summary must error (surfaced as mcp_summary_unavailable), never resolve to a
// fabricated open_case_count of 0.
test("summary fails closed on an invalid case aggregate, never a fake 0", async () => {
  const f = fixture();
  try {
    await f.seed();
    f.addCase(WS_A, "certificate_case", "certificates_trust", "detected");
    const realDb = f.env.cybermeters_db;
    const brokenDb = { prepare(statement) {
      if (statement.includes("GROUP BY case_type, status")) {
        return { bind() { return {
          async all() { return { results: null }; },
          async first() { return null; },
          async run() { return { meta: { changes: 0 } }; },
        }; } };
      }
      return realDb.prepare(statement);
    } };
    await denied(getWorkspaceSummaryForMcp({ ...f.env, cybermeters_db: brokenDb }, input()));
  } finally { f.close(); }
});
