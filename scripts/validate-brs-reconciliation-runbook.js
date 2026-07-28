#!/usr/bin/env node
// Pins the founder-gated BRS reconciliation inventory SQL to the canonical
// runtime resolver's definition of a latest incomplete terminal assessment.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const runbookPath = path.join(root, "docs", "runbooks", "BRS-PARTIAL-SCAN-RECONCILIATION.md");
const businessRiskPath = path.join(root, "workers", "scan-api", "src", "engines", "business-risk.js");
const {
  resolveWorkspaceBrsProjection,
  WORKSPACE_BRS_BASIS_CONTRACT,
  WORKSPACE_BRS_STATES,
} = await import(pathToFileURL(businessRiskPath).href);

const EXPECTED_ASSERTIONS = 16;
let passed = 0;
let failed = 0;
const check = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  check(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const runbook = fs.readFileSync(runbookPath, "utf8");
const sqlBlocks = [...runbook.matchAll(/```sql\s*\n([\s\S]*?)```/g)].map((match) => match[1].trim());
eq("runbook contains exactly one executable reconciliation SQL block", sqlBlocks.length, 1);
const inventorySql = sqlBlocks[0] || "";

check("latest terminal selector includes completed and failed",
  /WHERE status IN \('completed', 'failed'\)/.test(inventorySql));
check("latest incomplete condition includes failed terminal scans",
  /latest_status\s*=\s*'failed'\s+OR\s*\(\s*latest_status\s*=\s*'completed'[\s\S]*?COALESCE\(latest_quality,\s*'unknown'\)\s*<>\s*'complete'/m
    .test(inventorySql));
eq("no second completed-only latest-status assumption exists",
  (inventorySql.match(/latest_status\s*=\s*'completed'/g) || []).length, 1);

function evaluateFixture({ name, latestStatus, latestQuality, expectedIncomplete }) {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspace_brs_scores (
      workspace_id TEXT PRIMARY KEY,
      payload_json TEXT
    );
    CREATE TABLE scans (
      id TEXT PRIMARY KEY,
      workspace_id TEXT,
      status TEXT,
      scan_quality TEXT,
      created_at TEXT
    );
  `);

  const workspaceId = `ws-${name}`;
  const latestScanId = `latest-${name}`;
  const basisScanId = expectedIncomplete ? `basis-${name}` : latestScanId;
  const basisCreatedAt = "2026-07-28T08:00:00.000Z";
  const latestCreatedAt = "2026-07-28T09:00:00.000Z";
  const payload = {
    basis_contract: WORKSPACE_BRS_BASIS_CONTRACT,
    score: 70,
    risk_band: "medium",
    grade: "B",
    latest_scan: { scan_id: basisScanId },
    basis_scan: {
      scan_id: basisScanId,
      status: "completed",
      scan_quality: "complete",
      assessed_at: basisCreatedAt,
      scan_started_at: basisCreatedAt,
    },
  };
  db.prepare("INSERT INTO workspace_brs_scores (workspace_id,payload_json) VALUES (?,?)")
    .run(workspaceId, JSON.stringify(payload));
  db.prepare(`
    INSERT INTO scans (id,workspace_id,status,scan_quality,created_at)
    VALUES (?,?,'completed','complete',?)
  `).run(basisScanId, workspaceId, basisCreatedAt);
  if (latestScanId !== basisScanId) {
    db.prepare(`
      INSERT INTO scans (id,workspace_id,status,scan_quality,created_at)
      VALUES (?,?,?,?,?)
    `).run(latestScanId, workspaceId, latestStatus, latestQuality, latestCreatedAt);
  }

  const row = db.prepare(inventorySql).get();
  const counted = Number(row.rows_with_latest_incomplete_assessment) === 1;
  const storedRow = {
    workspace_id: workspaceId,
    score: 70,
    risk_band: "medium",
    calculated_at: basisCreatedAt,
    payload_json: JSON.stringify(payload),
  };
  const latestScan = {
    scan_id: latestScanId,
    workspace_id: workspaceId,
    status: latestStatus,
    scan_quality: latestQuality,
    created_at: latestCreatedAt,
  };
  const basisScan = {
    scan_id: basisScanId,
    workspace_id: workspaceId,
    status: "completed",
    scan_quality: "complete",
    created_at: basisCreatedAt,
  };
  const projection = resolveWorkspaceBrsProjection({ storedRow, latestScan, basisScan });
  const resolverIncomplete = projection.state === WORKSPACE_BRS_STATES.LATEST_INCOMPLETE;

  eq(`${name}: runtime resolver state`, resolverIncomplete, expectedIncomplete);
  eq(`${name}: runbook count`, counted, expectedIncomplete);
  eq(`${name}: runbook and runtime resolver agree`, counted, resolverIncomplete);
}

evaluateFixture({
  name: "completed-partial",
  latestStatus: "completed",
  latestQuality: "partial",
  expectedIncomplete: true,
});
evaluateFixture({
  name: "completed-unknown",
  latestStatus: "completed",
  latestQuality: null,
  expectedIncomplete: true,
});
evaluateFixture({
  name: "failed-terminal",
  latestStatus: "failed",
  latestQuality: "complete",
  expectedIncomplete: true,
});
evaluateFixture({
  name: "completed-complete",
  latestStatus: "completed",
  latestQuality: "complete",
  expectedIncomplete: false,
});

if (passed + failed !== EXPECTED_ASSERTIONS) {
  failed += 1;
  console.error(`FAIL pinned assertion count — got ${passed + failed - 1} want ${EXPECTED_ASSERTIONS}`);
}
console.log(`BRS reconciliation runbook: ${passed}/${passed + failed} assertions passed`);
if (failed > 0 || passed !== EXPECTED_ASSERTIONS) process.exit(1);
console.log("BRS reconciliation runbook validation passed");
