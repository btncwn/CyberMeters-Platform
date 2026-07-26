#!/usr/bin/env node
// Item 9 P3 — faithful multi-scan runScanEngine renewal lifecycle trace.
//
// The real production engine runs three times. Only network edges are fixtures:
// scan 1 observes an at-risk CT issuance, scan 2 observes a changed replacement,
// scan 3 re-observes the same replacement. The trace proves production lifecycle
// integration, append-only relationships, dedupe and CT-only non-verification.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { runScanEngine } = await import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", "scan-engine.js"
)).href);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) =>
  ok(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return {
        success: true,
        meta: {
          changes: result.changes,
          last_row_id: Number(result.lastInsertRowid || 0),
        },
      };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) =>
      Promise.all(statements.map((entry) =>
        /^\s*select/i.test(entry.__sql) ? entry.all() : entry.run())),
  };
}

function makeR2(store) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => {
      store.set(String(key), String(body));
      return {};
    },
    delete: async (key) => {
      store.delete(String(key));
      return {};
    },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

const DAY = 86_400_000;
const clockMs = Date.now();
const oldNotAfter = new Date(clockMs + (6 * DAY)).toISOString();
const newNotAfter = new Date(clockMs + (365 * DAY)).toISOString();
let scanPhase = 1;
const providerCalls = { crt_sh: 0, certspotter: 0 };
let outboundCalls = 0;
const realFetch = globalThis.fetch;
const realRandom = Math.random;
globalThis.fetch = async (input) => {
  outboundCalls++;
  const url = new URL(String(input));
  if (url.hostname === "crt.sh") {
    providerCalls.crt_sh++;
    return jsonResponse({}, 403);
  }
  if (url.hostname === "api.certspotter.com") {
    providerCalls.certspotter++;
    const replacement = scanPhase >= 2;
    return jsonResponse([{
      id: replacement ? "replacement-issued" : "baseline-issued",
      not_before: new Date(clockMs - (30 * DAY)).toISOString(),
      not_after: replacement ? newNotAfter : oldNotAfter,
      issuer: { name: replacement ? "Trace Renewal CA" : "Trace Baseline CA" },
      dns_names: replacement
        ? ["example.com", "www.example.com", "api.example.com", "*.example.com"]
        : ["example.com", "www.example.com"],
    }]);
  }
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "example.com" && type === "A") {
      return jsonResponse({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("<html><title>Example</title></html>", {
    status: 200,
    headers: { "content-type": "text/html", server: "item9-p3-trace" },
  });
};
Math.random = () => 0.123456789;

const db = buildDb();
const store = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: makeR2(store),
  SCAN_CAPACITY_MODE: "legacy",
  SCAN_SUBREQUEST_LIMIT: "200",
  SCAN_DEADLINE_MS: "19000",
  APP_VERSION: "item9-p3-engine-trace",
};

db.prepare("INSERT INTO users (id,email) VALUES ('usr','owner@example.com')").run();
for (const [id, name, deletedAt] of [
  ["ws-a", "Active A", null],
  ["ws-b", "Active B", null],
  ["ws-deleted", "Deleted", new Date(clockMs - DAY).toISOString()],
]) {
  db.prepare("INSERT INTO workspaces (id,name,deleted_at) VALUES (?,?,?)")
    .run(id, name, deletedAt);
}
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom','usr','example.com')").run();
for (const workspaceId of ["ws-a", "ws-b", "ws-deleted"]) {
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,'dom')")
    .run(workspaceId);
}

async function runTraceScan(scanId, phase) {
  scanPhase = phase;
  db.prepare(`INSERT INTO scans
    (id,workspace_id,domain_id,domain,status,scan_quality,created_at)
    VALUES (?,'ws-a','dom','example.com','running',NULL,?)`)
    .run(scanId, new Date(clockMs + (phase * 1000)).toISOString());
  let error = null;
  try {
    await runScanEngine(
      scanId,
      "dom",
      "ws-a",
      "example.com",
      env,
      {
        now: () => clockMs + (phase * 1000),
        executionContext: "queue",
        trigger: "manual",
      }
    );
  } catch (caught) {
    error = caught;
  }
  eq(`${scanId}: real runScanEngine completes`, error, null);
  eq(
    `${scanId}: terminal status`,
    db.prepare("SELECT status FROM scans WHERE id=?").get(scanId)?.status,
    "completed"
  );
  return JSON.parse(store.get(`reports/${scanId}.json`) || "{}");
}

try {
  const firstReport = await runTraceScan("scan-item9-p3-1", 1);
  const firstLifecycle = db.prepare(
    "SELECT * FROM certificate_lifecycle WHERE workspace_id='ws-a'"
  ).get();
  ok("scan 1 creates the existing canonical lifecycle", Boolean(firstLifecycle?.id));
  eq("scan 1 enters the critical renewal band", firstLifecycle?.renewal_readiness, "critical");
  ok("scan 1 opens one canonical certificate case", Boolean(firstLifecycle?.linked_case_id));
  eq(
    "scan 1 creates one case only",
    db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws-a' AND case_type='certificate_case'").get().n,
    1
  );
  eq(
    "scan 1 CT leaf remains unknown",
    firstReport.modules?.certificate_intelligence?.signal_completeness?.signals?.leaf?.observation,
    "unknown"
  );

  // Ensure the second persistence timestamp sorts after the first even on a very
  // fast CI runner while preserving production's real upsert/correlation path.
  db.prepare(`UPDATE certificate_observations
              SET last_seen=?
              WHERE workspace_id IN ('ws-a','ws-b')`)
    .run(new Date(clockMs - 10_000).toISOString());

  const secondReport = await runTraceScan("scan-item9-p3-2", 2);
  const secondLifecycle = db.prepare(
    "SELECT * FROM certificate_lifecycle WHERE workspace_id='ws-a'"
  ).get();
  ok(
    "scan 2 changes the lifecycle identity",
    secondLifecycle?.certificate_identity !== firstLifecycle?.certificate_identity
  );
  eq("scan 2 moves to monitoring band", secondLifecycle?.renewal_readiness, "monitoring");
  eq("scan 2 records one replaced relationship", db.prepare(
    "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='replaced'"
  ).get(secondLifecycle.id).n, 1);
  eq("scan 2 records one renewed event", db.prepare(
    "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='renewed'"
  ).get(secondLifecycle.id).n, 1);
  eq("scan 2 records one issuer change", db.prepare(
    "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='issuer_changed'"
  ).get(secondLifecycle.id).n, 1);
  eq("scan 2 records one SAN change", db.prepare(
    "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='san_changed'"
  ).get(secondLifecycle.id).n, 1);
  eq(
    "scan 2 keeps the old observation row",
    db.prepare("SELECT COUNT(*) AS n FROM certificate_observations WHERE workspace_id='ws-a'").get().n,
    2
  );
  const relationJson = db.prepare(
    "SELECT detail_json FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='replaced'"
  ).get(secondLifecycle.id).detail_json;
  const relation = JSON.parse(relationJson);
  ok("relationship names previous observation", Boolean(relation.previous_observation_id));
  ok("relationship names current observation", Boolean(relation.current_observation_id));

  eq(
    "CT-only replacement is not product-verified",
    secondLifecycle.verification_status,
    "not_verified"
  );
  eq(
    "CT-only replacement cannot close the case",
    db.prepare("SELECT status FROM managed_cases WHERE id=?").get(secondLifecycle.linked_case_id).status,
    "detected"
  );
  eq(
    "scan 2 still refuses a live leaf claim",
    secondReport.modules?.certificate_intelligence?.signal_completeness?.signals?.leaf?.observation,
    "unknown"
  );
  eq(
    "historical/CT multiplicity still refuses parallel_certificate_set",
    secondReport.modules?.certificate_intelligence?.signal_completeness
      ?.signals?.parallel_certificate_set?.observation,
    "unknown"
  );

  const lifecycleEventsBeforeThird = db.prepare(
    "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=?"
  ).get(secondLifecycle.id).n;
  const caseEventsBeforeThird = db.prepare(
    "SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?"
  ).get(secondLifecycle.linked_case_id).n;
  const relationshipBeforeThird = relationJson;

  const thirdReport = await runTraceScan("scan-item9-p3-3", 3);
  eq(
    "scan 3 unchanged replacement emits no duplicate lifecycle event",
    db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=?").get(secondLifecycle.id).n,
    lifecycleEventsBeforeThird
  );
  eq(
    "scan 3 unchanged active recurrence emits no duplicate case event",
    db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(secondLifecycle.linked_case_id).n,
    caseEventsBeforeThird
  );
  eq(
    "scan 3 preserves replacement history byte-for-byte",
    db.prepare("SELECT detail_json FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='replaced'").get(secondLifecycle.id).detail_json,
    relationshipBeforeThird
  );
  eq(
    "scan 3 still does not turn CT re-observation into live verification",
    db.prepare("SELECT verification_status FROM certificate_lifecycle WHERE id=?").get(secondLifecycle.id).verification_status,
    "not_verified"
  );
  eq(
    "scan 3 still has one case",
    db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws-a' AND case_type='certificate_case'").get().n,
    1
  );
  eq(
    "scan 3 CT signal remains scoped to issuance",
    thirdReport.modules?.certificate_intelligence?.signal_completeness?.signals?.expiry?.observation_scope,
    "ct_issuance"
  );

  eq("one shared crt.sh lookup per real scan", providerCalls.crt_sh, 3);
  eq("one shared CertSpotter fallback per real scan", providerCalls.certspotter, 3);
  ok("real engine exercised network edges", outboundCalls > 0);

  for (const report of [firstReport, secondReport, thirdReport]) {
    const diagnostic = (report.execution_diagnostics?.modules || [])
      .find((entry) => entry.module === "ssl");
    eq("trace preserves 19-second executable budget", report.execution_diagnostics?.deadline_budget_ms, 19_000);
    eq("trace preserves 9-second SSL cap", diagnostic?.allocated_ms, 9_000);
    ok(
      "trace preserves six-subrequest SSL ceiling",
      Number(diagnostic?.outbound_attempts_observed) <= 6,
      `attempts ${diagnostic?.outbound_attempts_observed}`
    );
  }

  eq(
    "soft-deleted workspace receives no observation",
    db.prepare("SELECT COUNT(*) AS n FROM certificate_observations WHERE workspace_id='ws-deleted'").get().n,
    0
  );
  eq(
    "soft-deleted workspace receives no lifecycle",
    db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle WHERE workspace_id='ws-deleted'").get().n,
    0
  );
  eq(
    "second active tenant receives its own append-only history",
    db.prepare("SELECT COUNT(*) AS n FROM certificate_observations WHERE workspace_id='ws-b'").get().n,
    2
  );
  eq(
    "workspace fan-out does not cross-link cases",
    db.prepare(`SELECT COUNT(*) AS n FROM certificate_lifecycle cl
                JOIN managed_cases mc ON mc.id=cl.linked_case_id
                WHERE cl.workspace_id != mc.workspace_id`).get().n,
    0
  );
} finally {
  globalThis.fetch = realFetch;
  Math.random = realRandom;
  db.close();
}

console.log(`\nItem 9 P3 runScanEngine trace: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P3 runScanEngine trace passed");
process.exit(fail ? 1 : 0);
