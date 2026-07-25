#!/usr/bin/env node
// Item 7 P5 — faithful runScanEngine alert/case-verification trace.
//
// Runs the real production engine through baseline, weakening, later fix and
// stable repeat observations. Providers are deterministic fixtures, but the
// scan orchestrator, DMARC production resolver, immutable snapshots, P4 writer,
// canonical alert pipeline and P5 case verifier are not stubbed.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (name) => pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", name,
)).href;
const { runScanEngine } = await import(enginePath("scan-engine.js"));
const { createDmarcPolicyCase } =
  await import(enginePath("dmarcbis-managed-lifecycle.js"));
const { readScanReportSnapshot } =
  await import(enginePath("report-snapshot.js"));
const { buildExecutiveReportV2 } =
  await import(enginePath("executive-report.js"));
const { buildScanReportPdf } =
  await import(enginePath("pdf.js"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) {
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  ok(name, got === want,
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

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
    all: async () => ({
      results: db.prepare(sql).all(...args),
      success: true,
      meta: {},
    }),
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

let requestedPolicy = "reject";
let outbound = 0;
globalThis.fetch = async (input) => {
  outbound += 1;
  const url = new URL(String(input));
  if (
    url.hostname === "cloudflare-dns.com" ||
    url.hostname === "dns.google"
  ) {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "_dmarc.example.com" && type === "TXT") {
      return new Response(JSON.stringify({
        Status: 0,
        Answer: [{
          type: 16,
          data: `v=DMARC1; p=${requestedPolicy}; psd=n`,
        }],
      }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    if (name === "example.com" && type === "A") {
      return new Response(JSON.stringify({
        Status: 0,
        Answer: [{ type: 1, data: "93.184.216.34" }],
      }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
      status: 200,
      headers: { "content-type": "application/dns-json" },
    });
  }
  if (url.hostname === "crt.sh") {
    return new Response("[]", {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  if (url.hostname === "api.certspotter.com") {
    return new Response("[]", {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response("<html><title>Example</title></html>", {
    status: 200,
    headers: {
      "content-type": "text/html",
      server: "fixture",
    },
  });
};

const db = buildDb();
const store = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: makeR2(store),
  SCAN_CAPACITY_MODE: "legacy",
  SCAN_SUBREQUEST_LIMIT: "200",
  APP_VERSION: "p5-engine-trace",
  RESEND_API_KEY: "",
};

db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')")
  .run();
db.prepare("INSERT INTO workspaces (id, name) VALUES ('ws', 'Trace')")
  .run();
db.prepare(
  "INSERT INTO domains (id, user_id, domain) VALUES ('dom', 'usr', 'example.com')",
).run();
db.prepare(
  "INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws', 'dom')",
).run();

function seedScan(id, at) {
  db.prepare(
    `INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
     VALUES (?, 'ws', 'dom', 'example.com', 'running', NULL, ?)`,
  ).run(id, at);
}

async function run(id, at) {
  seedScan(id, at);
  let error = null;
  try {
    await runScanEngine(id, "dom", "ws", "example.com", env);
  } catch (caught) {
    error = caught;
  }
  eq(`${id} real runScanEngine completes`, error, null);
  eq(`${id} terminal state is completed`,
    db.prepare("SELECT status FROM scans WHERE id = ?").get(id)?.status,
    "completed");
  eq(`${id} writes one canonical snapshot`,
    db.prepare(
      `SELECT COUNT(*) AS n FROM scan_report_snapshots
       WHERE scan_id = ? AND status = 'completed'`,
    ).get(id).n, 1);
}

function dmarcRiskAlertCount() {
  return db.prepare(
    `SELECT COUNT(*) AS n FROM notification_events
     WHERE workspace_id = 'ws' AND domain_key = 'email_protection'
       AND (
         metadata_json LIKE '%"recurrence_type":"record_removed"%'
         OR metadata_json LIKE '%"recurrence_type":"record_became_malformed"%'
         OR metadata_json LIKE '%"recurrence_type":"multiple_records_detected"%'
         OR metadata_json LIKE '%"recurrence_type":"enforcement_weakened"%'
         OR metadata_json LIKE '%"recurrence_type":"external_rua_unauthorised"%'
       )`,
  ).get().n;
}

await run("scan-p5-before", "2026-07-25T13:00:00.000Z");
eq("baseline creates no actionable DMARC occurrence",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws' AND record_type = 'dmarc_policy_condition'
       AND event_type = 'monitoring_changed'`,
  ).get().n, 0);

requestedPolicy = "none";
await run("scan-p5-weakened", "2026-07-25T14:00:00.000Z");
const occurrence = db.prepare(
  `SELECT e.id, e.record_id, e.created_at, e.detail_json
   FROM email_protection_events e
   WHERE e.workspace_id = 'ws'
     AND e.record_type = 'dmarc_policy_condition'
     AND e.event_type = 'monitoring_changed'
   ORDER BY e.rowid DESC LIMIT 1`,
).get();
ok("weakened scan appends one stable occurrence", !!occurrence);
const occurrenceDetail = JSON.parse(occurrence?.detail_json || "{}");
eq("real occurrence is requested-policy weakening",
  occurrenceDetail.subtype, "enforcement_weakened");
eq("real occurrence references current scan",
  occurrenceDetail.after_scan_id, "scan-p5-weakened");
eq("real engine emits one canonical risk alert",
  db.prepare(
    `SELECT COUNT(*) AS n FROM notification_events
     WHERE workspace_id = 'ws'
       AND metadata_json LIKE '%enforcement_weakened%'`,
  ).get().n, 1);
eq("risk alert does not auto-open a case",
  db.prepare(
    "SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id = 'ws'",
  ).get().n, 0);
const weakenedSnapshotRow = db.prepare(
  `SELECT scan_quality, assessed_at, r2_key
   FROM scan_report_snapshots
   WHERE scan_id = 'scan-p5-weakened'`,
).get();
eq("weakened engine fixture is whole-scan complete",
  weakenedSnapshotRow?.scan_quality, "complete");

const opened = await createDmarcPolicyCase(env, {
  workspace_id: "ws",
  record_id: occurrence.record_id,
  actor: { actor_type: "customer", actor_id: "usr" },
});
eq("explicit customer action creates one manual case", opened.ok, true);
eq("manual case is newly created", opened.created, true);
eq("manual case uses canonical remediation",
  opened.case?.remediation_id, "email.dmarc.enforce");
eq("manual case refusal code is absent", opened.code, undefined);
eq("manual case link is non-occurrence history",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws' AND record_id = ?
       AND event_type = 'case_linked'`,
  ).get(occurrence.record_id).n, 1);

if (!opened.case) {
  const reportBody = JSON.parse(
    store.get("reports/scan-p5-weakened.json") || "{}",
  );
  console.error("P5 trace scan quality detail",
    JSON.stringify(reportBody.scan_quality || null));
  console.log(`\nDMARCbis P5 runScanEngine trace: ${pass} passed, ${fail} failed`);
  db.close();
  process.exit(1);
}
db.prepare(
  `UPDATE managed_cases
   SET status = 'awaiting_verification',
       awaiting_verification_at = ?, updated_at = ?
   WHERE id = ?`,
).run(
  weakenedSnapshotRow.assessed_at,
  weakenedSnapshotRow.assessed_at,
  opened.case?.id,
);

requestedPolicy = "reject";
await run("scan-p5-fixed", "2026-07-25T15:00:00.000Z");
const afterFix = db.prepare(
  "SELECT * FROM managed_cases WHERE id = ?",
).get(opened.case?.id);
eq("later complete real scan verifies absent weak condition",
  afterFix.status, "verified");
ok("later complete scan stamps verified_at", !!afterFix.verified_at);
const verifiedEvent = db.prepare(
  `SELECT * FROM managed_case_events
   WHERE case_id = ? AND to_status = 'verified'
   ORDER BY rowid DESC LIMIT 1`,
).get(opened.case?.id);
eq("real-engine verification is a system transition",
  verifiedEvent?.actor_type, "system");
const verifiedDetail = JSON.parse(verifiedEvent?.detail_json || "{}");
eq("real-engine verification cites exact current scan",
  verifiedDetail.evidence?.evidence_reference?.scan_id,
  "scan-p5-fixed");
eq("strengthening creates no new risk alert",
  dmarcRiskAlertCount(), 1);

await run("scan-p5-stable", "2026-07-25T16:00:00.000Z");
eq("stable repeat creates no duplicate risk alert",
  dmarcRiskAlertCount(), 1);
eq("stable repeat creates no duplicate case",
  db.prepare(
    "SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id = 'ws'",
  ).get().n, 1);
eq("stable repeat creates no duplicate verification event",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_case_events
     WHERE case_id = ? AND to_status = 'verified'`,
  ).get(opened.case?.id).n, 1);
ok("faithful trace exercised real outbound provider paths", outbound > 0);

// P6 presentation proof over the exact immutable evidence produced by the real
// final run above. No renderer receives or re-runs the resolver.
const p6Read = await readScanReportSnapshot(env, "scan-p5-stable", {
  repair: false,
  allowReconstruction: false,
  includeSuccessor: false,
});
eq("P6 faithful trace reads the canonical snapshot", p6Read.status, "ok");
eq("P6 faithful trace reads current DMARCbis evidence",
  p6Read.dmarcPolicy?.status, "current");
const p6Executive = buildExecutiveReportV2({
  scan: {
    id: "scan-p5-stable",
    domain_id: "dom",
    domain: "example.com",
  },
  workspace: { id: "ws", name: "Trace" },
  read: p6Read,
});
eq("P6 Executive Report uses backend-owned presentation",
  p6Executive.dmarc_policy_presentation?.status, "current");
eq("P6 Executive Report preserves the real requested policy",
  p6Executive.dmarc_policy_presentation?.policy?.effective_requested,
  "reject");
eq("P6 Executive Report never claims receiver enforcement",
  p6Executive.dmarc_policy_presentation?.policy
    ?.receiver_enforcement_observed, false);
const p6Pdf = new TextDecoder().decode(buildScanReportPdf(
  { id: "scan-p5-stable", domain: "example.com" },
  p6Read,
));
ok("P6 PDF renders real runScanEngine DMARC evidence",
  p6Pdf.includes("DMARC Policy Evidence") &&
  p6Pdf.includes("Rejection requested"));
ok("P6 PDF renders the real technical appendix",
  p6Pdf.includes("Technical Appendix - DMARC Policy") &&
  p6Pdf.includes("rfc9989-treewalk-v1"));
if (!fail) console.log("P6 faithful customer projection passed");

console.log(`\nDMARCbis P5 runScanEngine trace: ${pass} passed, ${fail} failed`);
if (!fail) console.log("DMARCbis P5 runScanEngine trace passed");
db.close();
process.exit(fail ? 1 : 0);
