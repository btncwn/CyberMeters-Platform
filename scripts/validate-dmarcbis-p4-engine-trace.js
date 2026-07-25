#!/usr/bin/env node
// Item 7 P4 — faithful two-scan runScanEngine lifecycle trace.
//
// Runs the real production engine twice against in-memory D1/R2 and mocked
// providers. The first complete DMARCbis scan establishes a baseline; the
// second weakens the requested policy and must append one immutable migration-
// 088 occurrence only after its canonical snapshot is durable.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { runScanEngine } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "scan-engine.js",
)).href);

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
  APP_VERSION: "p4-engine-trace",
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

seedScan("scan-p4-before", "2026-07-25T13:00:00.000Z");
let firstError = null;
try {
  await runScanEngine(
    "scan-p4-before",
    "dom",
    "ws",
    "example.com",
    env,
  );
} catch (error) {
  firstError = error;
}
eq("first real runScanEngine trace completes", firstError, null);
eq("first scan terminal state is completed",
  db.prepare("SELECT status FROM scans WHERE id = 'scan-p4-before'")
    .get()?.status, "completed");
eq("first scan writes one canonical snapshot",
  db.prepare(
    `SELECT COUNT(*) AS n FROM scan_report_snapshots
     WHERE scan_id = 'scan-p4-before' AND status = 'completed'`,
  ).get().n, 1);
eq("first scan creates no actionable DMARC occurrence",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws' AND record_type = 'dmarc_policy_condition'
       AND event_type = 'monitoring_changed'`,
  ).get().n, 0);

requestedPolicy = "none";
seedScan("scan-p4-after", "2026-07-25T14:00:00.000Z");
let secondError = null;
try {
  await runScanEngine(
    "scan-p4-after",
    "dom",
    "ws",
    "example.com",
    env,
  );
} catch (error) {
  secondError = error;
}
eq("second real runScanEngine trace completes", secondError, null);
eq("second scan terminal state is completed",
  db.prepare("SELECT status FROM scans WHERE id = 'scan-p4-after'")
    .get()?.status, "completed");

const occurrence = db.prepare(
  `SELECT e.id, e.created_at, e.detail_json, s.id AS snapshot_id
   FROM email_protection_events e
   JOIN scan_report_snapshots s
     ON s.scan_id = 'scan-p4-after' AND s.status = 'completed'
   WHERE e.workspace_id = 'ws'
     AND e.record_type = 'dmarc_policy_condition'
     AND e.event_type = 'monitoring_changed'`,
).get();
ok("second scan appends one DMARC occurrence", !!occurrence);
const detail = occurrence ? JSON.parse(occurrence.detail_json) : {};
eq("real engine occurrence is requested-policy weakening",
  detail.subtype, "enforcement_weakened");
eq("real engine occurrence references current durable snapshot",
  detail.after_snapshot_id, occurrence?.snapshot_id);
eq("real engine occurrence references current scan",
  detail.after_scan_id, "scan-p4-after");
ok("real engine occurrence has both immutable fingerprints",
  /^[a-f0-9]{64}$/.test(detail.before_evidence_fingerprint || "") &&
  /^[a-f0-9]{64}$/.test(detail.after_evidence_fingerprint || ""));
eq("real engine path created no P4 DMARC occurrence alert",
  db.prepare(
    `SELECT COUNT(*) AS n FROM notification_events
     WHERE metadata_json LIKE '%enforcement_weakened%'
        OR dedupe_key LIKE '%enforcement_weakened%'`,
  ).get().n, 0);
eq("real engine path delivered no P4 DMARC occurrence alert",
  db.prepare(
    `SELECT COUNT(*) AS n FROM alert_deliveries
     WHERE alert_kind = 'enforcement_weakened'
        OR dedupe_key LIKE '%enforcement_weakened%'`,
  ).get().n, 0);
eq("real engine path created no managed case",
  db.prepare("SELECT COUNT(*) AS n FROM managed_cases").get().n, 0);
ok("faithful trace exercised real outbound provider paths", outbound > 0);

console.log(`\nDMARCbis P4 runScanEngine trace: ${pass} passed, ${fail} failed`);
if (!fail) console.log("DMARCbis P4 runScanEngine trace passed");
db.close();
process.exit(fail ? 1 : 0);
