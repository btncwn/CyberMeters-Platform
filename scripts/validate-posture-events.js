#!/usr/bin/env node
//
// Posture-events regression: recordPostureEvents compares the previous R2 scan
// report with current in-memory modules and writes Exposure Timeline asset_events
// for email-auth and internet-exposed service changes. Uses a real in-memory
// SQLite schema (schema.sql + migrations) plus a small R2 stub. Requires Node
// 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { recordPostureEvents } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "posture-events.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeR2(report) {
  return {
    async get(key) {
      if (key !== "reports/scan_prev.json" || report == null) return null;
      return { json: async () => report };
    },
  };
}

function harness(prevReport) {
  const db = buildDb();
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: makeR2(prevReport),
  };
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("usr_1", "owner@example.co.uk");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom_1", "usr_1", "example.co.uk");
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run("ws_1", "Acme");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws_1", "dom_1");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?)").run("scan_prev", "dom_1", "example.co.uk", "completed", "ws_1", "2026-07-01T10:00:00.000Z");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?)").run("scan_current", "dom_1", "example.co.uk", "completed", "ws_1", "2026-07-02T10:00:00.000Z");
  db.prepare(
    `INSERT INTO workspace_assets
       (id, workspace_id, domain_id, hostname, asset_type, source,
        first_seen, last_seen, status, wildcard_dns, created_at, updated_at)
     VALUES ('asset_x', 'ws_1', 'dom_1', 'x.example.co.uk', 'exposed_service', 'exposure_probe',
             datetime('now','-1 day'), datetime('now','-1 day'), 'active', 0, datetime('now','-1 day'), datetime('now','-1 day'))`
  ).run();
  return { db, env };
}

async function record(env, modules) {
  await recordPostureEvents("scan_current", "dom_1", "example.co.uk", modules, env);
}

const report = (modules) => ({ domain: "example.co.uk", modules });
const email = ({ spfPresent = true, spfRecord = "v=spf1 include:example.net -all", dmarcPresent = true, dmarcPolicy = "none", dkimPresent = true } = {}) => ({
  spf: { present: spfPresent, record: spfRecord },
  dmarc: { present: dmarcPresent, policy: dmarcPolicy },
  dkim: { present: dkimPresent },
});
const service = (hostname, product, severity = "high") => ({ hostname, product, severity, risk_level: severity });
const modules = ({ email_security = email(), services = [] } = {}) => ({
  email_security,
  admin_surface_detection: { services },
});
const rows = (db) => db.prepare("SELECT event_type, hostname, severity, description FROM asset_events ORDER BY created_at, event_type").all();
const rowsFor = (db, eventType) => rows(db).filter((row) => row.event_type === eventType);

// 1. SPF present -> absent emits high-severity email_spf_changed.
{
  const { db, env } = harness(report(modules({ email_security: email({ spfPresent: true }) })));
  await record(env, modules({ email_security: email({ spfPresent: false, spfRecord: null }) }));
  const events = rowsFor(db, "email_spf_changed");
  ok("SPF present -> absent emits one event", events.length === 1);
  ok("SPF present -> absent severity is high", events[0]?.severity === "high");
  ok("SPF description is customer-safe", events[0]?.description === "SPF record changed for example.co.uk");
}

// 2. DMARC none -> reject is an improvement and emits low severity.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "none" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }));
  const events = rowsFor(db, "email_dmarc_policy_changed");
  ok("DMARC none -> reject emits one event", events.length === 1);
  ok("DMARC none -> reject severity is low", events[0]?.severity === "low");
  ok("DMARC none -> reject description includes old -> new", events[0]?.description === "DMARC policy changed: none → reject");
}

// 3. DMARC reject -> none is a regression and emits high severity.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "reject" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "none" }) }));
  const events = rowsFor(db, "email_dmarc_policy_changed");
  ok("DMARC reject -> none emits one event", events.length === 1);
  ok("DMARC reject -> none severity is high", events[0]?.severity === "high");
}

// 4. DKIM present -> absent emits medium severity.
{
  const { db, env } = harness(report(modules({ email_security: email({ dkimPresent: true }) })));
  await record(env, modules({ email_security: email({ dkimPresent: false }) }));
  const events = rowsFor(db, "email_dkim_changed");
  ok("DKIM present -> absent emits one event", events.length === 1);
  ok("DKIM present -> absent severity is medium", events[0]?.severity === "medium");
}

// 5. Admin-surface services are diffed by hostname + product.
{
  const prev = report(modules({ services: [service("old.example.co.uk", "Jenkins")] }));
  const { db, env } = harness(prev);
  await record(env, modules({ services: [service("x.example.co.uk", "Rundeck")] }));
  const detected = rowsFor(db, "exposed_service_detected");
  const resolved = rowsFor(db, "exposed_service_resolved");
  ok("new exposed service emits exposed_service_detected", detected.length === 1);
  ok("new exposed service description includes product and host", detected[0]?.description === "New internet-exposed service detected: Rundeck on x.example.co.uk");
  ok("missing previous service emits exposed_service_resolved", resolved.length === 1);
  ok("resolved service severity is low", resolved[0]?.severity === "low");
}

// 6. Previous scan row exists but R2 report is missing: no baseline, no events.
{
  const { db, env } = harness(null);
  await record(env, modules({ email_security: email({ spfPresent: false, spfRecord: null }) }));
  ok("missing previous R2 report emits no events", rows(db).length === 0);
}

// 7. No changes emit no events.
{
  const baseline = modules({ services: [service("x.example.co.uk", "Rundeck")] });
  const { db, env } = harness(report(baseline));
  await record(env, baseline);
  ok("unchanged email posture and services emit no events", rows(db).length === 0);
}

// 8. Dedupe: same event_type:hostname within 24h is suppressed on second run.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "none" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }));
  ok("second DMARC policy event within 24h is deduped", rowsFor(db, "email_dmarc_policy_changed").length === 1);
}

console.log(`\nPosture events: ${pass}/${pass + fail} passed`);
if (fail) { console.error("posture-events validation FAILED"); process.exit(1); }
console.log("posture-events validation passed");
