#!/usr/bin/env node
//
// Exposure-timeline regression: asset inventory emits DNS-level change events
// when an existing asset's IP, CNAME or redirect target changes between scans.
// Drives upsertAssetInventory against a real in-memory SQLite schema
// (schema.sql + migrations) via the same D1 adapter pattern used by the
// request-pipeline harness. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { upsertAssetInventory } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asset-inventory.js")).href);
const { buildAssetTimelineTrustMetadata } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "timeline-trust.js")).href);

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

function report() {
  return {
    scan_quality: { status: "complete" },
    timeline_trust: buildAssetTimelineTrustMetadata(),
    modules: {},
  };
}

function makeR2() {
  return {
    async get(key) {
      if (key !== "reports/scan_prev.json") return null;
      return { json: async () => report() };
    },
  };
}

function harness() {
  const db = buildDb();
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: makeR2() };
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("usr_1", "owner@example.co.uk");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom_1", "usr_1", "example.co.uk");
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run("ws_1", "Acme");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws_1", "dom_1");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("scan_prev", "dom_1", "example.co.uk", "completed", "complete", "ws_1", "2026-07-17T10:00:00.000Z");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("scan_1", "dom_1", "example.co.uk", "completed", "complete", "ws_1", "2026-07-18T10:00:00.000Z");
  return { db, env };
}

function seedAsset(db, { hostname = "www.example.co.uk", ip_addresses = null, cname = null, redirect_to = null } = {}) {
  db.prepare(
    `INSERT INTO workspace_assets
       (id, workspace_id, domain_id, hostname, asset_type, source,
        first_seen, last_seen, status, wildcard_dns,
        ip_addresses, cname, redirect_to, created_at, updated_at)
     VALUES (?, 'ws_1', 'dom_1', ?, 'subdomain', 'dns_bruteforce',
             datetime('now','-1 day'), datetime('now','-1 day'), 'active', 0,
             ?, ?, ?, datetime('now','-1 day'), datetime('now','-1 day'))`
  ).run(`asset_${hostname.replace(/[^a-z0-9]+/gi, "_")}`, hostname, ip_addresses, cname, redirect_to);
}

async function runInventory(env, modules) {
  await upsertAssetInventory("scan_1", "dom_1", "example.co.uk", {
    subdomains: { items: [], wildcard_dns: false },
    dns_bruteforce: { items: [] },
    asset_exposure: { assets: [] },
    ...modules,
  }, env, { currentReport: report() });
}

const rows = (db, eventType) => db.prepare("SELECT event_type, hostname, severity, description FROM asset_events WHERE event_type = ? ORDER BY created_at").all(eventType);

// 1. Existing asset IP changes: exactly one event with old -> new description.
{
  const { db, env } = harness();
  seedAsset(db, { ip_addresses: JSON.stringify(["1.1.1.1"]) });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["2.2.2.2"] }] },
  });
  const events = rows(db, "dns_ip_changed");
  ok("IP change emits exactly one dns_ip_changed event", events.length === 1);
  ok("IP change description contains old and new values", events[0]?.description === "IP address for www.example.co.uk changed: 1.1.1.1 → 2.2.2.2");
}

// 2. redirect_to null -> value is first-seen enrichment, not a change event.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "app.example.co.uk", cname: "old.vendor.example" });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "app.example.co.uk", cname: "new.vendor.example" }] },
  });
  const events = rows(db, "dns_cname_changed");
  ok("CNAME change emits exactly one dns_cname_changed event", events.length === 1);
  ok("CNAME change description contains old and new values", events[0]?.description === "CNAME for app.example.co.uk changed: old.vendor.example → new.vendor.example");
}

// 3. redirect_to null -> value is first-seen enrichment, not a change event.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "app.example.co.uk", redirect_to: null });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "app.example.co.uk", redirect_to: "https://external.example.net/path" }] },
  });
  ok("redirect null -> value does not emit dns_redirect_changed", rows(db, "dns_redirect_changed").length === 0);
}

// 4. redirect_to A -> external B emits high-severity redirect change.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "app.example.co.uk", redirect_to: "https://old.example.co.uk/start" });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "app.example.co.uk", redirect_to: "https://external.example.net/path" }] },
  });
  const events = rows(db, "dns_redirect_changed");
  ok("external redirect change emits one dns_redirect_changed event", events.length === 1);
  ok("external redirect change severity is high", events[0]?.severity === "high");
  ok("redirect description contains old and new values", events[0]?.description === "app.example.co.uk now redirects to https://external.example.net/path (was https://old.example.co.uk/start)");
}

// 5. Same IP on the next scan does not emit a change event.
{
  const { db, env } = harness();
  seedAsset(db, { ip_addresses: JSON.stringify(["1.1.1.1"]) });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["1.1.1.1"] }] },
  });
  ok("same IP emits no dns_ip_changed event", rows(db, "dns_ip_changed").length === 0);
}

// 6. Dedupe: a second IP change event for the same hostname within 24h is suppressed.
{
  const { db, env } = harness();
  seedAsset(db, { ip_addresses: JSON.stringify(["1.1.1.1"]) });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["2.2.2.2"] }] },
  });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["3.3.3.3"] }] },
  });
  ok("second IP change within 24h is deduped", rows(db, "dns_ip_changed").length === 1);
}

console.log(`\nExposure events: ${pass}/${pass + fail} passed`);
if (fail) { console.error("exposure-events validation FAILED"); process.exit(1); }
console.log("exposure-events validation passed");
