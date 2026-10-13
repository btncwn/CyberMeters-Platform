#!/usr/bin/env node
// Item 10 P2 — real multi-scan runScanEngine → D1 lifecycle/event trace.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { runScanEngine } = await import(pathToFileURL(path.join(
  root, "workers/scan-api/src/engines/scan-engine.js",
)).href);
const NOW = "2026-07-27T00:00:00.000Z";

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, actual, expected) =>
  ok(name, actual === expected,
    `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent migrations */ }
  };
  apply(path.join(root, "database/schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database/migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database/migrations", file));
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
        /^\s*(?:select|with)\b/i.test(entry.__sql) ? entry.all() : entry.run())),
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

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

const db = buildDb();
const reports = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: makeR2(reports),
  SCAN_CAPACITY_MODE: "legacy",
  SCAN_SUBREQUEST_LIMIT: "200",
  SCAN_DEADLINE_MS: "19000",
  APP_VERSION: "item10-p2-engine-trace",
};

db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')").run();
for (const [id, name, deletedAt] of [
  ["ws", "Active", null],
  ["ws-deleted", "Deleted", "2026-07-01T00:00:00.000Z"],
  ["ws-foreign", "Foreign", null],
]) {
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES (?,?,?)")
    .run(id, name, deletedAt);
}
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom-foreign','usr','foreign.test')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-deleted','dom')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-foreign','dom-foreign')").run();
db.prepare(`
  INSERT INTO workspace_assets
    (id, workspace_id, domain_id, hostname, asset_type, source,
     first_seen, last_seen, status, wildcard_dns, created_at, updated_at,
     lifecycle_state, last_observation_state)
  VALUES
    ('asset-gone','ws','dom','gone.example.com','subdomain','dns_bruteforce',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z',
     'observed','observed'),
    ('asset-deleted','ws-deleted','dom','gone.example.com','subdomain','dns_bruteforce',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z',
     'observed','observed'),
    ('asset-foreign','ws-foreign','dom-foreign','gone.example.com','subdomain','dns_bruteforce',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','inactive',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z',
     'not_assessed','not_assessed')
`).run();

let phase = "negative";
const contactedHosts = new Set();
let goneHostHttpCalls = 0;
const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  contactedHosts.add(url.hostname);
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "gone.example.com") {
      if (phase === "unavailable") throw new DOMException("provider timeout", "TimeoutError");
      if (phase === "observed") {
        return json({ Status: 0, Answer: type === "A" ? [{ type: 1, data: "93.184.216.34" }] : [] });
      }
      return json({ Status: 3, Answer: [] });
    }
    if (type === "A") {
      return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    return json({ Status: 0, Answer: [] });
  }
  if (url.hostname === "gone.example.com") {
    goneHostHttpCalls += 1;
    if (phase === "unavailable") {
      throw new DOMException("probe timeout", "TimeoutError");
    }
    if (phase === "negative") {
      throw new TypeError("connection refused");
    }
  }
  return new Response("<html><title>Trace</title></html>", {
    status: 200,
    headers: { "content-type": "text/html", server: "item10-fixture" },
  });
};
Math.random = () => 0.23456789;

async function run(scanId, when, mode) {
  phase = mode;
  db.prepare(`
    INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
    VALUES (?, 'ws', 'dom', 'example.com', 'pending', NULL, ?)
  `).run(scanId, when);
  let error = null;
  try {
    await runScanEngine(scanId, "dom", "ws", "example.com", env, {
      now: () => Date.parse(when),
      executionContext: "queue",
      trigger: "manual",
    });
  } catch (caught) {
    error = caught;
  }
  eq(`${scanId} real engine completes`, error, null);
  eq(`${scanId} terminal scan status`,
    db.prepare("SELECT status FROM scans WHERE id=?").get(scanId)?.status,
    "completed");
  const report = JSON.parse(reports.get(`reports/${scanId}.json`) || "{}");
  eq(`${scanId} report attaches the seven-signal model`,
    report.modules?.attack_surface_signal_completeness?.model_version,
    "attack-surface-signal-completeness-v4");
  eq(`${scanId} report retains all seven independent signals`,
    Object.keys(report.modules?.attack_surface_signal_completeness?.signals || {}).length,
    7);
  return report;
}

try {
  await run("scan-1", NOW, "negative");
  const firstObservation = db.prepare(
    "SELECT observation_state, dns_state, http_state FROM asset_lifecycle_observations WHERE asset_id='asset-gone' AND scan_id='scan-1'",
  ).get();
  eq("real complete fixture records authoritative DNS absence",
    firstObservation?.dns_state, "absent");
  eq("DNS preflight without a terminal leaves HTTP unassessed",
    firstObservation?.http_state, "not_assessed");
  eq("DNS preflight does not issue a target HTTP request", goneHostHttpCalls, 0);
  eq("DNS absence alone cannot mark the asset removed",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "observed");
  eq("one real scan emits no removal event",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen'").get().n, 0);

  await run("scan-timeout", "2026-07-28T00:00:00.000Z", "unavailable");
  eq("real provider timeout persists unavailable",
    db.prepare("SELECT last_observation_state FROM workspace_assets WHERE id='asset-gone'").get().last_observation_state,
    "observation_unavailable");
  eq("provider timeout does not advance real threshold",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-gone' AND qualifies_removal=1").get().n,
    0);

  await run("scan-2", "2026-07-29T00:00:00.000Z", "negative");
  await run("scan-3", "2026-07-30T00:00:00.000Z", "negative");
  eq("three DNS-only negatives cannot confirm removal without HTTP evidence",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "observed");
  eq("unassessed HTTP never emits a removal event",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen' AND asset_id='asset-gone'").get().n,
    0);
  eq("DNS-only sequence has no target HTTP request", goneHostHttpCalls, 0);

  await run("scan-4", "2026-07-31T00:00:00.000Z", "observed");
  eq("real active observation resets confirmation",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "observed");
  ok("public DNS permits a real HTTP observation", goneHostHttpCalls > 0);
  eq("an asset never confirmed removed has no false reappearance event",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_reappeared'").get().n,
    0);
  eq("real reappearance creates no new asset row",
    db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id='ws' AND hostname='gone.example.com'").get().n,
    1);
  eq("soft-deleted tenant receives no lifecycle write",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws-deleted'").get().n,
    0);
  eq("same-host foreign tenant remains isolated",
    db.prepare("SELECT status FROM workspace_assets WHERE id='asset-foreign'").get().status,
    "inactive");
  // Discovery is CyberMeters' own observation: every request goes to a DNS
  // resolver, a registration-data (RDAP) service, a vulnerability feed or a
  // host under the scanned domain — never to a third-party discovery service.
  const ownObservationHost = (host) =>
    ["cloudflare-dns.com", "dns.google", "dns.quad9.net"].includes(host) ||
    /^rdap\./.test(host) || host === "rdap.org" ||
    ["www.cisa.gov", "services.nvd.nist.gov", "raw.githubusercontent.com"].includes(host) ||
    host === "example.com" || host.endsWith(".example.com");
  ok("real trace discovers and rechecks hosts from its own observation only",
    contactedHosts.has("gone.example.com") && [...contactedHosts].every(ownObservationHost),
    JSON.stringify([...contactedHosts].sort()));
} finally {
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
}

console.log(`\nItem 10 P2 runScanEngine trace: ${passed}/${passed + failed} assertions passed`);
if (failed) process.exit(1);
console.log("Item 10 P2 runScanEngine trace passed");
