#!/usr/bin/env node
// Item 10 P2 — deterministic production lifecycle/persistence integration.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const lifecycleUrl = process.env.ITEM10_LIFECYCLE_MODULE_URL || pathToFileURL(path.join(
  root, "workers/scan-api/src/engines/attack-surface-lifecycle.js",
)).href;
const signalUrl = pathToFileURL(path.join(
  root, "workers/scan-api/src/engines/attack-surface-signal-completeness.js",
)).href;
const {
  loadKnownAssetRecheckHosts,
  persistAttackSurfaceLifecycle,
} = await import(lifecycleUrl);
const {
  ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
  ATTACK_SURFACE_SIGNAL_KEYS,
} = await import(signalUrl);
const NOW = "2026-07-27T00:00:00.000Z";

let passed = 0;
let failed = 0;
function ok(name, condition, detail = "") {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}
function eq(name, actual, expected) {
  ok(name, actual === expected,
    `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    PRAGMA foreign_keys = OFF;
    CREATE TABLE workspaces (
      id TEXT PRIMARY KEY,
      deleted_at TEXT
    );
    CREATE TABLE workspace_domains (
      workspace_id TEXT NOT NULL,
      domain_id TEXT NOT NULL
    );
    CREATE TABLE workspace_assets (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      domain_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'dns_bruteforce',
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
      updated_at TEXT,
      UNIQUE (workspace_id, hostname)
    );
    CREATE TABLE asset_events (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      domain_id TEXT NOT NULL,
      asset_id TEXT,
      scan_id TEXT,
      event_type TEXT NOT NULL,
      hostname TEXT NOT NULL,
      severity TEXT,
      description TEXT,
      created_at TEXT NOT NULL
    );
  `);
  db.exec(fs.readFileSync(path.join(
    root, "database/migrations/102-attack-surface-observation-lifecycle.sql",
  ), "utf8"));
  return db;
}

function makeD1(db, counters) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      if (/^\s*select/i.test(sql)) counters.reads += 1;
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => {
      if (/^\s*select/i.test(sql)) counters.reads += 1;
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => {
      counters.batches += 1;
      return Promise.all(statements.map((entry) =>
        /^\s*select/i.test(entry.__sql) ? entry.all() : entry.run()));
    },
  };
}

function signalCompleteness(subdomainState = "observed") {
  return {
    model_version: ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
    signals: Object.fromEntries(ATTACK_SURFACE_SIGNAL_KEYS.map((key) => [
      key,
      {
        state: key === "subdomain_discovery" ? subdomainState : "not_assessed",
        reason: key === "subdomain_discovery"
          ? "ct_identity_observed"
          : "fixture_not_assessed",
        evidence_count: key === "subdomain_discovery" ? 1 : 0,
        sources: key === "subdomain_discovery" ? ["crt_sh"] : [],
        limitations: [],
      },
    ])),
  };
}

const negative = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "absent", reason: "authoritative_a_aaaa_absence" },
    http_https_service: { state: "not_observed", reason: "connection_refused" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});
const unavailable = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "unavailable", reason: "provider_timeout" },
    http_https_service: { state: "unavailable", reason: "probe_timeout" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});
const observed = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "observed", reason: "a_record_observed" },
    http_https_service: { state: "observed", reason: "http_response_observed" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});

const db = buildDb();
db.exec(`
  INSERT INTO workspaces (id, deleted_at) VALUES
    ('ws-active', NULL),
    ('ws-deleted', '2026-07-01T00:00:00.000Z'),
    ('ws-foreign', NULL);
  INSERT INTO workspace_domains (workspace_id, domain_id) VALUES
    ('ws-active', 'dom'),
    ('ws-deleted', 'dom'),
    ('ws-foreign', 'dom-foreign');
  INSERT INTO workspace_assets
    (id, workspace_id, domain_id, hostname, status, updated_at)
  VALUES
    ('asset-stable', 'ws-active', 'dom', 'gone.example.com', 'active', '2026-07-01T00:00:00.000Z'),
    ('asset-extra-1', 'ws-active', 'dom', 'one.example.com', 'active', '2026-07-01T00:00:00.000Z'),
    ('asset-extra-2', 'ws-active', 'dom', 'two.example.com', 'active', '2026-07-01T00:00:00.000Z'),
    ('asset-root', 'ws-active', 'dom', 'example.com', 'active', '2026-07-01T00:00:00.000Z'),
    ('asset-deleted', 'ws-deleted', 'dom', 'gone.example.com', 'active', '2026-07-01T00:00:00.000Z'),
    ('asset-foreign', 'ws-foreign', 'dom-foreign', 'gone.example.com', 'inactive', '2026-07-01T00:00:00.000Z');
`);
const counters = { reads: 0, batches: 0 };
const env = { cybermeters_db: makeD1(db, counters) };

const known = await loadKnownAssetRecheckHosts(env, "dom", "example.com");
ok("known-host recheck is bounded and excludes root",
  known.includes("gone.example.com") && !known.includes("example.com"));
ok("soft-deleted tenant does not add a duplicate outbound target",
  known.filter((host) => host === "gone.example.com").length === 1);

async function persist(scanId, observedAt, rows, subdomainState = "observed") {
  const readsBefore = counters.reads;
  await persistAttackSurfaceLifecycle({
    env,
    scanId,
    domainId: "dom",
    domain: "example.com",
    signalCompleteness: signalCompleteness(subdomainState),
    assetExposure: { removal_observations: rows },
    observedAt,
  });
  // One workspace lookup plus one two-query batch, independent of asset count.
  eq(`${scanId} has no per-asset read query`, counters.reads - readsBefore, 3);
}

await persist("scan-1", NOW, [negative("gone.example.com")]);
let asset = db.prepare("SELECT * FROM workspace_assets WHERE id = 'asset-stable'").get();
eq("one complete negative is not_observed", asset.lifecycle_state, "not_observed");
eq("one complete negative never changes legacy status", asset.status, "active");
eq("one complete negative never emits removal",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen'").get().n, 0);

await persist("scan-timeout", "2026-07-28T00:00:00.000Z", [unavailable("gone.example.com")]);
eq("unavailable evidence is explicit",
  db.prepare("SELECT last_observation_state FROM workspace_assets WHERE id='asset-stable'").get().last_observation_state,
  "observation_unavailable");
eq("unavailable does not advance threshold",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-stable' AND qualifies_removal=1").get().n, 1);
await persist("scan-timeout", "2026-07-28T00:00:00.000Z", [unavailable("gone.example.com")]);
eq("unavailable rerun is idempotent",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-stable' AND scan_id='scan-timeout'").get().n, 1);

// CT/passive identity is globally observed but no active recheck completed.
await persist("scan-ct-only", "2026-07-29T00:00:00.000Z", []);
eq("CT-only observation does not advance threshold",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-stable' AND qualifies_removal=1").get().n, 1);

await persist("scan-2", "2026-07-30T00:00:00.000Z", [negative("gone.example.com")]);
eq("second spaced negative remains not_observed",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-stable'").get().lifecycle_state,
  "not_observed");
await persist("scan-3", "2026-07-31T00:00:00.000Z", [negative("gone.example.com")]);
asset = db.prepare("SELECT * FROM workspace_assets WHERE id = 'asset-stable'").get();
eq("third qualifying observation confirms removal", asset.lifecycle_state, "confirmed_removed");
eq("confirmed removal is separately projected to legacy inactive", asset.status, "inactive");
eq("exactly one existing lifecycle event is emitted",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen'").get().n, 1);

await persist("scan-3", "2026-07-31T00:00:00.000Z", [negative("gone.example.com")]);
eq("same scan is idempotent for lifecycle observations",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-stable' AND scan_id='scan-3'").get().n, 1);
eq("same scan is idempotent for removal events",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen'").get().n, 1);

await persist("scan-4", "2026-08-01T00:00:00.000Z", [observed("gone.example.com")]);
asset = db.prepare("SELECT * FROM workspace_assets WHERE id = 'asset-stable'").get();
eq("observed asset resets lifecycle", asset.lifecycle_state, "observed");
eq("reappearance retains the same asset identity", asset.id, "asset-stable");
eq("reappearance creates no replacement row",
  db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id='ws-active' AND hostname='gone.example.com'").get().n, 1);
eq("confirmed-removed to observed emits existing reappeared event",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_reappeared'").get().n, 1);
eq("observed reset clears qualifying progress for subsequent reconstruction",
  db.prepare(`
    SELECT COUNT(*) AS n
    FROM asset_lifecycle_observations
    WHERE asset_id='asset-stable'
      AND qualifies_removal=1
      AND observed_at > '2026-08-01T00:00:00.000Z'
  `).get().n, 0);

eq("all nine per-signal rows persist for each active scan",
  db.prepare("SELECT COUNT(*) AS n FROM attack_surface_signal_observations WHERE workspace_id='ws-active'").get().n,
  6 * 9);
eq("soft-deleted workspace receives no signal observations",
  db.prepare("SELECT COUNT(*) AS n FROM attack_surface_signal_observations WHERE workspace_id='ws-deleted'").get().n, 0);
eq("soft-deleted workspace receives no lifecycle observations",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws-deleted'").get().n, 0);
eq("foreign tenant row remains untouched",
  db.prepare("SELECT status FROM workspace_assets WHERE id='asset-foreign'").get().status, "inactive");
eq("root identity never enters removal confirmation",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-root'").get().lifecycle_state,
  "not_assessed");

const indexSource = fs.readFileSync(path.join(root, "workers/scan-api/src/index.js"), "utf8");
ok("purge removes lifecycle children before workspace_assets",
  indexSource.indexOf('"attack_surface_signal_observations"') <
  indexSource.indexOf('"workspace_assets"') &&
  indexSource.indexOf('"asset_lifecycle_observations"') <
  indexSource.indexOf('"workspace_assets"'));
const lifecycleSource = fs.readFileSync(path.join(
  root, "workers/scan-api/src/engines/attack-surface-lifecycle.js",
), "utf8");
ok("history reconstruction is bounded per asset without N+1 reads",
  /ROW_NUMBER\(\) OVER \(\s*PARTITION BY alo\.asset_id/.test(lifecycleSource) &&
  /WHERE recency_rank <= 4/.test(lifecycleSource));

console.log(`\nItem 10 P2 integration: ${passed}/${passed + failed} assertions passed`);
if (failed) process.exit(1);
console.log("Item 10 P2 integration validation passed");
