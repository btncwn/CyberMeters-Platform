#!/usr/bin/env node
// Item 10 P3 — faithful runScanEngine → persistence → lifecycle → ASM case trace.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
// Frozen base clock: every engine invocation below receives an explicit
// deterministic offset from this trace epoch; wall-clock time is never used.
const NOW = "2026-07-27T00:00:00.000Z";
const engine = (name) => pathToFileURL(path.join(
  root, "workers/scan-api/src/engines", name,
)).href;
const { runScanEngine } = await import(engine("scan-engine.js"));
const {
  assignManagedCaseOwner,
  createManagedAsmCasesForScan,
  getManagedCase,
  transitionManagedCase,
} = await import(engine("asm-cases.js"));
const {
  SCAN_DEADLINE_DEFAULTS,
  SCAN_DURABLE_INVOCATION_DEADLINE_DEFAULTS,
} = await import(engine("scan-budget.js"));

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
  SCAN_DEADLINE_MS: "115000",
  APP_VERSION: "item10-p3-engine-trace",
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
    ('asset-gone','ws','dom','gone.example.com','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z',
     'observed','observed'),
    ('asset-deleted','ws-deleted','dom','gone.example.com','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z',
     'observed','observed'),
    ('asset-foreign','ws-foreign','dom-foreign','gone.foreign.test','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','inactive',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z',
     'not_assessed','not_assessed')
`).run();

const finding = {
  id: "asset_exposure_sensitive_tool",
  module: "asset_exposure",
  title: "Sensitive management tool exposed",
  description: "Grafana is reachable from the public internet.",
  severity: "high",
  affected_hosts: ["gone.example.com"],
};
await createManagedAsmCasesForScan(
  "scan-seed", "dom", "example.com", [finding], [], env,
);
let kase = db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws'").get();
let transition = await transitionManagedCase(env, kase, "triage", {
  actor_type: "customer",
  actor_id: "usr",
});
kase = transition.case;
transition = await assignManagedCaseOwner(env, kase, {
  owner_type: "person",
  owner_ref: "Security owner",
  assigned_by: "customer",
  actor_id: "usr",
});
kase = transition.case;
transition = await transitionManagedCase(env, kase, "remediation_in_progress", {
  actor_type: "customer",
  actor_id: "usr",
});
kase = transition.case;
transition = await transitionManagedCase(env, kase, "verification_requested", {
  actor_type: "customer",
  actor_id: "usr",
});
kase = transition.case;
eq("real trace case begins awaiting verification", kase.status, "verification_requested");
const originalCaseId = kase.id;

let phase = "negative";
const providerCalls = { crt: 0, certspotter: 0 };
const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (
    url.hostname === "www.cisa.gov" &&
    url.pathname.endsWith("known_exploited_vulnerabilities.json")
  ) {
    return json({
      title: "CISA Known Exploited Vulnerabilities Catalog",
      catalogVersion: "fixture",
      dateReleased: "2026-07-29T00:00:00.000Z",
      count: 0,
      vulnerabilities: [],
    });
  }
  if (url.hostname === "crt.sh") {
    providerCalls.crt += 1;
    return json([
      { name_value: "example.com\nwww.example.com\ngone.example.com" },
    ]);
  }
  if (url.hostname === "api.certspotter.com") {
    providerCalls.certspotter += 1;
    return json([{
      id: "ct-identity",
      not_before: "2026-07-01T00:00:00.000Z",
      not_after: "2026-12-01T00:00:00.000Z",
      issuer: { name: "Trace CA" },
      dns_names: ["example.com", "www.example.com", "gone.example.com"],
    }]);
  }
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "gone.example.com") {
      if (phase === "unavailable") throw new DOMException("provider timeout", "TimeoutError");
      if (phase === "observed" && type === "A") {
        return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
      }
      return json({ Status: 3, Answer: [] });
    }
    if (type === "A") {
      return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    return json({ Status: 0, Answer: [] });
  }
  if (url.hostname === "gone.example.com") {
    if (phase === "unavailable") {
      throw new DOMException("probe timeout", "TimeoutError");
    }
    if (phase === "negative") {
      throw new TypeError("connection refused");
    }
    if (phase === "observed") {
      return new Response("<html><title>Grafana</title></html>", {
        status: 200,
        headers: { "content-type": "text/html", server: "grafana" },
      });
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
  const scan = db.prepare(
    "SELECT status, scan_quality FROM scans WHERE id=?",
  ).get(scanId);
  eq(`${scanId} terminal scan status`, scan?.status, "completed");
  const report = JSON.parse(reports.get(`reports/${scanId}.json`) || "{}");
  eq(`${scanId} terminal R2 report is durable before case processing`,
    report.scan_id, scanId);
  eq(`${scanId} report retains all nine independent signals`,
    Object.keys(report.modules?.attack_surface_signal_completeness?.signals || {}).length,
    9);
  return { report, scan };
}

try {
  await run("scan-1", NOW, "negative");
  eq("first real negative leaves the case awaiting verification",
    (await getManagedCase(env, "ws", originalCaseId)).status,
    "verification_requested");
  eq("first real negative is only not_observed",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "not_observed");

  await run("scan-timeout", "2026-07-28T00:00:00.000Z", "unavailable");
  eq("real provider timeout persists observation_unavailable",
    db.prepare("SELECT last_observation_state FROM workspace_assets WHERE id='asset-gone'").get().last_observation_state,
    "observation_unavailable");
  eq("real provider timeout cannot close the case",
    (await getManagedCase(env, "ws", originalCaseId)).status,
    "verification_requested");
  eq("real provider timeout cannot advance removal threshold",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-gone' AND qualifies_removal=1").get().n,
    1);

  await run("scan-2", "2026-07-29T00:00:00.000Z", "negative");
  await run("scan-3", "2026-07-30T00:00:00.000Z", "negative");
  eq("real threshold confirms removal",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "confirmed_removed");
  eq("first real confirmed-removal transition still does not close",
    (await getManagedCase(env, "ws", originalCaseId)).status,
    "verification_requested");
  eq("real confirmation emits exactly one existing lifecycle event",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen' AND asset_id='asset-gone'").get().n,
    1);

  const later = await run(
    "scan-4", "2026-07-31T00:00:00.000Z", "negative",
  );
  ok("later re-observation scan is complete and publishable",
    later.report.scan_quality?.status === "complete",
    JSON.stringify(later.report.scan_quality));
  kase = await getManagedCase(env, "ws", originalCaseId);
  eq("later real re-observation resolves the same case", kase.status, "resolved");
  eq("later real re-observation creates no replacement case",
    db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws'").get().n,
    1);
  const verifiedRow = db.prepare(
    "SELECT detail_json FROM managed_case_events WHERE case_id=? AND action='verified_resolved' ORDER BY rowid DESC LIMIT 1",
  ).get(originalCaseId);
  ok("resolved case retains structured verification evidence", !!verifiedRow?.detail_json);
  if (verifiedRow?.detail_json) {
    const verifiedDetail = JSON.parse(verifiedRow.detail_json);
    eq("case evidence names the same stable asset",
      verifiedDetail.lifecycle.asset_ids[0], "asset-gone");
    eq("case evidence proves later re-observation",
      verifiedDetail.lifecycle.later_reobservation, true);
  }

  const reappeared = await run(
    "scan-5", "2026-08-01T00:00:00.000Z", "observed",
  );
  ok("real reappearance regenerates the same ASM finding",
    reappeared.report.findings.some((entry) =>
      entry.id === "asset_exposure_sensitive_tool" &&
      entry.affected_hosts?.includes("gone.example.com")));
  ok("score-bearing admin host has no duplicate score-zero admin bucket",
    !reappeared.report.findings.some((entry) =>
      entry.id.startsWith("admin_surface_") &&
      entry.affected_hosts?.includes("gone.example.com")),
    JSON.stringify(reappeared.report.findings
      .filter((entry) => entry.id.startsWith("admin_surface_") ||
        entry.id === "asset_exposure_sensitive_tool")));
  kase = await getManagedCase(env, "ws", originalCaseId);
  eq("real reappearance reopens the same case", kase.status, "remediation_in_progress");
  eq("real reappearance increments recurrence once", Number(kase.reopened_count), 1);
  eq("real reappearance uses the same asset identity",
    db.prepare("SELECT asset_id FROM asset_events WHERE event_type='asset_reappeared'").get()?.asset_id,
    "asset-gone");
  eq("real reappearance creates no new asset row",
    db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id='ws' AND hostname='gone.example.com'").get().n,
    1);
  eq("real lifecycle history is append-only across all six scans",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws' AND asset_id='asset-gone'").get().n,
    6);
  eq("soft-deleted tenant receives no lifecycle write",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws-deleted'").get().n,
    0);
  eq("foreign tenant remains isolated",
    db.prepare("SELECT status FROM workspace_assets WHERE id='asset-foreign'").get().status,
    "inactive");
  eq("real trace opens no duplicate case alert occurrence",
    db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=? AND action='monitoring_changed'").get(originalCaseId).n,
    3);
  ok("real trace reuses each shared CT provider exactly once per scan",
    providerCalls.crt === 6 && providerCalls.certspotter === 6,
    JSON.stringify(providerCalls));

  eq("legacy waitUntil executable envelope remains 19,000 ms",
    SCAN_DEADLINE_DEFAULTS.budgetMs, 19_000);
  eq("legacy waitUntil configurable ceiling remains 19,000 ms",
    SCAN_DEADLINE_DEFAULTS.maxBudgetMs, 19_000);
  eq("durable queue executable envelope remains 115,000 ms",
    SCAN_DURABLE_INVOCATION_DEADLINE_DEFAULTS.budgetMs, 115_000);
  eq("trace runs under the durable queue configuration",
    env.SCAN_DEADLINE_MS, "115000");
} finally {
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
}

console.log(`\nItem 10 P3 runScanEngine trace: ${passed}/${passed + failed} assertions passed`);
if (failed) process.exit(1);
console.log("Item 10 P3 runScanEngine lifecycle/case trace passed");
