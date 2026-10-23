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
// Compound values (arrays, rows) compared by their JSON form.
const same = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
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

// Fault injection: a statement matching this pattern throws, as a D1 error would.
let failSql = null;
const maybeFail = (sql) => {
  if (failSql && failSql.test(sql)) throw new Error("D1_ERROR: injected trace fault");
};

function makeD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      maybeFail(sql);
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({
      results: (maybeFail(sql), db.prepare(sql).all(...args)),
      success: true,
      meta: {},
    }),
    run: async () => {
      maybeFail(sql);
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
let goneHostHttpCalls = 0;
const contactedHosts = new Set();
const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  contactedHosts.add(url.hostname);
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
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    // Item 15 fix D: the scanned domain does not exist (both resolvers say
    // NXDOMAIN), or only one resolver says so (not definitive).
    if (phase === "apex_nxdomain") return json({ Status: 3, Answer: [] });
    if (phase === "apex_split" && name === "example.com" && type === "A") {
      return json({ Status: url.hostname === "dns.google" ? 2 : 3, Answer: [] });
    }
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

async function run(scanId, when, mode, { expectLifecycle = true } = {}) {
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
  // A completed scan always leaves its own lifecycle record (22 Oct 2026: a
  // swallowed finalize failure once left a completed scan with none).
  if (expectLifecycle) {
    ok(`${scanId} completed scan wrote lifecycle observations`,
      db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws' AND scan_id=?").get(scanId).n > 0);
  }
  eq(`${scanId} report retains all seven independent signals`,
    Object.keys(report.modules?.attack_surface_signal_completeness?.signals || {}).length,
    7);
  return { report, scan };
}

try {
  await run("scan-1", NOW, "negative");
  eq("first real negative leaves the case awaiting verification",
    (await getManagedCase(env, "ws", originalCaseId)).status,
    "verification_requested");
  eq("DNS absence without an HTTP probe leaves the asset observed",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "observed");

  await run("scan-timeout", "2026-07-28T00:00:00.000Z", "unavailable");
  eq("real provider timeout persists observation_unavailable",
    db.prepare("SELECT last_observation_state FROM workspace_assets WHERE id='asset-gone'").get().last_observation_state,
    "observation_unavailable");
  eq("real provider timeout cannot close the case",
    (await getManagedCase(env, "ws", originalCaseId)).status,
    "verification_requested");
  eq("real provider timeout cannot advance removal threshold",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-gone' AND qualifies_removal=1").get().n,
    0);

  await run("scan-2", "2026-07-29T00:00:00.000Z", "negative");
  await run("scan-3", "2026-07-30T00:00:00.000Z", "negative");
  eq("DNS-only negatives cannot confirm removal",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-gone'").get().lifecycle_state,
    "observed");
  eq("DNS-only sequence does not close the case",
    (await getManagedCase(env, "ws", originalCaseId)).status,
    "verification_requested");
  eq("unissued HTTP yields no removal event",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen' AND asset_id='asset-gone'").get().n,
    0);

  const later = await run(
    "scan-4", "2026-07-31T00:00:00.000Z", "negative",
  );
  ok("later DNS-only scan remains explicitly incomplete",
    later.report.scan_quality?.status === "partial" && later.report.modules.asset_exposure.incomplete_reason === "dns_resolution_unavailable",
    JSON.stringify(later.report.scan_quality));
  kase = await getManagedCase(env, "ws", originalCaseId);
  eq("later DNS-only scan keeps the case awaiting verification", kase.status, "verification_requested");
  eq("DNS-only sequence issued no HTTP to the absent host", goneHostHttpCalls, 0);
  eq("later real re-observation creates no replacement case",
    db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws'").get().n,
    1);
  const verifiedRow = db.prepare(
    "SELECT detail_json FROM managed_case_events WHERE case_id=? AND action='verified_resolved' ORDER BY rowid DESC LIMIT 1",
  ).get(originalCaseId);
  eq("incomplete evidence cannot create a verified resolution event", verifiedRow, undefined);

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
  eq("public re-observation proves the requested remediation failed", kase.status, "verification_failed");
  ok("public DNS allows the target HTTP probe", goneHostHttpCalls > 0);
  eq("a case never resolved has no false recurrence", Number(kase.reopened_count), 0);
  eq("a host never removed has no false reappearance event",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_reappeared'").get().n,
    0);
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
  eq("case alerts record initial unknown and later observed issue",
    db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=? AND action='monitoring_changed'").get(originalCaseId).n,
    2);
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

  // The lifecycle write fails (D1 error): the scan still completes, the
  // inventory is still updated, and the failure is no longer silent: one line
  // with the scan id, the stage and the error type only (never the message).
  {
    const warned = [];
    const originalWarn = console.warn;
    console.warn = (...args) => { warned.push(args.join(" ")); };
    failSql = /INSERT OR IGNORE INTO asset_lifecycle_observations/;
    try {
      await run("scan-lifecycle-fault", "2026-08-03T00:00:00.000Z", "observed", { expectLifecycle: false });
    } finally {
      failSql = null;
      console.warn = originalWarn;
    }
    const line = warned.find((entry) => entry.includes("[scan-finalize]")) || "";
    ok("a failed lifecycle write is logged with scan id and stage",
      line.includes("scan-lifecycle-fault") && line.includes("attack_surface_lifecycle"), line);
    eq("...and the inventory update still ran for that scan",
      db.prepare("SELECT last_seen FROM workspace_assets WHERE id='asset-gone'").get().last_seen,
      "2026-08-03T00:00:00.000Z");
    ok("...with the error type only, never the error message", !line.includes("injected trace fault"), line);
  }

  // Item 15 fix D: a domain that does not exist in public DNS is not assessed.
  // Two resolvers both answer NXDOMAIN: the scan stops before any module, with
  // no score, no findings, no lifecycle or inventory write, and says so.
  {
    const { scanOutcome, scanProgress } = await import(pathToFileURL(path.join(root, "workers/scan-api/src/routes/scans.js")).href);
    const before = db.prepare("SELECT lifecycle_state, last_seen, status FROM workspace_assets WHERE id='asset-gone'").get();
    const lifecycleRowsBefore = db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws'").get().n;
    contactedHosts.clear();
    phase = "apex_nxdomain";
    db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at) VALUES ('scan-nx', 'ws', 'dom', 'example.com', 'pending', NULL, '2026-08-04T00:00:00.000Z')").run();
    let caught = null;
    try {
      await runScanEngine("scan-nx", "dom", "ws", "example.com", env, { now: () => Date.parse("2026-08-04T00:00:00.000Z"), executionContext: "queue", trigger: "manual" });
    } catch (error) { caught = error; }
    const row = db.prepare("SELECT status, score, scan_quality, current_stage FROM scans WHERE id='scan-nx'").get();
    const report = JSON.parse(reports.get("reports/scan-nx.json") || "{}");
    eq("NXDOMAIN on both resolvers: the engine returns normally", caught, null);
    same("...the scan stops as not assessed (domain not found), never scored",
      [row.status, row.current_stage, row.score, row.scan_quality], ["failed", "domain_not_found", null, null]);
    same("...the report states the reason and carries no score or findings",
      [report.outcome, report.cyber_metrics_score, report.findings?.length, /does not exist in public DNS/.test(report.message || "")],
      ["domain_not_found", null, 0, true]);
    eq("...no findings are written", db.prepare("SELECT COUNT(*) AS n FROM findings WHERE scan_id='scan-nx'").get().n, 0);
    eq("...no lifecycle observation is written", db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws'").get().n, lifecycleRowsBefore);
    same("...previous observations are kept (asset row unchanged)",
      db.prepare("SELECT lifecycle_state, last_seen, status FROM workspace_assets WHERE id='asset-gone'").get(), before);
    ok("...only the two resolvers were asked; the domain itself was never contacted",
      [...contactedHosts].every((h) => h === "cloudflare-dns.com" || h === "dns.google"), JSON.stringify([...contactedHosts]));
    same("...an audit event records it as not assessed, not as a failure",
      db.prepare("SELECT event_type FROM audit_events WHERE entity_id='scan-nx'").all().map((e) => e.event_type), ["scan_not_assessed"]);
    const notice = db.prepare("SELECT type, title, message FROM notification_events WHERE metadata_json LIKE '%scan-nx%'").get();
    same("...the workspace is told in the scan page's words",
      [notice?.type, notice?.title, /does not exist in public DNS/.test(notice?.message || "")], ["scan_not_assessed", "Could not assess example.com", true]);
    eq("...customer rows carry outcome domain_not_found", scanOutcome(row), "domain_not_found");
    eq("...and the scan page's progress names the stop", scanProgress({ ...row, status: "failed" })?.stage, "domain_not_found");

    // One resolver says NXDOMAIN, the other SERVFAIL: not definitive, the scan
    // runs as before.
    await run("scan-split", "2026-08-05T00:00:00.000Z", "apex_split");
    eq("one NXDOMAIN + one SERVFAIL is not definitive: the scan completes normally",
      db.prepare("SELECT current_stage FROM scans WHERE id='scan-split'").get().current_stage === "domain_not_found", false);
  }

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
