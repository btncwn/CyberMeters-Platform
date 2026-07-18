#!/usr/bin/env node
//
// Phase A Timeline Trust validator: DB-backed producer checks plus source
// mutation proof for the shared comparability and presentation-collapse helper.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const timelinePath = path.join(root, "workers", "scan-api", "src", "engines", "timeline-trust.js");
const {
  ASSET_TIMELINE_PRODUCER_VERSION,
  assessTimelineComparison,
  buildAssetTimelineTrustMetadata,
  collapseCustomerTimelineEvents,
  countCustomerTimelineEventsByDay,
  filterCustomerTimelineEventsForScan,
} = await import(pathToFileURL(timelinePath).href);
const { upsertAssetInventory } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asset-inventory.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  if (!cond) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) => ok(name, actual === expected, `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* migrations are cumulative */ } };
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
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
  };
}

function makeR2(reports) {
  return {
    async get(key) {
      const report = reports.get(key);
      return report ? { json: async () => report } : null;
    },
  };
}

function report({ quality = "complete", version = ASSET_TIMELINE_PRODUCER_VERSION } = {}) {
  return {
    scan_quality: { status: quality },
    timeline_trust: version ? { asset_timeline_producer_version: version } : null,
    modules: {},
  };
}

function harness({ previous = report(), currentQuality = "complete", existingAsset = null } = {}) {
  const db = buildDb();
  db.prepare("INSERT INTO users (id, email) VALUES ('usr_1', 'owner@example.co.uk')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom_1', 'usr_1', 'blackbullbarbers.co.uk')").run();
  db.prepare("INSERT INTO workspaces (id, name) VALUES ('ws_1', 'Black Bull Barbers')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_1', 'dom_1')").run();
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
    "scan_prev", "dom_1", "blackbullbarbers.co.uk", "completed", previous?.scan_quality?.status ?? "complete", "ws_1", "2026-07-17T10:00:00.000Z"
  );
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
    "scan_current", "dom_1", "blackbullbarbers.co.uk", "completed", currentQuality, "ws_1", "2026-07-18T10:00:00.000Z"
  );
  if (existingAsset) {
    db.prepare(
      `INSERT INTO workspace_assets
         (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen,
          status, wildcard_dns, ip_addresses, cname, redirect_to, created_at, updated_at)
       VALUES (?, 'ws_1', 'dom_1', ?, 'subdomain', 'dns_bruteforce', ?, ?, ?, 0, ?, ?, ?, ?, ?)`
    ).run(
      existingAsset.id || "asset_old",
      existingAsset.hostname,
      existingAsset.first_seen || "2026-07-15T10:00:00.000Z",
      existingAsset.last_seen || "2026-07-15T10:00:00.000Z",
      existingAsset.status || "active",
      existingAsset.ip_addresses ?? null,
      existingAsset.cname ?? null,
      existingAsset.redirect_to ?? null,
      existingAsset.created_at || "2026-07-15T10:00:00.000Z",
      existingAsset.updated_at || "2026-07-15T10:00:00.000Z"
    );
  }
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: makeR2(new Map(previous ? [["reports/scan_prev.json", previous]] : [])),
  };
  return { db, env };
}

const currentReport = report();
const modulesWithRoot = () => ({ subdomains: { items: [], wildcard_dns: false } });
const modulesWithAdmin = () => ({
  subdomains: { items: ["admin.blackbullbarbers.co.uk"], wildcard_dns: false },
  dns_bruteforce: { items: [{ hostname: "admin.blackbullbarbers.co.uk", ip_addresses: ["203.0.113.10"] }] },
});
const events = (db) => db.prepare("SELECT event_type, hostname, scan_id, created_at FROM asset_events ORDER BY created_at, id").all();
const asset = (db, hostname) => db.prepare("SELECT hostname, status, last_seen FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = ?").get(hostname);

// Positive: comparable complete scans with the same producer stamp may emit.
{
  const { db, env } = harness();
  await upsertAssetInventory("scan_current", "dom_1", "blackbullbarbers.co.uk", modulesWithAdmin(), env, { currentReport });
  ok("positive comparable path emits customer asset event", events(db).some((e) => e.event_type === "new_asset_discovered" && e.hostname === "admin.blackbullbarbers.co.uk"));
}

// Negative: insufficient history is an operator diagnostic, not a customer event.
{
  const { db, env } = harness({ previous: null });
  await upsertAssetInventory("scan_current", "dom_1", "blackbullbarbers.co.uk", modulesWithAdmin(), env, { currentReport });
  eq("insufficient_history emits no customer asset_events", events(db).length, 0);
  ok("insufficient_history still preserves observed inventory", !!asset(db, "admin.blackbullbarbers.co.uk"));
}

// Cross-version: a methodology/producer shift is not a posture change.
{
  const { db, env } = harness({ previous: report({ version: "legacy-unversioned-producer" }) });
  await upsertAssetInventory("scan_current", "dom_1", "blackbullbarbers.co.uk", modulesWithAdmin(), env, { currentReport });
  eq("cross-version scans emit no customer asset_events", events(db).length, 0);
}

// Unavailable source: partial current scans cannot remove an asset or emit a clean/change event.
{
  const { db, env } = harness({
    currentQuality: "partial",
    existingAsset: { hostname: "old.blackbullbarbers.co.uk", status: "active", last_seen: "2026-07-15T10:00:00.000Z" },
  });
  await upsertAssetInventory("scan_current", "dom_1", "blackbullbarbers.co.uk", modulesWithRoot(), env, { currentReport: report({ quality: "partial" }) });
  eq("unavailable current scan emits no customer asset_events", events(db).length, 0);
  eq("unavailable current scan does not mark missing evidence inactive", asset(db, "old.blackbullbarbers.co.uk")?.status, "active");
}

// Stable state: no DNS drift means no event.
{
  const { db, env } = harness({
    existingAsset: {
      hostname: "admin.blackbullbarbers.co.uk",
      status: "active",
      ip_addresses: JSON.stringify(["203.0.113.10"]),
      last_seen: "2026-07-17T10:00:00.000Z",
    },
  });
  db.prepare(
    `INSERT INTO workspace_assets
       (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen,
        status, wildcard_dns, created_at, updated_at)
     VALUES ('asset_root', 'ws_1', 'dom_1', 'blackbullbarbers.co.uk', 'root_domain',
             'scan_root', '2026-07-17T10:00:00.000Z', '2026-07-17T10:00:00.000Z',
             'active', 0, '2026-07-17T10:00:00.000Z', '2026-07-17T10:00:00.000Z')`
  ).run();
  await upsertAssetInventory("scan_current", "dom_1", "blackbullbarbers.co.uk", modulesWithAdmin(), env, { currentReport });
  eq("stable-state comparable scan emits no asset_events", events(db).length, 0);
}

// Persistence + blackbullbarbers churn: raw rows stay intact, customer presentation collapses.
{
  const raw = [
    { id: "e1", scan_id: "s1", event_type: "new_asset_discovered", hostname: "blackbullbarbers.co.uk", created_at: "2026-07-18T09:00:00.000Z" },
    { id: "e2", scan_id: "s2", event_type: "asset_no_longer_seen", hostname: "blackbullbarbers.co.uk", created_at: "2026-07-18T09:05:00.000Z" },
    { id: "e3", scan_id: "s3", event_type: "asset_reappeared", hostname: "blackbullbarbers.co.uk", created_at: "2026-07-18T09:10:00.000Z" },
  ];
  eq("blackbullbarbers short-lived churn collapses from customer timeline", collapseCustomerTimelineEvents(raw).length, 0);
  eq("raw append-only event evidence remains intact in caller memory", raw.length, 3);
}

// Recurrence: persistent removal and genuine later reappearance survive collapse.
{
  const raw = [
    { id: "e1", event_type: "asset_no_longer_seen", hostname: "portal.blackbullbarbers.co.uk", created_at: "2026-07-16T09:00:00.000Z" },
    { id: "e2", event_type: "asset_reappeared", hostname: "portal.blackbullbarbers.co.uk", created_at: "2026-07-18T09:00:00.000Z" },
  ];
  const collapsed = collapseCustomerTimelineEvents(raw);
  eq("persistent removal remains visible", collapsed[0]?.event_type, "asset_no_longer_seen");
  eq("genuine later reappearance remains visible", collapsed[1]?.event_type, "asset_reappeared");
}

// Timeline aggregation: collapse raw rows before counting, preserving persistent removals.
{
  const raw = [
    { id: "a", event_type: "asset_no_longer_seen", hostname: "www.blackbullbarbers.co.uk", created_at: "2026-07-18T09:00:00.000Z" },
    { id: "b", event_type: "asset_reappeared", hostname: "www.blackbullbarbers.co.uk", created_at: "2026-07-18T09:04:00.000Z" },
    { id: "c", event_type: "asset_no_longer_seen", hostname: "old.blackbullbarbers.co.uk", created_at: "2026-07-18T09:10:00.000Z" },
  ];
  const counts = countCustomerTimelineEventsByDay(raw, ["asset_no_longer_seen"]);
  eq("timeline aggregation collapses short-lived churn before counting", counts[0]?.asset_no_longer_seen, 1);
  eq("timeline aggregation preserves persistent removal day", counts[0]?.day, "2026-07-18");
}

// Filtered alert presentation: recent context may collapse prior rows, but output is scan-scoped.
{
  const raw = [
    { id: "old", scan_id: "old_scan", event_type: "takeover_risk_detected", hostname: "x.blackbullbarbers.co.uk", created_at: "2026-07-18T08:00:00.000Z" },
    { id: "cur", scan_id: "scan_current", event_type: "new_asset_discovered", hostname: "y.blackbullbarbers.co.uk", created_at: "2026-07-18T09:00:00.000Z" },
  ];
  const filtered = filterCustomerTimelineEventsForScan(raw, "scan_current");
  eq("alert presentation remains scoped to current scan", filtered.length, 1);
  eq("alert presentation keeps current scan event", filtered[0]?.id, "cur");
}

// Static wiring: no migration, future reports stamped, non-scan brand event default silent.
{
  const scanEngine = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
  const brandDns = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "brand-dns-enrichment.js"), "utf8");
  ok("scan reports carry timeline_trust producer provenance", /timeline_trust:\s+buildAssetTimelineTrustMetadata\(\)/.test(scanEngine));
  ok("brand DNS enrichment default emits no non-comparable asset_events", /fireEvents\s+=\s+false/.test(brandDns));
  ok("Phase A added no migration file", !fs.readdirSync(path.join(root, "database", "migrations")).some((f) => /timeline-trust|asset-event.*producer/i.test(f)));
  eq("canonical producer version is stamped by helper", buildAssetTimelineTrustMetadata().asset_timeline_producer_version, ASSET_TIMELINE_PRODUCER_VERSION);
}

function pureContract(mod) {
  const current = report();
  const previous = report();
  const currentRow = { scan_quality: "complete" };
  const previousRow = { scan_quality: "complete" };
  const partial = mod.assessTimelineComparison({
    currentReport: report({ quality: "partial" }),
    previousReport: previous,
    currentScan: { scan_quality: "partial" },
    previousScan: previousRow,
  });
  if (partial.comparable) return "partial_current_became_comparable";
  const drift = mod.assessTimelineComparison({
    currentReport: current,
    previousReport: report({ version: "old" }),
    currentScan: currentRow,
    previousScan: previousRow,
  });
  if (drift.comparable) return "producer_version_drift_became_comparable";
  const churn = mod.collapseCustomerTimelineEvents([
    { id: "a", event_type: "asset_no_longer_seen", hostname: "blackbullbarbers.co.uk", created_at: "2026-07-18T09:00:00.000Z" },
    { id: "b", event_type: "asset_reappeared", hostname: "blackbullbarbers.co.uk", created_at: "2026-07-18T09:05:00.000Z" },
  ]);
  if (churn.length !== 0) return "flip_flop_pair_not_collapsed";
  const scoped = mod.filterCustomerTimelineEventsForScan([
    { id: "old", scan_id: "old_scan", event_type: "takeover_risk_detected", hostname: "x", created_at: "2026-07-18T08:00:00.000Z" },
    { id: "cur", scan_id: "scan_current", event_type: "takeover_risk_detected", hostname: "y", created_at: "2026-07-18T09:00:00.000Z" },
  ], "scan_current");
  if (scoped.length !== 1 || scoped[0].id !== "cur") return "alert_scan_scope_removed";
  const counts = mod.countCustomerTimelineEventsByDay([
    { id: "a", event_type: "asset_no_longer_seen", hostname: "x", created_at: "2026-07-18T09:00:00.000Z" },
    { id: "b", event_type: "asset_reappeared", hostname: "x", created_at: "2026-07-18T09:05:00.000Z" },
    { id: "c", event_type: "asset_no_longer_seen", hostname: "y", created_at: "2026-07-18T09:10:00.000Z" },
  ], ["asset_no_longer_seen"]);
  if (counts[0]?.asset_no_longer_seen !== 1) return "timeline_aggregation_did_not_collapse";
  return null;
}

eq("pure helper contract passes before mutations", pureContract({ assessTimelineComparison, collapseCustomerTimelineEvents, countCustomerTimelineEventsByDay, filterCustomerTimelineEventsForScan }), null);

if (!process.argv.includes("--no-mutate")) {
  const original = fs.readFileSync(timelinePath, "utf8");
  const mutations = [
    {
      name: "allow partial current scan",
      from: 'if (currentQuality !== "complete") {',
      to: 'if (false && currentQuality !== "complete") {',
      expected: "partial_current_became_comparable",
    },
    {
      name: "ignore producer version drift",
      from: "if (!currentVersion || !previousVersion || currentVersion !== previousVersion) {",
      to: "if (!currentVersion || !previousVersion || false) {",
      expected: "producer_version_drift_became_comparable",
    },
    {
      name: "remove disappearance/reappearance collapse",
      from: "if (hasAbsent && hasPresent) {",
      to: "if (false && hasAbsent && hasPresent) {",
      expected: "flip_flop_pair_not_collapsed",
    },
    {
      name: "remove alert scan scope",
      from: "return collapsed.filter((row) => row?.scan_id === scanId || (opts.missingScanIdMatches && row?.scan_id == null));",
      to: "return collapsed;",
      expected: "alert_scan_scope_removed",
    },
    {
      name: "aggregate raw timeline rows without collapse",
      from: "for (const row of collapseCustomerTimelineEvents(rows, opts)) {",
      to: "for (const row of (rows || [])) {",
      expected: "timeline_aggregation_did_not_collapse",
    },
  ];
  let mutationFailures = 0;
  for (const m of mutations) {
    if (!original.includes(m.from)) {
      console.log(`FAIL mutation anchor missing: ${m.name}`);
      mutationFailures++;
      continue;
    }
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "timeline-trust-mutant-"));
    const mutantPath = path.join(tmp, "timeline-trust.mjs");
    fs.writeFileSync(mutantPath, original.replace(m.from, m.to));
    const mutant = await import(pathToFileURL(mutantPath).href + `?m=${encodeURIComponent(m.name)}`);
    const reason = pureContract(mutant);
    if (reason !== m.expected) {
      console.log(`FAIL mutation NOT caught as intended: ${m.name} — got ${reason || "survived"}`);
      mutationFailures++;
    } else {
      console.log(`  mutation CAUGHT: ${m.name}`);
    }
  }
  ok("Timeline Trust mutations fail for intended reasons", mutationFailures === 0);
}

console.log(`\nphase-a-timeline-trust: ${pass}/${pass + fail} passed`);
if (fail) { console.error("phase-a-timeline-trust validation FAILED"); process.exit(1); }
console.log("phase-a-timeline-trust validation passed");
