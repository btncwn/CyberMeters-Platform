#!/usr/bin/env node
//
// Shadow IT FB-1 + EH-1 — founder-approved fail-closed source outcomes and
// customer-derived hostname provenance. CI-blocking, deterministic, local only.
//
// Contract: shadow-it-fb1-eh1/v1
// Each Fxx is one semantic verdict so the mutation runner can require an exact,
// ordered failure set. The normal summary marker is part of that contract.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (name) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", name)).href;
const inventory = await import(engineUrl("shadow-it-inventory.js"));
const discovery = await import(engineUrl("discovery-scan.js"));
const related = await import(engineUrl("related-changes-adapter.js"));
await import(engineUrl("report-snapshot.js"));

const {
  correlateShadowItInventory,
  evaluateShadowItMonitoring,
  getShadowItItem,
  shadowItItemToApi,
  summarizeShadowItEvidence,
  cataloguePruneCorrectionStatements,
} = inventory;
const { runSaasExposureModule } = discovery;
const { collectChangeEvents } = related;

let passed = 0;
let failed = 0;
const failures = [];
function verdict(id, condition, detail = "") {
  if (condition) passed += 1;
  else {
    failed += 1;
    failures.push(id);
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
const json = (value) => JSON.stringify(value);
const queryOne = (db, sql, ...args) => db.prepare(sql).get(...args) ?? null;
const queryAll = (db, sql, ...args) => db.prepare(sql).all(...args);

// Build the repository's real current schema once, then clone it per fixture.
// This keeps all managed-case/alert foreign surfaces available without sharing
// state between semantic verdicts.
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "shadow-fb1-eh1-"));
const templatePath = path.join(tempRoot, "template.sqlite");
{
  const db = new DatabaseSync(templatePath);
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* additive migration drift */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations")).filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.close();
}

let fixtureNumber = 0;
function createFixture() {
  const dbPath = path.join(tempRoot, `fixture-${++fixtureNumber}.sqlite`);
  fs.copyFileSync(templatePath, dbPath);
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id,email,name) VALUES ('u1','owner@example.com','Owner')").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES ('ws1','One','u1',datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES ('ws2','Two','u1',datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at,deleted_at) VALUES ('dead','Dead','u1',datetime('now'),datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','example.com')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d2','u1','other.example')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws2','d2')").run();
  return { db, controls: { failAll: [], failFirst: [], failed: new Set(), reads: [], writes: [] } };
}

function makeD1(db, controls) {
  function mustFail(method, sql) {
    const text = String(sql).replace(/\s+/g, " ").trim();
    if (controls.failAll.some((entry) => entry.method === method && entry.pattern.test(text))) return true;
    const index = controls.failFirst.findIndex((entry, i) =>
      !controls.failed.has(i) && entry.method === method && entry.pattern.test(text));
    if (index >= 0) { controls.failed.add(index); return true; }
    return false;
  }
  const statement = (sql, args) => ({
    _sql: sql,
    _args: args,
    first: async () => {
      controls.reads.push({ method: "first", sql: String(sql).replace(/\s+/g, " ").trim() });
      if (mustFail("first", sql)) throw new Error("injected first failure");
      return db.prepare(sql).get(...args) ?? null;
    },
    all: async () => {
      controls.reads.push({ method: "all", sql: String(sql).replace(/\s+/g, " ").trim() });
      if (mustFail("all", sql)) throw new Error("injected all failure");
      return { results: db.prepare(sql).all(...args) };
    },
    run: async () => {
      if (mustFail("run", sql)) throw new Error("injected run failure");
      controls.writes.push(String(sql).replace(/\s+/g, " ").trim());
      const result = db.prepare(sql).run(...args);
      return { meta: { changes: result.changes } };
    },
  });
  return {
    prepare(sql) { const bare = statement(sql, []); bare.bind = (...args) => statement(sql, args); return bare; },
    async batch(statements) {
      db.exec("BEGIN");
      const results = [];
      try {
        for (const prepared of statements) {
          const sql = prepared._sql;
          if (mustFail("run", sql)) throw new Error("injected run failure");
          controls.writes.push(String(sql).replace(/\s+/g, " ").trim());
          const result = db.prepare(sql).run(...prepared._args);
          results.push({ success: true, meta: { changes: result.changes } });
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

const NOW = "2026-08-09T12:00:00.000Z";
const completeInput = Object.freeze({ saasExposure: { exposures: [], error: null }, subdomainDiscovery: { executed: true, incomplete: false }, now: NOW });
const EXPECTED_OUTCOMES = ["ok", "empty", "failed", "incomplete"];
const EXPECTED_SOURCES = ["email_sender_sources", "identity_assets", "saas_exposure", "workspace_assets", "workspace_vendors"];
function closedOutcomeMap(result) {
  const outcomes = result?.source_outcomes;
  return json(inventory.SHADOW_IT_READ_OUTCOMES) === json(EXPECTED_OUTCOMES) &&
    outcomes && json(Object.keys(outcomes).sort()) === json(EXPECTED_SOURCES) &&
    Object.values(outcomes).every((outcome) => EXPECTED_OUTCOMES.includes(outcome));
}
function envFor(fixture) { return { cybermeters_db: makeD1(fixture.db, fixture.controls) }; }
function failRead(fixture, table) {
  fixture.controls.failAll.push({ method: "all", pattern: new RegExp(`FROM ${table}(?: |$)`, "i") });
}
function evidence(sourceTable, sourceType, id = "source-1", observed = "Example") {
  return [{ source_table: sourceTable, source_record_id: id, source_type: sourceType, observed_identifier: observed, first_seen_at: null, last_seen_at: null, confidence: "low" }];
}
function seedInventory(db, {
  id = "sii-1", workspace = "ws1", key = "example", display = "Example",
  sourceType = "vendor", sourceEvidence = evidence("workspace_vendors", "vendor"),
  hosts = [], classification = "unreviewed", monitoring = "observed",
  recurrence = null, removalStatus = null, removalVerified = null, linkedCaseId = null,
} = {}) {
  db.prepare(`INSERT INTO shadow_it_inventory
    (id,workspace_id,canonical_technology_key,display_name,provider,category,source_type,
     observed_identifiers_json,observed_hostnames_json,observed_domains_json,
     first_seen_at,last_seen_at,confidence,classification,ownership_status,monitoring_status,
     recurrence_type,removal_status,removal_verified,linked_case_id,source_evidence_json,created_at,updated_at)
    VALUES (?,?,?,?,?,'saas',?,'[]',?,'[]',?,?, 'low',?,'missing',?,?,?,?,?,?,?,?)`)
    .run(id, workspace, key, display, display, sourceType, json(hosts), NOW, NOW,
      classification, monitoring, recurrence, removalStatus, removalVerified, linkedCaseId,
      json(sourceEvidence), NOW, NOW);
  return id;
}
function seedVendor(db, { id = "source-1", workspace = "ws1", name = "Example", detail = null } = {}) {
  const entries = detail ? [{ source: "cname", detail }] : [];
  db.prepare(`INSERT INTO workspace_vendors
    (id,workspace_id,vendor_name,category,source,evidence,confidence,risk_level,first_seen,last_seen,status,created_at,updated_at)
    VALUES (?,?,?,'saas','cname',?,'low','low',?,?,'active',?,?)`)
    .run(id, workspace, name, json(entries), NOW, NOW, NOW, NOW);
}
function seedIdentity(db, { id = "source-1", workspace = "ws1", name = "Example" } = {}) {
  db.prepare(`INSERT INTO identity_assets
    (id,workspace_id,domain_id,scan_id,hostname,asset_type,identity_type,provider,first_seen,last_seen,status,risk_score,created_at)
    VALUES (?,?, 'd1','scan-1','id.example.com','portal','sso',?,?,?,'active',0,?)`)
    .run(id, workspace, name, NOW, NOW, NOW);
}
function seedSender(db, { id = "source-1", workspace = "ws1", name = "Example" } = {}) {
  db.prepare(`INSERT INTO email_sender_sources
    (id,workspace_id,domain,source_ip,provider_guess,provider_confidence,header_from,first_seen,last_seen,total_messages,classification,created_at)
    VALUES (?,?, 'example.com','192.0.2.1',?,'low','example.com',?,?,1,'unknown',?)`)
    .run(id, workspace, name, NOW, NOW, NOW);
}
function seedCloud(db, { id = "source-1", workspace = "ws1", provider = "cloudflare", source = "certificate_transparency" } = {}) {
  db.prepare(`INSERT INTO workspace_assets
    (id,workspace_id,domain_id,hostname,asset_type,source,first_seen,last_seen,status,cloud_provider,created_at,updated_at)
    VALUES (?,?, 'd1','cdn.example.com','cdn',?,?,?,'active',?,?,?)`)
    .run(id, workspace, source, NOW, NOW, provider, NOW, NOW);
}
function item(db, id = "sii-1") { return queryOne(db, "SELECT * FROM shadow_it_inventory WHERE id = ?", id); }
function eventRows(db, id = "sii-1") { return queryAll(db, "SELECT event_type,detail_json FROM shadow_it_inventory_events WHERE item_id = ? ORDER BY created_at,id", id); }
function noDisappearance(row, events) {
  return row?.monitoring_status === "observed" && !events.some((event) => event.event_type === "monitoring_changed" && /no_longer_observed/.test(event.detail_json || ""));
}

async function failedSourceDefers(id, sourceTable, sourceType) {
  const fx = createFixture();
  seedInventory(fx.db, { sourceType, sourceEvidence: evidence(sourceTable, sourceType) });
  failRead(fx, sourceTable);
  const result = await correlateShadowItInventory(envFor(fx), "ws1", completeInput);
  const sourceReads = fx.controls.reads.filter((read) => read.method === "all" && new RegExp(`FROM ${sourceTable}(?: |$)`, "i").test(read.sql)).length;
  verdict(id, noDisappearance(item(fx.db), eventRows(fx.db)) && fx.controls.writes.length === 0 && sourceReads === 1 &&
    closedOutcomeMap(result) && result.source_outcomes[sourceTable] === "failed",
    `status=${item(fx.db)?.monitoring_status}, writes=${fx.controls.writes.length}, source_reads=${sourceReads}`);
  fx.db.close();
}

await failedSourceDefers("F01", "workspace_vendors", "vendor");
await failedSourceDefers("F02", "identity_assets", "identity_provider");
await failedSourceDefers("F03", "email_sender_sources", "email_sender");

// F04: absent in-memory module is incomplete, never evidence of absence.
{
  const fx = createFixture();
  seedInventory(fx.db, { sourceType: "saas_portal", sourceEvidence: evidence("saas_exposure", "saas_portal", null, "Microsoft 365") });
  const result = await correlateShadowItInventory(envFor(fx), "ws1", { saasExposure: null, subdomainDiscovery: { executed: true }, now: NOW });
  verdict("F04", noDisappearance(item(fx.db), eventRows(fx.db)) && fx.controls.writes.length === 0 &&
    closedOutcomeMap(result) && result.source_outcomes.saas_exposure === "incomplete");
  fx.db.close();
}

// F05: a completed empty contributing source still supports true absence.
{
  const fx = createFixture();
  seedInventory(fx.db);
  const result = await correlateShadowItInventory(envFor(fx), "ws1", completeInput);
  const row = item(fx.db);
  verdict("F05", row?.monitoring_status === "no_longer_observed" &&
    result.source_outcomes.workspace_vendors === "empty" &&
    eventRows(fx.db).some((event) => /no_longer_observed/.test(event.detail_json || "")));
  fx.db.close();
}

// F06: one successful duplicate source wins over a failed contributor.
{
  const fx = createFixture();
  seedInventory(fx.db, { sourceType: "vendor,identity_provider", sourceEvidence: [
    ...evidence("workspace_vendors", "vendor", "vendor-1"),
    ...evidence("identity_assets", "identity_provider", "identity-1"),
  ] });
  seedVendor(fx.db, { id: "vendor-1" });
  failRead(fx, "identity_assets");
  const result = await correlateShadowItInventory(envFor(fx), "ws1", completeInput);
  const itemUpdates = fx.controls.writes.filter((sql) => /^UPDATE shadow_it_inventory SET/i.test(sql)).length;
  verdict("F06", item(fx.db)?.monitoring_status === "observed" &&
    result.source_outcomes.workspace_vendors === "ok" &&
    !eventRows(fx.db).some((event) => /no_longer_observed/.test(event.detail_json || "")) && itemUpdates >= 2);
  fx.db.close();
}

// F07/F08: failed-only passes preserve the entire prior contradiction/recurrence
// snapshot and append nothing; they do not launder a still-open lifecycle fact.
for (const scenario of [
  { id: "F07", classification: "unreviewed", recurrence: "removal_contradicted", removalStatus: "removed", removalVerified: "contradicted" },
  { id: "F08", classification: "rejected", recurrence: "rejected_reappeared", removalStatus: null, removalVerified: null },
]) {
  const fx = createFixture();
  seedInventory(fx.db, { classification: scenario.classification, recurrence: scenario.recurrence,
    removalStatus: scenario.removalStatus, removalVerified: scenario.removalVerified });
  failRead(fx, "workspace_vendors");
  const before = item(fx.db);
  await correlateShadowItInventory(envFor(fx), "ws1", completeInput);
  const after = item(fx.db);
  verdict(scenario.id,
    after.monitoring_status === before.monitoring_status &&
    after.recurrence_type === before.recurrence_type &&
    after.removal_verified === before.removal_verified &&
    eventRows(fx.db).length === 0 && fx.controls.writes.length === 0);
  fx.db.close();
}

// F09: a deferred pass never fabricates the absence needed for reappearance.
{
  const fx = createFixture();
  seedInventory(fx.db, { classification: "retired" });
  failRead(fx, "workspace_vendors");
  const env = envFor(fx);
  await correlateShadowItInventory(env, "ws1", completeInput);
  fx.controls.failAll = [];
  seedVendor(fx.db);
  await correlateShadowItInventory(env, "ws1", completeInput);
  const row = item(fx.db);
  verdict("F09", row.monitoring_status === "observed" && row.recurrence_type !== "retired_reappeared" &&
    queryOne(fx.db, "SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1'").n === 0);
  fx.db.close();
}

// F10: the existing CT-backed cloud deferral remains intact.
{
  const fx = createFixture();
  seedInventory(fx.db, { key: "cloudflare", display: "Cloudflare", sourceType: "cloud_asset", sourceEvidence: evidence("workspace_assets", "cloud_asset") });
  seedCloud(fx.db);
  const result = await correlateShadowItInventory(envFor(fx), "ws1", { ...completeInput, subdomainDiscovery: { executed: false, incomplete: true } });
  verdict("F10", noDisappearance(item(fx.db), eventRows(fx.db)) && fx.controls.writes.length === 0 &&
    result.source_outcomes.workspace_assets === "incomplete");
  fx.db.close();
}

// F11: inventory-list failure is explicit and causes no status/event writes.
{
  const fx = createFixture();
  seedInventory(fx.db);
  fx.controls.failAll.push({ method: "all", pattern: /SELECT \* FROM shadow_it_inventory WHERE workspace_id = \?/i });
  const result = await evaluateShadowItMonitoring(envFor(fx), "ws1", { seenKeys: new Set(), sourceOutcomes: Object.freeze({ workspace_vendors: "empty" }), now: NOW });
  verdict("F11", result?.read_outcome === "failed" && result?.evaluated === 0 && fx.controls.writes.length === 0 && eventRows(fx.db).length === 0);
  fx.db.close();
}

// F12: failed existing-row lookup cannot enter INSERT.
{
  const fx = createFixture();
  seedVendor(fx.db);
  fx.controls.failFirst.push({ method: "first", pattern: /SELECT \* FROM shadow_it_inventory WHERE workspace_id = \? AND canonical_technology_key = \?/i });
  await correlateShadowItInventory(envFor(fx), "ws1", completeInput);
  verdict("F12", queryOne(fx.db, "SELECT COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id='ws1'").n === 0 &&
    !fx.controls.writes.some((sql) => /^INSERT INTO shadow_it_inventory /i.test(sql)));
  fx.db.close();
}

function saasModules(name, cnames = []) {
  return {
    vendor_risk: { vendors: [{ name, evidence: [{ source: "cname", detail: name }], confidence: "medium" }] },
    subdomain_takeover: { risks: cnames.map((cname) => ({ cname })) },
    asset_exposure: { assets: [] }, dns_bruteforce: { items: [] },
  };
}
async function correlateSaas(name, cnames = []) {
  const fx = createFixture();
  const saas = runSaasExposureModule(saasModules(name, cnames));
  await correlateShadowItInventory(envFor(fx), "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  const row = queryOne(fx.db, "SELECT * FROM shadow_it_inventory WHERE workspace_id='ws1'");
  return { fx, saas, row, hosts: row ? JSON.parse(row.observed_hostnames_json || "[]") : [] };
}

// F13: catalogue-only Microsoft URLs never become observed hosts.
{
  const { fx, saas, hosts } = await correlateSaas("Microsoft 365");
  verdict("F13", saas.exposures[0]?.observed_tenant_url == null &&
    !hosts.includes("https://login.microsoftonline.com") && !hosts.includes("https://admin.microsoft.com"));
  fx.db.close();
}

// F14: a genuinely CNAME-derived tenant URL remains customer observation.
{
  const { fx, saas, hosts } = await correlateSaas("Atlassian", ["acme.atlassian.net"]);
  verdict("F14", saas.exposures[0]?.tenant_url === "https://acme.atlassian.net" && hosts.includes("https://acme.atlassian.net"));
  fx.db.close();
}

// F15: fallback tenant_url equal to the catalogue portal is not observation.
{
  const { fx, saas, hosts } = await correlateSaas("HubSpot", ["acme.hs-sites.com"]);
  verdict("F15", saas.exposures[0]?.tenant_url === "https://app.hubspot.com" &&
    saas.exposures[0]?.observed_tenant_url == null && !hosts.includes("https://app.hubspot.com"));
  fx.db.close();
}

async function seedLegacyCatalogueFixture({ mixed = false } = {}) {
  const fx = createFixture();
  const refs = evidence("saas_exposure", "saas_portal", null, "Microsoft 365");
  if (mixed) refs.unshift(...evidence("workspace_vendors", "vendor", "vendor-1", "Microsoft 365")
    .map((ref) => ({ ...ref, first_seen_at: NOW, last_seen_at: NOW })));
  seedInventory(fx.db, { key: "microsoft_365", display: "Microsoft 365",
    sourceType: mixed ? "vendor,saas_portal" : "saas_portal", sourceEvidence: refs,
    hosts: mixed ? ["https://login.microsoftonline.com", "customer.example.com"] : ["https://login.microsoftonline.com"] });
  if (mixed) seedVendor(fx.db, { id: "vendor-1", name: "Microsoft 365", detail: "customer.example.com" });
  const saas = runSaasExposureModule(saasModules("Microsoft 365"));
  return { fx, saas };
}

// F16: alert evidence cannot fall back to a pruned catalogue URL.
{
  const { fx, saas } = await seedLegacyCatalogueFixture();
  const env = envFor(fx);
  await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  const summary = await summarizeShadowItEvidence(env, item(fx.db));
  verdict("F16", summary?.detail == null || summary.detail !== "https://login.microsoftonline.com");
  fx.db.close();
}

// F17: forward/pruned rows cannot anchor Related Changes on catalogue domains.
{
  const { fx, saas } = await seedLegacyCatalogueFixture();
  const env = envFor(fx);
  await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  const events = await collectChangeEvents(env, { workspaceId: "ws1", windowStart: "2026-08-08T00:00:00.000Z", windowEnd: "2026-08-10T00:00:00.000Z" });
  verdict("F17", !events.some((event) => event.producer_family === "shadow_it" && ["microsoftonline.com", "microsoft.com"].includes(event.registrable_domain)));
  fx.db.close();
}

// F18: exact allow-list prune only; mutable evidence union and immutable stores stay intact.
{
  const { fx, saas } = await seedLegacyCatalogueFixture({ mixed: true });
  fx.db.prepare(`INSERT INTO shadow_it_inventory_events
    (id,item_id,workspace_id,actor_type,event_type,detail_json,created_at)
    VALUES ('history-1','sii-1','ws1','system','observed','{"historic":true}','2026-08-01T00:00:00.000Z')`).run();
  const evidenceBefore = item(fx.db).source_evidence_json;
  const historyBefore = queryOne(fx.db, "SELECT * FROM shadow_it_inventory_events WHERE id='history-1'");
  const casesBefore = queryOne(fx.db, "SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1'").n;
  await correlateShadowItInventory(envFor(fx), "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  const after = item(fx.db);
  const hosts = JSON.parse(after.observed_hostnames_json || "[]");
  verdict("F18", !hosts.includes("https://login.microsoftonline.com") && hosts.includes("customer.example.com") &&
    after.source_evidence_json === evidenceBefore &&
    json(queryOne(fx.db, "SELECT * FROM shadow_it_inventory_events WHERE id='history-1'")) === json(historyBefore) &&
    queryOne(fx.db, "SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1'").n === casesBefore,
  `hosts=${json(hosts)}, evidence_unchanged=${after.source_evidence_json === evidenceBefore}, history_unchanged=${json(queryOne(fx.db, "SELECT * FROM shadow_it_inventory_events WHERE id='history-1'")) === json(historyBefore)}, cases=${queryOne(fx.db, "SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1'").n}/${casesBefore}`);
  fx.db.close();
}

// F19: one bounded correction event, never a monitoring occurrence; second pass no-op.
{
  const { fx, saas } = await seedLegacyCatalogueFixture();
  const env = envFor(fx);
  const run = () => correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  await run();
  const afterOne = eventRows(fx.db);
  await run();
  const afterTwo = eventRows(fx.db);
  const corrections = afterTwo.filter((event) => event.event_type === "material_change" && /catalogue_hostname_prune/.test(event.detail_json || ""));
  verdict("F19", corrections.length === 1 && afterTwo.length === afterOne.length &&
    !afterTwo.some((event) => event.event_type === "monitoring_changed"));
  fx.db.close();
}

// F20: outcome state is workspace-local and the soft-delete gate writes nothing.
{
  const fx = createFixture();
  seedVendor(fx.db, { workspace: "ws1", id: "vendor-ws1", name: "Alpha Tool" });
  seedVendor(fx.db, { workspace: "ws2", id: "vendor-ws2", name: "Beta Tool" });
  seedVendor(fx.db, { workspace: "dead", id: "vendor-dead", name: "Dead Tool" });
  const env = envFor(fx);
  await correlateShadowItInventory(env, "ws1", completeInput);
  const readsAfterWs1 = fx.controls.reads.filter((read) => read.method === "all" &&
    /FROM (workspace_vendors|workspace_assets|identity_assets|email_sender_sources)(?: |$)/i.test(read.sql)).length;
  const deadWritesBefore = fx.controls.writes.length;
  const deadReadsBefore = fx.controls.reads.length;
  const dead = await correlateShadowItInventory(env, "dead", completeInput);
  verdict("F20", queryOne(fx.db, "SELECT COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id='ws1'").n === 1 &&
    queryOne(fx.db, "SELECT COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id='ws2'").n === 0 &&
    queryOne(fx.db, "SELECT COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id='dead'").n === 0 &&
    dead?.skipped === "workspace_inactive" && fx.controls.writes.length === deadWritesBefore &&
    readsAfterWs1 === 4 && fx.controls.reads.length === deadReadsBefore + 1);
  fx.db.close();
}

// F21: additive producer metadata does not change the public string[] field.
{
  const api = shadowItItemToApi({ id: "sii", workspace_id: "ws1", canonical_technology_key: "x", display_name: "X", observed_hostnames_json: '["tenant.example.com"]' });
  verdict("F21", Array.isArray(api.observed_hostnames) && api.observed_hostnames.every((value) => typeof value === "string") &&
    Object.prototype.hasOwnProperty.call(api, "observed_hostnames"));
}

// F22: the corrective may not enter report/snapshot/PDF/score/case sources.
{
  const protectedPaths = [
    "workers/scan-api/src/engines/report-snapshot.js",
    "workers/scan-api/src/engines/pdf.js",
    "workers/scan-api/src/engines/scorecard.js",
    "workers/scan-api/src/engines/managed-case-model.js",
  ];
  const unchanged = protectedPaths.every((relative) => {
    const head = spawnSync("git", ["show", `HEAD:${relative}`], { cwd: root, encoding: null });
    return head.status === 0 && crypto.createHash("sha256").update(head.stdout).digest("hex") ===
      crypto.createHash("sha256").update(fs.readFileSync(path.join(root, relative))).digest("hex");
  });
  verdict("F22", unchanged);
}

function correctionFixture({ workspace = "ws1", hosts = ["https://login.microsoftonline.com"], mixed = false } = {}) {
  const fx = createFixture();
  const refs = evidence("saas_exposure", "saas_portal", null, "Microsoft 365");
  if (mixed) refs.unshift(...evidence("workspace_vendors", "vendor", "vendor-1", "Microsoft 365"));
  seedInventory(fx.db, { workspace, key: "microsoft_365", display: "Microsoft 365", sourceType: mixed ? "vendor,saas_portal" : "saas_portal", sourceEvidence: refs, hosts });
  if (mixed) seedVendor(fx.db, { workspace, id: "vendor-1", name: "Microsoft 365", detail: "customer.example.com" });
  return fx;
}
const pruneCorrection = Object.freeze({ retained: [], removed: ["https://login.microsoftonline.com"] });

// F23: eligible correction is one row change and one material event.
{
  const { fx, saas } = await seedLegacyCatalogueFixture();
  const result = await correlateShadowItInventory(envFor(fx), "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  const events = eventRows(fx.db);
  verdict("F23", JSON.parse(item(fx.db).observed_hostnames_json).length === 0 && events.filter((e) => e.event_type === "material_change" && /catalogue_hostname_prune/.test(e.detail_json)).length === 1 && result.changed === 1 && !events.some((e) => e.event_type === "monitoring_changed"), `result=${json(result)}`);
  fx.db.close();
}

// F24: successful second evaluation is a no-op.
{
  const { fx, saas } = await seedLegacyCatalogueFixture(); const env = envFor(fx);
  await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  const before = { row: item(fx.db).updated_at, events: eventRows(fx.db).length };
  const result = await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  verdict("F24", item(fx.db).updated_at === before.row && eventRows(fx.db).length === before.events && result.changed === 0, `result=${json(result)}`);
  fx.db.close();
}

// F25: event INSERT failure rolls back the row and a clean retry repairs it.
{
  const { fx, saas } = await seedLegacyCatalogueFixture(); const env = envFor(fx); const before = item(fx.db).observed_hostnames_json;
  fx.controls.failFirst.push({ method: "run", pattern: /INSERT INTO shadow_it_inventory_events/i });
  let rejected = false; try { await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW }); } catch { rejected = true; }
  const rolled = item(fx.db).observed_hostnames_json === before && eventRows(fx.db).filter((e) => /catalogue_hostname_prune/.test(e.detail_json)).length === 0;
  await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW });
  verdict("F25", rejected && rolled && eventRows(fx.db).filter((e) => /catalogue_hostname_prune/.test(e.detail_json)).length === 1);
  fx.db.close();
}

// F26: UPDATE failure rolls back the already-executed event INSERT.
{
  const { fx, saas } = await seedLegacyCatalogueFixture(); const env = envFor(fx); const before = item(fx.db).observed_hostnames_json;
  fx.controls.failFirst.push({ method: "run", pattern: /UPDATE shadow_it_inventory SET observed_hostnames_json/i });
  let rejected = false; try { await correlateShadowItInventory(env, "ws1", { saasExposure: saas, subdomainDiscovery: { executed: true }, now: NOW }); } catch { rejected = true; }
  verdict("F26", rejected && item(fx.db).observed_hostnames_json === before && eventRows(fx.db).filter((e) => /catalogue_hostname_prune/.test(e.detail_json)).length === 0);
  fx.db.close();
}

// F27: two pairs derived from one pre-image serialize to one correction.
{
  const fx = correctionFixture(); const env = envFor(fx); const it = item(fx.db); const a = cataloguePruneCorrectionStatements(env, "ws1", it, pruneCorrection, NOW); const b = cataloguePruneCorrectionStatements(env, "ws1", it, pruneCorrection, NOW);
  const first = await env.cybermeters_db.batch(a.statements); const second = await env.cybermeters_db.batch(b.statements);
  verdict("F27", first[0].meta.changes === 1 && first[1].meta.changes === 1 && second[0].meta.changes === 0 && second[1].meta.changes === 0 && eventRows(fx.db).length === 1);
  fx.db.close();
}

// F28: no-op/ineligible correction never issues a batch or event.
{
  const fx = correctionFixture({ hosts: ["customer.example.com"] }); const before = fx.controls.writes.length; const result = await evaluateShadowItMonitoring(envFor(fx), "ws1", { sourceOutcomes: { saas_exposure: "ok", workspace_vendors: "ok", identity_assets: "ok", email_sender_sources: "ok", workspace_assets: "ok" }, seenKeys: new Set(["microsoft_365"]), deferredKeys: new Set(), lookupDeferredKeys: new Set(), currentObservedHostnamesByKey: new Map(), now: NOW });
  verdict("F28", JSON.parse(item(fx.db).observed_hostnames_json).join() === "customer.example.com" && eventRows(fx.db).filter((e) => /catalogue_hostname_prune/.test(e.detail_json)).length === 0 && result.evaluated === 1, `result=${json(result)},writes=${json(fx.controls.writes)},events=${json(eventRows(fx.db))}`); fx.db.close();
}

// F29: workspace authority prevents a foreign item from being corrected.
{
  const fx = correctionFixture({ workspace: "ws2" }); const env = envFor(fx); const before = item(fx.db).observed_hostnames_json; const result = await evaluateShadowItMonitoring(env, "ws1", { inventoryItems: [item(fx.db)], sourceOutcomes: { saas_exposure: "ok" }, seenKeys: new Set(["microsoft_365"]), deferredKeys: new Set(), lookupDeferredKeys: new Set(), currentObservedHostnamesByKey: new Map(), now: NOW });
  verdict("F29", item(fx.db).observed_hostnames_json === before && eventRows(fx.db).length === 0 && result.catalogue_pruned === 0); fx.db.close();
}

// F30: normal entry gate rejects a soft-deleted workspace.
{
  const fx = correctionFixture({ workspace: "dead" }); const before = fx.controls.writes.length; const result = await evaluateShadowItMonitoring(envFor(fx), "dead", { now: NOW });
  verdict("F30", result.skipped === "workspace_inactive" && fx.controls.writes.length === before); fx.db.close();
}

// F31: statement-level active guard remains effective even when entry is bypassed.
{
  const fx = correctionFixture({ workspace: "dead" }); const env = envFor(fx); const result = await env.cybermeters_db.batch(cataloguePruneCorrectionStatements(env, "dead", item(fx.db), pruneCorrection, NOW).statements);
  verdict("F31", result[0].meta.changes === 0 && result[1].meta.changes === 0 && eventRows(fx.db).length === 0); fx.db.close();
}

// F32: event type and exact removed-values payload are preserved.
{
  const fx = correctionFixture(); const env = envFor(fx); await env.cybermeters_db.batch(cataloguePruneCorrectionStatements(env, "ws1", item(fx.db), pruneCorrection, NOW).statements); const event = eventRows(fx.db)[0]; const detail = JSON.parse(event.detail_json);
  verdict("F32", event.event_type === "material_change" && detail.correction === "catalogue_hostname_prune" && json(detail.removed_hostnames) === json(pruneCorrection.removed) && detail.retained_hostname_count === 0); fx.db.close();
}

// F33: an ambiguous successful result can be retried blindly without a duplicate.
{
  const fx = correctionFixture(); const env = envFor(fx); const firstPair = cataloguePruneCorrectionStatements(env, "ws1", item(fx.db), pruneCorrection, NOW); await env.cybermeters_db.batch(firstPair.statements); const retry = await env.cybermeters_db.batch(firstPair.statements);
  verdict("F33", retry[0].meta.changes === 0 && retry[1].meta.changes === 0 && eventRows(fx.db).length === 1 && JSON.parse(item(fx.db).observed_hostnames_json).length === 0, `retry=${json(retry)}, events=${json(eventRows(fx.db))}`); fx.db.close();
}

fs.rmSync(tempRoot, { recursive: true, force: true });
const loadedProof = Object.fromEntries([
  "workers/scan-api/src/engines/shadow-it-inventory.js",
  "workers/scan-api/src/engines/discovery-scan.js",
  "workers/scan-api/src/engines/related-changes-adapter.js",
  "workers/scan-api/src/engines/report-snapshot.js",
].map((relative) => [relative, crypto.createHash("sha256").update(fs.readFileSync(path.join(root, relative))).digest("hex")]));
console.log(`SHADOW_IT_FB1_EH1_LOADED_PROOF ${JSON.stringify(loadedProof)}`);
console.log(`SHADOW_IT_FB1_EH1_NORMAL_SUMMARY ${passed}/${passed + failed} passed`);
console.log(`SHADOW_IT_FB1_EH1_FAIL_SET ${failures.join(",") || "none"}`);
if (failed) process.exit(1);
console.log("Shadow IT FB-1 + EH-1 validation passed");
