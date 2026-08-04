#!/usr/bin/env node
// PR-2B-1 — degraded CT discovery scope cannot drive CT-origin asset lifecycle.
//
// Deterministic production persistence proof. An optional lifecycle module URL
// lets the pinned mutation runner exercise fresh-process source mutants without
// changing checked-in bytes.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (file) => pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", file,
)).href;
const lifecycleUrl = process.env.PR2B1_LIFECYCLE_MODULE_URL ||
  engineUrl("attack-surface-lifecycle.js");
const shadowUrl = process.env.PR2B1_SHADOW_MODULE_URL ||
  engineUrl("shadow-it-inventory.js");
const { persistAttackSurfaceLifecycle } = await import(lifecycleUrl);
const { canonicalTechnologyKey, correlateShadowItInventory } = await import(shadowUrl);
const {
  ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
  ATTACK_SURFACE_SIGNAL_KEYS,
  ASSET_REMOVAL_CONFIRMATION_POLICY,
} = await import(engineUrl("attack-surface-signal-completeness.js"));

let passed = 0;
let failed = 0;
const seen = new Set();
function check(id, condition, detail = "") {
  if (seen.has(id)) throw new Error(`duplicate contract id: ${id}`);
  seen.add(id);
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function equal(id, actual, expected) {
  check(id, Object.is(actual, expected),
    `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

function buildDb(assets) {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    PRAGMA foreign_keys = OFF;
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL);
    CREATE TABLE workspace_assets (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      domain_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      source TEXT,
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
    INSERT INTO workspaces (id, deleted_at) VALUES ('ws', NULL);
    INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws', 'dom');
  `);
  db.exec(fs.readFileSync(path.join(
    root, "database/migrations/102-attack-surface-observation-lifecycle.sql",
  ), "utf8"));
  const insert = db.prepare(`
    INSERT INTO workspace_assets
      (id, workspace_id, domain_id, hostname, source, status, updated_at,
       lifecycle_state, last_observation_state, lifecycle_policy_version,
       confirmed_removed_at, last_observation_scan_id)
    VALUES (?, 'ws', 'dom', ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const asset of assets) {
    insert.run(
      asset.id,
      asset.hostname,
      asset.source ?? "certificate_transparency",
      asset.status ?? "active",
      asset.updated_at ?? "2026-07-01T00:00:00.000Z",
      asset.lifecycle_state ?? "not_assessed",
      asset.last_observation_state ?? "not_assessed",
      ASSET_REMOVAL_CONFIRMATION_POLICY.version,
      asset.confirmed_removed_at ?? null,
      asset.last_observation_scan_id ?? null,
    );
  }
  return db;
}

function makeFixtureD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => Promise.all(statements.map((entry) =>
      /^\s*select/i.test(entry.__sql) ? entry.all() : entry.run())),
  };
}

function buildShadowDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* additive drift */ }
  };
  apply(path.join(root, "database/schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database/migrations"))
    .filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", file));
  }
  db.exec(`
    PRAGMA foreign_keys = OFF;
    INSERT INTO users (id, email, name) VALUES ('u-shadow', 'shadow@example.com', 'Shadow Owner');
    INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at)
      VALUES ('ws-shadow', 'Shadow fixture', 'u-shadow', datetime('now'), datetime('now'));
    INSERT INTO domains (id, user_id, domain) VALUES ('dom-shadow', 'u-shadow', 'example.com');
    INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-shadow', 'dom-shadow');
    INSERT INTO workspace_assets
      (id, workspace_id, domain_id, hostname, asset_type, source, first_seen,
       last_seen, status, cloud_provider, created_at, updated_at)
    VALUES
      ('asset-shadow-ct', 'ws-shadow', 'dom-shadow', 'shop.example.com', 'subdomain',
       'certificate_transparency', '2026-07-01T00:00:00.000Z',
       '2026-07-01T00:00:00.000Z', 'active', 'Shopify', datetime('now'), datetime('now'));
  `);
  return db;
}

async function seedShadowItem(db) {
  const env = { cybermeters_db: makeFixtureD1(db) };
  await correlateShadowItInventory(env, "ws-shadow", {
    subdomainDiscovery: healthyScope,
    now: "2026-07-01T00:00:00.000Z",
  });
  return env;
}

function signalCompleteness() {
  return {
    model_version: ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
    signals: Object.fromEntries(ATTACK_SURFACE_SIGNAL_KEYS.map((key) => [
      key,
      {
        state: key === "subdomain_discovery" ? "observed" : "not_assessed",
        reason: key === "subdomain_discovery" ? "hostname_observed" : "fixture_not_assessed",
        evidence_count: key === "subdomain_discovery" ? 1 : 0,
        sources: key === "subdomain_discovery" ? ["crt_sh", "certspotter"] : [],
        limitations: [],
      },
    ])),
  };
}

const negative = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "absent", reason: "authoritative_a_aaaa_absence" },
    http_https_service: { state: "not_observed", reason: "http_service_not_observed" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});
const observed = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "observed", reason: "active_dns_records_observed" },
    http_https_service: { state: "observed", reason: "http_response_observed" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});
const healthyScope = {
  items: ["asset.example.com"],
  sources: {
    crt_sh: { count: 1, error: null },
    certspotter: { count: 1, error: null },
  },
  error: null,
};
const degradedScope = {
  items: ["asset.example.com"],
  sources: {
    crt_sh: { count: 0, error: "HTTP 502" },
    certspotter: { count: 1, error: null },
  },
  incomplete: true,
  incomplete_reason: "ct_source_degraded",
  error: null,
};

function addQualifying(db, assetId, scanId, observedAt) {
  db.prepare(`
    INSERT INTO asset_lifecycle_observations
      (id, workspace_id, domain_id, asset_id, scan_id, observation_state,
       dns_state, http_state, qualifies_removal, policy_version,
       source_detail_json, observed_at)
    VALUES (?, 'ws', 'dom', ?, ?, 'not_observed', 'absent', 'not_observed',
            1, ?, '{}', ?)
  `).run(`alo-${assetId}-${scanId}`, assetId, scanId,
    ASSET_REMOVAL_CONFIRMATION_POLICY.version, observedAt);
}

async function persist(db, { scanId, observedAt, rows, scope }) {
  await persistAttackSurfaceLifecycle({
    env: { cybermeters_db: makeFixtureD1(db) },
    scanId,
    domainId: "dom",
    domain: "example.com",
    signalCompleteness: signalCompleteness(),
    assetExposure: { removal_observations: rows },
    subdomainDiscovery: scope,
    observedAt,
  });
}

// 1. A degraded CT scan is neither negative nor positive lifecycle evidence.
{
  const db = buildDb([
    {
      id: "asset-progress",
      hostname: "asset.example.com",
      lifecycle_state: "not_observed",
      last_observation_state: "not_observed",
    },
    {
      id: "asset-removed",
      hostname: "removed.example.com",
      status: "inactive",
      lifecycle_state: "confirmed_removed",
      last_observation_state: "not_observed",
      confirmed_removed_at: "2026-07-01T00:00:00.000Z",
    },
  ]);
  addQualifying(db, "asset-progress", "healthy-before", "2026-07-01T00:00:00.000Z");
  await persist(db, {
    scanId: "degraded",
    observedAt: "2026-07-02T00:00:00.000Z",
    rows: [negative("asset.example.com"), observed("removed.example.com")],
    scope: degradedScope,
  });
  const progress = db.prepare("SELECT * FROM workspace_assets WHERE id='asset-progress'").get();
  const removed = db.prepare("SELECT * FROM workspace_assets WHERE id='asset-removed'").get();
  const degradedRows = db.prepare(`
    SELECT asset_id, observation_state, qualifies_removal, dns_state, http_state
    FROM asset_lifecycle_observations WHERE scan_id='degraded' ORDER BY asset_id
  `).all();
  equal("DEGRADED_EXPLICIT_INCOMPLETE", progress.last_observation_state, "observation_incomplete");
  equal("DEGRADED_NO_ABSENCE_PROGRESS", progress.lifecycle_state, "not_observed");
  equal("DEGRADED_QUALIFYING_CLOCK_PRESERVED",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-progress' AND qualifies_removal=1").get().n, 1);
  check("DEGRADED_ROWS_NEVER_QUALIFY", degradedRows.every((row) => row.qualifies_removal === 0));
  equal("DEGRADED_NO_RESET_OF_REMOVED_STATE", removed.lifecycle_state, "confirmed_removed");
  equal("DEGRADED_NO_REOPEN_EVENT",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_reappeared'").get().n, 0);
  equal("DEGRADED_NO_REMOVAL_EVENT",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen'").get().n, 0);
  const presentationSource = fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/attack-surface-customer-presentation.js",
  ), "utf8");
  check("DEGRADED_CUSTOMER_LABEL",
    /observation_incomplete:\s*"Evidence incomplete"/.test(presentationSource));
  check("DEGRADED_CUSTOMER_NO_ABSENCE_CLAIM",
    /relevant lifecycle evidence was incomplete and did not advance removal confirmation/.test(
      presentationSource,
    ));
}

// Executed:false reuses the existing not_assessed state rather than an absence.
{
  const db = buildDb([{ id: "asset-deadline", hostname: "deadline.example.com" }]);
  await persist(db, {
    scanId: "deadline",
    observedAt: "2026-07-02T00:00:00.000Z",
    rows: [negative("deadline.example.com")],
    scope: { executed: false, incomplete: true },
  });
  const row = db.prepare("SELECT * FROM workspace_assets WHERE id='asset-deadline'").get();
  equal("DEADLINE_EXPLICIT_NOT_ASSESSED", row.last_observation_state, "not_assessed");
  equal("DEADLINE_NO_ABSENCE_STATE", row.lifecycle_state, "not_assessed");
}

// 2. Healthy CT scope retains the existing confirmed-removal and reappearance path.
{
  const db = buildDb([{
    id: "asset-healthy",
    hostname: "healthy.example.com",
    lifecycle_state: "not_observed",
    last_observation_state: "not_observed",
  }]);
  addQualifying(db, "asset-healthy", "healthy-1", "2026-07-01T00:00:00.000Z");
  addQualifying(db, "asset-healthy", "healthy-2", "2026-07-02T00:00:00.000Z");
  await persist(db, {
    scanId: "healthy-3",
    observedAt: "2026-07-03T00:00:00.000Z",
    rows: [negative("healthy.example.com")],
    scope: healthyScope,
  });
  let row = db.prepare("SELECT * FROM workspace_assets WHERE id='asset-healthy'").get();
  equal("HEALTHY_CONFIRMS_REMOVAL_UNCHANGED", row.lifecycle_state, "confirmed_removed");
  equal("HEALTHY_PROJECTS_INACTIVE_UNCHANGED", row.status, "inactive");
  equal("HEALTHY_EMITS_REMOVAL_UNCHANGED",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_no_longer_seen'").get().n, 1);
  await persist(db, {
    scanId: "healthy-reappeared",
    observedAt: "2026-07-04T00:00:00.000Z",
    rows: [observed("healthy.example.com")],
    scope: healthyScope,
  });
  row = db.prepare("SELECT * FROM workspace_assets WHERE id='asset-healthy'").get();
  equal("HEALTHY_REAPPEARANCE_UNCHANGED", row.lifecycle_state, "observed");
  equal("HEALTHY_EMITS_REAPPEARANCE_UNCHANGED",
    db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE event_type='asset_reappeared'").get().n, 1);
}

// 3. Healthy -> degraded -> healthy resumes from the last assessable state.
{
  const db = buildDb([{ id: "asset-sequence", hostname: "sequence.example.com" }]);
  await persist(db, {
    scanId: "sequence-1",
    observedAt: "2026-07-01T00:00:00.000Z",
    rows: [negative("sequence.example.com")],
    scope: healthyScope,
  });
  await persist(db, {
    scanId: "sequence-degraded",
    observedAt: "2026-07-02T00:00:00.000Z",
    rows: [observed("sequence.example.com")],
    scope: degradedScope,
  });
  equal("SEQUENCE_DEGRADED_DOES_NOT_RESET_CLOCK",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-sequence' AND qualifies_removal=1").get().n, 1);
  await persist(db, {
    scanId: "sequence-2",
    observedAt: "2026-07-03T00:00:00.000Z",
    rows: [negative("sequence.example.com")],
    scope: healthyScope,
  });
  equal("SEQUENCE_NEXT_HEALTHY_RESUMES_AT_TWO",
    db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id='asset-sequence' AND qualifies_removal=1").get().n, 2);
  equal("SEQUENCE_NOT_PREMATURELY_REMOVED",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-sequence'").get().lifecycle_state, "not_observed");
  await persist(db, {
    scanId: "sequence-3",
    observedAt: "2026-07-04T00:00:00.000Z",
    rows: [negative("sequence.example.com")],
    scope: healthyScope,
  });
  equal("SEQUENCE_THIRD_ASSESSABLE_CONFIRMS",
    db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-sequence'").get().lifecycle_state, "confirmed_removed");
  equal("SEQUENCE_DEGRADED_ROW_NEVER_QUALIFIES",
    db.prepare("SELECT qualifies_removal FROM asset_lifecycle_observations WHERE scan_id='sequence-degraded'").get().qualifies_removal, 0);
}

// 4. The gate follows the module's explicit scope policy. It does not inspect a
// provider error and independently declare blindness when the carrier says the
// channel is adequate.
{
  const db = buildDb([{
    id: "asset-provider-control",
    hostname: "provider-control.example.com",
    lifecycle_state: "not_observed",
    last_observation_state: "not_observed",
  }]);
  addQualifying(db, "asset-provider-control", "provider-before", "2026-07-01T00:00:00.000Z");
  await persist(db, {
    scanId: "provider-control",
    observedAt: "2026-07-02T00:00:00.000Z",
    rows: [negative("provider-control.example.com")],
    scope: {
      items: ["provider-control.example.com"],
      sources: {
        crt_sh: { count: 0, error: "HTTP 502" },
        certspotter: { count: 1, error: null },
      },
      incomplete: false,
      error: null,
    },
  });
  const observation = db.prepare("SELECT * FROM asset_lifecycle_observations WHERE scan_id='provider-control'").get();
  equal("PROVIDER_DECLARED_ADEQUATE_USES_ACTIVE_EVIDENCE", observation.observation_state, "not_observed");
  equal("PROVIDER_DECLARED_ADEQUATE_ADVANCES_NORMALLY", observation.qualifies_removal, 1);
}

const lifecycleSource = fs.readFileSync(path.join(
  root, "workers/scan-api/src/engines/attack-surface-lifecycle.js",
), "utf8");
const scanEngineSource = fs.readFileSync(path.join(
  root, "workers/scan-api/src/engines/scan-engine.js",
), "utf8");
check("RUNTIME_SELECTS_PERSISTED_ASSET_SOURCE",
  /SELECT id, hostname, source, status, lifecycle_state/.test(lifecycleSource));
check("RUNTIME_PASSES_EXISTING_SCOPE_CARRIER",
  /subdomainDiscovery: modules\.subdomains/.test(scanEngineSource));
check("RUNTIME_PASSES_SCOPE_TO_SHADOW_BOUNDARY",
  /correlateShadowItInventory\(env, workspace_id, \{ saasExposure: modules\.saas_exposure, subdomainDiscovery: modules\.subdomains \|\| \{ executed: false \} \}\)/.test(
    scanEngineSource,
  ));

// 5. The same CT-origin asset evidence can feed Shadow IT through
// workspace_assets.cloud_provider. Degraded CT scope freezes that downstream
// item unless another independent observation source sees the same technology.
{
  const db = buildShadowDb();
  const env = await seedShadowItem(db);
  const before = db.prepare(`
    SELECT * FROM shadow_it_inventory
    WHERE workspace_id='ws-shadow' AND canonical_technology_key='shopify'
  `).get();
  const eventsBefore = db.prepare(`
    SELECT COUNT(*) AS n FROM shadow_it_inventory_events WHERE item_id=?
  `).get(before.id).n;
  db.prepare(`
    UPDATE workspace_assets SET last_seen='2026-07-02T00:00:00.000Z'
    WHERE id='asset-shadow-ct'
  `).run();
  await correlateShadowItInventory(env, "ws-shadow", {
    subdomainDiscovery: degradedScope,
    now: "2026-07-02T00:00:00.000Z",
  });
  let row = db.prepare("SELECT * FROM shadow_it_inventory WHERE id=?").get(before.id);
  equal("SHADOW_DEGRADED_NO_DISAPPEARANCE", row.monitoring_status, "observed");
  equal("SHADOW_DEGRADED_NO_LAST_SEEN_REFRESH", row.last_seen_at, before.last_seen_at);
  equal("SHADOW_DEGRADED_NO_DISAPPEARANCE_EVENT",
    db.prepare(`SELECT COUNT(*) AS n FROM shadow_it_inventory_events WHERE item_id=?`).get(before.id).n,
    eventsBefore);

  db.prepare(`
    UPDATE shadow_it_inventory
    SET classification='rejected', monitoring_status='no_longer_observed',
        recurrence_type=NULL, required_case_action='none'
    WHERE id=?
  `).run(before.id);
  await correlateShadowItInventory(env, "ws-shadow", {
    subdomainDiscovery: degradedScope,
    now: "2026-07-03T00:00:00.000Z",
  });
  row = db.prepare("SELECT * FROM shadow_it_inventory WHERE id=?").get(before.id);
  equal("SHADOW_DEGRADED_NO_REAPPEARANCE", row.monitoring_status, "no_longer_observed");
  equal("SHADOW_DEGRADED_NO_CASE_REOPEN",
    db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws-shadow'").get().n,
    0);

  const reappearanceEventsBefore = db.prepare(`
    SELECT COUNT(*) AS n FROM shadow_it_inventory_events
    WHERE item_id=? AND event_type='monitoring_changed'
  `).get(before.id).n;
  await correlateShadowItInventory(env, "ws-shadow", {
    subdomainDiscovery: healthyScope,
    now: "2026-07-04T00:00:00.000Z",
  });
  row = db.prepare("SELECT * FROM shadow_it_inventory WHERE id=?").get(before.id);
  const reappearanceEventsAfter = db.prepare(`
    SELECT COUNT(*) AS n FROM shadow_it_inventory_events
    WHERE item_id=? AND event_type='monitoring_changed'
  `).get(before.id).n;
  check("SHADOW_HEALTHY_RESUMES_REAPPEARANCE",
    row.monitoring_status === "reappeared" &&
    reappearanceEventsAfter > reappearanceEventsBefore,
    `status=${row.monitoring_status}, events=${reappearanceEventsBefore}->${reappearanceEventsAfter}`);
}

{
  const db = buildShadowDb();
  const env = await seedShadowItem(db);
  const row = db.prepare(`
    SELECT * FROM shadow_it_inventory
    WHERE workspace_id='ws-shadow' AND canonical_technology_key='shopify'
  `).get();
  db.prepare(`
    UPDATE shadow_it_inventory
    SET classification='rejected', monitoring_status='observed',
        recurrence_type=NULL, monitoring_reason=NULL,
        required_case_action='none', linked_case_id=NULL
    WHERE id=?
  `).run(row.id);
  db.prepare(`
    INSERT INTO workspace_vendors
      (id, workspace_id, vendor_name, category, source, evidence, confidence,
       risk_level, first_seen, last_seen, status, created_at, updated_at)
    VALUES
      ('vendor-shopify', 'ws-shadow', 'Shopify', 'saas', 'cname', '[]', 'medium',
       'low', '2026-07-01T00:00:00.000Z', '2026-07-02T00:00:00.000Z',
       'active', datetime('now'), datetime('now'))
  `).run();

  const ctInput = db.prepare(`
    SELECT source, cloud_provider FROM workspace_assets
    WHERE id='asset-shadow-ct' AND workspace_id='ws-shadow'
  `).get();
  const vendorInput = db.prepare(`
    SELECT id, vendor_name, status FROM workspace_vendors
    WHERE id='vendor-shopify' AND workspace_id='ws-shadow'
  `).get();
  const ctKey = canonicalTechnologyKey(ctInput.cloud_provider);
  const independentKey = canonicalTechnologyKey(vendorInput.vendor_name);
  check("SHADOW_INDEPENDENT_CT_KEY_IS_DEFERRED_INPUT",
    degradedScope.incomplete === true &&
    ctInput.source === "certificate_transparency" &&
    ctKey === row.canonical_technology_key,
    `incomplete=${degradedScope.incomplete}, source=${ctInput.source}, key=${ctKey}`);
  check("SHADOW_INDEPENDENT_VENDOR_SOURCE_IS_PRESENT",
    vendorInput.status === "active" && independentKey === row.canonical_technology_key,
    `status=${vendorInput.status}, key=${independentKey}`);

  const pre = db.prepare("SELECT * FROM shadow_it_inventory WHERE id=?").get(row.id);
  const preCases = db.prepare(`
    SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws-shadow'
  `).get().n;
  const preTransitions = db.prepare(`
    SELECT detail_json FROM shadow_it_inventory_events
    WHERE item_id=? AND event_type='monitoring_changed'
  `).all(row.id).filter((event) => {
    try { return JSON.parse(event.detail_json)?.to_recurrence_type === "rejected_reappeared"; }
    catch { return false; }
  }).length;
  check("SHADOW_INDEPENDENT_PHASE2_STATE_ABSENT_BEFORE",
    pre.classification === "rejected" &&
    pre.monitoring_status === "observed" &&
    pre.recurrence_type == null &&
    pre.required_case_action === "none" &&
    pre.linked_case_id == null &&
    preCases === 0 && preTransitions === 0,
    `classification=${pre.classification}, monitoring=${pre.monitoring_status}, ` +
      `recurrence=${pre.recurrence_type}, action=${pre.required_case_action}, ` +
      `linked_case=${pre.linked_case_id}, cases=${preCases}, transitions=${preTransitions}`);

  const result = await correlateShadowItInventory(env, "ws-shadow", {
    subdomainDiscovery: degradedScope,
    now: "2026-07-02T00:00:00.000Z",
  });
  const after = db.prepare("SELECT * FROM shadow_it_inventory WHERE id=?").get(row.id);
  const evidence = JSON.parse(after.source_evidence_json || "[]");
  const independentEvidence = evidence.find((entry) =>
    entry.source_table === "workspace_vendors" &&
    entry.source_record_id === vendorInput.id &&
    entry.observed_identifier === vendorInput.vendor_name);
  check("SHADOW_INDEPENDENT_SOURCE_WAS_COLLECTED",
    result.correlated === 1 && Boolean(independentEvidence),
    `correlated=${result.correlated}, evidence=${JSON.stringify(evidence)}`);
  check("SHADOW_INDEPENDENT_SOURCE_RESOLVES_CANONICAL_KEY",
    after.canonical_technology_key === independentKey && independentKey === ctKey,
    `inventory=${after.canonical_technology_key}, independent=${independentKey}, ct=${ctKey}`);
  check("SHADOW_INDEPENDENT_KEY_IS_DEFERRED_AND_SEEN",
    degradedScope.incomplete === true &&
    ctInput.source === "certificate_transparency" &&
    ctKey === after.canonical_technology_key &&
    result.correlated === 1 && Boolean(independentEvidence),
    `deferred=${ctKey}, seen=${independentKey}, correlated=${result.correlated}`);
  check("SHADOW_INDEPENDENT_SOURCE_REMAINS_ASSESSABLE",
    after.monitoring_status === "observed" &&
    after.recurrence_type === "rejected_reappeared" &&
    after.required_case_action === "open_or_reopen",
    `monitoring=${after.monitoring_status}, recurrence=${after.recurrence_type}, ` +
      `action=${after.required_case_action}`);

  const transitions = db.prepare(`
    SELECT detail_json FROM shadow_it_inventory_events
    WHERE item_id=? AND event_type='monitoring_changed'
  `).all(row.id).map((event) => {
    try { return JSON.parse(event.detail_json); } catch { return null; }
  }).filter(Boolean);
  const recurrenceTransition = transitions.find((detail) =>
    detail.to_recurrence_type === "rejected_reappeared");
  check("SHADOW_INDEPENDENT_PHASE2_TRANSITION_RECORDED",
    recurrenceTransition?.required_case_action === "open_or_reopen" &&
    recurrenceTransition?.entity === row.canonical_technology_key,
    `transitions=${JSON.stringify(transitions)}`);

  const linkedCaseCount = after.linked_case_id == null ? 0 : db.prepare(`
    SELECT COUNT(*) AS n FROM managed_cases
    WHERE id=? AND workspace_id='ws-shadow'
  `).get(after.linked_case_id).n;
  check("SHADOW_INDEPENDENT_PHASE2_CASE_CREATED",
    result.monitoring?.cases === 1 && after.linked_case_id != null && linkedCaseCount === 1,
    `cases=${result.monitoring?.cases}, linked_case=${after.linked_case_id}, rows=${linkedCaseCount}`);
}

console.log(`\nPR-2B-1 CT asset lifecycle scope: ${passed}/${passed + failed} contracts passed`);
if (failed) process.exit(1);
console.log("PR-2B-1 CT asset lifecycle scope validation passed");
