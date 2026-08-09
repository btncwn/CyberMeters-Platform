#!/usr/bin/env node
// Item 10 P3 — deterministic asset lifecycle → canonical ASM case integration.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(
  root, "workers/scan-api/src/engines", name,
)).href;
const fixture = JSON.parse(fs.readFileSync(path.join(
  root, "scripts/fixtures/item10-p3-asset-lifecycle-cases.json",
), "utf8"));
const lifecycleUrl = process.env.ITEM10_P3_LIFECYCLE_MODULE_URL ||
  engine("attack-surface-lifecycle.js");
const casesUrl = process.env.ITEM10_P3_CASES_MODULE_URL ||
  engine("asm-cases.js");
const signalUrl = process.env.ITEM10_P3_SIGNAL_MODULE_URL ||
  engine("attack-surface-signal-completeness.js");
const {
  persistAttackSurfaceLifecycle,
} = await import(lifecycleUrl);
const {
  assignManagedCaseOwner,
  createManagedAsmCasesForScan,
  getManagedCase,
  transitionManagedCase,
  verifyManagedAsmCasesForScan,
} = await import(casesUrl);
const {
  ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
  ATTACK_SURFACE_SIGNAL_KEYS,
  ASSET_REMOVAL_CONFIRMATION_POLICY,
  deriveRemovalObservation,
} = await import(signalUrl);
const { takeoverObservationFor } = await import(engine("takeover-scan.js"));

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

function buildDb({ applyMigration102 = true } = {}) {
  const db = new DatabaseSync(":memory:");
  const apply = (file, required = false) => {
    try {
      db.exec(fs.readFileSync(file, "utf8"));
      return true;
    } catch (error) {
      if (required) throw error;
      return false;
    }
  };
  apply(path.join(root, "database/schema.sql"));
  let migration102Applied = false;
  for (const file of fs.readdirSync(path.join(root, "database/migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    const is102 = file === "102-attack-surface-observation-lifecycle.sql";
    if (is102 && !applyMigration102) continue;
    const applied = apply(path.join(root, "database/migrations", file), is102);
    if (is102) migration102Applied = applied;
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return { db, migration102Applied };
}

function makeD1(db, counters) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      if (/^\s*(?:select|with)\b/i.test(sql)) counters.reads += 1;
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => {
      if (/^\s*(?:select|with)\b/i.test(sql)) counters.reads += 1;
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
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
    batch: async (statements) => {
      counters.batches += 1;
      return Promise.all(statements.map((entry) =>
        /^\s*(?:select|with)\b/i.test(entry.__sql) ? entry.all() : entry.run()));
    },
  };
}

function signalCompleteness() {
  return {
    model_version: ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
    signals: Object.fromEntries(ATTACK_SURFACE_SIGNAL_KEYS.map((key) => [
      key,
      {
        state: key === "subdomain_discovery" ? "observed" : "not_assessed",
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
const dnsOnly = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "observed", reason: "a_record_observed" },
    http_https_service: { state: "not_observed", reason: "connection_refused" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});
const httpOnly = (host) => ({
  host,
  signal_states: {
    dns_resolution: { state: "absent", reason: "authoritative_a_aaaa_absence" },
    http_https_service: { state: "observed", reason: "http_response_observed" },
  },
  active_sources: ["dns_resolution", "http_https_service"],
  passive_sources: [],
});

const { db, migration102Applied } = buildDb();
const counters = { reads: 0, batches: 0 };
const env = { cybermeters_db: makeD1(db, counters) };
const domain = fixture.domain;
const hostname = fixture.hostname;

db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')").run();
for (const [id, name, deletedAt] of [
  ["ws", "Active", null],
  ["ws-deleted", "Deleted", "2026-07-01T00:00:00.000Z"],
  ["ws-foreign", "Foreign", null],
]) {
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES (?,?,?)")
    .run(id, name, deletedAt);
}
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr',?)")
  .run(domain);
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom-foreign','usr','foreign.test')")
  .run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')")
  .run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-deleted','dom')")
  .run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-foreign','dom-foreign')")
  .run();
db.prepare(`
  INSERT INTO workspace_assets
    (id, workspace_id, domain_id, hostname, asset_type, source,
     first_seen, last_seen, status, wildcard_dns, created_at, updated_at,
     lifecycle_state, last_observation_state)
  VALUES
    ('asset-admin','ws','dom','admin.example.com','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','observed','observed'),
    ('asset-dns-only','ws','dom','dns-only.example.com','subdomain','dns_bruteforce',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','observed','observed'),
    ('asset-http-only','ws','dom','http-only.example.com','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','observed','observed'),
    ('asset-deleted','ws-deleted','dom','admin.example.com','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','observed','observed'),
    ('asset-foreign','ws-foreign','dom-foreign','admin.foreign.test','exposed_service','exposure_probe',
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','active',0,
     '2026-07-01T00:00:00.000Z','2026-07-01T00:00:00.000Z','observed','observed')
`).run();
db.prepare(`
  INSERT INTO managed_cases
    (id, workspace_id, case_type, domain_key, domain, finding_id,
     source_finding_type, source_scan_id, asset_ref, severity, status,
     evidence_json, created_by, created_at, updated_at)
  VALUES
    ('case-deleted','ws-deleted','asm_exposure','attack_surface',?,
     'asset_exposure_sensitive_tool','asset_exposure_sensitive_tool','scan-seed',
     'admin.example.com','high','verification_requested',?,
     'system',datetime('now'),datetime('now')),
    ('case-foreign','ws-foreign','asm_exposure','attack_surface','foreign.test',
     'asset_exposure_sensitive_tool','asset_exposure_sensitive_tool','scan-seed',
     'admin.foreign.test','high','verification_requested',?,
     'system',datetime('now'),datetime('now'))
`).run(
  domain,
  JSON.stringify({ finding: fixture.finding }),
  JSON.stringify({ finding: { ...fixture.finding, affected_hosts: ["admin.foreign.test"] } }),
);

ok("migration 102 applies exactly in the fresh compatibility database",
  migration102Applied);
eq("migration 102 lifecycle default remains separate from legacy status",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-admin'").get().lifecycle_state,
  "observed");
eq("P3 keeps the P1 threshold",
  ASSET_REMOVAL_CONFIRMATION_POLICY.required_qualifying_observations,
  fixture.removal_contract.required_qualifying_observations);

const firstCreate = await createManagedAsmCasesForScan(
  "scan-seed", "dom", domain, [fixture.finding], [], env,
);
eq("ASM finding creates one case through the production creator", firstCreate.opened, 1);
let kase = db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws'").get();
eq("ASM registry-owned initial state remains open", kase.status, "open");
eq("case stores the stable affected asset reference", kase.asset_ref, hostname);
eq("canonical case factory writes case_created once",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=? AND action='case_created'").get(kase.id).n,
  1);
await createManagedAsmCasesForScan(
  "scan-seed", "dom", domain, [fixture.finding], [], env,
);
eq("repeated source scan creates no duplicate case",
  db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws'").get().n,
  1);
eq("repeated source scan creates no duplicate occurrence source",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=? AND action='monitoring_changed'").get(kase.id).n,
  1);

const illegalBypass = await transitionManagedCase(env, kase, "remediation_in_progress", {
  actor_type: "system",
});
eq("direct open to remediation transition bypass is refused",
  illegalBypass.ok, false);
eq("refused bypass writes no status change",
  (await getManagedCase(env, "ws", kase.id)).status,
  "open");

let transition = await transitionManagedCase(env, kase, "triage", {
  actor_type: "customer",
  actor_id: "usr",
});
ok("open to triage uses canonical transition", transition.ok);
kase = transition.case;
transition = await assignManagedCaseOwner(env, kase, {
  owner_type: "person",
  owner_ref: "Security owner",
  assigned_by: "customer",
  actor_id: "usr",
});
ok("triage to owner_assigned uses canonical ownership and machine", transition.ok);
kase = transition.case;
transition = await transitionManagedCase(env, kase, "remediation_in_progress", {
  actor_type: "customer",
  actor_id: "usr",
});
ok("owner_assigned to remediation uses canonical transition", transition.ok);
kase = transition.case;
transition = await transitionManagedCase(env, kase, "verification_requested", {
  actor_type: "customer",
  actor_id: "usr",
});
ok("customer action reaches canonical awaiting-verification phase", transition.ok);
kase = transition.case;
eq("ASM persisted awaiting-verification state is verification_requested",
  kase.status, "verification_requested");

const customerVerify = await transitionManagedCase(env, kase, "resolved", {
  actor_type: "customer",
  actor_id: "usr",
  evidence: {
    verification_method: "manual_attestation",
    verification_result: "verified",
    evidence_type: "customer_assertion",
    observed_at: fixture.clock.first_negative,
    attestation: { note: "I removed it" },
  },
});
eq("customer assertion cannot verify an automated ASM case",
  customerVerify.ok, false);
eq("customer assertion leaves case awaiting verification",
  (await getManagedCase(env, "ws", kase.id)).status,
  "verification_requested");

async function persist(scanId, observedAt, rows) {
  await persistAttackSurfaceLifecycle({
    env,
    scanId,
    domainId: "dom",
    domain,
    signalCompleteness: signalCompleteness(),
    assetExposure: { removal_observations: rows },
    observedAt,
  });
}
const completeVerification = {
  modules: { asset_exposure: { checked: 1, assets: [] } },
  scanQuality: { status: "complete", modules_skipped: [] },
  scanPublished: true,
};

await persist("scan-facets", "2026-07-26T10:00:00.000Z", [
  observed(hostname),
  dnsOnly("dns-only.example.com"),
  httpOnly("http-only.example.com"),
]);
eq("DNS-only asset remains observed, never absent",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-dns-only'").get().lifecycle_state,
  "observed");
eq("HTTP-only asset remains observed, never absent",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-http-only'").get().lifecycle_state,
  "observed");
eq("pure contract also refuses DNS-only absence",
  deriveRemovalObservation(dnsOnly("x.example.com").signal_states),
  "observed");
eq("pure contract also refuses HTTP-only absence",
  deriveRemovalObservation(httpOnly("x.example.com").signal_states),
  "observed");
const unconfirmedTakeover = takeoverObservationFor({
  checked_hosts: [hostname],
  risks: [],
  unconfirmed: [{ host: hostname, reason: "provider_probe_failed" }],
}, hostname);
eq("takeover candidate is not a confirmed takeover",
  unconfirmedTakeover.status, "probe_unconfirmed");
eq("unconfirmed takeover evidence is incomplete",
  unconfirmedTakeover.complete, false);

await persist("scan-1", fixture.clock.first_negative, [negative(hostname)]);
let verification = await verifyManagedAsmCasesForScan(
  "scan-1", "dom", domain, [], env, completeVerification,
);
eq("one missing observation does not close the case", verification.resolved, 0);
eq("first missing observation is deferred", verification.deferred, 1);

await persist("scan-unavailable", fixture.clock.unavailable, [unavailable(hostname)]);
verification = await verifyManagedAsmCasesForScan(
  "scan-unavailable", "dom", domain, [], env, {
    modules: { asset_exposure: { incomplete: true, error: "provider timeout" } },
    scanQuality: { status: "partial", modules_skipped: ["asset_exposure"] },
    scanPublished: true,
  },
);
eq("unavailable scan cannot close the case", verification.resolved, 0);
eq("unavailable scan cannot advance threshold",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE asset_id=? AND qualifies_removal=1").get(fixture.asset_id).n,
  1);

await persist("scan-2", fixture.clock.second_negative, [negative(hostname)]);
await verifyManagedAsmCasesForScan(
  "scan-2", "dom", domain, [], env, completeVerification,
);
await persist("scan-3", fixture.clock.confirmed_removed, [negative(hostname)]);
verification = await verifyManagedAsmCasesForScan(
  "scan-3", "dom", domain, [], env, completeVerification,
);
eq("third observation establishes confirmed_removed",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id=?").get(fixture.asset_id).lifecycle_state,
  "confirmed_removed");
eq("first confirmed-removal transition does not close the case",
  verification.resolved, 0);
eq("case remains awaiting later CyberMeters re-observation",
  (await getManagedCase(env, "ws", kase.id)).status,
  "verification_requested");
eq("confirmed removal emits one append-only lifecycle event",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE asset_id=? AND event_type='asset_no_longer_seen'").get(fixture.asset_id).n,
  1);

await persist("scan-4", fixture.clock.later_reobservation, [negative(hostname)]);
verification = await verifyManagedAsmCasesForScan(
  "scan-4", "dom", domain, [], env, completeVerification,
);
eq("later complete publishable re-observation resolves the case",
  verification.resolved, 1);
kase = await getManagedCase(env, "ws", kase.id);
eq("canonical ASM verified state is resolved", kase.status, "resolved");
ok("canonical verified timestamp is recorded", Boolean(kase.verified_at));
eq("verification evidence is append-only and identifies lifecycle re-observation",
  JSON.parse(db.prepare(
    "SELECT detail_json FROM managed_case_events WHERE case_id=? AND action='verified_resolved' ORDER BY rowid DESC LIMIT 1",
  ).get(kase.id).detail_json).lifecycle.later_reobservation,
  true);

const caseEventCountBeforeReplay = db.prepare(
  "SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?",
).get(kase.id).n;
await persist("scan-4", fixture.clock.later_reobservation, [negative(hostname)]);
await verifyManagedAsmCasesForScan(
  "scan-4", "dom", domain, [], env, completeVerification,
);
eq("replayed scan duplicates no case event",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(kase.id).n,
  caseEventCountBeforeReplay);
eq("replayed scan duplicates no removal event",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE asset_id=? AND event_type='asset_no_longer_seen'").get(fixture.asset_id).n,
  1);

await persist("scan-5", fixture.clock.reappeared, [observed(hostname)]);
await createManagedAsmCasesForScan(
  "scan-5", "dom", domain, [fixture.finding], [], env,
);
kase = await getManagedCase(env, "ws", kase.id);
eq("reappearance reopens the same case into remediation", kase.status, "remediation_in_progress");
eq("reappearance increments recurrence exactly once", Number(kase.reopened_count), 1);
eq("reappearance preserves the same asset identity",
  db.prepare("SELECT asset_id FROM asset_events WHERE event_type='asset_reappeared'").get().asset_id,
  fixture.asset_id);
eq("workspace asset primary identity itself is unchanged",
  db.prepare("SELECT id FROM workspace_assets WHERE workspace_id='ws' AND hostname=?").get(hostname).id,
  fixture.asset_id);
eq("reappearance creates no replacement asset row",
  db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id='ws' AND hostname=?").get(hostname).n,
  1);
await persist("scan-5", fixture.clock.reappeared, [observed(hostname)]);
await createManagedAsmCasesForScan(
  "scan-5", "dom", domain, [fixture.finding], [], env,
);
eq("replayed reappearance duplicates no lifecycle event",
  db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE asset_id=? AND event_type='asset_reappeared'").get(fixture.asset_id).n,
  1);
eq("replayed reappearance duplicates no case",
  db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws'").get().n,
  1);
eq("replayed reappearance duplicates no reopen transition",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=? AND action='reopened'").get(kase.id).n,
  1);
eq("replayed reappearance duplicates no canonical alert occurrence source",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=? AND action='monitoring_changed'").get(kase.id).n,
  3);

eq("soft-deleted workspace receives no lifecycle observations",
  db.prepare("SELECT COUNT(*) AS n FROM asset_lifecycle_observations WHERE workspace_id='ws-deleted'").get().n,
  0);
eq("soft-deleted workspace case remains untouched",
  db.prepare("SELECT status FROM managed_cases WHERE id='case-deleted'").get().status,
  "verification_requested");
eq("foreign tenant asset remains untouched",
  db.prepare("SELECT lifecycle_state FROM workspace_assets WHERE id='asset-foreign'").get().lifecycle_state,
  "observed");
eq("foreign tenant case remains untouched",
  db.prepare("SELECT status FROM managed_cases WHERE id='case-foreign'").get().status,
  "verification_requested");

const indexSource = fs.readFileSync(path.join(
  root, "workers/scan-api/src/index.js",
), "utf8");
ok("purge removes lifecycle observations before workspace_assets",
  indexSource.indexOf('"asset_lifecycle_observations"') <
    indexSource.indexOf('"workspace_assets"'));
ok("purge removes case events before managed cases",
  indexSource.indexOf('"managed_case_events"') <
    indexSource.indexOf('"managed_cases"'));
const caseSource = fs.readFileSync(path.join(
  root, "workers/scan-api/src/engines/asm-cases.js",
), "utf8");
ok("ASM case creation reuses createManagedCase",
  caseSource.includes("const created = await createManagedCase(env"));
ok("all ASM status writers route through canTransitionCase",
  caseSource.includes("const result = canTransitionCase({") &&
    caseSource.includes("const decision = canTransitionCase({"));
ok("P3 adds no probe or subrequest path",
  !fs.readFileSync(path.join(
    root, "workers/scan-api/src/engines/attack-surface-lifecycle.js",
  ), "utf8").includes("fetch("));

// The verification path has one bounded case read and one bounded lifecycle
// read regardless of how many cases are eligible; writes remain per transition
// because append-only case evidence cannot be collapsed.
const n1 = buildDb();
const n1Counters = { reads: 0, batches: 0 };
const n1Env = { cybermeters_db: makeD1(n1.db, n1Counters) };
n1.db.prepare("INSERT INTO users (id, email) VALUES ('usr-n1','n1@example.com')").run();
n1.db.prepare("INSERT INTO workspaces (id, name) VALUES ('ws-n1','N+1 proof')").run();
n1.db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom-n1','usr-n1','n1.example.com')").run();
n1.db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-n1','dom-n1')").run();
for (let i = 0; i < 12; i += 1) {
  const assetId = `asset-n1-${i}`;
  const host = `host-${i}.n1.example.com`;
  n1.db.prepare(`
    INSERT INTO workspace_assets
      (id, workspace_id, domain_id, hostname, asset_type, source,
       first_seen, last_seen, status, wildcard_dns, created_at, updated_at,
       lifecycle_state, last_observation_state)
    VALUES (?, 'ws-n1', 'dom-n1', ?, 'exposed_service', 'exposure_probe',
      datetime('now'), datetime('now'), 'active', 0, datetime('now'), datetime('now'),
      'observed', 'observation_unavailable')
  `).run(assetId, host);
  n1.db.prepare(`
    INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id,
       source_finding_type, source_scan_id, asset_ref, severity, status,
       evidence_json, created_by, created_at, updated_at)
    VALUES (?, 'ws-n1', 'asm_exposure', 'attack_surface', 'n1.example.com', ?,
      ?, 'scan-seed', ?, 'high', 'verification_requested', ?,
      'system', datetime('now'), datetime('now'))
  `).run(
    `case-n1-${i}`,
    `asset_exposure_n1_${i}`,
    `asset_exposure_n1_${i}`,
    host,
    JSON.stringify({ finding: {
      id: `asset_exposure_n1_${i}`,
      module: "asset_exposure",
      affected_hosts: [host],
    } }),
  );
  n1.db.prepare(`
    INSERT INTO asset_lifecycle_observations
      (id, workspace_id, domain_id, asset_id, scan_id, observation_state,
       dns_state, http_state, qualifies_removal, policy_version, observed_at)
    VALUES (?, 'ws-n1', 'dom-n1', ?, 'scan-n1', 'observation_unavailable',
      'unavailable', 'unavailable', 0, 'fixture', datetime('now'))
  `).run(`alo-n1-${i}`, assetId);
}
const n1Verification = await verifyManagedAsmCasesForScan(
  "scan-n1", "dom-n1", "n1.example.com", [], n1Env, {
    modules: { asset_exposure: { checked: 12 } },
    scanQuality: { status: "complete", modules_skipped: [] },
    scanPublished: true,
  },
);
eq("bounded verification handles every eligible case", n1Verification.deferred, 12);
eq("verification avoids N+1 reads across twelve cases", n1Counters.reads, 2);

// Code-first staging and rollback compatibility: without migration 102, the
// legacy asset lookup preserves identity but supplies unavailable lifecycle
// evidence, so the case remains awaiting verification.
const legacy = buildDb({ applyMigration102: false });
const legacyCounters = { reads: 0, batches: 0 };
const legacyEnv = { cybermeters_db: makeD1(legacy.db, legacyCounters) };
legacy.db.prepare("INSERT INTO users (id, email) VALUES ('usr-legacy','legacy@example.com')").run();
legacy.db.prepare("INSERT INTO workspaces (id, name) VALUES ('ws-legacy','Legacy')").run();
legacy.db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom-legacy','usr-legacy','legacy.example.com')").run();
legacy.db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-legacy','dom-legacy')").run();
legacy.db.prepare(`
  INSERT INTO workspace_assets
    (id, workspace_id, domain_id, hostname, asset_type, source,
     first_seen, last_seen, status, wildcard_dns, created_at, updated_at)
  VALUES ('asset-legacy','ws-legacy','dom-legacy','admin.legacy.example.com',
    'exposed_service','exposure_probe',datetime('now'),datetime('now'),
    'active',0,datetime('now'),datetime('now'))
`).run();
legacy.db.prepare(`
  INSERT INTO managed_cases
    (id, workspace_id, case_type, domain_key, domain, finding_id,
     source_finding_type, source_scan_id, asset_ref, severity, status,
     evidence_json, created_by, created_at, updated_at)
  VALUES ('case-legacy','ws-legacy','asm_exposure','attack_surface','legacy.example.com',
    'asset_exposure_legacy','asset_exposure_legacy','scan-seed',
    'admin.legacy.example.com','high','verification_requested',?,
    'system',datetime('now'),datetime('now'))
`).run(JSON.stringify({ finding: {
  id: "asset_exposure_legacy",
  module: "asset_exposure",
  affected_hosts: ["admin.legacy.example.com"],
} }));
const legacyVerification = await verifyManagedAsmCasesForScan(
  "scan-legacy", "dom-legacy", "legacy.example.com", [], legacyEnv, {
    modules: { asset_exposure: { checked: 1 } },
    scanQuality: { status: "complete", modules_skipped: [] },
    scanPublished: true,
  },
);
eq("migration-102-missing staging path defers verification",
  legacyVerification.deferred, 1);
eq("migration-102-missing staging path never closes the case",
  legacy.db.prepare("SELECT status FROM managed_cases WHERE id='case-legacy'").get().status,
  "verification_requested");

console.log(`\nItem 10 P3 lifecycle/cases: ${passed}/${passed + failed} assertions passed`);
if (failed) process.exit(1);
console.log("Item 10 P3 lifecycle/case validation passed");
