#!/usr/bin/env node
// Item 10 P4 — deterministic evidence-aware ASM alert eligibility and delivery.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(fs.readFileSync(path.join(
  root,
  "scripts/fixtures/item10-p4-asset-alert-quality.json",
), "utf8"));
const engine = (name) => pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines",
  name,
)).href;
const alertsUrl = process.env.ITEM10_P4_ALERTS_MODULE_URL ||
  engine("asset-alerts.js");
const deliveryUrl = process.env.ITEM10_P4_DELIVERY_MODULE_URL ||
  engine("asset-alert-delivery.js");
const {
  ASSET_ALERT_ELIGIBILITY_REASON_CODES,
  ASSET_ALERT_EVENTS,
  assetAlertCounts,
  assetAlertSeverity,
  assetAlertWorthy,
  buildAssetAlertEmail,
  evaluateAssetAlertEligibility,
} = await import(alertsUrl);
const {
  loadAssetAlertEligibilityEvidence,
  sendAssetChangeAlert,
} = await import(deliveryUrl);

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

const expectedReasons = [
  "eligible_signal_observed",
  "eligible_event_evidence",
  "eligible_event_evidence_fallback",
  "eligible_confirmed_removal",
  "eligible_reappearance_after_confirmed_removal",
  "withheld_signal_not_supported",
  "withheld_lifecycle_schema_absent",
  "withheld_evidence_lookup_unavailable",
  "withheld_removal_confirmation_not_satisfied",
  "withheld_reappearance_predecessor_unconfirmed",
  "withheld_all_claims_unsupported",
];
eq(
  "frozen reason-code vocabulary",
  JSON.stringify(ASSET_ALERT_ELIGIBILITY_REASON_CODES),
  JSON.stringify(expectedReasons),
);
eq(
  "all ten alert event classes remain enabled",
  JSON.stringify([...ASSET_ALERT_EVENTS].sort()),
  JSON.stringify([
    "admin_surface_detected",
    "asset_no_longer_seen",
    "asset_reappeared",
    "certificate_new_detected",
    "certificate_new_issuer_detected",
    "certificate_new_san_detected",
    "cloud_storage_detected",
    "new_asset_discovered",
    "takeover_risk_detected",
    "wildcard_dns_detected",
  ]),
);

const incident = fixture.recorded_incident;
const incidentEvidence = {
  signal_status: "available",
  lifecycle_status: "available",
  signal_states: {
    subdomain_discovery: {
      state: "incomplete",
      reason: "discovery_sources_incomplete",
    },
    takeover_candidate: {
      state: "not_observed",
      reason: "complete_takeover_probe_no_candidate",
    },
    exposure_admin_surface: {
      state: "not_observed",
      reason: "complete_exposure_admin_probe_no_signal",
    },
  },
  lifecycle_observations: incident.lifecycle_observations,
};
const incidentRemoval = evaluateAssetAlertEligibility(
  [incident.removal_event],
  incidentEvidence,
);
eq(
  "14 Jul CT blackout cannot alert a removal claim",
  incidentRemoval.eligible_events.length,
  0,
);
eq(
  "14 Jul removal has a declared reason",
  incidentRemoval.decisions[0]?.reason_code,
  "withheld_removal_confirmation_not_satisfied",
);
ok(
  "14 Jul removal produces no alert-worthy eligible count",
  !assetAlertWorthy(assetAlertCounts(incidentRemoval.eligible_events)),
);
const incidentReappearance = evaluateAssetAlertEligibility(
  [incident.reappearance_event],
  incidentEvidence,
);
eq(
  "15 Jul recovery cannot alert reappearance after unconfirmed disappearance",
  incidentReappearance.eligible_events.length,
  0,
);
eq(
  "15 Jul reappearance has a declared reason",
  incidentReappearance.decisions[0]?.reason_code,
  "withheld_reappearance_predecessor_unconfirmed",
);
ok(
  "15 Jul replay produces no alert-worthy eligible count",
  !assetAlertWorthy(assetAlertCounts(incidentReappearance.eligible_events)),
);
ok(
  "Cloudflare 530 fixture carries no takeover/admin alert claim",
  ![
    incident.removal_event,
    incident.reappearance_event,
  ].some((event) => [
    "takeover_risk_detected",
    "admin_surface_detected",
  ].includes(event.event_type)),
);

const confirmed = fixture.confirmed_removal;
const confirmedDecision = evaluateAssetAlertEligibility(
  [confirmed.event],
  {
    lifecycle_status: "available",
    signal_states: {},
    lifecycle_observations: confirmed.observations,
  },
);
eq(
  "three active-source observations confirm removal eligibility",
  confirmedDecision.eligible_events.length,
  1,
);
eq(
  "confirmed removal reason is canonical",
  confirmedDecision.decisions[0]?.reason_code,
  "eligible_confirmed_removal",
);
const confirmedCounts = assetAlertCounts(
  confirmedDecision.eligible_events,
  confirmedDecision.record,
);
ok("genuine confirmed removal is alert-worthy", assetAlertWorthy(confirmedCounts));
eq("confirmed removal is information severity", assetAlertSeverity(confirmedCounts), "info");

const reappearedEvent = {
  id: "evt-confirmed-reappeared",
  asset_id: confirmed.asset_id,
  scan_id: "scan-confirmed-4",
  event_type: "asset_reappeared",
  hostname: confirmed.event.hostname,
};
const reappearedDecision = evaluateAssetAlertEligibility(
  [reappearedEvent],
  {
    lifecycle_status: "available",
    signal_states: {},
    lifecycle_observations: [
      ...confirmed.observations,
      {
        asset_id: confirmed.asset_id,
        scan_id: "scan-confirmed-4",
        observation_state: "observed",
        dns_state: "observed",
        http_state: "not_observed",
        qualifies_removal: 0,
        policy_version: "asset-removal-confirmation-v1",
        source_detail_json: {
          active_sources: ["dns_resolution", "http_https_service"],
          passive_sources: [],
        },
        observed_at: "2026-07-23T10:00:00.000Z",
      },
    ],
  },
);
eq(
  "reappearance after confirmed removal remains alertable",
  reappearedDecision.decisions[0]?.reason_code,
  "eligible_reappearance_after_confirmed_removal",
);

const siblingEvents = [
  {
    id: "evt-admin",
    event_type: "admin_surface_detected",
    hostname: "admin.example.com",
  },
  {
    id: "evt-takeover",
    event_type: "takeover_risk_detected",
    hostname: "dangling.example.com",
  },
];
const siblingDecision = evaluateAssetAlertEligibility(siblingEvents, {
  signal_status: "available",
  lifecycle_status: "available",
  signal_states: {
    subdomain_discovery: { state: "unavailable" },
    exposure_admin_surface: { state: "observed" },
    takeover_candidate: { state: "observed" },
  },
  lifecycle_observations: [],
});
eq(
  "CT-unavailable sibling does not suppress admin/takeover claims",
  siblingDecision.eligible_events.length,
  2,
);
eq(
  "strongest independently observed sibling keeps existing severity",
  assetAlertSeverity(assetAlertCounts(siblingDecision.eligible_events)),
  "critical",
);

const oneUnsupportedSibling = evaluateAssetAlertEligibility(siblingEvents, {
  signal_status: "available",
  lifecycle_status: "available",
  signal_states: {
    exposure_admin_surface: { state: "observed" },
    takeover_candidate: { state: "unavailable" },
  },
  lifecycle_observations: [],
});
eq(
  "one unsupported claim is withheld independently",
  oneUnsupportedSibling.withheld_events.length,
  1,
);
eq(
  "healthy sibling stays eligible",
  oneUnsupportedSibling.eligible_events[0]?.event_type,
  "admin_surface_detected",
);
eq(
  "unsupported critical claim cannot escalate eligible admin severity",
  assetAlertSeverity(assetAlertCounts(oneUnsupportedSibling.eligible_events)),
  "high",
);

const absentSchemaDecision = evaluateAssetAlertEligibility(siblingEvents, {
  signal_status: "schema_absent",
  lifecycle_status: "schema_absent",
  signal_states: {},
  lifecycle_observations: [],
});
eq(
  "migration-102-absent world keeps independent event evidence alertable",
  absentSchemaDecision.eligible_events.length,
  2,
);
ok(
  "migration-102-absent world cannot globally silence ASM alerts",
  assetAlertWorthy(assetAlertCounts(absentSchemaDecision.eligible_events)),
);
ok(
  "absent-model fallback is explicitly labelled",
  absentSchemaDecision.decisions.every(
    (decision) => decision.reason_code === "eligible_event_evidence_fallback",
  ),
);

const schemaAbsentLifecycle = evaluateAssetAlertEligibility(
  [incident.reappearance_event],
  {
    signal_status: "schema_absent",
    lifecycle_status: "schema_absent",
    signal_states: {},
    lifecycle_observations: [],
  },
);
eq(
  "absent schema cannot assert confirmed reappearance",
  schemaAbsentLifecycle.decisions[0]?.reason_code,
  "withheld_lifecycle_schema_absent",
);

const passiveRows = confirmed.observations.map((row) => ({
  ...row,
  source_detail_json: {
    active_sources: [],
    passive_sources: ["crt_sh", "certspotter"],
  },
}));
const passiveDecision = evaluateAssetAlertEligibility(
  [confirmed.event],
  {
    lifecycle_status: "available",
    signal_states: {},
    lifecycle_observations: passiveRows,
  },
);
eq(
  "CT/passive observations cannot confirm removal",
  passiveDecision.eligible_events.length,
  0,
);

ok(
  "withheld record is bounded and machine-inspectable",
  incidentReappearance.record.withheld.length === 1 &&
  incidentReappearance.record.withheld[0].count === 1 &&
  expectedReasons.includes(
    incidentReappearance.record.withheld[0].reason_code,
  ),
);

const email = buildAssetAlertEmail(
  fixture.domain,
  "ws",
  "scan",
  { takeover_risk_detected: 1 },
  [fixture.hostname],
  "critical",
);
ok(
  "customer wording does not claim attacker or compromise",
  !/\b(?:attacker|compromise(?:d)?)\b/i.test(`${email.subject}\n${email.text}`),
);

function makeD1(db, counters) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      counters.reads += /^\s*select/i.test(sql) ? 1 : 0;
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => {
      counters.reads += /^\s*(?:select|with)/i.test(sql) ? 1 : 0;
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return { prepare: (sql) => statement(sql) };
}

const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT,
    deleted_at TEXT
  );
  CREATE TABLE workspace_domains (
    workspace_id TEXT NOT NULL,
    domain_id TEXT NOT NULL
  );
  CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT,
    scan_quality TEXT
  );
  CREATE TABLE asset_events (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    asset_id TEXT,
    scan_id TEXT,
    event_type TEXT NOT NULL,
    hostname TEXT,
    severity TEXT,
    description TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE asset_alert_records (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    domain TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    event_counts TEXT NOT NULL,
    top_hostnames TEXT,
    sent_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'sent',
    error TEXT,
    UNIQUE (workspace_id, scan_id)
  );
`);
db.prepare(
  "INSERT INTO workspaces (id, owner_user_id, deleted_at) VALUES ('ws',NULL,NULL)",
).run();
db.prepare(
  "INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')",
).run();
for (const scanId of ["scan-absent-admin", "scan-absent-reappearance"]) {
  db.prepare(
    "INSERT INTO scans (id, workspace_id, scan_quality) VALUES (?,'ws','complete')",
  ).run(scanId);
}
db.prepare(`
  INSERT INTO asset_events
    (id, workspace_id, domain_id, asset_id, scan_id, event_type,
     hostname, severity, description, created_at)
  VALUES
    ('evt-absent-admin','ws','dom','asset-admin','scan-absent-admin',
     'admin_surface_detected','admin.example.com','high',
     'Admin surface detected','2026-07-27T10:00:00.000Z'),
    ('evt-absent-reappearance','ws','dom','asset-recorded',
     'scan-absent-reappearance','asset_reappeared',
     'www.email.blackbullbarbers.co.uk','medium',
     'Asset reappeared','2026-07-27T10:05:00.000Z')
`).run();
const counters = { reads: 0 };
const env = { cybermeters_db: makeD1(db, counters) };

const evidenceReadStart = counters.reads;
const absentEvidence = await loadAssetAlertEligibilityEvidence(
  env,
  "ws",
  "scan-absent-admin",
);
eq("real absent schema is detected for signals", absentEvidence.signal_status, "schema_absent");
eq("real absent schema is detected for lifecycle", absentEvidence.lifecycle_status, "schema_absent");
eq(
  "eligibility evidence uses two bounded reads, not one read per event",
  counters.reads - evidenceReadStart,
  2,
);

const originalInfo = console.info;
const originalError = console.error;
console.info = () => {};
console.error = () => {};
try {
  await sendAssetChangeAlert(
    "dom",
    fixture.domain,
    "scan-absent-admin",
    env,
    "complete",
  );
  await sendAssetChangeAlert(
    "dom",
    fixture.domain,
    "scan-absent-admin",
    env,
    "complete",
  );
  await sendAssetChangeAlert(
    "dom",
    fixture.domain,
    "scan-absent-reappearance",
    env,
    "complete",
  );
} finally {
  console.info = originalInfo;
  console.error = originalError;
}

const adminRecord = db.prepare(
  "SELECT event_counts, status, error FROM asset_alert_records WHERE scan_id='scan-absent-admin'",
).get();
const adminCounts = JSON.parse(adminRecord.event_counts);
eq(
  "absent migration still routes independent admin event to canonical delivery",
  adminCounts.admin_surface_detected,
  1,
);
eq(
  "entitlement suppression proves delivery gate was reached",
  adminRecord.error,
  "feature_not_entitled",
);
eq(
  "replay keeps one dedupe record",
  db.prepare(
    "SELECT COUNT(*) AS n FROM asset_alert_records WHERE scan_id='scan-absent-admin'",
  ).get().n,
  1,
);

const withheldRecord = db.prepare(
  "SELECT event_counts, status, error FROM asset_alert_records WHERE scan_id='scan-absent-reappearance'",
).get();
const withheldCounts = JSON.parse(withheldRecord.event_counts);
eq("unsupported reappearance is durably skipped", withheldRecord.status, "skipped");
eq(
  "withheld-only row records the frozen aggregate reason",
  withheldRecord.error,
  "withheld_all_claims_unsupported",
);
eq(
  "withheld reason remains inspectable in existing event_counts JSON",
  withheldCounts._eligibility.withheld[0]?.reason_code,
  "withheld_lifecycle_schema_absent",
);
ok(
  "full delivery trace remains bounded across initial, replay and withheld scans",
  counters.reads <= 19,
  `reads=${counters.reads}`,
);

db.exec(`
  CREATE TABLE attack_surface_signal_observations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    signal_key TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    sources_json TEXT NOT NULL DEFAULT '[]',
    limitations_json TEXT NOT NULL DEFAULT '[]',
    model_version TEXT NOT NULL,
    observed_at TEXT NOT NULL
  );
  CREATE TABLE asset_lifecycle_observations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    observation_state TEXT NOT NULL,
    dns_state TEXT NOT NULL,
    http_state TEXT NOT NULL,
    qualifies_removal INTEGER NOT NULL,
    policy_version TEXT NOT NULL,
    source_detail_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);
db.prepare(`
  INSERT INTO attack_surface_signal_observations
    (id, workspace_id, domain_id, scan_id, signal_key, state, reason,
     evidence_count, sources_json, limitations_json, model_version, observed_at)
  VALUES
    ('asso-admin','ws','dom','scan-absent-admin','exposure_admin_surface',
     'observed','exposure_or_admin_surface_observed',1,'["http_probe"]','[]',
     'attack-surface-signal-completeness-v1','2026-07-27T10:00:00.000Z')
`).run();
const persistedEvidence = await loadAssetAlertEligibilityEvidence(
  env,
  "ws",
  "scan-absent-admin",
);
eq(
  "migration-102-compatible signal query reads the persisted model",
  persistedEvidence.signal_states.exposure_admin_surface?.state,
  "observed",
);
eq(
  "migration-102-compatible lifecycle query remains available",
  persistedEvidence.lifecycle_status,
  "available",
);

console.log(`Item 10 P4 alert-quality validation: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exit(1);
