#!/usr/bin/env node
// Item 10 P5 — deterministic Attack Surface customer-surface parity.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines",
  name,
)).href;
const presentationUrl = process.env.ITEM10_P5_PRESENTATION_MODULE_URL ||
  engine("attack-surface-customer-presentation.js");
const executiveUrl = process.env.ITEM10_P5_EXECUTIVE_MODULE_URL ||
  engine("executive-report.js");
const {
  ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES,
  ATTACK_SURFACE_CUSTOMER_OBSERVATION_STATES,
  ATTACK_SURFACE_CUSTOMER_PRESENTATION_SCHEMA,
  ATTACK_SURFACE_CUSTOMER_SIGNAL_STATES,
  attackSurfaceAssuranceApiProjection,
  attackSurfaceAssuranceFromSnapshot,
  buildAttackSurfaceCustomerPresentation,
} = await import(presentationUrl);
const { buildExecutiveReportV2 } = await import(executiveUrl);
const { composeSnapshot } = await import(engine("report-snapshot.js"));
const {
  buildScanReportPdf,
  buildWorkspaceExecutivePdf,
} = await import(engine("pdf.js"));
const { attackSurfaceRoutes } = await import(pathToFileURL(path.join(
  root,
  "workers/scan-api/src/routes/attack-surface.js",
)).href);

const fixture = JSON.parse(fs.readFileSync(path.join(
  root,
  "scripts/fixtures/item10-p5-attack-surface-customer-parity.json",
), "utf8"));
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

const labels = {
  observed: "Observed",
  not_observed: "Not observed in this scan",
  absent: "Confirmed absent",
  unavailable: "Evidence unavailable",
  incomplete: "Evidence incomplete",
  not_assessed: "Not assessed",
};
const signal = (state) => ({
  state,
  reason: `fixture_${state}`,
  evidence_count: state === "observed" ? 1 : 0,
  sources: ["fixture_source"],
  limitations: ["fixture_scope"],
});
const modelFor = (state) => ({
  model_version: "attack-surface-signal-completeness-v1",
  signals: Object.fromEntries(
    fixture.signal_keys.map((key) => [key, signal(state)]),
  ),
});

eq("frozen schema id",
  ATTACK_SURFACE_CUSTOMER_PRESENTATION_SCHEMA, fixture.schema);
eq("signal vocabulary is exact",
  JSON.stringify(ATTACK_SURFACE_CUSTOMER_SIGNAL_STATES),
  JSON.stringify(fixture.signal_states));
eq("lifecycle vocabulary is exact",
  JSON.stringify(ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES),
  JSON.stringify(fixture.lifecycle_states));
eq("last-observation vocabulary is exact",
  JSON.stringify(ATTACK_SURFACE_CUSTOMER_OBSERVATION_STATES),
  JSON.stringify(fixture.last_observation_states));

// All nine signals in every one of the six non-overlapping signal states.
for (const state of fixture.signal_states) {
  const result = buildAttackSurfaceCustomerPresentation({
    signalCompleteness: modelFor(state),
    lifecycleRecords: [],
  });
  for (const key of fixture.signal_keys) {
    eq(`${key}/${state}: state retained`,
      result.signals[key].state, state);
    eq(`${key}/${state}: wording retained`,
      result.signals[key].state_label, labels[state]);
    ok(`${key}/${state}: no favourable missing-evidence wording`,
      !["unavailable", "incomplete", "not_assessed"].includes(state) ||
      !/\b(?:healthy|clean|no issues found)\b/i.test(
        `${result.signals[key].state_label} ${result.signals[key].customer_message}`,
      ));
  }
}

const mixedSignals = {
  model_version: "attack-surface-signal-completeness-v1",
  signals: Object.fromEntries(fixture.signal_keys.map((key) => [
    key,
    signal(key === "subdomain_discovery" ? "unavailable" : "observed"),
  ])),
};
const current = buildAttackSurfaceCustomerPresentation({
  signalCompleteness: mixedSignals,
  lifecycleRecords: fixture.lifecycle_records,
  alertEligibility: fixture.alert_eligibility,
  asOf: fixture.observed_at,
});
eq("mixed unavailable signal stays unavailable",
  current.signals.subdomain_discovery.state, "unavailable");
for (const key of fixture.signal_keys.slice(1)) {
  eq(`${key}: unavailable sibling does not erase observed state`,
    current.signals[key].state, "observed");
}
for (const state of fixture.lifecycle_states) {
  const record = current.lifecycle.records.find(
    (item) => item.lifecycle_state === state,
  );
  ok(`${state}: lifecycle state projected`, Boolean(record));
}
eq("confirmed removal timestamp retained",
  current.lifecycle.records.find(
    (item) => item.lifecycle_state === "confirmed_removed",
  )?.confirmed_removed_at,
  "2026-07-27T11:59:00.000Z");
eq("eligible alert reason retained",
  current.alert_eligibility.decisions.find((item) => item.eligible)?.reason_code,
  "eligible_signal_observed");
eq("withheld alert reason retained",
  current.alert_eligibility.decisions.find((item) => !item.eligible)?.reason_code,
  "withheld_reappearance_predecessor_unconfirmed");
ok("withheld alert remains inspectable",
  current.alert_eligibility.decisions.some(
    (item) => !item.eligible && item.reason_message,
  ));
eq("signal model version stamped",
  current.model_versions.signal_completeness,
  "attack-surface-signal-completeness-v1");
eq("lifecycle model version stamped",
  current.model_versions.lifecycle_policy,
  "asset-removal-confirmation-v1");
eq("alert model version stamped",
  current.model_versions.alert_eligibility,
  "asset-alert-eligibility-v1");

// Migration-102-absent: independent signals remain real while lifecycle stays
// explicitly not_recorded. It never becomes healthy or silently empty.
const migrationAbsent = buildAttackSurfaceCustomerPresentation({
  signalCompleteness: mixedSignals,
  lifecycleRecords: null,
  lifecycleAbsenceReason:
    "Migration 102 lifecycle fields are not recorded. Legacy status is not interpreted.",
});
eq("migration absent keeps independent signal",
  migrationAbsent.signals.dns_resolution.state, "observed");
eq("migration absent lifecycle is not_recorded",
  migrationAbsent.lifecycle.status, "not_recorded");
ok("migration absent lifecycle has explicit notice",
  Boolean(migrationAbsent.lifecycle.customer_message));
ok("migration absent never renders healthy/no-issues",
  !/\b(?:healthy|no issues|assessed healthy)\b/i.test(
    JSON.stringify(migrationAbsent),
  ));

function makeD1(db, counters) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async () => {
      counters.reads += 1;
      return db.prepare(sql).get(...args) ?? null;
    },
    all: async () => {
      counters.reads += 1;
      return { results: db.prepare(sql).all(...args) };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => Promise.all(
      statements.map((statementRow) => statementRow.all()),
    ),
  };
}

// Real legacy-schema route proof: migration 102 absent does not 500, does not
// leak a foreign tenant, and returns a bounded explicit not_recorded projection.
const legacyDb = new DatabaseSync(":memory:");
legacyDb.exec(`
  CREATE TABLE workspaces (id TEXT PRIMARY KEY);
  CREATE TABLE workspace_assets (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT,
    hostname TEXT,
    asset_type TEXT,
    source TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    wildcard_dns INTEGER,
    ip_addresses TEXT,
    cname TEXT,
    redirect_to TEXT,
    cloud_provider TEXT,
    risk_level TEXT,
    metadata_json TEXT,
    created_at TEXT,
    updated_at TEXT
  );
  INSERT INTO workspaces VALUES ('ws-item10-p5');
  INSERT INTO workspaces VALUES ('ws-foreign');
  INSERT INTO workspace_assets VALUES (
    'asset-legacy', 'ws-item10-p5', 'dom-item10-p5', 'legacy.example.com',
    'subdomain', 'legacy', '2026-07-01', '2026-07-27', 'inactive', 0,
    '[]', NULL, NULL, NULL, NULL, '{}', '2026-07-01', '2026-07-27'
  );
  INSERT INTO workspace_assets VALUES (
    'asset-foreign', 'ws-foreign', 'dom-foreign', 'foreign.example.net',
    'subdomain', 'legacy', '2026-07-01', '2026-07-27', 'active', 0,
    '[]', NULL, NULL, NULL, NULL, '{}', '2026-07-01', '2026-07-27'
  );
`);
const counters = { reads: 0 };
const routeResult = await attackSurfaceRoutes({
  request: new Request(
    "https://api.example/api/workspaces/ws-item10-p5/assets",
  ),
  env: { cybermeters_db: makeD1(legacyDb, counters) },
  url: new URL(
    "https://api.example/api/workspaces/ws-item10-p5/assets",
  ),
  json: (body, status = 200) => ({ body, status }),
  requireAuth: async () => ({ id: "user-fixture" }),
  requireWorkspaceRole: async () => ({ role: "owner" }),
});
eq("migration-102-absent assets API remains available",
  routeResult.status, 200);
eq("migration-102-absent assets API retains legacy row",
  routeResult.body.assets[0]?.id, "asset-legacy");
eq("legacy inactive stays separate from lifecycle",
  routeResult.body.assets[0]?.status, "inactive");
eq("migration-102-absent API lifecycle is not_recorded",
  routeResult.body.attack_surface_assurance?.[0]?.lifecycle?.status,
  "not_recorded");
ok("migration-102-absent API is explicit, not silently empty",
  routeResult.body.attack_surface_assurance?.[0]?.signal_order?.length === 9 &&
  Boolean(
    routeResult.body.attack_surface_assurance?.[0]
      ?.lifecycle?.customer_message,
  ));
ok("migration-102-absent list row does not duplicate assurance",
  !Object.hasOwn(routeResult.body.assets[0] || {}, "attack_surface_assurance"));
eq("migration-102-absent coverage remains explicit",
  routeResult.body.attack_surface_assurance_coverage?.status,
  "not_recorded");
ok("assets API remains tenant isolated",
  !JSON.stringify(routeResult.body).includes("foreign.example.net"));
ok("assets API evidence reads are bounded, not N+1",
  counters.reads <= 8,
  `read count ${counters.reads}`);
legacyDb.close();

const report = {
  status: "completed",
  domain: fixture.domain,
  started_at: fixture.observed_at,
  completed_at: fixture.observed_at,
  cyber_metrics_score: 70,
  scan_quality: { status: "complete", modules_skipped: [], warnings: [] },
  monitoring_states: { signals: {} },
  modules: {
    attack_surface_signal_completeness: mixedSignals,
  },
  findings: [],
};
const snapshot = composeSnapshot({
  snapshotId: fixture.snapshot_id,
  workspaceId: fixture.workspace_id,
  domainId: fixture.domain_id,
  scanId: fixture.scan_id,
  domain: fixture.domain,
  report,
  cyberEssentials: { status: "not_assessed" },
  ceReadiness: null,
  caseRows: [],
  questionSetVersions: [],
  certificateLifecycleRecords: null,
  attackSurfaceLifecycleRecords: fixture.lifecycle_records,
  supersedesSnapshotId: null,
  builtAt: fixture.built_at,
});
eq("new snapshot freezes one ASM projection",
  snapshot.attack_surface_assurance.schema, fixture.schema);
eq("snapshot builder version stamps the additive ASM shape",
  snapshot.methodology.snapshot_builder_version, "2026-07-27.1");

const apiProjection = attackSurfaceAssuranceApiProjection(snapshot);
const read = {
  status: "ok",
  snapshot,
  row: { id: fixture.snapshot_id },
  integrity: { verified: true },
  dmarcPolicy: null,
};
const executive = buildExecutiveReportV2({
  scan: {
    id: fixture.scan_id,
    domain_id: fixture.domain_id,
    domain: fixture.domain,
  },
  workspace: { id: fixture.workspace_id, name: "Fixture Workspace" },
  read,
});

// Headline six-surface parity: one fixture, one backend projection.
eq("surface 1 assets/API adapter and snapshot state agree",
  JSON.stringify(apiProjection.attack_surface_assurance),
  JSON.stringify(snapshot.attack_surface_assurance));
eq("surface 2 immutable snapshot records unavailable honestly",
  snapshot.attack_surface_assurance.signals.subdomain_discovery.state,
  "unavailable");
eq("surface 3 Executive Report and snapshot state agree",
  JSON.stringify(executive.attack_surface_assurance),
  JSON.stringify(snapshot.attack_surface_assurance));

const pdfText = new TextDecoder().decode(
  buildScanReportPdf(
    { id: fixture.scan_id, domain: fixture.domain },
    read,
  ),
);
for (const phrase of [
  "Attack Surface Evidence & Lifecycle",
  "Subdomain discovery: Evidence unavailable",
  "DNS resolution: Observed",
  "Asset lifecycle",
  "Confirmed removed",
  "ASM alert eligibility",
  "alert eligibility: not recorded",
]) {
  ok(`surface 4 PDF renders canonical semantic: ${phrase}`,
    pdfText.includes(phrase));
}
const executivePdfText = new TextDecoder().decode(
  buildWorkspaceExecutivePdf({
    workspaceName: "Fixture Workspace",
    reads: [read],
    generatedAt: fixture.built_at,
  }),
);
ok("Executive PDF uses the same ASM projection",
  executivePdfText.includes("Attack Surface Evidence & Lifecycle") &&
  executivePdfText.includes("Subdomain discovery: Evidence unavailable"));

const assetsRouteSource = fs.readFileSync(path.join(
  root, "workers/scan-api/src/routes/attack-surface.js",
), "utf8");
const assetsPageSource = fs.readFileSync(path.join(
  root, "frontend/src/pages/AssetsPage.jsx",
), "utf8");
const timelinePageSource = fs.readFileSync(path.join(
  root, "frontend/src/pages/ExposureTimelinePage.jsx",
), "utf8");
const timelineSource = fs.readFileSync(path.join(
  root, "frontend/src/components/ExposureTimeline.jsx",
), "utf8");
const frontendProjectionSource = fs.readFileSync(path.join(
  root, "frontend/src/components/AttackSurfaceAssurance.jsx",
), "utf8");
ok("assets API calls the one ASM projection",
  /buildAttackSurfaceCustomerPresentation/.test(assetsRouteSource) &&
  /attack_surface_assurance/.test(assetsRouteSource));
ok("surface 5 AssetsPage renders backend projection",
  /AttackSurfaceAssurance/.test(assetsPageSource) &&
  /attack_surface_assurance/.test(assetsPageSource));
ok("surface 6 ExposureTimelinePage delegates to the projection consumer",
  /ExposureTimeline/.test(timelinePageSource) &&
  /AttackSurfaceAssurance/.test(timelineSource) &&
  /attack_surface_assurance/.test(timelineSource));
ok("frontend renders backend-owned state labels/messages",
  /signal\.state_label/.test(frontendProjectionSource) &&
  /signal\.customer_message/.test(frontendProjectionSource));
ok("frontend owns no second ASM state vocabulary",
  !/const\\s+(?:SIGNAL|LIFECYCLE)_STATE_(?:LABELS|VOCABULARY)/.test(
    `${assetsPageSource}\n${timelineSource}\n${frontendProjectionSource}`,
  ));

// Pre-P5 historical snapshot: no in-place rewrite and no inference from raw
// module-looking data that was never frozen into the P5 block.
const legacySnapshot = {
  snapshot: {
    snapshot_id: "snap-pre-p5",
    snapshot_schema_version: "1",
  },
  modules: {
    attack_surface_signal_completeness: modelFor("observed"),
  },
};
const legacyBefore = JSON.stringify(legacySnapshot);
const legacy = attackSurfaceAssuranceFromSnapshot(legacySnapshot);
eq("pre-P5 snapshot object is not rewritten",
  JSON.stringify(legacySnapshot), legacyBefore);
eq("pre-P5 snapshot projects not_recorded",
  legacy.status, "not_recorded");
eq("pre-P5 snapshot does not invent raw-module observation",
  legacy.signals.dns_resolution.state, "not_assessed");
ok("pre-P5 snapshot has an explicit notice",
  /not recorded in this historical snapshot/i.test(legacy.historical_notice));
ok("pre-P5 snapshot cannot read healthy or silently empty",
  legacy.signal_order.length === 9 &&
  !/\b(?:healthy|no issues|clean)\b/i.test(JSON.stringify(legacy)));

console.log(
  `Item 10 P5 customer parity: ${passed}/${passed + failed} assertions passed`,
);
if (failed > 0) process.exit(1);
