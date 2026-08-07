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
const assetAlertsUrl = process.env.ITEM10_P5_ASSET_ALERTS_MODULE_URL ||
  engine("asset-alerts.js");
const {
  ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES,
  ATTACK_SURFACE_CUSTOMER_OBSERVATION_STATES,
  ATTACK_SURFACE_CUSTOMER_PRESENTATION_SCHEMA,
  ATTACK_SURFACE_CUSTOMER_SIGNAL_STATES,
  attackSurfaceAssuranceApiProjection,
  attackSurfaceAssuranceFromSnapshot,
  buildAttackSurfaceCustomerPresentation,
} = await import(presentationUrl);
const {
  ASSET_ALERT_ELIGIBILITY_REASON_CODES,
  ASSET_ALERT_EVENTS,
} = await import(assetAlertsUrl);
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
eq("internal lifecycle enum remains confirmed_removed",
  ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES.find(
    (state) => state === "confirmed_removed",
  ),
  "confirmed_removed");
ok("wire event key remains exactly asset_no_longer_seen",
  ASSET_ALERT_EVENTS.has("asset_no_longer_seen") &&
  !ASSET_ALERT_EVENTS.has("asset_no_longer_observed"));
eq("confirmed-removal alert reason codes remain unchanged",
  JSON.stringify(ASSET_ALERT_ELIGIBILITY_REASON_CODES.filter(
    (code) => code === "eligible_confirmed_removal" ||
      code === "eligible_reappearance_after_confirmed_removal",
  )),
  JSON.stringify([
    "eligible_confirmed_removal",
    "eligible_reappearance_after_confirmed_removal",
  ]));

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
const externallyAbsentRecord = current.lifecycle.records.find(
  (item) => item.lifecycle_state === "confirmed_removed",
);
const activeSourceWindowNarrative =
  "CyberMeters therefore did not observe the asset through those active sources during that window.";
eq("confirmed_removed customer label is honest external absence",
  externallyAbsentRecord?.lifecycle_state_label,
  "No longer externally observed");
ok("confirmed_removed message names the measured evidence",
  /three qualifying observations over at least 48 hours/i.test(
    externallyAbsentRecord?.lifecycle_message || "",
  ) &&
  /no authoritative DNS record and no HTTP or HTTPS service/i.test(
    externallyAbsentRecord?.lifecycle_message || "",
  ));
ok("confirmed_removed message denies removal/remediation proof",
  /not evidence that the asset was removed, decommissioned or remediated/i.test(
    externallyAbsentRecord?.lifecycle_message || "",
  ));
ok("confirmed_removed narrative is bounded to the active sources and window",
  (externallyAbsentRecord?.lifecycle_message || "").includes(
    activeSourceWindowNarrative,
  ));
ok("confirmed_removed narrative does not claim platform-wide invisibility",
  !/not externally visible to CyberMeters/i.test(
    externallyAbsentRecord?.lifecycle_message || "",
  ));
ok("confirmed_removed narrative does not use unqualified external absence",
  !/no longer externally observed/i.test(
    externallyAbsentRecord?.lifecycle_message || "",
  ));

const lifecycleAlertPresentation = buildAttackSurfaceCustomerPresentation({
  signalCompleteness: mixedSignals,
  lifecycleRecords: fixture.lifecycle_records,
  alertEligibility: {
    policy_version: "asset-alert-eligibility-v1",
    eligible: [
      {
        event_type: "asset_no_longer_seen",
        reason_code: "eligible_confirmed_removal",
        count: 1,
      },
      {
        event_type: "asset_reappeared",
        reason_code: "eligible_reappearance_after_confirmed_removal",
        count: 1,
      },
    ],
    withheld: [],
  },
  asOf: fixture.observed_at,
});
const confirmedRemovalDecision =
  lifecycleAlertPresentation.alert_eligibility.decisions.find(
    (item) => item.reason_code === "eligible_confirmed_removal",
  );
ok("eligible_confirmed_removal narrative is bounded to the active sources and window",
  (confirmedRemovalDecision?.reason_message || "").includes(
    activeSourceWindowNarrative,
  ));
ok("eligible_confirmed_removal narrative does not claim platform-wide invisibility",
  !/not externally visible to CyberMeters/i.test(
    confirmedRemovalDecision?.reason_message || "",
  ));
ok("eligible_confirmed_removal narrative does not use unqualified external absence",
  !/no longer externally observed/i.test(
    confirmedRemovalDecision?.reason_message || "",
  ));
ok("eligible_confirmed_removal narrative denies removal/remediation proof",
  /not evidence of removal, decommissioning or remediation/i.test(
    confirmedRemovalDecision?.reason_message || "",
  ));
const reappearanceDecision =
  lifecycleAlertPresentation.alert_eligibility.decisions.find(
    (item) => item.reason_code ===
      "eligible_reappearance_after_confirmed_removal",
  );
ok("eligible_reappearance_after_confirmed_removal: customer reason uses honest visibility vocabulary",
  /externally observed|external visibility/i.test(
    reappearanceDecision?.reason_message || "",
  ) &&
  /not proof of removal, decommissioning or remediation/i.test(
    reappearanceDecision?.reason_message || "",
  ));
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
  "No longer externally observed",
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
const assetsPageSource = fs.readFileSync(
  process.env.ITEM10_P5_ASSETS_PAGE_SOURCE || path.join(
    root, "frontend/src/pages/AssetsPage.jsx",
  ),
  "utf8",
);
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
ok("AssetsPage preserves the asset_no_longer_seen wire key",
  /key:\s*['"]asset_no_longer_seen['"]/.test(assetsPageSource));
ok("AssetsPage labels the event as no longer observed",
  /key:\s*['"]asset_no_longer_seen['"]\s*,\s*label:\s*['"]No longer observed['"]/.test(
    assetsPageSource,
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

// Stored P5 snapshots retain the old bytes in R2, but every live reader must
// project the historical overclaim onto honest external-observability wording.
const storedOverclaimPresentation = JSON.parse(JSON.stringify(
  lifecycleAlertPresentation,
));
const storedRemovedRecord = storedOverclaimPresentation.lifecycle.records.find(
  (item) => item.lifecycle_state === "confirmed_removed",
);
storedRemovedRecord.lifecycle_state_label = "Confirmed removed";
storedRemovedRecord.lifecycle_message =
  "The asset met the deterministic confirmed-removal policy using qualifying active-source observations.";
for (const decision of storedOverclaimPresentation.alert_eligibility.decisions) {
  if (decision.reason_code === "eligible_confirmed_removal") {
    decision.reason_message =
      "The removal claim satisfied the canonical confirmation policy.";
  }
  if (decision.reason_code ===
      "eligible_reappearance_after_confirmed_removal") {
    decision.reason_message =
      "The asset was observed again after a canonically confirmed removal.";
  }
}
const storedOverclaimSnapshot = {
  snapshot: {
    snapshot_id: "snap-p5-stored-overclaim",
    snapshot_schema_version: "1",
  },
  attack_surface_assurance: storedOverclaimPresentation,
};
const storedOverclaimBefore = JSON.stringify(storedOverclaimSnapshot);
const historicalProjection = attackSurfaceAssuranceFromSnapshot(
  storedOverclaimSnapshot,
);
eq("stored P5 snapshot object is not rewritten",
  JSON.stringify(storedOverclaimSnapshot), storedOverclaimBefore);
eq("stored P5 confirmed_removed label is projected honestly",
  historicalProjection.lifecycle.records.find(
    (item) => item.lifecycle_state === "confirmed_removed",
  )?.lifecycle_state_label,
  "No longer externally observed");
ok("stored P5 lifecycle overclaim is projected with an explicit limit",
  /not evidence that the asset was removed, decommissioned or remediated/i.test(
    historicalProjection.lifecycle.records.find(
      (item) => item.lifecycle_state === "confirmed_removed",
    )?.lifecycle_message || "",
  ));

const historicalApi = attackSurfaceAssuranceApiProjection(
  storedOverclaimSnapshot,
);
const historicalRead = {
  status: "ok",
  snapshot: storedOverclaimSnapshot,
  row: { id: "snap-p5-stored-overclaim" },
  integrity: { verified: true },
  dmarcPolicy: null,
};
const historicalExecutive = buildExecutiveReportV2({
  scan: {
    id: fixture.scan_id,
    domain_id: fixture.domain_id,
    domain: fixture.domain,
  },
  workspace: { id: fixture.workspace_id, name: "Fixture Workspace" },
  read: historicalRead,
});
const historicalPdfText = new TextDecoder().decode(
  buildScanReportPdf(
    { id: fixture.scan_id, domain: fixture.domain },
    historicalRead,
  ),
);
const historicalExecutivePdfText = new TextDecoder().decode(
  buildWorkspaceExecutivePdf({
    workspaceName: "Fixture Workspace",
    reads: [historicalRead],
    generatedAt: fixture.built_at,
  }),
);
const forbiddenCustomerOverclaim =
  /Confirmed removed|Removal event|deterministic confirmed-removal/i;
for (const [surface, rendered] of Object.entries({
  presentation: JSON.stringify(historicalProjection),
  api_projection: JSON.stringify(historicalApi),
  executive_report: JSON.stringify(historicalExecutive),
  scan_pdf: historicalPdfText,
  executive_pdf: historicalExecutivePdfText,
  assets_page: assetsPageSource,
})) {
  ok(`${surface}: no positive confirmed-removal customer overclaim`,
    !forbiddenCustomerOverclaim.test(rendered));
}

console.log(
  `Item 10 P5 customer parity: ${passed}/${passed + failed} assertions passed`,
);
if (failed > 0) process.exit(1);
